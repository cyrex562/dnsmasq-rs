#![cfg(feature = "dbus")]

//! D-Bus interface for dnsmasq — a real `zbus`-backed system-bus service.
//! Ported from `dbus.c`.
//!
//! The wire-level dispatch lives in a `#[zbus::interface]` impl further down
//! this file; everything above it is plain, bus-independent logic so the
//! actual method behavior (server-list mutation, option toggles, metrics
//! serialization, lease bookkeeping) is unit-testable without a running
//! D-Bus daemon.

use std::collections::HashMap;
use std::sync::Arc;

use crate::dnsmasq::DaemonHandle;
use crate::domain_match::{add_update_server, cleanup_servers, mark_servers};
use crate::dns_protocol::RrType;
use crate::option::new_server;
use crate::types::addr::MySockAddr;
use crate::types::constants::{OPT_BOGUSPRIV, OPT_FILTER, OPT_LOCALISE};
use crate::types::daemon::Daemon;
use crate::types::dns_records::RrList;
use crate::types::server::{SERV_4ADDR, SERV_6ADDR, SERV_FROM_DBUS, SERV_LITERAL_ADDRESS};
#[cfg(feature = "loop")]
use crate::types::server::SERV_LOOP;

/// The canonical dnsmasq D-Bus interface name and well-known bus name
/// (`DNSMASQ_SERVICE` / `DNSMASQ_PATH` in `dbus.c`/`config.h`).  `--enable-dbus`
/// may override the *bus name* (see `option.rs`); the interface/object path
/// stay fixed, which is the overwhelmingly common case upstream too.
pub const DNSMASQ_DBUS_INTERFACE: &str = "uk.org.thekelleys.dnsmasq";
pub const DNSMASQ_DBUS_PATH: &str = "/uk/org/thekelleys/dnsmasq";

/// Returns the list of D-Bus methods exposed by dnsmasq, reflecting the
/// methods actually reachable in this build (`GetLoopServers` needs the
/// `loop` feature, `AddDhcpLease`/`DeleteDhcpLease` need `dhcp`, matching
/// upstream's `HAVE_LOOP`/`HAVE_DHCP` gates around the same methods).
pub fn supported_methods() -> Vec<&'static str> {
    let mut m = vec![
        "GetVersion",
        "SetServers",
        "SetServersEx",
        "SetDomainServers",
        "SetFilterWin2KOption",
        "SetFilterA",
        "SetFilterAAAA",
        "SetLocaliseQueriesOption",
        "SetBogusPrivOption",
        "GetMetrics",
        "GetServerMetrics",
        "ClearMetrics",
        "ClearCache",
    ];
    #[cfg(feature = "loop")]
    m.push("GetLoopServers");
    #[cfg(feature = "dhcp")]
    {
        m.push("AddDhcpLease");
        m.push("DeleteDhcpLease");
    }
    m
}

/// Returns `true` if `name` is one of the supported D-Bus methods.
pub fn is_supported_method(name: &str) -> bool {
    supported_methods().contains(&name)
}

// ─── GetVersion ────────────────────────────────────────────────────────────

/// Mirrors `message_handler`'s `GetVersion` reply (`dbus.c:819-825`), which
/// echoes the daemon's own build version rather than a D-Bus-specific value.
pub fn get_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

// ─── Boolean option toggles ────────────────────────────────────────────────

/// Set or clear a plain option bit — the shared body of `dbus_set_bool()`
/// (`dbus.c:505-519`) used by `SetFilterWin2KOption`, `SetLocaliseQueriesOption`,
/// and `SetBogusPrivOption`.
pub fn apply_bool_option(daemon: &mut Daemon, opt: usize, enabled: bool) {
    if enabled {
        daemon.set_option(opt);
    } else {
        daemon.clear_option(opt);
    }
}

/// `SetFilterA` (`dbus.c:851-868`): toggles a single-entry RR filter for `A`
/// records, independent of `--filter-rr`'s own list.
pub fn apply_filter_a(daemon: &mut Daemon, enabled: bool) {
    apply_rr_filter(daemon, RrType::A as u16, enabled);
}

/// `SetFilterAAAA` (`dbus.c:869-886`): same as [`apply_filter_a`] for `AAAA`.
pub fn apply_filter_aaaa(daemon: &mut Daemon, enabled: bool) {
    apply_rr_filter(daemon, RrType::AAAA as u16, enabled);
}

fn apply_rr_filter(daemon: &mut Daemon, rr: u16, enabled: bool) {
    daemon.rrlist_filter.retain(|e| e.rr != rr);
    if enabled {
        daemon.rrlist_filter.push(RrList { rr });
    }
}

// ─── Server-list mutation (SetServers / SetServersEx / SetDomainServers) ──

/// Parse an `address[#port]` string into a socket address plus its
/// `SERV_4ADDR`/`SERV_6ADDR` flag.  Shared tail of the three `SetServers*`
/// variants below; mirrors the address part of `parse_server`/`parse_server_addr`
/// for the literal-IP case (hostname resolution via `getaddrinfo` is out of
/// scope — see `tasks.md`).
fn parse_dbus_addr(addr_str: &str) -> Result<(MySockAddr, u16), String> {
    let (host, port_str) = match addr_str.find('#') {
        Some(i) => (&addr_str[..i], Some(&addr_str[i + 1..])),
        None => (addr_str, None),
    };
    let ip: std::net::IpAddr =
        host.parse().map_err(|_| format!("Invalid IP address '{addr_str}'"))?;
    let port: u16 = match port_str {
        Some(p) => p.parse().map_err(|_| format!("Invalid port '{p}'"))?,
        None => 53,
    };
    let flags = if ip.is_ipv4() { SERV_4ADDR } else { SERV_6ADDR };
    let sock = match ip {
        std::net::IpAddr::V4(a) => MySockAddr::V4(std::net::SocketAddrV4::new(a, port)),
        std::net::IpAddr::V6(a) => MySockAddr::V6(std::net::SocketAddrV6::new(a, port, 0, 0)),
    };
    Ok((sock, flags))
}

fn dummy_source() -> MySockAddr {
    MySockAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0))
}

/// Push one server entry per domain (or a single catch-all entry when
/// `domains` is empty), reusing a stale `SERV_FROM_DBUS` slot where possible.
fn push_dbus_servers(daemon: &mut Daemon, flags: u16, domains: &[String], addr: &MySockAddr) {
    let source = dummy_source();
    if domains.is_empty() {
        add_update_server(&mut daemon.servers, new_server(flags, String::new(), addr.clone(), source));
    } else {
        for d in domains {
            add_update_server(&mut daemon.servers, new_server(flags, d.clone(), addr.clone(), source.clone()));
        }
    }
}

/// `SetDomainServers` (`dbus.c:272-486`, `strings=1`): each entry is either a
/// plain `address[#port]`, or `/domain[/domain...]/address[#port]` (the same
/// syntax as the `server=` directive's `/domain/` form — see
/// `parse_server_or_address` in `option.rs`), or `/domain[/domain...]/` (empty
/// address) meaning "never forward, answer locally".
pub fn apply_set_domain_servers(daemon: &mut Daemon, entries: &[String]) -> Result<(), String> {
    mark_servers(&mut daemon.servers, SERV_FROM_DBUS);

    for entry in entries {
        if entry.is_empty() {
            return Err("Empty string".to_string());
        }

        let (domains, addr_part): (Vec<String>, &str) = if let Some(idx) = entry.rfind('/') {
            if !entry.starts_with('/') || idx == 0 {
                return Err(format!("No domain terminator '{entry}'"));
            }
            let inner = &entry[1..idx];
            let doms: Vec<String> =
                inner.split('/').filter(|s| !s.is_empty()).map(|s| s.to_string()).collect();
            (doms, &entry[idx + 1..])
        } else {
            (vec![], entry.as_str())
        };

        if addr_part.is_empty() {
            push_dbus_servers(daemon, SERV_LITERAL_ADDRESS | SERV_FROM_DBUS, &domains, &dummy_source());
        } else {
            let (sock, addr_flags) = parse_dbus_addr(addr_part)?;
            push_dbus_servers(daemon, addr_flags | SERV_FROM_DBUS, &domains, &sock);
        }
    }

    cleanup_servers(&mut daemon.servers);
    Ok(())
}

/// `SetServersEx` (`dbus.c:272-486`, `strings=0`): each entry is
/// `[address[#port], domain, domain, ...]`; no domains means a catch-all.
pub fn apply_set_servers_ex(daemon: &mut Daemon, entries: &[Vec<String>]) -> Result<(), String> {
    mark_servers(&mut daemon.servers, SERV_FROM_DBUS);

    for entry in entries {
        let addr_str = entry.first().ok_or_else(|| "Expected IP address".to_string())?;
        if addr_str.is_empty() {
            return Err("Empty IP address".to_string());
        }
        let (sock, addr_flags) = parse_dbus_addr(addr_str)?;
        push_dbus_servers(daemon, addr_flags | SERV_FROM_DBUS, &entry[1..], &sock);
    }

    cleanup_servers(&mut daemon.servers);
    Ok(())
}

/// One element of the `SetServers` `av` (array-of-variant) argument
/// (`dbus.c:157-247`): an address (v4 as a plain integer, v6 as 16 raw bytes)
/// followed by zero or more domain strings, repeated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerArg {
    /// An IPv4 address. Upstream stores this via `ntohl()` into
    /// `sin_addr.s_addr`; this port takes the more conventional and
    /// unambiguous reading of the wire `uint32` as the address in network
    /// byte order (i.e. `Ipv4Addr::from(u32)`), which is what dnsmasq D-Bus
    /// clients such as NetworkManager actually send.
    Addr4(u32),
    /// An IPv6 address as 16 raw bytes.
    Addr6([u8; 16]),
    /// A domain name applying to the preceding address.
    Domain(String),
}

/// `SetServers` (`dbus.c:157-247`): apply a flat address/domain sequence.
pub fn apply_set_servers(daemon: &mut Daemon, args: &[ServerArg]) -> Result<(), String> {
    mark_servers(&mut daemon.servers, SERV_FROM_DBUS);

    let mut i = 0;
    while i < args.len() {
        let (sock, addr_flags) = match &args[i] {
            ServerArg::Addr4(a) => {
                let ip = std::net::Ipv4Addr::from(*a);
                (MySockAddr::V4(std::net::SocketAddrV4::new(ip, 53)), SERV_4ADDR)
            }
            ServerArg::Addr6(bytes) => {
                let ip = std::net::Ipv6Addr::from(*bytes);
                (MySockAddr::V6(std::net::SocketAddrV6::new(ip, 53, 0, 0)), SERV_6ADDR)
            }
            ServerArg::Domain(_) => {
                return Err("Expected an address before any domain name".to_string());
            }
        };
        i += 1;

        let mut domains = Vec::new();
        while let Some(ServerArg::Domain(d)) = args.get(i) {
            domains.push(d.clone());
            i += 1;
        }

        push_dbus_servers(daemon, addr_flags | SERV_FROM_DBUS, &domains, &sock);
    }

    cleanup_servers(&mut daemon.servers);
    Ok(())
}

// ─── Metrics (GetMetrics / GetServerMetrics / ClearMetrics) ───────────────

/// All tracked metrics except the `MetricMax` sentinel — kept local to this
/// module rather than added to `metrics.rs`, since `Metric` doesn't expose an
/// iteration helper and this is the only caller that needs one.
const ALL_METRICS: &[crate::metrics::Metric] = {
    use crate::metrics::Metric::*;
    &[
        DnsCacheInserted, DnsCacheLiveFreed, DnsQueriesForwarded, DnsAuthAnswered,
        DnsLocalAnswered, DnsStaleAnswered, DnsUnansweredQuery, CryptoHwm, SigFailHwm, WorkHwm,
        Bootp, Pxe, Dhcpack, Dhcpdecline, Dhcpdiscover, Dhcpinform, Dhcpnak, Dhcpoffer,
        Dhcprelease, Dhcprequest, Noanswer, LeasesAllocated4, LeasesPruned4, LeasesAllocated6,
        LeasesPruned6, TcpConnections, Dhcpleasequery, Dhcpleaseunassigned, Dhcpleaseactive,
        Dhcpleaseunknown,
    ]
};

/// `GetMetrics` (`dbus.c:703-725`): every counter, keyed by its upstream name.
pub fn metrics_dict() -> HashMap<String, u32> {
    ALL_METRICS
        .iter()
        .map(|m| (crate::metrics::metric_name(*m).to_string(), crate::metrics::get_metric(*m) as u32))
        .collect()
}

/// `GetServerMetrics` (`dbus.c:744-796`): one dict per distinct upstream
/// server address, summing stats across every `Server` entry that shares it
/// (there is one entry per domain for domain-specific servers).
pub fn server_metrics(daemon: &Daemon) -> Vec<HashMap<String, String>> {
    let mut seen = vec![false; daemon.servers.len()];
    let mut out = Vec::new();

    for i in 0..daemon.servers.len() {
        if seen[i] {
            continue;
        }
        let addr = daemon.servers[i].addr.clone();

        let mut queries = 0u32;
        let mut failed_queries = 0u32;
        let mut nxdomain = 0u32;
        let mut retries = 0u32;
        let mut sigma_latency = 0u32;
        let mut count_latency = 0u32;

        for (j, serv) in daemon.servers.iter().enumerate().skip(i) {
            if seen[j] || serv.addr != addr {
                continue;
            }
            seen[j] = true;
            queries += serv.queries;
            failed_queries += serv.failed_queries;
            nxdomain += serv.nxdomain_replies;
            retries += serv.retrys;
            sigma_latency += serv.query_latency;
            count_latency += 1;
        }

        let latency = if count_latency > 0 { sigma_latency / count_latency } else { 0 };

        let mut m = HashMap::new();
        m.insert("address".to_string(), addr.ip().to_string());
        m.insert("port".to_string(), addr.port().to_string());
        m.insert("queries".to_string(), queries.to_string());
        m.insert("failed_queries".to_string(), failed_queries.to_string());
        m.insert("nxdomain".to_string(), nxdomain.to_string());
        m.insert("retries".to_string(), retries.to_string());
        m.insert("latency".to_string(), latency.to_string());
        out.push(m);
    }

    out
}

// ─── GetLoopServers ────────────────────────────────────────────────────────

/// `GetLoopServers` (`dbus.c:249-269`, `HAVE_LOOP`): addresses of every
/// upstream server flagged `SERV_LOOP` (a duplicate of another configured
/// server, kept only to receive/detect forwarding loops).
#[cfg(feature = "loop")]
pub fn loop_servers(daemon: &Daemon) -> Vec<String> {
    daemon.servers.iter().filter(|s| s.flags & SERV_LOOP != 0).map(|s| s.addr.ip().to_string()).collect()
}

// ─── DHCP lease add/delete (AddDhcpLease / DeleteDhcpLease) ───────────────

#[cfg(feature = "dhcp")]
pub mod dhcp_leases {
    use super::*;
    use crate::dhcp_protocol::DHCP_CHADDR_MAX;
    use crate::types::dhcp::DhcpLease;
    use std::net::Ipv4Addr;
    use std::time::{Duration, UNIX_EPOCH};

    /// `AddDhcpLease` (`dbus.c:522-653`, IPv4 only — see `tasks.md` for the
    /// IPv6/`HAVE_DHCP6` gap this port leaves open).
    #[allow(clippy::too_many_arguments)]
    pub fn add_lease(
        leases: &mut crate::lease::LeaseDb,
        ipaddr: &str,
        hwaddr: &str,
        hostname: &[u8],
        clid: &[u8],
        lease_duration: u32,
        ia_id: u32,
        is_temporary: bool,
        now: u64,
    ) -> Result<(), String> {
        if ia_id != 0 || is_temporary {
            return Err("ia_id and is_temporary must be zero for an IPv4 lease".to_string());
        }

        let addr: Ipv4Addr =
            ipaddr.parse().map_err(|_| format!("Invalid IP address '{ipaddr}'"))?;

        let mut hw = Vec::new();
        let hw_len =
            crate::util::parse_hex(hwaddr, &mut hw, Some(DHCP_CHADDR_MAX), None);
        if hw_len < 0 {
            return Err(format!("Invalid HW address '{hwaddr}'"));
        }
        let mut hwaddr_fixed = [0u8; DHCP_CHADDR_MAX];
        hwaddr_fixed[..hw.len()].copy_from_slice(&hw);

        let hostname_str = if hostname.is_empty() {
            None
        } else {
            if let Some(pos) = hostname.iter().position(|&b| b == 0) {
                if pos != hostname.len() - 1 {
                    return Err("Hostname contains an embedded NUL character".to_string());
                }
            }
            let trimmed =
                if hostname.last() == Some(&0) { &hostname[..hostname.len() - 1] } else { hostname };
            Some(String::from_utf8_lossy(trimmed).into_owned())
        };

        let expires = UNIX_EPOCH + Duration::from_secs(now + lease_duration as u64);

        let lease = DhcpLease {
            clid: if clid.is_empty() { None } else { Some(clid.to_vec()) },
            hostname: hostname_str,
            fqdn: None,
            old_hostname: None,
            flags: 0,
            expires: Some(expires),
            hwaddr: hwaddr_fixed,
            hwaddr_len: hw.len(),
            // Upstream only assigns `ARPHRD_ETHER` when `parse_hex` didn't
            // already report a type; this port's `parse_hex` never reports
            // one, so it always falls back to `ARPHRD_ETHER` for a non-empty
            // address (`dbus.c:640-641`).
            hwaddr_type: if hw.is_empty() { 0 } else { 1 },
            addr,
            giaddr: Ipv4Addr::UNSPECIFIED,
            extradata: Vec::new(),
            last_interface: -1,
            new_interface: -1,
            new_prefixlen: -1,
            agent_id: None,
            vendorclass: None,
            #[cfg(feature = "dhcp6")]
            addr6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            iaid: 0,
            #[cfg(feature = "dhcp6")]
            slaac_address: Vec::new(),
            #[cfg(feature = "dhcp6")]
            vendorclass_count: 0,
        };

        leases.insert(lease);
        Ok(())
    }

    /// `DeleteDhcpLease` (`dbus.c:655-700`): returns whether a lease was found
    /// and removed.
    pub fn delete_lease(leases: &mut crate::lease::LeaseDb, ipaddr: &str) -> Result<bool, String> {
        let addr: Ipv4Addr =
            ipaddr.parse().map_err(|_| format!("Invalid IP address '{ipaddr}'"))?;
        Ok(leases.remove_by_addr(addr).is_some())
    }

    /// `(ipaddr, hwaddr, hostname)` as sent in `DhcpLease{Added,Deleted,Updated}`
    /// signal bodies (`emit_dbus_signal`, `dbus.c:1052-1103`).
    pub fn lease_signal_args(lease: &DhcpLease) -> (String, String, String) {
        let ip = lease.addr.to_string();
        let mac = crate::util::print_mac(&lease.hwaddr[..lease.hwaddr_len.min(lease.hwaddr.len())]);
        let hostname = lease.hostname.clone().unwrap_or_default();
        (ip, mac, hostname)
    }
}

/// Which `DhcpLease*` signal to emit — mirrors upstream's `ACTION_ADD` /
/// `ACTION_DEL` / `ACTION_OLD` (`emit_dbus_signal`, `dbus.c:1052-1103`).
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeaseAction {
    Added,
    Deleted,
    Updated,
}

#[cfg(feature = "dhcp")]
impl LeaseAction {
    fn signal_name(self) -> &'static str {
        match self {
            LeaseAction::Added => "DhcpLeaseAdded",
            LeaseAction::Deleted => "DhcpLeaseDeleted",
            LeaseAction::Updated => "DhcpLeaseUpdated",
        }
    }
}

/// Emit a `DhcpLease*` signal if `connection` is up — a no-op otherwise,
/// matching `if (!connection) return;` (`dbus.c:1062-1063`).
#[cfg(feature = "dhcp")]
pub async fn emit_lease_signal(
    connection: Option<&zbus::Connection>,
    interface: &str,
    action: LeaseAction,
    ipaddr: &str,
    hwaddr: &str,
    hostname: &str,
) {
    let Some(conn) = connection else { return };
    let _ = conn
        .emit_signal(
            None::<()>,
            DNSMASQ_DBUS_PATH,
            interface,
            action.signal_name(),
            &(ipaddr, hwaddr, hostname),
        )
        .await;
}

// ─── Bus connection lifecycle ──────────────────────────────────────────────

/// Everything the live D-Bus interface needs to answer a method call.
/// Analogous to upstream reaching through the single global `daemon`
/// pointer, but explicit about which pieces of shared state it touches.
#[derive(Clone)]
pub struct DbusContext {
    pub daemon: DaemonHandle,
    pub cache: crate::cache::SharedDnsCache,
    #[cfg(feature = "dhcp")]
    pub leases: Arc<tokio::sync::Mutex<crate::lease::LeaseDb>>,
    /// Where to persist DHCP lease changes made through the D-Bus methods
    /// (mirrors `lease_update_file`, `dbus.c:649,688`) — `None` disables
    /// persistence, matching "no `--dhcp-leasefile` configured".
    #[cfg(feature = "dhcp")]
    pub lease_file: Option<String>,
    /// The well-known bus name and interface name in use — defaults to
    /// [`DNSMASQ_DBUS_INTERFACE`], overridable via `--enable-dbus=<name>`.
    pub dbus_name: String,
}

struct DnsmasqInterface {
    ctx: DbusContext,
    /// Filled in once [`connect`] finishes building the connection — every
    /// method call arrives strictly after that, since nothing can reach this
    /// object before the connection exists to deliver the call.
    connection: Arc<tokio::sync::OnceCell<zbus::Connection>>,
}

#[zbus::interface(name = "uk.org.thekelleys.dnsmasq")]
impl DnsmasqInterface {
    async fn get_version(&self) -> String {
        get_version().to_string()
    }

    async fn clear_cache(&self) {
        crate::dnsmasq::clear_cache_and_reload(&self.ctx.daemon, &self.ctx.cache).await;
    }

    async fn clear_metrics(&self) {
        let mut d = self.ctx.daemon.write().await;
        crate::metrics::clear_metrics(&mut d);
    }

    async fn get_metrics(&self) -> HashMap<String, u32> {
        metrics_dict()
    }

    async fn get_server_metrics(&self) -> Vec<HashMap<String, String>> {
        let d = self.ctx.daemon.read().await;
        server_metrics(&d)
    }

    #[cfg(feature = "loop")]
    async fn get_loop_servers(&self) -> Vec<String> {
        let d = self.ctx.daemon.read().await;
        loop_servers(&d)
    }

    async fn set_servers(&self, servers: Vec<zbus::zvariant::OwnedValue>) -> zbus::fdo::Result<()> {
        let args = servers
            .into_iter()
            .map(value_to_server_arg)
            .collect::<Result<Vec<_>, _>>()
            .map_err(zbus::fdo::Error::InvalidArgs)?;
        let mut d = self.ctx.daemon.write().await;
        apply_set_servers(&mut d, &args).map_err(zbus::fdo::Error::InvalidArgs)?;
        drop(d);
        self.reload_servers().await;
        Ok(())
    }

    async fn set_servers_ex(&self, servers: Vec<Vec<String>>) -> zbus::fdo::Result<()> {
        let mut d = self.ctx.daemon.write().await;
        apply_set_servers_ex(&mut d, &servers).map_err(zbus::fdo::Error::InvalidArgs)?;
        drop(d);
        self.reload_servers().await;
        Ok(())
    }

    async fn set_domain_servers(&self, servers: Vec<String>) -> zbus::fdo::Result<()> {
        let mut d = self.ctx.daemon.write().await;
        apply_set_domain_servers(&mut d, &servers).map_err(zbus::fdo::Error::InvalidArgs)?;
        drop(d);
        self.reload_servers().await;
        Ok(())
    }

    #[zbus(name = "SetFilterWin2KOption")]
    async fn set_filter_win2k_option(&self, enabled: bool) {
        let mut d = self.ctx.daemon.write().await;
        apply_bool_option(&mut d, OPT_FILTER, enabled);
    }

    async fn set_filter_a(&self, enabled: bool) {
        let mut d = self.ctx.daemon.write().await;
        apply_filter_a(&mut d, enabled);
    }

    #[zbus(name = "SetFilterAAAA")]
    async fn set_filter_aaaa(&self, enabled: bool) {
        let mut d = self.ctx.daemon.write().await;
        apply_filter_aaaa(&mut d, enabled);
    }

    async fn set_localise_queries_option(&self, enabled: bool) {
        let mut d = self.ctx.daemon.write().await;
        apply_bool_option(&mut d, OPT_LOCALISE, enabled);
    }

    async fn set_bogus_priv_option(&self, enabled: bool) {
        let mut d = self.ctx.daemon.write().await;
        apply_bool_option(&mut d, OPT_BOGUSPRIV, enabled);
    }

    #[cfg(feature = "dhcp")]
    #[allow(clippy::too_many_arguments)]
    async fn add_dhcp_lease(
        &self,
        ipaddr: String,
        hwaddr: String,
        hostname: Vec<u8>,
        clid: Vec<u8>,
        lease_duration: u32,
        ia_id: u32,
        is_temporary: bool,
    ) -> zbus::fdo::Result<()> {
        let now = crate::util::dnsmasq_time();
        let mut leases = self.ctx.leases.lock().await;
        dhcp_leases::add_lease(
            &mut leases, &ipaddr, &hwaddr, &hostname, &clid, lease_duration, ia_id, is_temporary, now,
        )
        .map_err(zbus::fdo::Error::InvalidArgs)?;
        self.persist_leases(&leases);
        let signal_args = ipaddr
            .parse()
            .ok()
            .and_then(|addr| leases.find_by_addr(addr))
            .map(dhcp_leases::lease_signal_args);
        drop(leases);
        if let Some((ip, mac, host)) = signal_args {
            emit_lease_signal(self.connection.get(), &self.ctx.dbus_name, LeaseAction::Added, &ip, &mac, &host)
                .await;
        }
        Ok(())
    }

    #[cfg(feature = "dhcp")]
    async fn delete_dhcp_lease(&self, ipaddr: String) -> zbus::fdo::Result<bool> {
        let mut leases = self.ctx.leases.lock().await;
        let found = dhcp_leases::delete_lease(&mut leases, &ipaddr).map_err(zbus::fdo::Error::InvalidArgs)?;
        if found {
            self.persist_leases(&leases);
        }
        drop(leases);
        if found {
            emit_lease_signal(
                self.connection.get(), &self.ctx.dbus_name, LeaseAction::Deleted, &ipaddr, "", "",
            )
            .await;
        }
        Ok(found)
    }
}

impl DnsmasqInterface {
    /// `dbus.c:922-928`: any successful `SetServers*` call logs, re-checks
    /// the server list, and clears the cache when `--clear-on-reload` is set.
    async fn reload_servers(&self) {
        use tracing::info;
        info!("setting upstream servers from DBus");
        let reload = { self.ctx.daemon.read().await.option_bool(crate::types::constants::OPT_RELOAD) };
        if reload {
            crate::dnsmasq::clear_cache_and_reload(&self.ctx.daemon, &self.ctx.cache).await;
        }
    }

    #[cfg(feature = "dhcp")]
    fn persist_leases(&self, leases: &crate::lease::LeaseDb) {
        // Best-effort, matching `lease_update_file`'s "no configured lease
        // file" no-op case; write failures are not fatal to the D-Bus call.
        if let Some(path) = &self.ctx.lease_file {
            let _ = leases.write_to_file(path);
        }
    }
}

/// Convert one `SetServers` (`av`) element into a [`ServerArg`].
///
/// Takes `v` by value (the caller does `Vec::into_iter().map(...)`) rather
/// than by reference — `OwnedValue` only has by-value `TryFrom` conversions
/// for dynamically-sized types like `Vec<u8>`/`String`, and cloning a `&T`
/// via `.clone()` silently clones the reference itself, not the value.
fn value_to_server_arg(v: zbus::zvariant::OwnedValue) -> Result<ServerArg, String> {
    if let Ok(cloned) = v.try_clone() {
        if let Ok(a) = u32::try_from(cloned) {
            return Ok(ServerArg::Addr4(a));
        }
    }
    if let Ok(cloned) = v.try_clone() {
        if let Ok(bytes) = Vec::<u8>::try_from(cloned) {
            if bytes.len() != 16 {
                return Err("Expected a 16-byte IPv6 address".to_string());
            }
            let mut arr = [0u8; 16];
            arr.copy_from_slice(&bytes);
            return Ok(ServerArg::Addr6(arr));
        }
    }
    if let Ok(s) = String::try_from(v) {
        return Ok(ServerArg::Domain(s));
    }
    Err("Unexpected argument type in SetServers".to_string())
}

/// Connect to the system bus, request the configured well-known name, serve
/// the dnsmasq interface at [`DNSMASQ_DBUS_PATH`], and emit the startup `Up`
/// signal. Mirrors `dbus_init()` (`dbus.c:950-985`); may fail silently from
/// the caller's point of view if the bus daemon isn't up yet, same as
/// upstream — see [`run_dbus_task`] for the retry loop around this.
pub async fn connect(ctx: DbusContext) -> zbus::Result<zbus::Connection> {
    let connection_cell: Arc<tokio::sync::OnceCell<zbus::Connection>> = Arc::new(tokio::sync::OnceCell::new());
    let name = ctx.dbus_name.clone();
    let iface = DnsmasqInterface { ctx, connection: connection_cell.clone() };

    let connection = zbus::connection::Builder::system()?
        .name(name.as_str())?
        .serve_at(DNSMASQ_DBUS_PATH, iface)?
        .build()
        .await?;

    let _ = connection_cell.set(connection.clone());
    let _ = connection.emit_signal(None::<()>, DNSMASQ_DBUS_PATH, name.as_str(), "Up", &()).await;

    Ok(connection)
}

/// Keep a D-Bus connection alive, retrying on a fixed backoff whenever the
/// bus is unreachable. `zbus`'s I/O is fully async (its own internal
/// executor services watches/dispatch), so unlike upstream's
/// `set_dbus_listeners()`/`check_dbus_listeners()` poll integration, this
/// task only needs to hold the connection open — a deliberate async-native
/// replacement for that poll loop, not a behavior change to the interface
/// it serves.
pub async fn run_dbus_task(ctx: DbusContext) {
    use tracing::{info, warn};
    loop {
        match connect(ctx.clone()).await {
            Ok(connection) => {
                info!("D-Bus connection established as {}", ctx.dbus_name);
                std::future::pending::<()>().await;
                drop(connection);
            }
            Err(e) => {
                warn!("D-Bus connection failed, retrying: {e}");
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    }
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::server::Server;

    /// `addr` is `ip[#port]`; defaults to port 53 when no `#port` is given.
    fn test_server(flags: u16, domain: &str, addr: &str) -> Server {
        let (sock, addr_flags) = parse_dbus_addr(addr).unwrap();
        new_server(flags | addr_flags, domain.to_string(), sock, dummy_source())
    }

    // ── supported_methods / is_supported_method ────────────────────────────

    #[test]
    fn test_interface_constant() {
        assert_eq!(DNSMASQ_DBUS_INTERFACE, "uk.org.thekelleys.dnsmasq");
    }

    #[test]
    fn supported_methods_lists_all_upstream_names() {
        let m = supported_methods();
        for name in [
            "GetVersion", "SetServers", "SetServersEx", "SetDomainServers",
            "SetFilterWin2KOption", "SetFilterA", "SetFilterAAAA",
            "SetLocaliseQueriesOption", "SetBogusPrivOption",
            "GetMetrics", "GetServerMetrics", "ClearMetrics", "ClearCache",
        ] {
            assert!(m.contains(&name), "missing {name}");
        }
    }

    #[cfg(feature = "loop")]
    #[test]
    fn supported_methods_includes_get_loop_servers_under_loop_feature() {
        assert!(supported_methods().contains(&"GetLoopServers"));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn supported_methods_includes_dhcp_lease_methods_under_dhcp_feature() {
        let m = supported_methods();
        assert!(m.contains(&"AddDhcpLease"));
        assert!(m.contains(&"DeleteDhcpLease"));
    }

    #[test]
    fn test_is_supported_method_unknown() {
        assert!(!is_supported_method("Unknown"));
        assert!(!is_supported_method(""));
    }

    // ── GetVersion ──────────────────────────────────────────────────────────

    #[test]
    fn get_version_is_non_empty() {
        assert!(!get_version().is_empty());
    }

    // ── Boolean option toggles ───────────────────────────────────────────────

    #[test]
    fn apply_bool_option_sets_and_clears() {
        let mut d = Daemon::default();
        assert!(!d.option_bool(OPT_BOGUSPRIV));
        apply_bool_option(&mut d, OPT_BOGUSPRIV, true);
        assert!(d.option_bool(OPT_BOGUSPRIV));
        apply_bool_option(&mut d, OPT_BOGUSPRIV, false);
        assert!(!d.option_bool(OPT_BOGUSPRIV));
    }

    #[test]
    fn apply_filter_a_toggles_a_single_entry() {
        let mut d = Daemon::default();
        apply_filter_a(&mut d, true);
        assert_eq!(d.rrlist_filter.iter().filter(|e| e.rr == RrType::A as u16).count(), 1);
        apply_filter_a(&mut d, false);
        assert_eq!(d.rrlist_filter.iter().filter(|e| e.rr == RrType::A as u16).count(), 0);
    }

    #[test]
    fn apply_filter_a_does_not_disturb_filter_aaaa() {
        let mut d = Daemon::default();
        apply_filter_aaaa(&mut d, true);
        apply_filter_a(&mut d, true);
        assert!(d.rrlist_filter.iter().any(|e| e.rr == RrType::A as u16));
        assert!(d.rrlist_filter.iter().any(|e| e.rr == RrType::AAAA as u16));
    }

    // ── apply_set_domain_servers ─────────────────────────────────────────────

    #[test]
    fn set_domain_servers_plain_address() {
        let mut d = Daemon::default();
        apply_set_domain_servers(&mut d, &["1.2.3.4".to_string()]).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert_eq!(d.servers[0].addr.ip().to_string(), "1.2.3.4");
        assert_eq!(d.servers[0].domain, "");
        assert!(d.servers[0].flags & SERV_FROM_DBUS != 0);
    }

    #[test]
    fn set_domain_servers_with_domain_prefix() {
        let mut d = Daemon::default();
        apply_set_domain_servers(&mut d, &["/example.com/1.2.3.4".to_string()]).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert_eq!(d.servers[0].domain, "example.com");
        assert_eq!(d.servers[0].addr.ip().to_string(), "1.2.3.4");
    }

    #[test]
    fn set_domain_servers_multiple_domains_fan_out() {
        let mut d = Daemon::default();
        apply_set_domain_servers(&mut d, &["/a.com/b.com/1.2.3.4".to_string()]).unwrap();
        assert_eq!(d.servers.len(), 2);
        assert_eq!(d.servers[0].domain, "a.com");
        assert_eq!(d.servers[1].domain, "b.com");
    }

    #[test]
    fn set_domain_servers_empty_address_is_literal_never_forward() {
        let mut d = Daemon::default();
        apply_set_domain_servers(&mut d, &["/example.com/".to_string()]).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert!(d.servers[0].flags & SERV_LITERAL_ADDRESS != 0);
    }

    #[test]
    fn set_domain_servers_rejects_empty_string() {
        let mut d = Daemon::default();
        assert!(apply_set_domain_servers(&mut d, &["".to_string()]).is_err());
    }

    #[test]
    fn set_domain_servers_rejects_missing_leading_slash() {
        let mut d = Daemon::default();
        // A '/' not at the start is not a valid domain terminator.
        assert!(apply_set_domain_servers(&mut d, &["a/b".to_string()]).is_err());
    }

    #[test]
    fn set_domain_servers_replaces_stale_dbus_entries() {
        let mut d = Daemon::default();
        apply_set_domain_servers(&mut d, &["1.2.3.4".to_string()]).unwrap();
        apply_set_domain_servers(&mut d, &["5.6.7.8".to_string()]).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert_eq!(d.servers[0].addr.ip().to_string(), "5.6.7.8");
    }

    #[test]
    fn set_domain_servers_preserves_non_dbus_entries() {
        let mut d = Daemon::default();
        d.servers.push(test_server(0, "", "9.9.9.9#53"));
        apply_set_domain_servers(&mut d, &["1.2.3.4".to_string()]).unwrap();
        assert_eq!(d.servers.len(), 2);
        assert!(d.servers.iter().any(|s| s.addr.ip().to_string() == "9.9.9.9"));
    }

    #[test]
    fn set_domain_servers_parses_explicit_port() {
        let mut d = Daemon::default();
        apply_set_domain_servers(&mut d, &["1.2.3.4#5353".to_string()]).unwrap();
        assert_eq!(d.servers[0].addr.port(), 5353);
    }

    // ── apply_set_servers_ex ─────────────────────────────────────────────────

    #[test]
    fn set_servers_ex_no_domains_is_catch_all() {
        let mut d = Daemon::default();
        apply_set_servers_ex(&mut d, &[vec!["1.2.3.4".to_string()]]).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert_eq!(d.servers[0].domain, "");
    }

    #[test]
    fn set_servers_ex_fans_out_over_domains() {
        let mut d = Daemon::default();
        apply_set_servers_ex(&mut d, &[vec!["1.2.3.4".to_string(), "a.com".to_string(), "b.com".to_string()]])
            .unwrap();
        assert_eq!(d.servers.len(), 2);
        assert_eq!(d.servers[0].domain, "a.com");
        assert_eq!(d.servers[1].domain, "b.com");
    }

    #[test]
    fn set_servers_ex_rejects_empty_address() {
        let mut d = Daemon::default();
        assert!(apply_set_servers_ex(&mut d, &[vec!["".to_string()]]).is_err());
    }

    // ── apply_set_servers ────────────────────────────────────────────────────

    #[test]
    fn set_servers_v4_catch_all() {
        let mut d = Daemon::default();
        let a = u32::from(std::net::Ipv4Addr::new(1, 2, 3, 4));
        apply_set_servers(&mut d, &[ServerArg::Addr4(a)]).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert_eq!(d.servers[0].addr.ip().to_string(), "1.2.3.4");
    }

    #[test]
    fn set_servers_v4_with_domains() {
        let mut d = Daemon::default();
        let a = u32::from(std::net::Ipv4Addr::new(1, 2, 3, 4));
        apply_set_servers(
            &mut d,
            &[ServerArg::Addr4(a), ServerArg::Domain("a.com".to_string()), ServerArg::Domain("b.com".to_string())],
        )
        .unwrap();
        assert_eq!(d.servers.len(), 2);
    }

    #[test]
    fn set_servers_v6_address() {
        let mut d = Daemon::default();
        let ip = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        apply_set_servers(&mut d, &[ServerArg::Addr6(ip.octets())]).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert_eq!(d.servers[0].addr.ip(), std::net::IpAddr::V6(ip));
    }

    #[test]
    fn set_servers_rejects_domain_before_any_address() {
        let mut d = Daemon::default();
        assert!(apply_set_servers(&mut d, &[ServerArg::Domain("a.com".to_string())]).is_err());
    }

    #[test]
    fn set_servers_multiple_addresses() {
        let mut d = Daemon::default();
        let a1 = u32::from(std::net::Ipv4Addr::new(1, 1, 1, 1));
        let a2 = u32::from(std::net::Ipv4Addr::new(2, 2, 2, 2));
        apply_set_servers(&mut d, &[ServerArg::Addr4(a1), ServerArg::Addr4(a2)]).unwrap();
        assert_eq!(d.servers.len(), 2);
    }

    // ── metrics_dict / server_metrics ───────────────────────────────────────

    #[test]
    fn metrics_dict_has_one_entry_per_metric() {
        let dict = metrics_dict();
        assert_eq!(dict.len(), ALL_METRICS.len());
        assert!(dict.contains_key("dns_queries_forwarded"));
    }

    #[test]
    fn metrics_dict_reflects_live_counters() {
        crate::metrics::clear_metrics(&mut Daemon::default());
        crate::metrics::inc_metric(crate::metrics::Metric::Noanswer);
        let before = metrics_dict()["noanswer"];
        crate::metrics::inc_metric(crate::metrics::Metric::Noanswer);
        let after = metrics_dict()["noanswer"];
        assert_eq!(after, before + 1);
    }

    #[test]
    fn server_metrics_empty_when_no_servers() {
        let d = Daemon::default();
        assert!(server_metrics(&d).is_empty());
    }

    #[test]
    fn server_metrics_reports_one_row_per_distinct_address() {
        let mut d = Daemon::default();
        let mut s1 = test_server(0, "a.com", "1.2.3.4#53");
        s1.queries = 10;
        let mut s2 = test_server(0, "b.com", "1.2.3.4#53");
        s2.queries = 5;
        d.servers.push(s1);
        d.servers.push(s2);

        let rows = server_metrics(&d);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["address"], "1.2.3.4");
        assert_eq!(rows[0]["queries"], "15");
    }

    #[test]
    fn server_metrics_distinguishes_different_addresses() {
        let mut d = Daemon::default();
        d.servers.push(test_server(0, "", "1.1.1.1#53"));
        d.servers.push(test_server(0, "", "2.2.2.2#53"));
        assert_eq!(server_metrics(&d).len(), 2);
    }

    // ── loop_servers ─────────────────────────────────────────────────────────

    #[cfg(feature = "loop")]
    #[test]
    fn loop_servers_filters_by_serv_loop_flag() {
        let mut d = Daemon::default();
        d.servers.push(test_server(SERV_LOOP, "", "1.1.1.1#53"));
        d.servers.push(test_server(0, "", "2.2.2.2#53"));
        let servers = loop_servers(&d);
        assert_eq!(servers, vec!["1.1.1.1".to_string()]);
    }

    // ── DHCP lease add/delete ────────────────────────────────────────────────

    #[cfg(feature = "dhcp")]
    mod dhcp_lease_tests {
        use super::super::dhcp_leases::*;
        use crate::lease::LeaseDb;

        #[test]
        fn add_lease_inserts_a_findable_v4_lease() {
            let mut db = LeaseDb::new();
            add_lease(&mut db, "192.168.0.10", "aa:bb:cc:dd:ee:ff", b"myhost", &[], 3600, 0, false, 1_000)
                .unwrap();
            let lease = db.find_by_addr("192.168.0.10".parse().unwrap()).unwrap();
            assert_eq!(lease.hostname.as_deref(), Some("myhost"));
            assert_eq!(&lease.hwaddr[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        }

        #[test]
        fn add_lease_rejects_ia_id_or_temporary_for_v4() {
            let mut db = LeaseDb::new();
            assert!(add_lease(&mut db, "192.168.0.10", "aa:bb:cc:dd:ee:ff", b"", &[], 3600, 1, false, 0).is_err());
            assert!(add_lease(&mut db, "192.168.0.10", "aa:bb:cc:dd:ee:ff", b"", &[], 3600, 0, true, 0).is_err());
        }

        #[test]
        fn add_lease_rejects_invalid_address() {
            let mut db = LeaseDb::new();
            assert!(add_lease(&mut db, "not-an-ip", "aa:bb:cc:dd:ee:ff", b"", &[], 3600, 0, false, 0).is_err());
        }

        #[test]
        fn add_lease_rejects_embedded_nul_not_at_end() {
            let mut db = LeaseDb::new();
            let hostname = b"my\0host";
            assert!(add_lease(&mut db, "192.168.0.10", "aa:bb:cc:dd:ee:ff", hostname, &[], 3600, 0, false, 0).is_err());
        }

        #[test]
        fn delete_lease_removes_existing_lease() {
            let mut db = LeaseDb::new();
            add_lease(&mut db, "192.168.0.10", "aa:bb:cc:dd:ee:ff", b"", &[], 3600, 0, false, 0).unwrap();
            assert!(delete_lease(&mut db, "192.168.0.10").unwrap());
            assert!(db.find_by_addr("192.168.0.10".parse().unwrap()).is_none());
        }

        #[test]
        fn delete_lease_returns_false_when_not_found() {
            let mut db = LeaseDb::new();
            assert!(!delete_lease(&mut db, "192.168.0.10").unwrap());
        }

        #[test]
        fn lease_signal_args_formats_mac_and_ip() {
            let mut db = LeaseDb::new();
            add_lease(&mut db, "192.168.0.10", "aa:bb:cc:dd:ee:ff", b"myhost", &[], 3600, 0, false, 0).unwrap();
            let lease = db.find_by_addr("192.168.0.10".parse().unwrap()).unwrap();
            let (ip, mac, host) = lease_signal_args(lease);
            assert_eq!(ip, "192.168.0.10");
            assert_eq!(mac, "aa:bb:cc:dd:ee:ff");
            assert_eq!(host, "myhost");
        }
    }

    // ── Live bus connection ─────────────────────────────────────────────────
    //
    // Needs an actual D-Bus daemon (session or system) reachable from this
    // process — never guaranteed in a sandbox/CI container.  Skips rather
    // than fails when unreachable, same pattern as the socket/interface tests
    // gated elsewhere in this codebase (see e.g. `dhcp.rs`).

    #[tokio::test]
    async fn live_bus_connection_serves_get_version() {
        let daemon = crate::dnsmasq::init_daemon();
        let cache = crate::cache::new_shared_cache(100, 0, 3600);
        let ctx = DbusContext {
            daemon: daemon.clone(),
            cache,
            #[cfg(feature = "dhcp")]
            leases: Arc::new(tokio::sync::Mutex::new(crate::lease::LeaseDb::new())),
            #[cfg(feature = "dhcp")]
            lease_file: None,
            dbus_name: "uk.org.thekelleys.dnsmasq.test".to_string(),
        };

        let connection = match connect(ctx).await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("skipping: no D-Bus bus reachable in this sandbox ({e})");
                return;
            }
        };

        let reply = connection
            .call_method(
                Some("uk.org.thekelleys.dnsmasq.test"),
                DNSMASQ_DBUS_PATH,
                Some(DNSMASQ_DBUS_INTERFACE),
                "GetVersion",
                &(),
            )
            .await
            .expect("GetVersion call should succeed against our own connection");
        let version: String = reply.body().deserialize().expect("GetVersion should reply with a string");
        assert_eq!(version, get_version());

        // Regression check for the pascal_case-derived member-name trap:
        // zbus's `#[interface]` macro auto-derives D-Bus member names from
        // the Rust method identifier and only capitalizes the first letter
        // of each `_`-separated segment, so `set_filter_win2k_option` would
        // otherwise register as `SetFilterWin2kOption` and `set_filter_aaaa`
        // as `SetFilterAaaa` — neither matches the upstream wire name a real
        // caller (dbus-send, NetworkManager) actually invokes. Reuses this
        // test's already-established connection/name rather than a second
        // bus name, since this sandbox's D-Bus policy only allows this one.
        for (method, enabled) in [("SetFilterWin2KOption", true), ("SetFilterAAAA", false)] {
            connection
                .call_method(
                    Some("uk.org.thekelleys.dnsmasq.test"),
                    DNSMASQ_DBUS_PATH,
                    Some(DNSMASQ_DBUS_INTERFACE),
                    method,
                    &(enabled,),
                )
                .await
                .unwrap_or_else(|e| panic!("{method} should be reachable under its upstream wire name: {e}"));
        }
    }
}

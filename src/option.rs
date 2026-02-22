/// Configuration and command-line option parser for dnsmasq-rs.
///
/// Implements a subset of the logic in the original `option.c` (6322 lines).
/// The focus is on the config-file parsing infrastructure and the most common
/// options; exotic / rarely-used directives can be added incrementally.

use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::types::addr::MySockAddr;
use crate::types::constants::*;
use crate::types::daemon::Daemon;
use crate::types::network::{HostsFile, Iname};
use crate::types::server::{Server, SERV_4ADDR, SERV_6ADDR, SERV_LITERAL_ADDRESS};

// ── Public types ──────────────────────────────────────────────────────────────

/// A single parsed config directive (key + optional value).
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigLine {
    pub key:   String,
    pub value: Option<String>,
    pub file:  String,
    pub line:  usize,
}

/// Errors that can arise during config parsing or application.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("unknown option '{0}' at {1}:{2}")]
    UnknownOption(String, String, usize),
    #[error("missing value for '{0}' at {1}:{2}")]
    MissingValue(String, String, usize),
    #[error("invalid value '{0}' for '{1}' at {2}:{3}: {4}")]
    InvalidValue(String, String, String, usize, String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

// ── Config-file text parser ───────────────────────────────────────────────────

/// Parse config file text into a list of [`ConfigLine`]s.
///
/// Rules (mirrors dnsmasq's `read_opts`):
/// - Lines starting with `#` (after optional leading whitespace) are comments.
/// - Empty / whitespace-only lines are ignored.
/// - Format: `key=value` or just `key` (boolean flag).
/// - The `conf-file=path` directive triggers recursive inclusion (max depth 10).
pub fn parse_config_text(text: &str, filename: &str) -> Result<Vec<ConfigLine>, ConfigError> {
    parse_config_text_depth(text, filename, 0)
}

fn parse_config_text_depth(
    text: &str,
    filename: &str,
    depth: usize,
) -> Result<Vec<ConfigLine>, ConfigError> {
    const MAX_DEPTH: usize = 10;

    let mut lines = Vec::new();

    for (idx, raw) in text.lines().enumerate() {
        let lineno = idx + 1;
        let trimmed = raw.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let (key, value) = if let Some(eq) = trimmed.find('=') {
            let k = trimmed[..eq].trim().to_string();
            let v = trimmed[eq + 1..].trim().to_string();
            (k, Some(v))
        } else {
            (trimmed.to_string(), None)
        };

        if key.is_empty() {
            continue;
        }

        // Handle recursive inclusion.
        if key == "conf-file" {
            if depth >= MAX_DEPTH {
                return Err(ConfigError::InvalidValue(
                    value.unwrap_or_default(),
                    "conf-file".to_string(),
                    filename.to_string(),
                    lineno,
                    "maximum conf-file inclusion depth exceeded".to_string(),
                ));
            }
            let path = value.ok_or_else(|| {
                ConfigError::MissingValue("conf-file".to_string(), filename.to_string(), lineno)
            })?;
            let included = std::fs::read_to_string(&path)?;
            let sub = parse_config_text_depth(&included, &path, depth + 1)?;
            lines.extend(sub);
            continue;
        }

        lines.push(ConfigLine {
            key,
            value,
            file: filename.to_string(),
            line: lineno,
        });
    }

    Ok(lines)
}

// ── Config applicator ─────────────────────────────────────────────────────────

/// Apply a list of parsed config lines to a [`Daemon`] configuration.
pub fn apply_config(daemon: &mut Daemon, lines: &[ConfigLine]) -> Result<(), ConfigError> {
    for cl in lines {
        apply_line(daemon, cl)?;
    }
    Ok(())
}

/// Apply a single [`ConfigLine`] to the daemon state.
fn apply_line(daemon: &mut Daemon, cl: &ConfigLine) -> Result<(), ConfigError> {
    let key = cl.key.as_str();
    let file = &cl.file;
    let lineno = cl.line;

    // Helper closures.
    let require_value = |opt: &str| -> Result<&str, ConfigError> {
        cl.value.as_deref().ok_or_else(|| {
            ConfigError::MissingValue(opt.to_string(), file.clone(), lineno)
        })
    };

    let invalid = |val: &str, reason: &str| -> ConfigError {
        ConfigError::InvalidValue(
            val.to_string(),
            key.to_string(),
            file.clone(),
            lineno,
            reason.to_string(),
        )
    };

    match key {
        // ── Boolean flags ──────────────────────────────────────────────────
        "no-resolv" => daemon.set_option(OPT_NO_RESOLV),
        "no-poll"   => daemon.set_option(OPT_NO_POLL),
        "no-hosts"  => daemon.set_option(OPT_NO_HOSTS),
        "bogus-priv" | "bogus-privv4" => daemon.set_option(OPT_BOGUSPRIV),
        "expand-hosts" => daemon.set_option(OPT_EXPAND),
        "filterwin2k" | "filter-win2k" => daemon.set_option(OPT_FILTER),
        "localise-queries" | "localize-queries" => daemon.set_option(OPT_LOCALISE),
        "log-queries" => daemon.set_option(OPT_LOG),
        "log-dhcp"    => daemon.set_option(OPT_LOG_OPTS),
        "no-negcache" => daemon.set_option(OPT_NO_NEG),
        "strict-order" => daemon.set_option(OPT_ORDER),
        "all-servers"  => daemon.set_option(OPT_ALL_SERVERS),
        "reload-acl"   => daemon.set_option(OPT_RELOAD),
        "local-service" => daemon.set_option(OPT_LOCAL_SERVICE),
        "no-rebind"    => daemon.set_option(OPT_NO_REBIND),
        "bogus-nxdomain" => { /* handled below with value */ }
        "no-daemon"    => daemon.set_option(OPT_NO_FORK),
        "bind-interfaces" => daemon.set_option(OPT_NOWILD),
        "selfmx"       => daemon.set_option(OPT_SELFMX),
        "localmx"      => daemon.set_option(OPT_LOCALMX),
        "authoritative" => daemon.set_option(OPT_AUTHORITATIVE),
        "ra-param"     => {} // skip; DHCP6 only
        "dhcp-fqdn"    => daemon.set_option(OPT_DHCP_FQDN),
        "enable-dbus"  => daemon.set_option(OPT_DBUS),
        "no-ping"      => daemon.set_option(OPT_NO_PING),
        "lease-ro" | "leasefile-ro" => daemon.set_option(OPT_LEASE_RO),
        "conntrack"    => daemon.set_option(OPT_CONNTRACK),
        "quiet-dhcp"   => daemon.set_option(OPT_QUIET_DHCP),
        "quiet-dhcp6"  => daemon.set_option(OPT_QUIET_DHCP6),
        "quiet-ra"     => daemon.set_option(OPT_QUIET_RA),
        "dnssec"       => daemon.set_option(OPT_DNSSEC_VALID),
        "proxy-dnssec" => daemon.set_option(OPT_DNSSEC_PROXY),
        "dnssec-debug" => daemon.set_option(OPT_DNSSEC_DEBUG),
        "dnssec-no-timecheck" => daemon.set_option(OPT_DNSSEC_TIME),
        "enable-ra"    => daemon.set_option(OPT_RA),
        "enable-tftp"  => daemon.set_option(OPT_TFTP),
        "tftp-secure"  => daemon.set_option(OPT_TFTP_SECURE),
        "tftp-no-blocksize" => daemon.set_option(OPT_TFTP_NOBLOCK),
        "tftp-lowercase"    => daemon.set_option(OPT_TFTP_LC),
        "client-subnet"     => daemon.set_option(OPT_CLIENT_SUBNET),
        "loop-detect"       => daemon.set_option(OPT_LOOP_DETECT),
        "script-arp"        => daemon.set_option(OPT_SCRIPT_ARP),
        "rapid-commit"      => daemon.set_option(OPT_RAPID_COMMIT),
        "ubus"              => daemon.set_option(OPT_UBUS),
        "add-mac"           => daemon.set_option(OPT_ADD_MAC),
        "local-ttl" if cl.value.is_none() => {} // value required; handled below

        // ── Numeric / string options ────────────────────────────────────────
        "port" => {
            let v = require_value("port")?;
            let p: u16 = v.parse().map_err(|_| invalid(v, "expected a valid port number (0-65535)"))?;
            daemon.port = p;
        }

        "query-port" => {
            let v = require_value("query-port")?;
            let p: u16 = v.parse().map_err(|_| invalid(v, "expected a valid port number (0-65535)"))?;
            daemon.query_port = p;
        }

        "min-port" => {
            let v = require_value("min-port")?;
            let p: u16 = v.parse().map_err(|_| invalid(v, "expected a valid port number (0-65535)"))?;
            daemon.min_port = p;
        }

        "max-port" => {
            let v = require_value("max-port")?;
            let p: u16 = v.parse().map_err(|_| invalid(v, "expected a valid port number (0-65535)"))?;
            daemon.max_port = p;
        }

        "cache-size" => {
            let v = require_value("cache-size")?;
            let n: i32 = v.parse().map_err(|_| invalid(v, "expected an integer"))?;
            daemon.cachesize = n;
        }

        "local-ttl" => {
            let v = require_value("local-ttl")?;
            let n: u32 = v.parse().map_err(|_| invalid(v, "expected an unsigned integer"))?;
            daemon.local_ttl = n;
        }

        "neg-ttl" => {
            let v = require_value("neg-ttl")?;
            let n: u32 = v.parse().map_err(|_| invalid(v, "expected an unsigned integer"))?;
            daemon.neg_ttl = n;
        }

        "max-ttl" => {
            let v = require_value("max-ttl")?;
            let n: u32 = v.parse().map_err(|_| invalid(v, "expected an unsigned integer"))?;
            daemon.max_ttl = n;
        }

        "min-cache-ttl" => {
            let v = require_value("min-cache-ttl")?;
            let n: u32 = v.parse().map_err(|_| invalid(v, "expected an unsigned integer"))?;
            daemon.min_cache_ttl = n;
        }

        "max-cache-ttl" => {
            let v = require_value("max-cache-ttl")?;
            let n: u32 = v.parse().map_err(|_| invalid(v, "expected an unsigned integer"))?;
            daemon.max_cache_ttl = n;
        }

        "edns-packet-max" => {
            let v = require_value("edns-packet-max")?;
            let n: u16 = v.parse().map_err(|_| invalid(v, "expected an unsigned integer"))?;
            daemon.edns_pktsz = n;
        }

        "domain" => {
            let v = require_value("domain")?;
            // Optionally "domain=name,subnet" — we only store the name part for now.
            let name = v.split(',').next().unwrap_or(v).trim().to_string();
            daemon.domain_suffix = Some(name);
        }

        "user" => {
            let v = require_value("user")?;
            daemon.username = Some(v.to_string());
        }

        "group" => {
            let v = require_value("group")?;
            daemon.groupname = Some(v.to_string());
        }

        "pid-file" => {
            let v = require_value("pid-file")?;
            daemon.runfile = Some(v.to_string());
        }

        "log-facility" => {
            let v = require_value("log-facility")?;
            daemon.log_file = Some(v.to_string());
        }

        "log-async" => {
            // Optional integer argument; default to 5 if not given.
            let n: i32 = cl.value.as_deref()
                .unwrap_or("5")
                .parse()
                .map_err(|_| invalid(cl.value.as_deref().unwrap_or(""), "expected an integer"))?;
            daemon.max_logs = n;
        }

        "resolv-file" => {
            let v = require_value("resolv-file")?;
            use crate::types::network::Resolvc;
            daemon.resolv_files.push(Resolvc {
                is_default: false,
                logged: false,
                mtime: 0,
                ino: 0,
                name: v.to_string(),
                #[cfg(feature = "inotify")]
                wd: -1,
                #[cfg(feature = "inotify")]
                file: None,
            });
        }

        "servers-file" => {
            let v = require_value("servers-file")?;
            daemon.servers_file = Some(v.to_string());
        }

        "lease-file" => {
            let v = require_value("lease-file")?;
            daemon.lease_file = Some(v.to_string());
        }

        // ── listen-address ─────────────────────────────────────────────────
        "listen-address" => {
            let v = require_value("listen-address")?;
            let ip: IpAddr = v.parse().map_err(|_| invalid(v, "expected an IP address"))?;
            let sock = match ip {
                IpAddr::V4(a) => MySockAddr::V4(SocketAddrV4::new(a, 0)),
                IpAddr::V6(a) => MySockAddr::V6(SocketAddrV6::new(a, 0, 0, 0)),
            };
            daemon.if_addrs.push(Iname {
                name: None,
                addr: Some(sock),
                flags: 0,
            });
        }

        // ── interface / except-interface ───────────────────────────────────
        "interface" => {
            let v = require_value("interface")?;
            daemon.if_names.push(Iname { name: Some(v.to_string()), addr: None, flags: 0 });
        }

        "except-interface" => {
            let v = require_value("except-interface")?;
            daemon.if_except.push(Iname { name: Some(v.to_string()), addr: None, flags: 0 });
        }

        // ── server ─────────────────────────────────────────────────────────
        //
        // Format: server=[/domain/[domain/...]]address[#port][@source[@port]]
        // Minimal implementation: parse address[#port] and optional /domain/ prefix.
        "server" | "local" | "address" => {
            let v = require_value(key)?;
            parse_server_or_address(daemon, key, v, cl)?;
        }

        // ── DHCP options (stubs) ────────────────────────────────────────────
        "dhcp-range" => {
            let _ = require_value("dhcp-range")?;
            // TODO: parse into DhcpRange and push to daemon.dhcp
        }

        "dhcp-host" => {
            let _ = require_value("dhcp-host")?;
            // TODO: parse into DhcpConfig and push to daemon.dhcp_conf
        }

        "dhcp-option" => {
            let _ = require_value("dhcp-option")?;
            // TODO: parse into DhcpOpt and push to daemon.dhcp_opts
        }

        "dhcp-boot" => {
            let _ = require_value("dhcp-boot")?;
            // TODO: parse into DhcpBoot and push to daemon.boot_config
        }

        "dhcp-leasefile" => {
            let v = require_value("dhcp-leasefile")?;
            daemon.lease_file = Some(v.to_string());
        }

        "dhcp-lease-max" => {
            let v = require_value("dhcp-lease-max")?;
            let n: i32 = v.parse().map_err(|_| invalid(v, "expected an integer"))?;
            daemon.dhcp_max = n;
        }

        "dhcp-ignore" => {
            let _ = require_value("dhcp-ignore")?;
            // TODO: implement dhcp-ignore tag matching
        }

        "dhcp-vendor" => {
            let _ = require_value("dhcp-vendor")?;
            // TODO: implement dhcp-vendor class matching
        }

        "dhcp-userclass" => {
            let _ = require_value("dhcp-userclass")?;
            // TODO: implement dhcp-userclass matching
        }

        "dhcp-circuitid" => {
            let _ = require_value("dhcp-circuitid")?;
            // TODO: implement dhcp-circuitid matching
        }

        "dhcp-subscrid" => {
            let _ = require_value("dhcp-subscrid")?;
            // TODO: implement dhcp-subscrid matching
        }

        "dhcp-remoteid" => {
            let _ = require_value("dhcp-remoteid")?;
            // TODO: implement dhcp-remoteid matching
        }

        "dhcp-mac" => {
            let _ = require_value("dhcp-mac")?;
            // TODO: implement dhcp-mac matching
        }

        "dhcp-reply-delay" => {
            let _ = require_value("dhcp-reply-delay")?;
            // TODO: store in daemon.delay_conf when field is added
        }

        "no-dhcp-interface" => {
            let v = require_value("no-dhcp-interface")?;
            daemon.dhcp_except.push(Iname { name: Some(v.to_string()), addr: None, flags: 0 });
        }

        // ── DNS record stubs ────────────────────────────────────────────────
        "mx-host" => {
            let _ = require_value("mx-host")?;
            // TODO: parse and push to daemon.mxnames
        }

        "srv-host" => {
            let _ = require_value("srv-host")?;
            // TODO: parse and push to daemon.mxnames (SRV)
        }

        "txt-record" => {
            let _ = require_value("txt-record")?;
            // TODO: parse and push to daemon.txt
        }

        "ptr-record" => {
            let _ = require_value("ptr-record")?;
            // TODO: parse and push to daemon.ptr
        }

        "host-record" => {
            let _ = require_value("host-record")?;
            // TODO: parse and push to daemon.host_records
        }

        "cname" => {
            let _ = require_value("cname")?;
            // TODO: parse and push to daemon.cnames
        }

        "naptr-record" => {
            let _ = require_value("naptr-record")?;
            // TODO: parse and push to daemon.naptr
        }

        "trust-anchor" => {
            let _ = require_value("trust-anchor")?;
            // TODO: parse and push to daemon.ds
        }

        // ── Additional hosts files ──────────────────────────────────────────
        "addn-hosts" | "addn-hosts-dir" | "hosts-dir" => {
            let v = require_value(key)?;
            daemon.addn_hosts.push(HostsFile { flags: 0, fname: v.to_string(), index: 0 });
        }

        // ── conf-dir (recursive config loading) ────────────────────────────
        "conf-dir" => {
            let _ = require_value("conf-dir")?;
            // TODO: recursively load config files from directory
        }

        // ── DNS forwarding limit ────────────────────────────────────────────
        "dns-forward-max" => {
            let _ = require_value("dns-forward-max")?;
            // TODO: store in daemon.dns_forward_max when field is added
        }

        // ── Auth zone ──────────────────────────────────────────────────────
        "auth-zone" => {
            let _ = require_value("auth-zone")?;
            // TODO: parse and push to daemon.auth_zones
        }

        // ── TFTP options ───────────────────────────────────────────────────
        "tftp-root" => {
            let v = require_value("tftp-root")?;
            #[cfg(feature = "tftp")]
            { daemon.tftp_prefix = Some(v.to_string()); }
            #[cfg(not(feature = "tftp"))]
            { let _ = v; }
        }

        "tftp-max" => {
            let v = require_value("tftp-max")?;
            let n: i32 = v.parse().map_err(|_| invalid(v, "expected an integer"))?;
            #[cfg(feature = "tftp")]
            { daemon.tftp_max = n; }
            #[cfg(not(feature = "tftp"))]
            { let _ = n; }
        }

        "tftp-unique-root" => {
            daemon.set_option(OPT_TFTP_APREF_IP);
        }

        // ── ipset / nftset ─────────────────────────────────────────────────
        "ipset" => {
            let _ = require_value("ipset")?;
            // TODO: parse and push to daemon.ipsets
        }

        "nftset" => {
            let _ = require_value("nftset")?;
            // TODO: parse nftset rules
        }

        // ── alias ─────────────────────────────────────────────────────────
        "alias" => {
            let _ = require_value("alias")?;
            // TODO: parse and push to daemon.doctors
        }

        // ── bogus-nxdomain ────────────────────────────────────────────────
        "bogus-nxdomain" => {
            let _ = require_value("bogus-nxdomain")?;
            // TODO: parse address and push to daemon.bogus_addr
        }

        // ── log-rotate ────────────────────────────────────────────────────
        "log-rotate" => {
            let _ = require_value("log-rotate")?;
            // TODO: store in daemon.log_maxlines when field is added
        }

        // ── DNS rebind protection ─────────────────────────────────────────
        "stop-dns-rebind" => {
            daemon.set_option(OPT_NO_REBIND);
        }

        "rebind-localhost-ok" => {
            daemon.set_option(OPT_LOCAL_REBIND);
        }

        "rebind-domain-ok" => {
            let _ = require_value("rebind-domain-ok")?;
            // TODO: parse domain and push to daemon.no_rebind
        }

        "no-rebind-localhost" => {
            // noop: clears rebind-localhost-ok; no action needed as default
        }

        // ── DNSSEC ────────────────────────────────────────────────────────
        "dnssec-check-unsigned" => {
            daemon.set_option(OPT_DNSSEC_IGN_NS);
        }

        // ── Boolean flags not yet in the bool section ─────────────────────
        "no-round-robin" => {
            daemon.set_option(OPT_NORR);
        }

        "bind-dynamic" => {
            daemon.set_option(OPT_CLEVERBIND);
        }

        "no-hosts6" => {
            // TODO: implement no-hosts6 (skip IPv6 /etc/hosts entries)
        }

        "filter-A" => {
            // TODO: implement filter-A when OPT_FILTER_A constant is added
        }

        "filter-AAAA" => {
            // TODO: implement filter-AAAA when OPT_FILTER_AAAA constant is added
        }

        "port-limit" => {
            // TODO: implement port-limit when OPT_PORTLIMIT constant is added
        }

        // ── no-resolv (with value is alias for resolv-file) ────────────────
        // already handled above as boolean; ignore if value present
        _ => {
            return Err(ConfigError::UnknownOption(
                key.to_string(),
                file.clone(),
                lineno,
            ));
        }
    }

    Ok(())
}

/// Parse a `server=`, `local=`, or `address=` directive.
///
/// Supported grammar (subset of dnsmasq):
/// - `server=1.2.3.4`
/// - `server=1.2.3.4#5353`
/// - `server=/example.com/1.2.3.4`
/// - `server=/example.com/example.org/1.2.3.4#53`
/// - `address=/example.com/1.2.3.4`   (literal address reply)
/// - `local=/example.com/`            (local-only, no upstream)
fn parse_server_or_address(
    daemon: &mut Daemon,
    key: &str,
    v: &str,
    cl: &ConfigLine,
) -> Result<(), ConfigError> {
    let invalid = |val: &str, reason: &str| -> ConfigError {
        ConfigError::InvalidValue(
            val.to_string(),
            key.to_string(),
            cl.file.clone(),
            cl.line,
            reason.to_string(),
        )
    };

    // Split optional /domain/ prefix from the address part.
    let (domains, addr_part): (Vec<String>, &str) = if v.starts_with('/') {
        // /dom1/dom2/.../address  — last segment is the address
        let inner = v.trim_start_matches('/');
        let parts: Vec<&str> = inner.split('/').collect();
        if parts.is_empty() {
            return Err(invalid(v, "empty domain list"));
        }
        // Last entry is the address; everything before it is domain names.
        let addr_segment: &str = parts.last().copied().unwrap_or("");
        let doms: Vec<String> = parts[..parts.len() - 1]
            .iter()
            .filter(|d| !d.is_empty())
            .map(|d| d.to_string())
            .collect();
        // We need addr_segment to live long enough — it points into `v`.
        // Use split_at on v to get a `&str` with the correct lifetime.
        let offset = v.rfind('/').unwrap() + 1;
        (doms, &v[offset..])
    } else {
        (vec![], v)
    };

    // Empty address is allowed for `local=` (means "answer locally with NXDOMAIN")
    if addr_part.is_empty() {
        return Ok(());
    }

    // Split address[#port]
    let (addr_and_at, port_str) = if let Some(hash) = addr_part.find('#') {
        (&addr_part[..hash], Some(&addr_part[hash + 1..]))
    } else {
        (addr_part, None)
    };

    // Ignore @source
    let addr_str: &str = addr_and_at.split('@').next().unwrap_or(addr_and_at);

    let ip: IpAddr = addr_str.parse().map_err(|_| invalid(addr_str, "expected an IP address"))?;

    let port: u16 = if let Some(ps) = port_str {
        let ps_clean: &str = ps.split('@').next().unwrap_or(ps);
        ps_clean.parse().map_err(|_| invalid(ps_clean, "expected a port number"))?
    } else {
        53
    };

    let sock = match ip {
        IpAddr::V4(a) => MySockAddr::V4(SocketAddrV4::new(a, port)),
        IpAddr::V6(a) => MySockAddr::V6(SocketAddrV6::new(a, port, 0, 0)),
    };

    let mut flags = match ip {
        IpAddr::V4(_) => SERV_4ADDR,
        IpAddr::V6(_) => SERV_6ADDR,
    };

    if key == "address" {
        flags |= SERV_LITERAL_ADDRESS;
    }

    let dummy_addr = MySockAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0));

    if domains.is_empty() {
        daemon.servers.push(new_server(flags, String::new(), sock, dummy_addr));
    } else {
        for domain in domains {
            daemon.servers.push(new_server(flags, domain, sock.clone(), dummy_addr.clone()));
        }
    }

    Ok(())
}

fn new_server(flags: u16, domain: String, addr: MySockAddr, source_addr: MySockAddr) -> Server {
    Server {
        flags,
        domain,
        addr,
        source_addr,
        interface: String::new(),
        ifindex: 0,
        queries: 0,
        failed_queries: 0,
        nxdomain_replies: 0,
        retrys: 0,
        query_latency: 0,
        mma_latency: 0,
        forwardtime: None,
        forwardcount: 0,
        tcpfd: -1,
        serial: 0,
        arrayposn: -1,
        last_server: 0,
        #[cfg(feature = "loop")]
        uid: 0,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::daemon::Daemon;

    // ── parse_config_text ─────────────────────────────────────────────────

    #[test]
    fn parse_simple_key_value() {
        let lines = parse_config_text("port=5353", "test").unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].key, "port");
        assert_eq!(lines[0].value, Some("5353".to_string()));
        assert_eq!(lines[0].file, "test");
        assert_eq!(lines[0].line, 1);
    }

    #[test]
    fn parse_boolean_flag() {
        let lines = parse_config_text("no-resolv", "test").unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].key, "no-resolv");
        assert_eq!(lines[0].value, None);
    }

    #[test]
    fn parse_comment_lines_skipped() {
        let text = "# this is a comment\nport=53\n# another comment";
        let lines = parse_config_text(text, "test").unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].key, "port");
    }

    #[test]
    fn parse_blank_lines_skipped() {
        let text = "\n\nport=53\n\n";
        let lines = parse_config_text(text, "test").unwrap();
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].key, "port");
    }

    #[test]
    fn parse_multiple_directives() {
        let text = "port=5353\nno-resolv\ncache-size=1000";
        let lines = parse_config_text(text, "test").unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].key, "port");
        assert_eq!(lines[1].key, "no-resolv");
        assert_eq!(lines[2].key, "cache-size");
    }

    #[test]
    fn parse_line_numbers_correct() {
        let text = "# comment\nport=53\nno-resolv";
        let lines = parse_config_text(text, "test").unwrap();
        assert_eq!(lines[0].line, 2);
        assert_eq!(lines[1].line, 3);
    }

    #[test]
    fn parse_trims_whitespace() {
        let lines = parse_config_text("  port = 5353  ", "test").unwrap();
        assert_eq!(lines[0].key, "port");
        assert_eq!(lines[0].value, Some("5353".to_string()));
    }

    // ── apply_config ──────────────────────────────────────────────────────

    #[test]
    fn apply_port() {
        let mut d = Daemon::default();
        let lines = parse_config_text("port=5353", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.port, 5353);
    }

    #[test]
    fn apply_no_resolv() {
        let mut d = Daemon::default();
        let lines = parse_config_text("no-resolv", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_NO_RESOLV));
    }

    #[test]
    fn apply_bogus_priv() {
        let mut d = Daemon::default();
        let lines = parse_config_text("bogus-priv", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_BOGUSPRIV));
    }

    #[test]
    fn apply_expand_hosts() {
        let mut d = Daemon::default();
        let lines = parse_config_text("expand-hosts", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_EXPAND));
    }

    #[test]
    fn apply_log_queries() {
        let mut d = Daemon::default();
        let lines = parse_config_text("log-queries", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_LOG));
    }

    #[test]
    fn apply_cache_size() {
        let mut d = Daemon::default();
        let lines = parse_config_text("cache-size=500", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.cachesize, 500);
    }

    #[test]
    fn apply_domain() {
        let mut d = Daemon::default();
        let lines = parse_config_text("domain=example.com", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.domain_suffix, Some("example.com".to_string()));
    }

    #[test]
    fn apply_listen_address_v4() {
        let mut d = Daemon::default();
        let lines = parse_config_text("listen-address=192.168.1.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.if_addrs.len(), 1);
        let addr = d.if_addrs[0].addr.as_ref().unwrap();
        assert!(addr.is_v4());
    }

    #[test]
    fn apply_listen_address_v6() {
        let mut d = Daemon::default();
        let lines = parse_config_text("listen-address=::1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.if_addrs.len(), 1);
        let addr = d.if_addrs[0].addr.as_ref().unwrap();
        assert!(addr.is_v6());
    }

    #[test]
    fn apply_server_plain_ipv4() {
        let mut d = Daemon::default();
        let lines = parse_config_text("server=8.8.8.8", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert_eq!(d.servers[0].addr.port(), 53);
    }

    #[test]
    fn apply_server_with_port() {
        let mut d = Daemon::default();
        let lines = parse_config_text("server=8.8.8.8#5353", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers[0].addr.port(), 5353);
    }

    #[test]
    fn apply_server_with_domain() {
        let mut d = Daemon::default();
        let lines = parse_config_text("server=/example.com/8.8.8.8", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert_eq!(d.servers[0].domain, "example.com");
    }

    #[test]
    fn apply_server_multiple_domains() {
        let mut d = Daemon::default();
        let lines = parse_config_text("server=/a.com/b.com/8.8.8.8", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 2);
    }

    #[test]
    fn apply_unknown_option_error() {
        let mut d = Daemon::default();
        let lines = parse_config_text("totally-unknown-option=foo", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownOption(ref k, _, _) if k == "totally-unknown-option"));
    }

    #[test]
    fn apply_invalid_port_error() {
        let mut d = Daemon::default();
        let lines = parse_config_text("port=notanumber", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "port"));
    }

    #[test]
    fn apply_port_out_of_range_error() {
        let mut d = Daemon::default();
        let lines = parse_config_text("port=99999", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "port"));
    }

    #[test]
    fn error_display_unknown_option() {
        let err = ConfigError::UnknownOption("foo".into(), "dnsmasq.conf".into(), 42);
        assert!(err.to_string().contains("unknown option 'foo'"));
        assert!(err.to_string().contains("dnsmasq.conf:42"));
    }

    #[test]
    fn error_display_missing_value() {
        let err = ConfigError::MissingValue("port".into(), "dnsmasq.conf".into(), 7);
        assert!(err.to_string().contains("missing value for 'port'"));
        assert!(err.to_string().contains("dnsmasq.conf:7"));
    }

    #[test]
    fn error_display_invalid_value() {
        let err = ConfigError::InvalidValue(
            "abc".into(), "port".into(), "dnsmasq.conf".into(), 3, "bad".into(),
        );
        assert!(err.to_string().contains("invalid value 'abc'"));
        assert!(err.to_string().contains("for 'port'"));
    }

    #[test]
    fn parse_config_line_struct_fields() {
        // Verify ConfigLine derives PartialEq and Clone.
        let l1 = ConfigLine {
            key: "port".to_string(),
            value: Some("53".to_string()),
            file: "test".to_string(),
            line: 1,
        };
        let l2 = l1.clone();
        assert_eq!(l1, l2);
    }
}

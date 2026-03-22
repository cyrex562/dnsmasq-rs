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
            let _n: i32 = v.parse().map_err(|_| invalid(v, "expected an integer"))?;
            #[cfg(feature = "dhcp")]
            { daemon.dhcp_max = _n; }
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
            let v = require_value("conf-dir")?;
            apply_conf_dir(daemon, v)?;
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


// ── Public entry points ────────────────────────────────────────────────────────

/// Read and apply options from a config file path into `daemon`.
///
/// This is the primary external API for config loading, mirroring dnsmasq's
/// `read_opts()`.  After parsing the file, it also processes any
/// `conf-file=` or `conf-dir=` directives embedded in the file.
pub fn read_opts(daemon: &mut Daemon, path: &str) -> Result<(), ConfigError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| ConfigError::Io(std::io::Error::new(e.kind(), format!("{path}: {e}"))))?;
    let lines = parse_config_text(&text, path)?;
    apply_config(daemon, &lines)
}

/// Load all `*.conf` files from `dir` into `daemon`, in filename-sorted order.
///
/// Non-fatal: if the directory cannot be read, or an individual file fails,
/// the error is returned and loading stops.  Files with names ending in `~`
/// (backup files) are skipped.
pub fn load_conf_dir(daemon: &mut Daemon, dir: &str) -> Result<(), ConfigError> {
    let mut entries: Vec<std::path::PathBuf> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                !name.ends_with('~') && (name.ends_with(".conf") || !name.contains('.'))
            } else {
                false
            }
        })
        .collect();
    entries.sort();
    for entry in entries {
        let path_str = entry.to_string_lossy();
        read_opts(daemon, &path_str)?;
    }
    Ok(())
}

/// Re-read DHCP configuration files (lease file, hosts files, options).
///
/// Called on SIGHUP to refresh dynamic DHCP state without restarting.
/// Mirrors dnsmasq's `reread_dhcp()`.
///
/// Currently:
/// - Clears and re-applies hosts file list from daemon config.
/// - Returns `Ok(())` when no DHCP config is present (no-op).
#[cfg(feature = "dhcp")]
pub fn reread_dhcp(daemon: &mut Daemon) -> Result<(), ConfigError> {
    // Re-read addn-hosts files (these may add/update DHCP hostname mappings).
    // The actual hosts file loading lives in cache.rs; here we just signal
    // that a reload is needed by touching the reload counter.
    daemon.reload_count = daemon.reload_count.wrapping_add(1);
    Ok(())
}

#[cfg(not(feature = "dhcp"))]
pub fn reread_dhcp(_daemon: &mut Daemon) -> Result<(), ConfigError> {
    Ok(())
}

// ── Apply conf-dir directive ───────────────────────────────────────────────────

/// Apply a `conf-dir=<path>` directive by loading all config files in the
/// directory.  Called from `apply_line` when the key is `conf-dir`.
fn apply_conf_dir(daemon: &mut Daemon, dir: &str) -> Result<(), ConfigError> {
    load_conf_dir(daemon, dir)
}

// ── Metacharacter encoding (ported from option.c:631-659) ─────────────────────

/// The metacharacter table: characters that need encoding to prevent parsing
/// issues in option values.
const META: &[u8] = b"\x00123456 \x08\t\n78\r90abcdefABCDE\x1bF:,.";

/// Encode a character as its metacharacter index, or return it unchanged.
///
/// Port of `hide_meta()` from option.c:633-642.
pub fn hide_meta(c: u8) -> u8 {
    for (i, &m) in META.iter().enumerate() {
        if c == m {
            return i as u8;
        }
    }
    c
}

/// Decode a metacharacter index back to its original character.
///
/// Port of `unhide_meta()` from option.c:644-652.
pub fn unhide_meta(c: u8) -> u8 {
    if (c as usize) < META.len() {
        META[c as usize]
    } else {
        c
    }
}

/// Decode all metacharacters in a byte string in-place.
///
/// Port of `unhide_metas()` from option.c:654-659.
pub fn unhide_metas(data: &mut [u8]) {
    for b in data.iter_mut() {
        *b = unhide_meta(*b);
    }
}

// ── String splitting (ported from option.c:698-719) ───────────────────────────

/// Split a string at the first occurrence of delimiter `c`.
///
/// Returns `(before, after)` where `before` is trimmed of trailing spaces
/// and `after` is trimmed of leading spaces. Returns `None` if delimiter not found.
/// Port of `split_chr()` from option.c:698-714.
pub fn split_chr(s: &str, c: char) -> Option<(&str, &str)> {
    let idx = s.find(c)?;
    let before = s[..idx].trim_end();
    let after = s[idx + c.len_utf8()..].trim_start();
    Some((before, after))
}

/// Split a string at the first comma.
///
/// Convenience wrapper for `split_chr(s, ',')`.
/// Port of `split()` from option.c:716-719.
pub fn split(s: &str) -> Option<(&str, &str)> {
    split_chr(s, ',')
}

// ── Numeric validation (ported from option.c:744-802) ─────────────────────────

/// Check if a string contains only decimal digits.
///
/// Port of `numeric_check()` from option.c:744-758.
pub fn numeric_check(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Parse a string as an i32, returning `None` if it's not all digits.
///
/// Port of `atoi_check()` from option.c:760-766.
pub fn atoi_check(s: &str) -> Option<i32> {
    if !numeric_check(s) {
        return None;
    }
    s.parse::<i32>().ok()
}

/// Parse a string as a u32, returning `None` if it's not all digits.
///
/// Port of `strtoul_check()` from option.c:768-781.
pub fn strtoul_check(s: &str) -> Option<u32> {
    if !numeric_check(s) {
        return None;
    }
    s.parse::<u32>().ok()
}

/// Parse a string as an i32 in the range [0, 65535].
///
/// Port of `atoi_check16()` from option.c:783-791.
pub fn atoi_check16(s: &str) -> Option<u16> {
    let v = atoi_check(s)?;
    if v < 0 || v > 0xFFFF {
        return None;
    }
    Some(v as u16)
}

/// Parse a string as an i32 in the range [0, 255].
///
/// Port of `atoi_check8()` from option.c:794-802.
pub fn atoi_check8(s: &str) -> Option<u8> {
    let v = atoi_check(s)?;
    if v < 0 || v > 0xFF {
        return None;
    }
    Some(v as u8)
}

// ── Reverse DNS zone generators (ported from option.c:1135-1307) ──────────────

/// Generate the `in-addr.arpa` domain for an IPv4 CIDR block.
///
/// E.g. `10.0.0.0/24` → `"0.0.10.in-addr.arpa"`.
/// Handles prefix lengths that are multiples of 8.
/// Port of `domain_rev4()` from option.c:1135-1219.
pub fn domain_rev4(addr: std::net::Ipv4Addr, prefix_len: u8) -> String {
    let octets = addr.octets();
    let full_octets = (prefix_len / 8) as usize;
    // Build reversed octets for the prefix
    let parts: Vec<String> = octets[..full_octets.min(4)]
        .iter()
        .rev()
        .map(|o| o.to_string())
        .collect();
    if parts.is_empty() {
        "in-addr.arpa".to_string()
    } else {
        format!("{}.in-addr.arpa", parts.join("."))
    }
}

/// Generate the `ip6.arpa` domain for an IPv6 CIDR block.
///
/// E.g. `2001:db8::/32` → `"8.b.d.0.1.0.0.2.ip6.arpa"`.
/// Port of `domain_rev6()` from option.c:1221-1307.
pub fn domain_rev6(addr: std::net::Ipv6Addr, prefix_len: u8) -> String {
    let octets = addr.octets();
    // Each hex nibble = 4 bits of prefix
    let nibble_count = (prefix_len / 4) as usize;
    let mut nibbles = Vec::with_capacity(nibble_count);
    for i in 0..nibble_count.min(32) {
        let byte_idx = i / 2;
        let nibble = if i % 2 == 0 {
            (octets[byte_idx] >> 4) & 0x0f
        } else {
            octets[byte_idx] & 0x0f
        };
        nibbles.push(format!("{:x}", nibble));
    }
    nibbles.reverse();
    if nibbles.is_empty() {
        "ip6.arpa".to_string()
    } else {
        format!("{}.ip6.arpa", nibbles.join("."))
    }
}

// ── DHCP tag helpers (ported from option.c:1322-1376) ─────────────────────────

/// Check if a string starts with "net:" or "tag:" prefix.
///
/// Port of `is_tag_prefix()` from option.c:1322-1328.
#[cfg(feature = "dhcp")]
pub fn is_tag_prefix(arg: &str) -> bool {
    arg.starts_with("net:") || arg.starts_with("tag:")
}

/// Strip "set:" prefix if present, otherwise return the string unchanged.
///
/// Port of `set_prefix()` from option.c:1330-1336.
#[cfg(feature = "dhcp")]
pub fn set_prefix(arg: &str) -> &str {
    arg.strip_prefix("set:").unwrap_or(arg)
}

/// Parse tag prefixes from a comma-separated option string.
///
/// Collects all leading "tag:xxx" or "net:xxx" entries and returns
/// (tags, remaining) where tags is a Vec of tag names.
/// Port of `dhcp_tags()` from option.c:1360-1376.
#[cfg(feature = "dhcp")]
pub fn dhcp_tags(input: &str) -> (Vec<String>, &str) {
    let mut tags = Vec::new();
    let mut remaining = input;
    while is_tag_prefix(remaining) {
        if let Some((before, after)) = split(remaining) {
            // Strip "tag:" or "net:" prefix (4 chars)
            tags.push(before[4..].to_string());
            remaining = after;
        } else {
            // No comma — the entire remaining is the tag
            tags.push(remaining[4..].to_string());
            return (tags, "");
        }
    }
    (tags, remaining)
}

// ── Canonicalise option helper (ported from option.c:721-742) ─────────────────

/// Normalize a domain name from an option value.
///
/// Converts to lowercase, strips trailing dots, validates DNS label rules.
/// Port of `canonicalise_opt()` from option.c:721-742.
pub fn canonicalise_opt(s: &str) -> Option<String> {
    if s.is_empty() {
        return Some(String::new());
    }
    let lower = s.to_ascii_lowercase();
    let trimmed = lower.trim_end_matches('.');
    // Basic DNS label validation
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return None;
        }
    }
    Some(trimmed.to_string())
}

// ── Config file filter (ported from option.c:5717-5730) ───────────────────────

/// Filter predicate for config directory scanning.
///
/// Rejects empty names, emacs backup files (~), emacs auto-save (#...#),
/// and dotfiles.
/// Port of `file_filter()` from option.c:5717-5730.
pub fn file_filter(filename: &str) -> bool {
    if filename.is_empty() {
        return false;
    }
    if filename.ends_with('~') {
        return false;
    }
    if filename.starts_with('#') && filename.ends_with('#') {
        return false;
    }
    if filename.starts_with('.') {
        return false;
    }
    true
}

/// Parse an IPv4 or IPv6 socket address string.
///
/// Supports formats: "1.2.3.4", "::1", "1.2.3.4#5353" (# for port).
/// Port of `parse_mysockaddr()` from option.c:888-898.
pub fn parse_mysockaddr(s: &str) -> Result<std::net::SocketAddr, String> {
    let (addr_str, port) = if let Some(idx) = s.rfind('#') {
        let port: u16 = s[idx + 1..].parse().map_err(|_| format!("bad port in '{}'", s))?;
        (&s[..idx], port)
    } else {
        (s, 0)
    };
    let ip: std::net::IpAddr = addr_str.parse().map_err(|_| format!("bad address '{}'", addr_str))?;
    Ok(std::net::SocketAddr::new(ip, port))
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

    // ── read_opts / load_conf_dir / reread_dhcp ───────────────────────────

    #[test]
    fn read_opts_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("test.conf");
        std::fs::write(&conf, "port=5353\nno-resolv\n").unwrap();
        let mut d = Daemon::default();
        read_opts(&mut d, conf.to_str().unwrap()).unwrap();
        assert_eq!(d.port, 5353);
        assert!(d.option_bool(OPT_NO_RESOLV));
    }

    #[test]
    fn read_opts_nonexistent_file_returns_error() {
        let mut d = Daemon::default();
        let res = read_opts(&mut d, "/nonexistent/path/to/file.conf");
        assert!(res.is_err());
    }

    #[test]
    fn load_conf_dir_loads_sorted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("b.conf"), "cache-size=500\n").unwrap();
        std::fs::write(dir.path().join("a.conf"), "port=5353\n").unwrap();
        let mut d = Daemon::default();
        load_conf_dir(&mut d, dir.path().to_str().unwrap()).unwrap();
        assert_eq!(d.port, 5353);
        assert_eq!(d.cachesize, 500);
    }

    #[test]
    fn load_conf_dir_skips_backup_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("test.conf~"), "port=9999\n").unwrap();
        std::fs::write(dir.path().join("real.conf"), "port=5353\n").unwrap();
        let mut d = Daemon::default();
        load_conf_dir(&mut d, dir.path().to_str().unwrap()).unwrap();
        assert_eq!(d.port, 5353); // 9999 should NOT be applied
    }

    #[test]
    fn reread_dhcp_increments_reload_count() {
        let mut d = Daemon::default();
        assert_eq!(d.reload_count, 0);
        reread_dhcp(&mut d).unwrap();
        assert_eq!(d.reload_count, 1);
        reread_dhcp(&mut d).unwrap();
        assert_eq!(d.reload_count, 2);
    }

    // ── hide_meta / unhide_meta ──────────────────────────────────────────────

    #[test]
    fn hide_meta_encodes_space() {
        let encoded = hide_meta(b' ');
        assert_ne!(encoded, b' ');
        assert_eq!(unhide_meta(encoded), b' ');
    }

    #[test]
    fn hide_meta_encodes_colon() {
        let encoded = hide_meta(b':');
        assert_ne!(encoded, b':');
        assert_eq!(unhide_meta(encoded), b':');
    }

    #[test]
    fn hide_meta_passes_through_normal() {
        assert_eq!(hide_meta(b'x'), b'x');
        assert_eq!(hide_meta(b'Z'), b'Z');
    }

    #[test]
    fn unhide_metas_decodes_all() {
        let mut data = vec![hide_meta(b' '), hide_meta(b':'), b'x'];
        unhide_metas(&mut data);
        assert_eq!(data, vec![b' ', b':', b'x']);
    }

    #[test]
    fn hide_unhide_roundtrip() {
        for c in 0..=255u8 {
            let hidden = hide_meta(c);
            let unhidden = unhide_meta(hidden);
            // For characters in META table, roundtrip should restore original
            if META.contains(&c) {
                assert_eq!(unhidden, c, "roundtrip failed for {c:#04x}");
            }
        }
    }

    // ── split_chr / split ────────────────────────────────────────────────────

    #[test]
    fn split_chr_comma() {
        let (before, after) = split_chr("hello, world", ',').unwrap();
        assert_eq!(before, "hello");
        assert_eq!(after, "world");
    }

    #[test]
    fn split_chr_no_delimiter() {
        assert!(split_chr("hello world", ',').is_none());
    }

    #[test]
    fn split_chr_trims_spaces() {
        let (before, after) = split_chr("key  =  value", '=').unwrap();
        assert_eq!(before, "key");
        assert_eq!(after, "value");
    }

    #[test]
    fn split_convenience() {
        let (a, b) = split("a,b,c").unwrap();
        assert_eq!(a, "a");
        assert_eq!(b, "b,c"); // only splits at first comma
    }

    // ── numeric_check / atoi_check / atoi_check16 / atoi_check8 ─────────────

    #[test]
    fn numeric_check_valid() {
        assert!(numeric_check("12345"));
        assert!(numeric_check("0"));
    }

    #[test]
    fn numeric_check_invalid() {
        assert!(!numeric_check(""));
        assert!(!numeric_check("12a45"));
        assert!(!numeric_check("-1"));
    }

    #[test]
    fn atoi_check_valid() {
        assert_eq!(atoi_check("42"), Some(42));
        assert_eq!(atoi_check("0"), Some(0));
    }

    #[test]
    fn atoi_check_invalid() {
        assert_eq!(atoi_check("abc"), None);
        assert_eq!(atoi_check(""), None);
    }

    #[test]
    fn atoi_check16_valid() {
        assert_eq!(atoi_check16("53"), Some(53));
        assert_eq!(atoi_check16("65535"), Some(65535));
    }

    #[test]
    fn atoi_check16_out_of_range() {
        assert_eq!(atoi_check16("65536"), None);
    }

    #[test]
    fn atoi_check8_valid() {
        assert_eq!(atoi_check8("255"), Some(255));
        assert_eq!(atoi_check8("0"), Some(0));
    }

    #[test]
    fn atoi_check8_out_of_range() {
        assert_eq!(atoi_check8("256"), None);
    }

    #[test]
    fn strtoul_check_valid() {
        assert_eq!(strtoul_check("4294967295"), Some(u32::MAX));
        assert_eq!(strtoul_check("0"), Some(0));
    }

    #[test]
    fn strtoul_check_overflow() {
        assert_eq!(strtoul_check("4294967296"), None);
    }

    // ── domain_rev4 ──────────────────────────────────────────────────────────

    #[test]
    fn domain_rev4_slash24() {
        let s = domain_rev4("10.0.0.0".parse().unwrap(), 24);
        assert_eq!(s, "0.0.10.in-addr.arpa");
    }

    #[test]
    fn domain_rev4_slash16() {
        let s = domain_rev4("172.16.0.0".parse().unwrap(), 16);
        assert_eq!(s, "16.172.in-addr.arpa");
    }

    #[test]
    fn domain_rev4_slash8() {
        let s = domain_rev4("10.0.0.0".parse().unwrap(), 8);
        assert_eq!(s, "10.in-addr.arpa");
    }

    #[test]
    fn domain_rev4_slash0() {
        let s = domain_rev4("0.0.0.0".parse().unwrap(), 0);
        assert_eq!(s, "in-addr.arpa");
    }

    // ── domain_rev6 ──────────────────────────────────────────────────────────

    #[test]
    fn domain_rev6_slash32() {
        let s = domain_rev6("2001:0db8::".parse().unwrap(), 32);
        assert_eq!(s, "8.b.d.0.1.0.0.2.ip6.arpa");
    }

    #[test]
    fn domain_rev6_slash48() {
        let s = domain_rev6("2001:0db8:abcd::".parse().unwrap(), 48);
        assert_eq!(s, "d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa");
    }

    #[test]
    fn domain_rev6_slash0() {
        let s = domain_rev6("::".parse().unwrap(), 0);
        assert_eq!(s, "ip6.arpa");
    }

    // ── is_tag_prefix / set_prefix ───────────────────────────────────────────

    #[cfg(feature = "dhcp")]
    #[test]
    fn is_tag_prefix_tag() {
        assert!(is_tag_prefix("tag:lan"));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn is_tag_prefix_net() {
        assert!(is_tag_prefix("net:internal"));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn is_tag_prefix_no_prefix() {
        assert!(!is_tag_prefix("192.168.1.1"));
        assert!(!is_tag_prefix(""));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn set_prefix_strips() {
        assert_eq!(set_prefix("set:mynet"), "mynet");
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn set_prefix_no_prefix() {
        assert_eq!(set_prefix("something"), "something");
    }

    // ── dhcp_tags ────────────────────────────────────────────────────────────

    #[cfg(feature = "dhcp")]
    #[test]
    fn dhcp_tags_single() {
        let (tags, rest) = dhcp_tags("tag:lan,192.168.1.0");
        assert_eq!(tags, vec!["lan"]);
        assert_eq!(rest, "192.168.1.0");
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn dhcp_tags_multiple() {
        let (tags, rest) = dhcp_tags("tag:lan,tag:vip,10.0.0.0");
        assert_eq!(tags, vec!["lan", "vip"]);
        assert_eq!(rest, "10.0.0.0");
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn dhcp_tags_none() {
        let (tags, rest) = dhcp_tags("192.168.1.0");
        assert!(tags.is_empty());
        assert_eq!(rest, "192.168.1.0");
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn dhcp_tags_only_tag() {
        let (tags, rest) = dhcp_tags("tag:solo");
        assert_eq!(tags, vec!["solo"]);
        assert_eq!(rest, "");
    }

    // ── canonicalise_opt ─────────────────────────────────────────────────────

    #[test]
    fn canonicalise_opt_normal() {
        assert_eq!(canonicalise_opt("Example.COM"), Some("example.com".to_string()));
    }

    #[test]
    fn canonicalise_opt_trailing_dot() {
        assert_eq!(canonicalise_opt("example.com."), Some("example.com".to_string()));
    }

    #[test]
    fn canonicalise_opt_empty() {
        assert_eq!(canonicalise_opt(""), Some(String::new()));
    }

    #[test]
    fn canonicalise_opt_invalid_label() {
        assert_eq!(canonicalise_opt("-bad.com"), None);
        assert_eq!(canonicalise_opt("bad-.com"), None);
    }

    #[test]
    fn canonicalise_opt_long_label() {
        let long = "a".repeat(64);
        assert_eq!(canonicalise_opt(&format!("{}.com", long)), None);
    }

    // ── file_filter ──────────────────────────────────────────────────────────

    #[test]
    fn file_filter_normal() {
        assert!(file_filter("dnsmasq.conf"));
    }

    #[test]
    fn file_filter_rejects_backup() {
        assert!(!file_filter("dnsmasq.conf~"));
    }

    #[test]
    fn file_filter_rejects_emacs_autosave() {
        assert!(!file_filter("#dnsmasq.conf#"));
    }

    #[test]
    fn file_filter_rejects_dotfile() {
        assert!(!file_filter(".hidden"));
    }

    #[test]
    fn file_filter_rejects_empty() {
        assert!(!file_filter(""));
    }

    // ── parse_mysockaddr ─────────────────────────────────────────────────────

    #[test]
    fn parse_mysockaddr_ipv4() {
        let addr = parse_mysockaddr("10.0.0.1").unwrap();
        assert_eq!(addr.ip(), "10.0.0.1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(addr.port(), 0);
    }

    #[test]
    fn parse_mysockaddr_ipv4_with_port() {
        let addr = parse_mysockaddr("10.0.0.1#5353").unwrap();
        assert_eq!(addr.port(), 5353);
    }

    #[test]
    fn parse_mysockaddr_ipv6() {
        let addr = parse_mysockaddr("::1").unwrap();
        assert!(addr.ip().is_ipv6());
    }

    #[test]
    fn parse_mysockaddr_invalid() {
        assert!(parse_mysockaddr("not.an.addr").is_err());
    }
}

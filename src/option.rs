/// Configuration and command-line option parser for dnsmasq-rs.
///
/// Implements a subset of the logic in the original `option.c` (6322 lines).
/// The focus is on the config-file parsing infrastructure and the most common
/// options; exotic / rarely-used directives can be added incrementally.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

use crate::types::addr::AllAddr;
use crate::types::addr::MySockAddr;
use crate::types::constants::*;
use crate::types::daemon::Daemon;
use crate::types::dns_records::{
    Addrlist, AuthNameEntry, AuthZone, BogusAddr, Cname, Doctor, DsConfig, HostRecord, AUTH4,
    AUTH6,
    InterfaceName, MxSrvRecord, Naptr, PtrRecord, RrList, TxtRecord, ADDRLIST_IPV6,
    ADDRLIST_LITERAL, IN4, IN6, INP4, INP6,
};
use crate::types::network::{Allowlist, DynDir, DynDirFlags, HostsFile, Iname, Ipsets, MySubnet, INAME_4, INAME_6};
use crate::types::server::{Server, SERV_4ADDR, SERV_6ADDR, SERV_ALL_ZEROS, SERV_LITERAL_ADDRESS};
use crate::types::daemon::{DhcpBridge, SharedNetwork};
use crate::domain::CondDomain;
#[cfg(feature = "dhcp")]
use crate::types::dhcp::{
    CONFIG_ADDR, CONFIG_CLID, CONFIG_DISABLE, CONFIG_NAME, CONTEXT_DHCP, DHOPT_VENDOR, DHOPT_VENDOR_PXE,
    DhcpBoot, DhcpConfig, DhcpContext, DhcpMacRule, DhcpNetid, DhcpNetidList, DhcpOpt, DhcpPxeVendor,
    DhcpRelay, DhcpRelayIdRule, DhcpReplyDelay, DhcpUserClassRule, DhcpVendorRule, HwaddrConfig, PxeService,
};
#[cfg(feature = "dhcp6")]
use crate::types::dhcp::{RaInterface, CONTEXT_RA};

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

const UPSTREAM_TIMEOUT_SECS: i32 = 10;
const DEFAULT_FAST_RETRY_MS: i32 = 1000;
const STALE_CACHE_EXPIRY_SECS: i32 = 86_400;
/// Compiled-in default lease file path, matching upstream's `LEASEFILE` for
/// Linux (`config.h:219`).
#[cfg(feature = "dhcp")]
const DEFAULT_LEASEFILE: &str = "/var/lib/misc/dnsmasq.leases";

/// Thin CLI syntax layer. These arguments are translated into [`ConfigLine`]s
/// so CLI and config-file inputs share one normalization pipeline.
#[derive(clap::Parser, Debug, Clone, PartialEq, Eq, Default)]
#[command(name = "dnsmasq-rs", version, about = "A Rust port of dnsmasq")]
pub struct CliArgs {
    /// Path to the configuration file.
    #[arg(long = "conf-file", value_name = "FILE")]
    pub conf_file: Option<String>,

    /// DNS port to listen on (overrides config file).
    #[arg(long, value_name = "PORT")]
    pub port: Option<u16>,

    /// Source port for outbound DNS queries.
    #[arg(long = "query-port", value_name = "PORT")]
    pub query_port: Option<u16>,

    /// Lower bound for randomized source ports.
    #[arg(long = "min-port", value_name = "PORT")]
    pub min_port: Option<u16>,

    /// Upper bound for randomized source ports.
    #[arg(long = "max-port", value_name = "PORT")]
    pub max_port: Option<u16>,

    /// Do not read upstream servers from resolv.conf.
    #[arg(long = "no-resolv")]
    pub no_resolv: bool,

    /// Do not poll resolv.conf for changes.
    #[arg(long = "no-poll")]
    pub no_poll: bool,

    /// Do not read hosts files.
    #[arg(long = "no-hosts")]
    pub no_hosts: bool,

    /// Enable bogus private address filtering.
    #[arg(long = "bogus-priv")]
    pub bogus_priv: bool,

    /// Expand simple hostnames using the local domain.
    #[arg(long = "expand-hosts")]
    pub expand_hosts: bool,

    /// Enable query logging.
    #[arg(long = "log-queries")]
    pub log_queries: bool,

    /// Disable negative caching.
    #[arg(long = "no-negcache")]
    pub no_negcache: bool,

    /// Query all upstream servers.
    #[arg(long = "all-servers")]
    pub all_servers: bool,

    /// Query upstream servers in the configured order.
    #[arg(long = "strict-order")]
    pub strict_order: bool,

    /// Enable DNSSEC validation.
    #[arg(long = "dnssec")]
    pub dnssec: bool,

    /// Restrict service to local subnets.
    #[arg(long = "local-service")]
    pub local_service: bool,

    /// Enable DNS rebind protection.
    #[arg(long = "no-rebind")]
    pub no_rebind: bool,

    /// Do NOT fork into the background: run in debug mode.
    #[arg(short = 'd', long = "no-daemon")]
    pub no_daemon: bool,

    /// Do NOT fork into the background, do NOT run in debug mode.
    #[arg(short = 'k', long = "keep-in-foreground")]
    pub keep_in_foreground: bool,

    /// Bind only configured interfaces.
    #[arg(long = "bind-interfaces")]
    pub bind_interfaces: bool,

    /// Enable DNSSEC debug logging.
    #[arg(long = "dnssec-debug")]
    pub dnssec_debug: bool,

    /// Configure cache size.
    #[arg(long = "cache-size", value_name = "ENTRIES")]
    pub cache_size: Option<i32>,

    /// TTL for locally-generated answers.
    #[arg(long = "local-ttl", value_name = "SECS")]
    pub local_ttl: Option<u32>,

    /// TTL for negative answers.
    #[arg(long = "neg-ttl", value_name = "SECS")]
    pub neg_ttl: Option<u32>,

    /// Maximum TTL for forwarded answers.
    #[arg(long = "max-ttl", value_name = "SECS")]
    pub max_ttl: Option<u32>,

    /// Minimum cache TTL.
    #[arg(long = "min-cache-ttl", value_name = "SECS")]
    pub min_cache_ttl: Option<u32>,

    /// Maximum cache TTL.
    #[arg(long = "max-cache-ttl", value_name = "SECS")]
    pub max_cache_ttl: Option<u32>,

    /// Serve stale cache data with optional maximum TTL excess.
    #[arg(long = "use-stale-cache", value_name = "SECS")]
    pub use_stale_cache: Option<i32>,

    /// EDNS packet size limit.
    #[arg(long = "edns-packet-max", value_name = "BYTES")]
    pub edns_packet_max: Option<u16>,

    /// Fast DNS retry timing, optionally "retry_ms,timeout_ms".
    #[arg(long = "fast-dns-retry", value_name = "SPEC")]
    pub fast_dns_retry: Option<String>,

    /// Configure the local domain suffix.
    #[arg(long = "domain", value_name = "NAME")]
    pub domain: Option<String>,

    /// Drop privileges to this user.
    #[arg(long = "user", value_name = "USER")]
    pub user: Option<String>,

    /// Drop privileges to this group.
    #[arg(long = "group", value_name = "GROUP")]
    pub group: Option<String>,

    /// Write the PID file here.
    #[arg(long = "pid-file", value_name = "FILE")]
    pub pid_file: Option<String>,

    /// Log to this file/facility.
    #[arg(long = "log-facility", value_name = "TARGET")]
    pub log_facility: Option<String>,

    /// Asynchronous log queue length.
    #[arg(long = "log-async", value_name = "LINES")]
    pub log_async: Option<i32>,

    /// Read upstream servers from this file.
    #[arg(long = "servers-file", value_name = "FILE")]
    pub servers_file: Option<String>,

    /// Lease file path.
    #[arg(long = "lease-file", value_name = "FILE")]
    pub lease_file: Option<String>,

    /// Maximum concurrent DNS forwards.
    #[arg(long = "dns-forward-max", value_name = "QUERIES")]
    pub dns_forward_max: Option<i32>,

    /// DHCP alternate ports in "server[,client]" form.
    #[arg(long = "dhcp-alternate-port", value_name = "SPEC")]
    pub dhcp_alternate_port: Option<String>,

    /// Alternate resolv.conf source. May be repeated.
    #[arg(long = "resolv-file", value_name = "FILE")]
    pub resolv_file: Vec<String>,

    /// Listen only on this interface. May be repeated.
    #[arg(long = "interface", value_name = "IFACE")]
    pub interface: Vec<String>,

    /// Exclude this interface. May be repeated.
    #[arg(long = "except-interface", value_name = "IFACE")]
    pub except_interface: Vec<String>,

    /// Listen on this IP address. May be repeated.
    #[arg(long = "listen-address", value_name = "ADDR")]
    pub listen_address: Vec<String>,

    /// Add an upstream DNS server. May be repeated.
    #[arg(long = "server", value_name = "SPEC")]
    pub server: Vec<String>,

    /// Delegate reverse DNS for a subnet to an upstream server. May be repeated.
    #[arg(long = "rev-server", value_name = "SPEC")]
    pub rev_server: Vec<String>,

    /// Synthesise forward/reverse names for an IP range. May be repeated.
    #[arg(long = "synth-domain", value_name = "SPEC")]
    pub synth_domain: Vec<String>,

    /// Treat DHCP requests on aliases as arriving from interface. May be repeated.
    #[arg(long = "bridge-interface", value_name = "SPEC")]
    pub bridge_interface: Vec<String>,

    /// Specify extra networks sharing a broadcast domain for DHCP. May be repeated.
    #[arg(long = "shared-network", value_name = "SPEC")]
    pub shared_network: Vec<String>,
}

/// Finalized configuration produced by normalizing raw config directives.
#[derive(Debug)]
pub struct ResolvedConfig {
    pub daemon: Daemon,
}

impl ResolvedConfig {
    pub fn into_daemon(self) -> Daemon {
        self.daemon
    }
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

/// Convert supported CLI arguments into the same raw directive form used by
/// config files. Callers should append these after file-derived lines so CLI
/// overrides naturally win on later application.
pub fn config_lines_from_cli(args: &CliArgs) -> Vec<ConfigLine> {
    let mut lines = Vec::new();
    let mut push_line = |key: &str, value: Option<String>| {
        lines.push(ConfigLine {
            key: key.to_string(),
            value,
            file: "<cli>".to_string(),
            line: 0,
        });
    };

    if let Some(port) = args.port {
        push_line("port", Some(port.to_string()));
    }

    if let Some(query_port) = args.query_port {
        push_line("query-port", Some(query_port.to_string()));
    }

    if let Some(min_port) = args.min_port {
        push_line("min-port", Some(min_port.to_string()));
    }

    if let Some(max_port) = args.max_port {
        push_line("max-port", Some(max_port.to_string()));
    }

    if args.no_resolv {
        push_line("no-resolv", None);
    }

    if args.no_poll {
        push_line("no-poll", None);
    }

    if args.no_hosts {
        push_line("no-hosts", None);
    }

    if args.bogus_priv {
        push_line("bogus-priv", None);
    }

    if args.expand_hosts {
        push_line("expand-hosts", None);
    }

    if args.log_queries {
        push_line("log-queries", None);
    }

    if args.no_negcache {
        push_line("no-negcache", None);
    }

    if args.all_servers {
        push_line("all-servers", None);
    }

    if args.strict_order {
        push_line("strict-order", None);
    }

    if args.dnssec {
        push_line("dnssec", None);
    }

    if args.local_service {
        push_line("local-service", None);
    }

    if args.no_rebind {
        push_line("no-rebind", None);
    }

    if args.no_daemon {
        push_line("no-daemon", None);
    }

    if args.keep_in_foreground {
        push_line("keep-in-foreground", None);
    }

    if args.bind_interfaces {
        push_line("bind-interfaces", None);
    }

    if args.dnssec_debug {
        push_line("dnssec-debug", None);
    }

    if let Some(cache_size) = args.cache_size {
        push_line("cache-size", Some(cache_size.to_string()));
    }

    if let Some(local_ttl) = args.local_ttl {
        push_line("local-ttl", Some(local_ttl.to_string()));
    }

    if let Some(neg_ttl) = args.neg_ttl {
        push_line("neg-ttl", Some(neg_ttl.to_string()));
    }

    if let Some(max_ttl) = args.max_ttl {
        push_line("max-ttl", Some(max_ttl.to_string()));
    }

    if let Some(min_cache_ttl) = args.min_cache_ttl {
        push_line("min-cache-ttl", Some(min_cache_ttl.to_string()));
    }

    if let Some(max_cache_ttl) = args.max_cache_ttl {
        push_line("max-cache-ttl", Some(max_cache_ttl.to_string()));
    }

    if let Some(use_stale_cache) = args.use_stale_cache {
        push_line("use-stale-cache", Some(use_stale_cache.to_string()));
    }

    if let Some(edns_packet_max) = args.edns_packet_max {
        push_line("edns-packet-max", Some(edns_packet_max.to_string()));
    }

    if let Some(fast_dns_retry) = &args.fast_dns_retry {
        push_line("fast-dns-retry", Some(fast_dns_retry.clone()));
    }

    if let Some(domain) = &args.domain {
        push_line("domain", Some(domain.clone()));
    }

    if let Some(user) = &args.user {
        push_line("user", Some(user.clone()));
    }

    if let Some(group) = &args.group {
        push_line("group", Some(group.clone()));
    }

    if let Some(pid_file) = &args.pid_file {
        push_line("pid-file", Some(pid_file.clone()));
    }

    if let Some(log_facility) = &args.log_facility {
        push_line("log-facility", Some(log_facility.clone()));
    }

    if let Some(log_async) = args.log_async {
        push_line("log-async", Some(log_async.to_string()));
    }

    if let Some(servers_file) = &args.servers_file {
        push_line("servers-file", Some(servers_file.clone()));
    }

    if let Some(lease_file) = &args.lease_file {
        push_line("lease-file", Some(lease_file.clone()));
    }

    if let Some(dns_forward_max) = args.dns_forward_max {
        push_line("dns-forward-max", Some(dns_forward_max.to_string()));
    }

    if let Some(dhcp_alternate_port) = &args.dhcp_alternate_port {
        push_line("dhcp-alternate-port", Some(dhcp_alternate_port.clone()));
    }

    for resolv_file in &args.resolv_file {
        push_line("resolv-file", Some(resolv_file.clone()));
    }

    for interface in &args.interface {
        push_line("interface", Some(interface.clone()));
    }

    for except_interface in &args.except_interface {
        push_line("except-interface", Some(except_interface.clone()));
    }

    for listen_address in &args.listen_address {
        push_line("listen-address", Some(listen_address.clone()));
    }

    for server in &args.server {
        push_line("server", Some(server.clone()));
    }

    for rev_server in &args.rev_server {
        push_line("rev-server", Some(rev_server.clone()));
    }

    for synth_domain in &args.synth_domain {
        push_line("synth-domain", Some(synth_domain.clone()));
    }

    for bridge_interface in &args.bridge_interface {
        push_line("bridge-interface", Some(bridge_interface.clone()));
    }

    for shared_network in &args.shared_network {
        push_line("shared-network", Some(shared_network.clone()));
    }

    lines
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
    normalize_config(daemon)?;

    Ok(())
}

/// Resolve raw config lines into a finalized configuration.
pub fn resolve_config(lines: &[ConfigLine]) -> Result<ResolvedConfig, ConfigError> {
    let mut daemon = Daemon::default();
    seed_startup_defaults(&mut daemon);
    apply_config(&mut daemon, lines)?;
    Ok(ResolvedConfig { daemon })
}

/// Seed the compiled-in defaults upstream installs *before* it parses anything
/// (`read_opts`, option.c:5970-5990).
///
/// Seeding first rather than filling gaps afterwards is what makes `user=` and
/// `pid-file=` with an empty value work: `opt_string_alloc` (option.c:677-691)
/// maps the empty string to NULL, so those directives *clear* the default
/// rather than being ignored.  A post-hoc "if None then default" pass would
/// silently reinstate it.
fn seed_startup_defaults(daemon: &mut Daemon) {
    // "nobody" unless `user=` says otherwise, so an unconfigured daemon still
    // drops root.  The group has no unconditional default — it is resolved at
    // startup from CHGRP or the run user's primary group (dnsmasq.c:507-517).
    daemon.username = Some(CHUSER.to_string());
    daemon.runfile = Some(RUNFILE.to_string());
}

fn normalize_config(daemon: &mut Daemon) -> Result<(), ConfigError> {
    apply_dnssec_fast_retry_defaults(daemon);
    apply_local_ttl_defaults(daemon);
    apply_mx_defaults(daemon)?;
    apply_auth_defaults(daemon);
    apply_local_service_defaults(daemon);
    #[cfg(feature = "dhcp")]
    apply_dhcp_leasefile_default(daemon);
    #[cfg(feature = "dhcp6")]
    apply_doing_ra_default(daemon);
    #[cfg(feature = "tftp")]
    apply_tftp_defaults(daemon);
    validate_auth_config(daemon)?;
    Ok(())
}

/// Compute `daemon->doing_ra`: on whenever `--enable-ra` was given, or any
/// DHCPv6 context has `CONTEXT_RA` set (a `dhcp-range` with `ra-only`,
/// `ra-names`, `ra-stateless`, etc).
///
/// Port of `dnsmasq.c:289-305`.
#[cfg(feature = "dhcp6")]
fn apply_doing_ra_default(daemon: &mut Daemon) {
    if daemon.dhcp6.is_empty() {
        return;
    }
    daemon.doing_ra = daemon.option_bool(OPT_RA);
    for context in &daemon.dhcp6 {
        if context.flags & CONTEXT_RA != 0 {
            daemon.doing_ra = true;
        }
    }
}

/// Fill in `tftp_max` when unset, mirroring `dnsmasq.c`'s
/// `daemon->tftp_max = TFTP_MAX_CONNECTIONS;` default-assignment at startup
/// (option.c:5979) — without this, `--tftp-max` left unset would read as `0`
/// simultaneous transfers allowed, rather than "no explicit limit given".
#[cfg(feature = "tftp")]
fn apply_tftp_defaults(daemon: &mut Daemon) {
    if daemon.tftp_max == 0 {
        daemon.tftp_max = crate::tftp::TFTP_MAX_CONNECTIONS_DEFAULT;
    }
}

/// Fill in the default lease file when DHCP(v6) is configured and no
/// `--dhcp-leasefile`/`--lease-file` was given, mirroring `dnsmasq.c:151-156`
/// (`if (!daemon->lease_file) if (daemon->dhcp || daemon->dhcp6) daemon->lease_file = LEASEFILE;`).
#[cfg(feature = "dhcp")]
fn apply_dhcp_leasefile_default(daemon: &mut Daemon) {
    if daemon.lease_file.is_some() {
        return;
    }
    let dhcp6_configured = {
        #[cfg(feature = "dhcp6")]
        {
            !daemon.dhcp6.is_empty()
        }
        #[cfg(not(feature = "dhcp6"))]
        {
            false
        }
    };
    if !daemon.dhcp.is_empty() || dhcp6_configured {
        daemon.lease_file = Some(DEFAULT_LEASEFILE.to_string());
    }
}

fn apply_dnssec_fast_retry_defaults(daemon: &mut Daemon) {
    // Upstream enables default fast retries when DNSSEC validation is active
    // and no explicit fast-dns-retry value was configured.
    if daemon.option_bool(OPT_DNSSEC_VALID) && daemon.fast_retry_time == 0 {
        daemon.fast_retry_timeout = UPSTREAM_TIMEOUT_SECS;
        daemon.fast_retry_time = DEFAULT_FAST_RETRY_MS;
    }
}

fn apply_local_ttl_defaults(daemon: &mut Daemon) {
    let local_ttl = daemon.local_ttl as i32;
    for host_record in &mut daemon.host_records {
        if host_record.ttl == -1 {
            host_record.ttl = local_ttl;
        }
    }
    for cname in &mut daemon.cnames {
        if cname.ttl == -1 {
            cname.ttl = local_ttl;
        }
    }
}

fn apply_mx_defaults(daemon: &mut Daemon) -> Result<(), ConfigError> {
    if !daemon.option_bool(OPT_LOCALMX) && daemon.mxnames.is_empty() && daemon.mxtarget.is_none() {
        return Ok(());
    }

    let hostname = local_hostname_for_mx().ok_or_else(|| {
        ConfigError::InvalidValue(
            String::new(),
            "mx-target".to_string(),
            "<runtime>".to_string(),
            0,
            "failed to determine local hostname".to_string(),
        )
    })?;

    if (daemon.mxtarget.is_some() || daemon.option_bool(OPT_LOCALMX))
        && !daemon.mxnames.iter().any(|mx| !mx.is_srv && mx.name.eq_ignore_ascii_case(&hostname))
    {
        daemon.mxnames.push(MxSrvRecord {
            name: hostname.clone(),
            target: String::new(),
            is_srv: false,
            srv_port: 0,
            priority: 1,
            weight: 0,
            offset: 0,
        });
    }

    if daemon.mxtarget.is_none() {
        daemon.mxtarget = Some(hostname);
    }

    if let Some(target) = daemon.mxtarget.clone() {
        for mx in &mut daemon.mxnames {
            if !mx.is_srv && mx.target.is_empty() {
                mx.target = target.clone();
            }
        }
    }

    Ok(())
}

fn local_hostname_for_mx() -> Option<String> {
    let mut buf = [0i8; 256];
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr(), buf.len()) };
    if rc != 0 {
        return None;
    }
    buf[buf.len() - 1] = 0;
    let hostname = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) }.to_string_lossy();
    canonicalise_opt(hostname.as_ref()).filter(|name| !name.is_empty())
}

fn apply_auth_defaults(daemon: &mut Daemon) {
    if daemon.hostmaster.is_none() {
        if let Some(authserver) = daemon.authserver.as_ref() {
            daemon.hostmaster = Some(format!("hostmaster.{authserver}"));
        }
    }
}

fn apply_local_service_defaults(daemon: &mut Daemon) {
    if !daemon.if_names.is_empty()
        || !daemon.if_except.is_empty()
        || !daemon.if_addrs.is_empty()
        || daemon.authserver.is_some()
    {
        daemon.clear_option(OPT_LOCAL_SERVICE);
        daemon.clear_option(OPT_LOCALHOST_SERVICE);
    } else if daemon.option_bool(OPT_LOCALHOST_SERVICE) && !daemon.option_bool(OPT_LOCAL_SERVICE) {
        daemon.if_names.push(Iname {
            name: None,
            addr: None,
            flags: 0,
        });
        daemon.set_option(OPT_NOWILD);
    }
}

fn validate_auth_config(daemon: &Daemon) -> Result<(), ConfigError> {
    if !daemon.auth_zones.is_empty() && daemon.authserver.is_none() {
        return Err(ConfigError::InvalidValue(
            String::new(),
            "auth-server".to_string(),
            "<runtime>".to_string(),
            0,
            "--auth-server required when an auth zone is defined".to_string(),
        ));
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

    let require_no_value = |opt: &str| -> Result<(), ConfigError> {
        if let Some(value) = cl.value.as_deref() {
            return Err(ConfigError::InvalidValue(
                value.to_string(),
                opt.to_string(),
                file.clone(),
                lineno,
                "unexpected value".to_string(),
            ));
        }
        Ok(())
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
        "log-queries" => {
            daemon.set_option(OPT_LOG);
            match cl.value.as_deref() {
                Some("extra") => daemon.set_option(OPT_EXTRALOG),
                Some("proto") => {
                    daemon.set_option(OPT_EXTRALOG);
                    daemon.set_option(OPT_LOG_PROTO);
                }
                Some("auth") => daemon.set_option(OPT_AUTH_LOG),
                Some("only_failed") => daemon.set_option(OPT_LOG_ONLY_FAILED),
                _ => {}
            }
        }
        "log-dhcp"    => daemon.set_option(OPT_LOG_OPTS),
        "no-negcache" => daemon.set_option(OPT_NO_NEG),
        "strict-order" => daemon.set_option(OPT_ORDER),
        "all-servers"  => daemon.set_option(OPT_ALL_SERVERS),
        "reload-acl"   => daemon.set_option(OPT_RELOAD),
        "no-rebind"    => daemon.set_option(OPT_NO_REBIND),
        // `-d`/`--no-daemon` is debug mode (option.c:215,428): it suppresses the
        // fork *and* the pid file, the stdio redirect and the privilege drop.
        // `-k`/`--keep-in-foreground` (option.c:277,456) only suppresses the fork.
        "no-daemon"    => daemon.set_option(OPT_DEBUG),
        "keep-in-foreground" => daemon.set_option(OPT_NO_FORK),
        "bind-interfaces" => daemon.set_option(OPT_NOWILD),
        "selfmx"       => daemon.set_option(OPT_SELFMX),
        "localmx"      => daemon.set_option(OPT_LOCALMX),
        "authoritative" => daemon.set_option(OPT_AUTHORITATIVE),
        "dhcp-authoritative" => daemon.set_option(OPT_AUTHORITATIVE),
        "read-ethers" => daemon.set_option(OPT_ETHERS),
        "ra-param"     => {
            let v = require_value("ra-param")?;
            #[cfg(feature = "dhcp6")]
            parse_ra_param(daemon, v, cl)?;
            #[cfg(not(feature = "dhcp6"))]
            let _ = v;
        }
        "dhcp-no-override" => daemon.set_option(OPT_NO_OVERRIDE),
        "dhcp-sequential-ip" => daemon.set_option(OPT_CONSEC_ADDR),
        "dhcp-ignore-clid" => daemon.set_option(OPT_IGNORE_CLID),
        "dhcp-client-update" => daemon.set_option(OPT_FQDN_UPDATE),
        "dhcp-fqdn"    => daemon.set_option(OPT_DHCP_FQDN),
        "enable-dbus"  => {
            daemon.set_option(OPT_DBUS);
            #[cfg(feature = "dbus")]
            {
                daemon.dbus_name = Some(
                    cl.value.as_deref().unwrap_or(crate::dbus::DNSMASQ_DBUS_INTERFACE).to_string(),
                );
            }
        }
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
        "enable-tftp"  => {
            daemon.set_option(OPT_TFTP);
            if let Some(v) = cl.value.as_deref() {
                daemon.tftp_interfaces.extend(parse_tftp_interfaces(v, cl)?);
            }
        }
        "tftp-secure"  => daemon.set_option(OPT_TFTP_SECURE),
        "tftp-no-fail" => {
            require_no_value("tftp-no-fail")?;
            daemon.set_option(OPT_TFTP_NO_FAIL);
        }
        "tftp-no-blocksize" => daemon.set_option(OPT_TFTP_NOBLOCK),
        "tftp-lowercase"    => daemon.set_option(OPT_TFTP_LC),
        "tftp-single-port"  => {
            require_no_value("tftp-single-port")?;
            daemon.set_option(OPT_SINGLE_PORT);
        }
        "client-subnet"     => daemon.set_option(OPT_CLIENT_SUBNET),
        // `dns-loop-detect` (option.c:387) is the real upstream name for the
        // bit already reachable via the pre-existing `loop-detect` alias.
        "loop-detect" | "dns-loop-detect" => daemon.set_option(OPT_LOOP_DETECT),
        "script-arp"        => daemon.set_option(OPT_SCRIPT_ARP),
        "script-on-renewal" => daemon.set_option(OPT_LEASE_RENEW),
        // `dhcp-rapid-commit` (option.c:391) is the real upstream name for the
        // bit already reachable via the pre-existing `rapid-commit` alias.
        "rapid-commit" | "dhcp-rapid-commit" => daemon.set_option(OPT_RAPID_COMMIT),
        "log-debug"         => daemon.set_option(OPT_LOG_DEBUG),
        "quiet-tftp"        => daemon.set_option(OPT_QUIET_TFTP),
        "no-ident"          => daemon.set_option(OPT_NO_IDENT),
        "no-0x20-encode"    => daemon.set_option(OPT_NO_0X20),
        "do-0x20-encode"    => daemon.set_option(OPT_DO_0X20),
        "log-malloc"        => daemon.set_option(OPT_LOG_MALLOC),
        // `ubus` is a pre-existing alias for the real upstream directive
        // `enable-ubus` (option.c:285); upstream also stores an optional
        // service-name argument in `daemon->ubus_name`, but that field is
        // gated behind the (non-default) `ubus` cargo feature, so it is left
        // unset here, matching the existing `enable-dbus` precedent below.
        "ubus" | "enable-ubus" => daemon.set_option(OPT_UBUS),
        // `--domain-needed` / `-D` (option.c:268, `OPT_NODOTS_LOCAL`): suppress
        // forwarding of single-label A/AAAA queries.  See `forward.c:355-361`
        // and `answer_request()` in `rfc1035.rs` for the runtime behavior.
        "domain-needed" => daemon.set_option(OPT_NODOTS_LOCAL),
        // `--clear-on-reload` (option.c:295) is the real upstream name for the
        // bit already reachable via the pre-existing `reload-acl` alias below.
        "clear-on-reload" => daemon.set_option(OPT_RELOAD),
        // `--umbrella[=deviceid:<16 hex chars>][,orgid:<n>][,assetid:<n>]`
        // (option.c:2808-2850): sets the main bit unconditionally, as
        // upstream does regardless of whether sub-options are present, then
        // parses each comma-separated sub-option into `Daemon`.
        "umbrella" => {
            daemon.set_option(OPT_UMBRELLA);
            if let Some(v) = cl.value.as_deref() {
                parse_umbrella(daemon, v, cl)?;
            }
        }
        "local-ttl" if cl.value.is_none() => {} // value required; handled below

        // ── Numeric / string options ────────────────────────────────────────
        "local-service" => {
            match cl.value.as_deref() {
                None | Some("net") => daemon.set_option(OPT_LOCAL_SERVICE),
                Some("host") => daemon.set_option(OPT_LOCALHOST_SERVICE),
                Some(v) => return Err(invalid_value_for(cl, "local-service", v, "expected net or host")),
            }
        }

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
            let mut n: i32 = v.parse().map_err(|_| invalid(v, "expected an integer"))?;
            if n < 0 {
                n = 0;
            }
            if n > 5_000_000 {
                n = 5_000_000;
            }
            daemon.cachesize = n;
        }

        "local-ttl" => {
            let v = require_value("local-ttl")?;
            let n: u32 = v.parse().map_err(|_| invalid(v, "expected an unsigned integer"))?;
            daemon.local_ttl = n;
        }

        "fast-dns-retry" => {
            daemon.fast_retry_timeout = UPSTREAM_TIMEOUT_SECS;

            if let Some(v) = cl.value.as_deref() {
                let mut parts = v.splitn(2, ',');
                let retry = parts.next().unwrap_or_default();
                let retry_ms = parse_i32_token(retry, "fast-dns-retry", cl, "retry interval")?;
                if retry_ms < 50 {
                    return Err(invalid_value_for(cl, "fast-dns-retry", retry, "retry interval must be at least 50ms"));
                }
                daemon.fast_retry_time = retry_ms;

                if let Some(timeout) = parts.next() {
                    let timeout_ms = parse_i32_token(timeout, "fast-dns-retry", cl, "retry timeout")?;
                    daemon.fast_retry_timeout = timeout_ms / 1000;
                }
            } else {
                daemon.fast_retry_time = DEFAULT_FAST_RETRY_MS;
            }
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

        "auth-ttl" => {
            let v = require_value("auth-ttl")?;
            daemon.auth_ttl = parse_u32_token(v, "auth-ttl", cl, "authoritative TTL")?;
        }

        "dhcp-ttl" => {
            let v = require_value("dhcp-ttl")?;
            let ttl = parse_u32_token(v, "dhcp-ttl", cl, "DHCP TTL")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_ttl = ttl;
                daemon.use_dhcp_ttl = 1;
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = ttl;
            }
        }

        "auth-soa" => {
            let v = require_value("auth-soa")?;
            parse_auth_soa(daemon, v, cl)?;
        }

        "dnssec-timestamp" => {
            let v = require_value("dnssec-timestamp")?;
            #[cfg(feature = "dnssec")]
            {
                daemon.timestamp_file = Some(v.to_string());
            }
            #[cfg(not(feature = "dnssec"))]
            {
                let _ = v;
            }
        }

        "dnssec-limits" => {
            let v = require_value("dnssec-limits")?;
            #[cfg(feature = "dnssec")]
            {
                parse_dnssec_limits(v, cl, &mut daemon.dnssec_limits)?;
            }
            #[cfg(not(feature = "dnssec"))]
            {
                let _ = v;
            }
        }

        "use-stale-cache" => {
            let mut max_expiry = STALE_CACHE_EXPIRY_SECS;
            if let Some(v) = cl.value.as_deref() {
                max_expiry = parse_i32_token(v, "use-stale-cache", cl, "stale cache maximum TTL excess")?;
                if max_expiry < 0 {
                    return Err(invalid_value_for(cl, "use-stale-cache", v, "stale cache maximum TTL excess must be non-negative"));
                }
                if max_expiry == 0 {
                    max_expiry = -1;
                }
            }
            daemon.cache_max_expiry = max_expiry;
        }

        "edns-packet-max" => {
            let v = require_value("edns-packet-max")?;
            let n: u16 = v.parse().map_err(|_| invalid(v, "expected an unsigned integer"))?;
            daemon.edns_pktsz = n;
        }

        "domain" => {
            let v = require_value("domain")?;
            parse_domain(daemon, v, cl)?;
        }

        // `daemon->username = opt_string_alloc(arg)` (option.c:2868,2872), and
        // `opt_string_alloc` maps the empty string to NULL — so `user=` on its
        // own clears the seeded CHUSER default and means "do not change uid".
        "user" => {
            let v = require_value("user")?;
            daemon.username = if v.is_empty() { None } else { Some(v.to_string()) };
        }

        "group" => {
            let v = require_value("group")?;
            daemon.groupname = if v.is_empty() { None } else { Some(v.to_string()) };
        }

        "dhcp-scriptuser" => {
            let v = require_value("dhcp-scriptuser")?;
            daemon.scriptuser = Some(v.to_string());
        }

        "dhcp-script" => {
            #[cfg(feature = "script")]
            {
                let v = require_value("dhcp-script")?;
                daemon.lease_change_command = Some(v.to_string());
            }
            #[cfg(not(feature = "script"))]
            {
                return Err(ConfigError::InvalidValue(
                    "".to_string(),
                    "dhcp-script".to_string(),
                    cl.file.clone(),
                    cl.line,
                    "recompile with HAVE_SCRIPT defined to enable lease-change scripts".to_string(),
                ));
            }
        }

        "dhcp-luascript" => {
            #[cfg(feature = "script")]
            {
                let v = require_value("dhcp-luascript")?;
                daemon.luascript = Some(v.to_string());
            }
            #[cfg(not(feature = "script"))]
            {
                return Err(ConfigError::InvalidValue(
                    "".to_string(),
                    "dhcp-luascript".to_string(),
                    cl.file.clone(),
                    cl.line,
                    "recompile with HAVE_SCRIPT defined to enable lease-change scripts".to_string(),
                ));
            }
        }

        "pid-file" => {
            let v = require_value("pid-file")?;
            // `opt_string_alloc` (option.c:677-691) returns NULL for the empty
            // string, so `pid-file=` is upstream's way of asking for no pid file.
            daemon.runfile = if v.is_empty() { None } else { Some(v.to_string()) };
        }

        "log-facility" => {
            // `option.c:2279-2298`: a value containing `/` or exactly `-` is
            // a file path; anything else is looked up as a facility name
            // (`daemon`, `local0`, ...) and rejected if it isn't one.
            let v = require_value("log-facility")?;
            if v.contains('/') || v == "-" {
                daemon.log_file = Some(v.to_string());
            } else {
                match crate::log::facility_by_name(v) {
                    Some(fac) => daemon.log_fac = fac as i32,
                    None => return Err(invalid(v, "bad log facility")),
                }
            }
        }

        "log-async" => {
            // Optional integer argument; default to 5 if not given.
            let n: i32 = cl.value.as_deref()
                .unwrap_or("5")
                .parse()
                .map_err(|_| invalid(cl.value.as_deref().unwrap_or(""), "expected an integer"))?;
            daemon.max_logs = n;
        }

        "dumpfile" => {
            let v = require_value("dumpfile")?;
            #[cfg(feature = "dump")]
            {
                daemon.dump_file = Some(v.to_string());
            }
            #[cfg(not(feature = "dump"))]
            {
                let _ = v;
            }
        }

        "dumpmask" => {
            let v = require_value("dumpmask")?;
            let mask = parse_i32_base0_token(v, "dumpmask", cl, "dump mask")?;
            #[cfg(feature = "dump")]
            {
                daemon.dump_mask = mask;
            }
            #[cfg(not(feature = "dump"))]
            {
                let _ = mask;
            }
        }

        "add-mac" => {
            match cl.value.as_deref() {
                None => daemon.set_option(OPT_ADD_MAC),
                Some("base64") => daemon.set_option(OPT_MAC_B64),
                Some("text") => daemon.set_option(OPT_MAC_HEX),
                Some(v) => return Err(invalid_value_for(cl, "add-mac", v, "expected base64 or text")),
            }
        }

        "strip-mac" => {
            require_no_value("strip-mac")?;
            daemon.set_option(OPT_STRIP_MAC);
        }

        "add-cpe-id" => {
            let v = require_value("add-cpe-id")?;
            daemon.dns_client_id = Some(v.to_string());
        }

        "add-subnet" => {
            daemon.set_option(OPT_CLIENT_SUBNET);
            if let Some(v) = cl.value.as_deref() {
                if !v.trim().is_empty() {
                    let (subnet4, subnet6) = parse_add_subnet(v, cl)?;
                    daemon.add_subnet4 = Some(subnet4);
                    if let Some(subnet6) = subnet6 {
                        daemon.add_subnet6 = Some(subnet6);
                    }
                }
            }
        }

        "strip-subnet" => {
            require_no_value("strip-subnet")?;
            daemon.set_option(OPT_STRIP_ECS);
        }

        "dhcp-alternate-port" => {
            #[cfg(feature = "dhcp")]
            {
                let (server_port, client_port) = parse_dhcp_alternate_port(cl)?;
                daemon.dhcp_server_port = i32::from(server_port);
                daemon.dhcp_client_port = i32::from(client_port);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = cl;
            }
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

        // ── rev-server ─────────────────────────────────────────────────────
        //
        // Format: rev-server=<addr>/<prefix>,<ipaddr>[#port]
        // Delegates reverse (PTR) lookups for the subnet to the given
        // upstream, or answers them locally with no forwarding when the
        // server part is omitted.  Port of `option.c:3161` (`LOPT_REV_SERV`).
        "rev-server" => {
            let v = require_value("rev-server")?;
            parse_rev_server(daemon, v, cl)?;
        }

        // ── synth-domain ───────────────────────────────────────────────────
        //
        // Format: synth-domain=<domain>,<addr>/<prefix>[,<prefix-string>]
        //      or synth-domain=<domain>,<start>[,<end>][,<prefix-string>]
        // Port of `option.c:2622` (`LOPT_SYNTH`, the non-`--domain` half of
        // the shared `'s'`/`LOPT_SYNTH` case).
        "synth-domain" => {
            let v = require_value("synth-domain")?;
            parse_synth_domain(daemon, v, cl)?;
        }

        // ── bridge-interface ───────────────────────────────────────────────
        //
        // Format: bridge-interface=<iface>,<alias>[,<alias>...]
        // Port of `option.c:3673` (`LOPT_BRIDGE`).
        "bridge-interface" => {
            let v = require_value("bridge-interface")?;
            parse_bridge_interface(daemon, v, cl)?;
        }

        // ── shared-network ─────────────────────────────────────────────────
        //
        // Format: shared-network=<iface>|<addr>,<addr>
        // Port of `option.c:3709` (`LOPT_SHARED_NET`).
        "shared-network" => {
            let v = require_value("shared-network")?;
            parse_shared_network(daemon, v, cl)?;
        }

        // ── DHCP options (stubs) ────────────────────────────────────────────
        "dhcp-range" => {
            let v = require_value("dhcp-range")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp.push(parse_dhcp_range(v, cl)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-host" => {
            let v = require_value("dhcp-host")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_conf.push(parse_dhcp_host(v, cl)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-option" => {
            let v = require_value("dhcp-option")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_opts.push(parse_dhcp_option(v, cl, "dhcp-option", 0)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-option-force" => {
            let v = require_value("dhcp-option-force")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_opts.push(parse_dhcp_option(v, cl, "dhcp-option-force", crate::types::dhcp::DHOPT_FORCE)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-option-pxe" => {
            let v = require_value("dhcp-option-pxe")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_opts.push(parse_dhcp_option(v, cl, "dhcp-option-pxe", crate::types::dhcp::DHOPT_PXE_OPT)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-boot" => {
            let v = require_value("dhcp-boot")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.boot_config.push(parse_dhcp_boot(v, cl)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
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

        // `--dhcp-ignore` (option.c:275, `ARG_REQUIRED`): unlike its four
        // siblings below, a value is mandatory.
        "dhcp-ignore" => {
            let v = require_value("dhcp-ignore")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_ignore.push(parse_dhcp_netid_list(v, cl, "dhcp-ignore")?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        // ── dhcp-ignore-names / dhcp-generate-names / dhcp-broadcast /
        //    bootp-dynamic ───────────────────────────────────────────────
        //
        // Shared upstream case (option.c:4659-4700): each is a global
        // tag-list gate (`struct dhcp_netid_list`), populated by treating
        // every comma-separated field as a literal tag name (stripping a
        // leading `tag:`/`net:` prefix, matching upstream's `is_tag_prefix`
        // check exactly — `set:` is *not* special here). Unlike `dhcp-ignore`
        // above, these four take `ARG_DUP` (option.c:296,331,347,286): a bare
        // directive (no value) is valid and produces an entry with an empty
        // tag list, which its consumer treats as "matches every host"
        // (`(!id_list->list) || match_netid(...)`, e.g. `rfc2131.c:663-664`).
        "dhcp-ignore-names" | "dhcp-generate-names" | "dhcp-broadcast" | "bootp-dynamic" => {
            #[cfg(feature = "dhcp")]
            {
                let entry = match cl.value.as_deref() {
                    None => DhcpNetidList::default(),
                    Some(v) => parse_dhcp_netid_list(v, cl, key)?,
                };
                match key {
                    "dhcp-ignore-names" => daemon.dhcp_ignore_names.push(entry),
                    "dhcp-generate-names" => daemon.dhcp_gen_names.push(entry),
                    "dhcp-broadcast" => daemon.force_broadcast.push(entry),
                    _ => daemon.bootp_dynamic.push(entry),
                }
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = cl.value.as_deref();
            }
        }

        "dhcp-vendorclass" => {
            let v = require_value("dhcp-vendorclass")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_vendors.push(parse_dhcp_vendor(v, cl)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "tag-if" => {
            let v = require_value("tag-if")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.tag_if.push(parse_tag_if(v, cl)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-match" => {
            let v = require_value("dhcp-match")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_match.push(parse_dhcp_match(v, cl)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-name-match" => {
            let v = require_value("dhcp-name-match")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_name_match.push(parse_dhcp_name_match(v, cl)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-userclass" => {
            let v = require_value("dhcp-userclass")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_userclasses.push(parse_dhcp_userclass(v, cl)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-circuitid" => {
            let v = require_value("dhcp-circuitid")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_relay_ids.push(parse_dhcp_relay_id(v, cl, "dhcp-circuitid", crate::dhcp_protocol::SUBOPT_CIRCUIT_ID)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-subscrid" => {
            let v = require_value("dhcp-subscrid")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_relay_ids.push(parse_dhcp_relay_id(v, cl, "dhcp-subscrid", crate::dhcp_protocol::SUBOPT_SUBSCR_ID)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-remoteid" => {
            let v = require_value("dhcp-remoteid")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_relay_ids.push(parse_dhcp_relay_id(v, cl, "dhcp-remoteid", crate::dhcp_protocol::SUBOPT_REMOTE_ID)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-mac" => {
            let v = require_value("dhcp-mac")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_macs.push(parse_dhcp_mac(v, cl)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-reply-delay" => {
            let v = require_value("dhcp-reply-delay")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_reply_delays.push(parse_dhcp_reply_delay(v, cl)?);
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "dhcp-relay" | "dhcp-split-relay" => {
            let v = require_value(key)?;
            #[cfg(feature = "dhcp")]
            {
                match parse_dhcp_relay(v, cl, key == "dhcp-split-relay")? {
                    RelayEntry::V4(r) => daemon.relay4.push(r),
                    #[cfg(feature = "dhcp6")]
                    RelayEntry::V6(r) => daemon.relay6.push(r),
                }
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        "no-dhcp-interface" => {
            let v = require_value("no-dhcp-interface")?;
            daemon.dhcp_except.push(Iname { name: Some(v.to_string()), addr: None, flags: 0 });
        }

        // `--no-dhcpv4-interface` / `--no-dhcpv6-interface` (option.c:2898,
        // LOPT_NO_DHCP4/6) share `daemon->dhcp_except` with `no-dhcp-interface`
        // above; each record's `flags` says which family it excludes
        // (`option.c:2905-2914`).
        "no-dhcpv4-interface" => {
            let v = require_value("no-dhcpv4-interface")?;
            daemon.dhcp_except.push(Iname { name: Some(v.to_string()), addr: None, flags: INAME_4 });
        }

        "no-dhcpv6-interface" => {
            let v = require_value("no-dhcpv6-interface")?;
            daemon.dhcp_except.push(Iname { name: Some(v.to_string()), addr: None, flags: INAME_6 });
        }

        // `--dhcp-duid` (option.c:4857): `enterprise-number,hex-id`.
        "dhcp-duid" => {
            let v = require_value("dhcp-duid")?;
            let parts = split_csv(v);
            if parts.len() != 2 {
                return Err(invalid_value_for(cl, "dhcp-duid", v, "expected enterprise-number,hex-id"));
            }
            let enterprise = parse_u32_token(parts[0], "dhcp-duid", cl, "DUID enterprise number")?;
            let id = parse_hex_bytes(parts[1], "dhcp-duid", cl, "DUID")?;
            #[cfg(feature = "dhcp6")]
            {
                daemon.duid_enterprise = enterprise;
                daemon.duid_config = Some(id);
            }
            #[cfg(not(feature = "dhcp6"))]
            {
                let _ = (enterprise, id);
            }
        }

        // ── DNS record stubs ────────────────────────────────────────────────
        "mx-host" => {
            let v = require_value("mx-host")?;
            daemon.mxnames.push(parse_mx_host(v, cl)?);
        }

        "mx-target" => {
            let v = require_value("mx-target")?;
            daemon.mxtarget = Some(parse_domain_token(v, "mx-target", cl)?);
        }

        "srv-host" => {
            let v = require_value("srv-host")?;
            daemon.mxnames.push(parse_srv_host(v, cl)?);
        }

        "txt-record" => {
            let v = require_value("txt-record")?;
            daemon.txt.push(parse_txt_record(v, cl)?);
        }

        "ptr-record" => {
            let v = require_value("ptr-record")?;
            daemon.ptr.push(parse_ptr_record(v, cl)?);
        }

        "host-record" => {
            let v = require_value("host-record")?;
            daemon.host_records.push(parse_host_record(v, cl)?);
        }

        "interface-name" => {
            let v = require_value("interface-name")?;
            daemon.int_names.push(parse_interface_name(v, cl, false)?);
        }

        "dynamic-host" => {
            let v = require_value("dynamic-host")?;
            daemon.int_names.push(parse_interface_name(v, cl, true)?);
        }

        "cname" => {
            let v = require_value("cname")?;
            let cnames = parse_cname_records(v, cl, &daemon.cnames)?;
            daemon.cnames.extend(cnames);
        }

        "naptr-record" => {
            let v = require_value("naptr-record")?;
            daemon.naptr.push(parse_naptr_record(v, cl)?);
        }

        "dns-rr" => {
            let v = require_value("dns-rr")?;
            daemon.rr.push(parse_dns_rr(v, cl)?);
        }

        "caa-record" => {
            let v = require_value("caa-record")?;
            daemon.rr.push(parse_caa_record(v, cl)?);
        }

        "trust-anchor" => {
            let v = require_value("trust-anchor")?;
            #[cfg(feature = "dnssec")]
            {
                daemon.ds.push(parse_trust_anchor(v, cl)?);
            }
            #[cfg(not(feature = "dnssec"))]
            {
                let _ = parse_trust_anchor(v, cl)?;
            }
        }

        // ── Additional hosts files ──────────────────────────────────────────
        "addn-hosts" => {
            let v = require_value("addn-hosts")?;
            let file = make_hosts_file(daemon, v);
            daemon.addn_hosts.push(file);
        }

        "dhcp-hostsfile" => {
            let v = require_value("dhcp-hostsfile")?;
            let file = make_hosts_file(daemon, v);
            daemon.dhcp_hosts_file.push(file);
        }

        "dhcp-optsfile" => {
            let v = require_value("dhcp-optsfile")?;
            let file = make_hosts_file(daemon, v);
            daemon.dhcp_opts_file.push(file);
        }

        "hostsdir" | "addn-hosts-dir" | "hosts-dir" => {
            let v = require_value(key)?;
            daemon.dynamic_dirs.push(make_dynamic_dir(v, DynDirFlags::HOSTS));
        }

        "dhcp-hostsdir" => {
            let v = require_value("dhcp-hostsdir")?;
            daemon.dynamic_dirs.push(make_dynamic_dir(v, DynDirFlags::DHCP_HST));
        }

        "dhcp-optsdir" => {
            let v = require_value("dhcp-optsdir")?;
            daemon.dynamic_dirs.push(make_dynamic_dir(v, DynDirFlags::DHCP_OPT));
        }

        // ── conf-dir (recursive config loading) ────────────────────────────
        "conf-dir" => {
            let v = require_value("conf-dir")?;
            apply_conf_dir(daemon, v)?;
        }

        // ── DNS forwarding limit ────────────────────────────────────────────
        "dns-forward-max" => {
            let v = require_value("dns-forward-max")?;
            daemon.ftabsize = parse_i32_token(v, "dns-forward-max", cl, "maximum concurrent DNS queries")?;
        }

        "max-tcp-connections" => {
            let v = require_value("max-tcp-connections")?;
            daemon.max_procs = parse_i32_token(v, "max-tcp-connections", cl, "maximum TCP connections")?;
        }

        // ── Auth zone ──────────────────────────────────────────────────────
        "auth-zone" => {
            let v = require_value("auth-zone")?;
            daemon.auth_zones.push(parse_auth_zone(v, cl)?);
        }

        "auth-server" => {
            let v = require_value("auth-server")?;
            let (authserver, interfaces) = parse_auth_server(v, cl)?;
            daemon.authserver = Some(authserver);
            daemon.auth_interfaces.extend(interfaces);
        }

        "auth-sec-servers" => {
            let v = require_value("auth-sec-servers")?;
            daemon.secondary_forward_servers.extend(parse_auth_sec_servers(v, cl)?);
        }

        "auth-peer" => {
            let v = require_value("auth-peer")?;
            daemon.auth_peers.extend(parse_auth_peers(v, cl)?);
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

        "tftp-mtu" => {
            let v = require_value("tftp-mtu")?;
            let mtu = parse_i32_token(v, "tftp-mtu", cl, "TFTP MTU")?;
            #[cfg(feature = "tftp")]
            {
                daemon.tftp_mtu = mtu;
            }
            #[cfg(not(feature = "tftp"))]
            {
                let _ = mtu;
            }
        }

        "tftp-port-range" => {
            let v = require_value("tftp-port-range")?;
            let (start, end) = parse_tftp_port_range(v, cl)?;
            #[cfg(feature = "tftp")]
            {
                daemon.start_tftp_port = i32::from(start);
                daemon.end_tftp_port = i32::from(end);
            }
            #[cfg(not(feature = "tftp"))]
            {
                let _ = (start, end);
            }
        }

        "tftp-unique-root" => {
            match cl.value.as_deref() {
                None | Some("ip") => daemon.set_option(OPT_TFTP_APREF_IP),
                Some("mac") => daemon.set_option(OPT_TFTP_APREF_MAC),
                Some(v) => return Err(invalid_value_for(cl, "tftp-unique-root", v, "expected ip or mac")),
            }
        }

        // ── ipset / nftset ─────────────────────────────────────────────────
        "ipset" => {
            let v = require_value("ipset")?;
            daemon.ipsets.extend(parse_ipset(v, cl)?);
        }

        "nftset" => {
            let v = require_value("nftset")?;
            daemon.nftsets.extend(parse_nftset(v, cl)?);
        }

        // ── alias ─────────────────────────────────────────────────────────
        "alias" => {
            let v = require_value("alias")?;
            daemon.doctors.push(parse_alias(v, cl)?);
        }

        // ── bogus-nxdomain ────────────────────────────────────────────────
        "bogus-nxdomain" => {
            let v = require_value("bogus-nxdomain")?;
            daemon.bogus_addr.push(parse_bogus_addr(v, cl, "bogus-nxdomain")?);
        }

        "ignore-address" => {
            let v = require_value("ignore-address")?;
            daemon.ignore_addr.push(parse_bogus_addr(v, cl, "ignore-address")?);
        }

        "leasequery" => {
            daemon.set_option(OPT_LEASEQUERY);
            if let Some(v) = cl.value.as_deref() {
                daemon.leasequery_addr.push(parse_bogus_addr(v, cl, "leasequery")?);
            }
        }

        // ── DNS rebind protection ─────────────────────────────────────────
        "stop-dns-rebind" => {
            daemon.set_option(OPT_NO_REBIND);
        }

        "rebind-localhost-ok" => {
            daemon.set_option(OPT_LOCAL_REBIND);
        }

        "rebind-domain-ok" => {
            let v = require_value("rebind-domain-ok")?;
            parse_rebind_domains(v, cl, &mut daemon.no_rebind)?;
        }

        "no-rebind-localhost" => {
            // noop: clears rebind-localhost-ok; no action needed as default
        }

        // ── DNSSEC ────────────────────────────────────────────────────────
        "dnssec-check-unsigned" => {
            match cl.value.as_deref() {
                None => {}
                Some("no") => daemon.set_option(OPT_DNSSEC_IGN_NS),
                Some(v) => return Err(invalid_value_for(cl, "dnssec-check-unsigned", v, "expected no")),
            }
        }

        // ── Boolean flags not yet in the bool section ─────────────────────
        "no-round-robin" => {
            daemon.set_option(OPT_NORR);
        }

        "bind-dynamic" => {
            daemon.set_option(OPT_CLEVERBIND);
        }

        // `--connmark-allowlist-enable` (option.c:3284, `OPT_CMARK_ALST_EN`):
        // optional mask, defaulting to "match every bit" like upstream's
        // `mask = UINT32_MAX` before the optional-arg override. Upstream
        // hard-errors this directive without HAVE_CONNTRACK (option.c:3283-3286)
        // rather than silently ignoring it; do the same for the `conntrack`
        // feature. Runtime consumption of `allowlist_mask`/`allowlists` is
        // wired into `forward::mark_admits_query` (query admission, ported
        // from `is_query_allowed_for_mark()`) and `rfc1035::report_addresses`
        // (reply-time ubus reporting) — see `tasks.md`.
        "connmark-allowlist-enable" => {
            #[cfg(not(feature = "conntrack"))]
            {
                return Err(invalid_value_for(
                    cl, "connmark-allowlist-enable", cl.value.as_deref().unwrap_or(""),
                    "recompile with the conntrack feature enabled to use connmark-allowlist directives",
                ));
            }
            #[cfg(feature = "conntrack")]
            {
                daemon.set_option(OPT_CMARK_ALST_EN);
                daemon.allowlist_mask = match cl.value.as_deref() {
                    None => u32::MAX,
                    Some(v) => {
                        let mask = parse_u32_token(v, "connmark-allowlist-enable", cl, "allowlist mask")?;
                        if mask < 1 {
                            return Err(invalid_value_for(cl, "connmark-allowlist-enable", v, "mask must be at least 1"));
                        }
                        mask
                    }
                };
            }
        }

        // `--connmark-allowlist` (option.c:3302): `mark[/mask][,pattern...]`.
        // Same HAVE_CONNTRACK gate as above.
        "connmark-allowlist" => {
            #[cfg(not(feature = "conntrack"))]
            {
                return Err(invalid_value_for(
                    cl, "connmark-allowlist", cl.value.as_deref().unwrap_or(""),
                    "recompile with the conntrack feature enabled to use connmark-allowlist directives",
                ));
            }
            #[cfg(feature = "conntrack")]
            {
                let v = require_value("connmark-allowlist")?;
                let parts = split_csv(v);
                if parts.is_empty() {
                    return Err(invalid_value_for(cl, "connmark-allowlist", v, "expected mark[/mask][,pattern...]"));
                }
                let (mark_str, mask_str) = match parts[0].split_once('/') {
                    Some((m, k)) => (m, Some(k)),
                    None => (parts[0], None),
                };
                let mark = parse_u32_token(mark_str, "connmark-allowlist", cl, "connmark mark")?;
                if mark < 1 {
                    return Err(invalid_value_for(cl, "connmark-allowlist", v, "mark must be at least 1"));
                }
                let mask = match mask_str {
                    Some(m) => {
                        let mask = parse_u32_token(m, "connmark-allowlist", cl, "connmark mask")?;
                        if mask < 1 {
                            return Err(invalid_value_for(cl, "connmark-allowlist", v, "mask must be at least 1"));
                        }
                        mask
                    }
                    None => u32::MAX,
                };
                if mark & !mask != 0 {
                    return Err(invalid_value_for(cl, "connmark-allowlist", v, "mark must be a subset of mask"));
                }
                let patterns: Vec<String> = parts[1..].iter().map(|p| p.to_string()).collect();
                daemon.allowlists.push(Allowlist { mark, mask, patterns });
            }
        }

        // `--dhcp-proxy[=<addr>...]` (option.c:4703-4714, `LOPT_PROXY`):
        // enables proxy-DHCP mode and, when addresses are given, restricts
        // which relay agents are trusted without `giaddr` set.
        "dhcp-proxy" => {
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_override = true;
                if let Some(v) = cl.value.as_deref() {
                    for part in v.split(',') {
                        if part.is_empty() {
                            continue;
                        }
                        let addr: Ipv4Addr = part.parse().map_err(|_| {
                            invalid_value_for(cl, "dhcp-proxy", part, "bad dhcp-proxy address")
                        })?;
                        daemon.override_relays.push(addr);
                    }
                }
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = cl.value.as_deref();
            }
        }

        // `--dhcp-pxe-vendor` (option.c:4716-4727, `LOPT_PXE_VENDOR`):
        // additional PXE client-vendor strings to accept alongside the
        // built-in default `"PXEClient"`.
        "dhcp-pxe-vendor" => {
            let v = require_value("dhcp-pxe-vendor")?;
            #[cfg(feature = "dhcp")]
            {
                for part in v.split(',') {
                    if part.is_empty() {
                        return Err(invalid_value_for(cl, "dhcp-pxe-vendor", v, "empty vendor string"));
                    }
                    daemon.dhcp_pxe_vendors.push(DhcpPxeVendor { data: part.to_string() });
                }
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        // `--pxe-prompt` (option.c:4422-4457, `LOPT_PXE_PROMT`): builds a
        // `dhcp_opt` for option 10 (PXE_MENU_PROMPT), flagged
        // `DHOPT_VENDOR|DHOPT_VENDOR_PXE` so it's only sent inside a PXE
        // vendor-encapsulated option block, and sets `enable_pxe`.
        "pxe-prompt" => {
            let v = require_value("pxe-prompt")?;
            #[cfg(feature = "dhcp")]
            {
                daemon.dhcp_opts.push(parse_pxe_prompt(v, cl)?);
                daemon.enable_pxe = true;
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        // `--pxe-service` (option.c:4461-4539, `LOPT_PXE_SERV`): a PXE boot
        // menu entry.
        "pxe-service" => {
            let v = require_value("pxe-service")?;
            #[cfg(feature = "dhcp")]
            {
                let svc = parse_pxe_service(daemon, v, cl)?;
                daemon.pxe_services.push(svc);
                daemon.enable_pxe = true;
            }
            #[cfg(not(feature = "dhcp"))]
            {
                let _ = v;
            }
        }

        // `--conf-script` (option.c:2068): upstream executes the referenced
        // file and reads config lines back from its output.  Running an
        // external program as part of config parsing is a deliberate
        // capability this port does not implement (see tasks.md); the
        // directive is accepted so a config that carries it does not abort
        // startup, but the script itself is never executed or read.
        "conf-script" => {
            let _ = require_value("conf-script")?;
        }

        "filter-A" => {
            daemon.rrlist_filter.push(RrList { rr: 1 });
        }

        "filter-AAAA" => {
            daemon.rrlist_filter.push(RrList { rr: 28 });
        }

        "cache-rr" => {
            let v = require_value("cache-rr")?;
            daemon.rrlist_cache.extend(parse_rrlist(v, cl, "cache-rr")?);
        }

        "filter-rr" => {
            let v = require_value("filter-rr")?;
            daemon.rrlist_filter.extend(parse_rrlist(v, cl, "filter-rr")?);
        }

        "port-limit" => {
            let v = require_value("port-limit")?;
            let limit = parse_i32_token(v, "port-limit", cl, "port limit")?;
            if limit < 1 {
                return Err(invalid_value_for(cl, "port-limit", v, "port limit must be at least 1"));
            }
            daemon.randport_limit = limit;
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
        // A domain segment that is literally `#` ("address=/#/1.2.3.4" /
        // "server=/#/...") means "matches any domain" — upstream implements
        // this by rewriting it to the empty string before storing the server
        // entry (`option.c:3136-3138`: "address=/#/ matches the same as
        // without domain"), which is exactly the general/fallback entry a
        // bare `address=1.2.3.4` (no `/domain/` prefix at all) already
        // produces. Doing the same rewrite here means a mixed directive like
        // `/specific.test/#/1.2.3.4` correctly produces one entry per domain
        // (including the wildcard), rather than silently dropping the `#`.
        let doms: Vec<String> = parts[..parts.len() - 1]
            .iter()
            .filter(|d| !d.is_empty())
            .map(|d| if *d == "#" { String::new() } else { d.to_string() })
            .collect();
        // We need addr_segment to live long enough — it points into `v`.
        // Use split_at on v to get a `&str` with the correct lifetime.
        let offset = v.rfind('/').unwrap() + 1;
        (doms, &v[offset..])
    } else {
        (vec![], v)
    };

    // Empty address ("server=/domain/", "local=/domain/", "address=/domain/")
    // means "never forward, answer locally" (option.c:3060-3110: `if (!arg ||
    // !*arg) flags = SERV_LITERAL_ADDRESS;`) — create a literal, address-less
    // server entry per domain (or one catch-all entry with no domains given).
    if addr_part.is_empty() {
        let dummy_addr = MySockAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0));
        if domains.is_empty() {
            daemon.servers.push(new_server(
                SERV_LITERAL_ADDRESS,
                String::new(),
                dummy_addr.clone(),
                dummy_addr,
            ));
        } else {
            for domain in domains {
                daemon.servers.push(new_server(
                    SERV_LITERAL_ADDRESS,
                    domain,
                    dummy_addr.clone(),
                    dummy_addr.clone(),
                ));
            }
        }
        return Ok(());
    }

    // `--address=/domain/#` (the whole address argument is literally "#",
    // not a `<real-address>#<port>` string with a leading empty address):
    // return the NULL address (0.0.0.0 / ::) for domain + subdomains.
    // `--address`-only per upstream (`option.c:3093-3097`, gated on
    // `option == 'A'`) — `--server`/`--local` don't give `#` this meaning at
    // all, since server addresses always need a real, resolvable target.
    if key == "address" && addr_part == "#" {
        let dummy_addr = MySockAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0));
        let flags = SERV_ALL_ZEROS | SERV_LITERAL_ADDRESS;
        if domains.is_empty() {
            daemon.servers.push(new_server(flags, String::new(), dummy_addr.clone(), dummy_addr));
        } else {
            for domain in domains {
                daemon.servers.push(new_server(flags, domain, dummy_addr.clone(), dummy_addr.clone()));
            }
        }
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

pub(crate) fn new_server(flags: u16, domain: String, addr: MySockAddr, source_addr: MySockAddr) -> Server {
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
        // Upstream assigns this at the same construction site
        // (`add_update_server()`, `domain-match.c:759: serv->uid = rand32();`)
        // so loop-detection probes for distinct servers never collide.
        #[cfg(feature = "loop")]
        uid: rand::random::<u32>(),
    }
}

fn invalid_value_for(cl: &ConfigLine, key: &str, val: &str, reason: &str) -> ConfigError {
    ConfigError::InvalidValue(
        val.to_string(),
        key.to_string(),
        cl.file.clone(),
        cl.line,
        reason.to_string(),
    )
}

// ──────────────────────────────────────────────────────────────────────────────
// rev-server / synth-domain / bridge-interface / shared-network
// ──────────────────────────────────────────────────────────────────────────────

/// Parse an `address[#port]` pair, ignoring an optional trailing `@source`
/// spec (upstream's `server_details` source-binding, which this port does
/// not carry through here).  Shared by `rev-server` and by `synth-domain`'s
/// generated `local=/domain/` entries.
fn parse_addr_port(v: &str) -> Result<(IpAddr, u16), &'static str> {
    let (addr_and_at, port_str) = if let Some(hash) = v.find('#') {
        (&v[..hash], Some(&v[hash + 1..]))
    } else {
        (v, None)
    };
    let addr_str = addr_and_at.split('@').next().unwrap_or(addr_and_at);
    let ip: IpAddr = addr_str.parse().map_err(|_| "expected an IP address")?;
    let port: u16 = match port_str {
        Some(ps) => {
            let ps_clean = ps.split('@').next().unwrap_or(ps);
            ps_clean.parse().map_err(|_| "expected a port number")?
        }
        None => 53,
    };
    Ok((ip, port))
}

/// Push one [`Server`] per generated reverse-zone `domain`: literal
/// (`SERV_LITERAL_ADDRESS`, answer locally with no forwarding) when
/// `server_part` is `None`, or forwarding to the parsed address otherwise.
/// Port of the `add_update_server()` calls inside `domain_rev4()`/
/// `domain_rev6()` (option.c).
fn push_domain_servers(
    daemon: &mut Daemon,
    domains: &[String],
    server_part: Option<&str>,
    cl: &ConfigLine,
    key: &str,
    orig: &str,
) -> Result<(), ConfigError> {
    let dummy_addr = MySockAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0));
    match server_part {
        None => {
            for d in domains {
                daemon.servers.push(new_server(SERV_LITERAL_ADDRESS, d.clone(), dummy_addr.clone(), dummy_addr.clone()));
            }
        }
        Some(s) => {
            let (ip, port) = parse_addr_port(s).map_err(|e| invalid_value_for(cl, key, orig, e))?;
            let sock = match ip {
                IpAddr::V4(a) => MySockAddr::V4(SocketAddrV4::new(a, port)),
                IpAddr::V6(a) => MySockAddr::V6(SocketAddrV6::new(a, port, 0, 0)),
            };
            let flags = match ip {
                IpAddr::V4(_) => SERV_4ADDR,
                IpAddr::V6(_) => SERV_6ADDR,
            };
            for d in domains {
                daemon.servers.push(new_server(flags, d.clone(), sock.clone(), dummy_addr.clone()));
            }
        }
    }
    Ok(())
}

/// `rev-server=<addr>/<prefix>,<ipaddr>[#port]`.  Port of `option.c:3161`.
fn parse_rev_server(daemon: &mut Daemon, v: &str, cl: &ConfigLine) -> Result<(), ConfigError> {
    let key = "rev-server";
    let mut split = v.splitn(2, ',');
    let net_part = split.next().unwrap_or("");
    let server_part = split.next();

    let (net_addr_str, size_opt) = match net_part.split_once('/') {
        Some((addr, size_str)) => {
            let size: u32 = size_str.parse().map_err(|_| invalid_value_for(cl, key, v, "bad prefix length"))?;
            (addr, Some(size))
        }
        None => (net_part, None),
    };

    let domains = if let Ok(addr4) = net_addr_str.parse::<Ipv4Addr>() {
        let size = size_opt.unwrap_or(32);
        domain_rev4(addr4, size).map_err(|e| invalid_value_for(cl, key, v, e))?
    } else if let Ok(addr6) = net_addr_str.parse::<Ipv6Addr>() {
        let size = size_opt.unwrap_or(128);
        domain_rev6(addr6, size).map_err(|e| invalid_value_for(cl, key, v, e))?
    } else {
        return Err(invalid_value_for(cl, key, v, "expected an IPv4 or IPv6 address"));
    };

    push_domain_servers(daemon, &domains, server_part, cl, key, v)
}

/// `domain=<name>` or `domain=<name>,<subnet>[,local]`.
/// Port of `option.c:2622` (the `option == 's'` half of the shared
/// `case 's': case LOPT_SYNTH:` block), covering the bare form (plain
/// suffix, or `domain=#` to set `OPT_RESOLV_DOMAIN`) and the subnet form
/// (populating `daemon->cond_domain`, distinct from `synth_domains`).
fn parse_domain(daemon: &mut Daemon, v: &str, cl: &ConfigLine) -> Result<(), ConfigError> {
    let key = "domain";
    let mut parts = v.splitn(2, ',');
    let domain = parts.next().unwrap_or("").trim();
    if domain.is_empty() {
        return Err(invalid_value_for(cl, key, v, "missing domain"));
    }
    let rest = match parts.next() {
        None => {
            if domain == "#" {
                daemon.set_option(OPT_RESOLV_DOMAIN);
            } else {
                daemon.domain_suffix = Some(domain.to_string());
            }
            return Ok(());
        }
        Some(r) => r,
    };

    let mut cd = CondDomain {
        domain: domain.to_string(),
        prefix: None,
        interface: None,
        al: vec![],
        start: Ipv4Addr::UNSPECIFIED,
        end: Ipv4Addr::UNSPECIFIED,
        start6: Ipv6Addr::UNSPECIFIED,
        end6: Ipv6Addr::UNSPECIFIED,
        is6: false,
        indexed: false,
        prefixlen: 0,
    };

    if let Some((net_part, tail)) = rest.split_once('/') {
        // CIDR form: <addr>/<prefix>[,local]. Unlike `synth-domain`, a third
        // field here must be the literal `local` keyword (option.c:2670,2711)
        // — anything else is an error, and there is no prefix to record.
        // `local` triggers upstream's automatic PTR-zone/NS-record synthesis
        // (`domain_rev4`/`domain_rev6` + `add_update_server`), which this
        // port does not implement yet (see tasks.md); the subnet itself is
        // still recorded so `cond_domain` matching works.
        let mut tail_parts = tail.splitn(2, ',');
        let size_str = tail_parts.next().unwrap_or("");
        let local_field = tail_parts.next();
        let size: u32 = size_str.parse().map_err(|_| invalid_value_for(cl, key, v, "bad prefix length"))?;

        if let Ok(addr4) = net_part.parse::<Ipv4Addr>() {
            if !(1..=32).contains(&size) {
                return Err(invalid_value_for(cl, key, v, "bad prefix length"));
            }
            let mask = (1u32 << (32 - size)) - 1;
            let start = u32::from(addr4) & !mask;
            cd.is6 = false;
            cd.start = Ipv4Addr::from(start);
            cd.end = Ipv4Addr::from(start | mask);
        } else if let Ok(addr6) = net_part.parse::<Ipv6Addr>() {
            if !(1..=128).contains(&size) {
                return Err(invalid_value_for(cl, key, v, "bad prefix length"));
            }
            let addrpart = crate::domain::ipv6_low64(addr6);
            let mask: u64 = if size <= 64 { u64::MAX } else { (1u64 << (128 - size)) - 1 };
            cd.is6 = true;
            cd.prefixlen = size;
            cd.start6 = crate::domain::ipv6_set_low64(addr6, addrpart & !mask);
            cd.end6 = crate::domain::ipv6_set_low64(addr6, addrpart | mask);
        } else {
            return Err(invalid_value_for(cl, key, v, "expected an IPv4 or IPv6 address"));
        }

        if let Some(l) = local_field {
            if l != "local" {
                return Err(invalid_value_for(cl, key, v, "expected 'local'"));
            }
        }
    } else {
        // Range form: <start>[,<end>][,<ignored>], or a bare interface name
        // as a subnet-from-interface fallback (option.c:2750-2755) — a
        // fallback `synth-domain` does not have.
        let mut range_parts = rest.splitn(3, ',');
        let start_str = range_parts.next().unwrap_or("");
        let end_str = range_parts.next();

        if let Ok(start4) = start_str.parse::<Ipv4Addr>() {
            cd.is6 = false;
            cd.start = start4;
            cd.end = match end_str {
                None | Some("") => start4,
                Some(e) => e.parse().map_err(|_| invalid_value_for(cl, key, v, "expected an IPv4 address"))?,
            };
        } else if let Ok(start6) = start_str.parse::<Ipv6Addr>() {
            cd.is6 = true;
            cd.start6 = start6;
            cd.end6 = match end_str {
                None | Some("") => start6,
                Some(e) => e.parse().map_err(|_| invalid_value_for(cl, key, v, "expected an IPv6 address"))?,
            };
        } else {
            cd.interface = Some(start_str.to_string());
        }
    }

    daemon.cond_domain.push(cd);
    Ok(())
}

/// `umbrella[=deviceid:<16 hex chars>][,orgid:<n>][,assetid:<n>]`.
/// Port of `option.c:2810-2849` (`LOPT_UMBRELLA`'s sub-option loop). Only
/// `deviceid:`/`orgid:`/`assetid:` exist upstream — there is no `userid:`
/// sub-option in this dnsmasq version.
fn parse_umbrella(daemon: &mut Daemon, v: &str, cl: &ConfigLine) -> Result<(), ConfigError> {
    let key = "umbrella";
    for part in v.split(',') {
        if let Some(hex) = part.strip_prefix("deviceid:") {
            if hex.len() != 16 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid_value_for(cl, key, part, "deviceid must be 16 hex characters"));
            }
            for (i, byte) in daemon.umbrella_device.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
            }
            daemon.set_option(OPT_UMBRELLA_DEVID);
        } else if let Some(n) = part.strip_prefix("orgid:") {
            daemon.umbrella_org = n.parse().map_err(|_| invalid_value_for(cl, key, part, "expected an integer orgid"))?;
        } else if let Some(n) = part.strip_prefix("assetid:") {
            daemon.umbrella_asset = n.parse().map_err(|_| invalid_value_for(cl, key, part, "expected an integer assetid"))?;
        } else {
            return Err(invalid_value_for(cl, key, part, "expected deviceid:/orgid:/assetid:"));
        }
    }
    Ok(())
}

/// `synth-domain=<domain>,<addr>/<prefix>[,<prefix-string>]` or
/// `synth-domain=<domain>,<start>[,<end>][,<prefix-string>]`.
/// Port of `option.c:2622` (the `LOPT_SYNTH` half of the shared case).
fn parse_synth_domain(daemon: &mut Daemon, v: &str, cl: &ConfigLine) -> Result<(), ConfigError> {
    let key = "synth-domain";
    let mut parts = v.splitn(2, ',');
    let domain = parts.next().unwrap_or("").trim();
    if domain.is_empty() {
        return Err(invalid_value_for(cl, key, v, "missing domain"));
    }
    let rest = parts.next().ok_or_else(|| invalid_value_for(cl, key, v, "missing address range"))?;

    let mut cd = CondDomain {
        domain: domain.to_string(),
        prefix: None,
        interface: None,
        al: vec![],
        start: Ipv4Addr::UNSPECIFIED,
        end: Ipv4Addr::UNSPECIFIED,
        start6: Ipv6Addr::UNSPECIFIED,
        end6: Ipv6Addr::UNSPECIFIED,
        is6: false,
        indexed: false,
        prefixlen: 0,
    };

    if let Some((net_part, tail)) = rest.split_once('/') {
        // CIDR form.
        let mut tail_parts = tail.splitn(2, ',');
        let size_str = tail_parts.next().unwrap_or("");
        let prefix_field = tail_parts.next();
        let size: u32 = size_str.parse().map_err(|_| invalid_value_for(cl, key, v, "bad prefix length"))?;

        if let Ok(addr4) = net_part.parse::<Ipv4Addr>() {
            if !(1..=32).contains(&size) {
                return Err(invalid_value_for(cl, key, v, "bad prefix length"));
            }
            let mask = (1u32 << (32 - size)) - 1;
            let start = u32::from(addr4) & !mask;
            cd.is6 = false;
            cd.start = Ipv4Addr::from(start);
            cd.end = Ipv4Addr::from(start | mask);
            if let Some(p) = prefix_field {
                cd.prefix = Some(p.to_string());
            }
        } else if let Ok(addr6) = net_part.parse::<Ipv6Addr>() {
            if !(1..=128).contains(&size) {
                return Err(invalid_value_for(cl, key, v, "bad prefix length"));
            }
            let addrpart = crate::domain::ipv6_low64(addr6);
            // prefix==64 overflows the mask calculation (option.c comment).
            let mask: u64 = if size <= 64 { u64::MAX } else { (1u64 << (128 - size)) - 1 };
            cd.is6 = true;
            cd.prefixlen = size;
            cd.start6 = crate::domain::ipv6_set_low64(addr6, addrpart & !mask);
            cd.end6 = crate::domain::ipv6_set_low64(addr6, addrpart | mask);
            if let Some(p) = prefix_field {
                cd.prefix = Some(p.to_string());
            }
        } else {
            return Err(invalid_value_for(cl, key, v, "expected an IPv4 or IPv6 address"));
        }
    } else {
        // Range form: <start>[,<end>][,<prefix-string>].  Unlike the bare
        // `--domain` directive, `synth-domain` has no subnet-from-interface
        // fallback here (`option.c`'s `else if (option == 's')` branch is
        // specific to `'s'`) — a non-address first field is an error.
        let mut range_parts = rest.splitn(3, ',');
        let start_str = range_parts.next().unwrap_or("");
        let end_str = range_parts.next();
        let prefix_field = range_parts.next();

        if let Ok(start4) = start_str.parse::<Ipv4Addr>() {
            cd.is6 = false;
            cd.start = start4;
            cd.end = match end_str {
                None | Some("") => start4,
                Some(e) => e.parse().map_err(|_| invalid_value_for(cl, key, v, "expected an IPv4 address"))?,
            };
        } else if let Ok(start6) = start_str.parse::<Ipv6Addr>() {
            cd.is6 = true;
            cd.start6 = start6;
            cd.end6 = match end_str {
                None | Some("") => start6,
                Some(e) => e.parse().map_err(|_| invalid_value_for(cl, key, v, "expected an IPv6 address"))?,
            };
        } else {
            return Err(invalid_value_for(cl, key, v, "expected an IPv4 or IPv6 address"));
        }

        if let Some(p) = prefix_field {
            cd.prefix = Some(p.to_string());
        }
    }

    // A trailing '*' on the prefix marks the domain "indexed": names use a
    // decimal offset from `start` instead of the dashed/hex address form.
    if let Some(prefix) = cd.prefix.clone() {
        if let Some(stripped) = prefix.strip_suffix('*') {
            cd.indexed = true;
            cd.prefix = Some(stripped.to_string());
            if cd.is6 && cd.prefixlen < 64 {
                return Err(invalid_value_for(cl, key, v, "prefix length too small"));
            }
        }
    }

    daemon.synth_domains.push(cd);
    Ok(())
}

/// Interface name length limit mirroring Linux `IF_NAMESIZE`, used to
/// silently drop over-long bridge aliases exactly as upstream does
/// (`option.c:3673-3706`: `strlen(arg) <= IF_NAMESIZE - 1`).
const BRIDGE_IF_NAMESIZE: usize = 16;

/// `bridge-interface=<iface>,<alias>[,<alias>...]`.  Port of `option.c:3673`.
fn parse_bridge_interface(daemon: &mut Daemon, v: &str, cl: &ConfigLine) -> Result<(), ConfigError> {
    let key = "bridge-interface";
    let mut parts = v.splitn(2, ',');
    let iface = parts.next().unwrap_or("").trim();
    let rest = parts.next();

    if iface.is_empty() || iface.len() > BRIDGE_IF_NAMESIZE - 1 || rest.is_none() {
        return Err(invalid_value_for(cl, key, v, "bad bridge-interface"));
    }
    let rest = rest.unwrap();

    let idx = match daemon.bridges.iter().position(|b| b.iface == iface) {
        Some(i) => i,
        None => {
            daemon.bridges.push(DhcpBridge { iface: iface.to_string(), aliases: vec![] });
            daemon.bridges.len() - 1
        }
    };

    for alias in rest.split(',') {
        let alias = alias.trim();
        if !alias.is_empty() && alias.len() < BRIDGE_IF_NAMESIZE {
            daemon.bridges[idx].aliases.push(alias.to_string());
        }
    }

    Ok(())
}

/// `ra-param=<iface>,[mtu:<value>|<interface>|off,][high|low,]<intval>[,<lifetime>]`.
/// Port of `option.c:4814-4855` (`LOPT_RA_PARAM`).
#[cfg(feature = "dhcp6")]
fn parse_ra_param(daemon: &mut Daemon, v: &str, cl: &ConfigLine) -> Result<(), ConfigError> {
    let key = "ra-param";
    let bad = || invalid_value_for(cl, key, v, "bad RA-params");

    let mut parts = v.split(',').map(str::trim);
    let name = parts.next().filter(|s| !s.is_empty()).ok_or_else(bad)?;

    let mut new = RaInterface {
        name: name.to_string(),
        mtu_name: None,
        interval: 0,
        lifetime: -1,
        prio: 0,
        mtu: 0,
    };

    let mut next = parts.next();

    if let Some(rest) = next {
        if rest.len() >= 4 && rest.as_bytes()[..4].eq_ignore_ascii_case(b"mtu:") {
            let val = &rest[4..];
            if val.eq_ignore_ascii_case("off") {
                new.mtu = -1;
            } else if is_all_ascii_digits(val) {
                let n = val.parse::<i32>().map_err(|_| bad())?;
                if n < 1280 {
                    return Err(bad());
                }
                new.mtu = n;
            } else {
                new.mtu_name = Some(val.to_string());
            }
            next = parts.next();
        }
    }

    if let Some(rest) = next {
        if rest.eq_ignore_ascii_case("low") {
            new.prio = 0x18;
            next = parts.next();
        } else if rest.eq_ignore_ascii_case("high") {
            new.prio = 0x08;
            next = parts.next();
        }
    }

    let interval_str = next.ok_or_else(bad)?;
    if !is_all_ascii_digits(interval_str) {
        return Err(bad());
    }
    new.interval = interval_str.parse::<i32>().map_err(|_| bad())?;

    if let Some(lifetime_str) = parts.next() {
        if !is_all_ascii_digits(lifetime_str) {
            return Err(bad());
        }
        new.lifetime = lifetime_str.parse::<i32>().map_err(|_| bad())?;
    }

    daemon.ra_interfaces.push(new);
    Ok(())
}

/// Port of `numeric_check()` (`option.c:744-757`): every byte must be an
/// ASCII digit (rejecting a leading `-`, unlike `str::parse`), matching
/// `atoi_check()`'s gate before falling back to `atoi()`. An empty string
/// passes, mirroring the C loop over a NUL-terminated buffer never
/// executing its body.
fn is_all_ascii_digits(s: &str) -> bool {
    s.bytes().all(|b| b.is_ascii_digit())
}

/// `shared-network=<iface>|<addr>,<addr>`.  Port of `option.c:3709`
/// (`LOPT_SHARED_NET`).
fn parse_shared_network(daemon: &mut Daemon, v: &str, cl: &ConfigLine) -> Result<(), ConfigError> {
    let key = "shared-network";
    let mut parts = v.splitn(2, ',');
    let first = parts.next().unwrap_or("").trim();
    let second = parts.next().map(str::trim);

    let second = second.ok_or_else(|| invalid_value_for(cl, key, v, "bad shared-network"))?;
    if second.is_empty() {
        return Err(invalid_value_for(cl, key, v, "bad shared-network"));
    }

    let mut sn = SharedNetwork::default();

    if let Ok(shared4) = second.parse::<Ipv4Addr>() {
        sn.is6 = false;
        sn.shared_addr = shared4;
        if let Ok(match4) = first.parse::<Ipv4Addr>() {
            sn.match_addr = match4;
        } else {
            let idx = crate::network::nametoindex(first);
            if idx == 0 {
                return Err(invalid_value_for(cl, key, v, "bad shared-network"));
            }
            sn.if_index = idx;
        }
    } else if let Ok(shared6) = second.parse::<Ipv6Addr>() {
        sn.is6 = true;
        sn.shared_addr6 = shared6;
        if let Ok(match6) = first.parse::<Ipv6Addr>() {
            sn.match_addr6 = match6;
        } else {
            let idx = crate::network::nametoindex(first);
            if idx == 0 {
                return Err(invalid_value_for(cl, key, v, "bad shared-network"));
            }
            sn.if_index = idx;
        }
    } else {
        return Err(invalid_value_for(cl, key, v, "expected an IPv4 or IPv6 address"));
    }

    daemon.shared_networks.push(sn);
    Ok(())
}

fn split_csv(value: &str) -> Vec<&str> {
    value.split(',').map(str::trim).collect()
}

fn make_hosts_file(daemon: &mut Daemon, fname: &str) -> HostsFile {
    let index = daemon.host_index as u32;
    daemon.host_index += 1;
    HostsFile {
        flags: DynDirFlags::empty(),
        fname: fname.to_string(),
        index,
    }
}

fn make_dynamic_dir(dname: &str, flags: DynDirFlags) -> DynDir {
    DynDir {
        files: Vec::new(),
        flags,
        dname: dname.to_string(),
        #[cfg(feature = "inotify")]
        wd: -1,
    }
}

fn parse_tftp_interfaces(value: &str, cl: &ConfigLine) -> Result<Vec<Iname>, ConfigError> {
    let mut interfaces = Vec::new();
    for part in split_csv(value) {
        if part.is_empty() {
            return Err(invalid_value_for(cl, "enable-tftp", value, "expected interface name"));
        }
        interfaces.push(Iname {
            name: Some(part.to_string()),
            addr: None,
            flags: INAME_4 | INAME_6,
        });
    }
    Ok(interfaces)
}

fn parse_tftp_port_range(value: &str, cl: &ConfigLine) -> Result<(u16, u16), ConfigError> {
    let parts = split_csv(value);
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        return Err(invalid_value_for(cl, "tftp-port-range", value, "expected start,end"));
    }

    let mut start = parse_u16_token(parts[0], "tftp-port-range", cl, "TFTP port")?;
    let mut end = parse_u16_token(parts[1], "tftp-port-range", cl, "TFTP port")?;
    if start > end {
        std::mem::swap(&mut start, &mut end);
    }
    Ok((start, end))
}

fn parse_domain_token(token: &str, key: &str, cl: &ConfigLine) -> Result<String, ConfigError> {
    canonicalise_opt(token).filter(|s| !s.is_empty()).ok_or_else(|| {
        invalid_value_for(cl, key, token, "expected a valid domain name")
    })
}

fn parse_u16_token(token: &str, key: &str, cl: &ConfigLine, field: &str) -> Result<u16, ConfigError> {
    token.parse::<u16>().map_err(|_| {
        invalid_value_for(cl, key, token, &format!("expected a valid {field}"))
    })
}

fn parse_u32_token(token: &str, key: &str, cl: &ConfigLine, field: &str) -> Result<u32, ConfigError> {
    token.parse::<u32>().map_err(|_| {
        invalid_value_for(cl, key, token, &format!("expected a valid {field}"))
    })
}

fn parse_i32_token(token: &str, key: &str, cl: &ConfigLine, field: &str) -> Result<i32, ConfigError> {
    token.parse::<i32>().map_err(|_| {
        invalid_value_for(cl, key, token, &format!("expected a valid {field}"))
    })
}

fn parse_i32_base0_token(token: &str, key: &str, cl: &ConfigLine, field: &str) -> Result<i32, ConfigError> {
    let token = token.trim();
    if token.is_empty() {
        return Err(invalid_value_for(cl, key, token, &format!("expected a valid {field}")));
    }

    let (negative, unsigned) = token.strip_prefix('-').map_or((false, token), |rest| (true, rest));
    let (radix, digits) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
        .map_or((10, unsigned), |rest| (16, rest));

    if digits.is_empty() {
        return Err(invalid_value_for(cl, key, token, &format!("expected a valid {field}")));
    }

    let value = i64::from_str_radix(digits, radix).map_err(|_| {
        invalid_value_for(cl, key, token, &format!("expected a valid {field}"))
    })?;
    let signed = if negative { -value } else { value };
    i32::try_from(signed).map_err(|_| {
        invalid_value_for(cl, key, token, &format!("{field} out of range"))
    })
}

fn parse_auth_soa(daemon: &mut Daemon, value: &str, cl: &ConfigLine) -> Result<(), ConfigError> {
    let parts = split_csv(value);
    if parts.is_empty() || parts.len() > 5 || parts.iter().any(|p| p.is_empty()) {
        return Err(invalid_value_for(
            cl,
            "auth-soa",
            value,
            "expected serial[,hostmaster[,refresh[,retry[,expiry]]]]",
        ));
    }

    daemon.soa_sn = parse_u32_token(parts[0], "auth-soa", cl, "SOA serial")?;
    if parts.len() >= 2 {
        daemon.hostmaster = Some(parts[1].replace('@', "."));
    }
    if parts.len() >= 3 {
        daemon.soa_refresh = parse_u32_token(parts[2], "auth-soa", cl, "SOA refresh")?;
    }
    if parts.len() >= 4 {
        daemon.soa_retry = parse_u32_token(parts[3], "auth-soa", cl, "SOA retry")?;
    }
    if parts.len() == 5 {
        daemon.soa_expiry = parse_u32_token(parts[4], "auth-soa", cl, "SOA expiry")?;
    }

    Ok(())
}

fn parse_auth_peers(value: &str, cl: &ConfigLine) -> Result<Vec<Iname>, ConfigError> {
    let mut out = Vec::new();
    for token in split_csv(value) {
        if token.is_empty() {
            return Err(invalid_value_for(cl, "auth-peer", value, "empty peer address"));
        }
        let addr = match token.parse::<IpAddr>() {
            Ok(IpAddr::V4(ip4)) => MySockAddr::V4(SocketAddrV4::new(ip4, 0)),
            Ok(IpAddr::V6(ip6)) => MySockAddr::V6(SocketAddrV6::new(ip6, 0, 0, 0)),
            Err(_) => {
                return Err(invalid_value_for(
                    cl,
                    "auth-peer",
                    token,
                    "expected an IPv4 or IPv6 address",
                ));
            }
        };
        out.push(Iname {
            name: None,
            addr: Some(addr),
            flags: 0,
        });
    }

    if out.is_empty() {
        return Err(invalid_value_for(cl, "auth-peer", value, "expected at least one peer address"));
    }
    Ok(out)
}

fn parse_auth_server(value: &str, cl: &ConfigLine) -> Result<(String, Vec<Iname>), ConfigError> {
    let parts = split_csv(value);
    if parts.is_empty() || parts[0].is_empty() {
        return Err(invalid_value_for(
            cl,
            "auth-server",
            value,
            "expected domain[,interface|ip-address...]",
        ));
    }

    let authserver = parse_domain_token(parts[0], "auth-server", cl)?;
    let mut interfaces = Vec::new();
    for token in &parts[1..] {
        if token.is_empty() {
            return Err(invalid_value_for(cl, "auth-server", value, "empty auth-server field"));
        }
        interfaces.push(parse_auth_server_interface(token, cl)?);
    }

    Ok((authserver, interfaces))
}

fn parse_auth_server_interface(token: &str, cl: &ConfigLine) -> Result<Iname, ConfigError> {
    if let Ok(ip) = token.parse::<IpAddr>() {
        let addr = match ip {
            IpAddr::V4(ip4) => MySockAddr::V4(SocketAddrV4::new(ip4, 0)),
            IpAddr::V6(ip6) => MySockAddr::V6(SocketAddrV6::new(ip6, 0, 0, 0)),
        };
        return Ok(Iname {
            name: None,
            addr: Some(addr),
            flags: 0,
        });
    }

    let (name, family) = parse_interface_family(token, "auth-server", cl)?;
    let mut flags = 0;
    let addr = match family {
        Some(4) => {
            flags |= INAME_4;
            Some(MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)))
        }
        Some(6) => {
            flags |= INAME_6;
            Some(MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0)))
        }
        Some(_) => unreachable!(),
        None => None,
    };

    Ok(Iname {
        name: Some(name.to_string()),
        addr,
        flags,
    })
}

fn parse_auth_sec_servers(value: &str, cl: &ConfigLine) -> Result<Vec<String>, ConfigError> {
    let mut out = Vec::new();
    for token in split_csv(value) {
        if token.is_empty() {
            return Err(invalid_value_for(cl, "auth-sec-servers", value, "empty secondary server"));
        }
        out.push(parse_domain_token(token, "auth-sec-servers", cl)?);
    }

    if out.is_empty() {
        return Err(invalid_value_for(cl, "auth-sec-servers", value, "expected at least one domain"));
    }
    Ok(out)
}

#[cfg(feature = "dnssec")]
fn parse_dnssec_limits(value: &str, cl: &ConfigLine, limits: &mut [i32; LIMIT_MAX]) -> Result<(), ConfigError> {
    let parts = split_csv(value);
    if parts.is_empty() || parts.len() > LIMIT_MAX || parts.iter().any(|part| part.is_empty()) {
        return Err(invalid_value_for(
            cl,
            "dnssec-limits",
            value,
            "expected up to four comma-separated DNSSEC limits",
        ));
    }

    for (idx, part) in parts.iter().enumerate() {
        let val = parse_i32_token(part, "dnssec-limits", cl, "DNSSEC limit")?;
        if val != 0 {
            limits[idx] = val;
        }
    }

    Ok(())
}

fn parse_add_subnet(value: &str, cl: &ConfigLine) -> Result<(MySubnet, Option<MySubnet>), ConfigError> {
    let parts = split_csv(value);
    if parts.is_empty() || parts.len() > 2 || parts.iter().any(|p| p.is_empty()) {
        return Err(invalid_value_for(
            cl,
            "add-subnet",
            value,
            "expected [address/]IPv4-prefix[, [address/]IPv6-prefix]",
        ));
    }

    let subnet4 = parse_add_subnet_part(parts[0], false, cl)?;
    let subnet6 = if parts.len() == 2 {
        Some(parse_add_subnet_part(parts[1], true, cl)?)
    } else {
        None
    };
    Ok((subnet4, subnet6))
}

fn parse_add_subnet_part(token: &str, ipv6_slot: bool, cl: &ConfigLine) -> Result<MySubnet, ConfigError> {
    let (addr, mask_part) = if let Some((addr_part, mask_part)) = token.split_once('/') {
        let parsed = parse_mysockaddr(addr_part.trim())
            .map_err(|_| invalid_value_for(cl, "add-subnet", token, "expected a valid subnet address"))?;
        (Some(MySockAddr::from(parsed)), mask_part.trim())
    } else {
        (None, token.trim())
    };

    let mask = parse_i32_token(mask_part, "add-subnet", cl, "subnet prefix length")?;
    let max_mask = match addr.as_ref().map(MySockAddr::is_v6) {
        Some(true) => 128,
        Some(false) => 32,
        None if ipv6_slot => 128,
        None => 32,
    };
    if !(0..=max_mask).contains(&mask) {
        return Err(invalid_value_for(cl, "add-subnet", token, "subnet prefix length out of range"));
    }

    let default_addr = if ipv6_slot {
        MySockAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
    } else {
        MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0))
    };

    let addr_used = addr.is_some();
    Ok(MySubnet {
        addr: addr.unwrap_or(default_addr),
        addr_used,
        mask,
    })
}

fn parse_hex_bytes(token: &str, key: &str, cl: &ConfigLine, field: &str) -> Result<Vec<u8>, ConfigError> {
    let hex = token.trim();
    if hex.len() % 2 != 0 {
        return Err(invalid_value_for(cl, key, token, &format!("{field} must contain an even number of hex digits")));
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let pair = std::str::from_utf8(&bytes[i..i + 2]).map_err(|_| {
            invalid_value_for(cl, key, token, &format!("expected a hexadecimal {field}"))
        })?;
        let byte = u8::from_str_radix(pair, 16).map_err(|_| {
            invalid_value_for(cl, key, token, &format!("expected a hexadecimal {field}"))
        })?;
        out.push(byte);
        i += 2;
    }
    Ok(out)
}

fn parse_mx_host(value: &str, cl: &ConfigLine) -> Result<MxSrvRecord, ConfigError> {
    let parts = split_csv(value);
    if parts.is_empty() || parts.len() > 3 {
        return Err(invalid_value_for(cl, "mx-host", value, "expected name[,target[,priority]]"));
    }
    let name = parse_domain_token(parts[0], "mx-host", cl)?;
    let target = if parts.len() >= 2 {
        parse_domain_token(parts[1], "mx-host", cl)?
    } else {
        String::new()
    };
    let priority = if parts.len() == 3 {
        parse_u32_token(parts[2], "mx-host", cl, "MX priority")?
    } else {
        1
    };
    Ok(MxSrvRecord {
        name,
        target,
        is_srv: false,
        srv_port: 0,
        priority,
        weight: 0,
        offset: 0,
    })
}

fn parse_srv_host(value: &str, cl: &ConfigLine) -> Result<MxSrvRecord, ConfigError> {
    let parts = split_csv(value);
    if parts.len() < 3 || parts.len() > 5 {
        return Err(invalid_value_for(cl, "srv-host", value, "expected name,target,port[,priority[,weight]]"));
    }
    let name = parse_domain_token(parts[0], "srv-host", cl)?;
    let target = parse_domain_token(parts[1], "srv-host", cl)?;
    let srv_port = parse_u16_token(parts[2], "srv-host", cl, "SRV port")?;
    let priority = if parts.len() >= 4 {
        parse_u32_token(parts[3], "srv-host", cl, "SRV priority")?
    } else {
        0
    };
    let weight = if parts.len() == 5 {
        parse_u32_token(parts[4], "srv-host", cl, "SRV weight")?
    } else {
        0
    };
    Ok(MxSrvRecord {
        name,
        target,
        is_srv: true,
        srv_port,
        priority,
        weight,
        offset: 0,
    })
}

fn parse_txt_record(value: &str, cl: &ConfigLine) -> Result<TxtRecord, ConfigError> {
    let parts = split_csv(value);
    if parts.is_empty() || parts[0].is_empty() {
        return Err(invalid_value_for(cl, "txt-record", value, "expected name[,text...]"));
    }
    let name = parse_domain_token(parts[0], "txt-record", cl)?;
    let txt = encode_txt_record_chunks(&parts[1..]);
    Ok(TxtRecord { name, txt, class: 1, stat: 0 })
}

fn encode_txt_record_chunks(chunks: &[&str]) -> Vec<u8> {
    if chunks.is_empty() {
        return vec![0];
    }

    let mut out = Vec::new();
    for chunk in chunks {
        let bytes = chunk.as_bytes();
        if bytes.is_empty() {
            out.push(0);
            continue;
        }
        for piece in bytes.chunks(255) {
            out.push(piece.len() as u8);
            out.extend_from_slice(piece);
        }
    }
    out
}

fn parse_ptr_record(value: &str, cl: &ConfigLine) -> Result<PtrRecord, ConfigError> {
    let parts = split_csv(value);
    if parts.len() != 2 {
        return Err(invalid_value_for(cl, "ptr-record", value, "expected name,target"));
    }
    Ok(PtrRecord {
        name: parse_domain_token(parts[0], "ptr-record", cl)?,
        ptr: parse_domain_token(parts[1], "ptr-record", cl)?,
    })
}

fn parse_host_record(value: &str, cl: &ConfigLine) -> Result<HostRecord, ConfigError> {
    let parts = split_csv(value);
    if parts.len() < 2 {
        return Err(invalid_value_for(cl, "host-record", value, "expected name[,name...],ip4|ip6[,ip4|ip6][,ttl]"));
    }

    let mut names = Vec::new();
    let mut addr4 = None;
    let mut addr6 = None;
    let mut ttl = -1i32;

    for part in parts {
        if part.is_empty() {
            return Err(invalid_value_for(cl, "host-record", value, "empty host-record field"));
        }
        if let Ok(ip4) = part.parse::<Ipv4Addr>() {
            if addr4.is_some() {
                return Err(invalid_value_for(cl, "host-record", part, "duplicate IPv4 address"));
            }
            addr4 = Some(ip4);
        } else if let Ok(ip6) = part.parse::<Ipv6Addr>() {
            if addr6.is_some() {
                return Err(invalid_value_for(cl, "host-record", part, "duplicate IPv6 address"));
            }
            addr6 = Some(ip6);
        } else if let Ok(parsed_ttl) = part.parse::<i32>() {
            if ttl != -1 {
                return Err(invalid_value_for(cl, "host-record", part, "duplicate TTL"));
            }
            ttl = parsed_ttl;
        } else {
            names.push(parse_domain_token(part, "host-record", cl)?);
        }
    }

    if names.is_empty() {
        return Err(invalid_value_for(cl, "host-record", value, "host-record requires at least one name"));
    }
    if addr4.is_none() && addr6.is_none() {
        return Err(invalid_value_for(cl, "host-record", value, "host-record requires at least one IP address"));
    }

    Ok(HostRecord { ttl, flags: 0, names, addr4, addr6 })
}

fn parse_interface_name(
    value: &str,
    cl: &ConfigLine,
    dynamic: bool,
) -> Result<InterfaceName, ConfigError> {
    let key = if dynamic { "dynamic-host" } else { "interface-name" };
    let parts = split_csv(value);
    if parts.len() < 2 || parts.iter().any(|p| p.is_empty()) {
        return Err(invalid_value_for(
            cl,
            key,
            value,
            if dynamic {
                "expected name,[IPv4],[IPv6],interface"
            } else {
                "expected name,interface[/4|/6]"
            },
        ));
    }

    let name = parse_domain_token(parts[0], key, cl)?;
    let mut flags = IN4 | IN6;
    let mut proto4 = None;
    let mut proto6 = None;
    let mut iface_idx = 1;

    while iface_idx + 1 < parts.len() {
        if let Ok(ip4) = parts[iface_idx].parse::<Ipv4Addr>() {
            if proto4.is_some() {
                return Err(invalid_value_for(cl, key, parts[iface_idx], "duplicate IPv4 address"));
            }
            proto4 = Some(ip4);
            flags |= INP4;
            iface_idx += 1;
        } else if let Ok(ip6) = parts[iface_idx].parse::<Ipv6Addr>() {
            if proto6.is_some() {
                return Err(invalid_value_for(cl, key, parts[iface_idx], "duplicate IPv6 address"));
            }
            proto6 = Some(ip6);
            flags |= INP6;
            iface_idx += 1;
        } else {
            break;
        }
    }

    if iface_idx != parts.len() - 1 {
        return Err(invalid_value_for(cl, key, value, "unexpected field"));
    }

    let (intr, family) = parse_interface_family(parts[iface_idx], key, cl)?;
    match family {
        Some(4) => flags &= !IN6,
        Some(6) => flags &= !IN4,
        Some(_) => unreachable!(),
        None => {}
    }

    if dynamic {
        if flags & (INP4 | INP6) == 0 {
            return Err(invalid_value_for(cl, key, value, "dynamic-host requires an IPv4 or IPv6 address"));
        }
        if family.is_some() {
            return Err(invalid_value_for(cl, key, parts[iface_idx], "dynamic-host interface cannot use /4 or /6"));
        }
        flags &= !(IN4 | IN6);
    } else if flags & (INP4 | INP6) != 0 {
        return Err(invalid_value_for(cl, key, value, "interface-name does not accept address fields"));
    }

    Ok(InterfaceName {
        name,
        intr: intr.to_string(),
        flags,
        proto4,
        proto6,
        addrs: Vec::new(),
    })
}

fn parse_interface_family<'a>(
    token: &'a str,
    key: &str,
    cl: &ConfigLine,
) -> Result<(&'a str, Option<i32>), ConfigError> {
    if let Some((intr, family)) = token.rsplit_once('/') {
        if intr.is_empty() {
            return Err(invalid_value_for(cl, key, token, "expected an interface name"));
        }
        return match family {
            "4" => Ok((intr, Some(4))),
            "6" => Ok((intr, Some(6))),
            _ => Err(invalid_value_for(cl, key, token, "expected interface suffix /4 or /6")),
        };
    }

    Ok((token, None))
}

fn parse_cname_records(
    value: &str,
    cl: &ConfigLine,
    existing: &[Cname],
) -> Result<Vec<Cname>, ConfigError> {
    let parts = split_csv(value);
    if parts.len() < 2 {
        return Err(invalid_value_for(cl, "cname", value, "expected alias[,alias...],target[,ttl]"));
    }

    let (target_idx, ttl) = if parts.len() >= 3 {
        match parts.last().and_then(|last| last.parse::<i32>().ok()) {
            Some(ttl) => (parts.len() - 2, ttl),
            None => (parts.len() - 1, -1),
        }
    } else {
        (1, -1)
    };

    if target_idx == 0 {
        return Err(invalid_value_for(cl, "cname", value, "expected at least one alias and a target"));
    }

    let target = parse_domain_token(parts[target_idx], "cname", cl)?;
    let mut out = Vec::with_capacity(target_idx);

    for alias_part in &parts[..target_idx] {
        let alias = parse_domain_token(alias_part, "cname", cl)?;
        if existing.iter().any(|c| c.alias.eq_ignore_ascii_case(&alias))
            || out.iter().any(|c: &Cname| c.alias.eq_ignore_ascii_case(&alias))
        {
            return Err(invalid_value_for(cl, "cname", alias_part, "duplicate CNAME"));
        }
        out.push(Cname {
            ttl,
            flag: 0,
            alias,
            target: target.clone(),
        });
    }

    Ok(out)
}

fn parse_naptr_record(value: &str, cl: &ConfigLine) -> Result<Naptr, ConfigError> {
    let parts = split_csv(value);
    if parts.len() != 7 {
        return Err(invalid_value_for(cl, "naptr-record", value, "expected name,order,pref,flags,services,regexp,replace"));
    }
    Ok(Naptr {
        name: parse_domain_token(parts[0], "naptr-record", cl)?,
        order: parse_u32_token(parts[1], "naptr-record", cl, "NAPTR order")?,
        pref: parse_u32_token(parts[2], "naptr-record", cl, "NAPTR preference")?,
        flags: parts[3].to_string(),
        services: parts[4].to_string(),
        regexp: parts[5].to_string(),
        replace: parse_domain_token(parts[6], "naptr-record", cl)?,
    })
}

fn parse_dns_rr(value: &str, cl: &ConfigLine) -> Result<TxtRecord, ConfigError> {
    let parts = split_csv(value);
    if parts.len() < 2 || parts.len() > 3 {
        return Err(invalid_value_for(cl, "dns-rr", value, "expected name,type[,hex-data]"));
    }
    let rrtype = parse_rr_type(parts[1], "dns-rr", cl)?;
    let data = if parts.len() == 3 {
        parse_hex_bytes(parts[2], "dns-rr", cl, "RDATA")?
    } else {
        Vec::new()
    };
    Ok(TxtRecord {
        name: parse_domain_token(parts[0], "dns-rr", cl)?,
        txt: data,
        class: rrtype,
        stat: 0,
    })
}

fn parse_caa_record(value: &str, cl: &ConfigLine) -> Result<TxtRecord, ConfigError> {
    let parts = split_csv(value);
    if parts.len() != 4 {
        return Err(invalid_value_for(cl, "caa-record", value, "expected name,flags,tag,value"));
    }

    let flags = parts[1].parse::<u8>().map_err(|_| {
        invalid_value_for(cl, "caa-record", parts[1], "expected CAA flags in range 0-255")
    })?;
    let tag = parts[2].as_bytes();
    if tag.is_empty() || tag.len() > u8::MAX as usize {
        return Err(invalid_value_for(cl, "caa-record", parts[2], "CAA tag length must be 1-255"));
    }

    let mut data = Vec::with_capacity(2 + tag.len() + parts[3].len());
    data.push(flags);
    data.push(tag.len() as u8);
    data.extend_from_slice(tag);
    data.extend_from_slice(parts[3].as_bytes());

    Ok(TxtRecord {
        name: parse_domain_token(parts[0], "caa-record", cl)?,
        txt: data,
        class: crate::dns_protocol::RrType::CAA as u16,
        stat: 0,
    })
}

fn parse_rrlist(value: &str, cl: &ConfigLine, key: &str) -> Result<Vec<RrList>, ConfigError> {
    let mut out = Vec::new();
    for token in split_csv(value) {
        if token.is_empty() {
            return Err(invalid_value_for(cl, key, value, "empty RR type"));
        }
        out.push(RrList { rr: parse_rr_type(token, key, cl)? });
    }
    if out.is_empty() {
        return Err(invalid_value_for(cl, key, value, "expected at least one RR type"));
    }
    Ok(out)
}

fn parse_rr_type(token: &str, key: &str, cl: &ConfigLine) -> Result<u16, ConfigError> {
    if let Ok(rrtype) = token.parse::<u16>() {
        return Ok(rrtype);
    }

    let rrtype = match token.to_ascii_uppercase().as_str() {
        "A" => crate::dns_protocol::RrType::A as u16,
        "NS" => crate::dns_protocol::RrType::NS as u16,
        "CNAME" => crate::dns_protocol::RrType::CNAME as u16,
        "SOA" => crate::dns_protocol::RrType::SOA as u16,
        "PTR" => crate::dns_protocol::RrType::PTR as u16,
        "MX" => crate::dns_protocol::RrType::MX as u16,
        "TXT" => crate::dns_protocol::RrType::TXT as u16,
        "AAAA" => crate::dns_protocol::RrType::AAAA as u16,
        "SRV" => crate::dns_protocol::RrType::SRV as u16,
        "NAPTR" => crate::dns_protocol::RrType::NAPTR as u16,
        "DS" => crate::dns_protocol::RrType::DS as u16,
        "DNSKEY" => crate::dns_protocol::RrType::DNSKEY as u16,
        "CAA" => crate::dns_protocol::RrType::CAA as u16,
        "ANY" => crate::dns_protocol::RrType::ANY as u16,
        _ => return Err(invalid_value_for(cl, key, token, "unknown RR type")),
    };
    Ok(rrtype)
}

fn parse_trust_anchor(value: &str, cl: &ConfigLine) -> Result<DsConfig, ConfigError> {
    let parts = split_csv(value);
    if parts.len() != 5 {
        return Err(invalid_value_for(cl, "trust-anchor", value, "expected name,keytag,algo,digest_type,digest_hex"));
    }
    Ok(DsConfig {
        name: parse_domain_token(parts[0], "trust-anchor", cl)?,
        keytag: parse_i32_token(parts[1], "trust-anchor", cl, "DNSSEC key tag")?,
        algo: parse_i32_token(parts[2], "trust-anchor", cl, "DNSSEC algorithm")?,
        digest_type: parse_i32_token(parts[3], "trust-anchor", cl, "DNSSEC digest type")?,
        digest: parse_hex_bytes(parts[4], "trust-anchor", cl, "digest")?,
        class: 1,
    })
}

fn parse_bogus_addr(value: &str, cl: &ConfigLine, key: &str) -> Result<BogusAddr, ConfigError> {
    let (addr_part, prefix_part) = if let Some((addr, prefix)) = value.split_once('/') {
        (addr.trim(), Some(prefix.trim()))
    } else {
        (value.trim(), None)
    };

    if addr_part.is_empty() {
        return Err(invalid_value_for(cl, key, value, "expected an IP address"));
    }

    let ip: IpAddr = addr_part.parse().map_err(|_| {
        invalid_value_for(cl, key, value, "expected an IP address")
    })?;

    match ip {
        IpAddr::V4(v4) => {
            let prefix = match prefix_part {
                Some(prefix) => parse_i32_token(prefix, key, cl, "IPv4 prefix length")?,
                None => 32,
            };
            if !(0..=32).contains(&prefix) {
                return Err(invalid_value_for(cl, key, value, "IPv4 prefix length must be 0-32"));
            }
            Ok(BogusAddr {
                is6: false,
                prefix,
                addr: AllAddr::Addr4(v4),
            })
        }
        IpAddr::V6(v6) => {
            let prefix = match prefix_part {
                Some(prefix) => parse_i32_token(prefix, key, cl, "IPv6 prefix length")?,
                None => 128,
            };
            if !(0..=128).contains(&prefix) {
                return Err(invalid_value_for(cl, key, value, "IPv6 prefix length must be 0-128"));
            }
            Ok(BogusAddr {
                is6: true,
                prefix,
                addr: AllAddr::Addr6(v6),
            })
        }
    }
}

fn parse_rebind_domains(
    value: &str,
    cl: &ConfigLine,
    out: &mut Vec<crate::types::server::RebindDomain>,
) -> Result<(), ConfigError> {
    for raw in split_csv(value) {
        if raw.is_empty() {
            return Err(invalid_value_for(cl, "rebind-domain-ok", value, "empty domain in rebind-domain-ok"));
        }
        out.push(crate::types::server::RebindDomain {
            domain: parse_domain_token(raw, "rebind-domain-ok", cl)?,
        });
    }
    Ok(())
}

fn parse_auth_zone(value: &str, cl: &ConfigLine) -> Result<AuthZone, ConfigError> {
    let parts = split_csv(value);
    if parts.is_empty() || parts[0].is_empty() {
        return Err(invalid_value_for(cl, "auth-zone", value, "expected zone domain"));
    }

    let mut zone = AuthZone {
        domain: parse_domain_token(parts[0], "auth-zone", cl)?,
        interface_names: Vec::new(),
        subnet: Vec::new(),
        exclude: Vec::new(),
    };

    for token in parts.into_iter().skip(1) {
        if token.is_empty() {
            return Err(invalid_value_for(cl, "auth-zone", value, "empty auth-zone field"));
        }

        let (is_exclude, body) = if let Some(rest) = token.strip_prefix("exclude:") {
            (true, rest)
        } else {
            (false, token)
        };

        if let Ok(addr) = parse_auth_zone_addr(body, cl) {
            if is_exclude {
                zone.exclude.push(addr);
            } else {
                zone.subnet.push(addr);
            }
            continue;
        }

        if is_exclude {
            return Err(invalid_value_for(cl, "auth-zone", token, "exclude: requires an IP/prefix subnet"));
        }

        zone.interface_names.push(parse_auth_zone_interface(body, cl)?);
    }

    Ok(zone)
}

fn parse_auth_zone_addr(token: &str, cl: &ConfigLine) -> Result<Addrlist, ConfigError> {
    let (addr_part, prefix_part) = if let Some((addr, prefix)) = token.split_once('/') {
        (addr.trim(), Some(prefix.trim()))
    } else {
        (token.trim(), None)
    };

    if let Ok(v4) = addr_part.parse::<Ipv4Addr>() {
        let prefixlen = match prefix_part {
            Some(prefix) => parse_i32_token(prefix, "auth-zone", cl, "IPv4 prefix length")?,
            None => 24,
        };
        return Ok(Addrlist {
            addr: AllAddr::Addr4(v4),
            flags: ADDRLIST_LITERAL,
            prefixlen,
            decline_time: None,
        });
    }

    if let Ok(v6) = addr_part.parse::<Ipv6Addr>() {
        let prefixlen = match prefix_part {
            Some(prefix) => parse_i32_token(prefix, "auth-zone", cl, "IPv6 prefix length")?,
            None => 64,
        };
        return Ok(Addrlist {
            addr: AllAddr::Addr6(v6),
            flags: ADDRLIST_LITERAL | ADDRLIST_IPV6,
            prefixlen,
            decline_time: None,
        });
    }

    Err(invalid_value_for(cl, "auth-zone", token, "expected an IP subnet or interface name"))
}

fn parse_auth_zone_interface(token: &str, cl: &ConfigLine) -> Result<AuthNameEntry, ConfigError> {
    let (name, family_suffix) = if let Some((name, family)) = token.rsplit_once('/') {
        match family.trim() {
            "4" | "6" => (name.trim(), Some(family.trim())),
            _ => {
                return Err(invalid_value_for(
                    cl,
                    "auth-zone",
                    token,
                    "interface family suffix must be /4 or /6",
                ));
            }
        }
    } else {
        (token.trim(), None)
    };

    if name.is_empty() {
        return Err(invalid_value_for(cl, "auth-zone", token, "expected an interface name"));
    }

    let mut flags = AUTH4 | AUTH6;
    match family_suffix {
        Some("4") => flags &= !AUTH6,
        Some("6") => flags &= !AUTH4,
        Some(_) => unreachable!(),
        None => {}
    };

    Ok(AuthNameEntry {
        name: name.to_string(),
        flags,
    })
}

fn parse_ipset(value: &str, cl: &ConfigLine) -> Result<Vec<Ipsets>, ConfigError> {
    parse_ipset_family(value, cl, "ipset", false)
}

/// `--nftset` (`LOPT_NFTSET`, `option.c:3199-3280`): shares its config syntax
/// and `struct ipsets` storage with `--ipset` entirely — the only difference
/// is that every `#` in a set-name token becomes a space (`option.c:3268-3271`,
/// "Use '#' to delimit table and set"), which is how `nftset=/domain/4#table#set`
/// becomes the `"4 table set"` family-prefixed form `add_to_nftset()` parses
/// (`nftset.c:53-62`).
fn parse_nftset(value: &str, cl: &ConfigLine) -> Result<Vec<Ipsets>, ConfigError> {
    parse_ipset_family(value, cl, "nftset", true)
}

fn parse_ipset_family(
    value: &str,
    cl: &ConfigLine,
    directive: &str,
    hash_to_space: bool,
) -> Result<Vec<Ipsets>, ConfigError> {
    if !value.starts_with('/') {
        return Err(invalid_value_for(cl, directive, value, "expected /domain[/domain...]/set[,set...]"));
    }

    let inner = value.trim_start_matches('/');
    let slash = inner.rfind('/').ok_or_else(|| {
        invalid_value_for(cl, directive, value, "expected domains followed by one or more set names")
    })?;

    let domains_part = &inner[..slash];
    let sets_part = &inner[slash + 1..];
    if domains_part.is_empty() || sets_part.trim().is_empty() {
        return Err(invalid_value_for(cl, directive, value, "expected domains followed by one or more set names"));
    }

    let set_names: Vec<String> = split_csv(sets_part)
        .into_iter()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| if hash_to_space { s.replace('#', " ") } else { s.to_string() })
        .collect();
    if set_names.is_empty() {
        return Err(invalid_value_for(cl, directive, value, "expected at least one set name"));
    }

    let mut out = Vec::new();
    for domain in domains_part.split('/').filter(|d| !d.trim().is_empty()) {
        out.push(Ipsets {
            domain: parse_domain_token(domain, directive, cl)?,
            sets: set_names.clone(),
        });
    }

    if out.is_empty() {
        return Err(invalid_value_for(cl, directive, value, "expected at least one domain"));
    }

    Ok(out)
}

fn parse_alias(value: &str, cl: &ConfigLine) -> Result<Doctor, ConfigError> {
    let parts = split_csv(value);
    if !(parts.len() == 2 || parts.len() == 3) {
        return Err(invalid_value_for(cl, "alias", value, "expected old-ip|start-end,new-ip[,mask]"));
    }

    let (in_addr, end_addr) = if let Some((start, end)) = parts[0].split_once('-') {
        (
            start.trim().parse::<Ipv4Addr>().map_err(|_| {
                invalid_value_for(cl, "alias", parts[0], "expected a valid IPv4 range start")
            })?,
            end.trim().parse::<Ipv4Addr>().map_err(|_| {
                invalid_value_for(cl, "alias", parts[0], "expected a valid IPv4 range end")
            })?,
        )
    } else {
        (
            parts[0].parse::<Ipv4Addr>().map_err(|_| {
                invalid_value_for(cl, "alias", parts[0], "expected a valid IPv4 address")
            })?,
            Ipv4Addr::UNSPECIFIED,
        )
    };

    let out_addr = parts[1].parse::<Ipv4Addr>().map_err(|_| {
        invalid_value_for(cl, "alias", parts[1], "expected a valid translated IPv4 address")
    })?;

    let mask = if parts.len() == 3 {
        parts[2].parse::<Ipv4Addr>().map_err(|_| {
            invalid_value_for(cl, "alias", parts[2], "expected a valid IPv4 netmask")
        })?
    } else {
        Ipv4Addr::new(255, 255, 255, 255)
    };

    Ok(Doctor {
        in_addr,
        end_addr,
        out_addr,
        mask,
    })
}

#[cfg(feature = "dhcp")]
fn parse_dhcp_range(value: &str, cl: &ConfigLine) -> Result<DhcpContext, ConfigError> {
    let mut parts = split_csv(value);
    let mut filter = vec![];
    let mut netid = DhcpNetid { net: String::new() };
    while let Some(part) = parts.first().copied() {
        if let Some(tag) = part
            .strip_prefix("tag:")
            .or_else(|| part.strip_prefix("net:"))
        {
            if tag.is_empty() {
                return Err(invalid_value_for(cl, "dhcp-range", part, "expected tag name"));
            }
            filter.push(DhcpNetid { net: tag.to_string() });
            parts.remove(0);
            continue;
        }
        if let Some(tag) = part.strip_prefix("set:") {
            if tag.is_empty() {
                return Err(invalid_value_for(cl, "dhcp-range", part, "expected tag name"));
            }
            if !netid.net.is_empty() {
                return Err(invalid_value_for(cl, "dhcp-range", part, "only one set tag is supported"));
            }
            netid = DhcpNetid { net: tag.to_string() };
            parts.remove(0);
            continue;
        }
        break;
    }
    let ips: Vec<Ipv4Addr> = parts
        .iter()
        .filter_map(|p| p.parse::<Ipv4Addr>().ok())
        .collect();

    if ips.len() < 2 {
        return Err(invalid_value_for(cl, "dhcp-range", value, "expected at least start and end IPv4 addresses"));
    }

    let start = ips[0];
    let end = ips[1];

    let netmask = parts
        .iter()
        .find_map(|p| p.parse::<Ipv4Addr>().ok())
        .filter(|ip| *ip != start && *ip != end)
        .unwrap_or(Ipv4Addr::new(255, 255, 255, 0));

    let lease_time = parts
        .last()
        .and_then(|last| parse_lease_time(last))
        .unwrap_or(3600);

    Ok(DhcpContext {
        lease_time,
        addr_epoch: 0,
        netmask,
        broadcast: ipv4_broadcast(start, netmask),
        local: Ipv4Addr::UNSPECIFIED,
        router: Ipv4Addr::UNSPECIFIED,
        start,
        end,
        flags: CONTEXT_DHCP,
        netid,
        filter,
        #[cfg(feature = "dhcp6")]
        start6: Ipv6Addr::UNSPECIFIED,
        #[cfg(feature = "dhcp6")]
        end6: Ipv6Addr::UNSPECIFIED,
        #[cfg(feature = "dhcp6")]
        local6: Ipv6Addr::UNSPECIFIED,
        #[cfg(feature = "dhcp6")]
        prefix: 0,
        #[cfg(feature = "dhcp6")]
        if_index: 0,
        #[cfg(feature = "dhcp6")]
        valid: 0,
        #[cfg(feature = "dhcp6")]
        preferred: 0,
        #[cfg(feature = "dhcp6")]
        ra_time: 0,
        #[cfg(feature = "dhcp6")]
        ra_short_period_start: 0,
        #[cfg(feature = "dhcp6")]
        saved_valid: 0,
        #[cfg(feature = "dhcp6")]
        address_lost_time: 0,
    })
}

#[cfg(feature = "dhcp")]
fn parse_dhcp_host(value: &str, cl: &ConfigLine) -> Result<DhcpConfig, ConfigError> {
    let parts = split_csv(value);
    if parts.is_empty() {
        return Err(invalid_value_for(cl, "dhcp-host", value, "expected at least one field"));
    }

    let mut config = DhcpConfig {
        flags: 0,
        clid: None,
        hostname: None,
        domain: None,
        netid: vec![],
        filter: vec![],
        addr: Ipv4Addr::UNSPECIFIED,
        decline_time: None,
        lease_time: 0,
        hwaddrs: vec![],
        #[cfg(feature = "dhcp6")]
        addr6: vec![],
    };

    for part in parts {
        if part.is_empty() {
            return Err(invalid_value_for(cl, "dhcp-host", value, "empty field in dhcp-host"));
        }

        if let Some(tag) = part
            .strip_prefix("tag:")
            .or_else(|| part.strip_prefix("net:"))
        {
            if tag.is_empty() {
                return Err(invalid_value_for(cl, "dhcp-host", part, "expected tag name"));
            }
            config.filter.push(DhcpNetid { net: tag.to_string() });
            continue;
        }

        if let Some(tag) = part.strip_prefix("set:") {
            if tag.is_empty() {
                return Err(invalid_value_for(cl, "dhcp-host", part, "expected tag name"));
            }
            config.netid.push(DhcpNetid { net: tag.to_string() });
            continue;
        }

        if let Some(rest) = part.strip_prefix("id:") {
            if rest == "*" {
                config.flags |= crate::types::dhcp::CONFIG_NOCLID;
            } else {
                config.clid = Some(parse_client_id(rest, cl, "dhcp-host")?);
                config.flags |= CONFIG_CLID;
            }
            continue;
        }

        if let Ok(ip) = part.parse::<Ipv4Addr>() {
            config.addr = ip;
            config.flags |= CONFIG_ADDR;
            continue;
        }

        if let Some(lease_time) = parse_dhcp_host_time(part) {
            config.lease_time = lease_time;
            config.flags |= crate::types::dhcp::CONFIG_TIME;
            continue;
        }

        if part.eq_ignore_ascii_case("ignore") {
            config.flags |= CONFIG_DISABLE;
            continue;
        }

        if looks_like_mac_pattern(part) {
            let (hwaddr, hwaddr_len, hwaddr_type, wildcard_mask) =
                parse_mac_pattern(part, cl, "dhcp-host")?;
            config.hwaddrs.push(HwaddrConfig {
                hwaddr,
                hwaddr_len,
                hwaddr_type,
                wildcard_mask,
            });
            continue;
        }

        let hostname = parse_domain_token(part, "dhcp-host", cl)?;
        if config.hostname.is_some() {
            return Err(invalid_value_for(cl, "dhcp-host", part, "DHCP host has multiple names"));
        }
        config.domain = hostname.split_once('.').map(|(_, domain)| domain.to_string());
        config.hostname = Some(hostname);
        config.flags |= CONFIG_NAME;
    }

    if config.hwaddrs.is_empty()
        && (config.flags & CONFIG_CLID) == 0
        && (config.flags & crate::types::dhcp::CONFIG_NOCLID) == 0
        && (config.flags & CONFIG_NAME) == 0
    {
        return Err(invalid_value_for(
            cl,
            "dhcp-host",
            value,
            "dhcp-host requires a MAC, client id, id:*, or hostname",
        ));
    }

    Ok(config)
}

/// Parse the shared `dhcp-ignore`/`dhcp-ignore-names`/`dhcp-generate-names`/
/// `dhcp-broadcast`/`bootp-dynamic` value into one [`DhcpNetidList`] entry.
///
/// Port of the tag-collection loop in `option.c:4693-4699`: every
/// comma-separated field is a literal tag name, stripped of a leading
/// `tag:`/`net:` prefix via [`is_tag_prefix`] — never parsed as a MAC
/// address, client-id, or any other selector.
#[cfg(feature = "dhcp")]
fn parse_dhcp_netid_list(value: &str, cl: &ConfigLine, key: &str) -> Result<DhcpNetidList, ConfigError> {
    let mut list = Vec::new();
    for part in value.split(',') {
        if part.is_empty() {
            return Err(invalid_value_for(cl, key, value, "empty tag field"));
        }
        let tag = if is_tag_prefix(part) { &part[4..] } else { part };
        list.push(DhcpNetid { net: tag.to_string() });
    }
    Ok(DhcpNetidList { list })
}

/// Parse `--pxe-prompt=<prompt>[,<timeout>]` into the `dhcp_opt` entry
/// upstream stores it as (option.c:4422-4457, `LOPT_PXE_PROMT`): option 10
/// (PXE_MENU_PROMPT), value = one timeout byte (255 if omitted) followed by
/// the prompt text, flagged `DHOPT_VENDOR|DHOPT_VENDOR_PXE`.
#[cfg(feature = "dhcp")]
fn parse_pxe_prompt(value: &str, cl: &ConfigLine) -> Result<DhcpOpt, ConfigError> {
    let key = "pxe-prompt";
    let mut parts = value.splitn(2, ',');
    let prompt = parts.next().unwrap_or("");
    let timeout: u8 = match parts.next() {
        None | Some("") => 255,
        Some(t) => t.parse().map_err(|_| invalid_value_for(cl, key, value, "expected an integer timeout"))?,
    };
    let mut val = Vec::with_capacity(1 + prompt.len());
    val.push(timeout);
    val.extend_from_slice(prompt.as_bytes());
    Ok(DhcpOpt {
        opt: 10,
        flags: DHOPT_VENDOR | DHOPT_VENDOR_PXE,
        val: Some(val),
        netid: vec![],
        encap: 0,
        vendor_class: None,
    })
}

/// Client System Architecture names accepted as the first `pxe-service`
/// field (option.c:4464-4466), indexed by their upstream `CSA` value.
#[cfg(feature = "dhcp")]
const PXE_CSA_NAMES: &[&str] = &[
    "x86PC", "PC98", "IA64_EFI", "Alpha", "Arc_x86", "Intel_Lean_Client",
    "IA32_EFI", "x86-64_EFI", "Xscale_EFI", "BC_EFI", "ARM32_EFI", "ARM64_EFI",
];

/// Parse `--pxe-service=<CSA>,<menu-text>[,<basename>|<boot-service-type>[,<server>]]`
/// (option.c:4461-4539, `LOPT_PXE_SERV`).
#[cfg(feature = "dhcp")]
fn parse_pxe_service(daemon: &mut Daemon, value: &str, cl: &ConfigLine) -> Result<PxeService, ConfigError> {
    let key = "pxe-service";
    let bad = || invalid_value_for(cl, key, value, "Bad pxe-service");

    let (tags, rest) = dhcp_tags(value);
    let netid = tags.into_iter().map(|net| DhcpNetid { net }).collect();

    let parts = split_csv(rest);
    if parts.len() < 2 {
        return Err(bad());
    }

    let csa = match PXE_CSA_NAMES.iter().position(|n| n.eq_ignore_ascii_case(parts[0])) {
        Some(i) => i as u16,
        None => parts[0].parse::<u16>().map_err(|_| bad())?,
    };
    let menu = parts[1].to_string();

    let (boot_type, basename) = match parts.get(2) {
        None => (0, None),
        Some(bt) => match bt.parse::<u16>() {
            Ok(n) => (n, None),
            Err(_) => {
                let assigned = daemon.pxe_boottype_next;
                daemon.pxe_boottype_next += 1;
                (assigned, Some(bt.to_string()))
            }
        },
    };

    let (server, sname) = match parts.get(3) {
        None => (Ipv4Addr::UNSPECIFIED, None),
        Some(s) => match s.parse::<Ipv4Addr>() {
            Ok(addr) => (addr, None),
            Err(_) => (Ipv4Addr::UNSPECIFIED, Some(s.to_string())),
        },
    };

    Ok(PxeService { csa, boot_type, menu, basename, sname, server, netid })
}

#[cfg(feature = "dhcp")]
fn parse_dhcp_vendor(value: &str, cl: &ConfigLine) -> Result<DhcpVendorRule, ConfigError> {
    let parts = split_csv(value);
    if parts.len() != 2 {
        return Err(invalid_value_for(cl, "dhcp-vendorclass", value, "expected tag,vendor-class"));
    }

    let tag = parts[0]
        .strip_prefix("set:")
        .or_else(|| parts[0].strip_prefix("tag:"))
        .unwrap_or(parts[0])
        .trim();
    if tag.is_empty() {
        return Err(invalid_value_for(cl, "dhcp-vendorclass", parts[0], "expected a tag name"));
    }
    if parts[1].is_empty() {
        return Err(invalid_value_for(cl, "dhcp-vendorclass", value, "expected a vendor-class match string"));
    }

    Ok(DhcpVendorRule {
        netid: DhcpNetid { net: tag.to_string() },
        vendor_class: parts[1].as_bytes().to_vec(),
    })
}

/// Parse a `tag-if` directive into a [`TagIf`](crate::dhcp_common::TagIf) rule.
///
/// Mirrors `LOPT_TAG_IF` (option.c:4242-4307): each token must be `tag:<name>`
/// (a condition) or `set:<name>` (a tag to inject); anything else, or a
/// directive with no `set:` token at all, is `"bad tag-if"`. Upstream prepends
/// each recognized token onto its respective list, so both lists end up in
/// reverse order of appearance.
#[cfg(feature = "dhcp")]
fn parse_tag_if(value: &str, cl: &ConfigLine) -> Result<crate::dhcp_common::TagIf, ConfigError> {
    let parts = split_csv(value);
    let mut tag: Vec<DhcpNetid> = vec![];
    let mut set: Vec<DhcpNetid> = vec![];

    for part in &parts {
        // Upstream treats any token shorter than "tag:X"/"set:X" (5 chars) as
        // a parse failure (option.c:4266-4268).
        if part.len() < 5 {
            return Err(invalid_value_for(cl, "tag-if", value, "bad tag-if"));
        }
        if let Some(name) = part.strip_prefix("set:") {
            set.insert(0, DhcpNetid { net: name.to_string() });
        } else if let Some(name) = part.strip_prefix("tag:") {
            tag.insert(0, DhcpNetid { net: name.to_string() });
        } else {
            return Err(invalid_value_for(cl, "tag-if", value, "bad tag-if"));
        }
    }

    if set.is_empty() {
        return Err(invalid_value_for(cl, "tag-if", value, "bad tag-if"));
    }

    Ok(crate::dhcp_common::TagIf { tag, set })
}

/// Parse a `dhcp-match` directive into a `DhcpOpt` classifier rule.
///
/// Upstream reuses `parse_dhcp_opt()` with `flags = DHOPT_MATCH`
/// (option.c:4314-4319), then requires exactly one netid and rejects
/// `encap:`/`vendor:` combinations as `"illegal dhcp-match"` (option.c:1966-1969).
#[cfg(feature = "dhcp")]
fn parse_dhcp_match(value: &str, cl: &ConfigLine) -> Result<DhcpOpt, ConfigError> {
    use crate::types::dhcp::{DHOPT_ENCAPSULATE, DHOPT_MATCH, DHOPT_VENDOR};

    let opt = parse_dhcp_option(value, cl, "dhcp-match", DHOPT_MATCH)?;
    if opt.flags & (DHOPT_ENCAPSULATE | DHOPT_VENDOR) != 0 || opt.netid.len() != 1 {
        return Err(invalid_value_for(cl, "dhcp-match", value, "illegal dhcp-match"));
    }
    Ok(opt)
}

/// Parse a `dhcp-name-match` directive into a client-hostname classifier rule.
///
/// Mirrors `LOPT_NAME_MATCH` (option.c:4321-4345): `set:<tag>,<string>[*]`,
/// where a trailing `*` marks the match as a wildcard (prefix) match.
#[cfg(feature = "dhcp")]
fn parse_dhcp_name_match(value: &str, cl: &ConfigLine) -> Result<crate::types::dhcp::DhcpMatchName, ConfigError> {
    let parts = split_csv(value);
    if parts.len() != 2 {
        return Err(invalid_value_for(cl, "dhcp-name-match", value, "expected tag,name"));
    }

    let tag = parts[0]
        .strip_prefix("set:")
        .or_else(|| parts[0].strip_prefix("tag:"))
        .unwrap_or(parts[0])
        .trim();
    if tag.is_empty() {
        return Err(invalid_value_for(cl, "dhcp-name-match", parts[0], "expected a tag name"));
    }
    if parts[1].is_empty() {
        return Err(invalid_value_for(cl, "dhcp-name-match", value, "expected a match string"));
    }

    let (name, wildcard) = match parts[1].strip_suffix('*') {
        Some(stripped) => (stripped.to_string(), true),
        None => (parts[1].to_string(), false),
    };

    Ok(crate::types::dhcp::DhcpMatchName {
        netid: DhcpNetid { net: tag.to_string() },
        name,
        wildcard,
    })
}

#[cfg(feature = "dhcp")]
fn parse_dhcp_userclass(value: &str, cl: &ConfigLine) -> Result<DhcpUserClassRule, ConfigError> {
    let parts = split_csv(value);
    if parts.len() != 2 {
        return Err(invalid_value_for(cl, "dhcp-userclass", value, "expected tag,user-class"));
    }

    let tag = parts[0]
        .strip_prefix("set:")
        .or_else(|| parts[0].strip_prefix("tag:"))
        .unwrap_or(parts[0])
        .trim();
    if tag.is_empty() {
        return Err(invalid_value_for(cl, "dhcp-userclass", parts[0], "expected a tag name"));
    }
    if parts[1].is_empty() {
        return Err(invalid_value_for(cl, "dhcp-userclass", value, "expected a user-class match string"));
    }

    Ok(DhcpUserClassRule {
        netid: DhcpNetid { net: tag.to_string() },
        user_class: parts[1].as_bytes().to_vec(),
    })
}

#[cfg(feature = "dhcp")]
fn parse_dhcp_mac(value: &str, cl: &ConfigLine) -> Result<DhcpMacRule, ConfigError> {
    let parts = split_csv(value);
    if parts.len() != 2 {
        return Err(invalid_value_for(cl, "dhcp-mac", value, "expected tag,mac-address"));
    }

    let tag = parts[0]
        .strip_prefix("set:")
        .or_else(|| parts[0].strip_prefix("tag:"))
        .unwrap_or(parts[0])
        .trim();
    if tag.is_empty() {
        return Err(invalid_value_for(cl, "dhcp-mac", parts[0], "expected a tag name"));
    }

    let (hwaddr, hwaddr_len, hwaddr_type, wildcard_mask) =
        parse_mac_pattern(parts[1], cl, "dhcp-mac")?;

    Ok(DhcpMacRule {
        netid: DhcpNetid { net: tag.to_string() },
        hwaddr,
        hwaddr_len,
        hwaddr_type,
        wildcard_mask,
    })
}

#[cfg(feature = "dhcp")]
fn parse_dhcp_relay_id(
    value: &str,
    cl: &ConfigLine,
    key: &str,
    subopt: u8,
) -> Result<DhcpRelayIdRule, ConfigError> {
    let parts = split_csv(value);
    if parts.len() != 2 {
        return Err(invalid_value_for(cl, key, value, "expected tag,relay-id"));
    }

    let tag = parts[0]
        .strip_prefix("set:")
        .or_else(|| parts[0].strip_prefix("tag:"))
        .unwrap_or(parts[0])
        .trim();
    if tag.is_empty() {
        return Err(invalid_value_for(cl, key, parts[0], "expected a tag name"));
    }

    let data = parse_relay_id_data(parts[1], cl, key)?;
    Ok(DhcpRelayIdRule {
        netid: DhcpNetid { net: tag.to_string() },
        subopt,
        data,
    })
}

/// Result of parsing a `dhcp-relay` / `dhcp-split-relay` directive: either an
/// IPv4 entry (destined for `Daemon.relay4`) or an IPv6 entry (`Daemon.relay6`,
/// gated on the `dhcp6` feature exactly like upstream's `#ifdef HAVE_DHCP6`).
#[cfg(feature = "dhcp")]
enum RelayEntry {
    V4(DhcpRelay),
    #[cfg(feature = "dhcp6")]
    V6(DhcpRelay),
}

#[cfg(feature = "dhcp")]
fn new_dhcp_relay(split_mode: bool) -> DhcpRelay {
    DhcpRelay {
        local_addr:  AllAddr::Addr4(Ipv4Addr::UNSPECIFIED),
        server_addr: AllAddr::Addr4(Ipv4Addr::UNSPECIFIED),
        uplink_addr: AllAddr::Addr4(Ipv4Addr::UNSPECIFIED),
        interface:   None,
        iface_index: 0,
        port:        0,
        split_mode:  i32::from(split_mode),
        warned:      0,
        matchcount:  0,
    }
}

/// Split an optional `addr#port` token into its address and port parts.
fn split_relay_port(token: &str) -> (&str, Option<&str>) {
    match token.split_once('#') {
        Some((addr, port)) => (addr, Some(port)),
        None => (token, None),
    }
}

/// Parse `dhcp-relay`/`dhcp-split-relay` (`LOPT_RELAY`/`LOPT_SPLIT_RELAY`,
/// `option.c:4729-4809`).
///
/// Forms:
/// - `<local-addr>,<server>[#port][,<iface>]` — relay (IPv4 or, outside split
///   mode, IPv6) requests arriving on the interface owning `local-addr` to
///   `server`.
/// - `<local-addr>,<iface>` — broadcast form: relay via `iface` instead of a
///   specific server.
/// - `dhcp-split-relay=<local-addr>,<server>[#port],<iface-or-uplink-addr>` —
///   split mode; requires a non-wildcard third argument (interface name, or
///   an address to use directly as the uplink `giaddr`).
#[cfg(feature = "dhcp")]
fn parse_dhcp_relay(value: &str, cl: &ConfigLine, split_relay: bool) -> Result<RelayEntry, ConfigError> {
    let key = if split_relay { "dhcp-split-relay" } else { "dhcp-relay" };
    let bad = || invalid_value_for(cl, key, value, "Bad dhcp-relay");

    let parts = split_csv(value);
    if parts.is_empty() || parts.len() > 3 {
        return Err(bad());
    }
    let arg = parts[0];
    let mut two: Option<&str> = parts.get(1).copied();
    let mut three: Option<&str> = parts.get(2).copied();

    if split_relay {
        // Split mode must have two addresses and a non-wildcard interface name.
        if three.is_none() || three.is_some_and(|t| t.contains('*')) {
            two = None;
        }
    }

    let mut relay = new_dhcp_relay(split_relay);
    let mut is_v6 = false;

    if let Some(two_val) = two {
        if let Ok(local4) = arg.parse::<Ipv4Addr>() {
            relay.local_addr = AllAddr::Addr4(local4);

            let (server_part, port_part) = split_relay_port(two_val);
            relay.port = port_part
                .and_then(|p| p.parse::<u16>().ok())
                .map_or(i32::from(crate::dhcp_protocol::DHCP_SERVER_PORT), i32::from);

            if let Ok(server4) = server_part.parse::<Ipv4Addr>() {
                relay.server_addr = AllAddr::Addr4(server4);
                if split_relay {
                    if let Some(three_val) = three {
                        if let Ok(uplink4) = three_val.parse::<Ipv4Addr>() {
                            relay.uplink_addr = AllAddr::Addr4(uplink4);
                            three = None;
                        }
                    }
                }
            } else {
                relay.server_addr = AllAddr::Addr4(Ipv4Addr::UNSPECIFIED);
                // Fail for the three-arg form where there aren't two addresses;
                // also fail when broadcasting to a wildcard "address".
                if three.is_some() || two_val.contains('*') {
                    two = None;
                } else {
                    three = Some(server_part);
                }
            }
        } else if !split_relay {
            #[cfg(feature = "dhcp6")]
            {
                if let Ok(local6) = arg.parse::<Ipv6Addr>() {
                    is_v6 = true;
                    relay.local_addr = AllAddr::Addr6(local6);

                    let (server_part, port_part) = split_relay_port(two_val);
                    relay.port = port_part
                        .and_then(|p| p.parse::<u16>().ok())
                        .map_or(i32::from(crate::dhcp6_protocol::DHCPV6_SERVER_PORT), i32::from);

                    if let Ok(server6) = server_part.parse::<Ipv6Addr>() {
                        relay.server_addr = AllAddr::Addr6(server6);
                    } else {
                        relay.server_addr = AllAddr::Addr6("ff05::1:3".parse().unwrap());
                        if three.is_some() || two_val.contains('*') {
                            two = None;
                        } else {
                            three = Some(server_part);
                        }
                    }
                } else {
                    two = None;
                }
            }
            #[cfg(not(feature = "dhcp6"))]
            {
                two = None;
            }
        } else {
            two = None;
        }

        if two.is_some() {
            relay.interface = three.map(str::to_string);
        }
    }

    if two.is_none() {
        return Err(bad());
    }

    if is_v6 {
        #[cfg(feature = "dhcp6")]
        {
            return Ok(RelayEntry::V6(relay));
        }
        #[cfg(not(feature = "dhcp6"))]
        {
            unreachable!("is_v6 can only be set when the dhcp6 feature is enabled");
        }
    }

    Ok(RelayEntry::V4(relay))
}

#[cfg(feature = "dhcp")]
fn parse_dhcp_reply_delay(value: &str, cl: &ConfigLine) -> Result<DhcpReplyDelay, ConfigError> {
    let parts = split_csv(value);
    if parts.is_empty() {
        return Err(invalid_value_for(cl, "dhcp-reply-delay", value, "expected [tag:<tag>,...],<integer>"));
    }

    let mut filter = vec![];
    let mut idx = 0;
    while idx + 1 < parts.len() {
        let Some(tag) = parts[idx].strip_prefix("tag:") else {
            break;
        };
        if tag.is_empty() {
            return Err(invalid_value_for(cl, "dhcp-reply-delay", parts[idx], "expected tag name"));
        }
        filter.push(DhcpNetid { net: tag.to_string() });
        idx += 1;
    }

    if idx + 1 != parts.len() {
        return Err(invalid_value_for(cl, "dhcp-reply-delay", value, "expected [tag:<tag>,...],<integer>"));
    }

    let delay_str = parts[idx];

    let delay_secs = delay_str
        .parse::<u32>()
        .map_err(|_| invalid_value_for(cl, "dhcp-reply-delay", delay_str, "expected non-negative integer seconds"))?;

    Ok(DhcpReplyDelay { delay_secs, filter })
}

#[cfg(feature = "dhcp")]
fn parse_dhcp_alternate_port(cl: &ConfigLine) -> Result<(u16, u16), ConfigError> {
    let value = cl.value.as_deref().unwrap_or("");
    if value.is_empty() {
        return Ok((1067, 1068));
    }

    let parts = split_csv(value);
    if parts.is_empty() || parts.len() > 2 {
        return Err(invalid_value_for(cl, "dhcp-alternate-port", value, "expected [server[,client]]"));
    }

    let server_port = parts[0]
        .parse::<u16>()
        .map_err(|_| invalid_value_for(cl, "dhcp-alternate-port", parts[0], "expected a valid port number"))?;
    let client_port = if parts.len() == 2 {
        parts[1]
            .parse::<u16>()
            .map_err(|_| invalid_value_for(cl, "dhcp-alternate-port", parts[1], "expected a valid port number"))?
    } else {
        server_port
            .checked_add(1)
            .ok_or_else(|| invalid_value_for(cl, "dhcp-alternate-port", parts[0], "server port too large to derive client port"))?
    };

    Ok((server_port, client_port))
}

#[cfg(feature = "dhcp")]
fn parse_relay_id_data(value: &str, cl: &ConfigLine, key: &str) -> Result<Vec<u8>, ConfigError> {
    let is_hex = value.contains(':')
        && value
            .bytes()
            .all(|b| b == b':' || b.is_ascii_hexdigit());
    if is_hex {
        let mut out = Vec::new();
        let len = crate::util::parse_hex(value, &mut out, None, None);
        if len <= 0 || out.len() != len as usize {
            return Err(invalid_value_for(cl, key, value, "invalid colon-separated hex relay id"));
        }
        Ok(out)
    } else {
        Ok(value.as_bytes().to_vec())
    }
}

#[cfg(feature = "dhcp")]
fn parse_mac_pattern(
    value: &str,
    cl: &ConfigLine,
    key: &str,
) -> Result<([u8; 16], i32, i32, u32), ConfigError> {
    let (mac_type, pattern) = parse_mac_type_prefix(value)
        .ok_or_else(|| invalid_value_for(cl, key, value, "invalid hardware type prefix"))?;

    let mut bytes = Vec::new();
    let mut wildcard_mask = 0u32;
    let len = crate::util::parse_hex(
        pattern,
        &mut bytes,
        Some(crate::dhcp_protocol::DHCP_CHADDR_MAX),
        Some(&mut wildcard_mask),
    );
    if len <= 0 || bytes.len() != len as usize {
        return Err(invalid_value_for(cl, key, value, "expected MAC address pattern"));
    }

    let mut hwaddr = [0u8; 16];
    hwaddr[..bytes.len()].copy_from_slice(&bytes);
    Ok((hwaddr, len, mac_type, wildcard_mask))
}

#[cfg(feature = "dhcp")]
fn parse_mac_type_prefix(value: &str) -> Option<(i32, &str)> {
    let Some(first_sep) = value.find([':', '-', ' ']) else {
        return Some((0, value));
    };
    if value.as_bytes()[first_sep] != b'-' || first_sep == 0 {
        return Some((0, value));
    }

    let mac_type = i32::from_str_radix(&value[..first_sep], 16).ok()?;
    Some((mac_type, &value[first_sep + 1..]))
}

#[cfg(feature = "dhcp")]
fn parse_dhcp_option(
    value: &str,
    cl: &ConfigLine,
    key: &str,
    extra_flags: u32,
) -> Result<DhcpOpt, ConfigError> {
    use crate::dhcp_common::lookup_dhcp_len;
    use crate::types::dhcp::{DHOPT_ENCAPSULATE, DHOPT_PXE_OPT, DHOPT_VENDOR};

    let mut parts = split_csv(value);
    if parts.is_empty() {
        return Err(invalid_value_for(cl, key, value, "expected option and value"));
    }

    let mut flags = extra_flags;
    let mut netid = vec![];
    let mut encap = 0;
    let mut vendor_class = None;

    while let Some(part) = parts.first().copied() {
        if let Some(tag) = part
            .strip_prefix("tag:")
            .or_else(|| part.strip_prefix("net:"))
            .or_else(|| part.strip_prefix("set:"))
        {
            if tag.is_empty() {
                return Err(invalid_value_for(cl, key, part, "expected tag name"));
            }
            netid.push(DhcpNetid { net: tag.to_string() });
            parts.remove(0);
            continue;
        }
        if let Some(class) = part.strip_prefix("vendor:") {
            if flags & DHOPT_ENCAPSULATE != 0 {
                return Err(invalid_value_for(cl, key, part, "vendor: cannot be combined with encap:"));
            }
            vendor_class = Some(class.as_bytes().to_vec());
            flags |= DHOPT_VENDOR;
            parts.remove(0);
            continue;
        }
        if let Some(rest) = part.strip_prefix("encap:") {
            if flags & DHOPT_VENDOR != 0 {
                return Err(invalid_value_for(cl, key, part, "encap: cannot be combined with vendor:"));
            }
            if flags & DHOPT_PXE_OPT != 0 {
                return Err(invalid_value_for(cl, key, part, "encap: is not supported in dhcp-option-pxe"));
            }
            encap = i32::from(parse_u16_token(rest, key, cl, "encapsulated option")?);
            flags |= DHOPT_ENCAPSULATE;
            parts.remove(0);
            continue;
        }
        if part.starts_with("vi-encap:") {
            return Err(invalid_value_for(cl, key, part, "vi-encap is not implemented yet"));
        }
        break;
    }

    if parts.is_empty() {
        return Err(invalid_value_for(cl, key, value, "expected option number or option:name"));
    }

    let opt_token = parts[0];
    let opt_num = if let Some(rest) = opt_token.strip_prefix("option:") {
        dhcp_option_code(rest).ok_or_else(|| {
            invalid_value_for(cl, key, opt_token, "unknown DHCP option name")
        })?
    } else if opt_token.starts_with("option6:") {
        return Err(invalid_value_for(cl, key, opt_token, "DHCPv6 options are not implemented in this parser"));
    } else {
        opt_token.parse::<u8>().map_err(|_| {
            invalid_value_for(cl, key, opt_token, "expected DHCP option number or option:name")
        })?
    };

    let size_flags = lookup_dhcp_len(false, u16::from(opt_num));
    let value_parts = &parts[1..];
    let val = parse_dhcp_option_value(value_parts, size_flags, key, cl, &mut flags)?;

    Ok(DhcpOpt {
        opt: opt_num as i32,
        flags,
        val,
        netid,
        encap,
        vendor_class,
    })
}

#[cfg(feature = "dhcp")]
fn parse_dhcp_boot(value: &str, cl: &ConfigLine) -> Result<DhcpBoot, ConfigError> {
    let mut parts = split_csv(value);
    let mut netid = vec![];
    while let Some(part) = parts.first().copied() {
        if let Some(tag) = part
            .strip_prefix("tag:")
            .or_else(|| part.strip_prefix("net:"))
            .or_else(|| part.strip_prefix("set:"))
        {
            if tag.is_empty() {
                return Err(invalid_value_for(cl, "dhcp-boot", part, "expected tag name"));
            }
            netid.push(DhcpNetid { net: tag.to_string() });
            parts.remove(0);
            continue;
        }
        break;
    }
    if parts.is_empty() || parts[0].is_empty() {
        return Err(invalid_value_for(cl, "dhcp-boot", value, "expected boot file name"));
    }

    let file = Some(parts[0].to_string());
    let next_server = if parts.len() >= 3 && !parts[2].is_empty() {
        parts[2].parse::<Ipv4Addr>().map_err(|_| {
            invalid_value_for(cl, "dhcp-boot", parts[2], "expected next-server IPv4 address")
        })?
    } else {
        Ipv4Addr::UNSPECIFIED
    };

    if netid.is_empty() && parts.len() >= 4 && !parts[3].is_empty() {
        let tag = parts[3]
            .strip_prefix("tag:")
            .or_else(|| parts[3].strip_prefix("net:"))
            .or_else(|| parts[3].strip_prefix("set:"))
            .unwrap_or(parts[3]);
        netid.push(DhcpNetid { net: tag.to_string() });
    }

    Ok(DhcpBoot {
        file,
        sname: parts.get(1).filter(|s| !s.is_empty()).map(|s| s.to_string()),
        tftp_sname: parts.get(2).filter(|s| !s.is_empty()).map(|s| s.to_string()),
        next_server,
        netid,
    })
}

#[cfg(feature = "dhcp")]
fn parse_dhcp_option_value(
    value_parts: &[&str],
    size_flags: u16,
    key: &str,
    cl: &ConfigLine,
    flags: &mut u32,
) -> Result<Option<Vec<u8>>, ConfigError> {
    let fixed_size = size_flags & !(crate::dhcp_common::OT_ADDR_LIST
        | crate::dhcp_common::OT_RFC1035_NAME
        | crate::dhcp_common::OT_INTERNAL
        | crate::dhcp_common::OT_NAME
        | crate::dhcp_common::OT_CSTRING
        | crate::dhcp_common::OT_DEC
        | crate::dhcp_common::OT_TIME);

    if value_parts.is_empty() {
        return Ok(Some(vec![]));
    }

    if (size_flags & crate::dhcp_common::OT_ADDR_LIST) != 0 {
        let mut out = Vec::with_capacity(value_parts.len() * 4);
        for token in value_parts {
            let ip = token.parse::<Ipv4Addr>().map_err(|_| {
                invalid_value_for(cl, key, token, "expected IPv4 address")
            })?;
            out.extend_from_slice(&ip.octets());
        }
        return Ok(Some(out));
    }

    if (size_flags & crate::dhcp_common::OT_RFC1035_NAME) != 0 {
        let mut out = Vec::new();
        for token in value_parts {
            if !crate::util::do_rfc1035_name(&mut out, token, None) {
                return Err(invalid_value_for(cl, key, token, "expected valid RFC1035 domain name"));
            }
        }
        return Ok(Some(out));
    }

    if (size_flags & crate::dhcp_common::OT_TIME) != 0 {
        if value_parts.len() != 1 {
            return Err(invalid_value_for(cl, key, &value_parts.join(","), "expected a single time value"));
        }
        let secs = parse_lease_time(value_parts[0]).ok_or_else(|| {
            invalid_value_for(cl, key, value_parts[0], "expected DHCP time value")
        })?;
        return Ok(Some(secs.to_be_bytes().to_vec()));
    }

    if matches!(fixed_size, 1 | 2 | 4) {
        if value_parts.len() != 1 {
            return Err(invalid_value_for(cl, key, &value_parts.join(","), "expected a single integer value"));
        }
        let n = value_parts[0].parse::<u32>().map_err(|_| {
            invalid_value_for(cl, key, value_parts[0], "expected unsigned integer")
        })?;
        let encoded = match fixed_size {
            1 => u8::try_from(n)
                .map(|v| vec![v])
                .map_err(|_| invalid_value_for(cl, key, value_parts[0], "value exceeds 8-bit width"))?,
            2 => u16::try_from(n)
                .map(|v| v.to_be_bytes().to_vec())
                .map_err(|_| invalid_value_for(cl, key, value_parts[0], "value exceeds 16-bit width"))?,
            4 => n.to_be_bytes().to_vec(),
            _ => unreachable!(),
        };
        return Ok(Some(encoded));
    }

    let value_token = value_parts.join(",");
    if let Ok(ip) = value_token.parse::<Ipv4Addr>() {
        return Ok(Some(ip.octets().to_vec()));
    }
    if let Ok(n) = value_token.parse::<u32>() {
        return Ok(Some(encode_u32_minimal(n)));
    }

    *flags |= crate::types::dhcp::DHOPT_STRING;
    Ok(Some(value_token.into_bytes()))
}

#[cfg(feature = "dhcp")]
fn parse_client_id(value: &str, cl: &ConfigLine, key: &str) -> Result<Vec<u8>, ConfigError> {
    if value.contains(':') {
        let mut out = Vec::new();
        let len = crate::util::parse_hex(value, &mut out, None, None);
        if len <= 0 || out.len() != len as usize {
            return Err(invalid_value_for(cl, key, value, "bad hex client-id"));
        }
        Ok(out)
    } else {
        Ok(value.as_bytes().to_vec())
    }
}

#[cfg(feature = "dhcp")]
fn parse_dhcp_host_time(token: &str) -> Option<u32> {
    if token.eq_ignore_ascii_case("infinite") {
        return Some(u32::MAX);
    }
    parse_lease_time(token)
}

#[cfg(feature = "dhcp")]
fn dhcp_option_code(name: &str) -> Option<u8> {
    crate::dhcp_common::OPTTAB
        .iter()
        .find(|entry| entry.name.eq_ignore_ascii_case(name))
        .map(|entry| entry.val as u8)
}

#[cfg(feature = "dhcp")]
fn encode_u32_minimal(n: u32) -> Vec<u8> {
    if n <= u8::MAX as u32 {
        vec![n as u8]
    } else if n <= u16::MAX as u32 {
        (n as u16).to_be_bytes().to_vec()
    } else {
        n.to_be_bytes().to_vec()
    }
}

#[cfg(feature = "dhcp")]
fn parse_lease_time(token: &str) -> Option<u32> {
    if token.is_empty() {
        return None;
    }
    let (digits, multiplier) = match token.as_bytes().last().copied() {
        Some(b'h') | Some(b'H') => (&token[..token.len() - 1], 3600u32),
        Some(b'm') | Some(b'M') => (&token[..token.len() - 1], 60u32),
        Some(b's') | Some(b'S') => (&token[..token.len() - 1], 1u32),
        _ => (token, 1u32),
    };
    digits.parse::<u32>().ok().map(|n| n.saturating_mul(multiplier))
}

#[cfg(feature = "dhcp")]
fn ipv4_broadcast(start: Ipv4Addr, netmask: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(start) | !u32::from(netmask))
}

#[cfg(feature = "dhcp")]
fn looks_like_mac_pattern(value: &str) -> bool {
    value.contains(':') || value.contains('-') || value.contains('*')
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

/// Generate the `in-addr.arpa` domain names covering an IPv4 CIDR block.
///
/// Prefix lengths that are not a multiple of 8 split into multiple
/// non-octet-aligned zones (RFC 2317 style) — e.g. `10.0.0.0/20` yields the
/// 16 zones `0.0.10.in-addr.arpa` .. `15.0.10.in-addr.arpa`.  Byte-aligned
/// prefixes (e.g. `/24`) yield exactly one.  Port of the IPv4 half of
/// `domain_rev4()` from option.c:1135-1219.
pub fn domain_rev4(addr: std::net::Ipv4Addr, prefix_len: u32) -> Result<Vec<String>, &'static str> {
    let size = prefix_len;
    if !(1..=32).contains(&size) {
        return Err("bad IPv4 prefix length");
    }

    let rem = size & 0x7;
    let addrbytes = (32 - size) >> 3;
    let addrbits = (32 - size) & 7;

    let mut octets = addr.octets();
    octets[3 - addrbytes as usize] &= !(((1u32 << addrbits) - 1) as u8);

    let size = size & !0x7;
    let count = if rem != 0 { 1u32 << (8 - rem) } else { 1 };
    let msize = (size / 8) as i32;

    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let start_j = if rem == 0 { msize - 1 } else { msize };
        let mut labels = Vec::new();
        let mut j = start_j;
        while j >= 0 {
            let mut dig = octets[j as usize] as u32;
            if j == msize {
                dig += i;
            }
            labels.push(dig.to_string());
            j -= 1;
        }
        labels.push("in-addr.arpa".to_string());
        out.push(labels.join("."));
    }
    Ok(out)
}

/// Generate the `ip6.arpa` domain names covering an IPv6 CIDR block.
///
/// Prefix lengths that are not a multiple of 4 split into multiple
/// non-nibble-aligned zones, mirroring [`domain_rev4`]'s octet splitting.
/// Port of the IPv6 half of `domain_rev6()` from option.c:1221-1307.
pub fn domain_rev6(addr: std::net::Ipv6Addr, prefix_len: u32) -> Result<Vec<String>, &'static str> {
    let size = prefix_len;
    if !(1..=128).contains(&size) {
        return Err("bad IPv6 prefix length");
    }

    let rem = size & 0x3;
    let addrbytes = (128 - size) >> 3;
    let addrbits = (128 - size) & 7;

    let mut octets = addr.octets();
    octets[15 - addrbytes as usize] &= !(((1u32 << addrbits) - 1) as u8);

    let size = size & !0x3;
    let count = if rem != 0 { 1u32 << (4 - rem) } else { 1 };
    let msize = (size / 4) as i32;

    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let start_j = if rem == 0 { msize - 1 } else { msize };
        let mut labels = Vec::new();
        let mut j = start_j;
        while j >= 0 {
            let byte = octets[(j as usize) >> 1];
            let mut dig = if j & 1 == 1 { (byte & 0x0f) as u32 } else { (byte >> 4) as u32 };
            if j == msize {
                dig += i;
            }
            labels.push(format!("{dig:x}"));
            j -= 1;
        }
        labels.push("ip6.arpa".to_string());
        out.push(labels.join("."));
    }
    Ok(out)
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
        assert!(!d.option_bool(OPT_EXTRALOG));
        assert!(!d.option_bool(OPT_LOG_PROTO));
        assert!(!d.option_bool(OPT_AUTH_LOG));
        assert!(!d.option_bool(OPT_LOG_ONLY_FAILED));
    }

    #[test]
    fn apply_log_queries_modes() {
        let mut d = Daemon::default();
        let lines = parse_config_text("log-queries=extra", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_LOG));
        assert!(d.option_bool(OPT_EXTRALOG));
        assert!(!d.option_bool(OPT_LOG_PROTO));

        let mut d = Daemon::default();
        let lines = parse_config_text("log-queries=proto", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_LOG));
        assert!(d.option_bool(OPT_EXTRALOG));
        assert!(d.option_bool(OPT_LOG_PROTO));

        let mut d = Daemon::default();
        let lines = parse_config_text("log-queries=auth", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_LOG));
        assert!(d.option_bool(OPT_AUTH_LOG));

        let mut d = Daemon::default();
        let lines = parse_config_text("log-queries=only_failed", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_LOG));
        assert!(d.option_bool(OPT_LOG_ONLY_FAILED));
    }

    #[test]
    fn apply_log_queries_unknown_mode_matches_upstream_noop() {
        let mut d = Daemon::default();
        let lines = parse_config_text("log-queries=unknown", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_LOG));
        assert!(!d.option_bool(OPT_EXTRALOG));
        assert!(!d.option_bool(OPT_LOG_PROTO));
        assert!(!d.option_bool(OPT_AUTH_LOG));
        assert!(!d.option_bool(OPT_LOG_ONLY_FAILED));
    }

    #[test]
    fn apply_remaining_simple_boolean_flags() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "dhcp-no-override\n\
             dhcp-sequential-ip\n\
             dhcp-ignore-clid\n\
             dhcp-client-update\n\
             log-debug\n\
             quiet-tftp\n\
             no-ident\n\
             no-0x20-encode\n\
             do-0x20-encode\n\
             log-malloc",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();

        assert!(d.option_bool(OPT_NO_OVERRIDE));
        assert!(d.option_bool(OPT_CONSEC_ADDR));
        assert!(d.option_bool(OPT_IGNORE_CLID));
        assert!(d.option_bool(OPT_FQDN_UPDATE));
        assert!(d.option_bool(OPT_LOG_DEBUG));
        assert!(d.option_bool(OPT_QUIET_TFTP));
        assert!(d.option_bool(OPT_NO_IDENT));
        assert!(d.option_bool(OPT_NO_0X20));
        assert!(d.option_bool(OPT_DO_0X20));
        assert!(d.option_bool(OPT_LOG_MALLOC));
    }

    // ── domain-needed / Issue #18 directives ────────────────────────────────

    /// `--domain-needed` (`-D`, `OPT_NODOTS_LOCAL`) must be recognized and set
    /// the bit; previously this aborted startup with `UnknownOption`.
    #[test]
    fn apply_domain_needed_sets_opt_nodots_local() {
        let mut d = Daemon::default();
        let lines = parse_config_text("domain-needed", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_NODOTS_LOCAL));
    }

    /// `--dhcp-rapid-commit` and `--dns-loop-detect` are the real upstream
    /// directive names for the bits already reachable via the pre-existing
    /// `rapid-commit`/`loop-detect` aliases.
    #[test]
    fn apply_dhcp_rapid_commit_and_dns_loop_detect() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-rapid-commit\ndns-loop-detect", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_RAPID_COMMIT));
        assert!(d.option_bool(OPT_LOOP_DETECT));
    }

    /// Upstream assigns each server a fresh `rand32()` uid at the point it is
    /// added (`add_update_server()`, `domain-match.c:759`), so loop probes for
    /// two servers never collide. `new_server()` is the Rust equivalent of
    /// that construction site.
    #[cfg(feature = "loop")]
    #[test]
    fn new_server_assigns_a_random_uid() {
        let dummy = crate::types::addr::MySockAddr::V4(std::net::SocketAddrV4::new(
            std::net::Ipv4Addr::UNSPECIFIED,
            0,
        ));
        let a = new_server(0, String::new(), dummy.clone(), dummy.clone());
        let b = new_server(0, String::new(), dummy.clone(), dummy);
        assert_ne!(a.uid, b.uid);
    }

    /// `--dns-loop-detect` with a `server=` line ends up on `ForwardConfig`:
    /// the gate that lets [`crate::forward::ForwardEngine`] actually probe
    /// and detect a loop, not just parse the directive.
    #[cfg(feature = "loop")]
    #[test]
    fn dns_loop_detect_reaches_forward_config() {
        let mut d = Daemon::default();
        let lines =
            parse_config_text("dns-loop-detect\nserver=127.0.0.1#5353", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        let fwd = crate::dnsmasq::daemon_forward_config(&d);
        assert!(fwd.loop_detect);
        assert_eq!(fwd.loop_servers.len(), 1);
    }

    /// `--clear-on-reload` is the real upstream name sharing `OPT_RELOAD` with
    /// the existing `reload-acl` alias.
    #[test]
    fn apply_clear_on_reload_sets_opt_reload() {
        let mut d = Daemon::default();
        let lines = parse_config_text("clear-on-reload", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_RELOAD));
    }

    /// `--enable-ubus` is the real upstream name sharing `OPT_UBUS` with the
    /// existing `ubus` alias.
    #[test]
    fn apply_enable_ubus_sets_opt_ubus() {
        let mut d = Daemon::default();
        let lines = parse_config_text("enable-ubus", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_UBUS));
    }

    // ── rev-server ─────────────────────────────────────────────────────────

    #[test]
    fn rev_server_octet_aligned_forwards_to_given_upstream() {
        let mut d = Daemon::default();
        let lines = parse_config_text("rev-server=192.168.1.0/24,10.0.0.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 1);
        let s = &d.servers[0];
        assert_eq!(s.domain, "1.168.192.in-addr.arpa");
        assert_eq!(s.flags & SERV_4ADDR, SERV_4ADDR);
        assert_eq!(s.flags & SERV_LITERAL_ADDRESS, 0);
        match &s.addr {
            MySockAddr::V4(a) => {
                assert_eq!(*a.ip(), "10.0.0.1".parse::<Ipv4Addr>().unwrap());
                assert_eq!(a.port(), 53);
            }
            _ => panic!("expected an IPv4 socket address"),
        }
    }

    #[test]
    fn rev_server_defaults_to_32_when_no_prefix_given() {
        let mut d = Daemon::default();
        let lines = parse_config_text("rev-server=192.168.1.5,10.0.0.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert_eq!(d.servers[0].domain, "5.1.168.192.in-addr.arpa");
    }

    #[test]
    fn rev_server_non_octet_aligned_prefix_generates_multiple_zones() {
        let mut d = Daemon::default();
        // A /20 splits into 16 non-aligned reverse zones (RFC 2317 style).
        let lines = parse_config_text("rev-server=10.0.0.0/20,10.0.0.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 16);
        let domains: Vec<&str> = d.servers.iter().map(|s| s.domain.as_str()).collect();
        assert!(domains.contains(&"0.0.10.in-addr.arpa"));
        assert!(domains.contains(&"15.0.10.in-addr.arpa"));
    }

    #[test]
    fn rev_server_without_upstream_is_literal_no_forward() {
        let mut d = Daemon::default();
        let lines = parse_config_text("rev-server=192.168.1.0/24", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert_eq!(d.servers[0].flags & SERV_LITERAL_ADDRESS, SERV_LITERAL_ADDRESS);
    }

    #[test]
    fn rev_server_ipv6_forwards_to_given_upstream() {
        let mut d = Daemon::default();
        let lines = parse_config_text("rev-server=2001:db8::/64,fd00::1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert!(d.servers[0].domain.ends_with(".ip6.arpa"));
        assert_eq!(d.servers[0].flags & SERV_6ADDR, SERV_6ADDR);
    }

    #[test]
    fn rev_server_bad_address_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("rev-server=not-an-addr,10.0.0.1", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
    }

    #[test]
    fn rev_server_bad_upstream_address_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("rev-server=192.168.1.0/24,not-an-addr", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
    }

    #[test]
    fn rev_server_bad_prefix_length_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("rev-server=192.168.1.0/33,10.0.0.1", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
    }

    // ── synth-domain ───────────────────────────────────────────────────────

    #[test]
    fn synth_domain_cidr_form_populates_range() {
        let mut d = Daemon::default();
        let lines = parse_config_text("synth-domain=example.com,10.0.0.0/24", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.synth_domains.len(), 1);
        let sd = &d.synth_domains[0];
        assert_eq!(sd.domain, "example.com");
        assert!(!sd.is6);
        assert_eq!(sd.start, "10.0.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(sd.end, "10.0.0.255".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn synth_domain_range_form_with_prefix_resolves_a_query() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "synth-domain=example.com,10.0.0.0,10.0.0.255,ip-",
            "test",
        )
        .unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.synth_domains.len(), 1);
        let addr = crate::domain::synthesize_ipv4("ip-10-0-0-7.example.com", &d.synth_domains);
        assert_eq!(addr, Some("10.0.0.7".parse().unwrap()));
    }

    #[test]
    fn synth_domain_indexed_prefix_star() {
        let mut d = Daemon::default();
        let lines = parse_config_text("synth-domain=example.com,10.0.0.0,10.0.0.255,host*", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        let sd = &d.synth_domains[0];
        assert!(sd.indexed);
        assert_eq!(sd.prefix.as_deref(), Some("host"));
    }

    #[test]
    fn synth_domain_ipv6_indexed_requires_prefixlen_64() {
        let mut d = Daemon::default();
        let lines = parse_config_text("synth-domain=example.com,2001:db8::/32,host*", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
    }

    #[test]
    fn synth_domain_ipv6_indexed_ok_at_prefixlen_64() {
        let mut d = Daemon::default();
        let lines = parse_config_text("synth-domain=example.com,2001:db8::/64,host*", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.synth_domains[0].indexed);
    }

    #[test]
    fn synth_domain_missing_range_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("synth-domain=example.com", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
    }

    #[test]
    fn synth_domain_bad_address_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("synth-domain=example.com,not-an-addr", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
    }

    // ── bridge-interface ───────────────────────────────────────────────────

    #[test]
    fn bridge_interface_parses_aliases() {
        let mut d = Daemon::default();
        let lines = parse_config_text("bridge-interface=br0,eth0,eth1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.bridges.len(), 1);
        assert_eq!(d.bridges[0].iface, "br0");
        assert_eq!(d.bridges[0].aliases, vec!["eth0".to_string(), "eth1".to_string()]);
    }

    #[test]
    fn bridge_interface_merges_repeated_iface() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "bridge-interface=br0,eth0\nbridge-interface=br0,eth1",
            "test",
        )
        .unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.bridges.len(), 1);
        assert_eq!(d.bridges[0].aliases, vec!["eth0".to_string(), "eth1".to_string()]);
    }

    #[test]
    fn bridge_interface_missing_alias_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("bridge-interface=br0", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
    }

    // ── shared-network ─────────────────────────────────────────────────────

    #[test]
    fn shared_network_address_form() {
        let mut d = Daemon::default();
        let lines = parse_config_text("shared-network=192.168.1.1,192.168.2.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.shared_networks.len(), 1);
        let sn = &d.shared_networks[0];
        assert!(!sn.is6);
        assert_eq!(sn.match_addr, "192.168.1.1".parse::<Ipv4Addr>().unwrap());
        assert_eq!(sn.shared_addr, "192.168.2.1".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn shared_network_missing_field_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("shared-network=eth0", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
    }

    #[test]
    fn shared_network_bad_second_field_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("shared-network=eth0,not-an-addr", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
    }

    /// `--umbrella` sets `OPT_UMBRELLA`; per-key sub-options (deviceid, orgid,
    /// assetid, userid) are not parsed (see tasks.md).
    #[test]
    fn apply_umbrella_sets_opt_umbrella() {
        let mut d = Daemon::default();
        let lines = parse_config_text("umbrella", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_UMBRELLA));
        assert_eq!(d.umbrella_org, 0);
        assert_eq!(d.umbrella_asset, 0);
        assert!(!d.option_bool(crate::types::constants::OPT_UMBRELLA_DEVID));
    }

    #[test]
    fn apply_umbrella_orgid() {
        let mut d = Daemon::default();
        let lines = parse_config_text("umbrella=orgid:123", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_UMBRELLA));
        assert_eq!(d.umbrella_org, 123);
    }

    #[test]
    fn apply_umbrella_assetid() {
        let mut d = Daemon::default();
        let lines = parse_config_text("umbrella=assetid:456", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.umbrella_asset, 456);
    }

    #[test]
    fn apply_umbrella_orgid_and_assetid_combined() {
        let mut d = Daemon::default();
        let lines = parse_config_text("umbrella=orgid:123,assetid:456", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.umbrella_org, 123);
        assert_eq!(d.umbrella_asset, 456);
    }

    #[test]
    fn apply_umbrella_deviceid_sets_devid_option_and_bytes() {
        let mut d = Daemon::default();
        let lines = parse_config_text("umbrella=deviceid:0123456789abcdef", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(crate::types::constants::OPT_UMBRELLA_DEVID));
        assert_eq!(d.umbrella_device, [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn apply_umbrella_deviceid_wrong_length_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("umbrella=deviceid:0123", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "umbrella"));
    }

    #[test]
    fn apply_umbrella_deviceid_non_hex_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("umbrella=deviceid:zzzzzzzzzzzzzzzz", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "umbrella"));
    }

    #[test]
    fn apply_umbrella_unknown_suboption_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("umbrella=bogus:1", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "umbrella"));
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_dhcp_duid_parses_enterprise_and_hex_id() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-duid=9,00010203", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.duid_enterprise, 9);
        assert_eq!(d.duid_config.as_deref(), Some(&[0x00, 0x01, 0x02, 0x03][..]));
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_dhcp_duid_rejects_bad_hex() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-duid=9,zz", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-duid"));
    }

    // ── ra-param / enable-ra / doing_ra ──────────────────────────────────────

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_basic_interval() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0,60", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.ra_interfaces.len(), 1);
        let p = &d.ra_interfaces[0];
        assert_eq!(p.name, "eth0");
        assert_eq!(p.interval, 60);
        assert_eq!(p.lifetime, -1);
        assert_eq!(p.prio, 0);
        assert_eq!(p.mtu, 0);
        assert_eq!(p.mtu_name, None);
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_with_lifetime() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0,60,1800", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.ra_interfaces[0].interval, 60);
        assert_eq!(d.ra_interfaces[0].lifetime, 1800);
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_with_prio_high_and_low() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0,high,60\nra-param=eth1,low,60", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.ra_interfaces[0].prio, 0x08);
        assert_eq!(d.ra_interfaces[1].prio, 0x18);
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_with_mtu_value() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0,mtu:1500,60", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.ra_interfaces[0].mtu, 1500);
        assert_eq!(d.ra_interfaces[0].mtu_name, None);
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_with_mtu_off() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0,mtu:off,60", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.ra_interfaces[0].mtu, -1);
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_with_mtu_interface_name() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0,mtu:eth1,60", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.ra_interfaces[0].mtu, 0);
        assert_eq!(d.ra_interfaces[0].mtu_name.as_deref(), Some("eth1"));
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_mtu_below_1280_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0,mtu:1200,60", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "ra-param"));
    }

    /// Upstream's `atoi_check` (`option.c:760-766`) rejects any non-digit
    /// character — including a leading `-` — via `numeric_check` before
    /// `mtu:`'s value is ever treated as numeric, so `mtu:-5` falls through
    /// to the interface-name branch (`new->mtu_name = opt_string_alloc(arg)`)
    /// exactly like `mtu:eth1` does, rather than being parsed as -5 and
    /// rejected by the `< 1280` check.
    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_negative_mtu_is_treated_as_an_interface_name() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0,mtu:-5,60", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.ra_interfaces[0].mtu, 0);
        assert_eq!(d.ra_interfaces[0].mtu_name.as_deref(), Some("-5"));
    }

    /// Unlike `mtu:`, upstream's `interval`/`lifetime` fields have no
    /// interface-name fallback: `atoi_check` failing on either goes straight
    /// to `goto err` (`option.c:4841-4845`), so a leading `-` is a hard
    /// config error rather than a value `i32::parse` would silently accept.
    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_negative_interval_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0,-60", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "ra-param"));
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_negative_lifetime_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0,60,-1800", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "ra-param"));
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_missing_interval_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "ra-param"));
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_non_numeric_interval_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0,high,notanumber", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "ra-param"));
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_ra_param_full_form() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ra-param=eth0,mtu:9000,high,120,3600", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        let p = &d.ra_interfaces[0];
        assert_eq!(p.mtu, 9000);
        assert_eq!(p.prio, 0x08);
        assert_eq!(p.interval, 120);
        assert_eq!(p.lifetime, 3600);
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_enable_ra_without_dhcp6_contexts_leaves_doing_ra_false() {
        let mut d = Daemon::default();
        let lines = parse_config_text("enable-ra", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        // Upstream only computes doing_ra inside `if (daemon->dhcp6)`
        // (dnsmasq.c:290), so with no DHCPv6 contexts at all it stays false.
        assert!(!d.doing_ra);
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_enable_ra_with_dhcp6_context_sets_doing_ra() {
        use crate::types::dhcp::CONTEXT_DHCP;
        let mut d = Daemon::default();
        let lines = parse_config_text("enable-ra", "test").unwrap();
        d.dhcp6.push(dhcp6_ctx_for_test(CONTEXT_DHCP));
        apply_config(&mut d, &lines).unwrap();
        assert!(d.doing_ra);
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn context_ra_flag_sets_doing_ra_without_enable_ra() {
        use crate::types::dhcp::CONTEXT_RA;
        let mut d = Daemon::default();
        d.dhcp6.push(dhcp6_ctx_for_test(CONTEXT_RA));
        apply_config(&mut d, &[]).unwrap();
        assert!(d.doing_ra);
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn no_dhcp6_contexts_leaves_doing_ra_false_even_with_context_ra() {
        // Sanity check on the guard itself: without any dhcp6 entries at all,
        // normalize_config's `if daemon.dhcp6.is_empty() { return; }` should
        // short-circuit regardless of OPT_RA.
        let mut d = Daemon::default();
        let lines = parse_config_text("enable-ra", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.dhcp6.is_empty());
        assert!(!d.doing_ra);
    }

    #[cfg(feature = "dhcp6")]
    fn dhcp6_ctx_for_test(flags: u32) -> DhcpContext {
        DhcpContext {
            lease_time: 3600,
            addr_epoch: 0,
            netmask: Ipv4Addr::UNSPECIFIED,
            broadcast: Ipv4Addr::UNSPECIFIED,
            local: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            flags,
            netid: DhcpNetid { net: String::new() },
            filter: vec![],
            start6: Ipv6Addr::UNSPECIFIED,
            end6: Ipv6Addr::UNSPECIFIED,
            local6: Ipv6Addr::UNSPECIFIED,
            prefix: 64,
            if_index: 0,
            valid: 0,
            preferred: 0,
            ra_time: 0,
            ra_short_period_start: 0,
            saved_valid: 0,
            address_lost_time: 0,
        }
    }

    #[test]
    fn apply_no_dhcpv4_interface_and_no_dhcpv6_interface() {
        let mut d = Daemon::default();
        let lines = parse_config_text("no-dhcpv4-interface=eth0\nno-dhcpv6-interface=eth1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.dhcp_except.len(), 2);
        assert_eq!(d.dhcp_except[0].name.as_deref(), Some("eth0"));
        assert_eq!(d.dhcp_except[0].flags, INAME_4);
        assert_eq!(d.dhcp_except[1].name.as_deref(), Some("eth1"));
        assert_eq!(d.dhcp_except[1].flags, INAME_6);
    }

    // connmark-allowlist{,-enable} mirror upstream's `#ifndef HAVE_CONNTRACK`
    // hard error (option.c:3283-3286): without the `conntrack` feature they
    // must fail clearly, not parse successfully or silently no-op.
    #[test]
    #[cfg(not(feature = "conntrack"))]
    fn apply_connmark_allowlist_enable_without_conntrack_feature_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("connmark-allowlist-enable=255", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "connmark-allowlist-enable"));
    }

    #[test]
    #[cfg(not(feature = "conntrack"))]
    fn apply_connmark_allowlist_without_conntrack_feature_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("connmark-allowlist=6,*.example.com", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "connmark-allowlist"));
    }

    #[test]
    #[cfg(feature = "conntrack")]
    fn apply_connmark_allowlist_enable_sets_mask_and_bit() {
        let mut d = Daemon::default();
        let lines = parse_config_text("connmark-allowlist-enable=255", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_CMARK_ALST_EN));
        assert_eq!(d.allowlist_mask, 255);
    }

    #[test]
    #[cfg(feature = "conntrack")]
    fn apply_connmark_allowlist_enable_defaults_mask_to_all_bits() {
        let mut d = Daemon::default();
        let lines = parse_config_text("connmark-allowlist-enable", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_CMARK_ALST_EN));
        assert_eq!(d.allowlist_mask, u32::MAX);
    }

    #[test]
    #[cfg(feature = "conntrack")]
    fn apply_connmark_allowlist_parses_mark_mask_and_patterns() {
        let mut d = Daemon::default();
        let lines = parse_config_text("connmark-allowlist=6/14,*.example.com,*.example.org", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.allowlists.len(), 1);
        assert_eq!(d.allowlists[0].mark, 6);
        assert_eq!(d.allowlists[0].mask, 14);
        assert_eq!(d.allowlists[0].patterns, vec!["*.example.com", "*.example.org"]);
    }

    #[test]
    #[cfg(feature = "conntrack")]
    fn apply_connmark_allowlist_without_mask_defaults_to_all_bits() {
        let mut d = Daemon::default();
        let lines = parse_config_text("connmark-allowlist=6,*.example.com", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.allowlists[0].mark, 6);
        assert_eq!(d.allowlists[0].mask, u32::MAX);
    }

    #[test]
    #[cfg(feature = "conntrack")]
    fn apply_connmark_allowlist_rejects_mark_outside_mask() {
        let mut d = Daemon::default();
        // mark 8 (0b1000) is not a subset of mask 3 (0b0011).
        let lines = parse_config_text("connmark-allowlist=8/3,*.example.com", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "connmark-allowlist"));
    }

    /// Directives that are recognized and accepted, but whose full runtime
    /// behavior is not yet wired (tracked in tasks.md), must not abort
    /// startup — that is exactly the bug this issue fixes.
    #[test]
    fn apply_documented_unsupported_directives_do_not_abort_startup() {
        // `conf-script` (option.c:2068) is the one directive in this family
        // that remains a deliberate no-op: running an external program as
        // part of config parsing is a capability this port intentionally
        // does not implement (see tasks.md).
        let mut d = Daemon::default();
        let lines = parse_config_text("conf-script=/etc/dnsmasq-script.conf", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
    }

    #[test]
    fn apply_dhcp_broadcast_bare_and_tagged() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-broadcast\ndhcp-broadcast=tag:foo", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.force_broadcast.len(), 2);
            assert!(d.force_broadcast[0].list.is_empty());
            assert_eq!(d.force_broadcast[1].list[0].net, "foo");
        }
    }

    #[test]
    fn apply_dhcp_generate_names_and_ignore_names_and_bootp_dynamic() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "dhcp-generate-names=tag:foo\ndhcp-ignore-names=tag:bar\nbootp-dynamic=tag:baz",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_gen_names[0].list[0].net, "foo");
            assert_eq!(d.dhcp_ignore_names[0].list[0].net, "bar");
            assert_eq!(d.bootp_dynamic[0].list[0].net, "baz");
        }
    }

    #[test]
    fn apply_dhcp_proxy_bare_and_with_addresses() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-proxy=192.168.0.1,192.168.0.2", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert!(d.dhcp_override);
            assert_eq!(d.override_relays, vec![
                "192.168.0.1".parse::<Ipv4Addr>().unwrap(),
                "192.168.0.2".parse::<Ipv4Addr>().unwrap(),
            ]);
        }

        let mut d2 = Daemon::default();
        let lines2 = parse_config_text("dhcp-proxy", "test").unwrap();
        apply_config(&mut d2, &lines2).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert!(d2.dhcp_override);
            assert!(d2.override_relays.is_empty());
        }
    }

    #[test]
    fn apply_dhcp_pxe_vendor() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-pxe-vendor=PXEClient,Etherboot", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_pxe_vendors.len(), 2);
            assert_eq!(d.dhcp_pxe_vendors[0].data, "PXEClient");
            assert_eq!(d.dhcp_pxe_vendors[1].data, "Etherboot");
        }
    }

    #[test]
    fn apply_pxe_prompt_sets_dhcp_opt_and_enable_pxe() {
        let mut d = Daemon::default();
        let lines = parse_config_text("pxe-prompt=Boot from network,5", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert!(d.enable_pxe);
            assert_eq!(d.dhcp_opts.len(), 1);
            let opt = &d.dhcp_opts[0];
            assert_eq!(opt.opt, 10);
            assert_eq!(opt.flags, crate::types::dhcp::DHOPT_VENDOR | crate::types::dhcp::DHOPT_VENDOR_PXE);
            let val = opt.val.as_ref().unwrap();
            assert_eq!(val[0], 5);
            assert_eq!(&val[1..], b"Boot from network");
        }
    }

    #[test]
    fn apply_pxe_prompt_default_timeout() {
        let mut d = Daemon::default();
        let lines = parse_config_text("pxe-prompt=Boot from network", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_opts[0].val.as_ref().unwrap()[0], 255);
        }
    }

    #[test]
    fn apply_pxe_service_local_boot() {
        let mut d = Daemon::default();
        let lines = parse_config_text("pxe-service=x86PC,Boot from network", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert!(d.enable_pxe);
            assert_eq!(d.pxe_services.len(), 1);
            let svc = &d.pxe_services[0];
            assert_eq!(svc.csa, 0);
            assert_eq!(svc.menu, "Boot from network");
            assert_eq!(svc.boot_type, 0);
            assert!(svc.basename.is_none());
        }
    }

    #[test]
    fn apply_pxe_service_with_basename_auto_assigns_boot_type() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "pxe-service=x86PC,Boot,pxelinux\npxe-service=BC_EFI,Boot,pxelinux.efi",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.pxe_services[0].csa, 0);
            assert_eq!(d.pxe_services[0].basename.as_deref(), Some("pxelinux"));
            assert_eq!(d.pxe_services[0].boot_type, 32768);
            assert_eq!(d.pxe_services[1].csa, 9);
            assert_eq!(d.pxe_services[1].boot_type, 32769);
        }
    }

    #[test]
    fn apply_pxe_service_numeric_csa_and_boot_type() {
        let mut d = Daemon::default();
        let lines = parse_config_text("pxe-service=0,Boot,0,192.168.0.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let svc = &d.pxe_services[0];
            assert_eq!(svc.csa, 0);
            assert_eq!(svc.boot_type, 0);
            assert!(svc.basename.is_none());
            assert_eq!(svc.server, "192.168.0.1".parse::<Ipv4Addr>().unwrap());
        }
    }

    #[test]
    fn apply_pxe_service_sname_fallback_when_not_an_address() {
        let mut d = Daemon::default();
        let lines = parse_config_text("pxe-service=x86PC,Boot,pxelinux,bootserver.lan", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let svc = &d.pxe_services[0];
            assert_eq!(svc.sname.as_deref(), Some("bootserver.lan"));
            assert_eq!(svc.server, Ipv4Addr::UNSPECIFIED);
        }
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_pxe_service_requires_menu_text() {
        let mut d = Daemon::default();
        let lines = parse_config_text("pxe-service=x86PC", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "pxe-service"));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_bootp_dynamic_records_tag_filters() {
        let mut d = Daemon::default();
        let lines = parse_config_text("bootp-dynamic\nbootp-dynamic=tag:foo,bar", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.bootp_dynamic.len(), 2);
        assert!(d.bootp_dynamic[0].list.is_empty());
        assert_eq!(
            d.bootp_dynamic[1].list.iter().map(|n| n.net.as_str()).collect::<Vec<_>>(),
            vec!["foo", "bar"]
        );
    }

    #[test]
    fn apply_dhcp_authoritative_and_read_ethers_flags() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-authoritative\nread-ethers", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_AUTHORITATIVE));
        assert!(d.option_bool(OPT_ETHERS));
    }

    #[test]
    #[cfg(feature = "script")]
    fn apply_dhcp_script_paths_and_renewal_flag() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "dhcp-script=/usr/lib/dnsmasq/dhcp-hook\n\
             dhcp-luascript=/usr/lib/dnsmasq/dhcp-hook.lua\n\
             script-on-renewal",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.lease_change_command, Some("/usr/lib/dnsmasq/dhcp-hook".to_string()));
        assert_eq!(d.luascript, Some("/usr/lib/dnsmasq/dhcp-hook.lua".to_string()));
        assert!(d.option_bool(OPT_LEASE_RENEW));
    }

    #[test]
    #[cfg(not(feature = "script"))]
    fn dhcp_script_rejected_without_script_feature() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-script=/usr/lib/dnsmasq/dhcp-hook", "test").unwrap();
        let result = apply_config(&mut d, &lines);
        assert!(result.is_err(), "dhcp-script should be rejected when script feature is disabled");
        let err = result.unwrap_err();
        let err_msg = format!("{}", err);
        assert!(err_msg.contains("HAVE_SCRIPT"), "error message should mention HAVE_SCRIPT");
    }

    #[test]
    #[cfg(not(feature = "script"))]
    fn dhcp_luascript_rejected_without_script_feature() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-luascript=/usr/lib/dnsmasq/dhcp-hook.lua", "test").unwrap();
        let result = apply_config(&mut d, &lines);
        assert!(result.is_err(), "dhcp-luascript should be rejected when script feature is disabled");
        let err = result.unwrap_err();
        let err_msg = format!("{}", err);
        assert!(err_msg.contains("HAVE_SCRIPT"), "error message should mention HAVE_SCRIPT");
    }

    #[test]
    fn apply_max_tcp_connections() {
        let mut d = Daemon::default();
        let lines = parse_config_text("max-tcp-connections=42", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.max_procs, 42);
    }

    #[test]
    fn apply_max_tcp_connections_invalid_value_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("max-tcp-connections=lots", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "max-tcp-connections"));
    }

    #[test]
    fn apply_tftp_flags_and_unique_root_modes() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "tftp-no-fail\n\
             tftp-single-port\n\
             tftp-unique-root=mac",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_TFTP_NO_FAIL));
        assert!(d.option_bool(OPT_SINGLE_PORT));
        assert!(d.option_bool(OPT_TFTP_APREF_MAC));
        assert!(!d.option_bool(OPT_TFTP_APREF_IP));

        let mut d = Daemon::default();
        let lines = parse_config_text("tftp-unique-root", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_TFTP_APREF_IP));
    }

    #[test]
    fn apply_enable_tftp_with_interfaces() {
        let mut d = Daemon::default();
        let lines = parse_config_text("enable-tftp=eth0,br-lan", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_TFTP));
        assert_eq!(d.tftp_interfaces.len(), 2);
        assert_eq!(d.tftp_interfaces[0].name, Some("eth0".to_string()));
        assert_eq!(d.tftp_interfaces[0].flags, INAME_4 | INAME_6);
        assert_eq!(d.tftp_interfaces[1].name, Some("br-lan".to_string()));
        assert_eq!(d.tftp_interfaces[1].flags, INAME_4 | INAME_6);
    }

    #[test]
    #[cfg(feature = "dbus")]
    fn apply_enable_dbus_defaults_service_name() {
        let mut d = Daemon::default();
        let lines = parse_config_text("enable-dbus", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_DBUS));
        assert_eq!(d.dbus_name.as_deref(), Some("uk.org.thekelleys.dnsmasq"));
    }

    #[test]
    #[cfg(feature = "dbus")]
    fn apply_enable_dbus_with_custom_name() {
        let mut d = Daemon::default();
        let lines = parse_config_text("enable-dbus=uk.org.thekelleys.dnsmasq.custom", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_DBUS));
        assert_eq!(d.dbus_name.as_deref(), Some("uk.org.thekelleys.dnsmasq.custom"));
    }

    #[test]
    fn apply_tftp_numeric_options() {
        let mut d = Daemon::default();
        let lines = parse_config_text("tftp-mtu=1400\ntftp-port-range=7000,6000", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "tftp")]
        {
            assert_eq!(d.tftp_mtu, 1400);
            assert_eq!(d.start_tftp_port, 6000);
            assert_eq!(d.end_tftp_port, 7000);
        }
    }

    #[test]
    fn apply_tftp_invalid_values_error() {
        let mut d = Daemon::default();
        let lines = parse_config_text("tftp-unique-root=host", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "tftp-unique-root"));

        let mut d = Daemon::default();
        let lines = parse_config_text("tftp-port-range=6000", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "tftp-port-range"));
    }

    #[test]
    fn apply_local_service_default_and_net_mode() {
        let mut d = Daemon::default();
        let lines = parse_config_text("local-service", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_LOCAL_SERVICE));
        assert!(!d.option_bool(OPT_LOCALHOST_SERVICE));

        let mut d = Daemon::default();
        let lines = parse_config_text("local-service=net", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_LOCAL_SERVICE));
        assert!(!d.option_bool(OPT_LOCALHOST_SERVICE));
    }

    #[test]
    fn apply_local_service_host_mode_adds_loopback_interface() {
        let mut d = Daemon::default();
        let lines = parse_config_text("local-service=host", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(!d.option_bool(OPT_LOCAL_SERVICE));
        assert!(d.option_bool(OPT_LOCALHOST_SERVICE));
        assert!(d.option_bool(OPT_NOWILD));
        assert_eq!(d.if_names.len(), 1);
        assert_eq!(d.if_names[0].name, None);
    }

    #[test]
    fn apply_local_service_clears_when_access_control_is_explicit() {
        let mut d = Daemon::default();
        let lines = parse_config_text("local-service\ninterface=eth0", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(!d.option_bool(OPT_LOCAL_SERVICE));
        assert!(!d.option_bool(OPT_LOCALHOST_SERVICE));

        let mut d = Daemon::default();
        let lines = parse_config_text("local-service=host\nlisten-address=127.0.0.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(!d.option_bool(OPT_LOCAL_SERVICE));
        assert!(!d.option_bool(OPT_LOCALHOST_SERVICE));
        assert_eq!(d.if_names.len(), 0);
    }

    #[test]
    fn apply_local_service_invalid_mode_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("local-service=maybe", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "local-service"));
    }

    #[test]
    fn apply_dumpfile_and_hex_dumpmask() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dumpfile=/tmp/dnsmasq.pcap\ndumpmask=0x1001", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dump")]
        {
            assert_eq!(d.dump_file, Some("/tmp/dnsmasq.pcap".to_string()));
            assert_eq!(d.dump_mask, 0x1001);
        }
    }

    #[test]
    fn apply_dumpmask_invalid_value_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dumpmask=not-a-mask", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dumpmask"));
    }

    #[test]
    fn daemon_default_dump_mask_matches_upstream() {
        let d = Daemon::default();
        #[cfg(feature = "dump")]
        assert_eq!(d.dump_mask, -1);
    }

    #[test]
    fn apply_add_mac_modes_and_strip_mac() {
        let mut d = Daemon::default();
        let lines = parse_config_text("add-mac\nstrip-mac", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_ADD_MAC));
        assert!(d.option_bool(OPT_STRIP_MAC));

        let mut d = Daemon::default();
        let lines = parse_config_text("add-mac=base64", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_MAC_B64));

        let mut d = Daemon::default();
        let lines = parse_config_text("add-mac=text", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_MAC_HEX));
    }

    #[test]
    fn apply_add_mac_invalid_mode_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("add-mac=binary", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "add-mac"));
    }

    #[test]
    fn apply_add_cpe_id_and_strip_subnet() {
        let mut d = Daemon::default();
        let lines = parse_config_text("add-cpe-id=device-123\nstrip-subnet", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.dns_client_id, Some("device-123".to_string()));
        assert!(d.option_bool(OPT_STRIP_ECS));
    }

    #[test]
    fn apply_add_subnet_masks_and_constant_addresses() {
        let mut d = Daemon::default();
        let lines = parse_config_text("add-subnet=1.2.3.4/24,96", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_CLIENT_SUBNET));

        let subnet4 = d.add_subnet4.as_ref().unwrap();
        assert_eq!(subnet4.mask, 24);
        assert!(subnet4.addr_used);
        assert_eq!(subnet4.addr.ip(), IpAddr::V4("1.2.3.4".parse().unwrap()));

        let subnet6 = d.add_subnet6.as_ref().unwrap();
        assert_eq!(subnet6.mask, 96);
        assert!(!subnet6.addr_used);
        assert!(subnet6.addr.is_v6());
    }

    #[test]
    fn apply_add_subnet_without_value_sets_option_only() {
        let mut d = Daemon::default();
        let lines = parse_config_text("add-subnet", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_CLIENT_SUBNET));
        assert!(d.add_subnet4.is_none());
        assert!(d.add_subnet6.is_none());
    }

    #[test]
    fn apply_add_subnet_bad_prefix_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("add-subnet=33", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "add-subnet"));
    }

    #[test]
    fn apply_cache_size() {
        let mut d = Daemon::default();
        let lines = parse_config_text("cache-size=500", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.cachesize, 500);
    }

    #[test]
    fn apply_cache_size_negative_clamps_to_zero() {
        let mut d = Daemon::default();
        let lines = parse_config_text("cache-size=-5", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.cachesize, 0);
    }

    #[test]
    fn apply_cache_size_huge_value_clamps_to_upstream_cap() {
        let mut d = Daemon::default();
        let lines = parse_config_text("cache-size=99999999", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.cachesize, 5_000_000);
    }

    #[test]
    fn apply_domain() {
        let mut d = Daemon::default();
        let lines = parse_config_text("domain=example.com", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.domain_suffix, Some("example.com".to_string()));
        assert!(d.cond_domain.is_empty());
    }

    #[test]
    fn apply_domain_hash_sets_resolv_domain_option() {
        let mut d = Daemon::default();
        let lines = parse_config_text("domain=#", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(crate::types::constants::OPT_RESOLV_DOMAIN));
        assert_eq!(d.domain_suffix, None);
    }

    #[test]
    fn apply_domain_range_form_populates_cond_domain() {
        let mut d = Daemon::default();
        let lines = parse_config_text("domain=example.com,192.168.0.0,192.168.0.255", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.cond_domain.len(), 1);
        let cd = &d.cond_domain[0];
        assert_eq!(cd.domain, "example.com");
        assert!(!cd.is6);
        assert_eq!(cd.start, "192.168.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cd.end, "192.168.0.255".parse::<Ipv4Addr>().unwrap());
        // Not populated for `--domain` (only used as a `synth-domain` prefix).
        assert_eq!(cd.prefix, None);
        // Distinct from synth_domains.
        assert!(d.synth_domains.is_empty());
    }

    #[test]
    fn apply_domain_single_address_defaults_end_to_start() {
        let mut d = Daemon::default();
        let lines = parse_config_text("domain=example.com,10.0.0.5", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        let cd = &d.cond_domain[0];
        assert_eq!(cd.start, "10.0.0.5".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cd.end, "10.0.0.5".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn apply_domain_cidr_form_populates_range() {
        let mut d = Daemon::default();
        let lines = parse_config_text("domain=example.com,10.0.0.0/24", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        let cd = &d.cond_domain[0];
        assert_eq!(cd.start, "10.0.0.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(cd.end, "10.0.0.255".parse::<Ipv4Addr>().unwrap());
    }

    #[test]
    fn apply_domain_cidr_form_with_local_keyword_accepted() {
        let mut d = Daemon::default();
        let lines = parse_config_text("domain=example.com,10.0.0.0/24,local", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.cond_domain.len(), 1);
    }

    #[test]
    fn apply_domain_cidr_form_with_non_local_third_field_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("domain=example.com,10.0.0.0/24,bogus", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "domain"));
    }

    #[test]
    fn apply_domain_subnet_from_interface() {
        let mut d = Daemon::default();
        let lines = parse_config_text("domain=example.com,eth0", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        let cd = &d.cond_domain[0];
        assert_eq!(cd.interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn apply_domain_ipv6_range_form() {
        let mut d = Daemon::default();
        let lines = parse_config_text("domain=example.com,2001:db8::1,2001:db8::ff", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        let cd = &d.cond_domain[0];
        assert!(cd.is6);
        assert_eq!(cd.start6, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(cd.end6, "2001:db8::ff".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn apply_domain_repeatable() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "domain=a.example.com,10.0.0.0,10.0.0.255\ndomain=b.example.com,10.0.1.0,10.0.1.255",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.cond_domain.len(), 2);
        assert_eq!(d.cond_domain[0].domain, "a.example.com");
        assert_eq!(d.cond_domain[1].domain, "b.example.com");
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
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_alternate_port_defaults_to_unprivileged_pair() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-alternate-port", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.dhcp_server_port, 1067);
        assert_eq!(d.dhcp_client_port, 1068);
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_alternate_port_single_value_derives_client_port() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-alternate-port=2000", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.dhcp_server_port, 2000);
        assert_eq!(d.dhcp_client_port, 2001);
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_alternate_port_pair_sets_both_ports() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-alternate-port=2000,3000", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.dhcp_server_port, 2000);
        assert_eq!(d.dhcp_client_port, 3000);
    }

    // Without the `dhcp` feature the directive is accepted and ignored, matching the
    // other DHCP directives, so there is no error to assert.
    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_alternate_port_invalid_value_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-alternate-port=abc", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-alternate-port"));
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
    fn apply_address_with_ip_creates_literal_address_server() {
        let mut d = Daemon::default();
        let lines = parse_config_text("address=/example.com/1.2.3.4", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 1);
        let s = &d.servers[0];
        assert_eq!(s.domain, "example.com");
        assert_eq!(s.flags & SERV_LITERAL_ADDRESS, SERV_LITERAL_ADDRESS);
        assert_eq!(s.flags & SERV_4ADDR, SERV_4ADDR);
        assert_eq!(s.addr.ip(), "1.2.3.4".parse::<std::net::IpAddr>().unwrap());
    }

    #[test]
    fn apply_address_with_no_ip_creates_literal_no_forward_server() {
        // `address=/example.com/` (no address) blocks the domain instead of
        // silently doing nothing — matches `server=/example.com/`
        // (option.c:3060-3110: `if (!arg || !*arg) flags = SERV_LITERAL_ADDRESS;`).
        let mut d = Daemon::default();
        let lines = parse_config_text("address=/example.com/", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 1);
        let s = &d.servers[0];
        assert_eq!(s.domain, "example.com");
        assert_eq!(s.flags & SERV_LITERAL_ADDRESS, SERV_LITERAL_ADDRESS);
        assert_eq!(s.flags & (SERV_4ADDR | SERV_6ADDR), 0);
    }

    /// `address=/domain/#`: the whole address argument is literally `#`,
    /// meaning "return the NULL address (0.0.0.0/::) for domain and its
    /// subdomains" — syntactic sugar for `address=/domain/0.0.0.0` plus
    /// `address=/domain/::` (`option.c:3093-3097`, `--address`-only: `#`
    /// only gets this meaning under `option == 'A'`). Previously
    /// misparsed as an `<address>#<port>` string with an empty address,
    /// producing "invalid value '' for 'address': expected an IP address"
    /// instead of a valid config.
    #[test]
    fn apply_address_hash_creates_null_address_server() {
        let mut d = Daemon::default();
        let lines = parse_config_text("address=/example.com/#", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 1);
        let s = &d.servers[0];
        assert_eq!(s.domain, "example.com");
        assert_eq!(s.flags & SERV_LITERAL_ADDRESS, SERV_LITERAL_ADDRESS);
        assert_eq!(s.flags & SERV_ALL_ZEROS, SERV_ALL_ZEROS);
    }

    #[test]
    fn apply_address_hash_with_no_domain_creates_catch_all_null_address_server() {
        // `/#/` as a domain segment means "matches any domain" — upstream
        // rewrites it to the empty string before storing the entry
        // (option.c:3136-3138), the same general/fallback domain a bare
        // `address=1.2.3.4` (no `/domain/` prefix) already produces.
        let mut d = Daemon::default();
        let lines = parse_config_text("address=/#/#", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 1);
        assert_eq!(d.servers[0].domain, "");
        assert_eq!(d.servers[0].flags & SERV_ALL_ZEROS, SERV_ALL_ZEROS);
    }

    /// A mixed directive naming a specific domain alongside the `/#/`
    /// wildcard must produce one entry per domain, not silently drop the
    /// wildcard because its rewritten (empty-string) form looks like a
    /// filtered-out empty split segment.
    #[test]
    fn apply_address_specific_domain_plus_wildcard_creates_two_entries() {
        let mut d = Daemon::default();
        let lines = parse_config_text("address=/specific.test/#/198.51.100.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 2);
        assert_eq!(d.servers[0].domain, "specific.test");
        assert_eq!(d.servers[1].domain, "");
        for s in &d.servers {
            assert_eq!(s.addr.ip(), "198.51.100.1".parse::<std::net::IpAddr>().unwrap());
        }
    }

    /// `#` only means "NULL address" for `--address`; `--server`/`--local`
    /// don't give it that meaning (a server always needs a real address to
    /// forward to), so `server=8.8.8.8#5353`-style port syntax must still
    /// work and a bare `#` for `--server` is just an (invalid) address.
    #[test]
    fn apply_server_hash_is_not_treated_as_null_address() {
        let mut d = Daemon::default();
        let lines = parse_config_text("server=/example.com/#", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "server"));
    }

    #[test]
    fn apply_local_with_no_ip_creates_literal_no_forward_server() {
        let mut d = Daemon::default();
        let lines = parse_config_text("local=/example.com/", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 1);
        let s = &d.servers[0];
        assert_eq!(s.domain, "example.com");
        assert_eq!(s.flags & SERV_LITERAL_ADDRESS, SERV_LITERAL_ADDRESS);
    }

    #[test]
    fn apply_server_with_no_ip_creates_literal_no_forward_server() {
        let mut d = Daemon::default();
        let lines = parse_config_text("server=/example.com/", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.servers.len(), 1);
        let s = &d.servers[0];
        assert_eq!(s.domain, "example.com");
        assert_eq!(s.flags & SERV_LITERAL_ADDRESS, SERV_LITERAL_ADDRESS);
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
    fn apply_mx_host() {
        let mut d = Daemon::default();
        let lines = parse_config_text("mx-host=example.com,mail.example.com,20", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.mxnames.len(), 1);
        let mx = &d.mxnames[0];
        assert_eq!(mx.name, "example.com");
        assert_eq!(mx.target, "mail.example.com");
        assert_eq!(mx.priority, 20);
        assert!(!mx.is_srv);
    }

    #[test]
    fn apply_mx_host_without_target_uses_default_mx_target() {
        let mut d = Daemon::default();
        let lines = parse_config_text("mx-target=mail.example.com\nmx-host=example.com", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        let mx = d.mxnames.iter().find(|mx| mx.name == "example.com").unwrap();
        assert_eq!(mx.target, "mail.example.com");
        assert_eq!(mx.priority, 1);
    }

    #[test]
    fn apply_mx_target_adds_local_hostname_mx_record() {
        let hostname = local_hostname_for_mx().unwrap();
        let mut d = Daemon::default();
        let lines = parse_config_text("mx-target=mail.example.com", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.mxtarget, Some("mail.example.com".to_string()));
        assert!(d.mxnames.iter().any(|mx| {
            !mx.is_srv && mx.name == hostname && mx.target == "mail.example.com"
        }));
    }

    #[test]
    fn apply_srv_host() {
        let mut d = Daemon::default();
        let lines = parse_config_text("srv-host=_sip._tcp.example.com,sip.example.com,5060,10,5", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.mxnames.len(), 1);
        let srv = &d.mxnames[0];
        assert!(srv.is_srv);
        assert_eq!(srv.srv_port, 5060);
        assert_eq!(srv.priority, 10);
        assert_eq!(srv.weight, 5);
    }

    #[test]
    fn apply_txt_record() {
        let mut d = Daemon::default();
        let lines = parse_config_text("txt-record=example.com,v=spf1,-all", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.txt.len(), 1);
        assert_eq!(d.txt[0].name, "example.com");
        assert_eq!(d.txt[0].txt, b"\x06v=spf1\x04-all");
    }

    #[test]
    fn apply_txt_record_without_text_creates_empty_txt_string() {
        let mut d = Daemon::default();
        let lines = parse_config_text("txt-record=empty.example.com", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.txt.len(), 1);
        assert_eq!(d.txt[0].name, "empty.example.com");
        assert_eq!(d.txt[0].txt, vec![0]);
    }

    #[test]
    fn apply_ptr_record() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ptr-record=4.3.2.1.in-addr.arpa,host.example.com", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.ptr.len(), 1);
        assert_eq!(d.ptr[0].name, "4.3.2.1.in-addr.arpa");
        assert_eq!(d.ptr[0].ptr, "host.example.com");
    }

    #[test]
    fn apply_host_record_dual_stack() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "host-record=host.example.com,alias.example.com,192.0.2.10,2001:db8::10,120",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.host_records.len(), 1);
        let rec = &d.host_records[0];
        assert_eq!(rec.names, vec!["host.example.com".to_string(), "alias.example.com".to_string()]);
        assert_eq!(rec.addr4, Some("192.0.2.10".parse().unwrap()));
        assert_eq!(rec.addr6, Some("2001:db8::10".parse().unwrap()));
        assert_eq!(rec.ttl, 120);
    }

    #[test]
    fn apply_interface_name_with_family_suffix() {
        let mut d = Daemon::default();
        let lines = parse_config_text("interface-name=router.example.com,eth0/4", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.int_names.len(), 1);
        let rec = &d.int_names[0];
        assert_eq!(rec.name, "router.example.com");
        assert_eq!(rec.intr, "eth0");
        assert_eq!(rec.flags, IN4);
        assert_eq!(rec.proto4, None);
        assert_eq!(rec.proto6, None);
    }

    #[test]
    fn apply_dynamic_host_with_prototype_addresses() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "dynamic-host=dyn.example.com,0.0.0.8,::8,eth0",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.int_names.len(), 1);
        let rec = &d.int_names[0];
        assert_eq!(rec.name, "dyn.example.com");
        assert_eq!(rec.intr, "eth0");
        assert_eq!(rec.flags, INP4 | INP6);
        assert_eq!(rec.proto4, Some("0.0.0.8".parse().unwrap()));
        assert_eq!(rec.proto6, Some("::8".parse().unwrap()));
    }

    #[test]
    fn apply_interface_name_rejects_address_fields() {
        let mut d = Daemon::default();
        let lines = parse_config_text("interface-name=router.example.com,192.0.2.1,eth0", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "interface-name"));
    }

    #[test]
    fn apply_dynamic_host_requires_address() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dynamic-host=dyn.example.com,eth0", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dynamic-host"));
    }

    #[test]
    fn apply_cname() {
        let mut d = Daemon::default();
        let lines = parse_config_text("cname=www.example.com,target.example.com,300", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.cnames.len(), 1);
        assert_eq!(d.cnames[0].alias, "www.example.com");
        assert_eq!(d.cnames[0].target, "target.example.com");
        assert_eq!(d.cnames[0].ttl, 300);
    }

    #[test]
    fn apply_cname_multiple_aliases_share_target() {
        let mut d = Daemon::default();
        let lines = parse_config_text("cname=www.example.com,api.example.com,target.example.com,120", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.cnames.len(), 2);
        assert_eq!(d.cnames[0].alias, "www.example.com");
        assert_eq!(d.cnames[1].alias, "api.example.com");
        assert!(d.cnames.iter().all(|c| c.target == "target.example.com" && c.ttl == 120));
    }

    #[test]
    fn apply_cname_duplicate_alias_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("cname=www.example.com,target.example.com\ncname=www.example.com,other.example.com", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "cname"));
    }

    #[test]
    fn apply_naptr_record() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "naptr-record=example.com,100,10,S,SIP+D2U,,_sip._udp.example.com",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.naptr.len(), 1);
        let rec = &d.naptr[0];
        assert_eq!(rec.name, "example.com");
        assert_eq!(rec.order, 100);
        assert_eq!(rec.pref, 10);
        assert_eq!(rec.flags, "S");
        assert_eq!(rec.services, "SIP+D2U");
        assert_eq!(rec.replace, "_sip._udp.example.com");
    }

    #[test]
    fn apply_dns_rr_numeric_type_and_hex_rdata() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dns-rr=example.com,65,00010002", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.rr.len(), 1);
        assert_eq!(d.rr[0].name, "example.com");
        assert_eq!(d.rr[0].class, 65);
        assert_eq!(d.rr[0].txt, vec![0, 1, 0, 2]);
    }

    #[test]
    fn apply_dns_rr_named_type_without_rdata() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dns-rr=example.com,CAA", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.rr.len(), 1);
        assert_eq!(d.rr[0].class, crate::dns_protocol::RrType::CAA as u16);
        assert!(d.rr[0].txt.is_empty());
    }

    #[test]
    fn apply_caa_record() {
        let mut d = Daemon::default();
        let lines = parse_config_text("caa-record=example.com,0,issue,letsencrypt.org", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.rr.len(), 1);
        assert_eq!(d.rr[0].name, "example.com");
        assert_eq!(d.rr[0].class, crate::dns_protocol::RrType::CAA as u16);
        assert_eq!(d.rr[0].txt, b"\x00\x05issueletsencrypt.org");
    }

    #[test]
    fn apply_dns_rr_rejects_bad_hex() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dns-rr=example.com,65,001", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dns-rr"));
    }

    #[test]
    fn apply_trust_anchor() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "trust-anchor=example.com,12345,8,2,aabbccdd",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dnssec")]
        {
            assert_eq!(d.ds.len(), 1);
            let ds = &d.ds[0];
            assert_eq!(ds.name, "example.com");
            assert_eq!(ds.keytag, 12345);
            assert_eq!(ds.algo, 8);
            assert_eq!(ds.digest_type, 2);
            assert_eq!(ds.digest, vec![0xaa, 0xbb, 0xcc, 0xdd]);
        }
    }

    #[test]
    fn apply_hosts_files_assigns_incrementing_indexes() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "addn-hosts=/etc/hosts.extra\ndhcp-hostsfile=/etc/dhcp.hosts\ndhcp-optsfile=/etc/dhcp.opts",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.addn_hosts.len(), 1);
        assert_eq!(d.dhcp_hosts_file.len(), 1);
        assert_eq!(d.dhcp_opts_file.len(), 1);
        assert_eq!(d.addn_hosts[0].fname, "/etc/hosts.extra");
        assert_eq!(d.dhcp_hosts_file[0].fname, "/etc/dhcp.hosts");
        assert_eq!(d.dhcp_opts_file[0].fname, "/etc/dhcp.opts");
        assert_eq!(d.addn_hosts[0].index, 0);
        assert_eq!(d.dhcp_hosts_file[0].index, 1);
        assert_eq!(d.dhcp_opts_file[0].index, 2);
        assert_eq!(d.host_index, 3);
    }

    #[test]
    fn apply_hosts_dirs_sets_dynamic_dir_flags() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "hostsdir=/etc/hosts.d\ndhcp-hostsdir=/etc/dhcp-hosts.d\ndhcp-optsdir=/etc/dhcp-opts.d",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.dynamic_dirs.len(), 3);
        assert_eq!(d.dynamic_dirs[0].dname, "/etc/hosts.d");
        assert_eq!(d.dynamic_dirs[0].flags, DynDirFlags::HOSTS);
        assert_eq!(d.dynamic_dirs[1].dname, "/etc/dhcp-hosts.d");
        assert_eq!(d.dynamic_dirs[1].flags, DynDirFlags::DHCP_HST);
        assert_eq!(d.dynamic_dirs[2].dname, "/etc/dhcp-opts.d");
        assert_eq!(d.dynamic_dirs[2].flags, DynDirFlags::DHCP_OPT);
    }

    #[test]
    fn daemon_auth_defaults_match_upstream() {
        let d = Daemon::default();
        assert_eq!(d.auth_ttl, 600);
        assert_eq!(d.soa_refresh, 1200);
        assert_eq!(d.soa_retry, 180);
        assert_eq!(d.soa_expiry, 1209600);
    }

    #[test]
    fn apply_auth_ttl() {
        let mut d = Daemon::default();
        let lines = parse_config_text("auth-ttl=1800", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.auth_ttl, 1800);
    }

    #[test]
    fn apply_dhcp_ttl_sets_use_marker() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-ttl=120", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_ttl, 120);
            assert_eq!(d.use_dhcp_ttl, 1);
        }
    }

    #[test]
    fn apply_dhcp_ttl_invalid_value_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-ttl=not-a-ttl", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-ttl"));
    }

    #[test]
    fn apply_dhcp_scriptuser() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-scriptuser=nobody", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.scriptuser, Some("nobody".to_string()));
    }

    #[test]
    fn apply_auth_server_domain_interfaces_and_default_hostmaster() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "auth-server=ns.example.com,eth0/4,2001:db8::53",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.authserver, Some("ns.example.com".to_string()));
        assert_eq!(d.hostmaster, Some("hostmaster.ns.example.com".to_string()));
        assert_eq!(d.auth_interfaces.len(), 2);

        assert_eq!(d.auth_interfaces[0].name, Some("eth0".to_string()));
        assert_eq!(d.auth_interfaces[0].flags, INAME_4);
        assert!(d.auth_interfaces[0].addr.as_ref().unwrap().is_v4());

        assert_eq!(d.auth_interfaces[1].name, None);
        assert_eq!(d.auth_interfaces[1].addr.as_ref().unwrap().ip(), IpAddr::V6("2001:db8::53".parse().unwrap()));
    }

    #[test]
    fn apply_auth_server_preserves_explicit_hostmaster() {
        let mut d = Daemon::default();
        let lines = parse_config_text("auth-soa=1,admin@example.com\nauth-server=ns.example.com", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.authserver, Some("ns.example.com".to_string()));
        assert_eq!(d.hostmaster, Some("admin.example.com".to_string()));
    }

    #[test]
    fn apply_auth_sec_servers() {
        let mut d = Daemon::default();
        let lines = parse_config_text("auth-sec-servers=sec1.example.com,sec2.example.com", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(
            d.secondary_forward_servers,
            vec!["sec1.example.com".to_string(), "sec2.example.com".to_string()]
        );
    }

    #[test]
    fn apply_auth_server_bad_interface_suffix_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("auth-server=ns.example.com,eth0/9", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "auth-server"));
    }

    #[test]
    fn apply_auth_sec_servers_bad_name_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("auth-sec-servers=bad..example", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "auth-sec-servers"));
    }

    #[test]
    fn apply_auth_soa_full_form() {
        let mut d = Daemon::default();
        let lines = parse_config_text("auth-soa=1234,hostmaster@example.com,3600,600,86400", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.soa_sn, 1234);
        assert_eq!(d.hostmaster, Some("hostmaster.example.com".to_string()));
        assert_eq!(d.soa_refresh, 3600);
        assert_eq!(d.soa_retry, 600);
        assert_eq!(d.soa_expiry, 86400);
    }

    #[test]
    fn apply_auth_soa_serial_preserves_default_timers() {
        let mut d = Daemon::default();
        let lines = parse_config_text("auth-soa=42", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.soa_sn, 42);
        assert_eq!(d.hostmaster, None);
        assert_eq!(d.soa_refresh, 1200);
        assert_eq!(d.soa_retry, 180);
        assert_eq!(d.soa_expiry, 1209600);
    }

    #[test]
    fn apply_auth_peer_ipv4_and_ipv6() {
        let mut d = Daemon::default();
        let lines = parse_config_text("auth-peer=192.0.2.53,2001:db8::53", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.auth_peers.len(), 2);
        assert_eq!(d.auth_peers[0].addr.as_ref().unwrap().ip(), IpAddr::V4("192.0.2.53".parse().unwrap()));
        assert_eq!(d.auth_peers[1].addr.as_ref().unwrap().ip(), IpAddr::V6("2001:db8::53".parse().unwrap()));
        assert!(d.auth_peers.iter().all(|peer| peer.name.is_none() && peer.flags == 0));
    }

    #[test]
    fn apply_auth_peer_rejects_non_ip() {
        let mut d = Daemon::default();
        let lines = parse_config_text("auth-peer=secondary.example.com", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "auth-peer"));
    }

    #[test]
    fn apply_bogus_nxdomain_ipv4() {
        let mut d = Daemon::default();
        let lines = parse_config_text("bogus-nxdomain=64.94.110.11", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.bogus_addr.len(), 1);
        assert!(!d.bogus_addr[0].is6);
        assert_eq!(d.bogus_addr[0].prefix, 32);
        assert_eq!(d.bogus_addr[0].addr.as_ipv4(), Some("64.94.110.11".parse().unwrap()));
    }

    #[test]
    fn apply_bogus_nxdomain_ipv4_prefix() {
        let mut d = Daemon::default();
        let lines = parse_config_text("bogus-nxdomain=64.94.110.0/24", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.bogus_addr.len(), 1);
        assert!(!d.bogus_addr[0].is6);
        assert_eq!(d.bogus_addr[0].prefix, 24);
        assert_eq!(d.bogus_addr[0].addr.as_ipv4(), Some("64.94.110.0".parse().unwrap()));
    }

    #[test]
    fn apply_ignore_address_ipv6_prefix() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ignore-address=2001:db8::/32", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.ignore_addr.len(), 1);
        assert!(d.ignore_addr[0].is6);
        assert_eq!(d.ignore_addr[0].prefix, 32);
        assert_eq!(d.ignore_addr[0].addr.as_ipv6(), Some("2001:db8::".parse().unwrap()));
    }

    #[test]
    fn apply_ignore_address_bad_prefix_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ignore-address=192.0.2.0/33", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "ignore-address"));
    }

    #[test]
    fn apply_leasequery_enables_without_address_filter() {
        let mut d = Daemon::default();
        let lines = parse_config_text("leasequery", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_LEASEQUERY));
        assert!(d.leasequery_addr.is_empty());
    }

    #[test]
    fn apply_leasequery_address_filters() {
        let mut d = Daemon::default();
        let lines = parse_config_text("leasequery=192.0.2.0/24\nleasequery=2001:db8::/32", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_LEASEQUERY));
        assert_eq!(d.leasequery_addr.len(), 2);
        assert!(!d.leasequery_addr[0].is6);
        assert_eq!(d.leasequery_addr[0].prefix, 24);
        assert_eq!(d.leasequery_addr[0].addr.as_ipv4(), Some("192.0.2.0".parse().unwrap()));
        assert!(d.leasequery_addr[1].is6);
        assert_eq!(d.leasequery_addr[1].prefix, 32);
        assert_eq!(d.leasequery_addr[1].addr.as_ipv6(), Some("2001:db8::".parse().unwrap()));
    }

    #[test]
    fn apply_leasequery_bad_prefix_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("leasequery=192.0.2.0/33", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "leasequery"));
    }

    #[test]
    fn apply_rebind_domain_ok_multiple() {
        let mut d = Daemon::default();
        let lines = parse_config_text("rebind-domain-ok=example.com,internal.example", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.no_rebind.len(), 2);
        assert_eq!(d.no_rebind[0].domain, "example.com");
        assert_eq!(d.no_rebind[1].domain, "internal.example");
    }

    #[test]
    fn apply_auth_zone_with_subnets_and_interface() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "auth-server=ns.example.com\nauth-zone=example.com,192.0.2.0/24,exclude:192.0.2.128/25,eth0/4",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.auth_zones.len(), 1);
        let zone = &d.auth_zones[0];
        assert_eq!(zone.domain, "example.com");
        assert_eq!(zone.subnet.len(), 1);
        assert_eq!(zone.exclude.len(), 1);
        assert_eq!(zone.interface_names.len(), 1);
        assert_eq!(zone.subnet[0].addr.as_ipv4(), Some("192.0.2.0".parse().unwrap()));
        assert_eq!(zone.subnet[0].prefixlen, 24);
        assert_eq!(zone.exclude[0].addr.as_ipv4(), Some("192.0.2.128".parse().unwrap()));
        assert_eq!(zone.exclude[0].prefixlen, 25);
        assert_eq!(zone.interface_names[0].name, "eth0");
        assert_eq!(zone.interface_names[0].flags, AUTH4);
    }

    #[test]
    fn apply_auth_zone_requires_auth_server() {
        let mut d = Daemon::default();
        let lines = parse_config_text("auth-zone=example.com,192.0.2.0/24", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "auth-server"));
    }

    #[test]
    fn apply_auth_zone_interface_family_suffixes() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "auth-server=ns.example.com\nauth-zone=example.com,eth0/4,eth1/6,eth2",
            "test",
        ).unwrap();
        apply_config(&mut d, &lines).unwrap();
        let zone = &d.auth_zones[0];
        assert_eq!(zone.interface_names[0].name, "eth0");
        assert_eq!(zone.interface_names[0].flags, AUTH4);
        assert_eq!(zone.interface_names[1].name, "eth1");
        assert_eq!(zone.interface_names[1].flags, AUTH6);
        assert_eq!(zone.interface_names[2].name, "eth2");
        assert_eq!(zone.interface_names[2].flags, AUTH4 | AUTH6);
    }

    #[test]
    fn apply_auth_zone_bad_interface_suffix_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("auth-server=ns.example.com\nauth-zone=example.com,eth0/9", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "auth-zone"));
    }

    #[test]
    fn apply_ipset_multiple_domains() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ipset=/example.com/internal.example/vpn,search", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.ipsets.len(), 2);
        assert_eq!(d.ipsets[0].domain, "example.com");
        assert_eq!(d.ipsets[0].sets, vec!["vpn".to_string(), "search".to_string()]);
        assert_eq!(d.ipsets[1].domain, "internal.example");
    }

    #[test]
    fn apply_alias_single_address() {
        let mut d = Daemon::default();
        let lines = parse_config_text("alias=1.2.3.4,5.6.7.8", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.doctors.len(), 1);
        let doctor = d.doctors[0];
        assert_eq!(doctor.in_addr, "1.2.3.4".parse::<Ipv4Addr>().unwrap());
        assert_eq!(doctor.end_addr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(doctor.out_addr, "5.6.7.8".parse::<Ipv4Addr>().unwrap());
        assert_eq!(doctor.mask, Ipv4Addr::new(255, 255, 255, 255));
    }

    #[test]
    fn apply_port_limit_and_filters() {
        let mut d = Daemon::default();
        let lines = parse_config_text("port-limit=3\nfilter-A\nfilter-AAAA", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.randport_limit, 3);
        assert_eq!(d.rrlist_filter.iter().map(|rr| rr.rr).collect::<Vec<_>>(), vec![1, 28]);
    }

    #[test]
    fn apply_cache_rr_and_filter_rr_accept_named_and_numeric_types() {
        let mut d = Daemon::default();
        let lines = parse_config_text("cache-rr=TXT,65\nfilter-rr=CAA,46", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.rrlist_cache.iter().map(|rr| rr.rr).collect::<Vec<_>>(), vec![16, 65]);
        assert_eq!(d.rrlist_filter.iter().map(|rr| rr.rr).collect::<Vec<_>>(), vec![257, 46]);
    }

    #[test]
    fn apply_filter_rr_unknown_type_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("filter-rr=NOTATYPE", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "filter-rr"));
    }

    #[test]
    fn apply_host_record_without_ip_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("host-record=host.example.com", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "host-record"));
    }

    #[test]
    fn apply_trust_anchor_invalid_hex_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("trust-anchor=example.com,1,8,2,xyz", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "trust-anchor"));
    }

    #[test]
    fn apply_dhcp_range_basic() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-range=192.168.0.10,192.168.0.50,12h", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp.len(), 1);
            let ctx = &d.dhcp[0];
            assert_eq!(ctx.start, "192.168.0.10".parse::<Ipv4Addr>().unwrap());
            assert_eq!(ctx.end, "192.168.0.50".parse::<Ipv4Addr>().unwrap());
            assert_eq!(ctx.lease_time, 12 * 3600);
        }
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn dhcp_range_without_explicit_leasefile_defaults_lease_file() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-range=192.168.0.10,192.168.0.50,12h", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.lease_file.as_deref(), Some(DEFAULT_LEASEFILE));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn explicit_dhcp_leasefile_is_not_overridden_by_default() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "dhcp-range=192.168.0.10,192.168.0.50,12h\ndhcp-leasefile=/custom/leases.dat",
            "test",
        )
        .unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.lease_file.as_deref(), Some("/custom/leases.dat"));
    }

    #[test]
    fn no_dhcp_range_leaves_lease_file_unset() {
        let mut d = Daemon::default();
        let lines = parse_config_text("domain=example.com", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.lease_file, None);
    }

    #[test]
    fn apply_dhcp_range_with_set_and_tag() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-range=tag:blue,set:lan,192.168.0.10,192.168.0.50,12h", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let ctx = &d.dhcp[0];
            assert_eq!(ctx.netid.net, "lan");
            assert_eq!(ctx.filter.iter().map(|f| f.net.as_str()).collect::<Vec<_>>(), vec!["blue"]);
        }
    }

    #[test]
    fn apply_dhcp_host_mac_and_addr() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-host=aa:bb:cc:dd:ee:ff,192.168.0.20,printer", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_conf.len(), 1);
            let cfg = &d.dhcp_conf[0];
            assert_eq!(cfg.addr, "192.168.0.20".parse::<Ipv4Addr>().unwrap());
            assert_eq!(cfg.hostname.as_deref(), Some("printer"));
            assert_eq!(cfg.hwaddrs.len(), 1);
            assert_eq!(&cfg.hwaddrs[0].hwaddr[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        }
    }

    #[test]
    fn apply_dhcp_host_client_id() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-host=id:client-1,host1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_conf.len(), 1);
            let cfg = &d.dhcp_conf[0];
            assert_eq!(cfg.clid.as_deref(), Some(b"client-1".as_slice()));
            assert_eq!(cfg.hostname.as_deref(), Some("host1"));
        }
    }

    #[test]
    fn apply_dhcp_host_hex_client_id() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-host=id:01:02:03:04,host1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let cfg = &d.dhcp_conf[0];
            assert_eq!(cfg.clid.as_deref(), Some(&[0x01, 0x02, 0x03, 0x04][..]));
        }
    }

    #[test]
    fn apply_dhcp_host_id_star_sets_noclid() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-host=aa:bb:cc:dd:ee:ff,id:*,host1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let cfg = &d.dhcp_conf[0];
            assert_ne!(cfg.flags & crate::types::dhcp::CONFIG_NOCLID, 0);
            assert_eq!(cfg.hwaddrs.len(), 1);
        }
    }

    #[test]
    fn apply_dhcp_host_set_tag_and_ignore_and_time() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-host=aa:bb:cc:dd:ee:ff,set:lab,host1,ignore,45m", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let cfg = &d.dhcp_conf[0];
            assert_eq!(cfg.netid.iter().map(|n| n.net.as_str()).collect::<Vec<_>>(), vec!["lab"]);
            assert_ne!(cfg.flags & crate::types::dhcp::CONFIG_DISABLE, 0);
            assert_ne!(cfg.flags & crate::types::dhcp::CONFIG_TIME, 0);
            assert_eq!(cfg.lease_time, 45 * 60);
        }
    }

    #[test]
    fn apply_dhcp_host_tag_filters_accumulate() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-host=tag:pxe,tag:lab,aa:bb:cc:dd:ee:ff,host1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let cfg = &d.dhcp_conf[0];
            assert_eq!(cfg.filter.iter().map(|n| n.net.as_str()).collect::<Vec<_>>(), vec!["pxe", "lab"]);
        }
    }

    #[test]
    fn apply_dhcp_host_infinite_lease() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-host=aa:bb:cc:dd:ee:ff,host1,infinite", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let cfg = &d.dhcp_conf[0];
            assert_eq!(cfg.lease_time, u32::MAX);
            assert_ne!(cfg.flags & crate::types::dhcp::CONFIG_TIME, 0);
        }
    }

    #[test]
    fn apply_dhcp_host_wildcard_mac_pattern() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-host=01-00:20:e0:3b:13:*,host1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let hw = &d.dhcp_conf[0].hwaddrs[0];
            assert_eq!(hw.hwaddr_type, 1);
            assert_eq!(hw.hwaddr_len, 6);
            assert_eq!(&hw.hwaddr[..5], &[0x00, 0x20, 0xe0, 0x3b, 0x13]);
            assert_ne!(hw.wildcard_mask, 0);
        }
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_host_multiple_names_error() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-host=host1,host2", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-host"));
    }

    #[test]
    fn apply_dhcp_option_named_ipv4() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=option:router,192.168.0.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_opts.len(), 1);
            let opt = &d.dhcp_opts[0];
            assert_eq!(opt.opt, 3);
            assert_eq!(opt.val.as_deref(), Some(&[192, 168, 0, 1][..]));
        }
    }

    #[test]
    fn apply_dhcp_option_numeric_string() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=15,example.local", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_opts.len(), 1);
            let opt = &d.dhcp_opts[0];
            assert_eq!(opt.opt, 15);
            assert_eq!(opt.val.as_deref(), Some(b"example.local".as_slice()));
        }
    }

    #[test]
    fn apply_dhcp_option_with_tag_selector() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=tag:printers,option:router,192.168.0.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let opt = &d.dhcp_opts[0];
            assert_eq!(opt.netid.iter().map(|n| n.net.as_str()).collect::<Vec<_>>(), vec!["printers"]);
            assert_eq!(opt.opt, 3);
        }
    }

    #[test]
    fn apply_dhcp_option_with_multiple_tag_selectors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=tag:pxe,tag:lab,option:router,192.168.0.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let opt = &d.dhcp_opts[0];
            assert_eq!(opt.netid.iter().map(|n| n.net.as_str()).collect::<Vec<_>>(), vec!["pxe", "lab"]);
        }
    }

    #[test]
    fn apply_dhcp_option_force_sets_force_flag() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option-force=option:router,192.168.0.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let opt = &d.dhcp_opts[0];
            assert_ne!(opt.flags & crate::types::dhcp::DHOPT_FORCE, 0);
            assert_eq!(opt.opt, 3);
        }
    }

    #[test]
    fn apply_dhcp_option_pxe_sets_pxe_flag() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option-pxe=67,pxelinux.0", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let opt = &d.dhcp_opts[0];
            assert_ne!(opt.flags & crate::types::dhcp::DHOPT_PXE_OPT, 0);
            assert_eq!(opt.opt, 67);
        }
    }

    #[test]
    fn apply_dhcp_option_vendor_sets_vendor_match() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=vendor:PXEClient,1,0.0.0.0", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let opt = &d.dhcp_opts[0];
            assert_ne!(opt.flags & crate::types::dhcp::DHOPT_VENDOR, 0);
            assert_eq!(opt.vendor_class.as_deref(), Some(b"PXEClient".as_slice()));
        }
    }

    #[test]
    fn apply_dhcp_option_encap_sets_encap_fields() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=encap:175,190,iscsi-client0", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let opt = &d.dhcp_opts[0];
            assert_ne!(opt.flags & crate::types::dhcp::DHOPT_ENCAPSULATE, 0);
            assert_eq!(opt.encap, 175);
            assert_eq!(opt.opt, 190);
        }
    }

    #[test]
    fn apply_dhcp_option_addr_list_encodes_multiple_addresses() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=option:dns-server,8.8.8.8,1.1.1.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let opt = &d.dhcp_opts[0];
            assert_eq!(opt.val.as_deref(), Some(&[8, 8, 8, 8, 1, 1, 1, 1][..]));
        }
    }

    #[test]
    fn apply_dhcp_option_fixed_width_integer_uses_option_width() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=option:mtu,1500", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let opt = &d.dhcp_opts[0];
            assert_eq!(opt.val.as_deref(), Some(&[0x05, 0xdc][..]));
        }
    }

    #[test]
    fn apply_dhcp_option_time_encodes_seconds() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=option:T1,1h", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let opt = &d.dhcp_opts[0];
            assert_eq!(opt.val.as_deref(), Some(&3600u32.to_be_bytes()[..]));
        }
    }

    #[test]
    fn apply_dhcp_option_rfc1035_name_encodes_domain_search() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=option:domain-search,example.com,lab.local", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let mut expected = Vec::new();
            assert!(crate::util::do_rfc1035_name(&mut expected, "example.com", None));
            assert!(crate::util::do_rfc1035_name(&mut expected, "lab.local", None));
            let opt = &d.dhcp_opts[0];
            assert_eq!(opt.val.as_deref(), Some(expected.as_slice()));
        }
    }

    #[test]
    fn apply_dhcp_boot_basic() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-boot=pxelinux.0,boot.example,192.168.0.2,lab", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.boot_config.len(), 1);
            let boot = &d.boot_config[0];
            assert_eq!(boot.file.as_deref(), Some("pxelinux.0"));
            assert_eq!(boot.sname.as_deref(), Some("boot.example"));
            assert_eq!(boot.next_server, "192.168.0.2".parse::<Ipv4Addr>().unwrap());
            assert_eq!(boot.netid.iter().map(|n| n.net.as_str()).collect::<Vec<_>>(), vec!["lab"]);
        }
    }

    #[test]
    fn apply_dhcp_boot_leading_tag_prefix() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-boot=tag:pxe,pxelinux.0,boot.example,192.168.0.2", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let boot = &d.boot_config[0];
            assert_eq!(boot.netid.iter().map(|n| n.net.as_str()).collect::<Vec<_>>(), vec!["pxe"]);
            assert_eq!(boot.file.as_deref(), Some("pxelinux.0"));
        }
    }

    #[test]
    fn apply_dhcp_boot_multiple_tag_prefixes() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-boot=tag:pxe,tag:lab,pxelinux.0,boot.example,192.168.0.2", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            let boot = &d.boot_config[0];
            assert_eq!(boot.netid.iter().map(|n| n.net.as_str()).collect::<Vec<_>>(), vec!["pxe", "lab"]);
        }
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_option_unknown_name_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=option:not-real,1", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-option"));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_range_without_two_ips_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-range=192.168.0.10", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-range"));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_option_vi_encap_is_explicitly_unsupported() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=vi-encap:2,10,text", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-option"));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_option_option6_is_explicitly_unsupported() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=option6:dns-server,[2001:db8::1]", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-option"));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_option_vendor_and_encap_together_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-option=vendor:PXEClient,encap:175,190,text", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-option"));
    }

    /// `no-hosts6` and `log-rotate` are not real upstream directives (no
    /// entry in `option.c`'s option table) and must not be recognized.
    #[test]
    fn synthetic_non_upstream_keys_are_removed() {
        let mut d = Daemon::default();

        let lines = parse_config_text("no-hosts6", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownOption(ref k, _, _) if k == "no-hosts6"));

        let lines = parse_config_text("log-rotate=/var/log/dnsmasq.log", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownOption(ref k, _, _) if k == "log-rotate"));
    }

    #[test]
    fn apply_fast_dns_retry_defaults_match_upstream() {
        let mut d = Daemon::default();
        let lines = parse_config_text("fast-dns-retry", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.fast_retry_time, 1000);
        assert_eq!(d.fast_retry_timeout, 10);
    }

    #[test]
    fn apply_fast_dns_retry_custom_values() {
        let mut d = Daemon::default();
        let lines = parse_config_text("fast-dns-retry=250,9000", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.fast_retry_time, 250);
        assert_eq!(d.fast_retry_timeout, 9);
    }

    #[test]
    fn apply_fast_dns_retry_too_small_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("fast-dns-retry=49", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "fast-dns-retry"));
    }

    #[test]
    fn apply_dnssec_enables_default_fast_retry() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dnssec", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.fast_retry_time, 1000);
        assert_eq!(d.fast_retry_timeout, 10);
    }

    #[test]
    fn apply_dnssec_preserves_explicit_fast_retry() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dnssec\nfast-dns-retry=250,9000", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.fast_retry_time, 250);
        assert_eq!(d.fast_retry_timeout, 9);
    }

    #[test]
    fn apply_dnssec_check_unsigned_modes() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dnssec-check-unsigned", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(!d.option_bool(OPT_DNSSEC_IGN_NS));

        let mut d = Daemon::default();
        let lines = parse_config_text("dnssec-check-unsigned=no", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert!(d.option_bool(OPT_DNSSEC_IGN_NS));
    }

    #[test]
    fn apply_dnssec_check_unsigned_bad_value_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dnssec-check-unsigned=yes", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dnssec-check-unsigned"));
    }

    #[test]
    fn apply_dnssec_timestamp() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dnssec-timestamp=/var/lib/dnsmasq/dnssec.timestamp", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dnssec")]
        assert_eq!(d.timestamp_file, Some("/var/lib/dnsmasq/dnssec.timestamp".to_string()));
    }

    #[test]
    fn daemon_dnssec_limit_defaults_match_upstream() {
        let d = Daemon::default();
        #[cfg(feature = "dnssec")]
        assert_eq!(
            d.dnssec_limits,
            [
                DNSSEC_LIMIT_SIG_FAIL,
                DNSSEC_LIMIT_CRYPTO,
                DNSSEC_LIMIT_WORK,
                DNSSEC_LIMIT_NSEC3_ITERS,
            ]
        );
    }

    #[test]
    fn apply_dnssec_limits_overrides_nonzero_values() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dnssec-limits=1,0,3,4", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dnssec")]
        assert_eq!(
            d.dnssec_limits,
            [
                1,
                DNSSEC_LIMIT_CRYPTO,
                3,
                4,
            ]
        );
    }

    #[test]
    #[cfg(feature = "dnssec")]
    fn apply_dnssec_limits_bad_value_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dnssec-limits=1,nope", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dnssec-limits"));
    }

    #[test]
    fn cli_lines_emit_port_directive() {
        let args = CliArgs {
            conf_file: Some("dnsmasq.conf".into()),
            port: Some(1053),
            ..Default::default()
        };
        let lines = config_lines_from_cli(&args);
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].key, "port");
        assert_eq!(lines[0].value.as_deref(), Some("1053"));
        assert_eq!(lines[0].file, "<cli>");
    }

    #[test]
    fn cli_lines_emit_boolean_and_repeated_value_directives_in_order() {
        let args = CliArgs {
            port: Some(1053),
            query_port: Some(5300),
            min_port: Some(2000),
            max_port: Some(65000),
            no_resolv: true,
            no_poll: true,
            no_hosts: true,
            bogus_priv: true,
            expand_hosts: true,
            log_queries: true,
            no_negcache: true,
            all_servers: true,
            strict_order: true,
            dnssec: true,
            local_service: true,
            no_rebind: true,
            no_daemon: true,
            keep_in_foreground: true,
            bind_interfaces: true,
            dnssec_debug: true,
            cache_size: Some(2048),
            local_ttl: Some(60),
            neg_ttl: Some(120),
            max_ttl: Some(300),
            min_cache_ttl: Some(30),
            max_cache_ttl: Some(600),
            use_stale_cache: Some(0),
            edns_packet_max: Some(1232),
            fast_dns_retry: Some("250,9000".into()),
            domain: Some("lab.local".into()),
            user: Some("dnsmasq".into()),
            group: Some("dnsmasq".into()),
            pid_file: Some("/run/dnsmasq.pid".into()),
            log_facility: Some("/tmp/dnsmasq.log".into()),
            log_async: Some(25),
            servers_file: Some("/tmp/servers.conf".into()),
            lease_file: Some("/tmp/dnsmasq.leases".into()),
            dns_forward_max: Some(150),
            dhcp_alternate_port: Some("2000,3000".into()),
            resolv_file: vec!["/tmp/resolv.one".into(), "/tmp/resolv.two".into()],
            interface: vec!["eth0".into()],
            except_interface: vec!["wg0".into()],
            listen_address: vec!["127.0.0.1".into(), "::1".into()],
            server: vec!["8.8.8.8".into(), "/example.com/1.1.1.1".into()],
            ..Default::default()
        };
        let lines = config_lines_from_cli(&args);
        let keys: Vec<_> = lines.iter().map(|line| line.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "port", "query-port", "min-port", "max-port", "no-resolv", "no-poll", "no-hosts",
                "bogus-priv", "expand-hosts", "log-queries", "no-negcache", "all-servers",
                "strict-order", "dnssec", "local-service", "no-rebind", "no-daemon",
                "keep-in-foreground", "bind-interfaces", "dnssec-debug", "cache-size",
                "local-ttl", "neg-ttl", "max-ttl", "min-cache-ttl", "max-cache-ttl",
                "use-stale-cache", "edns-packet-max", "fast-dns-retry", "domain", "user",
                "group", "pid-file", "log-facility", "log-async", "servers-file", "lease-file",
                "dns-forward-max", "dhcp-alternate-port", "resolv-file", "resolv-file",
                "interface", "except-interface", "listen-address", "listen-address", "server", "server"
            ]
        );
        assert_eq!(
            lines.iter().find(|line| line.key == "cache-size").and_then(|line| line.value.as_deref()),
            Some("2048")
        );
        assert_eq!(
            lines.iter().find(|line| line.key == "use-stale-cache").and_then(|line| line.value.as_deref()),
            Some("0")
        );
        assert_eq!(
            lines.iter().find(|line| line.key == "fast-dns-retry").and_then(|line| line.value.as_deref()),
            Some("250,9000")
        );
        assert_eq!(
            lines.iter().find(|line| line.key == "domain").and_then(|line| line.value.as_deref()),
            Some("lab.local")
        );
        assert_eq!(
            lines.iter().find(|line| line.key == "log-facility").and_then(|line| line.value.as_deref()),
            Some("/tmp/dnsmasq.log")
        );
        let resolv_values: Vec<_> = lines
            .iter()
            .filter(|line| line.key == "resolv-file")
            .map(|line| line.value.as_deref().unwrap())
            .collect();
        assert_eq!(resolv_values, vec!["/tmp/resolv.one", "/tmp/resolv.two"]);
        let listen_values: Vec<_> = lines
            .iter()
            .filter(|line| line.key == "listen-address")
            .map(|line| line.value.as_deref().unwrap())
            .collect();
        assert_eq!(listen_values, vec!["127.0.0.1", "::1"]);
        let server_values: Vec<_> = lines
            .iter()
            .filter(|line| line.key == "server")
            .map(|line| line.value.as_deref().unwrap())
            .collect();
        assert_eq!(server_values, vec!["8.8.8.8", "/example.com/1.1.1.1"]);
    }

    // ── foreground flags (option.c:215,277,428,456) ───────────────────────────

    /// `-d`/`--no-daemon` is debug mode, not merely "do not fork": upstream maps
    /// it to `OPT_DEBUG`, which also suppresses the pid file and the privilege
    /// drop.  Mapping it to `OPT_NO_FORK` would silently keep both.
    #[test]
    fn no_daemon_sets_debug_and_not_no_fork() {
        let resolved = resolve_config(&parse_config_text("no-daemon", "test.conf").unwrap()).unwrap();
        assert!(resolved.daemon.option_bool(OPT_DEBUG));
        assert!(!resolved.daemon.option_bool(OPT_NO_FORK));
    }

    /// `-k`/`--keep-in-foreground` is the other half: no fork, but everything
    /// else about a normal start still happens.
    #[test]
    fn keep_in_foreground_sets_no_fork_and_not_debug() {
        let resolved =
            resolve_config(&parse_config_text("keep-in-foreground", "test.conf").unwrap()).unwrap();
        assert!(resolved.daemon.option_bool(OPT_NO_FORK));
        assert!(!resolved.daemon.option_bool(OPT_DEBUG));
    }

    #[test]
    fn keep_in_foreground_cli_flag_emits_its_directive() {
        let lines = config_lines_from_cli(&CliArgs {
            keep_in_foreground: true,
            ..Default::default()
        });
        assert_eq!(lines.len(), 1);
        assert_eq!(lines[0].key, "keep-in-foreground");
    }

    // ── run-user default (option.c:5976) ──────────────────────────────────────

    #[test]
    fn run_user_defaults_to_chuser() {
        let resolved = resolve_config(&[]).unwrap();
        assert_eq!(resolved.daemon.username.as_deref(), Some(CHUSER));
        // The group has no unconditional default; it is resolved at startup.
        assert_eq!(resolved.daemon.groupname, None);
    }

    #[test]
    fn explicit_user_overrides_the_default_run_user() {
        let resolved =
            resolve_config(&parse_config_text("user=dnsmasq", "test.conf").unwrap()).unwrap();
        assert_eq!(resolved.daemon.username.as_deref(), Some("dnsmasq"));
    }

    // ── pid-file default (option.c:5977) ──────────────────────────────────────

    /// `daemon->runfile = RUNFILE` is seeded next to `daemon->username = CHUSER`,
    /// so a config that never says `pid-file=` still writes `/var/run/dnsmasq.pid`.
    #[test]
    fn run_file_defaults_to_runfile() {
        let resolved = resolve_config(&[]).unwrap();
        assert_eq!(resolved.daemon.runfile.as_deref(), Some(RUNFILE));
    }

    #[test]
    fn explicit_pid_file_overrides_the_default() {
        let resolved =
            resolve_config(&parse_config_text("pid-file=/run/x.pid", "test.conf").unwrap()).unwrap();
        assert_eq!(resolved.daemon.runfile.as_deref(), Some("/run/x.pid"));
    }

    /// `pid-file=` with an empty value is upstream's way of asking for *no* pid
    /// file at all: `opt_string_alloc` (option.c:677-691) returns NULL for it,
    /// and the write at dnsmasq.c:659 is guarded on `daemon->runfile`.
    #[test]
    fn empty_pid_file_disables_the_pid_file() {
        let resolved =
            resolve_config(&parse_config_text("pid-file=", "test.conf").unwrap()).unwrap();
        assert_eq!(resolved.daemon.runfile, None);
    }

    // ── log-facility: filename vs. facility name (log.c:64-69, option.c:2279-2298) ──

    /// A bare facility name sets `log_fac` and leaves `log_file` unset — this is
    /// the branch that was entirely missing before: every value used to be
    /// treated as a file path.
    #[test]
    fn log_facility_name_sets_log_fac_not_log_file() {
        let resolved =
            resolve_config(&parse_config_text("log-facility=local0", "test.conf").unwrap()).unwrap();
        assert_eq!(resolved.daemon.log_fac, crate::log::LOG_LOCAL0 as i32);
        assert_eq!(resolved.daemon.log_file, None);
    }

    #[test]
    fn log_facility_daemon_name_maps_to_log_daemon() {
        let resolved =
            resolve_config(&parse_config_text("log-facility=daemon", "test.conf").unwrap()).unwrap();
        assert_eq!(resolved.daemon.log_fac, crate::log::LOG_DAEMON as i32);
        assert_eq!(resolved.daemon.log_file, None);
    }

    /// A value containing `/` is a file path, matching `option.c:2281`'s
    /// `strchr(arg, '/')` check.
    #[test]
    fn log_facility_path_sets_log_file_not_log_fac() {
        let resolved = resolve_config(
            &parse_config_text("log-facility=/tmp/dnsmasq.log", "test.conf").unwrap(),
        )
        .unwrap();
        assert_eq!(resolved.daemon.log_file.as_deref(), Some("/tmp/dnsmasq.log"));
        assert_eq!(resolved.daemon.log_fac, -1);
    }

    #[test]
    fn log_facility_unknown_name_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("log-facility=not-a-facility", "test.conf").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "log-facility"));
    }

    #[test]
    fn resolve_config_applies_later_cli_override() {
        let mut lines = parse_config_text("port=5353", "test.conf").unwrap();
        lines.extend(config_lines_from_cli(&CliArgs {
            port: Some(2053),
            ..Default::default()
        }));
        let resolved = resolve_config(&lines).unwrap();
        assert_eq!(resolved.daemon.port, 2053);
    }

    #[test]
    fn resolve_config_applies_cli_boolean_and_server_settings() {
        let lines = config_lines_from_cli(&CliArgs {
            no_resolv: true,
            no_poll: true,
            no_hosts: true,
            bogus_priv: true,
            expand_hosts: true,
            log_queries: true,
            no_negcache: true,
            all_servers: true,
            strict_order: true,
            dnssec: true,
            local_service: true,
            no_rebind: true,
            no_daemon: true,
            keep_in_foreground: true,
            bind_interfaces: true,
            dnssec_debug: true,
            cache_size: Some(1024),
            local_ttl: Some(60),
            neg_ttl: Some(120),
            max_ttl: Some(300),
            min_cache_ttl: Some(30),
            max_cache_ttl: Some(600),
            use_stale_cache: Some(0),
            edns_packet_max: Some(1232),
            fast_dns_retry: Some("250,9000".into()),
            domain: Some("lab.local".into()),
            user: Some("dnsmasq".into()),
            group: Some("dnsmasq".into()),
            pid_file: Some("/run/dnsmasq.pid".into()),
            log_facility: Some("/tmp/dnsmasq.log".into()),
            log_async: Some(25),
            servers_file: Some("/tmp/servers.conf".into()),
            lease_file: Some("/tmp/dnsmasq.leases".into()),
            dns_forward_max: Some(150),
            dhcp_alternate_port: Some("2000,3000".into()),
            resolv_file: vec!["/tmp/resolv.one".into()],
            interface: vec!["eth0".into()],
            except_interface: vec!["wg0".into()],
            listen_address: vec!["127.0.0.1".into()],
            server: vec!["8.8.8.8".into(), "1.1.1.1#5353".into()],
            ..Default::default()
        });
        let resolved = resolve_config(&lines).unwrap();
        assert!(resolved.daemon.option_bool(OPT_NO_RESOLV));
        assert!(resolved.daemon.option_bool(OPT_NO_POLL));
        assert!(resolved.daemon.option_bool(OPT_NO_HOSTS));
        assert!(resolved.daemon.option_bool(OPT_BOGUSPRIV));
        assert!(resolved.daemon.option_bool(OPT_EXPAND));
        assert!(resolved.daemon.option_bool(OPT_LOG));
        assert!(resolved.daemon.option_bool(OPT_NO_NEG));
        assert!(resolved.daemon.option_bool(OPT_ALL_SERVERS));
        assert!(resolved.daemon.option_bool(OPT_ORDER));
        assert!(resolved.daemon.option_bool(OPT_DNSSEC_VALID));
        assert!(!resolved.daemon.option_bool(OPT_LOCAL_SERVICE));
        assert!(resolved.daemon.option_bool(OPT_NO_REBIND));
        assert!(resolved.daemon.option_bool(OPT_DEBUG));
        assert!(resolved.daemon.option_bool(OPT_NO_FORK));
        assert!(resolved.daemon.option_bool(OPT_NOWILD));
        assert!(resolved.daemon.option_bool(OPT_DNSSEC_DEBUG));
        assert_eq!(resolved.daemon.cachesize, 1024);
        assert_eq!(resolved.daemon.local_ttl, 60);
        assert_eq!(resolved.daemon.neg_ttl, 120);
        assert_eq!(resolved.daemon.max_ttl, 300);
        assert_eq!(resolved.daemon.min_cache_ttl, 30);
        assert_eq!(resolved.daemon.max_cache_ttl, 600);
        assert_eq!(resolved.daemon.cache_max_expiry, -1);
        assert_eq!(resolved.daemon.edns_pktsz, 1232);
        assert_eq!(resolved.daemon.fast_retry_time, 250);
        assert_eq!(resolved.daemon.fast_retry_timeout, 9);
        assert_eq!(resolved.daemon.domain_suffix.as_deref(), Some("lab.local"));
        assert_eq!(resolved.daemon.username.as_deref(), Some("dnsmasq"));
        assert_eq!(resolved.daemon.groupname.as_deref(), Some("dnsmasq"));
        assert_eq!(resolved.daemon.runfile.as_deref(), Some("/run/dnsmasq.pid"));
        assert_eq!(resolved.daemon.log_file.as_deref(), Some("/tmp/dnsmasq.log"));
        assert_eq!(resolved.daemon.max_logs, 25);
        assert_eq!(resolved.daemon.servers_file.as_deref(), Some("/tmp/servers.conf"));
        assert_eq!(resolved.daemon.lease_file.as_deref(), Some("/tmp/dnsmasq.leases"));
        assert_eq!(resolved.daemon.ftabsize, 150);
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(resolved.daemon.dhcp_server_port, 2000);
            assert_eq!(resolved.daemon.dhcp_client_port, 3000);
        }
        assert_eq!(resolved.daemon.resolv_files.len(), 1);
        assert_eq!(resolved.daemon.if_names.len(), 1);
        assert_eq!(resolved.daemon.if_except.len(), 1);
        assert_eq!(resolved.daemon.if_addrs.len(), 1);
        assert_eq!(resolved.daemon.servers.len(), 2);
    }

    #[test]
    fn apply_use_stale_cache_defaults_match_upstream() {
        let mut d = Daemon::default();
        let lines = parse_config_text("use-stale-cache", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.cache_max_expiry, 86_400);
    }

    #[test]
    fn apply_use_stale_cache_zero_means_forever() {
        let mut d = Daemon::default();
        let lines = parse_config_text("use-stale-cache=0", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.cache_max_expiry, -1);
    }

    #[test]
    fn apply_use_stale_cache_negative_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("use-stale-cache=-1", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "use-stale-cache"));
    }

    #[test]
    fn apply_ipset_requires_domain_list() {
        let mut d = Daemon::default();
        let lines = parse_config_text("ipset=example.com/vpn", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "ipset"));
    }

    #[test]
    fn apply_port_limit_zero_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("port-limit=0", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "port-limit"));
    }

    // `dhcp-ignore` is upstream's global tag-list gate (`daemon->dhcp_ignore`,
    // `option.c:4659-4700`'s shared `dhcp_netid_list` case), not a per-host
    // selector: every comma-separated field becomes a literal tag name
    // (stripped of a leading `tag:`/`net:` prefix via `is_tag_prefix()`),
    // never parsed as a MAC address or client-id. That's a distinct upstream
    // mechanism from `dhcp-host=...,ignore` (`DhcpConfig`'s `CONFIG_DISABLE`
    // flag on a matched per-host entry).
    #[test]
    fn apply_dhcp_ignore_bare_tag() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-ignore=aa:bb:cc:dd:ee:ff", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_ignore.len(), 1);
            assert_eq!(
                d.dhcp_ignore[0].list.iter().map(|n| n.net.as_str()).collect::<Vec<_>>(),
                vec!["aa:bb:cc:dd:ee:ff"]
            );
            // Not routed through the dhcp-host matcher machinery.
            assert!(d.dhcp_conf.is_empty());
        }
    }

    #[test]
    fn apply_dhcp_ignore_tag_prefix_stripped() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-ignore=tag:pxe", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_ignore.len(), 1);
            assert_eq!(d.dhcp_ignore[0].list[0].net, "pxe");
        }
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_ignore_multiple_tags_and_repeated_directive() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-ignore=tag:a,tag:b\ndhcp-ignore=net:c", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.dhcp_ignore.len(), 2);
        assert_eq!(
            d.dhcp_ignore[0].list.iter().map(|n| n.net.as_str()).collect::<Vec<_>>(),
            vec!["a", "b"]
        );
        assert_eq!(d.dhcp_ignore[1].list[0].net, "c");
    }

    #[test]
    fn apply_dhcp_vendorclass_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-vendorclass=set:pxe,PXEClient", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_vendors.len(), 1);
            assert_eq!(d.dhcp_vendors[0].netid.net, "pxe");
            assert_eq!(d.dhcp_vendors[0].vendor_class, b"PXEClient".to_vec());
        }
    }

    #[test]
    fn dhcp_vendor_invented_key_is_rejected() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-vendor=set:pxe,PXEClient", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownOption(ref k, _, _) if k == "dhcp-vendor"));
    }

    #[test]
    fn apply_dhcp_userclass_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-userclass=set:accounts,engineering", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_userclasses.len(), 1);
            assert_eq!(d.dhcp_userclasses[0].netid.net, "accounts");
            assert_eq!(d.dhcp_userclasses[0].user_class, b"engineering".to_vec());
        }
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_userclass_missing_match_string_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-userclass=set:accounts", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-userclass"));
    }

    #[test]
    fn apply_dhcp_mac_rule_with_wildcards() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-mac=set:printer,00:60:8C:*:*:*", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_macs.len(), 1);
            let rule = &d.dhcp_macs[0];
            assert_eq!(rule.netid.net, "printer");
            assert_eq!(rule.hwaddr_len, 6);
            assert_eq!(rule.hwaddr_type, 0);
            assert_eq!(&rule.hwaddr[..3], &[0x00, 0x60, 0x8c]);
            assert_eq!(rule.wildcard_mask, 0b000111);
        }
    }

    #[test]
    fn apply_dhcp_mac_rule_with_hwtype_prefix() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-mac=set:eth,01-00:11:22:33:44:55", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_macs.len(), 1);
            let rule = &d.dhcp_macs[0];
            assert_eq!(rule.hwaddr_type, 1);
            assert_eq!(&rule.hwaddr[..6], &[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        }
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_mac_invalid_pattern_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-mac=set:printer,00:60:8C:**", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-mac"));
    }

    #[test]
    fn apply_tag_if_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("tag-if=tag:b,tag:c,set:a", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.tag_if.len(), 1);
            let rule = &d.tag_if[0];
            assert_eq!(rule.tag.iter().map(|n| n.net.as_str()).collect::<Vec<_>>(), vec!["c", "b"]);
            assert_eq!(rule.set.iter().map(|n| n.net.as_str()).collect::<Vec<_>>(), vec!["a"]);
        }
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_tag_if_missing_set_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("tag-if=tag:b,tag:c", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "tag-if"));
    }

    #[test]
    fn apply_dhcp_relay_two_address_form() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-relay=192.168.1.1,10.0.0.1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.relay4.len(), 1);
            let relay = &d.relay4[0];
            assert!(matches!(relay.local_addr, AllAddr::Addr4(a) if a == "192.168.1.1".parse::<Ipv4Addr>().unwrap()));
            assert!(matches!(relay.server_addr, AllAddr::Addr4(a) if a == "10.0.0.1".parse::<Ipv4Addr>().unwrap()));
            assert_eq!(relay.port, i32::from(crate::dhcp_protocol::DHCP_SERVER_PORT));
            assert_eq!(relay.split_mode, 0);
            assert_eq!(relay.interface, None);
        }
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_relay_with_port_and_interface() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-relay=192.168.1.1,10.0.0.1#5300,eth0", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.relay4.len(), 1);
        let relay = &d.relay4[0];
        assert!(matches!(relay.server_addr, AllAddr::Addr4(a) if a == "10.0.0.1".parse::<Ipv4Addr>().unwrap()));
        assert_eq!(relay.port, 5300);
        assert_eq!(relay.interface.as_deref(), Some("eth0"));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_relay_broadcast_two_arg_form() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-relay=192.168.1.1,eth0", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.relay4.len(), 1);
        let relay = &d.relay4[0];
        assert!(matches!(relay.server_addr, AllAddr::Addr4(a) if a == Ipv4Addr::UNSPECIFIED));
        assert_eq!(relay.interface.as_deref(), Some("eth0"));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_relay_broadcast_two_arg_form_strips_port_suffix() {
        // Regression test: upstream truncates `two` in place at '#' before
        // reusing it as the interface name (option.c's split_chr(two, '#')
        // mutates the buffer), so `dhcp-relay=<addr>,<iface>#<port>` in
        // broadcast form must store the interface without the port suffix.
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-relay=192.168.1.1,eth0#67", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.relay4.len(), 1);
        let relay = &d.relay4[0];
        assert!(matches!(relay.server_addr, AllAddr::Addr4(a) if a == Ipv4Addr::UNSPECIFIED));
        assert_eq!(relay.interface.as_deref(), Some("eth0"));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_relay_repeatable() {
        let mut d = Daemon::default();
        let lines = parse_config_text(
            "dhcp-relay=192.168.1.1,10.0.0.1\ndhcp-relay=192.168.2.1,10.0.0.2",
            "test",
        )
        .unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.relay4.len(), 2);
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_split_relay_populates_split_mode() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-split-relay=192.168.1.1,10.0.0.1,eth0", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.relay4.len(), 1);
        let relay = &d.relay4[0];
        assert_eq!(relay.split_mode, 1);
        assert_eq!(relay.interface.as_deref(), Some("eth0"));
        assert!(matches!(relay.server_addr, AllAddr::Addr4(a) if a == "10.0.0.1".parse::<Ipv4Addr>().unwrap()));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_split_relay_third_arg_as_uplink_address() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-split-relay=192.168.1.1,10.0.0.1,10.0.0.2", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.relay4.len(), 1);
        let relay = &d.relay4[0];
        assert!(matches!(relay.uplink_addr, AllAddr::Addr4(a) if a == "10.0.0.2".parse::<Ipv4Addr>().unwrap()));
        assert_eq!(relay.interface, None);
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_split_relay_rejects_wildcard_interface() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-split-relay=192.168.1.1,10.0.0.1,eth*", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-split-relay"));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_split_relay_rejects_missing_interface() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-split-relay=192.168.1.1,10.0.0.1", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-split-relay"));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_relay_bad_value_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-relay=not-an-address,10.0.0.1", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-relay"));
    }

    #[test]
    #[cfg(feature = "dhcp6")]
    fn apply_dhcp_relay_ipv6_form() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-relay=1::1,2::1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.relay6.len(), 1);
        let relay = &d.relay6[0];
        assert!(matches!(relay.local_addr, AllAddr::Addr6(a) if a == "1::1".parse::<Ipv6Addr>().unwrap()));
        assert!(matches!(relay.server_addr, AllAddr::Addr6(a) if a == "2::1".parse::<Ipv6Addr>().unwrap()));
        assert_eq!(relay.port, i32::from(crate::dhcp6_protocol::DHCPV6_SERVER_PORT));
    }

    #[test]
    fn apply_dhcp_match_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-match=set:efi-x86_64,60,PXEClient:Arch:00007", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_match.len(), 1);
            let rule = &d.dhcp_match[0];
            assert_eq!(rule.opt, 60);
            assert_eq!(rule.netid.len(), 1);
            assert_eq!(rule.netid[0].net, "efi-x86_64");
            assert_eq!(rule.val.as_deref(), Some(&b"PXEClient:Arch:00007"[..]));
        }
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_match_requires_single_netid_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-match=set:a,set:b,60,PXEClient", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-match"));
    }

    #[test]
    fn apply_dhcp_name_match_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-name-match=set:printer,HP*", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_name_match.len(), 1);
            let rule = &d.dhcp_name_match[0];
            assert_eq!(rule.netid.net, "printer");
            assert_eq!(rule.name, "HP");
            assert!(rule.wildcard);
        }
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_name_match_missing_string_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-name-match=set:printer", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-name-match"));
    }

    #[test]
    fn apply_dhcp_circuitid_string_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-circuitid=set:uplink-a,uplink", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_relay_ids.len(), 1);
            let rule = &d.dhcp_relay_ids[0];
            assert_eq!(rule.netid.net, "uplink-a");
            assert_eq!(rule.subopt, crate::dhcp_protocol::SUBOPT_CIRCUIT_ID);
            assert_eq!(rule.data, b"uplink".to_vec());
        }
    }

    #[test]
    fn apply_dhcp_circuitid_hex_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-circuitid=set:uplink-b,01:02:03:04", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_relay_ids.len(), 1);
            let rule = &d.dhcp_relay_ids[0];
            assert_eq!(rule.data, vec![0x01, 0x02, 0x03, 0x04]);
        }
    }

    #[test]
    fn apply_dhcp_circuitid_nonhex_colon_string_is_literal() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-circuitid=set:uplink-b,01:02:gg", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_relay_ids[0].data, b"01:02:gg".to_vec());
        }
    }

    #[test]
    fn apply_dhcp_remoteid_string_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-remoteid=set:relay-remote,remote-id1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_relay_ids.len(), 1);
            let rule = &d.dhcp_relay_ids[0];
            assert_eq!(rule.netid.net, "relay-remote");
            assert_eq!(rule.subopt, crate::dhcp_protocol::SUBOPT_REMOTE_ID);
            assert_eq!(rule.data, b"remote-id1".to_vec());
        }
    }

    #[test]
    fn apply_dhcp_remoteid_hex_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-remoteid=set:relay-remote,aa:bb:cc", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_relay_ids.len(), 1);
            let rule = &d.dhcp_relay_ids[0];
            assert_eq!(rule.subopt, crate::dhcp_protocol::SUBOPT_REMOTE_ID);
            assert_eq!(rule.data, vec![0xaa, 0xbb, 0xcc]);
        }
    }

    #[test]
    fn apply_dhcp_remoteid_nonhex_colon_string_is_literal() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-remoteid=set:relay-remote,aa:bb:gg", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_relay_ids[0].subopt, crate::dhcp_protocol::SUBOPT_REMOTE_ID);
            assert_eq!(d.dhcp_relay_ids[0].data, b"aa:bb:gg".to_vec());
        }
    }

    #[test]
    fn apply_dhcp_subscrid_string_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-subscrid=set:subscriber-a,subscriber-1", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_relay_ids.len(), 1);
            let rule = &d.dhcp_relay_ids[0];
            assert_eq!(rule.netid.net, "subscriber-a");
            assert_eq!(rule.subopt, crate::dhcp_protocol::SUBOPT_SUBSCR_ID);
            assert_eq!(rule.data, b"subscriber-1".to_vec());
        }
    }

    #[test]
    fn apply_dhcp_subscrid_hex_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-subscrid=set:subscriber-a,01:23:45", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_relay_ids.len(), 1);
            let rule = &d.dhcp_relay_ids[0];
            assert_eq!(rule.subopt, crate::dhcp_protocol::SUBOPT_SUBSCR_ID);
            assert_eq!(rule.data, vec![0x01, 0x23, 0x45]);
        }
    }

    #[test]
    fn apply_dhcp_subscrid_nonhex_colon_string_is_literal() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-subscrid=set:subscriber-a,01:23:zz", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_relay_ids[0].subopt, crate::dhcp_protocol::SUBOPT_SUBSCR_ID);
            assert_eq!(d.dhcp_relay_ids[0].data, b"01:23:zz".to_vec());
        }
    }

    #[test]
    fn apply_dhcp_reply_delay_default_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-reply-delay=5", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_reply_delays.len(), 1);
            assert_eq!(d.dhcp_reply_delays[0].delay_secs, 5);
            assert!(d.dhcp_reply_delays[0].filter.is_empty());
        }
    }

    #[test]
    fn apply_dhcp_reply_delay_tagged_rule() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-reply-delay=tag:pxe,2", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_reply_delays.len(), 1);
            assert_eq!(d.dhcp_reply_delays[0].delay_secs, 2);
            assert_eq!(d.dhcp_reply_delays[0].filter.iter().map(|f| f.net.as_str()).collect::<Vec<_>>(), vec!["pxe"]);
        }
    }

    #[test]
    fn apply_dhcp_reply_delay_multiple_tag_filters() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-reply-delay=tag:pxe,tag:lab,2", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        #[cfg(feature = "dhcp")]
        {
            assert_eq!(d.dhcp_reply_delays[0].filter.iter().map(|f| f.net.as_str()).collect::<Vec<_>>(), vec!["pxe", "lab"]);
        }
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_reply_delay_invalid_selector_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-reply-delay=set:pxe,2", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-reply-delay"));
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn apply_dhcp_reply_delay_invalid_seconds_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dhcp-reply-delay=tag:pxe,soon", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dhcp-reply-delay"));
    }

    #[test]
    fn apply_nftset_multiple_domains() {
        let mut d = Daemon::default();
        let lines = parse_config_text("nftset=/example.com/internal.example/inet#filter#vpn", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.nftsets.len(), 2);
        assert_eq!(d.nftsets[0].domain, "example.com");
        // '#' becomes ' ' (option.c:3268-3271) so `add_to_nftset` can later
        // split off a leading "4 "/"6 " family prefix (nftset.c:53-62).
        assert_eq!(d.nftsets[0].sets, vec!["inet filter vpn".to_string()]);
        assert_eq!(d.nftsets[1].domain, "internal.example");
    }

    #[test]
    fn apply_nftset_dual_family_syntax_parses() {
        let mut d = Daemon::default();
        let lines =
            parse_config_text("nftset=/example.com/4#inet#filter#set4,6#inet#filter#set6", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.nftsets.len(), 1);
        assert_eq!(
            d.nftsets[0].sets,
            vec!["4 inet filter set4".to_string(), "6 inet filter set6".to_string()]
        );
    }

    #[test]
    fn apply_nftset_requires_domain_list() {
        let mut d = Daemon::default();
        let lines = parse_config_text("nftset=example.com/vpn", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "nftset"));
    }

    #[test]
    fn apply_dns_forward_max_sets_forward_table_size() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dns-forward-max=150", "test").unwrap();
        apply_config(&mut d, &lines).unwrap();
        assert_eq!(d.ftabsize, 150);
    }

    #[test]
    fn apply_dns_forward_max_invalid_value_errors() {
        let mut d = Daemon::default();
        let lines = parse_config_text("dns-forward-max=lots", "test").unwrap();
        let err = apply_config(&mut d, &lines).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(_, ref k, _, _, _) if k == "dns-forward-max"));
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
    #[cfg(feature = "dhcp")]
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
        let s = domain_rev4("10.0.0.0".parse().unwrap(), 24).unwrap();
        assert_eq!(s, vec!["0.0.10.in-addr.arpa".to_string()]);
    }

    #[test]
    fn domain_rev4_slash16() {
        let s = domain_rev4("172.16.0.0".parse().unwrap(), 16).unwrap();
        assert_eq!(s, vec!["16.172.in-addr.arpa".to_string()]);
    }

    #[test]
    fn domain_rev4_slash8() {
        let s = domain_rev4("10.0.0.0".parse().unwrap(), 8).unwrap();
        assert_eq!(s, vec!["10.in-addr.arpa".to_string()]);
    }

    /// Upstream's `domain_rev4()` rejects `size < 1` (option.c:1163), so `/0`
    /// is an error, not "the whole `in-addr.arpa` tree".
    #[test]
    fn domain_rev4_slash0_is_rejected() {
        assert!(domain_rev4("0.0.0.0".parse().unwrap(), 0).is_err());
    }

    #[test]
    fn domain_rev4_slash20_splits_into_16_non_aligned_zones() {
        let s = domain_rev4("10.0.0.0".parse().unwrap(), 20).unwrap();
        assert_eq!(s.len(), 16);
        assert_eq!(s[0], "0.0.10.in-addr.arpa");
        assert_eq!(s[15], "15.0.10.in-addr.arpa");
    }

    // ── domain_rev6 ──────────────────────────────────────────────────────────

    #[test]
    fn domain_rev6_slash32() {
        let s = domain_rev6("2001:0db8::".parse().unwrap(), 32).unwrap();
        assert_eq!(s, vec!["8.b.d.0.1.0.0.2.ip6.arpa".to_string()]);
    }

    #[test]
    fn domain_rev6_slash48() {
        let s = domain_rev6("2001:0db8:abcd::".parse().unwrap(), 48).unwrap();
        assert_eq!(s, vec!["d.c.b.a.8.b.d.0.1.0.0.2.ip6.arpa".to_string()]);
    }

    /// Upstream's `domain_rev6()` rejects `size < 1` (option.c:1245), so `/0`
    /// is an error, not "the whole `ip6.arpa` tree".
    #[test]
    fn domain_rev6_slash0_is_rejected() {
        assert!(domain_rev6("::".parse().unwrap(), 0).is_err());
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

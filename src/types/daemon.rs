/// The central daemon state (`struct daemon` in dnsmasq.h).
///
/// In the C code, `daemon` is a single global pointer.  Here we use an
/// `Arc<RwLock<Daemon>>` passed explicitly to every task, enabling safe
/// concurrent access from tokio tasks.

use std::net::{Ipv4Addr, Ipv6Addr};
use crate::types::constants::*;
use crate::types::addr::MySockAddr;
use crate::types::dns_records::*;
use crate::types::network::*;
use crate::types::server::*;
use crate::domain::CondDomain;
use crate::arp::SharedArpState;

#[cfg(feature = "dhcp")]
use crate::types::dhcp::*;

/// A bridged DHCP interface (`struct dhcp_bridge`, `dnsmasq.h:1035-1038`).
///
/// `--bridge-interface=<iface>,<alias>...` remaps DHCP requests arriving on
/// `aliases` to be treated as if they arrived on `iface` for context
/// matching.  C represents `alias` as a linked list of single-field nodes;
/// here it is a `Vec<String>`.
#[derive(Debug, Clone, Default)]
pub struct DhcpBridge {
    pub iface:   String,
    pub aliases: Vec<String>,
}

/// An extra network sharing a DHCP broadcast domain (`struct shared_network`,
/// `dnsmasq.h:1075-1083`), from `--shared-network`.
#[derive(Debug, Clone)]
pub struct SharedNetwork {
    /// Set when the directive's first field was an interface name rather
    /// than a literal address (`if_nametoindex()`, `option.c:3730`).
    pub if_index:    u32,
    pub is6:         bool,
    pub match_addr:  Ipv4Addr,
    pub shared_addr: Ipv4Addr,
    pub match_addr6: Ipv6Addr,
    pub shared_addr6: Ipv6Addr,
}

impl Default for SharedNetwork {
    fn default() -> Self {
        Self {
            if_index:    0,
            is6:         false,
            match_addr:  Ipv4Addr::UNSPECIFIED,
            shared_addr: Ipv4Addr::UNSPECIFIED,
            match_addr6: Ipv6Addr::UNSPECIFIED,
            shared_addr6: Ipv6Addr::UNSPECIFIED,
        }
    }
}

/// Default advertised EDNS0 UDP payload size (`EDNS_PKTSZ` in `dnsmasq.h`),
/// overridable with `edns-packet-max`.
pub const EDNS_PKTSZ: u16 = 4096;

/// The global dnsmasq daemon configuration and runtime state.
///
/// Fields are organized to mirror the C `struct daemon` layout.
#[derive(Debug)]
pub struct Daemon {
    // ── Option bits ───────────────────────────────────────────────────────────
    pub options: [u32; OPTION_SIZE],

    // ── resolv-file / server configuration ───────────────────────────────────
    pub resolv_files:   Vec<Resolvc>,
    pub servers_file:   Option<String>,
    pub servers:        Vec<Server>,
    pub server_has_wildcard: bool,
    pub no_rebind:      Vec<RebindDomain>,
    /// `--synth-domain` (`daemon->synth_domains`, `dnsmasq.h:1196`): IP-range
    /// to domain-name synthesis rules, distinct from the plain `--domain`
    /// subnet form (`daemon->cond_domain`), which this port does not yet
    /// populate — see `tasks.md`.
    pub synth_domains:  Vec<CondDomain>,
    /// Plain `--domain=<name>,<subnet>` conditional-domain entries
    /// (`daemon->cond_domain`, `dnsmasq.h:1196`), distinct from
    /// `synth_domains` above (`--synth-domain`). Populated by the `"domain"`
    /// arm in `option.rs` when a subnet fragment follows the domain name.
    pub cond_domain:    Vec<CondDomain>,
    /// `--bridge-interface` (`daemon->bridges`, `dnsmasq.h:1316`). Declared
    /// unconditionally upstream (not gated on `HAVE_DHCP`).
    pub bridges:        Vec<DhcpBridge>,
    /// `--shared-network` (`daemon->shared_networks`, `dnsmasq.h:1317`).
    pub shared_networks: Vec<SharedNetwork>,

    // ── DNS record configuration ──────────────────────────────────────────────
    pub mxnames:       Vec<MxSrvRecord>,
    pub naptr:         Vec<Naptr>,
    pub txt:           Vec<TxtRecord>,
    pub rr:            Vec<TxtRecord>,
    pub ptr:           Vec<PtrRecord>,
    pub host_records:  Vec<HostRecord>,
    pub cnames:        Vec<Cname>,
    pub auth_zones:    Vec<AuthZone>,
    pub int_names:     Vec<InterfaceName>,
    pub bogus_addr:    Vec<BogusAddr>,
    pub ignore_addr:   Vec<BogusAddr>,
    pub leasequery_addr: Vec<BogusAddr>,
    pub doctors:       Vec<Doctor>,
    pub rrlist_cache:  Vec<RrList>,
    pub rrlist_filter: Vec<RrList>,

    // ── Network interface state ───────────────────────────────────────────────
    pub interfaces:    Vec<Irec>,
    pub if_names:      Vec<Iname>,
    pub if_addrs:      Vec<Iname>,
    pub if_except:     Vec<Iname>,
    pub dhcp_except:   Vec<Iname>,
    pub auth_peers:    Vec<Iname>,
    pub auth_interfaces: Vec<Iname>,
    pub tftp_interfaces: Vec<Iname>,
    pub interface_addrs: Vec<Addrlist>,
    pub ipsets:        Vec<Ipsets>,
    pub nftsets:       Vec<Ipsets>,
    pub allowlists:    Vec<Allowlist>,
    pub allowlist_mask: u32,

    // ── Ports and TTL settings ────────────────────────────────────────────────
    pub port:          u16,
    pub query_port:    u16,
    pub min_port:      u16,
    pub max_port:      u16,
    pub local_ttl:     u32,
    pub neg_ttl:       u32,
    pub max_ttl:       u32,
    pub min_cache_ttl: u32,
    pub max_cache_ttl: u32,
    pub auth_ttl:      u32,
    pub cachesize:     i32,
    pub ftabsize:      i32,
    pub cache_max_expiry: i32,
    pub fast_retry_time: i32,
    pub fast_retry_timeout: i32,
    pub edns_pktsz:    u16,

    // ── Logging ───────────────────────────────────────────────────────────────
    pub log_fac:       i32,
    pub log_file:      Option<String>,
    pub max_logs:      i32,
    pub log_malloc:    i32,
    pub log_id:        i32,
    pub log_display_id: i32,

    // ── Runtime misc ─────────────────────────────────────────────────────────
    pub username:        Option<String>,
    pub groupname:       Option<String>,
    pub scriptuser:      Option<String>,
    pub luascript:       Option<String>,
    pub authserver:      Option<String>,
    pub hostmaster:      Option<String>,
    pub secondary_forward_servers: Vec<String>,
    pub domain_suffix:   Option<String>,
    pub runfile:         Option<String>,
    pub lease_change_command: Option<String>,
    pub lease_file:      Option<String>,
    pub dns_client_id:   Option<String>,
    pub mxtarget:        Option<String>,
    /// `--umbrella orgid:<n>` (`daemon->umbrella_org`, `dnsmasq.h:1217`).
    pub umbrella_org:    u32,
    /// `--umbrella assetid:<n>` (`daemon->umbrella_asset`, `dnsmasq.h:1218`).
    pub umbrella_asset:  u32,
    /// `--umbrella deviceid:<16 hex chars>` (`daemon->umbrella_device`,
    /// `dnsmasq.h:1219`). Only meaningful when `OPT_UMBRELLA_DEVID` is set.
    pub umbrella_device: [u8; 8],
    pub add_subnet4:     Option<MySubnet>,
    pub add_subnet6:     Option<MySubnet>,
    pub addn_hosts:      Vec<HostsFile>,
    pub dhcp_hosts_file: Vec<HostsFile>,
    pub dhcp_opts_file:  Vec<HostsFile>,
    pub dynamic_dirs:    Vec<DynDir>,
    /// Raw inotify fd opened by `inotify::inotify_dnsmasq_init`; `-1` if
    /// unopened (init not yet run, or `inotify_init1` failed).
    #[cfg(feature = "inotify")]
    pub inotify_fd:      i32,
    pub soa_sn:          u32,
    pub soa_refresh:     u32,
    pub soa_retry:       u32,
    pub soa_expiry:      u32,
    pub osport:          i32,
    pub host_index:      i32,
    pub pipe_to_parent:  i32,
    pub max_procs:       i32,
    pub randport_limit:  i32,
    /// Incremented each time a config reload (SIGHUP) is processed.
    pub reload_count:    u32,
    /// Set when DNS data has been modified and needs re-serving.
    pub dns_dirty:       bool,
    /// The next scheduled alarm time (if any).
    pub next_alarm:      Option<std::time::Instant>,

    // ── ARP / neighbour cache ─────────────────────────────────────────────────
    /// IP → MAC cache backing `find_mac()` (`arp.c`'s file-scope `arps`/`old`
    /// lists), plus its persistent netlink socket. Consulted by EDNS0 MAC
    /// options (`--add-mac`, `--mac-base64`, `--mac-hex`) and DHCPv6 client
    /// MAC logging. Shared (`Arc<Mutex<_>>`, not owned outright) because the
    /// forwarding loop only sees a `ForwardConfig` snapshot of `Daemon`
    /// (`dnsmasq::daemon_forward_config`) and must consult this same cache,
    /// not a private copy, to match upstream's single file-scope `arps` list.
    pub arp_state:        SharedArpState,

    // ── DHCP state (feature-gated) ────────────────────────────────────────────
    #[cfg(feature = "dhcp")]
    pub dhcp:            Vec<DhcpContext>,
    #[cfg(feature = "dhcp")]
    pub dhcp_conf:       Vec<DhcpConfig>,
    #[cfg(feature = "dhcp")]
    pub dhcp_opts:       Vec<DhcpOpt>,
    #[cfg(feature = "dhcp")]
    pub dhcp_opts6:      Vec<DhcpOpt>,
    #[cfg(feature = "dhcp")]
    pub dhcp_vendors:    Vec<DhcpVendorRule>,
    #[cfg(feature = "dhcp")]
    pub dhcp_userclasses: Vec<DhcpUserClassRule>,
    #[cfg(feature = "dhcp")]
    pub dhcp_macs:      Vec<DhcpMacRule>,
    #[cfg(feature = "dhcp")]
    pub dhcp_relay_ids: Vec<DhcpRelayIdRule>,
    #[cfg(feature = "dhcp")]
    pub dhcp_reply_delays: Vec<DhcpReplyDelay>,
    #[cfg(feature = "dhcp")]
    pub boot_config:     Vec<DhcpBoot>,
    /// Conditional tag-setting rules from `tag-if` (`struct tag_if`).
    #[cfg(feature = "dhcp")]
    pub tag_if:          Vec<crate::dhcp_common::TagIf>,
    /// Option-substring classifier rules from `dhcp-match` (`daemon->dhcp_match`).
    #[cfg(feature = "dhcp")]
    pub dhcp_match:      Vec<DhcpOpt>,
    /// DHCPv6 counterpart of `dhcp_match` (`daemon->dhcp_match6`). Always empty
    /// today: the config parser rejects `option6:` inside `dhcp-match`, so
    /// nothing ever populates it — see tasks.md.
    #[cfg(feature = "dhcp")]
    pub dhcp_match6:     Vec<DhcpOpt>,
    /// Client-hostname classifier rules from `dhcp-name-match`.
    #[cfg(feature = "dhcp")]
    pub dhcp_name_match: Vec<DhcpMatchName>,
    #[cfg(feature = "dhcp")]
    pub dhcp_ttl:        u32,
    #[cfg(feature = "dhcp")]
    pub use_dhcp_ttl:    u32,
    #[cfg(feature = "dhcp")]
    pub dhcp_max:        i32,
    #[cfg(feature = "dhcp")]
    pub dhcp_server_port: i32,
    #[cfg(feature = "dhcp")]
    pub dhcp_client_port: i32,
    #[cfg(feature = "dhcp")]
    pub min_leasetime:   u32,
    #[cfg(feature = "dhcp")]
    pub relay4:          Vec<DhcpRelay>,
    /// `--dhcp-pxe-vendor` (`daemon->dhcp_pxe_vendors`, `dnsmasq.h:1227`).
    #[cfg(feature = "dhcp")]
    pub dhcp_pxe_vendors: Vec<DhcpPxeVendor>,
    /// `--pxe-service` (`daemon->pxe_services`, `dnsmasq.h:1231`).
    #[cfg(feature = "dhcp")]
    pub pxe_services:    Vec<PxeService>,
    /// `--pxe-prompt`/`--pxe-service` (`daemon->enable_pxe`, `dnsmasq.h:1237`):
    /// set once either directive successfully registers an entry.
    #[cfg(feature = "dhcp")]
    pub enable_pxe:      bool,
    /// Auto-assigned boot-service type counter for `--pxe-service` entries
    /// that give a `basename` instead of a literal boot-service type
    /// (`static int boottype` in `option.c`'s `LOPT_PXE_SERV` case, seeded at
    /// `32768`). Mirrors that function-local static as explicit `Daemon`
    /// state rather than inventing new semantics.
    #[cfg(feature = "dhcp")]
    pub pxe_boottype_next: u16,
    /// `--dhcp-ignore=<tag>[,<tag>...]` (`daemon->dhcp_ignore`,
    /// `dnsmasq.h:1239`): a global tag-list gate, distinct from a per-host
    /// `dhcp-host=...,ignore` entry (`DhcpConfig`'s `CONFIG_DISABLE` flag).
    #[cfg(feature = "dhcp")]
    pub dhcp_ignore:      Vec<DhcpNetidList>,
    /// `--dhcp-ignore-names` (`daemon->dhcp_ignore_names`, `dnsmasq.h:1239`).
    #[cfg(feature = "dhcp")]
    pub dhcp_ignore_names: Vec<DhcpNetidList>,
    /// `--dhcp-generate-names` (`daemon->dhcp_gen_names`, `dnsmasq.h:1239`).
    #[cfg(feature = "dhcp")]
    pub dhcp_gen_names:   Vec<DhcpNetidList>,
    /// `--dhcp-broadcast` (`daemon->force_broadcast`, `dnsmasq.h:1240`).
    #[cfg(feature = "dhcp")]
    pub force_broadcast:  Vec<DhcpNetidList>,
    /// `--bootp-dynamic` (`daemon->bootp_dynamic`, `dnsmasq.h:1240`).
    #[cfg(feature = "dhcp")]
    pub bootp_dynamic:    Vec<DhcpNetidList>,
    /// `--dhcp-proxy[=<addr>...]` (`daemon->override_relays`,
    /// `dnsmasq.h:1233`): addresses this proxy DHCP server should treat as
    /// legitimate relay agents even without `giaddr` set.
    #[cfg(feature = "dhcp")]
    pub override_relays:  Vec<Ipv4Addr>,
    /// `--dhcp-proxy` (`daemon->override`, `dnsmasq.h:1236`): proxy-DHCP mode
    /// is active.
    #[cfg(feature = "dhcp")]
    pub dhcp_override:    bool,

    #[cfg(feature = "dhcp6")]
    pub dhcp6:           Vec<DhcpContext>,
    #[cfg(feature = "dhcp6")]
    pub relay6:          Vec<DhcpRelay>,
    #[cfg(feature = "dhcp6")]
    pub ra_interfaces:   Vec<RaInterface>,
    /// `daemon->doing_ra` (dnsmasq.h:1238) — whether we send Router
    /// Advertisements at all, computed in `normalize_config` from
    /// `--enable-ra` and any `CONTEXT_RA` DHCPv6 context (dnsmasq.c:289-305).
    #[cfg(feature = "dhcp6")]
    pub doing_ra:        bool,
    /// The constructed on-wire server DUID (upstream's `daemon->duid`,
    /// `daemon->duid_len`), filled in by `dhcp6::make_duid()` at startup.
    /// `None` until `make_duid()` has run.
    #[cfg(feature = "dhcp6")]
    pub duid:            Option<Vec<u8>>,
    /// Raw `enterprise-number,hex-id` bytes from `--dhcp-duid=`, upstream's
    /// `daemon->duid_config`/`duid_config_len`. Input to `make_duid()`, not
    /// itself a valid wire-format DUID.
    #[cfg(feature = "dhcp6")]
    pub duid_config:     Option<Vec<u8>>,
    #[cfg(feature = "dhcp6")]
    pub duid_enterprise: u32,
    /// `daemon->doing_dhcp6` (`dnsmasq.h:1238`): set at startup when any
    /// `dhcp6` context carries `CONTEXT_DHCP` (`dnsmasq.c:288-296`). Not
    /// directly config-set; derived from `dhcp6` at `init_daemon_with` time.
    #[cfg(feature = "dhcp6")]
    pub doing_dhcp6:     bool,
    /// `daemon->doing_ra` (`dnsmasq.h:1238`): set at startup from
    /// `option_bool(OPT_RA)` and/or any `dhcp6` context carrying
    /// `CONTEXT_RA` (`dnsmasq.c:288-296`). Not directly config-set; derived
    /// from `dhcp6`/`OPT_RA` at `init_daemon_with` time.
    #[cfg(feature = "dhcp6")]
    pub doing_ra:        bool,

    // ── DNSSEC (feature-gated) ────────────────────────────────────────────────
    #[cfg(feature = "dnssec")]
    pub ds:                 Vec<DsConfig>,
    #[cfg(feature = "dnssec")]
    pub dnssec_limits:      [i32; LIMIT_MAX],
    #[cfg(feature = "dnssec")]
    pub timestamp_file:     Option<String>,
    #[cfg(feature = "dnssec")]
    pub dnssec_no_time_check: bool,
    #[cfg(feature = "dnssec")]
    pub back_to_the_future: bool,

    // ── TFTP (feature-gated) ──────────────────────────────────────────────────
    #[cfg(feature = "tftp")]
    pub tftp_prefix:        Option<String>,
    #[cfg(feature = "tftp")]
    pub tftp_max:           i32,
    #[cfg(feature = "tftp")]
    pub tftp_mtu:           i32,
    #[cfg(feature = "tftp")]
    pub start_tftp_port:    i32,
    #[cfg(feature = "tftp")]
    pub end_tftp_port:      i32,

    // ── Dump (feature-gated) ──────────────────────────────────────────────────
    #[cfg(feature = "dump")]
    pub dump_file:   Option<String>,
    #[cfg(feature = "dump")]
    pub dump_mask:   i32,

    // ── DBus (feature-gated) ──────────────────────────────────────────────────
    #[cfg(feature = "dbus")]
    pub dbus_name:   Option<String>,

    // ── UBus (feature-gated) ──────────────────────────────────────────────────
    #[cfg(feature = "ubus")]
    pub ubus_name:   Option<String>,
}

impl Daemon {
    /// Test whether an option bit is set.
    pub fn option_bool(&self, opt: usize) -> bool {
        let bits = u32::BITS as usize;
        self.options[opt / bits] & (1u32 << (opt % bits)) != 0
    }

    /// Set an option bit.
    pub fn set_option(&mut self, opt: usize) {
        let bits = u32::BITS as usize;
        self.options[opt / bits] |= 1u32 << (opt % bits);
    }

    /// Clear an option bit.
    pub fn clear_option(&mut self, opt: usize) {
        let bits = u32::BITS as usize;
        self.options[opt / bits] &= !(1u32 << (opt % bits));
    }
}

impl Default for Daemon {
    fn default() -> Self {
        Self {
            options: [0u32; OPTION_SIZE],
            resolv_files: vec![],
            servers_file: None,
            servers: vec![],
            server_has_wildcard: false,
            no_rebind: vec![],
            synth_domains: vec![],
            cond_domain: vec![],
            bridges: vec![],
            shared_networks: vec![],
            mxnames: vec![],
            naptr: vec![],
            txt: vec![],
            rr: vec![],
            ptr: vec![],
            host_records: vec![],
            cnames: vec![],
            auth_zones: vec![],
            int_names: vec![],
            bogus_addr: vec![],
            ignore_addr: vec![],
            leasequery_addr: vec![],
            doctors: vec![],
            rrlist_cache: vec![],
            rrlist_filter: vec![],
            interfaces: vec![],
            if_names: vec![],
            if_addrs: vec![],
            if_except: vec![],
            dhcp_except: vec![],
            auth_peers: vec![],
            auth_interfaces: vec![],
            tftp_interfaces: vec![],
            interface_addrs: vec![],
            ipsets: vec![],
            nftsets: vec![],
            allowlists: vec![],
            allowlist_mask: 0,
            port: 53,
            query_port: 0,
            min_port: 1024,
            max_port: 65535,
            local_ttl: 0,
            neg_ttl: 0,
            max_ttl: 0,
            min_cache_ttl: 0,
            max_cache_ttl: 0,
            auth_ttl: 600,
            cachesize: 150,
            ftabsize: 150,
            cache_max_expiry: -1,
            fast_retry_time: 0,
            fast_retry_timeout: 0,
            edns_pktsz: EDNS_PKTSZ,
            log_fac: -1,
            log_file: None,
            max_logs: 5,
            log_malloc: 0,
            log_id: 0,
            log_display_id: 0,
            username: None,
            groupname: None,
            scriptuser: None,
            luascript: None,
            authserver: None,
            hostmaster: None,
            secondary_forward_servers: vec![],
            domain_suffix: None,
            runfile: None,
            lease_change_command: None,
            lease_file: None,
            dns_client_id: None,
            mxtarget: None,
            umbrella_org: 0,
            umbrella_asset: 0,
            umbrella_device: [0u8; 8],
            add_subnet4: None,
            add_subnet6: None,
            addn_hosts: vec![],
            dhcp_hosts_file: vec![],
            dhcp_opts_file: vec![],
            dynamic_dirs: vec![],
            #[cfg(feature = "inotify")]
            inotify_fd: -1,
            soa_sn: 0,
            soa_refresh: 1200,
            soa_retry: 180,
            soa_expiry: 1209600,
            osport: 0,
            host_index: 0,
            pipe_to_parent: -1,
            max_procs: 0,
            // `option.c:5986` — one source port per transaction per server, and
            // `--port-limit` refuses anything below 1.  A zero here would make
            // the socket pool reuse a transaction's first port for every send.
            randport_limit: 1,
            reload_count: 0,
            dns_dirty: false,
            next_alarm: None,
            arp_state: crate::arp::new_shared_arp_state(),

            #[cfg(feature = "dhcp")]
            dhcp: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_conf: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_opts: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_opts6: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_vendors: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_userclasses: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_macs: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_relay_ids: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_reply_delays: vec![],
            #[cfg(feature = "dhcp")]
            boot_config: vec![],
            #[cfg(feature = "dhcp")]
            tag_if: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_match: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_match6: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_name_match: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_ttl: 0,
            #[cfg(feature = "dhcp")]
            use_dhcp_ttl: 0,
            #[cfg(feature = "dhcp")]
            dhcp_max: 1000,
            #[cfg(feature = "dhcp")]
            dhcp_server_port: 67,
            #[cfg(feature = "dhcp")]
            dhcp_client_port: 68,
            #[cfg(feature = "dhcp")]
            min_leasetime: 120,
            #[cfg(feature = "dhcp")]
            relay4: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_pxe_vendors: vec![],
            #[cfg(feature = "dhcp")]
            pxe_services: vec![],
            #[cfg(feature = "dhcp")]
            enable_pxe: false,
            #[cfg(feature = "dhcp")]
            pxe_boottype_next: 32768,
            #[cfg(feature = "dhcp")]
            dhcp_ignore: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_ignore_names: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_gen_names: vec![],
            #[cfg(feature = "dhcp")]
            force_broadcast: vec![],
            #[cfg(feature = "dhcp")]
            bootp_dynamic: vec![],
            #[cfg(feature = "dhcp")]
            override_relays: vec![],
            #[cfg(feature = "dhcp")]
            dhcp_override: false,

            #[cfg(feature = "dhcp6")]
            dhcp6: vec![],
            #[cfg(feature = "dhcp6")]
            relay6: vec![],
            #[cfg(feature = "dhcp6")]
            ra_interfaces: vec![],
            #[cfg(feature = "dhcp6")]
            doing_ra: false,
            #[cfg(feature = "dhcp6")]
            duid: None,
            #[cfg(feature = "dhcp6")]
            duid_config: None,
            #[cfg(feature = "dhcp6")]
            duid_enterprise: 0,
            #[cfg(feature = "dhcp6")]
            doing_dhcp6: false,
            #[cfg(feature = "dhcp6")]
            doing_ra: false,

            #[cfg(feature = "dnssec")]
            ds: vec![],
            #[cfg(feature = "dnssec")]
            dnssec_limits: [
                DNSSEC_LIMIT_SIG_FAIL,
                DNSSEC_LIMIT_CRYPTO,
                DNSSEC_LIMIT_WORK,
                DNSSEC_LIMIT_NSEC3_ITERS,
            ],
            #[cfg(feature = "dnssec")]
            timestamp_file: None,
            #[cfg(feature = "dnssec")]
            dnssec_no_time_check: false,
            #[cfg(feature = "dnssec")]
            back_to_the_future: false,

            #[cfg(feature = "tftp")]
            tftp_prefix: None,
            #[cfg(feature = "tftp")]
            tftp_max: 0,
            #[cfg(feature = "tftp")]
            tftp_mtu: 0,
            #[cfg(feature = "tftp")]
            start_tftp_port: 0,
            #[cfg(feature = "tftp")]
            end_tftp_port: 0,

            #[cfg(feature = "dump")]
            dump_file: None,
            #[cfg(feature = "dump")]
            dump_mask: -1,

            #[cfg(feature = "dbus")]
            dbus_name: None,

            #[cfg(feature = "ubus")]
            ubus_name: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::constants::{OPT_DEBUG, OPT_DNSSEC_VALID, OPT_NO_POLL};

    #[test]
    fn option_set_get_clear() {
        let mut d = Daemon::default();
        assert!(!d.option_bool(OPT_DEBUG));
        d.set_option(OPT_DEBUG);
        assert!(d.option_bool(OPT_DEBUG));
        d.clear_option(OPT_DEBUG);
        assert!(!d.option_bool(OPT_DEBUG));
    }

    #[test]
    fn multiple_option_bits_independent() {
        let mut d = Daemon::default();
        d.set_option(OPT_DEBUG);
        d.set_option(OPT_NO_POLL);
        assert!(d.option_bool(OPT_DEBUG));
        assert!(d.option_bool(OPT_NO_POLL));
        d.clear_option(OPT_DEBUG);
        assert!(!d.option_bool(OPT_DEBUG));
        assert!(d.option_bool(OPT_NO_POLL));
    }

    #[test]
    fn high_option_bit_set_get_clear() {
        let mut d = Daemon::default();
        assert!(!d.option_bool(OPT_DNSSEC_VALID));
        d.set_option(OPT_DNSSEC_VALID);
        assert!(d.option_bool(OPT_DNSSEC_VALID));
        d.clear_option(OPT_DNSSEC_VALID);
        assert!(!d.option_bool(OPT_DNSSEC_VALID));
    }

    #[test]
    fn default_port_is_53() {
        let d = Daemon::default();
        assert_eq!(d.port, 53);
    }
}

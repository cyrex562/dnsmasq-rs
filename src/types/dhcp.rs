/// DHCP configuration types.
/// Ported from `struct dhcp_lease`, `struct dhcp_context`, `struct dhcp_config`,
/// `struct dhcp_opt`, and related DHCP types in `dnsmasq.h`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
use crate::dhcp_protocol::DHCP_CHADDR_MAX;
use crate::types::addr::AllAddr;

// CONFIG_* flags for dhcp_config
bitflags::bitflags! {
    /// `struct dhcp_config`'s `flags` (upstream `CONFIG_*` constants in
    /// `dnsmasq.h`) — per-host `dhcp-host` reservation behavior bits. Bit
    /// positions 4, 64, and 8192 have no corresponding upstream `CONFIG_*`
    /// name and are intentionally absent here, matching `dnsmasq.h` exactly.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ConfigFlags: u32 {
        const DISABLE     = 1 << 0;
        const CLID        = 1 << 1;
        const TIME        = 1 << 3;
        const NAME        = 1 << 4;
        const ADDR        = 1 << 5;
        const NOCLID      = 1 << 7;
        const FROM_ETHERS = 1 << 8;
        const ADDR_HOSTS  = 1 << 9;
        const DECLINED    = 1 << 10;
        const BANK        = 1 << 11;
        const ADDR6       = 1 << 12;
        const ADDR6_HOSTS = 1 << 14;
    }
}

// DHOPT_* flags for dhcp_opt
bitflags::bitflags! {
    /// `struct dhcp_opt`'s `flags` (upstream `DHOPT_*` constants in
    /// `dnsmasq.h`) — per-option-record behavior bits for `dhcp-option`/
    /// `dhcp-match`/vendor-class encapsulation handling.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct DhOptFlags: u32 {
        const ADDR         = 1 << 0;
        const STRING       = 1 << 1;
        const ENCAPSULATE  = 1 << 2;
        const ENCAP_MATCH  = 1 << 3;
        const FORCE        = 1 << 4;
        const BANK         = 1 << 5;
        const ENCAP_DONE   = 1 << 6;
        const MATCH        = 1 << 7;
        const VENDOR       = 1 << 8;
        const HEX          = 1 << 9;
        const VENDOR_MATCH = 1 << 10;
        const RFC3925      = 1 << 11;
        const TAGOK        = 1 << 12;
        const ADDR6        = 1 << 13;
        const VENDOR_PXE   = 1 << 14;
        const PXE_OPT      = 1 << 15;
    }
}

// CONTEXT_* flags
bitflags::bitflags! {
    /// `struct dhcp_context`'s `flags` (upstream `CONTEXT_*` constants in
    /// `dnsmasq.h`) — per-subnet/interface DHCPv4/v6/RA context state.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ContextFlags: u32 {
        const STATIC        = 1 << 0;
        const NETMASK       = 1 << 1;
        const BRDCAST       = 1 << 2;
        const PROXY         = 1 << 3;
        const RA_ROUTER     = 1 << 4;
        const RA_DONE       = 1 << 5;
        const RA_NAME       = 1 << 6;
        const RA_STATELESS  = 1 << 7;
        const DHCP          = 1 << 8;
        const DEPRECATE     = 1 << 9;
        const TEMPLATE      = 1 << 10;
        const CONSTRUCTED   = 1 << 11;
        const GC            = 1 << 12;
        const RA            = 1 << 13;
        const CONF_USED     = 1 << 14;
        const USED          = 1 << 15;
        const OLD           = 1 << 16;
        const V6            = 1 << 17;
        const RA_OFF_LINK   = 1 << 18;
        const SETLEASE      = 1 << 19;
    }
}

// LEASE_* flags
bitflags::bitflags! {
    /// `struct dhcp_lease`'s `flags` (upstream `LEASE_*` constants in
    /// `dnsmasq.h`) — per-lease state and lease-script/renewal bookkeeping.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct LeaseFlags: u32 {
        const NEW          = 1 << 0;
        const CHANGED      = 1 << 1;
        const AUX_CHANGED  = 1 << 2;
        const AUTH_NAME    = 1 << 3;
        const USED         = 1 << 4;
        const NA           = 1 << 5;
        const TA           = 1 << 6;
        const HAVE_HWADDR  = 1 << 7;
        const EXP_CHANGED  = 1 << 8;
    }
}

// Action codes for the helper process RPC
pub const ACTION_DEL:          u32 = 1;
pub const ACTION_OLD_HOSTNAME: u32 = 2;
pub const ACTION_OLD:          u32 = 3;
pub const ACTION_ADD:          u32 = 4;
pub const ACTION_TFTP:         u32 = 5;
pub const ACTION_ARP:          u32 = 6;
pub const ACTION_ARP_DEL:      u32 = 7;
pub const ACTION_RELAY_SNOOP:  u32 = 8;

/// A DHCP network tag / class identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DhcpNetid {
    pub net: String,
}

/// A DHCP lease entry (`struct dhcp_lease`).
#[derive(Debug, Clone)]
pub struct DhcpLease {
    pub clid:       Option<Vec<u8>>,
    pub hostname:   Option<String>,
    pub fqdn:       Option<String>,
    pub old_hostname: Option<String>,
    pub flags:      LeaseFlags,
    pub expires:    Option<SystemTime>,
    pub hwaddr:     [u8; DHCP_CHADDR_MAX],
    pub hwaddr_len: usize,
    pub hwaddr_type: i32,
    pub addr:       Ipv4Addr,
    pub giaddr:     Ipv4Addr,
    pub extradata:  Vec<u8>,
    pub last_interface: i32,
    pub new_interface:  i32,
    pub new_prefixlen:  i32,
    pub agent_id:   Option<Vec<u8>>,
    pub vendorclass: Option<Vec<u8>>,

    #[cfg(feature = "dhcp6")]
    pub addr6: Ipv6Addr,
    #[cfg(feature = "dhcp6")]
    pub iaid:  u32,
    #[cfg(feature = "dhcp6")]
    pub slaac_address: Vec<SlaacAddress>,
    #[cfg(feature = "dhcp6")]
    pub vendorclass_count: i32,
}

/// A freshly-allocated, otherwise-empty lease: no client-id/hostname/agent
/// info, no hardware address, unspecified addresses, no flags set. Callers
/// building a new `DhcpLease` only need to name the handful of fields that
/// differ from this baseline via `..Default::default()`, rather than
/// repeating all ~20 fields (`Ipv4Addr`/`Ipv6Addr` don't implement `Default`
/// in std, so this can't be `#[derive(Default)]`).
impl Default for DhcpLease {
    fn default() -> Self {
        Self {
            clid: None,
            hostname: None,
            fqdn: None,
            old_hostname: None,
            flags: LeaseFlags::empty(),
            expires: None,
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            hwaddr_len: 0,
            hwaddr_type: 0,
            addr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            extradata: Vec::new(),
            last_interface: 0,
            new_interface: 0,
            new_prefixlen: 0,
            agent_id: None,
            vendorclass: None,
            #[cfg(feature = "dhcp6")]
            addr6: Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            iaid: 0,
            #[cfg(feature = "dhcp6")]
            slaac_address: Vec::new(),
            #[cfg(feature = "dhcp6")]
            vendorclass_count: 0,
        }
    }
}

#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone)]
pub struct SlaacAddress {
    pub addr:      Ipv6Addr,
    pub ping_time: Option<SystemTime>,
    pub backoff:   i32,
}

/// DHCPv4/v6 address context (`struct dhcp_context`).
#[derive(Debug, Clone)]
pub struct DhcpContext {
    pub lease_time: u32,
    pub addr_epoch: u32,
    pub netmask:    Ipv4Addr,
    pub broadcast:  Ipv4Addr,
    pub local:      Ipv4Addr,
    pub router:     Ipv4Addr,
    pub start:      Ipv4Addr,
    pub end:        Ipv4Addr,
    pub flags:      ContextFlags,
    pub netid:      DhcpNetid,
    pub filter:     Vec<DhcpNetid>,

    #[cfg(feature = "dhcp6")]
    pub start6:       Ipv6Addr,
    #[cfg(feature = "dhcp6")]
    pub end6:         Ipv6Addr,
    #[cfg(feature = "dhcp6")]
    pub local6:       Ipv6Addr,
    #[cfg(feature = "dhcp6")]
    pub prefix:       i32,
    #[cfg(feature = "dhcp6")]
    pub if_index:     i32,
    #[cfg(feature = "dhcp6")]
    pub valid:        u32,
    #[cfg(feature = "dhcp6")]
    pub preferred:    u32,
    /// `context->ra_time` (dnsmasq.h) — unix-epoch seconds of the next RA due
    /// on this context, or `0` when no RA is currently scheduled.
    #[cfg(feature = "dhcp6")]
    pub ra_time:      u64,
    /// `context->ra_short_period_start` — start of the "resend frequently"
    /// window used by `new_timeout()` (radv.c:973-984).
    #[cfg(feature = "dhcp6")]
    pub ra_short_period_start: u64,
    /// `context->saved_valid` — valid lifetime captured by `add_prefixes()`
    /// for use once the context becomes `CONTEXT_OLD` (radv.c:625).
    #[cfg(feature = "dhcp6")]
    pub saved_valid:  u32,
    /// `context->address_lost_time` — when a `CONTEXT_OLD` context's address
    /// disappeared, used to compute the shrinking valid lifetime it's still
    /// advertised with (radv.c:334-346).
    #[cfg(feature = "dhcp6")]
    pub address_lost_time: u64,
}

/// Static DHCP host configuration entry.
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    pub flags:      ConfigFlags,
    pub clid:       Option<Vec<u8>>,
    pub hostname:   Option<String>,
    pub domain:     Option<String>,
    pub netid:      Vec<DhcpNetid>,
    pub filter:     Vec<DhcpNetid>,
    pub addr:       Ipv4Addr,
    pub decline_time: Option<SystemTime>,
    pub lease_time: u32,
    pub hwaddrs:    Vec<HwaddrConfig>,
    #[cfg(feature = "dhcp6")]
    pub addr6:      Vec<crate::types::dns_records::Addrlist>,
}

/// Hardware address entry for static config.
#[derive(Debug, Clone)]
pub struct HwaddrConfig {
    pub hwaddr:       [u8; DHCP_CHADDR_MAX],
    pub hwaddr_len:   i32,
    pub hwaddr_type:  i32,
    pub wildcard_mask: u32,
}

/// DHCP option entry.
#[derive(Debug, Clone)]
pub struct DhcpOpt {
    pub opt:   i32,
    pub flags: DhOptFlags,
    pub val:   Option<Vec<u8>>,
    pub netid: Vec<DhcpNetid>,
    pub encap: i32,
    pub vendor_class: Option<Vec<u8>>,
}

/// DHCP boot entry (PXE / BOOTP).
#[derive(Debug, Clone)]
pub struct DhcpBoot {
    pub file:       Option<String>,
    pub sname:      Option<String>,
    pub tftp_sname: Option<String>,
    pub next_server: Ipv4Addr,
    pub netid:       Vec<DhcpNetid>,
}

/// DHCP classifier rule that assigns a tag when the vendor-class option matches.
#[derive(Debug, Clone)]
pub struct DhcpVendorRule {
    pub netid:        DhcpNetid,
    pub vendor_class: Vec<u8>,
}

/// DHCP classifier rule that assigns a tag when the user-class option matches.
#[derive(Debug, Clone)]
pub struct DhcpUserClassRule {
    pub netid:      DhcpNetid,
    pub user_class: Vec<u8>,
}

/// DHCP classifier rule that assigns a tag when the client MAC address matches.
#[derive(Debug, Clone)]
pub struct DhcpMacRule {
    pub netid:         DhcpNetid,
    pub hwaddr:        [u8; DHCP_CHADDR_MAX],
    pub hwaddr_len:    i32,
    pub hwaddr_type:   i32,
    pub wildcard_mask: u32,
}

/// DHCP relay-agent classifier rule keyed by an option-82 suboption payload.
#[derive(Debug, Clone)]
pub struct DhcpRelayIdRule {
    pub netid:   DhcpNetid,
    pub subopt:  u8,
    pub data:    Vec<u8>,
}

/// Client-hostname classifier rule assigning a tag on exact or prefix match.
///
/// Mirrors `struct dhcp_match_name` (`dnsmasq.h`), populated by `--dhcp-name-match`.
#[derive(Debug, Clone)]
pub struct DhcpMatchName {
    pub netid:    DhcpNetid,
    pub name:     String,
    pub wildcard: bool,
}

/// Delay policy for DHCP replies, optionally scoped to a matching tag.
#[derive(Debug, Clone)]
pub struct DhcpReplyDelay {
    pub delay_secs: u32,
    pub filter:     Vec<DhcpNetid>,
}

/// Router Advertisement interface parameters.
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone)]
pub struct RaInterface {
    pub name:     String,
    pub mtu_name: Option<String>,
    pub interval: i32,
    pub lifetime: i32,
    pub prio:     i32,
    pub mtu:      i32,
}

/// DHCP relay entry.
#[derive(Debug, Clone)]
pub struct DhcpRelay {
    pub local_addr:  AllAddr,
    pub server_addr: AllAddr,
    pub uplink_addr: AllAddr,
    pub interface:   Option<String>,
    pub iface_index: i32,
    pub port:        i32,
    pub split_mode:  i32,
    pub warned:      i32,
    pub matchcount:  i32,
}

/// One directive invocation's tag list, from `dhcp-ignore`, `dhcp-broadcast`,
/// `bootp-dynamic`, `dhcp-generate-names`, or `dhcp-ignore-names`
/// (`struct dhcp_netid_list`, `dnsmasq.h:898-901`). Each repetition of the
/// directive contributes one entry; a client matches an entry when every tag
/// in `list` is present in its derived tags (`match_netid()`,
/// `dhcp-common.c:224-248` — conjunction within an entry, disjunction across
/// entries).
#[derive(Debug, Clone, Default)]
pub struct DhcpNetidList {
    pub list: Vec<DhcpNetid>,
}

/// A PXE client-vendor string to accept in place of the default
/// `"PXEClient"` (`struct dhcp_pxe_vendor`, `dnsmasq.h:1022-1025`), from
/// `--dhcp-pxe-vendor`.
#[derive(Debug, Clone)]
pub struct DhcpPxeVendor {
    pub data: String,
}

/// A PXE boot menu entry (`struct pxe_service`, `dnsmasq.h:997-1003`), from
/// `--pxe-service`.
#[derive(Debug, Clone)]
pub struct PxeService {
    /// Client System Architecture index (`CSA`).
    pub csa:      u16,
    /// `0` = local boot; otherwise a boot-service type, either a literal
    /// numeric type or an auto-assigned type (starting at 32768) when a
    /// `basename` is given instead.
    pub boot_type: u16,
    pub menu:     String,
    pub basename: Option<String>,
    pub sname:    Option<String>,
    pub server:   Ipv4Addr,
    pub netid:    Vec<DhcpNetid>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_flags_non_overlapping() {
        assert_ne!(ContextFlags::STATIC, ContextFlags::NETMASK);
        assert_ne!(ContextFlags::DHCP, ContextFlags::V6);
    }

    #[test]
    fn dhcp_netid_equality() {
        let a = DhcpNetid { net: "tag1".into() };
        let b = DhcpNetid { net: "tag1".into() };
        assert_eq!(a, b);
    }
}

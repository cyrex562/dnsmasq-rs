/// DHCP configuration types.
/// Ported from `struct dhcp_lease`, `struct dhcp_context`, `struct dhcp_config`,
/// `struct dhcp_opt`, and related DHCP types in `dnsmasq.h`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;
use crate::dhcp_protocol::DHCP_CHADDR_MAX;
use crate::types::addr::AllAddr;

// CONFIG_* flags for dhcp_config
pub const CONFIG_DISABLE:       u32 = 1;
pub const CONFIG_CLID:          u32 = 2;
pub const CONFIG_TIME:          u32 = 8;
pub const CONFIG_NAME:          u32 = 16;
pub const CONFIG_ADDR:          u32 = 32;
pub const CONFIG_NOCLID:        u32 = 128;
pub const CONFIG_FROM_ETHERS:   u32 = 256;
pub const CONFIG_ADDR_HOSTS:    u32 = 512;
pub const CONFIG_DECLINED:      u32 = 1024;
pub const CONFIG_BANK:          u32 = 2048;
pub const CONFIG_ADDR6:         u32 = 4096;
pub const CONFIG_ADDR6_HOSTS:   u32 = 16384;

// DHOPT_* flags for dhcp_opt
pub const DHOPT_ADDR:            u32 = 1;
pub const DHOPT_STRING:          u32 = 2;
pub const DHOPT_ENCAPSULATE:     u32 = 4;
pub const DHOPT_ENCAP_MATCH:     u32 = 8;
pub const DHOPT_FORCE:           u32 = 16;
pub const DHOPT_BANK:            u32 = 32;
pub const DHOPT_ENCAP_DONE:      u32 = 64;
pub const DHOPT_MATCH:           u32 = 128;
pub const DHOPT_VENDOR:          u32 = 256;
pub const DHOPT_HEX:             u32 = 512;
pub const DHOPT_VENDOR_MATCH:    u32 = 1024;
pub const DHOPT_RFC3925:         u32 = 2048;
pub const DHOPT_TAGOK:           u32 = 4096;
pub const DHOPT_ADDR6:           u32 = 8192;
pub const DHOPT_VENDOR_PXE:      u32 = 16384;
pub const DHOPT_PXE_OPT:         u32 = 32768;

// CONTEXT_* flags
pub const CONTEXT_STATIC:        u32 = 1 << 0;
pub const CONTEXT_NETMASK:       u32 = 1 << 1;
pub const CONTEXT_BRDCAST:       u32 = 1 << 2;
pub const CONTEXT_PROXY:         u32 = 1 << 3;
pub const CONTEXT_RA_ROUTER:     u32 = 1 << 4;
pub const CONTEXT_RA_DONE:       u32 = 1 << 5;
pub const CONTEXT_RA_NAME:       u32 = 1 << 6;
pub const CONTEXT_RA_STATELESS:  u32 = 1 << 7;
pub const CONTEXT_DHCP:          u32 = 1 << 8;
pub const CONTEXT_DEPRECATE:     u32 = 1 << 9;
pub const CONTEXT_TEMPLATE:      u32 = 1 << 10;
pub const CONTEXT_CONSTRUCTED:   u32 = 1 << 11;
pub const CONTEXT_GC:            u32 = 1 << 12;
pub const CONTEXT_RA:            u32 = 1 << 13;
pub const CONTEXT_CONF_USED:     u32 = 1 << 14;
pub const CONTEXT_USED:          u32 = 1 << 15;
pub const CONTEXT_OLD:           u32 = 1 << 16;
pub const CONTEXT_V6:            u32 = 1 << 17;
pub const CONTEXT_RA_OFF_LINK:   u32 = 1 << 18;
pub const CONTEXT_SETLEASE:      u32 = 1 << 19;

// LEASE_* flags
pub const LEASE_NEW:          u32 = 1;
pub const LEASE_CHANGED:      u32 = 2;
pub const LEASE_AUX_CHANGED:  u32 = 4;
pub const LEASE_AUTH_NAME:    u32 = 8;
pub const LEASE_USED:         u32 = 16;
pub const LEASE_NA:           u32 = 32;
pub const LEASE_TA:           u32 = 64;
pub const LEASE_HAVE_HWADDR:  u32 = 128;
pub const LEASE_EXP_CHANGED:  u32 = 256;

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
    pub flags:      u32,
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
    pub flags:      u32,
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
}

/// Static DHCP host configuration entry.
#[derive(Debug, Clone)]
pub struct DhcpConfig {
    pub flags:      u32,
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
    pub flags: u32,
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
        assert_ne!(CONTEXT_STATIC, CONTEXT_NETMASK);
        assert_ne!(CONTEXT_DHCP, CONTEXT_V6);
    }

    #[test]
    fn dhcp_netid_equality() {
        let a = DhcpNetid { net: "tag1".into() };
        let b = DhcpNetid { net: "tag1".into() };
        assert_eq!(a, b);
    }
}

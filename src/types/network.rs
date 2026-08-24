/// Network interface and listener types.
/// Ported from `struct irec`, `struct listener`, `struct iname`, `struct mysubnet`,
/// `struct resolvc`, `struct hostsfile`, and related types in `dnsmasq.h`.

use std::net::{Ipv4Addr, Ipv6Addr};
use crate::types::addr::MySockAddr;

pub const IFACE_TENTATIVE:  u32 = 1;
pub const IFACE_DEPRECATED: u32 = 2;
pub const IFACE_PERMANENT:  u32 = 4;

pub const INAME_USED: u32 = 1;
pub const INAME_4:    u32 = 2;
pub const INAME_6:    u32 = 4;

/// A network interface record (`struct irec`).
#[derive(Debug, Clone)]
pub struct Irec {
    pub addr:           MySockAddr,
    pub netmask:        Option<Ipv4Addr>,  // IPv4 only
    pub tftp_ok:        bool,
    pub dhcp4_ok:       bool,
    pub dhcp6_ok:       bool,
    pub mtu:            i32,
    pub done:           bool,
    pub warned:         bool,
    pub dad:            bool,
    pub dns_auth:       bool,
    pub index:          i32,
    pub multicast_done: bool,
    pub found:          bool,
    pub label:          i32,
    pub name:           Option<String>,
}

/// A listening socket descriptor (`struct listener`).
#[derive(Debug)]
pub struct Listener {
    pub addr:    MySockAddr,
    pub iface:   Option<usize>, // index into interface list
    // Raw file descriptors are represented as i32; in async code these will be
    // wrapped in tokio socket types instead.
    pub fd:      i32,
    pub tcpfd:   i32,
    pub tftpfd:  i32,
    pub used:    bool,
}

/// Interface name / address from the command line (`struct iname`).
#[derive(Debug, Clone)]
pub struct Iname {
    pub name:  Option<String>,
    pub addr:  Option<MySockAddr>,
    pub flags: u32,
}

/// Subnet parameter from the command line (`struct mysubnet`).
#[derive(Debug, Clone)]
pub struct MySubnet {
    pub addr:      MySockAddr,
    pub addr_used: bool,
    pub mask:      i32,
}

/// resolv-file parameter (`struct resolvc`).
#[derive(Debug, Clone)]
pub struct Resolvc {
    pub is_default: bool,
    pub logged:     bool,
    pub mtime:      i64,        // seconds since epoch
    pub ino:        u64,
    pub name:       String,
    #[cfg(feature = "inotify")]
    pub wd:         i32,
    #[cfg(feature = "inotify")]
    pub file:       Option<String>,
}

bitflags::bitflags! {
    /// Hosts/options-file and dynamic-directory flags (upstream `AH_*`
    /// constants in `dnsmasq.h`, used by `struct hostsfile`/`struct dyndir`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct DynDirFlags: u32 {
        const DIR      = 1 << 0;
        const INACTIVE = 1 << 1;
        const WD_DONE  = 1 << 2;
        const HOSTS    = 1 << 3;
        const DHCP_HST = 1 << 4;
        const DHCP_OPT = 1 << 5;
    }
}

/// Hosts/options file parameter (`struct hostsfile`).
#[derive(Debug, Clone)]
pub struct HostsFile {
    pub flags: DynDirFlags,
    pub fname: String,
    pub index: u32,
}

/// Dynamic directory watcher (`struct dyndir`).
#[derive(Debug, Clone)]
pub struct DynDir {
    pub files: Vec<HostsFile>,
    pub flags: DynDirFlags,
    pub dname: String,
    #[cfg(feature = "inotify")]
    pub wd:    i32,
}

/// ipset domain-name → set mapping (`struct ipsets`).
#[derive(Debug, Clone)]
pub struct Ipsets {
    pub sets:   Vec<String>,
    pub domain: String,
}

/// Conntrack allow-list entry.
#[derive(Debug, Clone)]
pub struct Allowlist {
    pub mark:     u32,
    pub mask:     u32,
    pub patterns: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iface_flags_distinct() {
        assert_ne!(IFACE_TENTATIVE, IFACE_DEPRECATED);
        assert_ne!(IFACE_DEPRECATED, IFACE_PERMANENT);
    }

    #[test]
    fn iname_default() {
        let i = Iname { name: None, addr: None, flags: INAME_USED };
        assert_eq!(i.flags, INAME_USED);
    }
}

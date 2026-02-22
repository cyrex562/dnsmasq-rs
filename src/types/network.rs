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

pub const AH_DIR:      u32 = 1;
pub const AH_INACTIVE: u32 = 2;
pub const AH_WD_DONE:  u32 = 4;
pub const AH_HOSTS:    u32 = 8;
pub const AH_DHCP_HST: u32 = 16;
pub const AH_DHCP_OPT: u32 = 32;

/// Hosts/options file parameter (`struct hostsfile`).
#[derive(Debug, Clone)]
pub struct HostsFile {
    pub flags: u32,
    pub fname: String,
    pub index: u32,
}

/// Dynamic directory watcher (`struct dyndir`).
#[derive(Debug, Clone)]
pub struct DynDir {
    pub files: Vec<HostsFile>,
    pub flags: u32,
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

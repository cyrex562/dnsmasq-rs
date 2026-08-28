/// Network interface and listener types.
/// Ported from `struct irec`, `struct listener`, `struct iname`, `struct mysubnet`,
/// `struct resolvc`, `struct hostsfile`, and related types in `dnsmasq.h`.

use std::net::{Ipv4Addr, Ipv6Addr};
use crate::types::addr::MySockAddr;

bitflags::bitflags! {
    /// `struct iname`'s deny-list/family-restriction flags (upstream
    /// `INAME_*` constants in `dnsmasq.h`), used by `Iname`/`AuthInterface`
    /// entries built from `--interface`, `--except-interface`,
    /// `--no-dhcp-interface`, `--auth-server`, and `--enable-tftp`.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct IfaceNameFlags: u32 {
        const USED = 1 << 0;
        const V4   = 1 << 1;
        const V6   = 1 << 2;
    }
}

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
    pub flags: IfaceNameFlags,
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
        /// `--zones-dir` (issue #177; no upstream `AH_*` counterpart).
        const ZONES    = 1 << 6;
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
    fn iname_default() {
        let i = Iname { name: None, addr: None, flags: IfaceNameFlags::USED };
        assert_eq!(i.flags, IfaceNameFlags::USED);
    }
}

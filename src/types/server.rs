/// Upstream server, pending-forward record, and related types.
/// Ported from `struct server`, `struct frec`, `struct serverfd`, `struct randfd`,
/// and related types in `dnsmasq.h`.

use std::time::{Duration, Instant};
use crate::types::addr::MySockAddr;
use crate::types::constants::*;

bitflags::bitflags! {
    /// Upstream-server flags (`struct server`'s `flags`, upstream `SERV_*`
    /// constants in `dnsmasq.h`).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct ServFlags: u16 {
        const USE_RESOLV       = 1 << 0;
        const LITERAL_ADDRESS  = 1 << 1;
        const ALL_ZEROS        = 1 << 2;
        const ADDR4            = 1 << 3;
        const ADDR6            = 1 << 4;
        const HAS_SOURCE       = 1 << 5;
        const FOR_NODOTS       = 1 << 6;
        const WARNED_RECURSIVE = 1 << 7;
        const FROM_DBUS        = 1 << 8;
        const MARK             = 1 << 9;
        const WILDCARD         = 1 << 10;
        const FROM_RESOLV      = 1 << 11;
        const FROM_FILE        = 1 << 12;
        const LOOP             = 1 << 13;
        const DO_DNSSEC        = 1 << 14;
        const GOT_TCP          = 1 << 15;
    }
}

/// An upstream DNS server entry (`struct server`).
#[derive(Debug, Clone)]
pub struct Server {
    pub flags:       ServFlags,
    pub domain:      String,
    pub addr:        MySockAddr,
    pub source_addr: MySockAddr,
    pub interface:   String,
    pub ifindex:     u32,

    // Statistics
    pub queries:          u32,
    pub failed_queries:   u32,
    pub nxdomain_replies: u32,
    pub retrys:           u32,
    pub query_latency:    u32,
    pub mma_latency:      u32,

    pub forwardtime:  Option<Instant>,
    pub forwardcount: i32,

    pub tcpfd:      i32,
    pub serial:     i32,
    pub arrayposn:  i32,
    pub last_server: i32,

    #[cfg(feature = "loop")]
    pub uid: u32,
}

/// A bound/connected server socket (`struct serverfd`).
#[derive(Debug)]
pub struct ServerFd {
    pub fd:          i32,
    pub source_addr: MySockAddr,
    pub interface:   String,
    pub ifindex:     u32,
    pub used:        u32,
    pub preallocated: u32,
}

/// A per-query random UDP socket (`struct randfd`).
#[derive(Debug)]
pub struct RandFd {
    pub fd:       i32,
    pub refcount: u16,
    // Reference to parent server — stored by index in async code
    pub server_idx: Option<usize>,
}

/// Source-address record within a pending forward record.
#[derive(Debug, Clone)]
pub struct FrecSrc {
    pub source:        MySockAddr,
    pub dest:          crate::types::addr::AllAddr,
    pub iface:         u32,
    pub log_id:        u32,
    pub fd:            i32,
    pub orig_id:       u16,
    pub udp_pkt_size:  u16,
}

/// Pending DNS forward record (`struct frec`).
///
/// One `Frec` is created per outstanding upstream query, keyed by `new_id`.
/// When the reply arrives, we match on `new_id` + server fd to locate this frec
/// and send the answer back to the original clients listed in `srcs`.
#[derive(Debug)]
pub struct Frec {
    pub srcs:              Vec<FrecSrc>,
    /// Index into the server list of the server we sent to.
    pub sentto:            Option<usize>,
    pub new_id:            u16,
    pub forwardall:        bool,
    pub flags:             u32,
    pub time:              Instant,
    pub forward_timestamp: u32,
    pub forward_delay:     i32,
    /// Saved copy of the query (for DNSSEC validation).
    pub stash:             Option<Vec<u8>>,

    #[cfg(feature = "dnssec")]
    pub uid:               i32,
    #[cfg(feature = "dnssec")]
    pub class:             i32,
    #[cfg(feature = "dnssec")]
    pub work_counter:      i32,
    #[cfg(feature = "dnssec")]
    pub validate_counter:  i32,
}

/// Rebound-domain entry — prevents rebinding attacks.
///
/// RFC 5735 / RFC 1918 addresses returned for names under one of these domain
/// suffixes are *not* rejected as possible DNS-rebind attacks.  Mirrors
/// dnsmasq's `struct rebind_domain`.  An empty `domain` means "any
/// single-label name".
#[derive(Debug, Clone, Default)]
pub struct RebindDomain {
    pub domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serv_flags_distinct() {
        assert_ne!(ServFlags::USE_RESOLV, ServFlags::LITERAL_ADDRESS);
        assert_ne!(ServFlags::ADDR4, ServFlags::ADDR6);
    }

    #[test]
    fn frec_flags_match_constants() {
        // Verify the FREC_* constants stay in sync with the bit positions.
        assert_eq!(FREC_NOREBIND, 1);
        assert_eq!(FREC_ANSWER, 512);
    }
}

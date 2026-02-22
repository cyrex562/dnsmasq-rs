/// Upstream server, pending-forward record, and related types.
/// Ported from `struct server`, `struct frec`, `struct serverfd`, `struct randfd`,
/// and related types in `dnsmasq.h`.

use std::time::{Duration, Instant};
use crate::types::addr::MySockAddr;
use crate::types::constants::*;

// Server flags (SERV_*)
pub const SERV_USE_RESOLV:        u16 = 1;
pub const SERV_LITERAL_ADDRESS:   u16 = 2;
pub const SERV_ALL_ZEROS:         u16 = 4;
pub const SERV_4ADDR:             u16 = 8;
pub const SERV_6ADDR:             u16 = 16;
pub const SERV_HAS_SOURCE:        u16 = 32;
pub const SERV_FOR_NODOTS:        u16 = 64;
pub const SERV_WARNED_RECURSIVE:  u16 = 128;
pub const SERV_FROM_DBUS:         u16 = 256;
pub const SERV_MARK:              u16 = 512;
pub const SERV_WILDCARD:          u16 = 1024;
pub const SERV_FROM_RESOLV:       u16 = 2048;
pub const SERV_FROM_FILE:         u16 = 4096;
pub const SERV_LOOP:              u16 = 8192;
pub const SERV_DO_DNSSEC:         u16 = 16384;
pub const SERV_GOT_TCP:           u16 = 32768;

/// An upstream DNS server entry (`struct server`).
#[derive(Debug, Clone)]
pub struct Server {
    pub flags:       u16,
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
#[derive(Debug, Clone)]
pub struct RebindDomain {
    pub domain: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serv_flags_distinct() {
        assert_ne!(SERV_USE_RESOLV, SERV_LITERAL_ADDRESS);
        assert_ne!(SERV_4ADDR, SERV_6ADDR);
    }

    #[test]
    fn frec_flags_match_constants() {
        // Verify the FREC_* constants stay in sync with the bit positions.
        assert_eq!(FREC_NOREBIND, 1);
        assert_eq!(FREC_ANSWER, 512);
    }
}

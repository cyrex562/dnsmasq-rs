/// DNS cache record types.
/// Ported from `struct crec`, `union bigname`, and `struct blockdata` in `dnsmasq.h`.

use std::time::Instant;
use crate::types::addr::AllAddr;
use crate::dns_protocol::MAXDNAME;

pub const SMALLDNAME: usize = 25;

/// A single DNS cache entry, equivalent to `struct crec`.
///
/// In the C code, `crec` uses intrusive linked lists and a union for the name
/// (either inline for short names or via a `bigname` pointer).  Here we use
/// `String` and `Box<Crec>` / `Option` for safety and simplicity; the LRU and
/// hash-table bookkeeping is handled by the cache module.
#[derive(Debug, Clone)]
pub struct Crec {
    /// The domain name this record is keyed on.
    pub name:  String,
    /// The record data (address, CNAME pointer, DNSKEY, etc.)
    pub addr:  Option<AllAddr>,
    /// Time at which this record expires (`ttd` = time-to-die).
    pub ttd:   Option<Instant>,
    /// Class / key-index / hosts-file source index.
    pub uid:   u32,
    /// Bitmask of F_* flags.
    pub flags: u32,
}

impl Crec {
    pub fn new(name: impl Into<String>, flags: u32) -> Self {
        Self {
            name: name.into(),
            addr: None,
            ttd: None,
            uid: 0,
            flags,
        }
    }

    pub fn is_expired(&self) -> bool {
        match self.ttd {
            Some(t) => Instant::now() > t,
            None    => false, // immortal
        }
    }

    pub fn is_immortal(&self) -> bool {
        use crate::types::constants::F_IMMORTAL;
        self.flags & F_IMMORTAL != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::constants::F_IMMORTAL;

    #[test]
    fn crec_immortal_flag() {
        let c = Crec::new("example.com", F_IMMORTAL);
        assert!(c.is_immortal());
        assert!(!c.is_expired());
    }

    #[test]
    fn crec_not_expired_when_no_ttd() {
        let c = Crec::new("example.com", 0);
        assert!(!c.is_expired());
    }
}

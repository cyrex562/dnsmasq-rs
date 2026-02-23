//! ARP record cache.
//! Full port of `arp.c` (240 lines).
//!
//! The cache stores ARP/ND entries (IP → MAC) with a state machine that
//! mirrors dnsmasq's C implementation:
//!
//! * `New`   — just discovered; script not yet notified.
//! * `Found` — confirmed by kernel; script has been notified.
//! * `Mark`  — was `Found`/`Empty`; awaiting re-confirmation in this refresh cycle.
//! * `Empty` — negative cache entry: address seen but no MAC available.
//!
//! The kernel-enumeration glue (`iface_enumerate`) is left to the caller;
//! `ArpCache::filter_mac` is the callback that integrates kernel results.

use std::collections::VecDeque;
use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum hardware-address length (mirrors `DHCP_CHADDR_MAX` in dnsmasq.h).
pub const DHCP_CHADDR_MAX: usize = 16;

/// Seconds between forced re-loads from the kernel (mirrors `INTERVAL` in C).
pub const REFRESH_INTERVAL: u64 = 90;

// ---------------------------------------------------------------------------
// ArpStatus
// ---------------------------------------------------------------------------

/// State of an ARP cache entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpStatus {
    /// `ARP_MARK` — was confirmed; awaiting re-verification in the current refresh.
    Mark,
    /// `ARP_FOUND` — confirmed positive entry (script notified).
    Found,
    /// `ARP_NEW` — newly created; script has not been notified yet.
    New,
    /// `ARP_EMPTY` — negative entry: address seen but MAC was unavailable.
    Empty,
}

// ---------------------------------------------------------------------------
// ArpRecord
// ---------------------------------------------------------------------------

/// A single ARP / Neighbour Discovery record.
///
/// Equivalent to `struct arp_record` in C.
#[derive(Debug, Clone)]
pub struct ArpRecord {
    pub status: ArpStatus,
    /// Hardware address bytes (length in `hwaddr.len()`; capped at `DHCP_CHADDR_MAX`).
    pub hwaddr: Vec<u8>,
    /// IP address (v4 or v6).
    pub addr: IpAddr,
}

// ---------------------------------------------------------------------------
// ArpAction — returned by do_arp_script_run
// ---------------------------------------------------------------------------

/// An event to pass to an external ARP-change script.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArpAction {
    /// A new or updated ARP entry was found.
    Add { addr: IpAddr, hwaddr: Vec<u8> },
    /// An ARP entry was removed.
    Del { addr: IpAddr, hwaddr: Vec<u8> },
}

// ---------------------------------------------------------------------------
// ArpCache
// ---------------------------------------------------------------------------

/// In-memory ARP cache with a kernel-refresh state machine.
///
/// Mirrors the three linked-lists in the C (`arps`, `old`, `freelist`)
/// using two `Vec`s (active, old).
pub struct ArpCache {
    /// Active ARP entries (`arps` in C).
    active: Vec<ArpRecord>,
    /// Entries that have been evicted and are pending script notification (`old` in C).
    old: VecDeque<ArpRecord>,
    /// Time of the last successful kernel refresh (seconds since some epoch).
    pub last_refresh: u64,
}

impl ArpCache {
    pub fn new() -> Self {
        ArpCache {
            active: Vec::new(),
            old: VecDeque::new(),
            last_refresh: 0,
        }
    }

    /// Returns `true` if the cache is stale and needs a kernel refresh.
    pub fn is_stale(&self, now: u64) -> bool {
        now.saturating_sub(self.last_refresh) >= REFRESH_INTERVAL
    }

    // ── Refresh cycle ────────────────────────────────────────────────────────

    /// Begin a refresh cycle.
    ///
    /// Marks all positive (`Found`) entries as `Mark` so that any entry not
    /// confirmed by `filter_mac` during this cycle will be expired.
    /// Equivalent to the marking loop before `iface_enumerate` in C.
    pub fn begin_refresh(&mut self, now: u64) {
        self.last_refresh = now;
        for r in &mut self.active {
            if r.status != ArpStatus::Empty {
                r.status = ArpStatus::Mark;
            }
        }
    }

    /// Process one ARP entry returned by the kernel.
    ///
    /// This is the `filter_mac` callback in C; call it once per kernel entry
    /// during a refresh cycle (between `begin_refresh` and `finish_refresh`).
    ///
    /// Returns `false` if the hardware address is too long.
    pub fn filter_mac(&mut self, addr: IpAddr, hwaddr: &[u8]) -> bool {
        if hwaddr.len() > DHCP_CHADDR_MAX {
            return false;
        }

        for r in &mut self.active {
            if r.addr != addr || r.status == ArpStatus::New {
                continue;
            }

            if r.status == ArpStatus::Empty {
                // Was a negative entry; now we have a MAC.
                r.status = ArpStatus::New;
                r.hwaddr = hwaddr.to_vec();
                return true;
            }

            if r.hwaddr == hwaddr {
                // Same MAC: confirm the existing entry.
                r.status = ArpStatus::Found;
                return true;
            }

            // MAC changed — fall through to add as a new entry.
        }

        // New entry: add to active list.
        self.active.push(ArpRecord {
            status: ArpStatus::New,
            hwaddr: hwaddr.to_vec(),
            addr,
        });
        true
    }

    /// End a refresh cycle.
    ///
    /// Moves any still-`Mark` entries (not re-confirmed by kernel) to the
    /// expired `old` queue.  Equivalent to the post-`iface_enumerate` cleanup in C.
    pub fn finish_refresh(&mut self) {
        let mut still_active = Vec::with_capacity(self.active.len());
        for r in self.active.drain(..) {
            if r.status == ArpStatus::Mark {
                self.old.push_back(r);
            } else {
                still_active.push(r);
            }
        }
        self.active = still_active;
    }

    // ── Lookup ───────────────────────────────────────────────────────────────

    /// Look up the MAC for `addr` in the current in-memory cache.
    ///
    /// * `lazy` — if `true`, return `Empty` (negative) entries too.
    ///
    /// Returns the hardware-address bytes, or `None` if not found or the
    /// entry is negative (and `lazy` is `false`).
    ///
    /// Equivalent to the first half of `find_mac` in C (the in-cache path).
    pub fn find_mac_cached(&self, addr: IpAddr, lazy: bool) -> Option<&[u8]> {
        for r in &self.active {
            if r.addr != addr {
                continue;
            }
            // Accept positive entries, or negative ones if in lazy mode.
            if r.status != ArpStatus::Empty || lazy {
                if !r.hwaddr.is_empty() {
                    return Some(&r.hwaddr);
                }
            }
        }
        None
    }

    /// Add a negative (no-MAC) entry for `addr`.
    ///
    /// Called when a kernel lookup fails so the same address is not
    /// queried again until the cache expires.
    /// Equivalent to the failure path at the end of `find_mac` in C.
    pub fn add_empty(&mut self, addr: IpAddr) {
        // Don't add a duplicate.
        if self.active.iter().any(|r| r.addr == addr) {
            return;
        }
        self.active.push(ArpRecord {
            status: ArpStatus::Empty,
            hwaddr: Vec::new(),
            addr,
        });
    }

    // ── Script notification ───────────────────────────────────────────────────

    /// Drain one pending ARP event.
    ///
    /// Processes the `old` queue first (deletions), then scans for `New`
    /// entries (additions).  Call repeatedly until `None` to flush all events.
    ///
    /// Mirrors `do_arp_script_run` in C.
    pub fn do_arp_script_run(&mut self) -> Option<ArpAction> {
        // Deletions take priority.
        if let Some(old) = self.old.pop_front() {
            return Some(ArpAction::Del {
                addr: old.addr,
                hwaddr: old.hwaddr,
            });
        }

        // Then additions.
        for r in &mut self.active {
            if r.status == ArpStatus::New {
                let action = ArpAction::Add {
                    addr: r.addr,
                    hwaddr: r.hwaddr.clone(),
                };
                r.status = ArpStatus::Found;
                return Some(action);
            }
        }

        None
    }

    // ── Utilities ─────────────────────────────────────────────────────────────

    /// Number of active entries.
    pub fn len(&self) -> usize {
        self.active.len()
    }

    /// `true` if there are no active entries.
    pub fn is_empty(&self) -> bool {
        self.active.is_empty()
    }

    /// Number of entries pending script notification (deletions).
    pub fn old_len(&self) -> usize {
        self.old.len()
    }
}

impl Default for ArpCache {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const MAC1: &[u8] = &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
    const MAC2: &[u8] = &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(a, b, c, d))
    }
    fn v6(a: u16, b: u16) -> IpAddr {
        IpAddr::V6(Ipv6Addr::new(a, b, 0, 0, 0, 0, 0, 1))
    }

    // ── filter_mac / find_mac_cached ─────────────────────────────────────────

    #[test]
    fn filter_and_find_ipv4() {
        let mut cache = ArpCache::new();
        cache.begin_refresh(0);
        cache.filter_mac(v4(192, 168, 1, 1), MAC1);
        cache.finish_refresh();

        assert_eq!(cache.find_mac_cached(v4(192, 168, 1, 1), false), Some(MAC1));
    }

    #[test]
    fn filter_and_find_ipv6() {
        let mut cache = ArpCache::new();
        cache.begin_refresh(0);
        cache.filter_mac(v6(0x2001, 0xdb8), MAC1);
        cache.finish_refresh();

        assert_eq!(
            cache.find_mac_cached(v6(0x2001, 0xdb8), false),
            Some(MAC1)
        );
    }

    #[test]
    fn miss_returns_none() {
        let cache = ArpCache::new();
        assert_eq!(cache.find_mac_cached(v4(1, 1, 1, 1), false), None);
    }

    // ── Mark / confirm cycle ──────────────────────────────────────────────────

    #[test]
    fn unconfirmed_entry_moved_to_old() {
        let mut cache = ArpCache::new();
        // First refresh: adds entry.
        cache.begin_refresh(0);
        cache.filter_mac(v4(10, 0, 0, 1), MAC1);
        cache.finish_refresh();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.old_len(), 0);

        // Second refresh: entry NOT seen → should expire to old.
        cache.begin_refresh(REFRESH_INTERVAL);
        // (no filter_mac calls)
        cache.finish_refresh();

        assert_eq!(cache.len(), 0);
        assert_eq!(cache.old_len(), 1);
    }

    #[test]
    fn confirmed_entry_stays_active() {
        let mut cache = ArpCache::new();
        cache.begin_refresh(0);
        cache.filter_mac(v4(10, 0, 0, 1), MAC1);
        cache.finish_refresh();

        // Second refresh: re-confirm same entry.
        cache.begin_refresh(REFRESH_INTERVAL);
        cache.filter_mac(v4(10, 0, 0, 1), MAC1);
        cache.finish_refresh();

        assert_eq!(cache.len(), 1);
        assert_eq!(cache.old_len(), 0);
    }

    // ── MAC change ────────────────────────────────────────────────────────────

    #[test]
    fn changed_mac_adds_new_entry() {
        let mut cache = ArpCache::new();
        cache.begin_refresh(0);
        cache.filter_mac(v4(10, 0, 0, 2), MAC1);
        cache.finish_refresh();

        // Refresh with a different MAC for the same IP → old entry expires,
        // new entry added.
        cache.begin_refresh(REFRESH_INTERVAL);
        cache.filter_mac(v4(10, 0, 0, 2), MAC2);
        cache.finish_refresh();

        // One entry expired to old, one new entry active.
        assert_eq!(cache.old_len(), 1);
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.find_mac_cached(v4(10, 0, 0, 2), false),
            Some(MAC2)
        );
    }

    // ── Negative (empty) entries ──────────────────────────────────────────────

    #[test]
    fn empty_entry_not_returned_without_lazy() {
        let mut cache = ArpCache::new();
        cache.add_empty(v4(192, 168, 0, 1));
        assert_eq!(cache.find_mac_cached(v4(192, 168, 0, 1), false), None);
    }

    #[test]
    fn empty_entry_returned_in_lazy_mode() {
        let mut cache = ArpCache::new();
        cache.add_empty(v4(192, 168, 0, 1));
        // Empty entry has no hwaddr bytes, so still None even in lazy mode.
        assert_eq!(cache.find_mac_cached(v4(192, 168, 0, 1), true), None);
    }

    #[test]
    fn empty_entry_upgraded_on_filter_mac() {
        let mut cache = ArpCache::new();
        cache.add_empty(v4(192, 168, 0, 1));

        cache.begin_refresh(0);
        cache.filter_mac(v4(192, 168, 0, 1), MAC1);
        cache.finish_refresh();

        // Should now be findable.
        assert_eq!(
            cache.find_mac_cached(v4(192, 168, 0, 1), false),
            Some(MAC1)
        );
    }

    // ── do_arp_script_run ─────────────────────────────────────────────────────

    #[test]
    fn script_run_notifies_new_entry() {
        let mut cache = ArpCache::new();
        cache.begin_refresh(0);
        cache.filter_mac(v4(10, 1, 1, 1), MAC1);
        cache.finish_refresh();

        let action = cache.do_arp_script_run();
        assert_eq!(
            action,
            Some(ArpAction::Add {
                addr: v4(10, 1, 1, 1),
                hwaddr: MAC1.to_vec(),
            })
        );
        // Entry is now Found; no more events.
        assert_eq!(cache.do_arp_script_run(), None);
    }

    #[test]
    fn script_run_notifies_deletion_before_addition() {
        let mut cache = ArpCache::new();
        // First cycle: add entry.
        cache.begin_refresh(0);
        cache.filter_mac(v4(10, 1, 1, 1), MAC1);
        cache.finish_refresh();
        cache.do_arp_script_run(); // consume Add event

        // Second cycle: entry disappears → goes to old queue.
        cache.begin_refresh(REFRESH_INTERVAL);
        // No filter_mac
        cache.finish_refresh();

        // Third cycle: new entry appears.
        cache.begin_refresh(REFRESH_INTERVAL * 2);
        cache.filter_mac(v4(10, 1, 1, 2), MAC2);
        cache.finish_refresh();

        // Deletion event comes first.
        let ev1 = cache.do_arp_script_run();
        assert!(matches!(ev1, Some(ArpAction::Del { .. })));

        // Then addition.
        let ev2 = cache.do_arp_script_run();
        assert!(matches!(ev2, Some(ArpAction::Add { .. })));
    }

    // ── is_stale / last_refresh ───────────────────────────────────────────────

    #[test]
    fn stale_check() {
        let cache = ArpCache::new(); // last_refresh = 0
        // At now=REFRESH_INTERVAL, diff = REFRESH_INTERVAL → stale.
        assert!(cache.is_stale(REFRESH_INTERVAL));
        // At now < REFRESH_INTERVAL → not yet stale.
        assert!(!cache.is_stale(REFRESH_INTERVAL - 1));
    }

    #[test]
    fn not_stale_after_refresh() {
        let mut cache = ArpCache::new();
        cache.begin_refresh(1000);
        assert!(!cache.is_stale(1000 + REFRESH_INTERVAL - 1));
        assert!(cache.is_stale(1000 + REFRESH_INTERVAL));
    }

    // ── hwaddr too long ───────────────────────────────────────────────────────

    #[test]
    fn filter_mac_rejects_too_long_hwaddr() {
        let mut cache = ArpCache::new();
        let long_mac = vec![0u8; DHCP_CHADDR_MAX + 1];
        let ok = cache.filter_mac(v4(1, 2, 3, 4), &long_mac);
        assert!(!ok);
        assert!(cache.is_empty());
    }
}

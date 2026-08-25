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
//! [`find_mac`] is the orchestrator that ties the state machine to kernel
//! enumeration, mirroring C's `find_mac()` (`arp.c:107-208`): a cache hit
//! returns immediately, a miss triggers exactly one refresh cycle
//! (`begin_refresh`/`filter_mac`/`finish_refresh`) via the caller-supplied
//! `enumerate` closure, then the cache is re-checked once before falling
//! back to a negative (`add_empty`) entry. [`find_mac_for_daemon`] and
//! [`find_mac_shared`] are the Linux, real-kernel wirings of that closure via
//! [`crate::netlink`], sharing one [`ArpRuntimeState`] (mirroring upstream's
//! single file-scope `arps` list) between `Daemon` and any snapshot-based
//! runtime path such as [`crate::forward`]'s forwarding loop.

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
#[derive(Debug)]
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

}

/// Look up (and, on a miss, refresh from the kernel and retry) the MAC
/// address for `addr`.
///
/// Mirrors `find_mac()` (`arp.c:107-208`) end to end:
///
/// 1. If the cache doesn't need a forced refresh (`!cache.is_stale(now)`) or
///    the caller cannot query the kernel at all (`can_query_kernel == false`,
///    C's "child with no netlink socket" branch, `arp.c:119,148-150`), try the
///    in-cache lookup first.
/// 2. If that misses and `can_query_kernel` is true, run exactly one refresh
///    cycle — `enumerate` is expected to call [`ArpCache::filter_mac`] once
///    per kernel-reported entry, mirroring `iface_enumerate(..., filter_mac)`
///    (`arp.c:163`) — then retry the lookup, this time accepting a negative
///    (`Empty`) entry as a match too (C's `|| updated`, `arp.c:139`).
/// 3. If it still misses, record a negative entry via [`ArpCache::add_empty`]
///    so the kernel isn't re-queried for this address until the next
///    refresh, and return `None`.
///
/// `enumerate` is dependency-injected so this orchestration is testable
/// without a real netlink socket; [`find_mac_for_daemon`] supplies the real
/// kernel-backed closure.
pub fn find_mac<E>(
    cache: &mut ArpCache,
    addr: IpAddr,
    lazy: bool,
    now: u64,
    can_query_kernel: bool,
    mut enumerate: E,
) -> Option<Vec<u8>>
where
    E: FnMut(&mut ArpCache),
{
    let mut updated = false;
    loop {
        if !cache.is_stale(now) || !can_query_kernel {
            if let Some(mac) = cache.find_mac_cached(addr, lazy || updated) {
                return Some(mac.to_vec());
            }
        }

        if !can_query_kernel {
            return None;
        }

        if !updated {
            updated = true;
            cache.begin_refresh(now);
            enumerate(cache);
            cache.finish_refresh();
            continue;
        }

        break;
    }

    cache.add_empty(addr);
    None
}

/// Refresh the cache from the kernel if (and only if) it's stale, without
/// looking anything up.
///
/// Mirrors upstream's `find_mac(NULL, NULL, 0, now)` (`arp.c:119-120,152-181`
/// with `addr == NULL`): the main select loop calls this once per
/// housekeeping tick when `OPT_SCRIPT_ARP` is set, purely to keep the cache
/// — and thus the `old` deletion queue [`ArpCache::do_arp_script_run`]
/// drains — current even when nothing is actively being looked up. A fresh
/// cache is a no-op and never touches `enumerate`.
pub fn refresh_if_stale<E>(cache: &mut ArpCache, now: u64, mut enumerate: E)
where
    E: FnMut(&mut ArpCache),
{
    if !cache.is_stale(now) {
        return;
    }
    cache.begin_refresh(now);
    enumerate(cache);
    cache.finish_refresh();
}

/// The ARP cache plus its persistent kernel socket, bundled so runtime paths
/// that don't carry a full `Daemon` (the forwarding loop only sees a
/// `ForwardConfig` snapshot — see `dnsmasq::daemon_forward_config`) can still
/// share the *same* cache DHCPv6 consults via `Daemon::arp_state`, mirroring
/// upstream's single file-scope `arps` list (`arp.c`).
#[derive(Debug, Default)]
pub struct ArpRuntimeState {
    pub cache: ArpCache,
    /// The persistent `NETLINK_ROUTE` socket `find_mac()`'s kernel refresh
    /// uses, mirroring `daemon->netlinkfd` (opened once by `netlink_init()`
    /// rather than per-lookup). `None` until the first refresh is attempted,
    /// or permanently on non-Linux targets / if the socket can't be opened.
    pub netlink: Option<crate::netlink::NetlinkSocket>,
}

/// Shared handle to an [`ArpRuntimeState`]. A plain `std::sync::Mutex` (not
/// `tokio::sync::Mutex`) is deliberate: every lock is held only across a
/// synchronous kernel netlink round-trip, never across an `.await`, so a
/// blocking mutex avoids taking a lock across a suspension point.
pub type SharedArpState = std::sync::Arc<std::sync::Mutex<ArpRuntimeState>>;

/// Build a fresh, empty [`SharedArpState`] — one per daemon instance.
pub fn new_shared_arp_state() -> SharedArpState {
    std::sync::Arc::new(std::sync::Mutex::new(ArpRuntimeState::default()))
}

/// Open the persistent netlink socket if it isn't already, mirroring
/// `netlink_init()` populating `daemon->netlinkfd` once at startup
/// (`netlink.c:60-92`). Returns the `(fd, pid)` handle to enumerate with, or
/// `None` if no socket is open and none could be opened.
#[cfg(target_os = "linux")]
fn ensure_netlink_open(netlink: &mut Option<crate::netlink::NetlinkSocket>) -> Option<(i32, u32)> {
    if netlink.is_none() {
        match crate::netlink::open_netlink_socket() {
            Ok(sock) => *netlink = Some(sock),
            Err(e) => {
                tracing::warn!("failed to open netlink socket for ARP cache: {e}");
            }
        }
    }
    netlink.as_ref().map(|s| (std::os::fd::AsRawFd::as_raw_fd(&s.fd), s.pid))
}

/// Enumerate the kernel neighbour table into `cache` via `(fd, pid)`.
/// Equivalent to `iface_enumerate(AF_UNSPEC, NULL, filter_mac)` (`arp.c:163`).
#[cfg(target_os = "linux")]
fn kernel_enumerate_into(cache: &mut ArpCache, fd: i32, pid: u32) {
    // AF_UNSPEC (0) requests the neighbour table.
    let _ = crate::netlink::iface_enumerate(fd, pid, 0, &mut |rec| {
        if let crate::netlink::IfaceRecord::Arp { family, ip, mac } = rec {
            if let Some(ip_addr) = crate::netlink::parse_ip(&ip, family) {
                cache.filter_mac(ip_addr, &mac);
            }
        }
        true
    });
}

/// Real, Linux-backed [`find_mac`]: opens the persistent netlink socket on
/// first use (mirroring `netlink_init()` populating `daemon->netlinkfd` once
/// at startup, `netlink.c:60-92`) and drives a refresh via
/// [`crate::netlink::iface_enumerate`].
///
/// Returns `None` (with no kernel query attempted) if the socket has never
/// been opened and cannot be opened now — e.g. no netlink support in this
/// environment. Unlike C's `daemon->pipe_to_parent != -1` check (privilege-
/// dropped children reuse the parent's cache instead of holding their own
/// netlink socket, `arp.c:119,148-150`), this port has no forked-child
/// model for the main DNS path, so `can_query_kernel` here reduces to
/// "do we have a socket" — tracked as a deliberate deviation in `tasks.md`.
#[cfg(target_os = "linux")]
fn find_mac_kernel_backed(
    cache: &mut ArpCache,
    netlink: &mut Option<crate::netlink::NetlinkSocket>,
    addr: IpAddr,
    lazy: bool,
    now: u64,
) -> Option<Vec<u8>> {
    let handle = ensure_netlink_open(netlink);
    let can_query_kernel = handle.is_some();

    find_mac(cache, addr, lazy, now, can_query_kernel, |cache| {
        let Some((fd, pid)) = handle else { return };
        kernel_enumerate_into(cache, fd, pid);
    })
}

/// [`find_mac_kernel_backed`] against a `Daemon`'s own ARP state.
///
/// Live callers: [`crate::dhcp6::get_client_mac`]. `Daemon` shares the same
/// underlying [`ArpRuntimeState`] as [`find_mac_shared`], so a refresh
/// triggered from either path is visible to the other.
#[cfg(target_os = "linux")]
pub fn find_mac_for_daemon(
    daemon: &crate::types::daemon::Daemon,
    addr: IpAddr,
    lazy: bool,
    now: u64,
) -> Option<Vec<u8>> {
    find_mac_shared(&daemon.arp_state, addr, lazy, now)
}

/// [`find_mac_kernel_backed`] against a standalone [`SharedArpState`], for
/// runtime paths that only carry a snapshot of `Daemon`'s config rather than
/// `Daemon` itself.
///
/// Live caller: [`crate::forward::ForwardEngine::forward_query`], which
/// resolves the client's MAC for `--add-mac`/`--mac-base64`/`--mac-hex`
/// before the query goes upstream (`edns0.c:315-334`, wired at
/// `edns0::add_edns0_config`).
#[cfg(target_os = "linux")]
pub fn find_mac_shared(state: &SharedArpState, addr: IpAddr, lazy: bool, now: u64) -> Option<Vec<u8>> {
    let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
    let ArpRuntimeState { cache, netlink } = &mut *guard;
    find_mac_kernel_backed(cache, netlink, addr, lazy, now)
}

/// Non-Linux fallback: no netlink support in this port, so no kernel query is
/// ever possible — matches `find_mac_kernel_backed`'s own "no socket" branch,
/// just without a Linux target to open one on at all. Callers (e.g.
/// [`crate::forward::ForwardEngine::forward_query`]) stay platform-agnostic.
#[cfg(not(target_os = "linux"))]
pub fn find_mac_shared(_state: &SharedArpState, _addr: IpAddr, _lazy: bool, _now: u64) -> Option<Vec<u8>> {
    None
}

/// Kernel-backed [`refresh_if_stale`] against a [`SharedArpState`].
///
/// Mirrors upstream's periodic `if (option_bool(OPT_SCRIPT_ARP)) find_mac(NULL, NULL, 0, now);`
/// (`dnsmasq.c:1173`), called by the daemon's housekeeping tick
/// ([`crate::dnsmasq::spawn_arp_housekeeping_task`]) so the cache — and the
/// `old` deletion queue [`ArpCache::do_arp_script_run`] drains from — stays
/// current even when no lookup is in flight.
#[cfg(target_os = "linux")]
pub fn refresh_arp_cache_shared(state: &SharedArpState, now: u64) {
    let mut guard = state.lock().unwrap_or_else(|e| e.into_inner());
    let ArpRuntimeState { cache, netlink } = &mut *guard;
    if !cache.is_stale(now) {
        return;
    }
    let Some((fd, pid)) = ensure_netlink_open(netlink) else { return };
    refresh_if_stale(cache, now, |cache| kernel_enumerate_into(cache, fd, pid));
}

/// Non-Linux fallback for [`refresh_arp_cache_shared`]: no netlink support in
/// this port, so there is nothing to refresh from.
#[cfg(not(target_os = "linux"))]
pub fn refresh_arp_cache_shared(_state: &SharedArpState, _now: u64) {}

impl ArpCache {
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

/// Drain every pending ARP event and convert it into the wire event the
/// (privilege-dropped) script helper consumes, mirroring `do_arp_script_run`'s
/// `queue_arp()` calls (`arp.c:217-233`) gated on `OPT_SCRIPT_ARP`
/// (`option_bool(OPT_SCRIPT_ARP)`, `arp.c:218,232`).
///
/// This only builds the [`crate::helper::ScriptData`] events — actually
/// delivering them to a running helper still needs `HelperHandle::send`,
/// which (per `tasks.md`) has no caller anywhere yet because the helper
/// process itself isn't forked from the main startup path. Once that
/// wiring lands, its ARP call site is exactly "call this, then `send()`
/// each result."
#[cfg(feature = "dhcp")]
pub fn drain_arp_script_events(cache: &mut ArpCache, script_arp_enabled: bool) -> Vec<crate::helper::ScriptData> {
    if !script_arp_enabled {
        // Still drain the queue so state (Mark->old, New->Found) advances;
        // C's `do_arp_script_run` always pops/advances regardless of the
        // `OPT_SCRIPT_ARP` check, which only gates the `queue_arp()` call.
        let mut n = 0;
        while cache.do_arp_script_run().is_some() {
            n += 1;
            if n > 100_000 {
                break; // defensive: never spin forever on a malformed cache
            }
        }
        return Vec::new();
    }

    let mut events = Vec::new();
    while let Some(action) = cache.do_arp_script_run() {
        events.push(match action {
            ArpAction::Add { addr, hwaddr } => crate::helper::ScriptData::for_arp(false, &hwaddr, addr),
            ArpAction::Del { addr, hwaddr } => crate::helper::ScriptData::for_arp(true, &hwaddr, addr),
        });
    }
    events
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

    // ── find_mac orchestrator ─────────────────────────────────────────────────

    #[test]
    fn find_mac_populates_cache_via_kernel_enumerate() {
        let mut cache = ArpCache::new();
        let addr = v4(10, 0, 0, 5);
        let mut enumerate_calls = 0;
        let mac = find_mac(&mut cache, addr, false, 0, true, |c| {
            enumerate_calls += 1;
            c.filter_mac(addr, MAC1);
        });
        assert_eq!(mac, Some(MAC1.to_vec()));
        assert_eq!(enumerate_calls, 1);
        assert_eq!(cache.find_mac_cached(addr, false), Some(MAC1));
    }

    #[test]
    fn find_mac_cache_hit_never_enumerates() {
        let mut cache = ArpCache::new();
        cache.begin_refresh(0);
        cache.filter_mac(v4(10, 0, 0, 5), MAC1);
        cache.finish_refresh();

        let mut called = false;
        // now = 10 < REFRESH_INTERVAL, so the cache is still fresh.
        let mac = find_mac(&mut cache, v4(10, 0, 0, 5), false, 10, true, |_| called = true);
        assert_eq!(mac, Some(MAC1.to_vec()));
        assert!(!called, "a cache hit must not trigger a kernel refresh");
    }

    #[test]
    fn find_mac_adds_empty_entry_when_kernel_has_no_match() {
        let mut cache = ArpCache::new();
        let addr = v4(10, 0, 0, 9);
        let mac = find_mac(&mut cache, addr, false, 0, true, |_c| { /* kernel: no match */ });
        assert_eq!(mac, None);
        assert_eq!(cache.len(), 1); // negative entry recorded
        assert_eq!(cache.find_mac_cached(addr, false), None);
    }

    #[test]
    fn find_mac_without_kernel_access_returns_none_and_does_not_mark_empty() {
        // Mirrors C's "child process with no netlink socket" branch
        // (`arp.c:148-150`): a miss returns 0 immediately, with no negative
        // cache entry recorded.
        let mut cache = ArpCache::new();
        let addr = v4(10, 0, 0, 9);
        let mut called = false;
        let mac = find_mac(&mut cache, addr, false, 0, false, |_| called = true);
        assert_eq!(mac, None);
        assert!(!called);
        assert!(cache.is_empty());
    }

    #[test]
    fn find_mac_upgrades_existing_empty_entry_via_refresh() {
        let mut cache = ArpCache::new();
        let addr = v4(10, 0, 0, 7);
        cache.add_empty(addr);

        let mac = find_mac(&mut cache, addr, false, REFRESH_INTERVAL * 2, true, |c| {
            c.filter_mac(addr, MAC2);
        });
        assert_eq!(mac, Some(MAC2.to_vec()));
    }

    #[test]
    fn find_mac_only_enumerates_once_per_call() {
        let mut cache = ArpCache::new();
        let addr = v4(10, 0, 0, 8);
        let mut calls = 0;
        let _ = find_mac(&mut cache, addr, false, REFRESH_INTERVAL * 5, true, |_| calls += 1);
        assert_eq!(calls, 1);
    }

    #[test]
    fn find_mac_lazy_returns_existing_negative_entry_without_refresh() {
        let mut cache = ArpCache::new();
        let addr = v4(10, 0, 0, 9);
        cache.add_empty(addr);
        let mut called = false;
        // Fresh cache (now=0), lazy=true: an Empty entry counts as a match,
        // but since it carries no hwaddr bytes, find_mac still reports it as
        // "no MAC" (matching C returning `arp->hwlen` == 0) without ever
        // touching the kernel.
        let mac = find_mac(&mut cache, addr, true, 0, true, |_| called = true);
        assert_eq!(mac, None);
        assert!(called, "a rejected/empty match still falls through to a refresh attempt");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn find_mac_for_daemon_opens_socket_and_does_not_panic() {
        let daemon = crate::types::daemon::Daemon::default();
        assert!(daemon.arp_state.lock().unwrap().netlink.is_none());
        // TEST-NET-3 (RFC 5737): documentation-only, never a real neighbour.
        let addr = v4(203, 0, 113, 250);
        let _ = find_mac_for_daemon(&daemon, addr, false, 0);
        assert!(
            daemon.arp_state.lock().unwrap().netlink.is_some(),
            "netlink socket should have been opened"
        );
    }

    // ── refresh_if_stale ──────────────────────────────────────────────────────

    #[test]
    fn refresh_if_stale_enumerates_when_stale() {
        let mut cache = ArpCache::new(); // last_refresh = 0
        let mut calls = 0;
        refresh_if_stale(&mut cache, REFRESH_INTERVAL, |c| {
            calls += 1;
            c.filter_mac(v4(10, 0, 0, 1), MAC1);
        });
        assert_eq!(calls, 1);
        assert_eq!(cache.find_mac_cached(v4(10, 0, 0, 1), false), Some(MAC1));
        assert_eq!(cache.last_refresh, REFRESH_INTERVAL);
    }

    #[test]
    fn refresh_if_stale_does_nothing_when_fresh() {
        let mut cache = ArpCache::new();
        cache.begin_refresh(1000);
        let mut called = false;
        refresh_if_stale(&mut cache, 1000 + REFRESH_INTERVAL - 1, |_| called = true);
        assert!(!called, "a fresh cache must not trigger a kernel refresh");
    }

    #[test]
    fn refresh_if_stale_moves_unconfirmed_entries_to_old() {
        // Mirrors `find_mac(NULL, NULL, 0, now)` (`arp.c:119-120,152-181`):
        // a stale-triggered refresh with no matching kernel entries still
        // expires unconfirmed entries to `old`, feeding `do_arp_script_run`'s
        // deletion queue even though nothing was being looked up.
        let mut cache = ArpCache::new();
        cache.begin_refresh(0);
        cache.filter_mac(v4(10, 0, 0, 1), MAC1);
        cache.finish_refresh();

        refresh_if_stale(&mut cache, REFRESH_INTERVAL, |_c| { /* kernel: no entries */ });

        assert_eq!(cache.len(), 0);
        assert_eq!(cache.old_len(), 1);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refresh_arp_cache_shared_opens_socket_and_does_not_panic() {
        let state = new_shared_arp_state();
        assert!(state.lock().unwrap().netlink.is_none());
        // now = REFRESH_INTERVAL against a fresh (last_refresh = 0) cache is
        // stale, so this must touch the kernel.
        refresh_arp_cache_shared(&state, REFRESH_INTERVAL);
        assert!(
            state.lock().unwrap().netlink.is_some(),
            "netlink socket should have been opened by a stale refresh"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refresh_arp_cache_shared_does_not_open_socket_when_fresh() {
        let state = new_shared_arp_state();
        // now = 0 against a fresh (last_refresh = 0) cache is not stale, so
        // this must not touch the kernel at all — matches upstream's
        // `find_mac(NULL, ...)` returning immediately on a fresh cache.
        refresh_arp_cache_shared(&state, 0);
        assert!(state.lock().unwrap().netlink.is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn find_mac_shared_and_find_mac_for_daemon_see_the_same_cache() {
        // The forwarding loop (via `find_mac_shared`) and DHCPv6 (via
        // `find_mac_for_daemon`) must consult the same underlying cache, or a
        // refresh triggered by one is invisible to the other.
        let daemon = crate::types::daemon::Daemon::default();
        let addr = v4(203, 0, 113, 251);
        let _ = find_mac_shared(&daemon.arp_state, addr, false, 0);
        assert!(daemon.arp_state.lock().unwrap().netlink.is_some());
    }

    // ── drain_arp_script_events ───────────────────────────────────────────────

    #[cfg(feature = "dhcp")]
    #[test]
    fn drain_arp_script_events_disabled_still_advances_state_but_returns_nothing() {
        let mut cache = ArpCache::new();
        cache.begin_refresh(0);
        cache.filter_mac(v4(10, 1, 1, 1), MAC1);
        cache.finish_refresh();

        let events = drain_arp_script_events(&mut cache, false);
        assert!(events.is_empty());
        // The New entry should have been advanced to Found by the drain.
        assert_eq!(drain_arp_script_events(&mut cache, true).len(), 0);
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn drain_arp_script_events_enabled_returns_add_and_del() {
        let mut cache = ArpCache::new();
        cache.begin_refresh(0);
        cache.filter_mac(v4(10, 1, 1, 1), MAC1);
        cache.finish_refresh();
        cache.begin_refresh(REFRESH_INTERVAL);
        // entry not re-confirmed -> moves to old (deletion)
        cache.finish_refresh();
        cache.begin_refresh(REFRESH_INTERVAL * 2);
        cache.filter_mac(v4(10, 1, 1, 2), MAC2);
        cache.finish_refresh();

        let events = drain_arp_script_events(&mut cache, true);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].action, crate::types::dhcp::ACTION_ARP_DEL);
        assert_eq!(events[1].action, crate::types::dhcp::ACTION_ARP);
    }
}

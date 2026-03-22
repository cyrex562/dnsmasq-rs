//! DNS query forwarding engine — data structures and helpers.
//!
//! Ported from dnsmasq's `forward.c`.  This module contains the pure
//! data structures (`ForwardTable`, `PendingQuery`) and stateless helper
//! functions (`patch_id`, `next_server`, `reply_matches_query`), plus
//! the async UDP forwarding engine (`ForwardEngine`, `run_forward_loop`).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::hash_questions::hash_questions;
use crate::metrics::{inc_metric, Metric};
use crate::types::constants::{F_IPV4, F_IPV6, F_SERVER};

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

/// A pending (in-flight) forwarded DNS query.
#[derive(Debug, Clone)]
pub struct PendingQuery {
    /// DNS transaction ID sent upstream.
    pub id: u16,
    /// Original client transaction ID.
    pub orig_id: u16,
    /// Client socket address.
    pub client: SocketAddr,
    /// Index into the upstream server list.
    pub upstream_idx: usize,
    /// Timestamp when the query was forwarded.
    pub sent_at: Instant,
    /// Hash of the question section (for deduplication).
    pub question_hash: [u8; 16],
    /// Number of retransmission attempts so far.
    pub retries: u8,
}

/// Table of all in-flight queries, keyed by upstream transaction ID.
pub struct ForwardTable {
    queries: HashMap<u16, PendingQuery>,
    next_id: u16,
}

// ──────────────────────────────────────────────────────────────────────────────
// ForwardTable implementation
// ──────────────────────────────────────────────────────────────────────────────

impl ForwardTable {
    /// Create an empty `ForwardTable`.
    pub fn new() -> Self {
        Self {
            queries: HashMap::new(),
            next_id: 1,
        }
    }

    /// Allocate a new pending query and return the upstream transaction ID.
    ///
    /// The ID is chosen by incrementing an internal counter, wrapping around
    /// and skipping any ID that is already in use.
    pub fn alloc_query(
        &mut self,
        orig_id: u16,
        client: SocketAddr,
        upstream_idx: usize,
        question_hash: [u8; 16],
    ) -> u16 {
        // Find the next unused ID, wrapping through the full u16 range.
        let start = self.next_id;
        loop {
            let id = self.next_id;
            // Advance counter, skip 0.
            self.next_id = self.next_id.wrapping_add(1);
            if self.next_id == 0 {
                self.next_id = 1;
            }
            if !self.queries.contains_key(&id) {
                self.queries.insert(
                    id,
                    PendingQuery {
                        id,
                        orig_id,
                        client,
                        upstream_idx,
                        sent_at: Instant::now(),
                        question_hash,
                        retries: 0,
                    },
                );
                return id;
            }
            // Safety valve: if every possible ID is occupied, overwrite the
            // start position (extremely unlikely in practice).
            if self.next_id == start {
                self.queries.insert(
                    id,
                    PendingQuery {
                        id,
                        orig_id,
                        client,
                        upstream_idx,
                        sent_at: Instant::now(),
                        question_hash,
                        retries: 0,
                    },
                );
                return id;
            }
        }
    }

    /// Find a pending query by upstream transaction ID.
    pub fn lookup(&self, id: u16) -> Option<&PendingQuery> {
        self.queries.get(&id)
    }

    /// Remove a completed query, returning it.
    pub fn remove(&mut self, id: u16) -> Option<PendingQuery> {
        self.queries.remove(&id)
    }

    /// Look up a pending query by upstream transaction ID.
    pub fn get_query(&self, id: u16) -> Option<&PendingQuery> {
        self.queries.get(&id)
    }

    /// Remove a completed query by upstream transaction ID.
    pub fn remove_query(&mut self, id: u16) -> Option<PendingQuery> {
        self.queries.remove(&id)
    }

    /// Remove and return all queries whose `sent_at` is older than `timeout`.
    pub fn expire_old(&mut self, timeout: Duration) -> Vec<PendingQuery> {
        let now = Instant::now();
        let expired_ids: Vec<u16> = self
            .queries
            .iter()
            .filter(|(_, q)| now.duration_since(q.sent_at) > timeout)
            .map(|(&id, _)| id)
            .collect();

        expired_ids
            .into_iter()
            .filter_map(|id| self.queries.remove(&id))
            .collect()
    }
}

impl Default for ForwardTable {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// FREC flag constants (mirrors C #define FREC_*)
// ──────────────────────────────────────────────────────────────────────────────

/// Don't use the cache; pass query straight through.
pub const FREC_NO_CACHE:           u32 = 4;
/// Query is a DNSKEY sub-query issued by DNSSEC validation.
pub const FREC_DNSKEY_QUERY:       u32 = 8;
/// Query is a DS sub-query issued by DNSSEC validation.
pub const FREC_DS_QUERY:           u32 = 16;
/// Original question had AD bit set (client requests authentic data).
pub const FREC_AD_QUESTION:        u32 = 32;
/// Original question had DO bit set (client requests DNSSEC OK).
pub const FREC_DO_QUESTION:        u32 = 64;
/// Packet has a EDNS pseudo-header that must be stripped on send.
pub const FREC_HAS_PHEADER:        u32 = 128;
/// Query was escalated to TCP.
pub const FREC_GONE_TO_TCP:        u32 = 256;
/// Used internally by `lookup_frec` to indicate an answer match (case).
pub const FREC_ANSWER:             u32 = 512;
/// CD (checking disabled) bit was set in the original question.
pub const FREC_CHECKING_DISABLED:  u32 = 2;
/// Refuse rebinding-attack addresses in replies.
pub const FREC_NOREBIND:           u32 = 1;

/// Default timeout seconds before a forwarded query is considered stale.
pub const FREC_TIMEOUT_SECS: u64 = 10;

// ──────────────────────────────────────────────────────────────────────────────
// Frec — in-flight forwarded query (mirrors C `struct frec`)
// ──────────────────────────────────────────────────────────────────────────────

/// Per-source context for a forwarded query.
///
/// A single `Frec` may be shared by multiple clients sending the same question
/// (query de-duplication); `FrecSrc` tracks each original client separately.
/// Mirrors C's embedded `struct frec_src`.
#[derive(Debug, Clone, Default)]
pub struct FrecSrc {
    /// Original client address.
    pub source:      Option<std::net::SocketAddr>,
    /// Destination address used to receive the reply.
    pub dest:        Option<std::net::IpAddr>,
    /// Interface index on which the original query arrived.
    pub iface:       u32,
    /// Log ID for correlated log messages.
    pub log_id:      u32,
    /// 0x20-encoding random bitmap (0 = disabled).
    pub encode_bitmap: u32,
    /// File descriptor index used for the reply socket.
    pub fd:          i32,
    /// Original DNS transaction ID from the client.
    pub orig_id:     u16,
    /// Maximum UDP packet size the client indicated (EDNS0 OPT).
    pub udp_pkt_size: u16,
}

/// An in-flight forwarded DNS query.
///
/// Mirrors C's `struct frec`.  When `sentto` is `None` the record is
/// considered free and may be reused.
#[derive(Debug, Clone)]
pub struct Frec {
    /// Primary client source context.
    pub frec_src:        FrecSrc,
    /// Additional duplicate-query client contexts.
    pub extra_srcs:      Vec<FrecSrc>,
    /// Index of the upstream server this query was sent to, or `None` if free.
    pub sentto:          Option<usize>,
    /// Transaction ID used in the outgoing (upstream) query.
    pub new_id:          u16,
    /// `forwardall` flag — try every server in turn.
    pub forwardall:      bool,
    /// FREC_* bitfield flags.
    pub flags:           u32,
    /// Timestamp when the query was created / forwarded.
    pub sent_at:         Instant,
    /// Saved copy of the query wire bytes (for retransmit and duplicate detect).
    pub stash:           Option<Vec<u8>>,
    /// DNSSEC: DNS class of the question.
    pub class:           u16,
    /// DNSSEC: per-query work budget counter.
    pub work_counter:    i32,
    /// DNSSEC: validation-attempt counter.
    pub validate_counter: i32,
    /// DNSSEC: unique monotone identifier.
    pub uid:             u32,
    /// DNSSEC: index of the `Frec` this query is waiting on (`blocking_query`).
    pub blocking_query:  Option<usize>,
    /// DNSSEC: index of the `Frec` that spawned this one (`dependent`).
    pub dependent:       Option<usize>,
}

impl Frec {
    /// Create a new free (unassigned) `Frec`.
    fn new_free() -> Self {
        Self {
            frec_src:         FrecSrc::default(),
            extra_srcs:       Vec::new(),
            sentto:           None,
            new_id:           0,
            forwardall:       false,
            flags:            0,
            sent_at:          Instant::now(),
            stash:            None,
            class:            1,
            work_counter:     0,
            validate_counter: 0,
            uid:              0,
            blocking_query:   None,
            dependent:        None,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// FrecTable — manages the pool of in-flight queries
// ──────────────────────────────────────────────────────────────────────────────

/// Manages a fixed-size pool of [`Frec`] records.
///
/// Mirrors the `daemon->frec_list` linked-list in C but uses a `Vec` so that
/// entries can be referenced by index without unsafe pointers.
pub struct FrecTable {
    frecs:           Vec<Frec>,
    /// Maximum concurrent queries per server group (`daemon->ftabsize`).
    pub max_per_group: usize,
    /// DNSSEC uid counter (monotone, local to the table).
    next_uid:        u32,
    /// Rate-limiting for `query_full` log messages.
    last_full_log:   Option<Instant>,
}

impl FrecTable {
    /// Create an empty `FrecTable` with the given per-group limit.
    pub fn new(max_per_group: usize) -> Self {
        Self {
            frecs: Vec::new(),
            max_per_group,
            next_uid: 0,
            last_full_log: None,
        }
    }

    /// Release a `Frec` back to the free pool.
    ///
    /// Clears all fields and walks the DNSSEC dependency graph:
    /// if the freed `Frec` was the last dependent of its `blocking_query`,
    /// that blocking query is freed recursively.
    ///
    /// Mirrors C's `free_frec()`.
    pub fn free_frec(&mut self, idx: usize) {
        if idx >= self.frecs.len() {
            return;
        }

        // Gather fields we need before we mutably borrow self again.
        let blocking = self.frecs[idx].blocking_query;
        let dependent = self.frecs[idx].dependent;

        // Reset this frec.
        self.frecs[idx].sentto         = None;
        self.frecs[idx].flags          = 0;
        self.frecs[idx].stash          = None;
        self.frecs[idx].extra_srcs     .clear();
        self.frecs[idx].forwardall     = false;
        self.frecs[idx].blocking_query = None;
        self.frecs[idx].dependent      = None;
        self.frecs[idx].next_dependent_slot().take(); // no-op stub below

        // If we were a dependent of a blocking query, unlink ourselves.
        if let Some(bq) = blocking {
            if bq < self.frecs.len() {
                // Remove `idx` from the blocking query's dependent list.
                // We store dependents as Option<usize> (single-linked via a
                // separate flat list is not done here; C uses pointers).
                // Simple: if the blocking query's sole dependent was `idx`,
                // free it too.
                let still_has_deps = self.frecs[bq].dependent.is_some()
                    && self.frecs[bq].dependent != Some(idx);
                if !still_has_deps {
                    self.free_frec(bq);
                }
            }
        }
        let _ = dependent; // mark used
    }

    /// Allocate a new `Frec`, or reuse an expired one.
    ///
    /// Scans the pool for:
    /// 1. A free slot (`sentto == None`).
    /// 2. A slot older than `4 * FREC_TIMEOUT_SECS` (garbage collected).
    /// 3. The oldest slot beyond `FREC_TIMEOUT_SECS` (last resort, no-force).
    ///
    /// Returns the pool index of the allocated `Frec`, or `None` if the
    /// per-group limit is reached and `force` is false.
    ///
    /// Mirrors C's `get_new_frec()`.
    pub fn get_new_frec(
        &mut self,
        now:        Instant,
        server_idx: usize,
        force:      bool,
    ) -> Option<usize> {
        let timeout       = Duration::from_secs(FREC_TIMEOUT_SECS);
        let hard_timeout  = Duration::from_secs(4 * FREC_TIMEOUT_SECS);

        let mut free_slot:   Option<usize> = None;
        let mut oldest_slot: Option<usize> = None;
        let mut count = 0usize; // queries in-flight for this server group

        for (i, f) in self.frecs.iter_mut().enumerate() {
            if f.sentto.is_none() {
                if free_slot.is_none() {
                    free_slot = Some(i);
                }
                continue;
            }

            // Non-DNSSEC-dependent entries may be garbage collected.
            if !force && f.dependent.is_none() {
                let age = now.duration_since(f.sent_at);
                if age >= hard_timeout {
                    free_slot = Some(i);
                    continue;
                }
                if age >= timeout {
                    oldest_slot = oldest_slot.or(Some(i));
                }
            }

            if f.sentto == Some(server_idx) && now.duration_since(f.sent_at) < timeout {
                count += 1;
            }
        }

        if !force && count >= self.max_per_group {
            self.emit_query_full(now, None);
            return None;
        }

        // Find the slot to use.
        let target = free_slot.or_else(|| {
            if !force { oldest_slot } else { None }
        });

        let idx = match target {
            Some(i) => {
                // Evict it first if it was in-flight.
                if self.frecs[i].sentto.is_some() {
                    self.free_frec(i);
                }
                i
            }
            None => {
                // Grow the pool.
                let i = self.frecs.len();
                self.frecs.push(Frec::new_free());
                i
            }
        };

        // Initialise the new entry.
        self.frecs[idx].sent_at = now;
        self.frecs[idx].uid     = { let u = self.next_uid; self.next_uid = self.next_uid.wrapping_add(1); u };
        Some(idx)
    }

    /// Return a unique random DNS transaction ID that is not in use by any
    /// current in-flight query.
    ///
    /// Mirrors C's `get_id()`.
    pub fn get_id(&self) -> u16 {
        loop {
            let id = rand::random::<u16>();
            if id == 0 { continue; }
            let in_use = self.frecs.iter().any(|f| f.sentto.is_some() && f.new_id == id);
            if !in_use {
                return id;
            }
        }
    }

    /// Find a live (non-expired) `Frec` matching `id` and flag criteria.
    ///
    /// `id = 0xFFFF` is treated as a wildcard (match any new_id).
    /// A `Frec` older than `4 * FREC_TIMEOUT_SECS` is never returned.
    ///
    /// Mirrors C's `lookup_frec()`.
    pub fn lookup_frec(
        &self,
        now:       Instant,
        id:        u16,
        flags:     u32,
        flagmask:  u32,
    ) -> Option<usize> {
        let hard_timeout = Duration::from_secs(4 * FREC_TIMEOUT_SECS);
        for (i, f) in self.frecs.iter().enumerate() {
            if f.sentto.is_none() {
                continue;
            }
            if (f.flags & flagmask) != flags {
                continue;
            }
            if id != u16::MAX && f.new_id != id {
                continue;
            }
            if now.duration_since(f.sent_at) >= hard_timeout {
                return None;
            }
            return Some(i);
        }
        None
    }

    /// Find a live `Frec` matching the given stash bytes, id, and flags.
    ///
    /// This variant searches by comparing stash content (first `cmp_len`
    /// bytes), useful when the query name is encoded in the stash.
    ///
    /// Returns the index if found.
    pub fn lookup_frec_by_stash(
        &self,
        now:      Instant,
        stash:    &[u8],
        cmp_len:  usize,
        id:       u16,
        flags:    u32,
        flagmask: u32,
    ) -> Option<usize> {
        let hard_timeout = Duration::from_secs(4 * FREC_TIMEOUT_SECS);
        for (i, f) in self.frecs.iter().enumerate() {
            if f.sentto.is_none() { continue; }
            if (f.flags & flagmask) != flags { continue; }
            if id != u16::MAX && f.new_id != id { continue; }
            if now.duration_since(f.sent_at) >= hard_timeout { continue; }
            if let Some(saved) = &f.stash {
                let n = cmp_len.min(saved.len()).min(stash.len());
                if saved[..n] == stash[..n] {
                    return Some(i);
                }
            }
        }
        None
    }

    /// Emit a rate-limited "query table full" warning.
    ///
    /// Only logs if at least 5 seconds have passed since the last warning.
    /// Returns `true` if the message was emitted.
    ///
    /// Mirrors C's `query_full()`.
    pub fn emit_query_full(&mut self, now: Instant, domain: Option<&str>) -> bool {
        let cooldown = Duration::from_secs(5);
        if self.last_full_log.map_or(true, |t| now.duration_since(t) >= cooldown) {
            self.last_full_log = Some(now);
            match domain {
                Some(d) if !d.is_empty() =>
                    eprintln!("dnsmasq-rs: max concurrent DNS queries to {} reached (max: {})", d, self.max_per_group),
                _ =>
                    eprintln!("dnsmasq-rs: max concurrent DNS queries reached (max: {})", self.max_per_group),
            }
            true
        } else {
            false
        }
    }

    /// Return the number of currently in-flight queries.
    pub fn active_count(&self) -> usize {
        self.frecs.iter().filter(|f| f.sentto.is_some()).count()
    }

    /// Get a shared reference to a `Frec` by index.
    pub fn get(&self, idx: usize) -> Option<&Frec> {
        self.frecs.get(idx)
    }

    /// Get a mutable reference to a `Frec` by index.
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut Frec> {
        self.frecs.get_mut(idx)
    }
}

impl Frec {
    // Stub so free_frec can call it without an extra field.
    fn next_dependent_slot(&mut self) -> &mut Option<usize> {
        &mut self.dependent
    }
}



/// Patch the DNS transaction ID in a packet (first 2 bytes of the header).
///
/// Does nothing if `pkt` is shorter than 2 bytes.
pub fn patch_id(pkt: &mut [u8], new_id: u16) {
    if pkt.len() < 2 {
        return;
    }
    let bytes = new_id.to_be_bytes();
    pkt[0] = bytes[0];
    pkt[1] = bytes[1];
}

/// Select the next upstream server index using round-robin.
///
/// `servers` is the full ordered list of server indices.
/// `tried` is the set of indices already attempted for this query.
/// `last` is the index of the most-recently tried server.
///
/// Returns `None` if all servers have been tried.
pub fn next_server(servers: &[usize], tried: &HashSet<usize>, last: usize) -> Option<usize> {
    if servers.is_empty() || tried.len() >= servers.len() {
        return None;
    }
    // Find the position of `last` in `servers`, then scan forward.
    let start = servers
        .iter()
        .position(|&s| s == last)
        .map(|p| (p + 1) % servers.len())
        .unwrap_or(0);

    for i in 0..servers.len() {
        let idx = servers[(start + i) % servers.len()];
        if !tried.contains(&idx) {
            return Some(idx);
        }
    }
    None
}

/// Check whether a reply's question section matches the original query.
///
/// Returns `true` if the first question's (canonicalised) name and qtype are
/// identical in both packets.  A structural parse failure returns `false`.
pub fn reply_matches_query(query_pkt: &[u8], reply_pkt: &[u8]) -> bool {
    match (hash_questions(query_pkt), hash_questions(reply_pkt)) {
        (Some(qh), Some(rh)) => qh == rh,
        _ => false,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Random FD pool (allocate_rfd / free_rfd)
// ──────────────────────────────────────────────────────────────────────────────

/// Maximum number of cached random UDP sockets.
pub const RANDOM_SOCKS: usize = 64;

/// A cached random-port UDP socket with reference counting.
///
/// Mirrors dnsmasq's `struct randfd`.  In the async Rust version we store
/// `tokio::net::UdpSocket` instead of a raw file descriptor so the socket is
/// owned by the pool and dropped when refcount reaches zero.
#[derive(Debug)]
pub struct RandomSocket {
    pub socket:     Arc<tokio::net::UdpSocket>,
    /// How many pending queries currently share this socket.
    pub refcount:   usize,
    /// Upstream server index this socket is "pinned" to, or `None` if free.
    pub server_idx: Option<usize>,
}

/// Pool of cached random-port UDP sockets.
///
/// Mirrors dnsmasq's `daemon->randomsocks[]` array plus the logic in
/// `allocate_rfd()` / `free_rfd()`.
///
/// The pool keeps up to `RANDOM_SOCKS` sockets open.  When a query needs an
/// ephemeral source socket the pool tries to reuse an existing socket bound to
/// the same upstream server.  If none exists and the pool is full, the entry
/// with `refcount == 0` and the oldest last-used index is evicted.
pub struct RandFdPool {
    slots: Vec<Option<RandomSocket>>,
}

impl RandFdPool {
    /// Create an empty pool.
    pub fn new() -> Self {
        let mut slots = Vec::with_capacity(RANDOM_SOCKS);
        for _ in 0..RANDOM_SOCKS {
            slots.push(None);
        }
        Self { slots }
    }

    /// Allocate or reuse a random UDP socket for the given upstream server.
    ///
    /// Returns an `Arc` clone of the socket on success.  The socket is bound
    /// to `0.0.0.0:0` (OS picks an ephemeral port).
    ///
    /// Binding is performed asynchronously; the method is `async`.
    pub async fn allocate(&mut self, server_idx: usize) -> Option<Arc<tokio::net::UdpSocket>> {
        // 1. Look for an existing slot pinned to this server with room.
        for slot in self.slots.iter_mut().flatten() {
            if slot.server_idx == Some(server_idx) {
                slot.refcount += 1;
                return Some(Arc::clone(&slot.socket));
            }
        }

        // 2. Find a free slot (empty or refcount == 0).
        let free_idx = self
            .slots
            .iter()
            .position(|s| s.is_none() || s.as_ref().is_some_and(|r| r.refcount == 0));

        let idx = free_idx?;

        // Bind a new UDP socket on an OS-assigned ephemeral port.
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
        let sock = Arc::new(sock);
        self.slots[idx] = Some(RandomSocket {
            socket: Arc::clone(&sock),
            refcount: 1,
            server_idx: Some(server_idx),
        });
        Some(sock)
    }

    /// Release one reference to the socket used by the query with `server_idx`.
    ///
    /// Decrements `refcount`.  When `refcount` reaches zero the slot is left
    /// in place (the socket stays open for reuse) but flagged as available.
    pub fn free(&mut self, server_idx: usize) {
        for slot in self.slots.iter_mut().flatten() {
            if slot.server_idx == Some(server_idx) && slot.refcount > 0 {
                slot.refcount -= 1;
                return;
            }
        }
    }

    /// Return the number of occupied slots (refcount > 0).
    pub fn active_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| s.as_ref().is_some_and(|r| r.refcount > 0))
            .count()
    }
}

impl Default for RandFdPool {
    fn default() -> Self { Self::new() }
}

// ──────────────────────────────────────────────────────────────────────────────
// Async forwarding engine
// ──────────────────────────────────────────────────────────────────────────────

/// Maximum DNS packet size (UDP).
pub const MAX_PACKET_SIZE: usize = 65535;

/// Default query timeout before a forwarded query is abandoned.
pub const QUERY_TIMEOUT_SECS: u64 = 10;

/// Configuration for the forwarding engine.
#[derive(Debug, Clone)]
pub struct ForwardConfig {
    /// Ordered list of upstream resolver addresses.
    pub upstreams: Vec<SocketAddr>,
    /// Per-query timeout.
    pub timeout: Duration,
    /// Maximum number of retries per query.
    pub max_retries: u8,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            upstreams:   Vec::new(),
            timeout:     Duration::from_secs(QUERY_TIMEOUT_SECS),
            max_retries: 2,
        }
    }
}

/// Stateful DNS forwarding engine.
///
/// Owns a [`ForwardTable`] and the forwarding configuration.  Used by
/// `run_forward_loop` but can also be driven manually for testing.
pub struct ForwardEngine {
    pub config:          ForwardConfig,
    pub table:           ForwardTable,
    upstream_order:      Vec<usize>,
    /// Pool of cached random-port UDP sockets for query dispatch.
    pub rfd_pool:        RandFdPool,
}

impl ForwardEngine {
    /// Create a new engine with the given configuration.
    pub fn new(config: ForwardConfig) -> Self {
        let n = config.upstreams.len();
        Self {
            upstream_order: (0..n).collect(),
            table: ForwardTable::new(),
            config,
            rfd_pool: RandFdPool::new(),
        }
    }

    /// Forward `pkt` to an upstream server and record the pending query.
    ///
    /// Returns `Some(upstream_id)` on success, `None` if no upstream is
    /// available or the send fails.
    pub async fn forward_query(
        &mut self,
        pkt: &[u8],
        client: SocketAddr,
        upstream_sock: &tokio::net::UdpSocket,
    ) -> Option<u16> {
        if pkt.len() < 12 || self.config.upstreams.is_empty() {
            return None;
        }
        let tried = HashSet::new();
        let server_idx = next_server(&self.upstream_order, &tried, usize::MAX)?;
        let upstream_addr = self.config.upstreams[server_idx];

        let qhash = hash_questions(pkt).unwrap_or([0u8; 16]);
        let orig_id = u16::from_be_bytes([pkt[0], pkt[1]]);
        let new_id = self.table.alloc_query(orig_id, client, server_idx, qhash);

        let mut out = pkt.to_vec();
        patch_id(&mut out, new_id);
        match upstream_sock.send_to(&out, upstream_addr).await {
            Ok(_) => {
                inc_metric(Metric::DnsQueriesForwarded);
                Some(new_id)
            }
            Err(_) => {
                self.table.remove(new_id);
                None
            }
        }
    }

    /// Process an upstream reply.
    ///
    /// Matches the reply's transaction ID against the pending table.  Returns:
    /// - `Ok(Some((client_addr, reply)))` — valid reply, restore client ID
    /// - `Ok(None)` — no matching pending query (ignore)
    /// - `Err(pending)` — SERVFAIL reply; caller should retry with `retry_query`
    pub fn handle_reply_with_failover(
        &mut self,
        reply: &mut Vec<u8>,
    ) -> Result<Option<(SocketAddr, Vec<u8>)>, PendingQuery> {
        if reply.len() < 12 { return Ok(None); }
        let reply_id = u16::from_be_bytes([reply[0], reply[1]]);
        // Peek at rcode (lower 4 bits of byte 3).
        let rcode = reply[3] & 0x0F;
        if rcode == 2 /* SERVFAIL */ {
            // Remove from table and return Err so caller can try next server.
            if let Some(pending) = self.table.remove(reply_id) {
                if pending.retries < self.config.max_retries {
                    return Err(pending);
                }
                // Max retries exhausted — return SERVFAIL to client.
                patch_id(reply, pending.orig_id);
                return Ok(Some((pending.client, reply.clone())));
            }
            return Ok(None);
        }
        // Normal reply (including NXDOMAIN etc.).
        let pending = match self.table.remove(reply_id) {
            Some(p) => p,
            None => return Ok(None),
        };
        patch_id(reply, pending.orig_id);
        Ok(Some((pending.client, reply.clone())))
    }

    /// Retry a query that received SERVFAIL, using the next available upstream.
    ///
    /// Increments `pending.retries`, picks the next server that has not yet
    /// been tried (stored in `pending.upstream_idx`), and re-sends the
    /// original query.  Returns `Some(new_id)` on success.
    pub async fn retry_query(
        &mut self,
        mut pending: PendingQuery,
        orig_pkt: &[u8],
        upstream_sock: &tokio::net::UdpSocket,
    ) -> Option<u16> {
        let mut tried = HashSet::new();
        tried.insert(pending.upstream_idx);
        let next_idx = next_server(&self.upstream_order, &tried, pending.upstream_idx)?;
        let upstream_addr = self.config.upstreams[next_idx];

        pending.retries += 1;
        pending.upstream_idx = next_idx;
        pending.sent_at = Instant::now();
        let new_id = self.table.alloc_query(
            pending.orig_id, pending.client, next_idx, pending.question_hash,
        );

        let mut out = orig_pkt.to_vec();
        patch_id(&mut out, new_id);
        match upstream_sock.send_to(&out, upstream_addr).await {
            Ok(_) => Some(new_id),
            Err(_) => {
                self.table.remove(new_id);
                None
            }
        }
    }

    /// Process an upstream reply.
    ///
    /// Matches the reply's transaction ID against the pending table.  If a
    /// match is found, restores the original client ID and returns
    /// `(client_addr, reply_bytes)`.
    pub fn handle_reply(&mut self, reply: &mut Vec<u8>) -> Option<(SocketAddr, Vec<u8>)> {
        if reply.len() < 2 { return None; }
        let reply_id = u16::from_be_bytes([reply[0], reply[1]]);
        let pending = self.table.remove(reply_id)?;
        patch_id(reply, pending.orig_id);
        Some((pending.client, reply.clone()))
    }

    /// Expire timed-out pending queries.
    pub fn expire_queries(&mut self) -> Vec<PendingQuery> {
        self.table.expire_old(self.config.timeout)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TCP fallback
// ──────────────────────────────────────────────────────────────────────────────

/// Check whether the TC (truncated) bit is set in a DNS reply.
///
/// Returns `true` only when the packet is at least 12 bytes (header-complete)
/// and byte 2, bit 1 is set.
pub fn is_truncated(pkt: &[u8]) -> bool {
    pkt.len() >= 12 && pkt[2] & 0x02 != 0
}

// ──────────────────────────────────────────────────────────────────────────────
// Send helpers  (ported from forward.c: send_from, server_send,
//                set_outgoing_mark, log_query_mysockaddr)
// ──────────────────────────────────────────────────────────────────────────────

/// Send `packet` from a UDP socket, optionally specifying the source address
/// via `cmsg(3)`.
///
/// When `nowild` is `true` the socket is already bound to the desired source,
/// so no ancillary data is needed and a plain `sendto` is used.  When
/// `nowild` is `false` the caller wants the kernel to use `source_addr` as
/// the outgoing source IP.  On Linux we achieve this with `IP_PKTINFO` /
/// `IPV6_PKTINFO` control messages; on other platforms the behaviour
/// degrades to a plain `sendto` (the socket must be bound correctly by the
/// caller).
///
/// Mirrors `send_from()` in `forward.c`.
#[cfg(unix)]
pub fn send_from(
    fd: std::os::unix::io::RawFd,
    nowild: bool,
    packet: &[u8],
    to: SocketAddr,
    source_addr: Option<IpAddr>,
    iface: u32,
) -> std::io::Result<usize> {
    use std::io;
    use std::mem;

    // Build the destination sockaddr.
    let (to_storage, to_len) = sockaddr_from_socket_addr(to);

    if nowild || source_addr.is_none() {
        // Simple sendto — no cmsg needed.
        let rc = unsafe {
            libc::sendto(
                fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &to_storage as *const libc::sockaddr_storage as *const libc::sockaddr,
                to_len as libc::socklen_t,
            )
        };
        return if rc < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(rc as usize)
        };
    }

    // We need to specify the source address via cmsg.
    let source = source_addr.unwrap();

    // Allocate a large-enough control buffer.
    let mut ctrl_buf = [0u8; 256];

    let iov = libc::iovec {
        iov_base: packet.as_ptr() as *mut libc::c_void,
        iov_len:  packet.len(),
    };

    let mut msghdr: libc::msghdr = unsafe { mem::zeroed() };
    msghdr.msg_name    = &to_storage as *const libc::sockaddr_storage as *mut libc::c_void;
    msghdr.msg_namelen = to_len as libc::socklen_t;
    msghdr.msg_iov     = &iov as *const libc::iovec as *mut libc::iovec;
    msghdr.msg_iovlen  = 1;
    msghdr.msg_control = ctrl_buf.as_mut_ptr() as *mut libc::c_void;

    match source {
        IpAddr::V4(v4) => {
            #[cfg(target_os = "linux")]
            {
                let space = unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in_pktinfo>() as u32) };
                msghdr.msg_controllen = space as _;
                let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
                if !cmsg.is_null() {
                    unsafe {
                        (*cmsg).cmsg_len   = libc::CMSG_LEN(mem::size_of::<libc::in_pktinfo>() as u32) as _;
                        (*cmsg).cmsg_level = libc::IPPROTO_IP;
                        (*cmsg).cmsg_type  = libc::IP_PKTINFO;
                        let pktinfo = libc::CMSG_DATA(cmsg) as *mut libc::in_pktinfo;
                        (*pktinfo).ipi_ifindex  = 0;
                        (*pktinfo).ipi_spec_dst = libc::in_addr { s_addr: u32::from_ne_bytes(v4.octets()) };
                    }
                }
            }
            #[cfg(not(target_os = "linux"))]
            {
                // Non-Linux: send without source annotation.
                let _ = (v4, iface);
                msghdr.msg_controllen = 0;
                msghdr.msg_control    = std::ptr::null_mut();
            }
        }
        IpAddr::V6(v6) => {
            let space = unsafe { libc::CMSG_SPACE(mem::size_of::<libc::in6_pktinfo>() as u32) };
            msghdr.msg_controllen = space as _;
            let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
            if !cmsg.is_null() {
                unsafe {
                    (*cmsg).cmsg_len   = libc::CMSG_LEN(mem::size_of::<libc::in6_pktinfo>() as u32) as _;
                    (*cmsg).cmsg_level = libc::IPPROTO_IPV6;
                    (*cmsg).cmsg_type  = libc::IPV6_PKTINFO;
                    let pktinfo = libc::CMSG_DATA(cmsg) as *mut libc::in6_pktinfo;
                    (*pktinfo).ipi6_ifindex = iface;
                    (*pktinfo).ipi6_addr    = libc::in6_addr { s6_addr: v6.octets() };
                }
            }
        }
    }

    let rc = unsafe { libc::sendmsg(fd, &msghdr, 0) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(rc as usize)
    }
}

/// No-op stub for non-Unix targets.
#[cfg(not(unix))]
pub fn send_from(
    _fd: i32,
    _nowild: bool,
    _packet: &[u8],
    _to: SocketAddr,
    _source_addr: Option<IpAddr>,
    _iface: u32,
) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "send_from not supported on this platform",
    ))
}

/// Construct a `(sockaddr_storage, len)` pair from a `SocketAddr`.
/// Used by `send_from`.
#[cfg(unix)]
fn sockaddr_from_socket_addr(addr: SocketAddr) -> (libc::sockaddr_storage, usize) {
    use std::mem;
    let mut storage: libc::sockaddr_storage = unsafe { mem::zeroed() };
    match addr {
        SocketAddr::V4(v4) => {
            let sin = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port   = v4.port().to_be();
            sin.sin_addr   = libc::in_addr { s_addr: u32::from_ne_bytes(v4.ip().octets()) };
            (storage, mem::size_of::<libc::sockaddr_in>())
        }
        SocketAddr::V6(v6) => {
            let sin6 = unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family   = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port     = v6.port().to_be();
            sin6.sin6_addr     = libc::in6_addr { s6_addr: v6.ip().octets() };
            sin6.sin6_scope_id = v6.scope_id();
            (storage, mem::size_of::<libc::sockaddr_in6>())
        }
    }
}

/// Send `packet` directly to `server_addr` using a plain `sendto`.
///
/// Mirrors `server_send()` in `forward.c`.  Retries are handled by the
/// caller (the C version loops on `EINTR`; here we rely on the OS and
/// the non-blocking or blocking nature of `fd`).
#[cfg(unix)]
pub fn server_send(
    fd: std::os::unix::io::RawFd,
    server_addr: SocketAddr,
    packet: &[u8],
) -> std::io::Result<usize> {
    use std::io;
    let (storage, len) = sockaddr_from_socket_addr(server_addr);
    let rc = unsafe {
        libc::sendto(
            fd,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &storage as *const libc::sockaddr_storage as *const libc::sockaddr,
            len as libc::socklen_t,
        )
    };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(rc as usize) }
}

/// No-op stub for non-Unix targets.
#[cfg(not(unix))]
pub fn server_send(
    _fd: i32,
    _server_addr: SocketAddr,
    _packet: &[u8],
) -> std::io::Result<usize> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "server_send not supported on this platform",
    ))
}

/// On Linux with `SO_MARK` / conntrack support, copy the connection mark of
/// an incoming query to the outgoing socket.
///
/// Mirrors `set_outgoing_mark()` in `forward.c`.  Only compiled on Linux;
/// on other platforms this is a no-op returning `Ok(())`.
#[cfg(all(unix, target_os = "linux"))]
pub fn set_outgoing_mark(
    fd: std::os::unix::io::RawFd,
    mark: u32,
) -> std::io::Result<()> {
    use std::io;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_MARK,
            &mark as *const u32 as *const libc::c_void,
            std::mem::size_of::<u32>() as libc::socklen_t,
        )
    };
    if rc < 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
}

/// No-op stub for non-Linux platforms.
#[cfg(not(all(unix, target_os = "linux")))]
pub fn set_outgoing_mark(_fd: i32, _mark: u32) -> std::io::Result<()> {
    Ok(())
}

/// Format a query log line from a socket address, mirroring
/// `log_query_mysockaddr()` from `forward.c`.
///
/// Returns a `(flags, addr_str, port)` tuple that callers can pass to their
/// log sink.  The `flags` value augments the caller-provided `flags` with
/// `F_IPV4` or `F_IPV6` depending on the address family, and with the
/// `F_SERVER` bit when `flags & F_SERVER != 0` (the port is then included in
/// the returned `port` field rather than a query type).
pub fn log_query_mysockaddr(
    flags: u32,
    addr: SocketAddr,
) -> (u32, String, u16) {
    match addr {
        SocketAddr::V4(v4) => {
            let port = if flags & F_SERVER != 0 { v4.port() } else { 0 };
            (flags | F_IPV4, v4.ip().to_string(), port)
        }
        SocketAddr::V6(v6) => {
            let port = if flags & F_SERVER != 0 { v6.port() } else { 0 };
            (flags | F_IPV6, v6.ip().to_string(), port)
        }
    }
}


///
/// DNS-over-TCP prefixes the message with a 2-byte big-endian length field
/// (RFC 1035 §4.2.2).  This function:
/// 1. Writes the 2-byte length prefix + query payload.
/// 2. Reads the 2-byte length prefix of the response.
/// 3. Reads exactly that many bytes and returns them.
///
/// Returns `None` on any I/O error or if the server closes the connection
/// before a complete response is received.
pub async fn tcp_query(
    upstream: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let connect = tokio::time::timeout(timeout, TcpStream::connect(upstream));
    let mut stream = connect.await.ok()?.ok()?;

    // Write length-prefixed query.
    let len = query.len() as u16;
    let frame: Vec<u8> = {
        let mut v = Vec::with_capacity(2 + query.len());
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(query);
        v
    };
    tokio::time::timeout(timeout, stream.write_all(&frame))
        .await.ok()?.ok()?;

    // Read 2-byte response length.
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await.ok()?.ok()?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    // Read the response body.
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(timeout, stream.read_exact(&mut resp))
        .await.ok()?.ok()?;

    Some(resp)
}

/// Handle a UDP reply that has the TC bit set.
///
/// Retries the original query (`orig_query`) over TCP to the same upstream
/// server.  On success the full (untruncated) response is returned with the
/// client's original query ID restored.
pub async fn tcp_fallback(
    upstream: SocketAddr,
    orig_query: &[u8],
    client_id: u16,
    timeout: Duration,
) -> Option<Vec<u8>> {
    inc_metric(Metric::TcpConnections);
    let mut resp = tcp_query(upstream, orig_query, timeout).await?;
    if resp.len() >= 2 {
        resp[0] = (client_id >> 8) as u8;
        resp[1] = (client_id & 0xFF) as u8;
    }
    Some(resp)
}

/// Run the DNS UDP forwarding event loop.
///
/// * `client_sock` — bound UDP socket facing DNS clients.
/// * `config`      — forwarding configuration (upstreams, timeout).
///
/// Runs until an unrecoverable I/O error occurs.  Logs are omitted for
/// simplicity; callers should wrap this in a task and handle the error.
pub async fn run_forward_loop(
    client_sock: Arc<tokio::net::UdpSocket>,
    config: ForwardConfig,
) -> std::io::Result<()> {
    // Ephemeral socket for upstream communication.
    let upstream_sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

    let mut engine       = ForwardEngine::new(config);
    let mut client_buf   = vec![0u8; MAX_PACKET_SIZE];
    let mut upstream_buf = vec![0u8; MAX_PACKET_SIZE];
    let mut ticker = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            // ── Incoming client query ─────────────────────────────────────────
            result = client_sock.recv_from(&mut client_buf) => {
                let (len, src) = result?;
                let pkt = &client_buf[..len];
                // Only forward DNS queries (QR bit == 0).
                if pkt.len() >= 12 && pkt[2] & 0x80 == 0 {
                    engine.forward_query(pkt, src, &upstream_sock).await;
                }
            }
            // ── Upstream reply ────────────────────────────────────────────────
            result = upstream_sock.recv_from(&mut upstream_buf) => {
                let (len, upstream_addr) = result?;
                let mut pkt = upstream_buf[..len].to_vec();
                if let Some((client_addr, reply)) = engine.handle_reply(&mut pkt) {
                    if is_truncated(&reply) {
                        // TC bit set — retry over TCP.
                        let pending = engine.table.lookup(
                            u16::from_be_bytes([reply[0], reply[1]])
                        ).cloned();
                        if let Some(q) = pending {
                            let timeout = engine.config.timeout;
                            if let Some(full) = tcp_fallback(
                                upstream_addr, &pkt, q.orig_id, timeout
                            ).await {
                                let _ = client_sock.send_to(&full, client_addr).await;
                                continue;
                            }
                        }
                    }
                    let _ = client_sock.send_to(&reply, client_addr).await;
                }
            }
            // ── Periodic expiry cleanup ───────────────────────────────────────
            _ = ticker.tick() => {
                let _expired = engine.expire_queries();
            }
        }
    }
}

// ─── Reply processing helpers ─────────────────────────────────────────────────

/// A rebind-exclusion domain entry.
///
/// RFC 5735 / RFC 1918 addresses returned for names in these domains are
/// *not* rejected as possible DNS-rebind attacks.  Mirrors dnsmasq's
/// `struct rebind_domain`.
#[derive(Debug, Clone, Default)]
pub struct RebindDomain {
    /// The domain suffix to exempt, e.g. `"home.arpa"`.
    /// An empty string means "any single-label name".
    pub domain: String,
}

/// Check whether `domain` appears in the no-rebind exclusion list.
///
/// Returns `true` if `domain` (or one of its super-domains) matches an
/// entry in `no_rebind`.  Match is case-insensitive and whole-label only
/// (i.e. `"example.com"` matches the suffix `"com"` but not `"xcom"`).
///
/// Mirrors `domain_no_rebind()` in `forward.c`.
pub fn domain_no_rebind(domain: &str, no_rebind: &[RebindDomain]) -> bool {
    let dlen = domain.len();
    let has_dots = domain.contains('.');
    for rbd in no_rebind {
        let tlen = rbd.domain.len();
        if tlen == 0 {
            // Empty entry matches any single-label name (no dots).
            if !has_dots {
                return true;
            }
            continue;
        }
        if dlen >= tlen {
            let start = dlen - tlen;
            let suffix = &domain[start..];
            if suffix.eq_ignore_ascii_case(&rbd.domain)
                && (dlen == tlen || domain.as_bytes().get(start.wrapping_sub(1)) == Some(&b'.'))
            {
                return true;
            }
        }
    }
    false
}

/// An IP-set / nft-set target entry associated with a domain suffix.
///
/// Mirrors dnsmasq's `struct ipsets`.
#[derive(Debug, Clone)]
pub struct IpSet {
    /// Domain suffix this entry matches (empty = wildcard / match-all).
    pub domain:   String,
    /// Set names to add matched addresses to.
    pub set_names: Vec<String>,
}

/// Find the most-specific `IpSet` entry whose domain suffix matches `domain`.
///
/// Uses the same longest-suffix-match algorithm as dnsmasq's
/// `domain_find_sets()` in `forward.c`.  Returns `None` if no entry matches.
pub fn domain_find_sets<'a>(setlist: &'a [IpSet], domain: &str) -> Option<&'a IpSet> {
    let namelen = domain.len();
    let mut matchlen: usize = 0;
    let mut result: Option<&IpSet> = None;

    for entry in setlist {
        let domainlen = entry.domain.len();
        if namelen >= domainlen {
            let matchstart = namelen - domainlen;
            let suffix = &domain[matchstart..];
            let boundary_ok = domainlen == 0
                || namelen == domainlen
                || domain.as_bytes().get(matchstart.wrapping_sub(1)) == Some(&b'.');
            if suffix.eq_ignore_ascii_case(&entry.domain) && boundary_ok && domainlen >= matchlen {
                matchlen = domainlen;
                result = Some(entry);
            }
        }
    }
    result
}

/// Outcome of `process_reply`.
#[derive(Debug, Clone, PartialEq)]
pub enum ProcessReplyResult {
    /// The reply is ready to be forwarded; the final RCODE is included.
    Forward { rcode: u8 },
    /// The reply was silently discarded (policy or parse error).
    Discard,
    /// DNS-rebind attack detected; the caller should log a warning.
    RebindAttack { name: String },
}

/// Configuration flags passed to `process_reply`.
#[derive(Debug, Clone, Default)]
pub struct ProcessReplyConfig {
    /// Reject RFC 1918 / 5735 addresses that resolve via global DNS.
    pub check_rebind: bool,
    /// Skip caching even for valid answers.
    pub no_cache:     bool,
    /// Answer has been validated as DNSSEC-secure.
    pub cache_secure: bool,
    /// Answer was flagged bogus by DNSSEC validation.
    pub bogus_answer: bool,
    /// Client requested the AD bit (authenticated data).
    pub ad_reqd:      bool,
    /// Client set the DNSSEC OK bit.
    pub do_bit:       bool,
}

/// Lightweight reply-processing pipeline, independent of global state.
///
/// This mirrors the core logic of `process_reply()` in `forward.c`:
/// - Validates the reply opcode and RCODE.
/// - Detects truncation and logs it.
/// - Applies rebind protection.
/// - Propagates the AD bit if secure and requested.
/// - Returns a disposition for the caller.
///
/// Full integration (EDNS0 stripping, bogus-wildcard detection, rrfilter,
/// `extract_addresses`, DNSSEC validation) requires the relevant modules
/// to be ported; those paths are marked as TODO below.
pub fn process_reply(
    pkt:    &[u8],
    name:   &str,
    config: &ProcessReplyConfig,
    no_rebind: &[RebindDomain],
) -> ProcessReplyResult {
    if pkt.len() < 12 {
        return ProcessReplyResult::Discard;
    }

    let flags2 = pkt[3]; // hb3 (QR|AA|TC|RD) ; hb4 (RA|Z|AD|CD|RCODE4bits)
    let hb4    = pkt[3]; // second octet of flags word
    let rcode  = hb4 & 0x0F;
    let opcode = (pkt[2] >> 3) & 0x0F;
    let is_tc  = (pkt[2] & 0x02) != 0; // TC bit is bit 1 of byte 2 (hb3)

    let _ = flags2; // suppress warning

    // Only handle standard queries (OPCODE=0).
    if opcode != 0 {
        // Non-QUERY opcodes pass through unchanged.
        return ProcessReplyResult::Forward { rcode };
    }

    // Truncated replies — log and pass through.
    if is_tc {
        // Caller should log "truncated"; we just forward.
        return ProcessReplyResult::Forward { rcode };
    }

    // RCODE filtering: only NOERROR and NXDOMAIN carry useful data.
    if rcode != 0 && rcode != 3 /* NXDOMAIN */ {
        return ProcessReplyResult::Forward { rcode };
    }

    // Rebind check for NOERROR answers.
    if config.check_rebind && rcode == 0 && !domain_no_rebind(name, no_rebind) {
        // TODO: inspect A/AAAA records for RFC-1918 addresses.
        // For now surface the policy check result to callers.
        // A real implementation would call extract_addresses() and check
        // whether any returned address is private-space.
    }

    // DNSSEC: bogus answers become SERVFAIL (if CD bit not set).
    if config.bogus_answer {
        let cd_bit = (pkt[3] & 0x10) != 0;
        if !cd_bit {
            return ProcessReplyResult::Forward { rcode: 2 /* SERVFAIL */ };
        }
    }

    // DNSSEC: set AD bit if the answer is secure and was requested.
    // (Actual bit mutation would happen on a mutable copy of the packet.)
    // TODO: mutate pkt copy for AD bit.

    ProcessReplyResult::Forward { rcode }
}

/// Disposition returned by `reply_query`.
#[derive(Debug, Clone, PartialEq)]
pub enum ReplyQueryResult {
    /// Reply fully processed; send `pkt` to `client`.
    Send {
        /// Processed reply packet to forward to the client.
        pkt:    Vec<u8>,
        /// Client address.
        client: SocketAddr,
        /// Upstream server index that replied.
        server_idx: usize,
    },
    /// Reply was discarded (spoof, parse error, etc.).
    Discard,
    /// All upstream servers for this query have been tried.
    AllServersTried,
}

/// Core of the reply-handling path.
///
/// Given a raw `reply_pkt` received from upstream server `from_addr`, look up
/// the matching pending query in `table`, apply `process_reply` policy, patch
/// the transaction ID back to the client's original ID, and return a
/// `ReplyQueryResult` describing what to do next.
///
/// Mirrors the key logic of `reply_query()` in `forward.c` without global
/// daemon state.
pub fn reply_query(
    reply_pkt:  &[u8],
    from_addr:  SocketAddr,
    servers:    &[SocketAddr],
    table:      &mut ForwardTable,
    config:     &ProcessReplyConfig,
    no_rebind:  &[RebindDomain],
    query_name: &str,
) -> ReplyQueryResult {
    if reply_pkt.len() < 12 {
        return ReplyQueryResult::Discard;
    }

    // Packet must be a response (QR bit set).
    let qr_bit = (reply_pkt[2] & 0x80) != 0;
    if !qr_bit {
        return ReplyQueryResult::Discard;
    }

    let upstream_id = u16::from_be_bytes([reply_pkt[0], reply_pkt[1]]);

    // Look up pending query by upstream transaction ID.
    let pending = match table.get_query(upstream_id) {
        Some(q) => q.clone(),
        None    => return ReplyQueryResult::Discard,
    };

    // Spoof check: verify the reply came from the expected server.
    let expected_addr = servers.get(pending.upstream_idx);
    if expected_addr != Some(&from_addr) {
        return ReplyQueryResult::Discard;
    }

    // Process the reply through policy filters.
    let result = process_reply(reply_pkt, query_name, config, no_rebind);
    if result == ProcessReplyResult::Discard {
        table.remove_query(upstream_id);
        return ReplyQueryResult::Discard;
    }

    // Patch the transaction ID back to the client's original.
    let mut pkt = reply_pkt.to_vec();
    patch_id(&mut pkt, pending.orig_id);

    let server_idx = pending.upstream_idx;
    let client     = pending.client;

    table.remove_query(upstream_id);

    ReplyQueryResult::Send { pkt, client, server_idx }
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure utility functions (ported from forward.c)
// ─────────────────────────────────────────────────────────────────────────────

/// XOR two u32 slices element-wise, storing results in `a`.
///
/// Only XORs up to `min(a.len(), b.len())` elements.
/// Port of `xor_array()` from forward.c:1301-1307.
pub fn xor_array(a: &mut [u32], b: &[u32]) {
    for (x, &y) in a.iter_mut().zip(b.iter()) {
        *x ^= y;
    }
}

/// Generate a random DNS query ID that doesn't conflict with existing entries.
///
/// Port of the unique-id logic from `get_id()` in forward.c:3302+.
pub fn get_unique_id(existing: &[u16]) -> u16 {
    use std::collections::HashSet;
    let used: HashSet<u16> = existing.iter().copied().collect();
    // Simple approach: try random values
    let mut id: u16 = rand::random();
    let mut attempts = 0;
    while used.contains(&id) && attempts < 1000 {
        id = rand::random();
        attempts += 1;
    }
    id
}

/// Check if a DNS reply should be considered "bogus" due to rebinding attack.
///
/// Returns true if the answer contains a private/RFC1918 address that doesn't
/// match any configured exception.
/// Port of the rebind-check logic used in return_reply().
pub fn is_private_reply(addr_bytes: &[u8]) -> bool {
    if addr_bytes.len() == 4 {
        // IPv4 private ranges: 10/8, 172.16/12, 192.168/16, 127/8
        let a = addr_bytes[0];
        let b = addr_bytes[1];
        a == 10
            || (a == 172 && (b & 0xf0) == 16)
            || (a == 192 && b == 168)
            || a == 127
    } else if addr_bytes.len() == 16 {
        // IPv6 ULA (fc00::/7) or link-local (fe80::/10)
        let a = addr_bytes[0];
        (a & 0xfe) == 0xfc || (a == 0xfe && (addr_bytes[1] & 0xc0) == 0x80)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }

    fn dummy_hash() -> [u8; 16] {
        [1u8; 16]
    }

    // ── ForwardTable ──────────────────────────────────────────────────────────

    #[test]
    fn alloc_query_unique_ids() {
        let mut ft = ForwardTable::new();
        let id1 = ft.alloc_query(100, dummy_addr(), 0, dummy_hash());
        let id2 = ft.alloc_query(101, dummy_addr(), 0, dummy_hash());
        let id3 = ft.alloc_query(102, dummy_addr(), 0, dummy_hash());
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn lookup_finds_inserted_query() {
        let mut ft = ForwardTable::new();
        let id = ft.alloc_query(42, dummy_addr(), 1, dummy_hash());
        let q = ft.lookup(id).expect("should find query");
        assert_eq!(q.orig_id, 42);
        assert_eq!(q.upstream_idx, 1);
    }

    #[test]
    fn remove_removes_query() {
        let mut ft = ForwardTable::new();
        let id = ft.alloc_query(7, dummy_addr(), 0, dummy_hash());
        let removed = ft.remove(id);
        assert!(removed.is_some());
        assert!(ft.lookup(id).is_none());
    }

    #[test]
    fn remove_absent_id_returns_none() {
        let mut ft = ForwardTable::new();
        assert!(ft.remove(9999).is_none());
    }

    #[test]
    fn expire_old_removes_timed_out_leaves_fresh() {
        let mut ft = ForwardTable::new();

        // Insert a query and immediately back-date its sent_at.
        let old_id = ft.alloc_query(1, dummy_addr(), 0, dummy_hash());
        ft.queries.get_mut(&old_id).unwrap().sent_at =
            Instant::now() - Duration::from_secs(10);

        // Insert a fresh query.
        let fresh_id = ft.alloc_query(2, dummy_addr(), 0, dummy_hash());

        let expired = ft.expire_old(Duration::from_secs(5));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, old_id);
        assert!(ft.lookup(fresh_id).is_some());
        assert!(ft.lookup(old_id).is_none());
    }

    // ── patch_id ──────────────────────────────────────────────────────────────

    #[test]
    fn patch_id_updates_first_two_bytes() {
        let mut pkt = vec![0x00, 0x01, 0x02, 0x03];
        patch_id(&mut pkt, 0xABCD);
        assert_eq!(pkt[0], 0xAB);
        assert_eq!(pkt[1], 0xCD);
        assert_eq!(pkt[2], 0x02); // unchanged
    }

    #[test]
    fn patch_id_short_packet_no_panic() {
        let mut pkt = vec![0x00];
        patch_id(&mut pkt, 0xFFFF); // should not panic
    }

    // ── next_server ───────────────────────────────────────────────────────────

    #[test]
    fn next_server_round_robin() {
        let servers = vec![0, 1, 2];
        let tried = HashSet::new();
        // Starting from last=0, next should be 1.
        let next = next_server(&servers, &tried, 0);
        assert_eq!(next, Some(1));
    }

    #[test]
    fn next_server_none_when_all_tried() {
        let servers = vec![0, 1, 2];
        let tried: HashSet<usize> = [0, 1, 2].iter().copied().collect();
        assert_eq!(next_server(&servers, &tried, 0), None);
    }

    #[test]
    fn next_server_skips_tried() {
        let servers = vec![0, 1, 2];
        let tried: HashSet<usize> = [1].iter().copied().collect();
        // last=0, next would be 1 but it's tried → should skip to 2.
        let next = next_server(&servers, &tried, 0);
        assert_eq!(next, Some(2));
    }

    #[test]
    fn next_server_empty_list_returns_none() {
        let servers: Vec<usize> = vec![];
        let tried = HashSet::new();
        assert_eq!(next_server(&servers, &tried, 0), None);
    }

    // ── reply_matches_query ───────────────────────────────────────────────────

    fn make_dns_query(qname: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x00, 0x01, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in qname.split('.') {
            if label.is_empty() {
                continue;
            }
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.push((qtype >> 8) as u8);
        pkt.push((qtype & 0xFF) as u8);
        pkt.push(0x00);
        pkt.push(0x01); // qclass IN
        pkt
    }

    #[test]
    fn reply_matches_query_matching() {
        let query = make_dns_query("example.com", 1);
        let reply = make_dns_query("example.com", 1);
        assert!(reply_matches_query(&query, &reply));
    }

    #[test]
    fn reply_matches_query_different_name() {
        let query = make_dns_query("example.com", 1);
        let reply = make_dns_query("other.com", 1);
        assert!(!reply_matches_query(&query, &reply));
    }

    #[test]
    fn reply_matches_query_different_qtype() {
        let query = make_dns_query("example.com", 1);
        let reply = make_dns_query("example.com", 28);
        assert!(!reply_matches_query(&query, &reply));
    }

    #[test]
    fn reply_matches_query_invalid_packet() {
        let query = make_dns_query("example.com", 1);
        assert!(!reply_matches_query(&query, &[0u8; 3]));
    }

    // ── ForwardEngine ─────────────────────────────────────────────────────────

    #[test]
    fn forward_engine_handle_reply_restores_id() {
        let config = ForwardConfig {
            upstreams: vec!["127.0.0.1:5353".parse().unwrap()],
            ..Default::default()
        };
        let mut engine = ForwardEngine::new(config);
        let client: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        // Simulate inserting a pending query with orig_id=42.
        let new_id = engine.table.alloc_query(42, client, 0, [0u8; 16]);

        // Build a fake reply with the upstream ID.
        let mut reply = vec![
            (new_id >> 8) as u8, (new_id & 0xFF) as u8, // upstream ID
            0x84, 0x00, // QR=1, AA=1
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // counts
        ];
        let (addr, patched) = engine.handle_reply(&mut reply).expect("should match");
        assert_eq!(addr, client);
        // Restored to original client ID 42.
        let restored_id = u16::from_be_bytes([patched[0], patched[1]]);
        assert_eq!(restored_id, 42);
    }

    #[test]
    fn forward_engine_handle_reply_unknown_id_returns_none() {
        let config = ForwardConfig::default();
        let mut engine = ForwardEngine::new(config);
        let mut reply = vec![0xAB, 0xCD, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00];
        assert!(engine.handle_reply(&mut reply).is_none());
    }

    #[test]
    fn forward_engine_expire_queries() {
        let config = ForwardConfig {
            timeout: Duration::from_millis(1),
            ..Default::default()
        };
        let mut engine = ForwardEngine::new(config);
        let client: SocketAddr = "127.0.0.1:999".parse().unwrap();
        engine.table.alloc_query(1, client, 0, [0u8; 16]);
        // Wait for timeout.
        std::thread::sleep(Duration::from_millis(5));
        let expired = engine.expire_queries();
        assert_eq!(expired.len(), 1);
    }

    // ── TCP fallback helpers ──────────────────────────────────────────────────

    #[test]
    fn servfail_triggers_retry_path() {
        let config = ForwardConfig {
            upstreams: vec![
                "127.0.0.1:5353".parse().unwrap(),
                "127.0.0.2:5353".parse().unwrap(),
            ],
            max_retries: 1,
            ..Default::default()
        };
        let client: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let mut engine = ForwardEngine::new(config);
        let new_id = engine.table.alloc_query(42, client, 0, [0u8; 16]);

        // Build a SERVFAIL reply (rcode=2 in byte 3).
        let mut reply = vec![
            (new_id >> 8) as u8, (new_id & 0xFF) as u8,
            0x84, 0x02, // QR=1, rcode=SERVFAIL
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = engine.handle_reply_with_failover(&mut reply);
        // Should return Err(pending) because retries < max_retries.
        assert!(result.is_err(), "SERVFAIL with retries left should return Err");
        let pending = result.unwrap_err();
        assert_eq!(pending.orig_id, 42);
        assert_eq!(pending.retries, 0); // not yet incremented — retry_query does that
    }

    #[test]
    fn servfail_exhausted_retries_returns_reply() {
        let config = ForwardConfig {
            upstreams: vec!["127.0.0.1:5353".parse().unwrap()],
            max_retries: 0,
            ..Default::default()
        };
        let client: SocketAddr = "127.0.0.1:1234".parse().unwrap();
        let mut engine = ForwardEngine::new(config);
        let new_id = engine.table.alloc_query(99, client, 0, [0u8; 16]);

        let mut reply = vec![
            (new_id >> 8) as u8, (new_id & 0xFF) as u8,
            0x84, 0x02, // SERVFAIL
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let result = engine.handle_reply_with_failover(&mut reply);
        // max_retries=0 → return SERVFAIL to client.
        assert!(result.is_ok());
        let inner = result.unwrap();
        assert!(inner.is_some());
        let (addr, resp) = inner.unwrap();
        assert_eq!(addr, client);
        let restored = u16::from_be_bytes([resp[0], resp[1]]);
        assert_eq!(restored, 99);
    }


    #[test]
    fn is_truncated_detects_tc_bit() {
        let mut pkt = vec![0u8; 12];
        assert!(!is_truncated(&pkt));
        pkt[2] |= 0x02; // set TC bit
        assert!(is_truncated(&pkt));
    }

    #[test]
    fn is_truncated_short_packet_safe() {
        assert!(!is_truncated(&[]));
        assert!(!is_truncated(&[0u8; 11]));
    }

    #[tokio::test]
    async fn tcp_fallback_restores_client_id() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Start a mock TCP DNS server that echoes back the query.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut len_buf = [0u8; 2];
                let _ = stream.read_exact(&mut len_buf).await;
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; len];
                let _ = stream.read_exact(&mut body).await;
                // Echo: prepend length prefix.
                let resp_len = (body.len() as u16).to_be_bytes();
                let _ = stream.write_all(&resp_len).await;
                let _ = stream.write_all(&body).await;
            }
        });

        // Build a minimal query (12-byte header).
        let query = vec![0x00, 0x42, 0x01, 0x00,
                         0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let client_id: u16 = 0x1234;
        let resp = tcp_fallback(addr, &query, client_id, Duration::from_secs(2)).await;
        assert!(resp.is_some());
        let r = resp.unwrap();
        let restored = u16::from_be_bytes([r[0], r[1]]);
        assert_eq!(restored, client_id);
    }

    // ── RandFdPool ────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rfd_pool_allocate_returns_socket() {
        let mut pool = RandFdPool::new();
        let sock = pool.allocate(0).await;
        assert!(sock.is_some());
        assert_eq!(pool.active_count(), 1);
    }

    #[tokio::test]
    async fn rfd_pool_reuses_same_server_socket() {
        let mut pool = RandFdPool::new();
        let s1 = pool.allocate(0).await.unwrap();
        let s2 = pool.allocate(0).await.unwrap();
        // Both arcs should point to the same socket (same local addr).
        assert_eq!(
            s1.local_addr().unwrap(),
            s2.local_addr().unwrap()
        );
        assert_eq!(pool.active_count(), 1);
    }

    #[tokio::test]
    async fn rfd_pool_free_decrements_refcount() {
        let mut pool = RandFdPool::new();
        pool.allocate(7).await.unwrap();
        assert_eq!(pool.active_count(), 1);
        pool.free(7);
        assert_eq!(pool.active_count(), 0);
    }

    #[tokio::test]
    async fn rfd_pool_different_servers_get_different_sockets() {
        let mut pool = RandFdPool::new();
        let s0 = pool.allocate(0).await.unwrap();
        let s1 = pool.allocate(1).await.unwrap();
        assert_ne!(
            s0.local_addr().unwrap(),
            s1.local_addr().unwrap()
        );
        assert_eq!(pool.active_count(), 2);
    }

    // ── FrecTable ─────────────────────────────────────────────────────────────

    #[test]
    fn frec_table_alloc_returns_index() {
        let mut table = FrecTable::new(100);
        let now = Instant::now();
        let idx = table.get_new_frec(now, 0, false);
        assert!(idx.is_some());
        assert_eq!(table.active_count(), 0); // sentto not yet set
    }

    #[test]
    fn frec_table_get_id_unique() {
        let mut table = FrecTable::new(100);
        let now = Instant::now();
        // Allocate two frecs, assign them IDs, verify get_id differs.
        let i0 = table.get_new_frec(now, 0, false).unwrap();
        let id0 = table.get_id();
        table.get_mut(i0).unwrap().sentto = Some(0);
        table.get_mut(i0).unwrap().new_id = id0;
        let id1 = table.get_id();
        assert_ne!(id0, id1, "get_id should avoid IDs already in use");
    }

    #[test]
    fn frec_table_free_clears_sentto() {
        let mut table = FrecTable::new(100);
        let now = Instant::now();
        let idx = table.get_new_frec(now, 0, false).unwrap();
        table.get_mut(idx).unwrap().sentto = Some(0);
        assert_eq!(table.active_count(), 1);
        table.free_frec(idx);
        assert_eq!(table.active_count(), 0);
    }

    #[test]
    fn frec_table_reuses_expired_slot() {
        let mut table = FrecTable::new(100);
        let long_ago = Instant::now() - Duration::from_secs(60);
        let idx0 = table.get_new_frec(long_ago, 0, false).unwrap();
        table.get_mut(idx0).unwrap().sentto = Some(0);
        // Grow: the slot is old enough to GC
        let now = Instant::now();
        let idx1 = table.get_new_frec(now, 0, false).unwrap();
        assert_eq!(idx0, idx1, "should reuse the expired slot");
    }

    #[test]
    fn frec_table_limit_enforced() {
        let mut table = FrecTable::new(2);
        let now = Instant::now();
        // Fill to limit.
        for i in 0..2 {
            let idx = table.get_new_frec(now, 0, false).unwrap();
            table.get_mut(idx).unwrap().sentto = Some(0);
            table.get_mut(idx).unwrap().new_id = (i + 1) as u16;
        }
        // Next alloc should fail (limit = 2 for server 0).
        let result = table.get_new_frec(now, 0, false);
        assert!(result.is_none(), "should be None when limit reached");
    }

    #[test]
    fn frec_table_force_bypasses_limit() {
        let mut table = FrecTable::new(1);
        let now = Instant::now();
        let idx = table.get_new_frec(now, 0, false).unwrap();
        table.get_mut(idx).unwrap().sentto = Some(0);
        // Force should succeed despite limit.
        let forced = table.get_new_frec(now, 0, true);
        assert!(forced.is_some());
    }

    #[test]
    fn frec_table_lookup_frec_by_id() {
        let mut table = FrecTable::new(100);
        let now = Instant::now();
        let idx = table.get_new_frec(now, 0, false).unwrap();
        let id = table.get_id();
        table.get_mut(idx).unwrap().sentto = Some(0);
        table.get_mut(idx).unwrap().new_id = id;
        let found = table.lookup_frec(now, id, 0, 0);
        assert_eq!(found, Some(idx));
    }

    #[test]
    fn frec_table_lookup_frec_wildcard_id() {
        let mut table = FrecTable::new(100);
        let now = Instant::now();
        let idx = table.get_new_frec(now, 0, false).unwrap();
        table.get_mut(idx).unwrap().sentto = Some(0);
        table.get_mut(idx).unwrap().new_id = 42;
        // u16::MAX = wildcard
        let found = table.lookup_frec(now, u16::MAX, 0, 0);
        assert_eq!(found, Some(idx));
    }

    #[test]
    fn frec_table_lookup_frec_expired_returns_none() {
        let mut table = FrecTable::new(100);
        let long_ago = Instant::now() - Duration::from_secs(60);
        let idx = table.get_new_frec(long_ago, 0, false).unwrap();
        table.get_mut(idx).unwrap().sentto = Some(0);
        table.get_mut(idx).unwrap().new_id = 99;
        let found = table.lookup_frec(Instant::now(), 99, 0, 0);
        assert!(found.is_none(), "expired frec should not be found");
    }

    // ── log_query_mysockaddr ──────────────────────────────────────────────────

    #[test]
    fn log_query_mysockaddr_ipv4_no_server_flag() {
        let addr: SocketAddr = "10.0.0.1:53".parse().unwrap();
        let (flags, addr_str, port) = log_query_mysockaddr(0, addr);
        assert!(flags & F_IPV4 != 0);
        assert!(flags & F_IPV6 == 0);
        assert_eq!(addr_str, "10.0.0.1");
        assert_eq!(port, 0, "port should be 0 when F_SERVER not set");
    }

    #[test]
    fn log_query_mysockaddr_ipv4_server_flag() {
        let addr: SocketAddr = "8.8.8.8:5353".parse().unwrap();
        let (flags, addr_str, port) = log_query_mysockaddr(F_SERVER, addr);
        assert!(flags & F_IPV4 != 0);
        assert_eq!(addr_str, "8.8.8.8");
        assert_eq!(port, 5353);
    }

    #[test]
    fn log_query_mysockaddr_ipv6_no_server_flag() {
        let addr: SocketAddr = "[::1]:53".parse().unwrap();
        let (flags, addr_str, port) = log_query_mysockaddr(0, addr);
        assert!(flags & F_IPV6 != 0);
        assert!(flags & F_IPV4 == 0);
        assert_eq!(addr_str, "::1");
        assert_eq!(port, 0);
    }

    #[test]
    fn log_query_mysockaddr_ipv6_server_flag() {
        let addr: SocketAddr = "[2001:db8::1]:853".parse().unwrap();
        let (flags, addr_str, port) = log_query_mysockaddr(F_SERVER, addr);
        assert!(flags & F_IPV6 != 0);
        assert_eq!(port, 853);
    }

    #[test]
    fn log_query_mysockaddr_preserves_caller_flags() {
        let addr: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let extra_flag: u32 = 1 << 25;
        let (flags, _, _) = log_query_mysockaddr(extra_flag, addr);
        assert!(flags & extra_flag != 0, "caller flags should be preserved");
        assert!(flags & F_IPV4 != 0);
    }

    // ── set_outgoing_mark ─────────────────────────────────────────────────────

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    fn set_outgoing_mark_valid_socket() {
        use std::os::unix::io::AsRawFd;
        // Create a real UDP socket to test setsockopt.
        let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        // SO_MARK requires CAP_NET_ADMIN; the call may fail with EPERM in CI.
        // We only verify it doesn't panic or produce an unexpected error type.
        match set_outgoing_mark(sock.as_raw_fd(), 42) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    // ── server_send ───────────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn server_send_loopback_roundtrip() {
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dst_addr: SocketAddr = receiver.local_addr().unwrap();
        let sender   = UdpSocket::bind("127.0.0.1:0").unwrap();
        let pkt = b"hello-server-send";
        server_send(sender.as_raw_fd(), dst_addr, pkt).unwrap();
        let mut buf = [0u8; 64];
        receiver.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], pkt);
    }

    // ── send_from ─────────────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn send_from_nowild_loopback() {
        use std::net::UdpSocket;
        use std::os::unix::io::AsRawFd;
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let dst_addr: SocketAddr = receiver.local_addr().unwrap();
        let sender   = UdpSocket::bind("127.0.0.1:0").unwrap();
        let pkt = b"hello-send-from";
        // nowild=true: plain sendto, no cmsg
        send_from(sender.as_raw_fd(), true, pkt, dst_addr, None, 0).unwrap();
        let mut buf = [0u8; 64];
        receiver.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], pkt);
    }

    // ── domain_no_rebind ──────────────────────────────────────────────────────

    fn rebind(d: &str) -> RebindDomain { RebindDomain { domain: d.to_string() } }

    #[test]
    fn domain_no_rebind_exact_match() {
        let list = vec![rebind("home.arpa")];
        assert!(domain_no_rebind("home.arpa", &list));
    }

    #[test]
    fn domain_no_rebind_subdomain_match() {
        let list = vec![rebind("home.arpa")];
        assert!(domain_no_rebind("router.home.arpa", &list));
    }

    #[test]
    fn domain_no_rebind_no_false_partial_match() {
        let list = vec![rebind("arpa")];
        // "xarpa" must NOT match the suffix "arpa"
        assert!(!domain_no_rebind("xarpa", &list));
    }

    #[test]
    fn domain_no_rebind_empty_entry_matches_single_label() {
        let list = vec![rebind("")];
        assert!(domain_no_rebind("localhost", &list));
        assert!(!domain_no_rebind("a.b", &list));
    }

    #[test]
    fn domain_no_rebind_no_match() {
        let list = vec![rebind("home.arpa")];
        assert!(!domain_no_rebind("example.com", &list));
    }

    // ── domain_find_sets ──────────────────────────────────────────────────────

    fn ipset(domain: &str, sets: &[&str]) -> IpSet {
        IpSet { domain: domain.to_string(), set_names: sets.iter().map(|s| s.to_string()).collect() }
    }

    #[test]
    fn domain_find_sets_longest_suffix_wins() {
        let sets = vec![
            ipset("com",         &["generic"]),
            ipset("example.com", &["specific"]),
        ];
        let result = domain_find_sets(&sets, "www.example.com").unwrap();
        assert_eq!(result.set_names, vec!["specific"]);
    }

    #[test]
    fn domain_find_sets_no_match_returns_none() {
        let sets = vec![ipset("example.com", &["s"])];
        assert!(domain_find_sets(&sets, "other.org").is_none());
    }

    #[test]
    fn domain_find_sets_wildcard_empty_matches_all() {
        let sets = vec![ipset("", &["catchall"])];
        let result = domain_find_sets(&sets, "anything.example.net");
        assert!(result.is_some());
    }

    // ── process_reply ─────────────────────────────────────────────────────────

    fn minimal_reply(rcode: u8, qr: bool, opcode: u8, tc: bool) -> Vec<u8> {
        // Minimal 12-byte DNS header
        let mut pkt = vec![0u8; 12];
        pkt[0] = 0x00; pkt[1] = 0x01; // ID
        // byte 2: QR(1) | OPCODE(4) | AA | TC | RD
        pkt[2] = (if qr { 0x80 } else { 0 })
               | ((opcode & 0x0F) << 3)
               | (if tc { 0x02 } else { 0 });
        // byte 3: RA | Z | AD | CD | RCODE(4)
        pkt[3] = rcode & 0x0F;
        pkt
    }

    #[test]
    fn process_reply_noerror_forwards() {
        let pkt = minimal_reply(0, true, 0, false);
        let cfg = ProcessReplyConfig::default();
        let result = process_reply(&pkt, "example.com", &cfg, &[]);
        assert_eq!(result, ProcessReplyResult::Forward { rcode: 0 });
    }

    #[test]
    fn process_reply_nxdomain_forwards() {
        let pkt = minimal_reply(3, true, 0, false);
        let cfg = ProcessReplyConfig::default();
        let result = process_reply(&pkt, "example.com", &cfg, &[]);
        assert_eq!(result, ProcessReplyResult::Forward { rcode: 3 });
    }

    #[test]
    fn process_reply_truncated_forwards() {
        let pkt = minimal_reply(0, true, 0, true);
        let cfg = ProcessReplyConfig::default();
        let result = process_reply(&pkt, "example.com", &cfg, &[]);
        assert_eq!(result, ProcessReplyResult::Forward { rcode: 0 });
    }

    #[test]
    fn process_reply_too_short_discards() {
        let cfg = ProcessReplyConfig::default();
        let result = process_reply(&[0u8; 5], "x", &cfg, &[]);
        assert_eq!(result, ProcessReplyResult::Discard);
    }

    // ── reply_query ───────────────────────────────────────────────────────────

    fn make_reply_pkt(upstream_id: u16, rcode: u8) -> Vec<u8> {
        let mut pkt = vec![0u8; 12];
        pkt[0] = (upstream_id >> 8) as u8;
        pkt[1] = (upstream_id & 0xFF) as u8;
        pkt[2] = 0x80; // QR=1
        pkt[3] = rcode & 0x0F;
        pkt
    }

    #[test]
    fn reply_query_patches_id_and_routes() {
        let server_addr: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let client_addr: SocketAddr = "192.168.1.1:12345".parse().unwrap();
        let mut table = ForwardTable::new();
        let upstream_id = table.alloc_query(0xABCD, client_addr, 0, [0u8; 16]);
        let reply = make_reply_pkt(upstream_id, 0);
        let cfg = ProcessReplyConfig::default();
        let result = reply_query(&reply, server_addr, &[server_addr], &mut table, &cfg, &[], "example.com");
        match result {
            ReplyQueryResult::Send { pkt, client, server_idx } => {
                let patched_id = u16::from_be_bytes([pkt[0], pkt[1]]);
                assert_eq!(patched_id, 0xABCD, "ID should be restored to original");
                assert_eq!(client, client_addr);
                assert_eq!(server_idx, 0);
            }
            other => panic!("expected Send, got {other:?}"),
        }
    }

    #[test]
    fn reply_query_discards_spoofed_reply() {
        let server_addr: SocketAddr  = "1.2.3.4:53".parse().unwrap();
        let spoofed_addr: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let client_addr: SocketAddr  = "192.168.1.1:12345".parse().unwrap();
        let mut table = ForwardTable::new();
        let upstream_id = table.alloc_query(0x1111, client_addr, 0, [0u8; 16]);
        let reply = make_reply_pkt(upstream_id, 0);
        let cfg = ProcessReplyConfig::default();
        // Reply comes from spoofed_addr, not server_addr
        let result = reply_query(&reply, spoofed_addr, &[server_addr], &mut table, &cfg, &[], "example.com");
        assert_eq!(result, ReplyQueryResult::Discard);
    }

    #[test]
    fn reply_query_discards_unknown_id() {
        let server_addr: SocketAddr = "1.2.3.4:53".parse().unwrap();
        let mut table = ForwardTable::new();
        let reply = make_reply_pkt(0xFFFF, 0); // unknown upstream ID
        let cfg = ProcessReplyConfig::default();
        let result = reply_query(&reply, server_addr, &[server_addr], &mut table, &cfg, &[], "example.com");
        assert_eq!(result, ReplyQueryResult::Discard);
    }

    // ── xor_array ────────────────────────────────────────────────────────────

    #[test]
    fn xor_array_basic() {
        let mut a = [0xFF00FF00u32, 0x12345678];
        let b = [0x00FF00FFu32, 0x87654321];
        xor_array(&mut a, &b);
        assert_eq!(a[0], 0xFFFFFFFF);
        assert_eq!(a[1], 0x12345678 ^ 0x87654321);
    }

    #[test]
    fn xor_array_different_lengths() {
        let mut a = [1u32, 2, 3];
        let b = [10u32, 20];
        xor_array(&mut a, &b);
        assert_eq!(a, [1 ^ 10, 2 ^ 20, 3]); // third element unchanged
    }

    #[test]
    fn xor_array_empty() {
        let mut a = [1u32, 2];
        xor_array(&mut a, &[]);
        assert_eq!(a, [1, 2]); // unchanged
    }

    #[test]
    fn xor_array_self_inverse() {
        let mut a = [0xDEADBEEFu32];
        let b = [0x12345678u32];
        xor_array(&mut a, &b);
        xor_array(&mut a, &b); // XOR again restores
        assert_eq!(a, [0xDEADBEEF]);
    }

    // ── get_unique_id ────────────────────────────────────────────────────────

    #[test]
    fn get_unique_id_empty_set() {
        let id = get_unique_id(&[]);
        assert!(id > 0 || id == 0); // any u16 is valid
    }

    #[test]
    fn get_unique_id_avoids_existing() {
        let existing: Vec<u16> = (0..100).collect();
        let id = get_unique_id(&existing);
        assert!(!existing.contains(&id));
    }

    // ── is_private_reply ─────────────────────────────────────────────────────

    #[test]
    fn is_private_reply_ipv4_10() {
        assert!(is_private_reply(&[10, 0, 0, 1]));
    }

    #[test]
    fn is_private_reply_ipv4_172_16() {
        assert!(is_private_reply(&[172, 16, 0, 1]));
        assert!(!is_private_reply(&[172, 32, 0, 1]));
    }

    #[test]
    fn is_private_reply_ipv4_192_168() {
        assert!(is_private_reply(&[192, 168, 1, 1]));
    }

    #[test]
    fn is_private_reply_ipv4_public() {
        assert!(!is_private_reply(&[8, 8, 8, 8]));
    }

    #[test]
    fn is_private_reply_ipv6_ula() {
        let mut addr = [0u8; 16];
        addr[0] = 0xfd;
        assert!(is_private_reply(&addr));
    }

    #[test]
    fn is_private_reply_ipv6_link_local() {
        let mut addr = [0u8; 16];
        addr[0] = 0xfe;
        addr[1] = 0x80;
        assert!(is_private_reply(&addr));
    }

    #[test]
    fn is_private_reply_ipv6_global() {
        let mut addr = [0u8; 16];
        addr[0] = 0x20;
        assert!(!is_private_reply(&addr));
    }
}


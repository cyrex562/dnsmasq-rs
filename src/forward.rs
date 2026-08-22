//! DNS query forwarding engine — data structures and helpers.
//!
//! Ported from dnsmasq's `forward.c`.  This module contains the in-flight query
//! table (`Frec`, `FrecSrc`, `FrecTable` — C's `struct frec`), the random-port
//! source-socket pool (`RandFdPool`, C's `daemon->randomsocks[]`), stateless
//! helpers (`patch_id`, `next_server`, `reply_matches_query`), and the async UDP
//! forwarding engine (`ForwardEngine`, `run_forward_loop`).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::net::IpAddr;

use crate::cache::{DnsCache, SharedDnsCache};
use crate::hash_questions::hash_questions;
use crate::metrics::{inc_metric, Metric};
use crate::dns_protocol::{Ede, EDNS0_OPTION_EDE, HB3_AA, HB4_AD, HB4_CD, HB4_RA};
use crate::edns0::Edns0Option;
use crate::rfc1035::{
    answer_request, DnsPacket, DnsRr, ExtractConfig, ExtractResult, LocalConfig,
};
use crate::types::constants::{F_IPV4, F_IPV6, F_SERVER};
use crate::types::dns_records::{
    BogusAddr, Cname, HostRecord, InterfaceName, MxSrvRecord, Naptr, PtrRecord, TxtRecord,
};
use crate::types::network::{Allowlist, Ipsets};
use crate::domain::CondDomain;

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

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

/// The flags two queries must agree on before one may be folded onto the other.
///
/// C's `flagmask` argument to the duplicate-detection `lookup_frec()` call
/// (`forward.c:196-197`).
pub const DEDUP_MASK: u32 = FREC_CHECKING_DISABLED
    | FREC_AD_QUESTION
    | FREC_DO_QUESTION
    | FREC_HAS_PHEADER
    | FREC_DNSKEY_QUERY
    | FREC_DS_QUERY
    | FREC_NO_CACHE;

/// DO bit (RFC 3225) within an OPT record's TTL field.
const EDNS_DO: u32 = 0x8000;

/// Fixed size of a DNS message header.
const DNS_HEADER_LEN: usize = 12;

/// Locate an EDNS0 OPT pseudo-header in a DNS message, returning its CLASS (the
/// sender's advertised UDP payload size) and TTL (extended rcode, version and
/// flags — bit 15 is DO).
///
/// Port of `find_pseudoheader()` (`edns0.c:19`) for the query path, where C
/// passes `is_sign = NULL` and so does no TSIG/TKEY inspection.  Like C, the
/// OPT record is recognised by TYPE alone, wherever in the additional section
/// it sits, and the *last* one wins.
///
/// This walks the raw wire bytes rather than a parsed packet because it runs on
/// every client query, including ones the full parser would reject: a query
/// this port cannot fully parse must still be recognised as carrying EDNS0, or
/// it would be folded onto a plain query in [`FrecTable::lookup_frec_by_question`].
pub fn find_pseudoheader(pkt: &[u8]) -> Option<(u16, u32)> {
    use crate::rfc1035::skip_name;

    if pkt.len() < DNS_HEADER_LEN {
        return None;
    }
    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;
    let nscount = u16::from_be_bytes([pkt[8], pkt[9]]) as usize;
    let arcount = u16::from_be_bytes([pkt[10], pkt[11]]) as usize;
    if arcount == 0 {
        return None;
    }

    let mut pos = DNS_HEADER_LEN;
    for _ in 0..qdcount {
        skip_name(pkt, &mut pos).ok()?;
        pos = pos.checked_add(4)?;
    }
    // Every record has a fixed 10-byte type/class/ttl/rdlength preamble after
    // its name, then `rdlength` bytes of RDATA.
    let skip_rr = |pos: &mut usize| -> Option<(u16, u16, u32)> {
        skip_name(pkt, pos).ok()?;
        let end = pos.checked_add(10)?;
        if end > pkt.len() {
            return None;
        }
        let rtype  = u16::from_be_bytes([pkt[*pos], pkt[*pos + 1]]);
        let class  = u16::from_be_bytes([pkt[*pos + 2], pkt[*pos + 3]]);
        let ttl    = u32::from_be_bytes([pkt[*pos + 4], pkt[*pos + 5], pkt[*pos + 6], pkt[*pos + 7]]);
        let rdlen  = u16::from_be_bytes([pkt[*pos + 8], pkt[*pos + 9]]) as usize;
        *pos = end.checked_add(rdlen)?;
        if *pos > pkt.len() {
            return None;
        }
        Some((rtype, class, ttl))
    };

    for _ in 0..(ancount + nscount) {
        skip_rr(&mut pos)?;
    }
    let mut found = None;
    for _ in 0..arcount {
        let (rtype, class, ttl) = skip_rr(&mut pos)?;
        if rtype == 41 {
            found = Some((class, ttl));
        }
    }
    found
}

/// Derive the EDNS0/DNSSEC context flags a query is forwarded under.
///
/// Port of C's `fwd_flags` computation in `receive_query()`
/// (`forward.c:1867-1898`).  These are stored on the `Frec` (`forward.c:373`)
/// and are what makes two identical questions genuinely interchangeable — or
/// not — for duplicate folding.
pub fn fwd_flags_from_query(pkt: &[u8]) -> u32 {
    if pkt.len() < DNS_HEADER_LEN {
        return 0;
    }
    let mut flags  = 0;
    let mut do_bit = false;

    if let Some((_udp_size, ttl)) = find_pseudoheader(pkt) {
        flags |= FREC_HAS_PHEADER;
        do_bit = ttl & EDNS_DO != 0;
    }

    // RFC 6840 5.7: DO implies the client can handle AD.
    if do_bit || pkt[3] & HB4_AD != 0 {
        flags |= FREC_AD_QUESTION;
    }
    if do_bit {
        flags |= FREC_DO_QUESTION;
    }
    if pkt[3] & HB4_CD != 0 {
        flags |= FREC_CHECKING_DISABLED;
    }
    flags
}

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
    /// Digest of the question section, the key both duplicate detection and
    /// reply matching use.  C re-parses `stash` for this
    /// (`lookup_frec`, `forward.c:3209`); the digest is the same comparison
    /// over name, type and class, done once.
    pub question_hash:   [u8; 16],
    /// Pool slots (source sockets) this transaction holds — C's `frec->rfds`.
    pub rfds:            RfdList,
    /// Upstream servers already tried for this query.
    pub tried:           HashSet<usize>,
    /// Number of upstream failures this query has been retried over.
    pub retries:         u8,
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
            question_hash:    [0u8; 16],
            rfds:             RfdList::new(),
            tried:            HashSet::new(),
            retries:          0,
            class:            1,
            work_counter:     0,
            validate_counter: 0,
            uid:              0,
            blocking_query:   None,
            dependent:        None,
        }
    }

    /// Every client waiting on this query, primary first.
    ///
    /// C walks `for (src = &forward->frec_src; src; src = src->next)`
    /// (`forward.c:1435`); the primary source is embedded in the `frec` and the
    /// duplicates are chained off it, which is why they are two fields here.
    pub fn srcs(&self) -> impl Iterator<Item = &FrecSrc> {
        std::iter::once(&self.frec_src).chain(self.extra_srcs.iter())
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
    /// Total `FrecSrc` records handed out for duplicate clients across the
    /// whole table — C's `daemon->frec_src_count`, also capped at `ftabsize`
    /// (`forward.c:227`).  It is a global budget, not a per-query one, so one
    /// heavily duplicated question cannot starve the rest.
    frec_src_count:  usize,
    /// DNSSEC uid counter (monotone, local to the table).
    next_uid:        u32,
    /// Rate-limiting for `query_full` log messages.
    last_full_log:   Option<Instant>,
    /// Pool slots freed along with their `Frec`s, waiting to be handed back to
    /// the [`RandFdPool`].  The table does not own the pool, so it parks the
    /// slot indices here and the pool's owner drains them with
    /// [`FrecTable::take_released_rfds`].
    released_rfds:   RfdList,
}

impl FrecTable {
    /// Create an empty `FrecTable` with the given per-group limit.
    pub fn new(max_per_group: usize) -> Self {
        Self {
            frecs: Vec::new(),
            max_per_group,
            frec_src_count: 0,
            next_uid: 0,
            last_full_log: None,
            released_rfds: RfdList::new(),
        }
    }

    /// Take the pool slots freed since the last call, for release into the
    /// [`RandFdPool`] the engine owns.
    pub fn take_released_rfds(&mut self) -> RfdList {
        std::mem::take(&mut self.released_rfds)
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

        // Hand the source sockets back (C: `free_rfds(&f->rfds)`) and return
        // the duplicate-client records to the global budget.
        let rfds = std::mem::take(&mut self.frecs[idx].rfds);
        self.released_rfds.extend(rfds);
        self.frec_src_count = self
            .frec_src_count
            .saturating_sub(self.frecs[idx].extra_srcs.len());

        // Reset this frec.
        self.frecs[idx].sentto         = None;
        self.frecs[idx].flags          = 0;
        self.frecs[idx].stash          = None;
        self.frecs[idx].question_hash  = [0u8; 16];
        self.frecs[idx].tried          .clear();
        self.frecs[idx].retries        = 0;
        self.frecs[idx].frec_src       = FrecSrc::default();
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
    /// `id = None` matches on the flags alone — C's `id == -1`
    /// (`forward.c:3227`).  It is deliberately *not* spelled as some reserved
    /// 16-bit value: C's `id` argument is an `int`, and the only wire-derived
    /// value ever passed to it is `ntohs(header->id)` (`forward.c:1173`), so
    /// `-1` is unreachable from a packet.  A sentinel inside the ID space would
    /// be reachable, and a forged reply carrying it would match whatever query
    /// happened to be in flight — collapsing the transaction ID to zero bits of
    /// the credential guarding [`ForwardEngine::validate_reply`].
    ///
    /// A `Frec` older than `4 * FREC_TIMEOUT_SECS` is never returned.
    ///
    /// Mirrors C's `lookup_frec()`.
    pub fn lookup_frec(
        &self,
        now:       Instant,
        id:        Option<u16>,
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
            if id.is_some_and(|want| f.new_id != want) {
                continue;
            }
            if now.duration_since(f.sent_at) >= hard_timeout {
                return None;
            }
            return Some(i);
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
                Some(d) if !d.is_empty() => tracing::warn!(
                    "Maximum number of concurrent DNS queries to {d} reached (max: {})",
                    self.max_per_group,
                ),
                _ => tracing::warn!(
                    "Maximum number of concurrent DNS queries reached (max: {})",
                    self.max_per_group,
                ),
            }
            true
        } else {
            false
        }
    }

    /// Find a live `Frec` asking the identical question.
    ///
    /// This is C's duplicate-detection call — `lookup_frec(now, namebuff,
    /// rrclass, rrtype, -1, ...)` (`forward.c:194`) — which matches on the
    /// question rather than the transaction ID so that a *second client's* query
    /// can be folded onto an existing upstream transaction.
    ///
    /// `fwd_flags` is the incoming query's own context, from
    /// [`fwd_flags_from_query`].  C requires *equality* on the mask it passes —
    /// `(f->flags & flagmask) == flags` (`forward.c:3226`) — not merely that the
    /// candidate is context-free, and that equality is load-bearing: two clients
    /// asking the same name under different EDNS0/DNSSEC context need different
    /// answers.  Folding a plain query onto a DO=1 one would hand it an OPT
    /// record and RRSIGs it never asked for (RFC 6891 §6.1.1 forbids the
    /// former); folding the other way would hand a validating stub an answer it
    /// cannot validate.
    ///
    /// The mask also covers `FREC_DNSKEY_QUERY`, `FREC_DS_QUERY` and
    /// `FREC_NO_CACHE`, none of which `fwd_flags` can contain — so a DNSSEC
    /// sub-query or a source-address-contingent query is never returned here,
    /// exactly as C notes at `forward.c:184-190`.
    pub fn lookup_frec_by_question(
        &self,
        now:           Instant,
        question_hash: [u8; 16],
        fwd_flags:     u32,
    ) -> Option<usize> {
        let hard_timeout = Duration::from_secs(4 * FREC_TIMEOUT_SECS);
        for (i, f) in self.frecs.iter().enumerate() {
            if f.sentto.is_none() || f.question_hash != question_hash {
                continue;
            }
            if (f.flags & DEDUP_MASK) != (fwd_flags & DEDUP_MASK) {
                continue;
            }
            if now.duration_since(f.sent_at) >= hard_timeout {
                return None;
            }
            return Some(i);
        }
        None
    }

    /// Attach another client to an in-flight query.
    ///
    /// Returns `false` when the global `FrecSrc` budget (`ftabsize`) is
    /// exhausted, which is C's "we've been spammed with many duplicates"
    /// condition (`forward.c:232-245`) and makes the caller answer REFUSED.
    pub fn add_src(&mut self, idx: usize, src: FrecSrc) -> bool {
        if self.frec_src_count >= self.max_per_group {
            return false;
        }
        let Some(frec) = self.frecs.get_mut(idx) else { return false };
        frec.extra_srcs.push(src);
        self.frec_src_count += 1;
        true
    }

    /// Free every in-flight query older than `timeout`, returning how many.
    ///
    /// C has no timer for this — it garbage-collects inside `get_new_frec()`
    /// (`forward.c:3140-3146`) — but an idle forwarder here would otherwise
    /// hold an unanswered query's source socket open indefinitely, and that
    /// socket is exactly the thing we are trying not to leave predictable.
    pub fn expire_old(&mut self, timeout: Duration) -> usize {
        let now = Instant::now();
        let stale: Vec<usize> = self
            .frecs
            .iter()
            .enumerate()
            .filter(|(_, f)| f.sentto.is_some() && now.duration_since(f.sent_at) > timeout)
            .map(|(i, _)| i)
            .collect();
        let n = stale.len();
        for idx in stale {
            self.free_frec(idx);
        }
        n
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

/// Default size of the random-socket pool (`daemon->numrrand`).
///
/// C derives it from the query table at startup — `daemon->numrrand =
/// daemon->ftabsize/2`, capped at a third of the fd limit
/// (`dnsmasq.c:425-431`) — which [`RandFdPool::sized_for`] reproduces.  This
/// constant is the value that falls out of the default `ftabsize` of 150.
pub const RANDOM_SOCKS: usize = 75;

/// Default `daemon->randport_limit` (`option.c:5986`): one source port per
/// transaction per server, so every send that is not a same-server repeat of an
/// existing one gets a port of its own.
pub const RANDPORT_LIMIT: usize = 1;

/// The pool slots one in-flight query holds, mirroring C's `struct randfd_list`
/// chain hanging off `frec->rfds`.
///
/// Ordered most-recently-promoted first, as C keeps it: `allocate_rfd()` moves
/// a reused entry to the head of the list (`forward.c:2881-2887`).
pub type RfdList = Vec<usize>;

/// A cached random-port UDP socket with reference counting.
///
/// Mirrors dnsmasq's `struct randfd`.  In the async Rust version we store
/// `tokio::net::UdpSocket` instead of a raw file descriptor so the socket is
/// owned by the pool and closed when the refcount reaches zero.
#[derive(Debug)]
pub struct RandomSocket {
    pub socket:     Arc<tokio::net::UdpSocket>,
    /// How many in-flight queries currently share this socket.
    pub refcount:   usize,
    /// Upstream server index this socket is "pinned" to.
    pub server_idx: Option<usize>,
    /// C's `refcount == 0xffff` marker: an overflow socket allocated outside
    /// the fixed pool because every slot was taken and none could be shared
    /// (`forward.c:2960-2990`).  It is never shared and is closed as soon as
    /// its one owner is done with it.
    pub temporary:  bool,
}

/// Pool of random-port UDP sockets — C's `daemon->randomsocks[]` array plus
/// `allocate_rfd()` / `free_rfds()`.
///
/// The point of the pool is *source-port* unpredictability.  A resolver that
/// sends every query from one socket offers an off-path attacker a single fixed
/// port, leaving only the 16-bit transaction ID to guess; with a socket per
/// in-flight transaction the attacker has to hit both, and the ports in use
/// change constantly.  So the ordering here matters: a *free* slot always wins
/// over sharing a live socket, because a free slot means a fresh `bind()` to
/// port 0 and therefore a fresh ephemeral port.  Sharing is the fallback that
/// keeps the fd count bounded, exactly as it is in C.
pub struct RandFdPool {
    /// Slots `0..numrrand` are the fixed pool; anything past that is a
    /// temporary overflow socket.
    slots:          Vec<Option<RandomSocket>>,
    /// Size of the fixed pool (`daemon->numrrand`).
    numrrand:       usize,
    /// `daemon->randport_limit`: how many source ports one transaction may hold
    /// for the same server before it starts reusing the ones it has.
    randport_limit: usize,
    /// Round-robin cursor for the share-an-existing-socket path (C's
    /// `static int finger` in `allocate_rfd()`).
    finger:         usize,
}

/// The process file-descriptor ceiling, C's `sysconf(_SC_OPEN_MAX)`
/// (`dnsmasq.c:56`).
///
/// C reads it once at startup and lets a negative return propagate into the
/// arithmetic; we treat an unavailable or nonsensical answer as "no ceiling"
/// instead, leaving the query table the only thing sizing the pool, because
/// `sysconf` failing is not a reason to run with one source port.
fn open_max() -> usize {
    // SAFETY: `sysconf` reads no memory we own and returns a plain `long`.
    let n = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if n > 0 { n as usize } else { usize::MAX }
}

impl RandFdPool {
    /// Create an empty pool of `numrrand` slots.
    pub fn new(numrrand: usize, randport_limit: usize) -> Self {
        Self {
            slots:          (0..numrrand).map(|_| None).collect(),
            numrrand,
            randport_limit: randport_limit.max(1),
            finger:         0,
        }
    }

    /// Size the pool the way `dnsmasq.c:425-431` does: half the query table,
    /// capped at a third of the process file-descriptor limit.
    ///
    /// Both halves matter.  Without the fd cap a large `--dns-forward-max`
    /// sizes the pool past the number of sockets the process may open, and
    /// every `bind()` beyond the limit fails — [`RandFdPool::allocate`] returns
    /// `None`, the query never leaves, and the client sees a REFUSED it has no
    /// way to explain.
    pub fn sized_for(ftabsize: usize, randport_limit: usize) -> Self {
        Self::sized_for_with_fd_limit(ftabsize, randport_limit, open_max())
    }

    /// [`RandFdPool::sized_for`] against an explicit fd limit, so the sizing
    /// rule can be tested without depending on the host's `ulimit`.
    ///
    /// Unlike C this never yields zero slots: a pool of none would push every
    /// query onto the shared/temporary path and defeat the point of the thing.
    pub fn sized_for_with_fd_limit(
        ftabsize:       usize,
        randport_limit: usize,
        max_fd:         usize,
    ) -> Self {
        Self::new((ftabsize / 2).min(max_fd / 3).max(1), randport_limit)
    }

    /// Allocate a source socket for a send to `server_idx`, recording it in the
    /// calling transaction's `fdl`.
    ///
    /// Mirrors `allocate_rfd()` (`forward.c:2843`), in the same order:
    ///
    /// 1. If this transaction already holds `randport_limit` sockets for this
    ///    server, promote the last of them to the head of its list and reuse it.
    /// 2. Otherwise take a free pool slot and `bind()` a **new** socket on an
    ///    OS-assigned ephemeral port.
    /// 3. Otherwise share an in-use socket for the same server that this
    ///    transaction does not already hold.
    /// 4. Otherwise open a temporary socket outside the pool.
    pub async fn allocate(
        &mut self,
        fdl:        &mut RfdList,
        server_idx: usize,
    ) -> Option<Arc<tokio::net::UdpSocket>> {
        // 1. Sockets this transaction already holds for this server.
        let mut held = 0usize;
        let mut last_held: Option<usize> = None;
        for (pos, &slot) in fdl.iter().enumerate() {
            if self.slot(slot).is_some_and(|r| r.server_idx == Some(server_idx)) {
                held += 1;
                last_held = Some(pos);
            }
        }
        if let (Some(pos), true) = (last_held, held >= self.randport_limit) {
            let slot = fdl.remove(pos);
            fdl.insert(0, slot);
            return Some(Arc::clone(&self.slot(slot)?.socket));
        }

        // 2. A free slot in the fixed pool — a fresh port.
        if let Some(idx) = self.slots[..self.numrrand].iter().position(Option::is_none) {
            let sock = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?);
            self.slots[idx] = Some(RandomSocket {
                socket:     Arc::clone(&sock),
                refcount:   1,
                server_idx: Some(server_idx),
                temporary:  false,
            });
            fdl.push(idx);
            return Some(sock);
        }

        // 3. Pool full: piggy-back on a live socket for the same server that we
        //    are not already using.
        let n = self.slots.len();
        for j in 0..n {
            let i = (j + self.finger) % n;
            let shareable = self.slots[i].as_ref().is_some_and(|r| {
                !r.temporary && r.refcount > 0 && r.server_idx == Some(server_idx)
            });
            if shareable && !fdl.contains(&i) {
                self.finger = i + 1;
                let slot = self.slots[i].as_mut()?;
                slot.refcount += 1;
                fdl.push(i);
                return Some(Arc::clone(&slot.socket));
            }
        }

        // 4. Nothing to share: a temporary socket, closed on release.
        let sock = Arc::new(tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?);
        let idx = self
            .slots
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| { self.slots.push(None); self.slots.len() - 1 });
        self.slots[idx] = Some(RandomSocket {
            socket:     Arc::clone(&sock),
            refcount:   1,
            server_idx: Some(server_idx),
            temporary:  true,
        });
        fdl.push(idx);
        Some(sock)
    }

    /// Release every socket a finished transaction held (C's `free_rfds()`,
    /// `forward.c:3012`).
    ///
    /// Dropping the last reference closes the socket, which is deliberate: a
    /// port that stays open past its transaction is a port an attacker has more
    /// time to find, and C closes the fd at exactly this point.
    pub fn free_rfds(&mut self, fdl: &mut RfdList) {
        for &idx in fdl.iter() {
            let Some(slot) = self.slots.get_mut(idx).and_then(Option::as_mut) else { continue };
            slot.refcount = slot.refcount.saturating_sub(1);
            if slot.temporary || slot.refcount == 0 {
                self.slots[idx] = None;
            }
        }
        fdl.clear();
        // Drop trailing overflow slots so the poll set does not grow forever.
        while self.slots.len() > self.numrrand && self.slots.last().is_some_and(Option::is_none) {
            self.slots.pop();
        }
    }

    /// Every live socket, paired with its slot index, for the reply poll set.
    ///
    /// The slot index is the identity a `Frec` records in its `rfds`, so the
    /// reply path can tell whether a datagram arrived on a socket the query it
    /// claims to answer actually sent from — C's check against `forward->rfds`
    /// at `forward.c:1181-1184`.
    pub fn sockets(&self) -> Vec<(usize, Arc<tokio::net::UdpSocket>)> {
        self.slots
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|r| (i, Arc::clone(&r.socket))))
            .collect()
    }

    /// Return the number of sockets currently open.
    pub fn active_count(&self) -> usize {
        self.slots.iter().flatten().count()
    }

    fn slot(&self, idx: usize) -> Option<&RandomSocket> {
        self.slots.get(idx).and_then(Option::as_ref)
    }
}

impl Default for RandFdPool {
    fn default() -> Self { Self::new(RANDOM_SOCKS, RANDPORT_LIMIT) }
}

// ──────────────────────────────────────────────────────────────────────────────
// Async forwarding engine
// ──────────────────────────────────────────────────────────────────────────────

/// Maximum DNS packet size (UDP).
pub const MAX_PACKET_SIZE: usize = 65535;

/// Default query timeout before a forwarded query is abandoned.
pub const QUERY_TIMEOUT_SECS: u64 = 10;

/// Default number of cached answers, matching upstream's `CACHESIZ`.
pub const DEFAULT_CACHE_SIZE: usize = 150;

/// Default `daemon->ftabsize` — upstream's `FTABSIZ` (`config.h`).
pub const FTABSIZE: usize = 150;

/// Owned snapshot of the locally-configured DNS data (`host-record`, `cname`,
/// `txt-record`, `mx-host`, `srv-host`, `ptr-record`, `naptr-record`, …) that
/// the query loop answers from before forwarding.
///
/// [`LocalConfig`] borrows its record slices, so it cannot be held across the
/// loop's `.await` points; this owned form lives in [`ForwardConfig`] and a
/// borrowed [`LocalConfig`] is rebuilt per query via [`LocalData::as_config`].
#[derive(Debug, Clone)]
pub struct LocalData {
    /// TTL applied to answers synthesised from config data (`local-ttl`).
    pub local_ttl:     u32,
    /// Payload size advertised in the OPT record re-attached to a locally
    /// generated answer (`edns-packet-max`).
    pub edns_pktsz:    u16,
    pub txt_records:   Vec<TxtRecord>,
    /// Arbitrary configured RR types (`dns-rr`); `class` holds the RR type.
    pub rr_records:    Vec<TxtRecord>,
    /// `mx-host` and `srv-host` entries (discriminated by `is_srv`).
    pub mx_records:    Vec<MxSrvRecord>,
    pub ptr_records:   Vec<PtrRecord>,
    pub host_records:  Vec<HostRecord>,
    pub cnames:        Vec<Cname>,
    pub naptr_records: Vec<Naptr>,
    /// `--interface-name` (`daemon->int_names`).
    pub int_names:     Vec<InterfaceName>,
    /// `--domain-needed` (`OPT_NODOTS_LOCAL`).
    pub nodots_local:  bool,
    /// `--synth-domain` (`daemon->synth_domains`).
    pub synth_domains: Vec<CondDomain>,
    /// `server` entries with `SERV_LITERAL_ADDRESS` set — see
    /// [`crate::rfc1035::LocalConfig::address_server_list`].
    pub address_server_list: Vec<crate::types::server::Server>,
    /// Sorted lookup table built once from `address_server_list` — see
    /// [`crate::rfc1035::LocalConfig::address_servers`].
    pub address_servers: crate::domain_match::ServerArray,
}

impl Default for LocalData {
    /// Everything empty, but `edns_pktsz` matching `Daemon::default()` — a zero
    /// there would advertise a zero-byte UDP payload in the OPT record.
    fn default() -> Self {
        Self {
            local_ttl:     0,
            edns_pktsz:    crate::types::daemon::EDNS_PKTSZ,
            txt_records:   Vec::new(),
            rr_records:    Vec::new(),
            mx_records:    Vec::new(),
            ptr_records:   Vec::new(),
            host_records:  Vec::new(),
            cnames:        Vec::new(),
            naptr_records: Vec::new(),
            int_names:     Vec::new(),
            nodots_local:  false,
            synth_domains: Vec::new(),
            address_server_list: Vec::new(),
            address_servers: crate::domain_match::ServerArray::build(&[], &[]),
        }
    }
}

impl LocalData {
    /// Borrow this snapshot as the [`LocalConfig`] view `answer_request` takes.
    pub fn as_config(&self) -> LocalConfig<'_> {
        LocalConfig {
            local_ttl:     self.local_ttl,
            edns_pktsz:    self.edns_pktsz,
            txt_records:   &self.txt_records,
            rr_records:    &self.rr_records,
            mx_records:    &self.mx_records,
            ptr_records:   &self.ptr_records,
            host_records:  &self.host_records,
            cnames:        &self.cnames,
            naptr_records: &self.naptr_records,
            int_names:     &self.int_names,
            nodots_local:  self.nodots_local,
            synth_domains: &self.synth_domains,
            address_servers: &self.address_servers,
            address_server_list: &self.address_server_list,
        }
    }

    /// `true` when no local data at all is configured, in which case
    /// `answer_request` could still answer from the cache.
    pub fn is_empty(&self) -> bool {
        self.txt_records.is_empty()
            && self.rr_records.is_empty()
            && self.mx_records.is_empty()
            && self.ptr_records.is_empty()
            && self.host_records.is_empty()
            && self.cnames.is_empty()
            && self.naptr_records.is_empty()
            && self.int_names.is_empty()
            && self.address_server_list.is_empty()
    }
}

/// Configuration for the forwarding engine.
#[derive(Debug, Clone)]
pub struct ForwardConfig {
    /// Ordered list of upstream resolver addresses.
    pub upstreams: Vec<SocketAddr>,
    /// Per-upstream domain restriction, parallel to `upstreams` (same index,
    /// same length): the `.domain` of the `Server` each entry came from
    /// (`server=/domain/ip`, `rev-server`, ...). An empty string means "no
    /// restriction" — a general resolver usable for any query that no
    /// domain-scoped entry claims. Mirrors upstream's per-server domain
    /// match in `forward.c`'s server selection.
    pub server_domains: Vec<String>,
    /// Per-query timeout.
    pub timeout: Duration,
    /// Maximum number of retries per query.
    pub max_retries: u8,
    /// Locally-configured DNS data consulted before forwarding.
    pub local: LocalData,
    /// Maximum number of entries in the answer cache (`cache-size`).
    /// `0` disables caching without disabling anything else on the reply path.
    pub cache_size: usize,
    /// `--min-cache-ttl`: floor applied to a cached DNS answer (0 = none).
    pub min_cache_ttl: u32,
    /// `--max-cache-ttl`: ceiling applied to a cached DNS answer (0 = none).
    pub max_cache_ttl: u32,
    /// `--max-ttl`: ceiling applied to a TTL as it is read off the wire
    /// (`rfc1035.c:752,834`).  Distinct from `max_cache_ttl`, which C applies
    /// later, inside `cache_insert()`.
    pub max_ttl: u32,
    /// `--neg-ttl`: negative-cache TTL used when a reply carries no SOA.
    pub neg_ttl: u32,
    /// `--no-negcache`: never cache NXDOMAIN / NODATA answers.
    pub no_neg_cache: bool,
    /// `--stop-dns-rebind`: reject private addresses in upstream answers.
    pub check_rebind: bool,
    /// `--rebind-localhost-ok`: exempt loopback addresses from that check.
    pub local_rebind_ok: bool,
    /// `--rebind-domain-ok`: domains exempt from the rebind check.
    pub no_rebind: Vec<RebindDomain>,
    /// `--bogus-nxdomain`: address ranges that mark an ISP wildcard answer.  A
    /// reply carrying one is rewritten into an empty NXDOMAIN.
    pub bogus_addr: Vec<BogusAddr>,
    /// `--ignore-address`: a reply carrying one of these addresses is dropped
    /// outright and never reaches the client.
    pub ignore_addr: Vec<BogusAddr>,
    /// `--filter-rr` / `--filter-a` / `--filter-aaaa`: RR types elided from an
    /// answer on its way back to the client.
    pub filter_rr: Vec<u16>,
    /// `--cache-rr` (`daemon->cache_rr`): RR types, beyond the always-cached
    /// `T_SRV`/`T_PTR`, that `extract_addresses` may cache via `F_RR`.  A
    /// `T_ANY` (255) entry means "cache every RR type" (`rfc1035.c:801`).
    pub cache_rr: Vec<u16>,
    /// `--dnssec` (`OPT_DNSSEC_VALID`).  Validation itself is not implemented —
    /// see `tasks.md` — but the option still gates the reply-side DNSSEC
    /// handling C puts behind it: clearing a DO bit the client did not set, and
    /// stripping DNSSEC RRs from the answer (`forward.c:750`, `forward.c:869`).
    pub dnssec_valid: bool,
    /// `--proxy-dnssec` (`OPT_DNSSEC_PROXY`): relay the upstream AD bit instead
    /// of clearing it (`forward.c:762-764`).
    pub dnssec_proxy: bool,
    /// `--dns-forward-max` (`daemon->ftabsize`): the cap on queries in flight to
    /// one server group, and on duplicate-client records overall.  Exceeding it
    /// makes the query REFUSED rather than queued.
    pub ftabsize: usize,
    /// `--port-limit` (`daemon->randport_limit`): source ports one transaction
    /// may hold per server.
    pub randport_limit: usize,
    /// The port this resolver listens on (`daemon->port`), used as the
    /// destination port when looking up a client connection's firewall mark
    /// (`conntrack.c:37`).
    pub port: u16,
    /// `--conntrack` (`OPT_CONNTRACK`): copy the firewall mark of the
    /// incoming client connection onto the outgoing upstream socket
    /// (`forward.c:531-535`).
    pub conntrack: bool,
    /// `--ipset` (`daemon->ipsets`). See [`ExtractConfig::ipsets`].
    pub ipsets: Vec<Ipsets>,
    /// `--connmark-allowlist-enable` (`OPT_CMARK_ALST_EN`): look up the
    /// client connection's firewall mark on reply and, if it is allow-listed
    /// for this query's answer, broadcast the resolved name(s) via ubus
    /// (`report_addresses`, `rfc1035.c:1148-1218`).
    pub cmark_alst_en: bool,
    /// `--connmark-allowlist` entries (`daemon->allowlists`).
    pub allowlists: Vec<crate::types::network::Allowlist>,
    /// `--connmark-allowlist-enable`'s mask argument (`daemon->allowlist_mask`).
    pub allowlist_mask: u32,
    /// `OPT_CLIENT_SUBNET` (`--add-subnet`): gates `check_source()` reply
    /// verification (`forward.c:727-731`) — a reply whose ECS echo doesn't
    /// match what we would have sent is discarded rather than delivered.
    pub client_subnet: bool,
    /// `--add-subnet` (IPv4 half): mask, and optional constant address
    /// override, consulted by [`crate::edns0::calc_subnet_opt`].
    pub add_subnet4: Option<crate::edns0::AddSubnetOpt>,
    /// `--add-subnet` (IPv6 half). See [`ForwardConfig::add_subnet4`].
    pub add_subnet6: Option<crate::edns0::AddSubnetOpt>,
    /// `--dump-file`/`--dump-mask`: the open pcap dump file, if configured.
    /// The Rust equivalent of `daemon->dumpfd`/`daemon->dump_mask`, opened
    /// once at startup by [`crate::dump::DumpHandle::init`].
    #[cfg(feature = "dump")]
    pub dump: Option<crate::dump::DumpHandle>,
    /// `--dns-loop-detect` (`OPT_LOOP_DETECT`): probe upstream servers for
    /// forwarding loops and stop selecting any that echo our own probe back.
    #[cfg(feature = "loop")]
    pub loop_detect: bool,
    /// Loop-detection state, index-aligned with `upstreams`/`server_domains`
    /// (same `forwardable` list `daemon_forward_config` built them from).
    /// [`ForwardEngine`] owns the live copy it mutates; this is the starting
    /// snapshot.
    #[cfg(feature = "loop")]
    pub loop_servers: Vec<crate::types::server::Server>,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            upstreams:     Vec::new(),
            server_domains: Vec::new(),
            timeout:       Duration::from_secs(QUERY_TIMEOUT_SECS),
            max_retries:   2,
            local:         LocalData::default(),
            cache_size:    DEFAULT_CACHE_SIZE,
            min_cache_ttl: 0,
            max_cache_ttl: 0,
            max_ttl:       0,
            neg_ttl:       0,
            no_neg_cache:  false,
            check_rebind:  false,
            local_rebind_ok: false,
            no_rebind:     Vec::new(),
            bogus_addr:    Vec::new(),
            ignore_addr:   Vec::new(),
            filter_rr:     Vec::new(),
            cache_rr:      Vec::new(),
            dnssec_valid:  false,
            dnssec_proxy:  false,
            ftabsize:      FTABSIZE,
            randport_limit: RANDPORT_LIMIT,
            port:          53,
            conntrack:     false,
            ipsets:        Vec::new(),
            cmark_alst_en: false,
            allowlists:    Vec::new(),
            allowlist_mask: 0,
            client_subnet: false,
            add_subnet4:   None,
            add_subnet6:   None,
            #[cfg(feature = "dump")]
            dump:          None,
            #[cfg(feature = "loop")]
            loop_detect:   false,
            #[cfg(feature = "loop")]
            loop_servers:  Vec::new(),
        }
    }
}

impl ForwardConfig {
    /// Build the [`ExtractConfig`] for a reply to a query for `qname`.
    ///
    /// The rebind check is decided per query name, not globally: C records
    /// `FREC_NOREBIND` at forward time from `domain_no_rebind()`
    /// (`forward.c:413`) and turns it back into `check_rebind` when the reply
    /// arrives (`forward.c:1416`).
    pub fn extract_config(&self, qname: &str) -> ExtractConfig {
        ExtractConfig {
            max_ttl:      self.max_ttl,
            neg_ttl:      self.neg_ttl,
            check_rebind: self.check_rebind && !domain_no_rebind(qname, &self.no_rebind),
            local_rebind_ok: self.local_rebind_ok,
            no_neg_cache: self.no_neg_cache,
            // DNSSEC validation is not wired into the forward path yet, so no
            // reply is ever marked authenticated.  See `tasks.md`.
            secure:       false,
            cache_rr:     self.cache_rr.clone(),
            ipsets:       self.ipsets.clone(),
        }
    }
}

/// What [`ForwardEngine::forward_query`] did with a client query.
///
/// The three non-forwarding outcomes are distinct because C answers them
/// differently: a duplicate is silently absorbed, a full table gets REFUSED
/// (`setup_reply()` with no flags, `domain-match.c:430`), and an unparseable or
/// unroutable query is dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ForwardOutcome {
    /// Sent upstream under the given transaction ID.
    Forwarded(u16),
    /// Folded onto an identical query already in flight; that query's reply
    /// will be fanned out to this client too.
    Duplicate,
    /// No capacity — the client must be answered REFUSED.
    Refused,
    /// Nothing could be done with it; no reply.
    Dropped,
}

/// One client waiting on an upstream answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplyTarget {
    /// Address to send the answer to.
    pub client:   SocketAddr,
    /// Index of the listening socket the query arrived on.  The reply has to go
    /// back out the same socket, or it would leave with the wrong source
    /// address once more than one listener is bound.
    pub listener: usize,
    /// The transaction ID this client used, restored into the reply.
    pub orig_id:  u16,
    /// Destination address the original query arrived on (`frec_src.dest`).
    /// Needed alongside `client` to look up this connection's firewall mark
    /// for `--connmark-allowlist-enable` (`conntrack.c:37`, `forward.c:1439`).
    pub dest:     Option<std::net::IpAddr>,
}

/// What the engine decided about an upstream datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyAction {
    /// A good answer: process it under `flags` and deliver it to every client
    /// on the list.
    ///
    /// `flags` is the completed query's `FREC_*` bitfield.  It has to come out
    /// with the targets because the query record is freed here, and
    /// [`process_reply`] cannot do its job without it: whether the client sent
    /// an OPT record, asked for DNSSEC, or set CD is decided at *query* time and
    /// is what C threads into `process_reply()` (`forward.c:1429-1433`).
    Deliver { targets: Vec<ReplyTarget>, flags: u32 },
    /// The server failed the query and it has been re-sent to another one.
    Retried,
    /// Not an answer to anything outstanding, or it failed validation.
    Ignore,
}

/// Stateful DNS forwarding engine.
///
/// Owns the in-flight query table ([`FrecTable`]), the source-socket pool
/// ([`RandFdPool`]) and the forwarding configuration.  Used by
/// `run_forward_loop` but can also be driven manually for testing.
pub struct ForwardEngine {
    pub config:          ForwardConfig,
    pub table:           FrecTable,
    upstream_order:      Vec<usize>,
    /// Pool of random-port UDP sockets for query dispatch.
    pub rfd_pool:        RandFdPool,
    /// Live loop-detection state, index-aligned with `config.upstreams`.
    /// Seeded from `config.loop_servers` and mutated in place: cleared and
    /// re-probed by [`crate::loop_detect::send_probes`], flagged
    /// [`SERV_LOOP`](crate::types::server::SERV_LOOP) by
    /// [`crate::loop_detect::detect_loop`] on the incoming-query path.
    #[cfg(feature = "loop")]
    pub loop_servers: Vec<crate::types::server::Server>,
}

impl ForwardEngine {
    /// Create a new engine with the given configuration.
    pub fn new(config: ForwardConfig) -> Self {
        let n = config.upstreams.len();
        let ftabsize = config.ftabsize.max(1);
        #[cfg(feature = "loop")]
        let loop_servers = config.loop_servers.clone();
        Self {
            upstream_order: (0..n).collect(),
            table:          FrecTable::new(ftabsize),
            rfd_pool:       RandFdPool::sized_for(ftabsize, config.randport_limit),
            #[cfg(feature = "loop")]
            loop_servers,
            config,
        }
    }

    /// Whether `idx` (an index into `config.upstreams`) currently carries
    /// [`SERV_LOOP`](crate::types::server::SERV_LOOP) — set by
    /// [`crate::loop_detect::detect_loop`] once a probe to that server has
    /// come back to us.  A server without loop-detection state (index out of
    /// range, or the `loop` feature disabled) is never excluded on this
    /// basis.
    #[cfg(feature = "loop")]
    fn is_looping(&self, idx: usize) -> bool {
        self.loop_servers
            .get(idx)
            .is_some_and(|s| s.flags & crate::types::server::SERV_LOOP != 0)
    }

    /// Hand any sockets freed along with a `Frec` back to the pool.
    fn release_rfds(&mut self) {
        let mut freed = self.table.take_released_rfds();
        if !freed.is_empty() {
            self.rfd_pool.free_rfds(&mut freed);
        }
    }

    /// Forward `pkt` upstream, or fold it onto an identical query already in
    /// flight.
    ///
    /// `listener` is the index of the socket the query arrived on, carried so
    /// the reply leaves by the same one. `dest` is the local address the
    /// query arrived on, when known — C's `local_addr` (`forward.c:2388-2393`),
    /// used only to look up the connection's firewall mark via conntrack.
    ///
    /// Mirrors `forward_query()` (`forward.c:165`) for the UDP client path.
    pub async fn forward_query(
        &mut self,
        pkt:      &[u8],
        client:   SocketAddr,
        listener: usize,
        dest:     Option<IpAddr>,
    ) -> ForwardOutcome {
        if pkt.len() < 12 {
            return ForwardOutcome::Dropped;
        }
        // A query whose question C cannot read is not forwarded — C would have
        // no way to recognise the answer — but it is not dropped either: it
        // falls through to the `reply:` label with `flags = 0`, which
        // `make_local_answer()` renders as REFUSED (`forward.c:337-343`,
        // `domain-match.c:411-430`).  Where C's `make_local_answer()` gives up
        // because `skip_questions()` cannot walk the question section, so does
        // ours — `make_refused_answer` returns `None` and the caller sends
        // nothing.
        let Some(qhash) = hash_questions(pkt) else { return ForwardOutcome::Refused };
        let orig_id = u16::from_be_bytes([pkt[0], pkt[1]]);
        let now = Instant::now();
        // The EDNS0/DNSSEC context this query is forwarded under: two clients
        // may only share one upstream transaction if theirs agree
        // (`forward.c:1867-1898`, then `forward.c:195-197`).
        let fwd_flags = fwd_flags_from_query(pkt);

        if let Some(idx) = self.table.lookup_frec_by_question(now, qhash, fwd_flags) {
            return self.join_in_flight(idx, now, orig_id, client, listener).await;
        }

        if self.config.upstreams.is_empty() {
            return ForwardOutcome::Dropped;
        }
        let candidates = self.candidate_servers(pkt);
        // A server whose loop probe has come back to us is excluded from
        // selection until the next probe round clears it — the runtime
        // equivalent of `ServerArray::build` skipping `SERV_LOOP` entries
        // (`domain_match.rs`), applied here because `ForwardEngine` selects
        // straight from `config.upstreams` rather than through a `ServerArray`.
        #[cfg(feature = "loop")]
        let candidates: Vec<usize> =
            candidates.into_iter().filter(|&i| !self.is_looping(i)).collect();
        let Some(server_idx) = next_server(&candidates, &HashSet::new(), usize::MAX) else {
            return ForwardOutcome::Dropped;
        };

        // Per-server-group admission control.  `force = false` is what the
        // client path always passes; only DNSSEC sub-queries may exceed the
        // limit, and those do not exist here yet.
        let Some(idx) = self.table.get_new_frec(now, server_idx, false) else {
            self.release_rfds();
            return ForwardOutcome::Refused;
        };
        self.release_rfds();

        let new_id = self.table.get_id();
        {
            let Some(frec) = self.table.get_mut(idx) else { return ForwardOutcome::Dropped };
            frec.sentto        = Some(server_idx);
            frec.new_id        = new_id;
            frec.question_hash = qhash;
            frec.flags         = fwd_flags;   // C: `forward->flags = fwd_flags` (`forward.c:373`)
            frec.stash         = Some(pkt.to_vec());
            frec.frec_src      = FrecSrc {
                source:  Some(client),
                dest,
                orig_id,
                fd:      listener as i32,
                ..FrecSrc::default()
            };
            frec.tried.insert(server_idx);
        }

        if !self.send_upstream(idx, server_idx).await {
            // Nothing went out — C frees the frec and returns REFUSED with
            // EDE_NETERR (`forward.c:583-586`).
            self.table.free_frec(idx);
            self.release_rfds();
            return ForwardOutcome::Refused;
        }
        inc_metric(Metric::DnsQueriesForwarded);
        ForwardOutcome::Forwarded(new_id)
    }

    /// Handle a query that matches one already in flight (`forward.c:194-323`).
    async fn join_in_flight(
        &mut self,
        idx:      usize,
        now:      Instant,
        orig_id:  u16,
        client:   SocketAddr,
        listener: usize,
    ) -> ForwardOutcome {
        let Some(frec) = self.table.get(idx) else { return ForwardOutcome::Dropped };
        let known_src = frec
            .srcs()
            .any(|s| s.orig_id == orig_id && s.source == Some(client));
        let age    = now.duration_since(frec.sent_at);
        let sentto = frec.sentto;

        if !known_src {
            let src = FrecSrc {
                source:  Some(client),
                orig_id,
                fd:      listener as i32,
                ..FrecSrc::default()
            };
            if !self.table.add_src(idx, src) {
                // Being blasted with the same question from many sources.  C
                // returns REFUSED, and explicitly deletes the frec once it has
                // aged out so the state can reset (`forward.c:236-245`).
                self.table.emit_query_full(now, None);
                if age >= Duration::from_secs(FREC_TIMEOUT_SECS) {
                    self.table.free_frec(idx);
                    self.release_rfds();
                }
                return ForwardOutcome::Refused;
            }
            // "Closely spaced identical queries cannot be a try and a retry, so
            // it's safe to wait for the reply from the first without forwarding
            // the second" (`forward.c:315-318`).
            if age < Duration::from_secs(2) {
                return ForwardOutcome::Duplicate;
            }
        }

        // A retry: re-send the stashed query, which picks up a source port of
        // its own unless this transaction is already at `randport_limit`.
        let Some(server_idx) = sentto else { return ForwardOutcome::Duplicate };
        if self.send_upstream(idx, server_idx).await {
            inc_metric(Metric::DnsQueriesForwarded);
            let id = self.table.get(idx).map_or(0, |f| f.new_id);
            ForwardOutcome::Forwarded(id)
        } else {
            ForwardOutcome::Duplicate
        }
    }

    /// Send a query's stashed packet to `server_idx` from a pooled source
    /// socket, recording that socket against the query.
    async fn send_upstream(&mut self, idx: usize, server_idx: usize) -> bool {
        let Some(&addr) = self.config.upstreams.get(server_idx) else { return false };
        let Some(frec) = self.table.get(idx) else { return false };
        let Some(mut out) = frec.stash.clone() else { return false };
        patch_id(&mut out, frec.new_id);
        let frec_src = frec.frec_src.clone();

        // The rfd list lives on the frec; lift it out for the pool call so the
        // table is not borrowed across the `await`.
        let mut rfds = self.table.get_mut(idx).map(|f| std::mem::take(&mut f.rfds)).unwrap_or_default();
        let sock = self.rfd_pool.allocate(&mut rfds, server_idx).await;
        if let Some(frec) = self.table.get_mut(idx) {
            frec.rfds = rfds;
        }
        let Some(sock) = sock else { return false };

        // Copy the connection mark of the incoming query onto the outgoing
        // socket (`forward.c:531-535`).
        if self.config.conntrack {
            apply_conntrack_mark(&sock, &frec_src, self.config.port);
        }

        sock.send_to(&out, addr).await.is_ok()
    }

    /// Validate an upstream reply against the query it claims to answer,
    /// returning that query's table index.
    ///
    /// This is the set of checks C makes before a reply is allowed to affect
    /// anything (`forward.c:1164-1209`):
    ///
    /// - the packet is a well-formed response (QR set, header-complete);
    /// - a query with that transaction ID is in flight;
    /// - the reply answers the *same question* that was sent — C gets this
    ///   from `lookup_frec()`, which matches name/class/type alongside the ID
    ///   (`forward.c:1173`);
    /// - **it arrived on one of the sockets that query was actually sent from**
    ///   — C: "Check that this arrived on the file descriptor we expected",
    ///   walking `forward->rfds` and returning if none matches
    ///   (`forward.c:1178-1199`).  `arrived_on` is the [`RandFdPool`] slot the
    ///   datagram was read from;
    /// - the reply came from the server the query was actually sent to
    ///   (`forward.c:1201-1209`).
    ///
    /// A 16-bit ID on its own is far too weak a credential to admit a packet
    /// that will be cached: matching on the ID alone turns one lucky forged
    /// datagram into a cache entry every later client is served from.  The
    /// source port the query left from is the other half of that credential,
    /// which is why each transaction gets its own — see [`RandFdPool`].  The
    /// arrival check above is what makes that half *count*: without it an
    /// attacker need only land on any one of the ports this resolver currently
    /// holds open, rather than the one specific port belonging to the query
    /// being poisoned.
    ///
    /// Returns `None` — leaving the query in flight, so the genuine answer can
    /// still arrive — for anything that fails a check.
    fn validate_reply(&self, reply: &[u8], from: SocketAddr, arrived_on: usize) -> Option<usize> {
        if reply.len() < 12 || reply[2] & 0x80 == 0 {
            return None;
        }
        let id  = u16::from_be_bytes([reply[0], reply[1]]);
        let idx = self.table.lookup_frec(Instant::now(), Some(id), 0, 0)?;
        let frec = self.table.get(idx)?;
        if hash_questions(reply)? != frec.question_hash {
            return None;
        }
        // C falls back to the per-server bound sockets (`server->sfd`) when the
        // fd is not in `forward->rfds`; this port has no such sockets — every
        // send goes out through the pool — so the rfd list is the whole set.
        if !frec.rfds.contains(&arrived_on) {
            return None;
        }
        if self.config.upstreams.get(frec.sentto?) != Some(&from) {
            return None;
        }
        Some(idx)
    }

    /// Process an upstream datagram.
    ///
    /// A SERVFAIL or REFUSED answer is not delivered while another server is
    /// left to ask: C re-enters `forward_query()` with the saved query in that
    /// case (`forward.c:1242-1250`).  Anything else completes the query, frees
    /// its source socket(s), and yields one [`ReplyTarget`] per waiting client.
    ///
    /// `arrived_on` is the [`RandFdPool`] slot the datagram was read from; see
    /// [`ForwardEngine::validate_reply`] for why it matters.
    pub async fn accept_reply(
        &mut self,
        reply:      &[u8],
        from:       SocketAddr,
        arrived_on: usize,
    ) -> ReplyAction {
        let Some(idx) = self.validate_reply(reply, from, arrived_on) else {
            return ReplyAction::Ignore;
        };

        let rcode = reply[3] & 0x0F;

        // `--ignore-address`: a NOERROR answer carrying a listed address is
        // dropped where it stands, *before* the failover and completion logic
        // below (`forward.c:1228-1230`).  C `return`s without freeing the frec,
        // so the query stays in flight and a later, honest answer from another
        // server can still be accepted — hence `Ignore` rather than a delivery
        // with no targets.
        if !self.config.ignore_addr.is_empty() && rcode == 0 {
            if let Ok(parsed) = DnsPacket::parse(reply) {
                if crate::rfc1035::check_for_ignored_address(&parsed, &self.config.ignore_addr) {
                    tracing::debug!("discarding DNS reply: --ignore-address match");
                    return ReplyAction::Ignore;
                }
            }
        }

        if rcode == 2 /* SERVFAIL */ || rcode == 5 /* REFUSED */ {
            if let Some(next_idx) = self.next_untried_server(idx) {
                if let Some(frec) = self.table.get_mut(idx) {
                    frec.retries = frec.retries.saturating_add(1);
                    frec.sentto  = Some(next_idx);
                    frec.tried.insert(next_idx);
                    // `sent_at` is deliberately not refreshed: C's
                    // `forward->time` is only ever set by `get_new_frec()`, so
                    // the group-occupancy count and the garbage collector stay
                    // anchored to when the *client* asked, and a query bouncing
                    // between broken servers still ages out.
                }
                if self.send_upstream(idx, next_idx).await {
                    inc_metric(Metric::DnsQueriesForwarded);
                    return ReplyAction::Retried;
                }
            }
        }

        let (targets, flags) = self
            .table
            .get(idx)
            .map(|f| {
                let targets: Vec<ReplyTarget> = f
                    .srcs()
                    .filter_map(|s| {
                        Some(ReplyTarget {
                            client:   s.source?,
                            listener: if s.fd < 0 { 0 } else { s.fd as usize },
                            orig_id:  s.orig_id,
                            dest:     s.dest,
                        })
                    })
                    .collect();
                (targets, f.flags)
            })
            .unwrap_or_default();

        self.table.free_frec(idx);
        self.release_rfds();
        ReplyAction::Deliver { targets, flags }
    }

    /// The next upstream server this query has not been sent to, if the retry
    /// budget allows one.
    fn next_untried_server(&self, idx: usize) -> Option<usize> {
        let frec = self.table.get(idx)?;
        if frec.retries >= self.config.max_retries {
            return None;
        }
        let candidates = match &frec.stash {
            Some(pkt) => self.candidate_servers(pkt),
            None => self.upstream_order.clone(),
        };
        next_server(&candidates, &frec.tried, frec.sentto?)
    }

    /// Restrict `self.upstream_order` to the servers eligible for `pkt`'s
    /// question name: the longest domain-suffix match among
    /// `config.server_domains`, or every server with no domain restriction
    /// (`""`) when nothing matches or `pkt`'s question can't be read.
    /// Mirrors upstream's per-server `.domain` scoping — the mechanism
    /// `server=/domain/ip` and `rev-server` both rely on for their upstream
    /// to actually be used. Returns `self.upstream_order` unmodified — no
    /// allocation, no behaviour change — when no server is domain-restricted.
    pub(crate) fn candidate_servers(&self, pkt: &[u8]) -> Vec<usize> {
        if !self.config.server_domains.iter().any(|d| !d.is_empty()) {
            return self.upstream_order.clone();
        }

        let qname = query_name_lower(pkt);

        let mut best_len: usize = 0;
        let mut candidates: Vec<usize> = Vec::new();
        for &idx in &self.upstream_order {
            let domain = self.config.server_domains.get(idx).map(String::as_str).unwrap_or("");
            if domain.is_empty() || !domain_matches_suffix(&qname, domain) {
                continue;
            }
            let dlen = domain.len();
            if candidates.is_empty() || dlen > best_len {
                best_len = dlen;
                candidates.clear();
                candidates.push(idx);
            } else if dlen == best_len {
                candidates.push(idx);
            }
        }

        if !candidates.is_empty() {
            return candidates;
        }

        // No domain-scoped server matches this name: fall back to the
        // general (unrestricted-domain) resolvers, if any.
        self.upstream_order
            .iter()
            .copied()
            .filter(|&idx| self.config.server_domains.get(idx).is_none_or(|d| d.is_empty()))
            .collect()
    }

    /// Expire timed-out queries, releasing their source sockets.  Returns how
    /// many were dropped.
    pub fn expire_queries(&mut self) -> usize {
        let n = self.table.expire_old(self.config.timeout);
        self.release_rfds();
        n
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

/// Look up the firewall mark of the client connection recorded in `frec_src`,
/// via an nfnetlink `CT_GET` query.
///
/// Mirrors `set_outgoing_mark()`'s call into `get_incoming_mark()`
/// (`forward.c:112-118`): both the client's source address and the local
/// address the query arrived on must be known, or there is no tuple to query.
#[cfg(all(feature = "conntrack", unix))]
fn conntrack_mark_for(frec_src: &FrecSrc, daemon_port: u16, istcp: bool) -> Option<u32> {
    let peer = frec_src.source?;
    let local = frec_src.dest?;
    crate::conntrack::get_incoming_mark(peer, local, istcp, daemon_port)
}

/// Copy the connection mark of the incoming query onto `sock`, if one can be
/// found. Mirrors `set_outgoing_mark()` (`forward.c:112-118`).
#[cfg(all(feature = "conntrack", unix))]
fn apply_conntrack_mark(sock: &tokio::net::UdpSocket, frec_src: &FrecSrc, daemon_port: u16) {
    if let Some(mark) = conntrack_mark_for(frec_src, daemon_port, false) {
        use std::os::unix::io::AsRawFd;
        let _ = set_outgoing_mark(sock.as_raw_fd(), mark);
    }
}

/// No-op stub when built without the `conntrack` feature, or on non-Unix
/// targets where there is no raw fd to attach `SO_MARK` to.
#[cfg(not(all(feature = "conntrack", unix)))]
fn apply_conntrack_mark(_sock: &tokio::net::UdpSocket, _frec_src: &FrecSrc, _daemon_port: u16) {}

/// `--connmark-allowlist-enable` admission decision for one client query.
///
/// Mirrors the guard around `is_query_allowed_for_mark()`'s only call site
/// (`forward.c:1905-1907`): the feature must be on, a mark must have been
/// found for this connection, and it must share at least one bit with
/// `allowlist_mask` — a query with no mark, or with a mark the mask ignores
/// entirely, always passes through unfiltered. Kept independent of the
/// `conntrack` feature (unlike the mark lookup itself) so the decision logic
/// is unit-testable without `CAP_NET_ADMIN` or a live conntrack table.
fn mark_admits_query(config: &ForwardConfig, mark: Option<u32>, name: &str) -> bool {
    if !config.cmark_alst_en {
        return true;
    }
    match mark {
        Some(mark) if mark & config.allowlist_mask != 0 => {
            crate::rfc1035::is_query_allowed_for_mark(
                mark,
                name,
                &config.allowlists,
                config.allowlist_mask,
            )
        }
        _ => true,
    }
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

/// Try to satisfy `pkt` from local config data and the cache, mirroring the
/// `answer_request()` call `udp_request()` makes before deciding to forward
/// (`forward.c`).
///
/// Returns `true` when a reply was sent to `src`, in which case the query must
/// *not* be forwarded.  A packet that fails to parse is left to the forwarding
/// path, matching upstream's behaviour of forwarding whatever `answer_request`
/// declines to answer.
/// Build a locally-answerable reply, if `cache`/`local` can supply one.
///
/// Takes only what `answer_request` needs — no socket — so the caller can
/// drop the cache lock before sending, instead of holding it across the
/// `send_to` await.
fn answer_locally(pkt: &[u8], cache: &mut DnsCache, local: &LocalData) -> Option<Vec<u8>> {
    let query = DnsPacket::parse(pkt).ok()?;
    let reply = answer_request(&query, cache, Instant::now(), &local.as_config())?;
    Some(reply.write().to_vec())
}

/// Run the DNS UDP forwarding event loop.
///
/// * `client_sock` — bound UDP socket facing DNS clients.
/// * `config`      — forwarding configuration (upstreams, timeout, local data).
///
/// Each client query is first offered to [`answer_request`] via
/// [`answer_locally`]; only queries it declines are forwarded upstream.  This
/// is the ordering upstream's `udp_request()` uses, and it is what lets a
/// purely local configuration (no upstream servers at all) answer queries.
///
/// Runs until an unrecoverable I/O error occurs.  Logs are omitted for
/// simplicity; callers should wrap this in a task and handle the error.
pub async fn run_forward_loop(
    client_sock: Arc<tokio::net::UdpSocket>,
    config: ForwardConfig,
) -> std::io::Result<()> {
    let cache = crate::cache::new_shared_cache(
        config.cache_size,
        config.min_cache_ttl,
        config.max_cache_ttl,
    );
    run_forward_loop_on(
        vec![DnsListener { sock: client_sock, check_dst: false }],
        None,
        config,
        cache,
    )
    .await
}

/// One bound DNS listening socket.
///
/// `--bind-interfaces` / `--bind-dynamic` produce one of these per allowed
/// interface address; the default wildcard mode produces one per address
/// family.
pub struct DnsListener {
    /// The bound UDP socket.
    pub sock: Arc<tokio::net::UdpSocket>,
    /// Upstream's `check_dst` (`forward.c:1612`):
    /// `!option_bool(OPT_NOWILD) || family == AF_INET6`.
    ///
    /// A wildcard socket obviously needs it — it receives datagrams for every
    /// local address.  An address-bound socket needs it too, because a query
    /// addressed to an internal interface can still arrive via an external one;
    /// only IPv4 under plain `--bind-interfaces` gives that up, which is why
    /// `network.c:1240-1250` recommends `--bind-dynamic` instead.
    pub check_dst: bool,
}

/// Wait until one of `listeners` has a datagram ready, returning its index.
///
/// `start` rotates the scan order so a busy listener cannot starve the others.
async fn next_readable(
    listeners: &[DnsListener],
    start:     usize,
) -> (usize, std::io::Result<()>) {
    std::future::poll_fn(|cx| {
        use std::task::Poll;
        for offset in 0..listeners.len() {
            let i = (start + offset) % listeners.len();
            if let Poll::Ready(r) = listeners[i].sock.poll_recv_ready(cx) {
                return Poll::Ready((i, r));
            }
        }
        Poll::Pending
    })
    .await
}

/// Receive one datagram from `listener`, with the destination metadata a
/// wildcard socket needs.
#[cfg(unix)]
fn recv_datagram(
    listener: &DnsListener,
    buf:      &mut [u8],
) -> std::io::Result<crate::network::RecvMeta> {
    use std::os::unix::io::AsRawFd;
    let fd = listener.sock.as_raw_fd();
    listener
        .sock
        .try_io(tokio::io::Interest::READABLE, || crate::network::recv_with_dest(fd, buf))
}

/// Non-Unix fallback: no control messages, so no arrival metadata.
#[cfg(not(unix))]
fn recv_datagram(
    listener: &DnsListener,
    buf:      &mut [u8],
) -> std::io::Result<crate::network::RecvMeta> {
    let (len, src) = listener.sock.try_recv_from(buf)?;
    Ok(crate::network::RecvMeta { len, src, dest: None, if_index: 0 })
}

/// Rebuild `parsed` as a wire packet with no resource records, keeping its
/// header flags, its question section and any OPT pseudo-RR, and forcing
/// `rcode`.
///
/// This is what C does when `extract_addresses()` returns non-zero, or when
/// `check_for_bogus_wildcard()` fires (`forward.c:813-832`): the client still
/// gets an answer packet, but an empty one.  Re-serialising rather than just
/// zeroing the count fields also drops the record bytes themselves, so nothing
/// is left dangling after the question section.
///
/// The OPT record survives because C's `resize_packet()` puts the pseudoheader
/// back once the sections are gone (`rfc1035.c:resize_packet`) — and because
/// the EDE option this reply is about to earn has nowhere else to live.
fn strip_records(parsed: &DnsPacket, rcode: u8) -> Vec<u8> {
    let additional: Vec<DnsRr> =
        parsed.additional.iter().filter(|rr| rr.rtype == 41).cloned().collect();
    let mut header = parsed.header;
    header.ancount = 0;
    header.nscount = 0;
    header.arcount = additional.len() as u16;
    header.set_rcode(rcode);
    DnsPacket {
        header,
        questions:  parsed.questions.clone(),
        answers:    Vec::new(),
        authority:  Vec::new(),
        additional,
    }
    .write()
    .to_vec()
}

/// Clear the AA (authoritative answer) bit in place.
///
/// A forced NXDOMAIN is ours, not the upstream server's, so the claim of
/// authority has to go with the records (`forward.c:818`).
fn clear_authoritative(pkt: &mut [u8]) {
    if pkt.len() >= DNS_HEADER_LEN {
        pkt[2] &= !HB3_AA;
    }
}

/// Feed an accepted upstream reply into the cache, and apply the answer-side
/// policy `process_reply()` applies around that call (`forward.c:806-846`).
///
/// `extract_addresses` runs for **every** accepted, non-truncated reply that
/// carries cacheable data — never gated on whether caching is enabled.  It is
/// also where DNS-rebind protection lives, so gating it on `cache_size` would
/// let `cache-size=0` silently disable `--stop-dns-rebind`.  A zero cache size
/// only makes the eventual insert fail to commit, exactly as C's zero
/// `daemon->cachesize` leaves `really_insert()` with no free `crec`.
///
/// Returns the [`Ede`] code the outcome earns, which is what the caller
/// reports back to an EDNS0-speaking client.
fn cache_upstream_reply(
    pkt:    &mut Vec<u8>,
    cache:  &mut DnsCache,
    now:    Instant,
    config: &ForwardConfig,
) -> Ede {
    let Ok(parsed) = DnsPacket::parse(pkt) else {
        // Unparseable body.  It cannot be re-serialised, so zero the counts in
        // place and SERVFAIL it, matching C's handling of `extract_addresses()`
        // returning 2.  The question section is known good — `validate_reply`
        // already hashed it.
        if pkt.len() >= DNS_HEADER_LEN {
            pkt[6..12].fill(0);
            set_rcode(pkt, 2 /* SERVFAIL */);
        }
        return Ede::Other;
    };
    let rcode = parsed.header.rcode();
    let Some(question) = parsed.questions.first() else { return Ede::Unset };
    let qname = question.name.to_lowercase();

    // `--bogus-nxdomain`.  C's comment is the whole story: "check_for_bogus_
    // wildcard() does its own caching, so don't call extract_addresses() if it
    // triggers" (`forward.c:809-821`).  It cannot fire on an answer that is
    // already NXDOMAIN, since there would be no address to match.
    if rcode != 3 /* NXDOMAIN */
        && crate::rfc1035::check_for_bogus_wildcard(&parsed, cache, now, &config.bogus_addr)
    {
        *pkt = strip_records(&parsed, 3 /* NXDOMAIN */);
        clear_authoritative(pkt);
        tracing::info!("bogus-nxdomain wildcard address for {qname}: answering NXDOMAIN");
        return Ede::Blocked;
    }

    let outcome = crate::cache::cache_reply(pkt, cache, &config.extract_config(&qname));
    // Push each match into the kernel ipset, mirroring `add_to_ipset()`
    // (`ipset.c:177-193`) being called from the `F_IPV4`/`F_IPV6` branch of
    // `extract_addresses()` (`rfc1035.c:1016`). `nftset=` config parsing is
    // explicitly rejected today (see `tasks.md`), so there is never an nftset
    // hit to deliver here yet.
    for hit in &outcome.ipset_hits {
        #[cfg(all(feature = "ipset", target_os = "linux"))]
        {
            if let Err(e) = crate::ipset::add_to_ipset(&hit.set_name, hit.addr, false) {
                tracing::warn!(set = %hit.set_name, addr = %hit.addr, error = %e, "failed to update ipset");
            } else {
                tracing::debug!(set = %hit.set_name, addr = %hit.addr, "added to ipset");
            }
        }
        #[cfg(not(all(feature = "ipset", target_os = "linux")))]
        {
            tracing::debug!(set = %hit.set_name, addr = %hit.addr, "matched configured ipset (ipset feature/platform not enabled)");
        }
    }
    match outcome.result {
        ExtractResult::Cached => Ede::Unset,
        ExtractResult::RebindBlocked => {
            // Sections cleared, rcode left alone: C logs and blocks but does
            // not rewrite the rcode for a rebind hit.
            *pkt = strip_records(&parsed, rcode);
            tracing::warn!("possible DNS-rebind attack detected: {qname}");
            Ede::Blocked
        }
        ExtractResult::BadPacket => {
            *pkt = strip_records(&parsed, 2 /* SERVFAIL */);
            Ede::Other
        }
    }
}

/// Set `RA` (recursion available) on a reply in place.
///
/// C does this to every reply it processes — `header->hb4 |= HB4_RA;`
/// (`forward.c:776`) — before the opcode and rcode checks, before the
/// truncation check, and before `extract_addresses()`.  Two consequences follow
/// and both are load-bearing:
///
/// * The client is told what *this* server offers, not what the upstream server
///   happened to answer with.  `dnsmasq` recurses on the client's behalf, so
///   `RA` is always true of it.
/// * The `RA` test guarding `cache_end_insert()` (`rfc1035.c:1124-1127`) is
///   consequently always true on the live path, so a reply from a
///   non-recursive nameserver — an authoritative server named by
///   `server=/domain/addr` answers `RA=0` — is cached like any other.  Skipping
///   this bit would leave caching inert for that whole class of configuration.
fn set_recursion_available(pkt: &mut [u8]) {
    if pkt.len() >= 12 {
        pkt[3] |= HB4_RA;
    }
}

/// Overwrite the RCODE nibble of a DNS packet in place.
fn set_rcode(pkt: &mut [u8], rcode: u8) {
    if pkt.len() >= 12 {
        pkt[3] = (pkt[3] & 0xF0) | (rcode & 0x0F);
    }
}

/// Run the DNS UDP forwarding event loop over a set of bound listeners.
///
/// `filter` is consulted for datagrams arriving on any listener whose
/// `check_dst` is set, which is where `--interface` / `--except-interface` /
/// `--listen-address` are enforced — upstream's `iface_check()` call in
/// `udp_request()` (`forward.c:1771-1780`).  Only IPv4 listeners under plain
/// `--bind-interfaces` skip it, and there the bind is the only access control
/// available (`forward.c:1612`).
pub async fn run_forward_loop_on(
    listeners: Vec<DnsListener>,
    filter:    Option<crate::network::ArrivalFilter>,
    config:    ForwardConfig,
    cache:     SharedDnsCache,
) -> std::io::Result<()> {
    if listeners.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no DNS listening sockets were bound",
        ));
    }
    let mut filter = filter;

    // Local data is owned by the loop; `LocalConfig` borrows from `local` and
    // is rebuilt per query.  The cache is shared with SIGHUP reload handling
    // (`dnsmasq::clear_cache_and_reload`), which is the only other thing that
    // ever touches it, so a `tokio::sync::Mutex` needs no fairness tuning.
    let local            = config.local.clone();
    let mut engine       = ForwardEngine::new(config);
    let mut client_buf   = vec![0u8; MAX_PACKET_SIZE];
    let mut upstream_buf = vec![0u8; MAX_PACKET_SIZE];
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    let mut scan_from = 0usize;
    let mut upstream_scan_from = 0usize;

    loop {
        // Outbound sockets come and go with the queries that own them, so the
        // reply poll set is rebuilt each time round rather than fixed at start.
        let upstream_socks = engine.rfd_pool.sockets();

        tokio::select! {
            // ── Incoming client query ─────────────────────────────────────────
            (idx, ready) = next_readable(&listeners, scan_from) => {
                ready?;
                scan_from = (idx + 1) % listeners.len();
                let listener = &listeners[idx];
                let meta = match recv_datagram(listener, &mut client_buf) {
                    Ok(meta) => meta,
                    // `poll_recv_ready` can produce a spurious wake-up; another
                    // reader is not possible here, but the kernel may still say
                    // "would block".
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => return Err(e),
                };
                // Re-apply the interface config per datagram: the address a
                // socket is bound to does not constrain which interface a
                // datagram for it arrived on.
                if listener.check_dst {
                    if let Some(f) = filter.as_mut() {
                        if !f.accepts(meta.if_index, meta.dest) {
                            continue;
                        }
                    }
                }
                let (len, src) = (meta.len, meta.src);
                let pkt = &client_buf[..len];
                // The local address the query arrived on: `IP_PKTINFO` gives
                // it per-datagram in wildcard mode; an address-bound listener
                // has no need of that control message, so its own bound
                // address is the answer (`forward.c:2388-2393`).
                let dest = meta.dest.or_else(|| listener.sock.local_addr().ok().map(|a| a.ip()));
                // Only forward DNS queries (QR bit == 0).
                if pkt.len() >= 12 && pkt[2] & 0x80 == 0 {
                    // `--dump-file`/`--dump-mask`: record the client query,
                    // mirroring `dump_packet_udp(DUMP_QUERY, ...)` at
                    // `forward.c:1818`.
                    #[cfg(feature = "dump")]
                    if let Some(dump) = &engine.config.dump {
                        let local = dest.map(|ip| SocketAddr::new(ip, engine.config.port));
                        dump.dump_packet_udp(
                            crate::types::constants::DUMP_QUERY,
                            pkt,
                            Some(src),
                            local,
                            crate::dump::DumpFallback::None,
                        );
                    }
                    // `--dns-loop-detect`: a query that is one of our own loop
                    // probes coming back marks the offending upstream server
                    // and is dropped outright — no reply, no forwarding, no
                    // local-data lookup (`detect_loop()` returning 1 makes
                    // `udp_request()` `return;` immediately, `forward.c:1862-1863`).
                    #[cfg(feature = "loop")]
                    let is_loop_probe = engine.config.loop_detect
                        && crate::rfc1035::extract_request(pkt).is_some_and(|(name, rtype)| {
                            crate::loop_detect::detect_loop(&name, rtype as u16, &mut engine.loop_servers)
                        });
                    #[cfg(not(feature = "loop"))]
                    let is_loop_probe = false;

                    if is_loop_probe {
                        continue;
                    }
                    // `--connmark-allowlist-enable`: a query whose connection
                    // mark is not allow-listed gets REFUSED here, before it
                    // ever reaches local-data lookup or forwarding — this
                    // gates the whole `answer_request`/forward decision, not
                    // just the forwarding half (`forward.c:1905-1918`).
                    let admitted = if engine.config.cmark_alst_en {
                        let qname = query_name_lower(pkt);
                        #[cfg(feature = "conntrack")]
                        let mark_lookup = dest.and_then(|d| {
                            crate::conntrack::get_incoming_mark(src, d, /* istcp: */ false, engine.config.port)
                        });
                        #[cfg(not(feature = "conntrack"))]
                        let mark_lookup: Option<u32> = None;

                        let allowed = mark_admits_query(&engine.config, mark_lookup, &qname);
                        #[cfg(all(feature = "conntrack", feature = "ubus"))]
                        if !allowed {
                            if let Some(mark) = mark_lookup {
                                crate::ubus::ubus_event_bcast_connmark_allowlist_refused(mark, &qname);
                            }
                        }
                        allowed
                    } else {
                        true
                    };

                    if !admitted {
                        if let Some(wire) = make_refused_answer(pkt, engine.config.local.edns_pktsz) {
                            #[cfg(feature = "dump")]
                            dump_reply(&engine.config.dump, &wire, dest, engine.config.port, src);
                            let _ = listener.sock.send_to(&wire, src).await;
                        }
                    } else {
                        // Local data and cache first — exactly as upstream does.
                        // The lock is dropped before `send_to` so a slow client
                        // send can't hold up a concurrent SIGHUP reload (or vice
                        // versa) — only the lookup itself needs the cache.
                        let local_wire = {
                            let mut cache = cache.lock().await;
                            answer_locally(pkt, &mut cache, &local)
                        };
                        if let Some(wire) = local_wire {
                            #[cfg(feature = "dump")]
                            dump_reply(&engine.config.dump, &wire, dest, engine.config.port, src);
                            let _ = listener.sock.send_to(&wire, src).await;
                            inc_metric(Metric::DnsLocalAnswered);
                        } else {
                            match engine.forward_query(pkt, src, idx, dest).await {
                                // The query table (or the duplicate-client budget)
                                // is full, or the question could not be read.  C
                                // answers REFUSED rather than dropping, so the
                                // client fails fast instead of timing out
                                // (`forward.c:337-343`, `forward.c:369`,
                                // `domain-match.c:430`).  `make_refused_answer`
                                // returning `None` is C's `make_local_answer()`
                                // bailing out on an unwalkable question section, in
                                // which case nothing is sent.
                                ForwardOutcome::Refused => {
                                    if let Some(wire) =
                                        make_refused_answer(pkt, engine.config.local.edns_pktsz)
                                    {
                                        #[cfg(feature = "dump")]
                                        dump_reply(&engine.config.dump, &wire, dest, engine.config.port, src);
                                        let _ = listener.sock.send_to(&wire, src).await;
                                    }
                                }
                                ForwardOutcome::Forwarded(_)
                                | ForwardOutcome::Duplicate
                                | ForwardOutcome::Dropped => {}
                            }
                        }
                    }
                }
            }
            // ── Upstream reply ────────────────────────────────────────────────
            (pos, ready) = next_upstream_readable(&upstream_socks, upstream_scan_from),
                    if !upstream_socks.is_empty() => {
                upstream_scan_from = pos + 1;
                // One sick outbound socket must not take the whole resolver
                // down; the query it belongs to will simply time out.
                if ready.is_err() { continue }
                // The pool slot — not the position in this pass's snapshot — is
                // the identity a query records in its `rfds`, and is what the
                // reply has to match.
                let (arrived_on, sock) = &upstream_socks[pos];
                let (len, upstream_addr) = match sock.try_recv_from(&mut upstream_buf) {
                    Ok(v)  => v,
                    Err(_) => continue,
                };
                let mut pkt = upstream_buf[..len].to_vec();

                // Nothing may act on this datagram until it has proved it
                // answers an outstanding query, from the server that query
                // went to.  A failed check leaves the query in flight so the
                // genuine answer can still be accepted.
                let (targets, flags) =
                    match engine.accept_reply(&pkt, upstream_addr, *arrived_on).await {
                        ReplyAction::Deliver { targets, flags } => (targets, flags),
                        ReplyAction::Retried | ReplyAction::Ignore => continue,
                    };

                // Everything C's `process_reply()` does to an accepted answer
                // before it is handed to the waiting clients: EDNS0 fix-up,
                // rebind and bogus-wildcard blocking, caching, RR filtering,
                // the DNSSEC strip and the EDE option (`forward.c:696-889`).
                //
                // `query_source` is the *primary* client's address (`targets[0]`,
                // C's `frec->frec_src.source`) — what `check_source()` recomputes
                // the expected ECS option against (`forward.c:1431`).
                let deliver = {
                    let mut cache = cache.lock().await;
                    let ctx = ReplyContext {
                        query_source: targets.first().map(|t| t.client.ip()),
                        ..ReplyContext::from_flags(flags)
                    };
                    process_reply(&mut pkt, &mut cache, Instant::now(), &engine.config, ctx)
                };
                if !deliver {
                    continue;
                }

                // One upstream answer, one reply per waiting client, each under
                // the ID that client used (`forward.c:1435-1440`).
                //
                // Parsed once, outside the per-client loop, purely for
                // `report_addresses` (`forward.c:1439-1444`) — the answer
                // section is identical for every target, only the wire
                // transaction ID changes per client below.
                #[cfg(all(feature = "conntrack", feature = "ubus"))]
                let parsed_for_report = if engine.config.cmark_alst_en {
                    crate::rfc1035::DnsPacket::parse(&pkt).ok()
                } else {
                    None
                };
                for target in targets {
                    let listener_idx = if target.listener < listeners.len() {
                        target.listener
                    } else {
                        0
                    };
                    patch_id(&mut pkt, target.orig_id);

                    // `--connmark-allowlist-enable`: look up this client
                    // connection's firewall mark and, if allow-listed,
                    // broadcast the resolved names via ubus
                    // (`forward.c:1439-1444`).
                    #[cfg(all(feature = "conntrack", feature = "ubus"))]
                    if engine.config.cmark_alst_en {
                        if let (Some(dest), Some(parsed)) = (target.dest, parsed_for_report.as_ref()) {
                            if let Some(mark) = crate::conntrack::get_incoming_mark(
                                target.client,
                                dest,
                                /* istcp: */ false,
                                engine.config.port,
                            ) {
                                if mark & engine.config.allowlist_mask != 0 {
                                    for reported in crate::rfc1035::report_addresses(
                                        parsed,
                                        mark,
                                        &engine.config.allowlists,
                                        engine.config.allowlist_mask,
                                    ) {
                                        crate::ubus::ubus_event_bcast_connmark_allowlist_resolved(
                                            mark,
                                            &reported.name,
                                            &reported.resolved,
                                            reported.ttl,
                                        );
                                    }
                                }
                            }
                        }
                    }

                    #[cfg(feature = "dump")]
                    if let Some(dump) = &engine.config.dump {
                        let local = listeners[listener_idx].sock.local_addr().ok();
                        dump.dump_packet_udp(
                            crate::types::constants::DUMP_REPLY,
                            &pkt,
                            local,
                            Some(target.client),
                            crate::dump::DumpFallback::None,
                        );
                    }
                    let _ = listeners[listener_idx].sock.send_to(&pkt, target.client).await;
                }
            }
            // ── Periodic expiry cleanup ───────────────────────────────────────
            _ = ticker.tick() => {
                let _expired = engine.expire_queries();
            }
        }
    }
}

/// Record a reply sent to a client, mirroring `dump_packet_udp(DUMP_REPLY,
/// ...)` at the various `forward.c` reply call sites (e.g. `forward.c:616`).
///
/// `local_ip`/`local_port` are the server's own address — the reply's
/// source; `client` is its destination.
#[cfg(feature = "dump")]
fn dump_reply(
    dump: &Option<crate::dump::DumpHandle>,
    wire: &[u8],
    local_ip: Option<IpAddr>,
    local_port: u16,
    client: SocketAddr,
) {
    if let Some(dump) = dump {
        let local = local_ip.map(|ip| SocketAddr::new(ip, local_port));
        dump.dump_packet_udp(
            crate::types::constants::DUMP_REPLY,
            wire,
            local,
            Some(client),
            crate::dump::DumpFallback::None,
        );
    }
}

/// Wait until one of `socks` has a datagram ready, returning its **position in
/// `socks`** — the caller reads the pool slot back out of the pair.
///
/// The outbound set changes as queries start and finish, so unlike
/// [`next_readable`] this works from a snapshot the caller takes for one pass
/// round the loop.  `start` rotates the scan so a socket being flooded — the
/// obvious thing to do once an attacker has found one of our ports — cannot
/// starve the replies every other query is waiting for.
async fn next_upstream_readable(
    socks: &[(usize, Arc<tokio::net::UdpSocket>)],
    start: usize,
) -> (usize, std::io::Result<()>) {
    std::future::poll_fn(|cx| {
        use std::task::Poll;
        for offset in 0..socks.len() {
            let i = (start + offset) % socks.len();
            if let Poll::Ready(r) = socks[i].1.poll_recv_ready(cx) {
                return Poll::Ready((i, r));
            }
        }
        Poll::Pending
    })
    .await
}

/// Build the REFUSED answer C returns when a query cannot be forwarded.
///
/// `setup_reply()` with no flags set (`domain-match.c:416`,
/// `rfc1035.c:setup_reply`): question section kept, every record section
/// dropped, QR and RA set, AA/TC/AD cleared, RCODE REFUSED.  Re-serialising
/// rather than editing the counts in place also drops the record bytes.
///
/// A query that carried an OPT record gets one back: C's `reply:` path calls
/// `add_pseudoheader()` after `make_local_answer()` whenever
/// `fwd_flags & FREC_HAS_PHEADER` (`forward.c:595-601`).  As there, the OPT we
/// return advertises *our* payload size rather than echoing the client's, drops
/// whatever options the client sent, and carries only the DO bit forward.
/// C also attaches an EDE option when it has a reason code to report; this path
/// has none of C's `ede` plumbing yet — see `tasks.md`.
fn make_refused_answer(query: &[u8], edns_pktsz: u16) -> Option<Vec<u8>> {
    let parsed = DnsPacket::parse(query).ok()?;
    let mut header = parsed.header;
    crate::rfc1035::setup_reply(&mut header, 0);
    let additional = parsed
        .additional
        .iter()
        .find(|rr| rr.rtype == 41)
        .map(|opt| DnsRr {
            name:  String::new(), // root: OPT always has an empty name
            rtype: 41,            // T_OPT
            class: edns_pktsz,
            ttl:   opt.ttl & EDNS_DO, // extended rcode 0, version 0, DO copied
            rdata: Vec::new(),
        })
        .into_iter()
        .collect();
    Some(
        DnsPacket {
            header,
            questions:  parsed.questions.clone(),
            answers:    Vec::new(),
            authority:  Vec::new(),
            additional,
        }
        .write()
        .to_vec(),
    )
}

// ─── Server domain matching ────────────────────────────────────────────────────

/// Read the (lower-cased) question name out of a raw query packet, or `""`
/// if the question can't be parsed.  Used only for domain-scoped server
/// selection — a query that fails to parse here already failed
/// `hash_questions()` earlier and was refused before reaching this code.
fn query_name_lower(pkt: &[u8]) -> String {
    let mut offset = 12;
    match crate::rfc1035::parse_question(pkt, &mut offset) {
        Ok(q) => q.name.to_lowercase(),
        Err(_) => String::new(),
    }
}

/// Case-insensitive, label-boundary-aware suffix match: `name` equals
/// `domain` or is a subdomain of it.
fn domain_matches_suffix(name: &str, domain: &str) -> bool {
    let dlen = domain.len();
    if dlen == 0 || name.len() < dlen {
        return false;
    }
    let start = name.len() - dlen;
    let suffix = &name[start..];
    suffix.eq_ignore_ascii_case(domain)
        && (name.len() == dlen || name.as_bytes().get(start.wrapping_sub(1)) == Some(&b'.'))
}

// ─── Reply processing helpers ─────────────────────────────────────────────────

/// A rebind-exclusion domain entry — the same type `Daemon::no_rebind` holds,
/// re-exported here because `domain_no_rebind` is the only consumer.
pub use crate::types::server::RebindDomain;

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

/// The per-query context [`process_reply`] runs under — C's `frec->flags`,
/// unpacked.
///
/// C passes these as five separate `int` parameters derived from the completed
/// query's flags (`forward.c:1429-1433`).  They are decided when the *client*
/// asks, not when the answer arrives, which is why they have to be carried out
/// of [`ForwardEngine::accept_reply`] alongside the reply targets.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReplyContext {
    /// `FREC_HAS_PHEADER`: the client's query carried an EDNS0 OPT record.
    /// When it did not, C added one on the way upstream and has to strip it off
    /// the answer — its `added_pheader` argument is exactly `!has_pheader`.
    pub has_pheader:       bool,
    /// `FREC_AD_QUESTION`: the client asked for authenticated data.
    pub ad_question:       bool,
    /// `FREC_DO_QUESTION`: the client set the DNSSEC OK bit.
    pub do_question:       bool,
    /// `FREC_CHECKING_DISABLED`: the client set CD in its query.
    pub checking_disabled: bool,
    /// The original client's address (`frec_src.source`) — C's `query_source`
    /// (`forward.c:1431`), the `peer` `check_source()` recomputes the expected
    /// ECS option against. `None` when the query had no waiting client left to
    /// take it from (should not happen in practice; treated as "no check").
    pub query_source: Option<std::net::IpAddr>,
}

impl ReplyContext {
    /// Unpack a `Frec`'s flag word.
    pub fn from_flags(flags: u32) -> Self {
        Self {
            has_pheader:       flags & FREC_HAS_PHEADER != 0,
            ad_question:       flags & FREC_AD_QUESTION != 0,
            do_question:       flags & FREC_DO_QUESTION != 0,
            checking_disabled: flags & FREC_CHECKING_DISABLED != 0,
            query_source:      None,
        }
    }
}

/// Byte offset of an OPT record's CLASS field — C's `sizep`, the pointer
/// `find_pseudoheader()` hands back so the caller can rewrite the advertised
/// payload size and the flags word behind it (`edns0.c:19`).
///
/// `opt_offset` is the start of the OPT RR (its name).  The layout from there
/// is name, TYPE(2), CLASS(2), TTL(4), RDLENGTH(2); `sizep` points at CLASS,
/// so `sizep + 2` is the extended RCODE, `sizep + 3` the EDNS version and
/// `sizep + 4 .. sizep + 6` the flags word holding the DO bit.
fn opt_sizep(pkt: &[u8], opt_offset: usize) -> Option<usize> {
    let mut pos = opt_offset;
    crate::rfc1035::skip_name(pkt, &mut pos).ok()?;
    (pos + 10 <= pkt.len()).then_some(pos + 2)
}

/// Attach an Extended DNS Error option to the reply's OPT record.
///
/// Port of the `add_pseudoheader(..., EDNS0_OPTION_EDE, ...)` call at the tail
/// of `process_reply()` (`forward.c:877-882`).  C passes `replace = 1`, so an
/// EDE already present is overwritten rather than duplicated; the reply's other
/// EDNS0 options, and its advertised payload size and flags, are kept.
///
/// Returns `None` when the reply has no pseudoheader to hang the option on —
/// C guards the call on `pheader` for the same reason.
fn attach_ede(pkt: &[u8], ede: Ede) -> Option<Vec<u8>> {
    let info = crate::edns0::find_pseudoheader(pkt)?;
    let mut options: Vec<Edns0Option> = info
        .options
        .iter()
        .filter(|o| o.code != EDNS0_OPTION_EDE)
        .cloned()
        .collect();
    options.push(Edns0Option {
        code: EDNS0_OPTION_EDE,
        // INFO-CODE is a 16-bit big-endian field; the EXTRA-TEXT C omits is
        // simply absent, which RFC 8914 sect 2 allows.
        data: (ede as i16 as u16).to_be_bytes().to_vec(),
    });
    crate::edns0::add_pseudoheader(pkt, info.udp_size, info.flags, &options).ok()
}

/// Turn an accepted upstream answer into the packet the client gets.
///
/// Port of `process_reply()` (`forward.c:696`), which upstream calls once per
/// accepted reply from `return_reply()` (`forward.c:1429`).  In order:
///
/// 1. restore the CD bit the client sent — C does this in its caller
///    (`forward.c:1418-1422`), but it belongs to the same reply rewrite;
/// 2. EDNS0: verify a `--add-subnet` ECS echo against `check_source()` and
///    discard the whole reply on mismatch; otherwise strip the OPT record
///    entirely when the client never sent one, or advertise *our* payload
///    size and clear a DO bit the client did not ask for;
/// 3. clear AD unless `--proxy-dnssec` (RFC 4035 sect 4.6 para 3), and set RA,
///    because we are the recursive resolver whatever upstream claimed to be;
/// 4. pass non-QUERY opcodes and non-NOERROR/NXDOMAIN rcodes straight through;
/// 5. for anything else that is not truncated: `--bogus-nxdomain`, then
///    `extract_addresses()` (caching, and the rebind check), then `--filter-rr`;
/// 6. strip DNSSEC RRs a DO=0 client must not be sent;
/// 7. attach an EDE option describing anything that was blocked or filtered.
///
/// Not yet ported, and tracked in `tasks.md`: DNSSEC validation itself (so C's
/// `bogusanswer`/`cache_secure` are always false here and the AD bit is never
/// *set*), `--alias` address rewriting (`do_doctor`), the NXDOMAIN→NODATA
/// conversion for locally-known names, and actually sending a matched
/// `--ipset` address to the kernel (the matching itself now happens in
/// `extract_addresses` — see `cache_upstream_reply`).
///
/// Returns `false` when the reply must be discarded outright rather than
/// delivered — currently only `check_source()`'s ECS-mismatch case
/// (`forward.c:727-731`), C's `return 0`. The caller must not send `*pkt` to
/// any client when this returns `false`.
pub fn process_reply(
    pkt:    &mut Vec<u8>,
    cache:  &mut DnsCache,
    now:    Instant,
    config: &ForwardConfig,
    ctx:    ReplyContext,
) -> bool {
    if pkt.len() < DNS_HEADER_LEN {
        return true;
    }

    // ── Restore the CD bit to the value in the query (`forward.c:1418-1422`) ─
    if ctx.checking_disabled {
        pkt[3] |= HB4_CD;
    } else {
        pkt[3] &= !HB4_CD;
    }

    // ── EDNS0 pseudoheader (`forward.c:720-758`) ─────────────────────────────
    //
    // `has_pheader` below tracks C's `pheader` *after* this block: it is only
    // true when the reply still carries an OPT record we may write to, which is
    // what gates the EDE option at the end.
    let mut has_pheader = false;
    let mut ext_rcode   = 0u8;
    if let Some(info) = crate::edns0::find_pseudoheader(pkt) {
        ext_rcode = info.ext_rcode;

        // `--add-subnet` reply verification (`check_source()`, `forward.c:727-731`):
        // reject a reply whose ECS echo doesn't match what we would have sent
        // for this client — a spoofed/mismatched echo is not something the
        // cache should ever remember.
        if config.client_subnet
            && !crate::edns0::check_source(
                pkt,
                ctx.query_source,
                config.add_subnet4.as_ref(),
                config.add_subnet6.as_ref(),
            )
        {
            tracing::warn!("discarding DNS reply: subnet option mismatch");
            return false;
        }

        if !ctx.has_pheader {
            // The client didn't send EDNS0, so it must not get an OPT record
            // back — C strips the one it added itself on the way upstream.
            if let Ok(stripped) = crate::rrfilter::filter_rr_types(pkt, &[41 /* T_OPT */]) {
                *pkt = stripped;
            }
        } else if let Some(sizep) = opt_sizep(pkt, info.offset) {
            has_pheader = true;
            // Advertise our max UDP packet to the client, not upstream's.
            pkt[sizep..sizep + 2].copy_from_slice(&config.local.edns_pktsz.to_be_bytes());
            // If the client didn't set the DO bit, but we did, reset it.
            if config.dnssec_valid && !ctx.do_question {
                let flags = u16::from_be_bytes([pkt[sizep + 4], pkt[sizep + 5]]) & !0x8000;
                pkt[sizep + 4..sizep + 6].copy_from_slice(&flags.to_be_bytes());
            }
        }
    }

    // ── Header bits (`forward.c:762-776`) ────────────────────────────────────
    // RFC 4035 sect 4.6 para 3: we have not validated this answer, so we must
    // not let the upstream server's AD bit tell the client that we did.
    if !config.dnssec_proxy {
        pkt[3] &= !HB4_AD;
    }
    set_recursion_available(pkt);

    // The full 12-bit rcode: four bits in the header, eight more in the OPT
    // record's extended-RCODE byte (`forward.c:723`).
    let rcode  = u16::from(pkt[3] & 0x0F) | (u16::from(ext_rcode) << 4);
    let opcode = (pkt[2] >> 3) & 0x0F;

    // Non-QUERY opcodes, and errors other than NXDOMAIN, carry nothing worth
    // inspecting (`forward.c:778-789`).
    if opcode != 0 || (rcode != 0 && rcode != 3) {
        return true;
    }

    let mut ede = Ede::Unset;

    // A truncated reply is relayed to the client as-is and nothing is cached
    // from it: C logs "truncated" and skips `extract_addresses()`
    // (`forward.c:791-792`), leaving the client to retry over TCP itself.  It
    // does not escalate to TCP on the client's behalf, so neither do we — see
    // `tasks.md` for the missing TCP listener.
    if is_truncated(pkt) {
        tracing::debug!("upstream reply truncated");
    } else {
        ede = cache_upstream_reply(pkt, cache, now, config);

        // `--filter-rr` / `--filter-a` / `--filter-aaaa` (`forward.c:848-849`).
        // Only a NOERROR answer has anything to filter.
        if pkt.len() >= DNS_HEADER_LEN && pkt[3] & 0x0F == 0 && !config.filter_rr.is_empty() {
            if let Ok((filtered, removed)) =
                crate::rrfilter::filter_configured_rr_types(pkt, &config.filter_rr)
            {
                if removed > 0 {
                    *pkt = filtered;
                    ede  = Ede::Filtered;
                }
            }
        }
    }

    // ── DNSSEC (`forward.c:853-873`) ─────────────────────────────────────────
    // Validation is not implemented, so there is never a bogus answer to turn
    // into SERVFAIL and never a secure one to set AD on.  What *is* live is the
    // last step: a client that didn't set DO must not be sent DNSSEC records.
    if config.dnssec_valid && !ctx.do_question {
        if let Ok(stripped) = crate::rrfilter::strip_dnssec_if_not_requested(pkt) {
            *pkt = stripped;
        }
    }

    // ── Extended DNS Error (`forward.c:877-882`) ─────────────────────────────
    if has_pheader && ede != Ede::Unset {
        if let Some(with_ede) = attach_ede(pkt, ede) {
            *pkt = with_ede;
        }
    }

    true
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
    use std::net::{Ipv4Addr, Ipv6Addr};
    use bytes::BytesMut;
    use std::net::SocketAddr;
    use crate::rfc1035::{write_name, write_question};
    use crate::rfc1035::DnsQuestion;

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }

    fn dummy_hash() -> [u8; 16] {
        [1u8; 16]
    }

    // ── FrecTable: in-flight query bookkeeping ────────────────────────────────

    /// Put one live query into the table, the way `forward_query` does.
    fn insert_frec(
        ft:         &mut FrecTable,
        orig_id:    u16,
        client:     SocketAddr,
        server_idx: usize,
        qhash:      [u8; 16],
    ) -> usize {
        let idx = ft
            .get_new_frec(Instant::now(), server_idx, false)
            .expect("table must have room");
        let new_id = ft.get_id();
        let frec = ft.get_mut(idx).expect("just allocated");
        frec.sentto        = Some(server_idx);
        frec.new_id        = new_id;
        frec.question_hash = qhash;
        frec.stash         = Some(vec![0u8; 12]);
        frec.frec_src      = FrecSrc {
            source: Some(client),
            orig_id,
            fd: 0,
            ..FrecSrc::default()
        };
        // Stand in for the pool slot a real send would have recorded, so the
        // reply path's arrival check has something to match.
        frec.rfds = vec![TEST_RFD_SLOT];
        frec.tried.insert(server_idx);
        idx
    }

    /// The pool slot `insert_frec` pretends the query was sent from.
    const TEST_RFD_SLOT: usize = 0;

    fn src_from(client: SocketAddr, orig_id: u16) -> FrecSrc {
        FrecSrc { source: Some(client), orig_id, fd: 0, ..FrecSrc::default() }
    }

    /// C draws outgoing IDs from `rand16()` (`get_id()`, `forward.c:3302`).
    /// A counter would make every ID after the first one predictable, which is
    /// half the credential a forged reply has to guess.
    #[test]
    fn frec_ids_are_not_sequential() {
        let mut ft = FrecTable::new(4096);
        let ids: Vec<u16> = (0..32)
            .map(|i| { let idx = insert_frec(&mut ft, i, dummy_addr(), 0, [i as u8; 16]); ft.get(idx).unwrap().new_id })
            .collect();

        let all_consecutive = ids.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
        assert!(
            !all_consecutive,
            "transaction IDs must be unpredictable, got a run of consecutive ids: {ids:?}",
        );
    }

    #[test]
    fn frec_ids_stay_unique_under_load() {
        let mut ft = FrecTable::new(4096);
        let ids: HashSet<u16> = (0..1000u16)
            .map(|i| {
                let mut qhash = [0u8; 16];
                qhash[..2].copy_from_slice(&i.to_be_bytes());
                let idx = insert_frec(&mut ft, i, dummy_addr(), 0, qhash);
                ft.get(idx).unwrap().new_id
            })
            .collect();
        assert_eq!(ids.len(), 1000, "every in-flight query needs its own id");
    }

    #[test]
    fn expire_old_frees_timed_out_and_leaves_fresh() {
        let mut ft = FrecTable::new(64);

        let old = insert_frec(&mut ft, 1, dummy_addr(), 0, [1u8; 16]);
        let fresh = insert_frec(&mut ft, 2, dummy_addr(), 0, [2u8; 16]);
        // Back-dated only after both exist: `get_new_frec` recycles a slot that
        // is already past `TIMEOUT`, so an aged entry would not survive the
        // second allocation.
        ft.get_mut(old).unwrap().sent_at = Instant::now() - Duration::from_secs(10);

        assert_eq!(ft.expire_old(Duration::from_secs(5)), 1);
        assert!(ft.get(old).unwrap().sentto.is_none(), "the stale query must be freed");
        assert!(ft.get(fresh).unwrap().sentto.is_some(), "the fresh query must survive");
    }

    /// Expiring a query has to hand its source socket back, or an unanswered
    /// query would keep a port pinned open for the life of the process.
    #[test]
    fn expire_old_releases_the_source_sockets() {
        let mut ft = FrecTable::new(64);
        let idx = insert_frec(&mut ft, 1, dummy_addr(), 0, [1u8; 16]);
        ft.get_mut(idx).unwrap().rfds = vec![3, 7];
        ft.get_mut(idx).unwrap().sent_at = Instant::now() - Duration::from_secs(10);

        ft.expire_old(Duration::from_secs(5));
        assert_eq!(ft.take_released_rfds(), vec![3, 7]);
        assert!(ft.take_released_rfds().is_empty(), "released slots are handed over once");
    }

    // ── FrecTable: duplicate-question lookup ──────────────────────────────────

    #[test]
    fn lookup_frec_by_question_finds_the_identical_question() {
        let mut ft = FrecTable::new(64);
        let idx = insert_frec(&mut ft, 1, dummy_addr(), 0, dummy_hash());
        assert_eq!(ft.lookup_frec_by_question(Instant::now(), dummy_hash(), 0), Some(idx));
    }

    #[test]
    fn lookup_frec_by_question_ignores_a_different_question() {
        let mut ft = FrecTable::new(64);
        insert_frec(&mut ft, 1, dummy_addr(), 0, dummy_hash());
        assert_eq!(ft.lookup_frec_by_question(Instant::now(), [9u8; 16], 0), None);
    }

    #[test]
    fn lookup_frec_by_question_ignores_a_completed_query() {
        let mut ft = FrecTable::new(64);
        let idx = insert_frec(&mut ft, 1, dummy_addr(), 0, dummy_hash());
        ft.free_frec(idx);
        assert_eq!(ft.lookup_frec_by_question(Instant::now(), dummy_hash(), 0), None);
    }

    /// A DNSSEC sub-query or a query whose answer depends on client-specific
    /// EDNS options must never absorb another client's question
    /// (`forward.c:194-196`).  Neither flag can appear in a client query's
    /// `fwd_flags`, so the equality test excludes them however it is called.
    #[test]
    fn lookup_frec_by_question_skips_context_specific_queries() {
        let mut ft = FrecTable::new(64);
        let idx = insert_frec(&mut ft, 1, dummy_addr(), 0, dummy_hash());
        ft.get_mut(idx).unwrap().flags = FREC_NO_CACHE;
        assert_eq!(ft.lookup_frec_by_question(Instant::now(), dummy_hash(), 0), None);
    }

    /// The EDNS/DNSSEC context has to *match*, not merely be absent: C compares
    /// `(f->flags & flagmask) == flags` (`forward.c:3226`).
    #[test]
    fn lookup_frec_by_question_requires_matching_edns_context() {
        let mut ft = FrecTable::new(64);
        let idx = insert_frec(&mut ft, 1, dummy_addr(), 0, dummy_hash());
        let edns = FREC_HAS_PHEADER | FREC_DO_QUESTION | FREC_AD_QUESTION;
        ft.get_mut(idx).unwrap().flags = edns;

        assert_eq!(
            ft.lookup_frec_by_question(Instant::now(), dummy_hash(), edns),
            Some(idx),
            "the same context folds together",
        );
        assert_eq!(
            ft.lookup_frec_by_question(Instant::now(), dummy_hash(), 0),
            None,
            "a plain query must not be folded onto a DO=1 one",
        );
        assert_eq!(
            ft.lookup_frec_by_question(Instant::now(), dummy_hash(), FREC_HAS_PHEADER),
            None,
            "EDNS without DO is a different context again",
        );
    }

    // ── fwd_flags_from_query / find_pseudoheader ──────────────────────────────

    /// Build a query, optionally with an OPT record, and with chosen header
    /// bits — the four inputs C reads to compute `fwd_flags`.
    fn ctx_query(opt: Option<u32>, hb4: u8) -> Vec<u8> {
        let mut pkt = DnsPacket {
            header:     crate::dns_protocol::DnsHeader {
                id: 1, hb3: 0, hb4, qdcount: 1, ..Default::default()
            },
            questions:  vec![crate::rfc1035::DnsQuestion {
                name: "example.com".into(), qtype: 1, qclass: 1,
            }],
            answers:    Vec::new(),
            authority:  Vec::new(),
            additional: Vec::new(),
        };
        if let Some(ttl) = opt {
            pkt.additional.push(DnsRr {
                name: String::new(), rtype: 41, class: 4096, ttl, rdata: Vec::new(),
            });
        }
        pkt.write().to_vec()
    }

    #[test]
    fn a_plain_query_has_no_context_flags() {
        assert_eq!(fwd_flags_from_query(&ctx_query(None, 0)), 0);
        assert_eq!(find_pseudoheader(&ctx_query(None, 0)), None);
    }

    #[test]
    fn an_opt_record_sets_has_pheader() {
        let pkt = ctx_query(Some(0), 0);
        assert_eq!(find_pseudoheader(&pkt), Some((4096, 0)));
        assert_eq!(fwd_flags_from_query(&pkt), FREC_HAS_PHEADER);
    }

    /// RFC 6840 5.7: DO implies the client can handle AD, so C sets both.
    #[test]
    fn the_do_bit_sets_do_and_ad() {
        let pkt = ctx_query(Some(EDNS_DO), 0);
        assert_eq!(
            fwd_flags_from_query(&pkt),
            FREC_HAS_PHEADER | FREC_DO_QUESTION | FREC_AD_QUESTION,
        );
    }

    #[test]
    fn the_header_ad_and_cd_bits_are_read() {
        assert_eq!(fwd_flags_from_query(&ctx_query(None, HB4_AD)), FREC_AD_QUESTION);
        assert_eq!(
            fwd_flags_from_query(&ctx_query(None, HB4_CD)),
            FREC_CHECKING_DISABLED,
        );
    }

    /// `find_pseudoheader` runs on unvalidated client input; a truncated or
    /// lying packet must yield `None`, never a panic.
    #[test]
    fn find_pseudoheader_survives_malformed_input() {
        assert_eq!(find_pseudoheader(&[]), None);
        assert_eq!(find_pseudoheader(&[0u8; 11]), None);
        // arcount claims a record that is not there.
        let mut lying = ctx_query(None, 0);
        lying[11] = 1;
        assert_eq!(find_pseudoheader(&lying), None);
        assert_eq!(fwd_flags_from_query(&lying), 0);
        // Every truncation of a valid EDNS query.
        let full = ctx_query(Some(EDNS_DO), 0);
        for n in 0..full.len() {
            let _ = find_pseudoheader(&full[..n]);
        }
    }

    // ── FrecTable: duplicate-client budget ────────────────────────────────────

    #[test]
    fn add_src_attaches_another_client() {
        let mut ft = FrecTable::new(64);
        let idx = insert_frec(&mut ft, 1, dummy_addr(), 0, dummy_hash());
        let other: SocketAddr = "127.0.0.1:5555".parse().unwrap();
        assert!(ft.add_src(idx, src_from(other, 2)));

        let srcs: Vec<u16> = ft.get(idx).unwrap().srcs().map(|s| s.orig_id).collect();
        assert_eq!(srcs, vec![1, 2], "the primary source stays first");
    }

    /// C caps `daemon->frec_src_count` at `ftabsize` across the whole table so
    /// one spammed question cannot exhaust memory (`forward.c:227-249`).
    #[test]
    fn add_src_is_capped_by_the_global_budget() {
        let mut ft = FrecTable::new(3);
        let idx = insert_frec(&mut ft, 0, dummy_addr(), 0, dummy_hash());
        for i in 1..=3u16 {
            let client: SocketAddr = format!("127.0.0.1:{}", 5000 + i).parse().unwrap();
            assert!(ft.add_src(idx, src_from(client, i)), "src {i} is within budget");
        }
        let client: SocketAddr = "127.0.0.1:6000".parse().unwrap();
        assert!(!ft.add_src(idx, src_from(client, 99)), "the budget must be enforced");
    }

    #[test]
    fn freeing_a_query_returns_its_clients_to_the_budget() {
        let mut ft = FrecTable::new(2);
        let first = insert_frec(&mut ft, 0, dummy_addr(), 0, [1u8; 16]);
        let extra: SocketAddr = "127.0.0.1:5001".parse().unwrap();
        assert!(ft.add_src(first, src_from(extra, 1)));
        assert!(ft.add_src(first, src_from(extra, 2)));

        let second = insert_frec(&mut ft, 10, dummy_addr(), 0, [2u8; 16]);
        assert!(!ft.add_src(second, src_from(extra, 3)), "budget is exhausted");

        ft.free_frec(first);
        assert!(ft.add_src(second, src_from(extra, 3)), "freeing must refund the budget");
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

    // ── candidate_servers (domain-scoped server selection) ──────────────────

    /// A `rev-server=192.168.1.0/24,10.0.0.1`-shaped config: a general
    /// resolver at index 0, and a reverse-zone-scoped resolver at index 1.
    fn engine_with_domain_scoped_server() -> ForwardEngine {
        let config = ForwardConfig {
            upstreams: vec!["10.0.0.9:53".parse().unwrap(), "10.0.0.1:53".parse().unwrap()],
            server_domains: vec![String::new(), "1.168.192.in-addr.arpa".to_string()],
            ..Default::default()
        };
        ForwardEngine::new(config)
    }

    #[test]
    fn candidate_servers_routes_matching_reverse_query_to_its_scoped_upstream() {
        let engine = engine_with_domain_scoped_server();
        let pkt = make_dns_query("1.1.168.192.in-addr.arpa", 12);
        assert_eq!(engine.candidate_servers(&pkt), vec![1]);
    }

    #[test]
    fn candidate_servers_falls_back_to_general_resolver_for_unmatched_name() {
        let engine = engine_with_domain_scoped_server();
        let pkt = make_dns_query("example.com", 1);
        assert_eq!(engine.candidate_servers(&pkt), vec![0]);
    }

    #[test]
    fn candidate_servers_prefers_the_longest_domain_match() {
        let config = ForwardConfig {
            upstreams: vec![
                "10.0.0.1:53".parse().unwrap(),
                "10.0.0.2:53".parse().unwrap(),
            ],
            server_domains: vec!["in-addr.arpa".to_string(), "1.168.192.in-addr.arpa".to_string()],
            ..Default::default()
        };
        let engine = ForwardEngine::new(config);
        let pkt = make_dns_query("1.1.168.192.in-addr.arpa", 12);
        assert_eq!(engine.candidate_servers(&pkt), vec![1]);
    }

    #[test]
    fn candidate_servers_is_the_full_order_when_nothing_is_domain_scoped() {
        let config = ForwardConfig {
            upstreams: vec!["10.0.0.1:53".parse().unwrap(), "10.0.0.2:53".parse().unwrap()],
            ..Default::default()
        };
        let engine = ForwardEngine::new(config);
        let pkt = make_dns_query("example.com", 1);
        assert_eq!(engine.candidate_servers(&pkt), vec![0, 1]);
    }

    #[test]
    fn candidate_servers_with_no_match_and_no_general_resolver_is_empty() {
        let config = ForwardConfig {
            upstreams: vec!["10.0.0.1:53".parse().unwrap()],
            server_domains: vec!["1.168.192.in-addr.arpa".to_string()],
            ..Default::default()
        };
        let engine = ForwardEngine::new(config);
        let pkt = make_dns_query("example.com", 1);
        assert!(engine.candidate_servers(&pkt).is_empty());
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

    /// The address every engine built by `engine_with_pending` forwards to.
    fn upstream_addr() -> SocketAddr {
        "127.0.0.1:5353".parse().unwrap()
    }

    /// Turn a query into the reply an honest server would send: same ID, same
    /// question, QR set.
    fn reply_for(query: &[u8], upstream_id: u16) -> Vec<u8> {
        let mut reply = query.to_vec();
        patch_id(&mut reply, upstream_id);
        reply[2] |= 0x80; // QR
        reply
    }

    fn client_addr() -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }

    /// An engine holding one outstanding query for `qname` — allocated through
    /// the same `FrecTable` path `forward_query` uses, but without a send, so
    /// the test needs no sockets.
    fn engine_with_pending(qname: &str, orig_id: u16) -> (ForwardEngine, Vec<u8>, u16) {
        let config = ForwardConfig {
            upstreams: vec![upstream_addr()],
            ..Default::default()
        };
        let mut engine = ForwardEngine::new(config);
        let mut query = make_dns_query(qname, 1);
        patch_id(&mut query, orig_id);
        let qhash = hash_questions(&query).expect("query must hash");
        let idx = insert_frec(&mut engine.table, orig_id, client_addr(), 0, qhash);
        let upstream_id = engine.table.get(idx).unwrap().new_id;
        (engine, query, upstream_id)
    }

    fn delivered(action: ReplyAction) -> Option<Vec<ReplyTarget>> {
        match action {
            ReplyAction::Deliver { targets, .. } => Some(targets),
            _ => None,
        }
    }

    #[tokio::test]
    async fn accept_reply_claims_the_matching_pending_query() {
        let (mut engine, query, upstream_id) = engine_with_pending("example.com", 42);
        let reply = reply_for(&query, upstream_id);

        let targets = delivered(engine.accept_reply(&reply, upstream_addr(), TEST_RFD_SLOT).await)
            .expect("a matching reply from the right server must be accepted");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].orig_id, 42);
        assert_eq!(targets[0].client, client_addr());
        // The entry is consumed, so a duplicate reply finds nothing.
        assert_eq!(engine.accept_reply(&reply, upstream_addr(), TEST_RFD_SLOT).await, ReplyAction::Ignore);
    }

    #[tokio::test]
    async fn accept_reply_rejects_an_unknown_transaction_id() {
        let (mut engine, query, upstream_id) = engine_with_pending("example.com", 42);
        let mut reply = reply_for(&query, upstream_id);
        patch_id(&mut reply, upstream_id.wrapping_add(1));
        assert_eq!(engine.accept_reply(&reply, upstream_addr(), TEST_RFD_SLOT).await, ReplyAction::Ignore);
    }

    /// C's match-anything sentinel for `lookup_frec()`'s `id` argument is `-1`
    /// on an `int` (`forward.c:3227`), and the only wire-derived value ever
    /// passed there is `ntohs(header->id)` (`forward.c:1173`) — so nothing an
    /// attacker can put in a packet can reach the sentinel.  Spelling the
    /// sentinel `0xFFFF` would move it *inside* the 16-bit ID space and let a
    /// forged reply carrying that one ID match whichever query happens to be in
    /// flight, reducing the transaction ID to zero bits of the credential and
    /// leaving the source port alone to defend the cache.
    #[tokio::test]
    async fn accept_reply_rejects_a_reply_using_the_wildcard_id() {
        let (mut engine, query, upstream_id) = engine_with_pending("example.com", 42);
        // Pin the query's ID away from 0xFFFF so the forgery cannot match it
        // by luck.
        let idx = engine
            .table
            .lookup_frec(Instant::now(), Some(upstream_id), 0, 0)
            .expect("query is in flight");
        engine.table.get_mut(idx).unwrap().new_id = 0x1234;

        let forged = reply_for(&query, u16::MAX);
        assert_eq!(
            engine.accept_reply(&forged, upstream_addr(), TEST_RFD_SLOT).await,
            ReplyAction::Ignore,
            "0xFFFF is an ordinary transaction ID, not a match-anything wildcard",
        );
        // The query survives, so the genuine answer still lands.
        let real = reply_for(&query, 0x1234);
        assert!(delivered(engine.accept_reply(&real, upstream_addr(), TEST_RFD_SLOT).await).is_some());
    }

    /// The other half of the same defect: a query legitimately issued with
    /// `new_id == 0xFFFF` — which `get_id()` produces roughly once in 65535 —
    /// must have its own answer matched to it, not to whatever entry the table
    /// happens to hold first.
    #[tokio::test]
    async fn accept_reply_matches_a_query_whose_id_is_0xffff() {
        let (mut engine, _query, upstream_id) = engine_with_pending("example.com", 42);
        // An unrelated query ahead of it in the table.
        let other = make_dns_query("other.test", 1);
        let other_idx = insert_frec(
            &mut engine.table,
            7,
            client_addr(),
            0,
            hash_questions(&other).expect("query must hash"),
        );
        let idx = engine
            .table
            .lookup_frec(Instant::now(), Some(upstream_id), 0, 0)
            .expect("query is in flight");
        assert!(idx < other_idx, "the unrelated query must be scanned first");
        engine.table.get_mut(other_idx).unwrap().new_id = u16::MAX;

        let reply = reply_for(&other, u16::MAX);
        let targets = delivered(engine.accept_reply(&reply, upstream_addr(), TEST_RFD_SLOT).await)
            .expect("0xFFFF must identify the query that actually used it");
        assert_eq!(targets, vec![ReplyTarget { client: client_addr(), listener: 0, orig_id: 7, dest: None }]);
    }

    #[tokio::test]
    async fn accept_reply_rejects_a_reply_from_another_address() {
        let (mut engine, query, upstream_id) = engine_with_pending("example.com", 42);
        let reply = reply_for(&query, upstream_id);
        let spoofer: SocketAddr = "127.0.0.2:5353".parse().unwrap();

        assert_eq!(
            engine.accept_reply(&reply, spoofer, TEST_RFD_SLOT).await,
            ReplyAction::Ignore,
            "a correct ID from the wrong source must not be accepted",
        );
        // The pending entry survives, so the real server can still answer.
        assert!(delivered(engine.accept_reply(&reply, upstream_addr(), TEST_RFD_SLOT).await).is_some());
    }

    /// C: "Check that this arrived on the file descriptor we expected"
    /// (`forward.c:1178-1184`).  Everything else about this datagram is right —
    /// the source address, the transaction ID, the question — so the arrival
    /// socket is the only thing rejecting it, and it is the thing that makes
    /// per-query source ports worth having.
    #[tokio::test]
    async fn accept_reply_rejects_a_reply_on_another_querys_socket() {
        let (mut engine, query, upstream_id) = engine_with_pending("example.com", 42);
        let reply = reply_for(&query, upstream_id);

        assert_eq!(
            engine.accept_reply(&reply, upstream_addr(), TEST_RFD_SLOT + 1).await,
            ReplyAction::Ignore,
            "a reply on a socket this query never sent from must not be accepted",
        );
        // The query is untouched, so the genuine answer still lands.
        assert!(delivered(engine.accept_reply(&reply, upstream_addr(), TEST_RFD_SLOT).await).is_some());
    }

    #[tokio::test]
    async fn accept_reply_rejects_a_reply_answering_a_different_question() {
        let (mut engine, _query, upstream_id) = engine_with_pending("example.com", 42);
        // Right ID, right source, wrong question — a cache-poisoning attempt.
        let forged = reply_for(&make_dns_query("victim.test", 1), upstream_id);

        assert_eq!(
            engine.accept_reply(&forged, upstream_addr(), TEST_RFD_SLOT).await,
            ReplyAction::Ignore,
            "a reply for a different name must not be accepted",
        );
    }

    #[tokio::test]
    async fn accept_reply_rejects_a_packet_without_the_qr_bit() {
        let (mut engine, query, upstream_id) = engine_with_pending("example.com", 42);
        let mut not_a_reply = reply_for(&query, upstream_id);
        not_a_reply[2] &= !0x80;
        assert_eq!(
            engine.accept_reply(&not_a_reply, upstream_addr(), TEST_RFD_SLOT).await,
            ReplyAction::Ignore,
        );
    }

    #[tokio::test]
    async fn accept_reply_rejects_a_truncated_header() {
        let (mut engine, _query, _id) = engine_with_pending("example.com", 42);
        assert_eq!(engine.accept_reply(&[0u8; 4], upstream_addr(), TEST_RFD_SLOT).await, ReplyAction::Ignore);
    }

    /// One upstream answer, one reply target per client that asked.
    #[tokio::test]
    async fn accept_reply_fans_out_to_every_waiting_client() {
        let (mut engine, query, upstream_id) = engine_with_pending("example.com", 42);
        let second: SocketAddr = "127.0.0.1:4321".parse().unwrap();
        let idx = engine
            .table
            .lookup_frec(Instant::now(), Some(upstream_id), 0, 0)
            .expect("query is in flight");
        assert!(engine.table.add_src(idx, src_from(second, 0xBEEF)));

        let reply = reply_for(&query, upstream_id);
        let targets = delivered(engine.accept_reply(&reply, upstream_addr(), TEST_RFD_SLOT).await)
            .expect("reply must be delivered");

        assert_eq!(
            targets,
            vec![
                ReplyTarget { client: client_addr(), listener: 0, orig_id: 42, dest: None },
                ReplyTarget { client: second,        listener: 0, orig_id: 0xBEEF, dest: None },
            ],
        );
    }

    #[test]
    fn forward_engine_expire_queries() {
        let config = ForwardConfig {
            timeout: Duration::from_millis(1),
            ..Default::default()
        };
        let mut engine = ForwardEngine::new(config);
        insert_frec(&mut engine.table, 1, client_addr(), 0, [0u8; 16]);
        // Wait for timeout.
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(engine.expire_queries(), 1);
    }

    // ── Upstream failure hand-off ─────────────────────────────────────────────

    /// C re-forwards a SERVFAIL/REFUSED answer to the next server rather than
    /// passing the failure on (`forward.c:1242-1250`).
    #[tokio::test]
    async fn servfail_is_retried_against_the_next_server() {
        let Ok(second) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };
        let Ok(second_addr) = second.local_addr() else { return };
        let config = ForwardConfig {
            upstreams:   vec![upstream_addr(), second_addr],
            max_retries: 1,
            ..Default::default()
        };
        let mut engine = ForwardEngine::new(config);
        let query = make_dns_query("example.com", 1);
        let qhash = hash_questions(&query).expect("query must hash");
        let idx = insert_frec(&mut engine.table, 42, client_addr(), 0, qhash);
        engine.table.get_mut(idx).unwrap().stash = Some(query.clone());
        let first_id = engine.table.get(idx).unwrap().new_id;

        let mut reply = reply_for(&query, first_id);
        reply[3] = (reply[3] & 0xF0) | 0x02; // SERVFAIL
        assert_eq!(engine.accept_reply(&reply, upstream_addr(), TEST_RFD_SLOT).await, ReplyAction::Retried);

        let frec = engine.table.get(idx).expect("query stays in flight for the retry");
        assert_eq!(frec.retries, 1);
        assert_eq!(frec.sentto, Some(1), "the retry goes to the other server");

        let mut buf = vec![0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(1), second.recv(&mut buf))
            .await
            .expect("the retry must actually be sent")
            .expect("recv must succeed");
        assert_eq!(hash_questions(&buf[..n]), Some(qhash));
    }

    #[tokio::test]
    async fn servfail_with_no_server_left_is_delivered_to_the_client() {
        let config = ForwardConfig {
            upstreams:   vec![upstream_addr()],
            max_retries: 1,
            ..Default::default()
        };
        let mut engine = ForwardEngine::new(config);
        let query = make_dns_query("example.com", 1);
        let qhash = hash_questions(&query).expect("query must hash");
        let idx = insert_frec(&mut engine.table, 99, client_addr(), 0, qhash);
        let new_id = engine.table.get(idx).unwrap().new_id;

        let mut reply = reply_for(&query, new_id);
        reply[3] = (reply[3] & 0xF0) | 0x02; // SERVFAIL
        let targets = delivered(engine.accept_reply(&reply, upstream_addr(), TEST_RFD_SLOT).await)
            .expect("with nowhere left to retry the failure goes to the client");
        assert_eq!(targets, vec![ReplyTarget { client: client_addr(), listener: 0, orig_id: 99, dest: None }]);
    }

    #[tokio::test]
    async fn retries_stop_at_max_retries() {
        let Ok(second) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };
        let Ok(second_addr) = second.local_addr() else { return };
        let config = ForwardConfig {
            upstreams:   vec![upstream_addr(), second_addr],
            max_retries: 0,
            ..Default::default()
        };
        let mut engine = ForwardEngine::new(config);
        let query = make_dns_query("example.com", 1);
        let qhash = hash_questions(&query).expect("query must hash");
        let idx = insert_frec(&mut engine.table, 7, client_addr(), 0, qhash);
        let new_id = engine.table.get(idx).unwrap().new_id;

        let mut reply = reply_for(&query, new_id);
        reply[3] = (reply[3] & 0xF0) | 0x02; // SERVFAIL
        assert!(
            delivered(engine.accept_reply(&reply, upstream_addr(), TEST_RFD_SLOT).await).is_some(),
            "max_retries = 0 must not open another upstream query",
        );
    }

    // ── forward_query admission control ───────────────────────────────────────

    /// The local address a query arrived on must reach the frec, or a
    /// conntrack mark lookup (`forward.c:2388-2393`) would have nothing to
    /// query against.
    #[tokio::test]
    async fn forward_query_records_the_arrival_destination_address() {
        let Ok(upstream) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };
        let Ok(upstream_addr) = upstream.local_addr() else { return };
        let config = ForwardConfig { upstreams: vec![upstream_addr], ..Default::default() };
        let mut engine = ForwardEngine::new(config);
        let query = make_dns_query("example.com", 1);
        let dest = Some(IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));

        let ForwardOutcome::Forwarded(new_id) =
            engine.forward_query(&query, client_addr(), 0, dest).await
        else {
            panic!("expected the query to forward");
        };
        let idx = engine
            .table
            .lookup_frec(Instant::now(), Some(new_id), 0, 0)
            .expect("query is in flight");
        assert_eq!(engine.table.get(idx).unwrap().frec_src.dest, dest);
    }

    /// `get_new_frec()` refuses once `ftabsize` queries are in flight to one
    /// server group, and C answers the client REFUSED (`forward.c:369`).
    #[tokio::test]
    async fn forward_query_refuses_once_the_group_is_full() {
        let Ok(upstream) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };
        let Ok(upstream_addr) = upstream.local_addr() else { return };
        let config = ForwardConfig {
            upstreams: vec![upstream_addr],
            ftabsize:  2,
            ..Default::default()
        };
        let mut engine = ForwardEngine::new(config);

        for i in 0..2u16 {
            let query = make_dns_query(&format!("q{i}.test"), 1);
            assert!(
                matches!(
                    engine.forward_query(&query, client_addr(), 0, None).await,
                    ForwardOutcome::Forwarded(_),
                ),
                "query {i} is within the limit",
            );
        }

        let query = make_dns_query("overflow.test", 1);
        assert_eq!(
            engine.forward_query(&query, client_addr(), 0, None).await,
            ForwardOutcome::Refused,
            "the third concurrent query to a full group must be refused",
        );
    }

    /// A second client asking the identical question joins the query in flight
    /// instead of opening another one (`forward.c:221-323`).
    #[tokio::test]
    async fn forward_query_folds_a_duplicate_question() {
        let Ok(upstream) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };
        let Ok(upstream_addr) = upstream.local_addr() else { return };
        let config = ForwardConfig { upstreams: vec![upstream_addr], ..Default::default() };
        let mut engine = ForwardEngine::new(config);

        let mut first = make_dns_query("shared.test", 1);
        patch_id(&mut first, 0x1111);
        assert!(matches!(
            engine.forward_query(&first, client_addr(), 0, None).await,
            ForwardOutcome::Forwarded(_),
        ));

        let mut second = make_dns_query("shared.test", 1);
        patch_id(&mut second, 0x2222);
        let other: SocketAddr = "127.0.0.1:4321".parse().unwrap();
        assert_eq!(
            engine.forward_query(&second, other, 1, None).await,
            ForwardOutcome::Duplicate,
        );

        assert_eq!(engine.table.active_count(), 1, "still one upstream transaction");
        let idx = engine
            .table
            .lookup_frec_by_question(Instant::now(), hash_questions(&first).unwrap(), 0)
            .expect("the query is in flight");
        let srcs: Vec<(u16, i32)> = engine
            .table
            .get(idx)
            .unwrap()
            .srcs()
            .map(|s| (s.orig_id, s.fd))
            .collect();
        assert_eq!(
            srcs,
            vec![(0x1111, 0), (0x2222, 1)],
            "each client keeps its own transaction ID and listener",
        );
    }

    /// A malformed query has no recognisable question, so C will not forward it
    /// — it would have no way to match the answer.  It does not go quiet
    /// either: it falls through to the `reply:` label with `flags = 0`, which
    /// `make_local_answer()` turns into a REFUSED answer for the client
    /// (`forward.c:337-343`, `domain-match.c:411-430`).
    #[tokio::test]
    async fn forward_query_refuses_a_question_it_cannot_read() {
        let config = ForwardConfig {
            upstreams: vec![upstream_addr()],
            ..Default::default()
        };
        let mut engine = ForwardEngine::new(config);
        // Header-only packet: qdcount is zero, so there is no question.
        let outcome = engine.forward_query(&[0u8; 12], client_addr(), 0, None).await;
        assert_eq!(outcome, ForwardOutcome::Refused);
        assert_eq!(engine.table.active_count(), 0);
        // And the REFUSED the caller sends is well-formed.
        let wire = make_refused_answer(&[0u8; 12], 4096)
            .expect("a header-only query is still answerable");
        assert_eq!(wire[3] & 0x0F, 5, "RCODE REFUSED");
        assert_eq!(wire[2] & 0x80, 0x80, "QR set");
    }

    /// The limit of that: C's REFUSED is built by `make_local_answer()`, which
    /// bails out when `skip_questions()` cannot walk the question section
    /// (`domain-match.c:429-430`), and no reply is sent at all.  A question
    /// name that runs off the end of the packet is exactly that case.
    #[test]
    fn make_refused_answer_declines_a_question_it_cannot_walk() {
        let mut truncated = vec![0u8; 12];
        truncated[5] = 1;      // qdcount = 1
        truncated.push(9);     // a 9-byte label with no bytes behind it
        assert_eq!(make_refused_answer(&truncated, 4096), None);
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
        let mut pool = RandFdPool::new(4, 1);
        let mut fdl = RfdList::new();
        let Some(_sock) = pool.allocate(&mut fdl, 0).await else { return };
        assert_eq!(pool.active_count(), 1);
        assert_eq!(fdl.len(), 1, "the transaction records the slot it took");
    }

    /// The whole point of the pool: two *different* transactions asking the
    /// same server must not share a source port while both are in flight.
    #[tokio::test]
    async fn rfd_pool_gives_each_transaction_its_own_port() {
        let mut pool = RandFdPool::new(4, 1);
        let (mut a, mut b) = (RfdList::new(), RfdList::new());
        let Some(s_a) = pool.allocate(&mut a, 0).await else { return };
        let Some(s_b) = pool.allocate(&mut b, 0).await else { return };
        assert_ne!(
            s_a.local_addr().unwrap(),
            s_b.local_addr().unwrap(),
            "concurrent queries to one server must leave from different ports",
        );
        assert_eq!(pool.active_count(), 2);
    }

    /// Within one transaction, `randport_limit` caps the ports it holds per
    /// server; past that it reuses the one it has (`forward.c:2881-2887`).
    #[tokio::test]
    async fn rfd_pool_reuses_a_transactions_own_socket_at_the_limit() {
        let mut pool = RandFdPool::new(4, 1);
        let mut fdl = RfdList::new();
        let Some(first) = pool.allocate(&mut fdl, 0).await else { return };
        let Some(again) = pool.allocate(&mut fdl, 0).await else { return };
        assert_eq!(first.local_addr().unwrap(), again.local_addr().unwrap());
        assert_eq!(pool.active_count(), 1);
        assert_eq!(fdl.len(), 1);
    }

    #[tokio::test]
    async fn rfd_pool_honours_a_higher_randport_limit() {
        let mut pool = RandFdPool::new(4, 2);
        let mut fdl = RfdList::new();
        let Some(first) = pool.allocate(&mut fdl, 0).await else { return };
        let Some(second) = pool.allocate(&mut fdl, 0).await else { return };
        assert_ne!(first.local_addr().unwrap(), second.local_addr().unwrap());
        assert_eq!(fdl.len(), 2);
    }

    #[tokio::test]
    async fn rfd_pool_free_closes_the_transactions_sockets() {
        let mut pool = RandFdPool::new(4, 1);
        let mut fdl = RfdList::new();
        if pool.allocate(&mut fdl, 7).await.is_none() { return }
        assert_eq!(pool.active_count(), 1);
        pool.free_rfds(&mut fdl);
        assert_eq!(pool.active_count(), 0);
        assert!(fdl.is_empty());
    }

    /// A socket two transactions ended up sharing stays open until the second
    /// one is done with it (C's refcount, `forward.c:3014`).
    #[tokio::test]
    async fn rfd_pool_shared_socket_survives_the_first_release() {
        // One slot forces the second transaction onto the sharing path.
        let mut pool = RandFdPool::new(1, 1);
        let (mut a, mut b) = (RfdList::new(), RfdList::new());
        let Some(s_a) = pool.allocate(&mut a, 0).await else { return };
        let Some(s_b) = pool.allocate(&mut b, 0).await else { return };
        assert_eq!(s_a.local_addr().unwrap(), s_b.local_addr().unwrap());

        pool.free_rfds(&mut a);
        assert_eq!(pool.active_count(), 1, "the other transaction still needs it");
        pool.free_rfds(&mut b);
        assert_eq!(pool.active_count(), 0);
    }

    /// With the pool full and nothing to share, C opens a temporary socket
    /// outside the pool rather than failing the query (`forward.c:2960-2990`).
    #[tokio::test]
    async fn rfd_pool_overflows_to_a_temporary_socket() {
        let mut pool = RandFdPool::new(1, 1);
        let (mut a, mut b) = (RfdList::new(), RfdList::new());
        let Some(s_a) = pool.allocate(&mut a, 0).await else { return };
        // Different server, so the one live socket cannot be shared.
        let Some(s_b) = pool.allocate(&mut b, 1).await else { return };
        assert_ne!(s_a.local_addr().unwrap(), s_b.local_addr().unwrap());
        assert_eq!(pool.active_count(), 2);

        pool.free_rfds(&mut b);
        assert_eq!(pool.active_count(), 1, "the overflow socket is closed at once");
    }

    #[tokio::test]
    async fn rfd_pool_sockets_lists_the_live_set() {
        let mut pool = RandFdPool::new(4, 1);
        let (mut a, mut b) = (RfdList::new(), RfdList::new());
        if pool.allocate(&mut a, 0).await.is_none() { return }
        if pool.allocate(&mut b, 1).await.is_none() { return }
        assert_eq!(pool.sockets().len(), 2);
        pool.free_rfds(&mut a);
        assert_eq!(pool.sockets().len(), 1);
    }

    #[test]
    fn rfd_pool_is_sized_from_the_query_table() {
        // `dnsmasq.c:427` — numrrand = ftabsize / 2, never zero.
        assert_eq!(RandFdPool::sized_for_with_fd_limit(150, 1, 1024).numrrand, 75);
        assert_eq!(RandFdPool::sized_for_with_fd_limit(1, 1, 1024).numrrand, 1);
    }

    /// `dnsmasq.c:428-429` — the pool is *also* capped at a third of the
    /// process fd limit.  Without that cap a large `--dns-forward-max` sizes
    /// the pool past the number of sockets the process may open, and every
    /// `bind()` past the limit fails: `allocate()` returns `None`, the send
    /// never happens, and the client is refused for no reason it can see.
    #[test]
    fn rfd_pool_is_capped_by_the_fd_limit() {
        assert_eq!(
            RandFdPool::sized_for_with_fd_limit(10_000, 1, 90).numrrand,
            30,
            "max_fd/3 wins over ftabsize/2",
        );
        assert_eq!(
            RandFdPool::sized_for_with_fd_limit(10, 1, 90).numrrand,
            5,
            "ftabsize/2 wins when it is the smaller of the two",
        );
        assert_eq!(
            RandFdPool::sized_for_with_fd_limit(10_000, 1, 2).numrrand,
            1,
            "the pool never collapses to zero slots",
        );
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
        let found = table.lookup_frec(now, Some(id), 0, 0);
        assert_eq!(found, Some(idx));
    }

    #[test]
    fn frec_table_lookup_frec_wildcard_id() {
        let mut table = FrecTable::new(100);
        let now = Instant::now();
        let idx = table.get_new_frec(now, 0, false).unwrap();
        table.get_mut(idx).unwrap().sentto = Some(0);
        table.get_mut(idx).unwrap().new_id = 42;
        // `None` is C's `id == -1`: match on the flags alone.  It is not
        // reachable from any 16-bit value on the wire.
        let found = table.lookup_frec(now, None, 0, 0);
        assert_eq!(found, Some(idx));
    }

    #[test]
    fn frec_table_lookup_frec_expired_returns_none() {
        let mut table = FrecTable::new(100);
        let long_ago = Instant::now() - Duration::from_secs(60);
        let idx = table.get_new_frec(long_ago, 0, false).unwrap();
        table.get_mut(idx).unwrap().sentto = Some(0);
        table.get_mut(idx).unwrap().new_id = 99;
        let found = table.lookup_frec(Instant::now(), Some(99), 0, 0);
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

    // ── conntrack_mark_for ───────────────────────────────────────────────────

    #[cfg(all(feature = "conntrack", unix))]
    #[test]
    fn conntrack_mark_for_returns_none_without_a_source() {
        let frec_src = FrecSrc {
            dest: Some(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 6))),
            ..FrecSrc::default()
        };
        assert_eq!(conntrack_mark_for(&frec_src, 53, false), None);
    }

    #[cfg(all(feature = "conntrack", unix))]
    #[test]
    fn conntrack_mark_for_returns_none_without_a_dest() {
        let frec_src = FrecSrc { source: Some(client_addr()), ..FrecSrc::default() };
        assert_eq!(conntrack_mark_for(&frec_src, 53, false), None);
    }

    /// A GET query for a flow the kernel has never seen finds no entry — the
    /// same "no match" path upstream leaves `gotit == 0` for
    /// (`conntrack.c:32`). This must not panic even without CAP_NET_ADMIN.
    #[cfg(all(feature = "conntrack", unix))]
    #[test]
    fn conntrack_mark_for_returns_none_for_an_unmatched_flow() {
        let frec_src = FrecSrc {
            source: Some("203.0.113.9:4321".parse().unwrap()),
            dest:   Some(IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 6))),
            ..FrecSrc::default()
        };
        assert_eq!(conntrack_mark_for(&frec_src, 53, false), None);
    }

    // ── mark_admits_query ────────────────────────────────────────────────────

    #[test]
    fn mark_admits_query_passes_through_when_the_feature_is_disabled() {
        let config = ForwardConfig { cmark_alst_en: false, ..ForwardConfig::default() };
        assert!(mark_admits_query(&config, Some(6), "blocked.example.com"));
    }

    #[test]
    fn mark_admits_query_passes_through_a_query_with_no_mark() {
        // `forward.c:1906`: `have_mark` must be true before the check even
        // runs — a client whose mark could not be looked up is never denied.
        let config = ForwardConfig {
            cmark_alst_en: true,
            allowlist_mask: u32::MAX,
            allowlists: vec![Allowlist { mark: 6, mask: u32::MAX, patterns: vec![] }],
            ..ForwardConfig::default()
        };
        assert!(mark_admits_query(&config, None, "blocked.example.com"));
    }

    #[test]
    fn mark_admits_query_passes_through_a_mark_outside_the_allowlist_mask() {
        // `forward.c:1906`: `mark & daemon->allowlist_mask` must be nonzero.
        let config = ForwardConfig {
            cmark_alst_en: true,
            allowlist_mask: 0xF0,
            allowlists: vec![Allowlist { mark: 6, mask: u32::MAX, patterns: vec![] }],
            ..ForwardConfig::default()
        };
        assert!(mark_admits_query(&config, Some(0x0F), "blocked.example.com"));
    }

    #[test]
    fn mark_admits_query_allows_a_name_matching_an_allowlist_pattern() {
        let config = ForwardConfig {
            cmark_alst_en: true,
            allowlist_mask: u32::MAX,
            allowlists: vec![Allowlist {
                mark: 6,
                mask: u32::MAX,
                patterns: vec!["*.example.com".to_string()],
            }],
            ..ForwardConfig::default()
        };
        assert!(mark_admits_query(&config, Some(6), "www.example.com"));
    }

    #[test]
    fn mark_admits_query_denies_a_name_not_matching_any_allowlist_pattern() {
        let config = ForwardConfig {
            cmark_alst_en: true,
            allowlist_mask: u32::MAX,
            allowlists: vec![Allowlist {
                mark: 6,
                mask: u32::MAX,
                patterns: vec!["*.example.com".to_string()],
            }],
            ..ForwardConfig::default()
        };
        assert!(!mark_admits_query(&config, Some(6), "www.example.org"));
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

    // ── set_recursion_available ───────────────────────────────────────────────

    /// `header->hb4 |= HB4_RA` (`forward.c:776`) — set the bit, touch nothing
    /// else, including the RCODE nibble that shares the octet.
    #[test]
    fn set_recursion_available_sets_only_the_ra_bit() {
        let mut pkt = vec![0u8; 12];
        pkt[3] = 0x03; // NXDOMAIN, RA clear
        set_recursion_available(&mut pkt);
        assert_eq!(pkt[3], HB4_RA | 0x03);
        assert!(pkt[..3].iter().all(|b| *b == 0) && pkt[4..].iter().all(|b| *b == 0));
    }

    #[test]
    fn set_recursion_available_ignores_a_runt_packet() {
        let mut pkt = vec![0u8; 4];
        set_recursion_available(&mut pkt);
        assert_eq!(pkt, vec![0u8; 4], "a header-less datagram must not be rewritten");
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

    fn reply_with_single_answer(name: &str, rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&0x0001u16.to_be_bytes()); // ID
        pkt.push(0x80); // QR=1
        pkt.push(0x00); // RCODE=NOERROR
        pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        pkt.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

        let mut body = BytesMut::new();
        write_question(&mut body, &DnsQuestion {
            name: name.to_string(),
            qtype: rtype,
            qclass: 1,
        });
        write_name(&mut body, name);
        body.extend_from_slice(&rtype.to_be_bytes());
        body.extend_from_slice(&1u16.to_be_bytes()); // class IN
        body.extend_from_slice(&60u32.to_be_bytes()); // ttl
        body.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        body.extend_from_slice(rdata);
        pkt.extend_from_slice(&body);
        pkt
    }

    /// Run `process_reply` over `pkt` with a throwaway cache, returning the
    /// rewritten packet parsed back out.
    fn run_process_reply(pkt: &[u8], config: &ForwardConfig, ctx: ReplyContext) -> Vec<u8> {
        run_process_reply_deliver(pkt, config, ctx).0
    }

    fn run_process_reply_deliver(pkt: &[u8], config: &ForwardConfig, ctx: ReplyContext) -> (Vec<u8>, bool) {
        let mut cache = DnsCache::new(100);
        let mut wire  = pkt.to_vec();
        let deliver = process_reply(&mut wire, &mut cache, Instant::now(), config, ctx);
        (wire, deliver)
    }

    fn bogus_v4(octets: [u8; 4], prefix: i32) -> BogusAddr {
        BogusAddr {
            is6: false,
            prefix,
            addr: crate::types::addr::AllAddr::Addr4(Ipv4Addr::from(octets)),
        }
    }

    #[test]
    fn process_reply_noerror_forwards() {
        let pkt = minimal_reply(0, true, 0, false);
        let out = run_process_reply(&pkt, &ForwardConfig::default(), ReplyContext::default());
        assert_eq!(out[3] & 0x0F, 0);
    }

    #[test]
    fn process_reply_nxdomain_forwards() {
        let pkt = minimal_reply(3, true, 0, false);
        let out = run_process_reply(&pkt, &ForwardConfig::default(), ReplyContext::default());
        assert_eq!(out[3] & 0x0F, 3);
    }

    /// A truncated reply is relayed untouched apart from the header bits — in
    /// particular nothing is extracted from it (`forward.c:791-792`).
    #[test]
    fn process_reply_truncated_forwards() {
        let pkt = minimal_reply(0, true, 0, true);
        let out = run_process_reply(&pkt, &ForwardConfig::default(), ReplyContext::default());
        assert_eq!(out[3] & 0x0F, 0);
        assert_ne!(out[2] & 0x02, 0, "the TC bit must survive");
    }

    #[test]
    fn process_reply_too_short_is_left_alone() {
        let out = run_process_reply(&[0u8; 5], &ForwardConfig::default(), ReplyContext::default());
        assert_eq!(out, vec![0u8; 5]);
    }

    /// A non-QUERY opcode is passed straight through: no extraction, no
    /// filtering (`forward.c:778-779`).
    #[test]
    fn process_reply_non_query_opcode_passes_through() {
        let pkt = minimal_reply(0, true, 4 /* NOTIFY */, false);
        let config = ForwardConfig { filter_rr: vec![1], ..ForwardConfig::default() };
        let out = run_process_reply(&pkt, &config, ReplyContext::default());
        assert_eq!(out[3] & 0x0F, 0);
    }

    #[test]
    fn process_reply_rebind_attack_ipv4_is_stripped() {
        let pkt = reply_with_single_answer("example.com", 1, &[192, 168, 1, 10]);
        let config = ForwardConfig { check_rebind: true, ..ForwardConfig::default() };
        let out = run_process_reply(&pkt, &config, ReplyContext::default());
        let parsed = DnsPacket::parse(&out).expect("the blocked answer must still be well formed");
        assert!(parsed.answers.is_empty(), "the private address must not survive");
    }

    #[test]
    fn process_reply_rebind_attack_ipv6_is_stripped() {
        let pkt = reply_with_single_answer("example.com", 28, &Ipv6Addr::LOCALHOST.octets());
        let config = ForwardConfig { check_rebind: true, ..ForwardConfig::default() };
        let out = run_process_reply(&pkt, &config, ReplyContext::default());
        let parsed = DnsPacket::parse(&out).expect("the blocked answer must still be well formed");
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn process_reply_rebind_exclusion_allows_private_answer() {
        let pkt = reply_with_single_answer("router.home.arpa", 1, &[192, 168, 1, 1]);
        let config = ForwardConfig {
            check_rebind: true,
            no_rebind: vec![rebind("home.arpa")],
            ..ForwardConfig::default()
        };
        let out = run_process_reply(&pkt, &config, ReplyContext::default());
        let parsed = DnsPacket::parse(&out).expect("the answer must still be well formed");
        assert_eq!(parsed.answers.len(), 1, "an excluded domain keeps its private address");
    }

    /// `--bogus-nxdomain` short-circuits extraction and forces an empty,
    /// non-authoritative NXDOMAIN (`forward.c:811-820`).
    #[test]
    fn process_reply_bogus_wildcard_becomes_empty_nxdomain() {
        let pkt = reply_with_single_answer("typo.test", 1, &[64, 94, 110, 11]);
        let config = ForwardConfig {
            bogus_addr: vec![bogus_v4([64, 94, 110, 11], 32)],
            ..ForwardConfig::default()
        };
        let out = run_process_reply(&pkt, &config, ReplyContext::default());
        let parsed = DnsPacket::parse(&out).expect("the forced NXDOMAIN must be well formed");
        assert_eq!(parsed.header.rcode(), 3);
        assert!(parsed.answers.is_empty());
        assert!(!parsed.header.is_aa(), "the forced NXDOMAIN is not authoritative");
        assert_eq!(parsed.questions.len(), 1, "the question section is preserved");
    }

    /// The CD bit the client gets is the one it sent, whatever upstream echoed
    /// (`forward.c:1418-1422`).
    #[test]
    fn process_reply_restores_the_checking_disabled_bit() {
        let mut pkt = minimal_reply(0, true, 0, false);
        pkt[3] |= HB4_CD;
        let out = run_process_reply(&pkt, &ForwardConfig::default(), ReplyContext::default());
        assert_eq!(out[3] & HB4_CD, 0, "a client that did not set CD must not get it back");

        let ctx = ReplyContext { checking_disabled: true, ..ReplyContext::default() };
        let out = run_process_reply(&minimal_reply(0, true, 0, false), &ForwardConfig::default(), ctx);
        assert_ne!(out[3] & HB4_CD, 0, "a client that set CD must get it back");
    }

    /// RFC 4035 sect 4.6 para 3 (`forward.c:762-764`).
    #[test]
    fn process_reply_clears_the_ad_bit_unless_proxying() {
        let mut pkt = minimal_reply(0, true, 0, false);
        pkt[3] |= HB4_AD;
        let out = run_process_reply(&pkt, &ForwardConfig::default(), ReplyContext::default());
        assert_eq!(out[3] & HB4_AD, 0);

        let config = ForwardConfig { dnssec_proxy: true, ..ForwardConfig::default() };
        let out = run_process_reply(&pkt, &config, ReplyContext::default());
        assert_ne!(out[3] & HB4_AD, 0, "--proxy-dnssec relays the upstream AD bit");
    }

    /// `check_source()` (`edns0.c:445-488`, wired at `forward.c:727-731`): a
    /// reply whose ECS echo doesn't match what we'd have sent for this client
    /// must be discarded outright, not delivered to the client.
    #[test]
    fn process_reply_rejects_mismatched_ecs_echo() {
        let client = IpAddr::V4("10.0.0.1".parse().unwrap());
        let other  = IpAddr::V4("192.168.0.1".parse().unwrap());
        let pkt = crate::edns0::add_source_addr(&minimal_reply(0, true, 0, false), other, 24)
            .expect("add_source_addr");
        let config = ForwardConfig {
            client_subnet: true,
            add_subnet4: Some(crate::edns0::AddSubnetOpt { mask: 24, const_addr: None }),
            ..ForwardConfig::default()
        };
        let ctx = ReplyContext { query_source: Some(client), ..ReplyContext::default() };
        let (_out, deliver) = run_process_reply_deliver(&pkt, &config, ctx);
        assert!(!deliver, "a mismatched ECS echo must be discarded");
    }

    /// The matching counterpart of `process_reply_rejects_mismatched_ecs_echo`:
    /// a reply whose ECS echo matches what we'd have sent is delivered as usual.
    #[test]
    fn process_reply_accepts_matching_ecs_echo() {
        let client = IpAddr::V4("10.0.0.1".parse().unwrap());
        let pkt = crate::edns0::add_source_addr(&minimal_reply(0, true, 0, false), client, 24)
            .expect("add_source_addr");
        let config = ForwardConfig {
            client_subnet: true,
            add_subnet4: Some(crate::edns0::AddSubnetOpt { mask: 24, const_addr: None }),
            ..ForwardConfig::default()
        };
        let ctx = ReplyContext {
            query_source: Some(client),
            has_pheader: true,
            ..ReplyContext::default()
        };
        let (_out, deliver) = run_process_reply_deliver(&pkt, &config, ctx);
        assert!(deliver, "a matching ECS echo must be delivered");
    }

    /// Without `--add-subnet` configured, ECS echoes are not checked at all —
    /// `check_source()` is gated on `option_bool(OPT_CLIENT_SUBNET)` in C
    /// (`forward.c:727`).
    #[test]
    fn process_reply_ignores_ecs_when_client_subnet_not_configured() {
        let client = IpAddr::V4("10.0.0.1".parse().unwrap());
        let other  = IpAddr::V4("192.168.0.1".parse().unwrap());
        let pkt = crate::edns0::add_source_addr(&minimal_reply(0, true, 0, false), other, 24)
            .expect("add_source_addr");
        let ctx = ReplyContext {
            query_source: Some(client),
            has_pheader: true,
            ..ReplyContext::default()
        };
        let (_out, deliver) = run_process_reply_deliver(&pkt, &ForwardConfig::default(), ctx);
        assert!(deliver, "no --add-subnet configured means no ECS verification");
    }

    #[test]
    fn process_reply_sets_recursion_available() {
        let pkt = minimal_reply(0, true, 0, false);
        let out = run_process_reply(&pkt, &ForwardConfig::default(), ReplyContext::default());
        assert_ne!(out[3] & HB4_RA, 0);
    }

    #[test]
    fn reply_context_unpacks_the_frec_flags() {
        let ctx = ReplyContext::from_flags(
            FREC_HAS_PHEADER | FREC_DO_QUESTION | FREC_AD_QUESTION | FREC_CHECKING_DISABLED,
        );
        assert_eq!(
            ctx,
            ReplyContext {
                has_pheader: true,
                ad_question: true,
                do_question: true,
                checking_disabled: true,
                query_source: None,
            }
        );
        assert_eq!(ReplyContext::from_flags(0), ReplyContext::default());
    }

    // ── make_refused_answer ───────────────────────────────────────────────────

    #[test]
    fn refused_answer_keeps_the_question_and_sets_refused() {
        let mut query = make_dns_query("full.test", 1);
        patch_id(&mut query, 0x9876);

        let wire  = make_refused_answer(&query, 4096).expect("a well-formed query must be answerable");
        let reply = DnsPacket::parse(&wire).expect("the refusal must be well formed");

        assert_eq!(reply.header.id, 0x9876, "the client's own ID comes back");
        assert_eq!(reply.header.rcode(), 5, "REFUSED, not an empty NOERROR");
        assert!(reply.header.is_response());
        assert!(reply.header.is_ra(), "we are still a recursive resolver");
        assert!(!reply.header.is_aa());
        assert_eq!(reply.questions.len(), 1);
        assert_eq!(reply.questions[0].name, "full.test");
        assert!(reply.answers.is_empty());
        assert!(reply.authority.is_empty());
        assert!(reply.additional.is_empty());
    }

    #[test]
    fn refused_answer_declines_an_unparseable_query() {
        assert!(make_refused_answer(&[0u8; 4], 4096).is_none());
    }

    /// C re-attaches the pseudo-header on the `reply:` path whenever the query
    /// carried one (`forward.c:595-601`), advertising our own payload size.
    #[test]
    fn refused_answer_re_attaches_the_pseudoheader() {
        let query = ctx_query(Some(EDNS_DO), 0);
        let wire  = make_refused_answer(&query, 1232).expect("an EDNS query must be answerable");
        let reply = DnsPacket::parse(&wire).expect("the refusal must be well formed");

        assert_eq!(reply.header.rcode(), 5);
        let opt = reply
            .additional
            .iter()
            .find(|rr| rr.rtype == 41)
            .expect("the OPT record comes back");
        assert_eq!(opt.class, 1232, "our payload size, not the client's");
        assert_eq!(opt.ttl, EDNS_DO, "only the DO bit is carried forward");
        assert!(opt.rdata.is_empty(), "the client's options are dropped");
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

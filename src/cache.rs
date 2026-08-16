//! DNS cache — idiomatic Rust port of `cache.c` from dnsmasq.
//!
//! The cache is a bounded LRU map keyed by `(name, type-flags)`.  Expired
//! entries are evicted lazily on lookup and proactively via `expire_old`.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Instant;

use lru::LruCache;

use crate::metrics::{inc_metric, Metric};
use crate::types::addr::AllAddr;
use crate::types::constants::{
    F_CNAME, F_CONFIG, F_DHCP, F_DNSSEC, F_DNSKEY, F_DS, F_FORWARD, F_HOSTS, F_IMMORTAL,
    F_IPV4, F_IPV6, F_NEG, F_NXDOMAIN, F_REVERSE, F_RR, UID_NONE,
};

// ---------------------------------------------------------------------------
// UID counter (mirrors C static `unsigned int uid = 0` in next_uid())
// ---------------------------------------------------------------------------

/// Minimum TTL enforced for DNSKEY and DS records.
///
/// Short TTLs can break DNSSEC validation in-flight; 60 s is the value
/// used by the reference C implementation.
pub const DNSSEC_MIN_TTL: u32 = 60;
static UID_COUNTER: AtomicU32 = AtomicU32::new(1);

/// Assign the next available UID.
///
/// Mirrors C `next_uid()`: the value `UID_NONE` (0) is never returned so that
/// it can be used as a sentinel meaning "no UID assigned yet".
pub fn next_uid() -> u32 {
    loop {
        let uid = UID_COUNTER.fetch_add(1, Ordering::Relaxed);
        if uid != UID_NONE {
            return uid;
        }
        // Wrapped to 0 — skip it
    }
}

// ---------------------------------------------------------------------------
// Type-flag mask
// ---------------------------------------------------------------------------

/// Mask of all "type" bits that identify what kind of record a cache entry is.
pub const TYPE_MASK: u32 =
    F_IPV4 | F_IPV6 | F_CNAME | F_NEG | F_NXDOMAIN | F_REVERSE
    | F_DNSKEY | F_DS | F_RR
    | F_DNSSEC; // extra type bits for DNSSEC records

/// Return only the type bits from a flags word.
pub fn type_flags(flags: u32) -> u32 {
    flags & TYPE_MASK
}

// ---------------------------------------------------------------------------
// Public data structures
// ---------------------------------------------------------------------------

/// Cache lookup key: lower-cased name + type-flag bits.
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct CacheKey {
    pub name:  String,
    /// Only the type bits (see `type_flags`).
    pub flags: u32,
}

/// A single DNS cache record — equivalent to `struct crec` in C.
#[derive(Debug, Clone)]
pub struct CacheRecord {
    /// The domain name this record belongs to.
    pub name:    String,
    /// Full set of F_* flag bits for this record.
    pub flags:   u32,
    /// Original TTL in seconds.
    pub ttl:     u32,
    /// Wall-clock instant at which this record expires.
    pub expires: Instant,
    /// Address / CNAME / DS / DNSKEY payload.
    pub addr:    Option<AllAddr>,
    /// Raw RR wire-format bytes (DNSSEC / arbitrary RR data).
    pub rdata:   Option<Vec<u8>>,
    /// Unique ID used to group records loaded together (e.g. from one hosts
    /// file).  `UID_NONE` (0) means no UID assigned.  Mirrors C `crec::uid`.
    pub uid:     u32,
}

/// The DNS cache — bounded LRU map with per-query statistics.
/// Snapshot of cache usage counters returned by [`DnsCache::stats`].
#[derive(Debug, Clone, Copy, Default)]
pub struct CacheStats {
    pub inserts:   u64,
    pub evictions: u64,
    pub hits:      u64,
    pub misses:    u64,
    /// Current number of entries in the cache (may include expired ones not yet swept).
    pub size:      usize,
}

/// Outcome of [`DnsCache::really_insert`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InsertOutcome {
    /// The record was successfully inserted (or updated).
    Inserted,
    /// Rejected: zero TTL and stale-caching is disabled.
    ZeroTtlDropped,
    /// A config/hosts/DHCP record with the *same* address already exists; the
    /// incoming DNS response was silently dropped (this is normal behaviour).
    BlockedSameAddr,
    /// A config/hosts/DHCP record with a *different* address exists; the
    /// incoming record was refused to avoid overwriting static config.
    BlockedConflict,
    /// The cache has no storage at all (`cache-size=0`), so nothing was kept.
    /// Mirrors C's `really_insert()` finding no free `crec` when
    /// `daemon->cachesize` is zero — the record is dropped, but everything the
    /// caller does *around* the insert (rebind checks, section clearing) still
    /// runs.
    CachingDisabled,
}

pub struct DnsCache {
    max_size: usize,
    records:  LruCache<CacheKey, CacheRecord>,
    /// Lower bound for DNS TTLs (0 = no minimum).  DNSKEY/DS entries use
    /// `DNSSEC_MIN_TTL` if that is larger.
    pub min_cache_ttl: u32,
    /// Upper bound for DNS TTLs (0 = no maximum).
    pub max_cache_ttl: u32,
    // statistics
    pub inserts:   u64,
    pub evictions: u64,
    pub hits:      u64,
    pub misses:    u64,
}

/// A [`DnsCache`] shared between the forwarding loop and reload handling.
///
/// Upstream's cache is a set of static globals in `cache.c`, reachable from
/// anywhere in the process; `run_forward_loop_on` and SIGHUP reload each need
/// their own reference to the same live cache, so the Rust port makes that
/// sharing explicit instead of inventing a second, unsynchronized copy.
pub type SharedDnsCache = std::sync::Arc<tokio::sync::Mutex<DnsCache>>;

/// Build a [`SharedDnsCache`] with the given size and TTL bounds.
pub fn new_shared_cache(max_size: usize, min_ttl: u32, max_ttl: u32) -> SharedDnsCache {
    std::sync::Arc::new(tokio::sync::Mutex::new(DnsCache::with_ttl_limits(
        max_size, min_ttl, max_ttl,
    )))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `rec` is expired at `now`.
/// Immortal records (F_IMMORTAL set) never expire.
pub fn record_is_expired(rec: &CacheRecord, now: Instant) -> bool {
    if rec.flags & F_IMMORTAL != 0 {
        return false;
    }
    rec.expires <= now
}

// ---------------------------------------------------------------------------
// DnsCache implementation
// ---------------------------------------------------------------------------

/// Return the list of parent-label names for `name`, from most specific to
/// least specific, stopping before the TLD.
///
/// Example: `"foo.bar.example.com"` → `["bar.example.com", "example.com"]`
///
/// Used by `insert_with_non_terminals()` to create non-terminal placeholders,
/// mirroring the `while ((name = strchr(name, '.')))` loop in C's
/// `make_non_terminals()`.
pub fn non_terminal_names(name: &str) -> Vec<String> {
    let mut parents = Vec::new();
    let mut rest = name;
    while let Some(pos) = rest.find('.') {
        rest = &rest[pos + 1..];
        // Only create a non-terminal if there is at least one more dot
        // (i.e., we're not at the TLD itself).
        if rest.contains('.') {
            parents.push(rest.to_string());
        }
    }
    parents
}

impl DnsCache {
    /// Create a new cache with the given maximum number of entries.
    ///
    /// `max_size == 0` is upstream's `cache-size=0`: the cache stores nothing
    /// and every lookup misses.  The backing LRU still needs a non-zero
    /// capacity, so [`Self::insert`] refuses instead — the same observable
    /// behaviour C gets from `really_insert()` never finding a free `crec`.
    pub fn new(max_size: usize) -> Self {
        let capacity = NonZeroUsize::new(max_size.max(1))
            .expect("max(1) is never zero");
        Self {
            max_size,
            records: LruCache::new(capacity),
            min_cache_ttl: 0,
            max_cache_ttl: 0,
            inserts:   0,
            evictions: 0,
            hits:      0,
            misses:    0,
        }
    }

    /// Create a cache with explicit TTL bounds.
    ///
    /// `min_ttl` and `max_ttl` are in seconds; 0 means "no limit".
    /// These bounds are enforced inside [`Self::really_insert`] and mirror the
    /// `daemon->min_cache_ttl` / `daemon->max_cache_ttl` fields in C.
    pub fn with_ttl_limits(max_size: usize, min_ttl: u32, max_ttl: u32) -> Self {
        let mut c = Self::new(max_size);
        c.min_cache_ttl = min_ttl;
        c.max_cache_ttl = max_ttl;
        c
    }

    /// Insert (or replace) a record in the cache.
    ///
    /// The LRU crate evicts the least-recently-used entry automatically when
    /// the cache is full; we track that as an eviction.
    pub fn insert(&mut self, rec: CacheRecord) {
        if self.max_size == 0 {
            return;
        }
        let key = CacheKey {
            name:  rec.name.to_lowercase(),
            flags: type_flags(rec.flags),
        };
        let was_full = self.records.len() == self.max_size;
        self.records.put(key, rec);
        self.inserts += 1;
        inc_metric(Metric::DnsCacheInserted);
        if was_full {
            self.evictions += 1;
            inc_metric(Metric::DnsCacheLiveFreed);
        }
    }

    /// Validated insert that mirrors C's `cache_insert()` + `really_insert()`.
    ///
    /// Applies:
    /// - **Zero-TTL rejection** — records with TTL 0 are dropped unless the
    ///   record already carries `F_IMMORTAL`.
    /// - **TTL clamping** — enforces `min_cache_ttl` / `max_cache_ttl` and,
    ///   for DNSKEY/DS records, `DNSSEC_MIN_TTL`.
    /// - **Conflict detection** — refuses to overwrite a static config/hosts/
    ///   DHCP record with a DNS answer.  If the address matches exactly the
    ///   existing static record the call is silently dropped (`BlockedSameAddr`);
    ///   otherwise it returns `BlockedConflict`.
    ///
    /// Only DNS-answer records (`!F_HOSTS & !F_DHCP & !F_CONFIG`) go through
    /// TTL clamping.  Static records are inserted directly (same as calling
    /// [`insert`] directly).
    pub fn really_insert(&mut self, mut rec: CacheRecord, now: Instant) -> InsertOutcome {
        use crate::types::constants::{F_DNSKEY, F_DS};

        let is_static = (rec.flags & (F_HOSTS | F_DHCP | F_CONFIG)) != 0;

        if !is_static {
            // Apply DNSSEC minimum TTL.
            if rec.flags & (F_DNSKEY | F_DS) != 0 {
                if rec.ttl < DNSSEC_MIN_TTL {
                    rec.ttl = DNSSEC_MIN_TTL;
                }
            } else {
                // Clamp against operator-configured bounds.
                if self.max_cache_ttl != 0 && rec.ttl > self.max_cache_ttl {
                    rec.ttl = self.max_cache_ttl;
                }
                if self.min_cache_ttl != 0 && rec.ttl < self.min_cache_ttl {
                    rec.ttl = self.min_cache_ttl;
                }
            }

            // Reject zero-TTL records (no stale-caching support yet).
            if rec.ttl == 0 && (rec.flags & F_IMMORTAL) == 0 {
                return InsertOutcome::ZeroTtlDropped;
            }

            // Recompute expiry after TTL clamping.
            rec.expires = now + std::time::Duration::from_secs(u64::from(rec.ttl));
        }

        // Conflict detection: look for an existing static record for this name.
        let key = CacheKey {
            name:  rec.name.to_lowercase(),
            flags: type_flags(rec.flags),
        };
        if let Some(existing) = self.records.peek(&key) {
            if (existing.flags & (F_HOSTS | F_DHCP | F_CONFIG)) != 0 {
                // Existing entry is from static config.
                if !is_static {
                    // Incoming DNS answer — check if address matches.
                    match (&existing.addr, &rec.addr) {
                        (Some(AllAddr::Addr4(ex)), Some(AllAddr::Addr4(r))) if ex == r => {
                            return InsertOutcome::BlockedSameAddr;
                        }
                        (Some(AllAddr::Addr6(ex)), Some(AllAddr::Addr6(r))) if ex == r => {
                            return InsertOutcome::BlockedSameAddr;
                        }
                        _ => return InsertOutcome::BlockedConflict,
                    }
                }
            }
        }

        if self.max_size == 0 {
            return InsertOutcome::CachingDisabled;
        }

        self.insert(rec);
        InsertOutcome::Inserted
    }

    /// Remaining lifetime of `rec`, in seconds, as it should be served to a
    /// client.
    ///
    /// Port of `crec_ttl()` (`rfc1035.c:1570`).  Immortal entries (config,
    /// `/etc/hosts`, DHCP) hold their configured TTL in the TTL field and are
    /// served with it verbatim; a cached DNS answer is served with
    /// `ttd - now`, so a client never sees a longer lifetime than the record
    /// actually has left.  Replaying the stored TTL instead would give the
    /// record up to twice its upstream lifetime downstream.
    pub fn crec_ttl(rec: &CacheRecord, now: Instant) -> u32 {
        if rec.flags & F_IMMORTAL != 0 {
            return rec.ttl;
        }
        rec.expires
            .saturating_duration_since(now)
            .as_secs()
            .min(u64::from(u32::MAX)) as u32
    }

    /// Remove all expired records from the cache and return the count removed.
    ///
    /// This is an eager sweep; in normal operation the LRU crate handles
    /// eviction automatically, but this is useful for bulk cleanup after
    /// loading a hosts file or after a TTL reconfiguration.
    pub fn evict_expired(&mut self, now: Instant) -> u32 {
        let expired_keys: Vec<CacheKey> = self
            .records
            .iter()
            .filter(|(_, r)| record_is_expired(r, now))
            .map(|(k, _)| k.clone())
            .collect();
        let count = expired_keys.len() as u32;
        for k in expired_keys {
            self.records.pop(&k);
            self.evictions += 1;
            inc_metric(Metric::DnsCacheLiveFreed);
        }
        count
    }

    /// Look up a record by name and type flags.
    ///
    /// Returns `None` if no matching record exists or if the record has
    /// expired.  Expired records are removed from the cache on access.
    pub fn lookup_by_name(
        &mut self,
        name:  &str,
        flags: u32,
        now:   Instant,
    ) -> Option<&CacheRecord> {
        let key = CacheKey {
            name:  name.to_lowercase(),
            flags: type_flags(flags),
        };

        // Peek first so we can evict without fighting the borrow checker.
        let expired = self
            .records
            .peek(&key)
            .map_or(false, |r| record_is_expired(r, now));

        if expired {
            self.records.pop(&key);
            self.misses += 1;
            return None;
        }

        if self.records.get(&key).is_some() {
            self.hits += 1;
            // Re-borrow immutably for the return value.
            self.records.get(&key)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Look up a forward record of type `flags`, falling back to the NODATA
    /// negative entry recorded for that same type.
    ///
    /// C stores a NODATA answer with the queried type bit *plus* `F_NEG`
    /// (`rfc1035.c:1288`) and finds it again because `cache_find_by_name()`
    /// matches with a bitwise AND — a lookup for `F_IPV4` therefore also finds
    /// an `F_IPV4|F_NEG` record.  Here the cache is a hash map keyed on the
    /// exact type bits, so the negative key has to be probed explicitly;
    /// without this, every NODATA entry is written to a key nothing ever reads
    /// and negative caching is inert for anything but NXDOMAIN.
    ///
    /// Counts exactly one hit or one miss, whichever key answers.
    pub fn lookup_forward(
        &mut self,
        name:  &str,
        flags: u32,
        now:   Instant,
    ) -> Option<&CacheRecord> {
        let lower    = name.to_lowercase();
        let type_bits = type_flags(flags);
        let positive = CacheKey { name: lower.clone(), flags: type_bits };
        let negative = CacheKey { name: lower,         flags: type_bits | F_NEG };

        // Resolve which key answers before taking the `get` borrow, so the
        // expiry eviction and the returned reference do not overlap.
        let mut hit: Option<CacheKey> = None;
        for key in [positive, negative] {
            let expired = self
                .records
                .peek(&key)
                .map_or(false, |r| record_is_expired(r, now));
            if expired {
                self.records.pop(&key);
                continue;
            }
            if self.records.peek(&key).is_some() {
                hit = Some(key);
                break;
            }
        }

        match hit {
            Some(key) => {
                self.hits += 1;
                self.records.get(&key)
            }
            None => {
                self.misses += 1;
                None
            }
        }
    }

    /// Reverse lookup: return a record whose `addr` matches `addr`.
    ///
    /// Performs a linear scan; intended for PTR / hostname lookups where the
    /// caller knows only the IP address.  Expired records are skipped.
    pub fn lookup_by_addr(
        &mut self,
        addr: &AllAddr,
        now:  Instant,
    ) -> Option<&CacheRecord> {
        // Collect keys of expired records to evict them first.
        let expired_keys: Vec<CacheKey> = self
            .records
            .iter()
            .filter(|(_, r)| record_is_expired(r, now))
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired_keys {
            self.records.pop(&k);
        }

        // Now search for a matching address in live records.
        // We find the key first, then re-borrow.
        let found_key: Option<CacheKey> = self
            .records
            .iter()
            .find(|(_, r)| addr_matches(&r.addr, addr))
            .map(|(k, _)| k.clone());

        if let Some(k) = found_key {
            self.hits += 1;
            self.records.get(&k)
        } else {
            self.misses += 1;
            None
        }
    }

    /// Sweep the cache and remove all expired records.
    ///
    /// This is best-effort; the LRU naturally evicts entries when the cache is
    /// full, so this sweep is mainly useful to reclaim memory between fills.
    pub fn expire_old(&mut self, now: Instant) {
        let expired_keys: Vec<CacheKey> = self
            .records
            .iter()
            .filter(|(_, r)| record_is_expired(r, now))
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired_keys {
            self.records.pop(&k);
        }
    }

    /// Check whether a negative cache record (NXDOMAIN or NODATA) exists for
    /// the given name.
    ///
    /// A negative record is one with both `F_NEG` and either `F_NXDOMAIN`
    /// (the name doesn't exist) or no `F_NXDOMAIN` (NODATA — the name exists
    /// but has no records of the queried type).
    ///
    /// Returns `Some(record)` if an unexpired negative entry exists.
    pub fn lookup_negative(
        &mut self,
        name: &str,
        nxdomain: bool,
        now: Instant,
    ) -> Option<&CacheRecord> {
        let flags = if nxdomain {
            crate::types::constants::F_NEG | crate::types::constants::F_NXDOMAIN
        } else {
            crate::types::constants::F_NEG
        };
        self.lookup_by_name(name, flags, now)
    }

    /// Returns `true` when `name` is known to be NXDOMAIN (not expired).
    pub fn is_nxdomain(&mut self, name: &str, now: Instant) -> bool {
        self.lookup_negative(name, true, now).is_some()
    }

    /// Returns `true` when `name` is known to have no data for the queried type
    /// (NODATA / negative caching without NXDOMAIN, not expired).
    pub fn is_nodata(&mut self, name: &str, now: Instant) -> bool {
        self.lookup_negative(name, false, now).is_some()
    }

    /// Remove every record from the cache.
    pub fn clear(&mut self) {
        self.records.clear();
    }

    /// Number of entries currently in the cache.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// Returns `true` if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Number of live (non-expired) entries.
    ///
    /// Mirrors C's `daemon->metrics[METRIC_DNS_CACHE_ENTRIES]`.
    pub fn cache_count(&self, now: Instant) -> usize {
        self.records
            .iter()
            .filter(|(_, r)| !record_is_expired(r, now))
            .count()
    }

    /// Snapshot of cache counters.
    pub fn stats(&self) -> CacheStats {
        CacheStats {
            inserts:   self.inserts,
            evictions: self.evictions,
            hits:      self.hits,
            misses:    self.misses,
            size:      self.records.len(),
        }
    }

    /// Return **all** live records whose name matches `name` (case-insensitive)
    /// and whose type flags overlap with `prot_mask`.
    ///
    /// `prot_mask` mirrors the `prot` parameter of C's `cache_find_by_name()`:
    /// a record matches if `(record.flags & type_flags(prot_mask)) != 0`.
    ///
    /// Expired records are collected and removed before the search.
    /// This enables round-robin / multi-answer lookups that the keyed
    /// `lookup_by_name` cannot express.
    pub fn lookup_all_by_name(
        &mut self,
        name:      &str,
        prot_mask: u32,
        now:       Instant,
    ) -> Vec<CacheRecord> {
        let name_lc    = name.to_lowercase();
        let prot_typed = type_flags(prot_mask);

        // Evict expired records first (mirrors C freeing expired entries during scan).
        let expired: Vec<CacheKey> = self
            .records
            .iter()
            .filter(|(_, r)| record_is_expired(r, now))
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            self.records.pop(&k);
            self.evictions += 1;
            inc_metric(Metric::DnsCacheLiveFreed);
        }

        // Collect all matching records.
        let matches: Vec<CacheRecord> = self
            .records
            .iter()
            .filter(|(_, r)| {
                r.name.to_lowercase() == name_lc
                    && (r.flags & F_FORWARD) != 0
                    && (r.flags & prot_typed) != 0
            })
            .map(|(_, r)| r.clone())
            .collect();

        if matches.is_empty() {
            self.misses += 1;
        } else {
            self.hits += 1;
        }

        matches
    }

    /// Return the first live record whose name matches `name` and whose flags
    /// overlap with `prot_mask`.
    ///
    /// Mirrors the first call to C's `cache_find_by_name(NULL, name, now, prot)`.
    /// For exact single-type lookups prefer the faster `lookup_by_name`.
    pub fn lookup_prot(
        &mut self,
        name:      &str,
        prot_mask: u32,
        now:       Instant,
    ) -> Option<CacheRecord> {
        let mut all = self.lookup_all_by_name(name, prot_mask, now);
        if all.is_empty() { None } else { Some(all.swap_remove(0)) }
    }

    /// Return **all** live reverse records whose address matches `addr` and
    /// whose flags overlap with `prot_mask` (typically `F_IPV4` or `F_IPV6`).
    ///
    /// Mirrors C's `cache_find_by_addr()` being called until it returns NULL.
    pub fn lookup_all_by_addr(
        &mut self,
        addr:      &AllAddr,
        prot_mask: u32,
        now:       Instant,
    ) -> Vec<CacheRecord> {
        let prot_typed = type_flags(prot_mask);

        // Evict expired reverse records.
        let expired: Vec<CacheKey> = self
            .records
            .iter()
            .filter(|(_, r)| (r.flags & F_REVERSE) != 0 && record_is_expired(r, now))
            .map(|(k, _)| k.clone())
            .collect();
        for k in expired {
            self.records.pop(&k);
            self.evictions += 1;
            inc_metric(Metric::DnsCacheLiveFreed);
        }

        let matches: Vec<CacheRecord> = self
            .records
            .iter()
            .filter(|(_, r)| {
                (r.flags & F_REVERSE) != 0
                    && (r.flags & prot_typed) != 0
                    && addr_matches(&r.addr, addr)
            })
            .map(|(_, r)| r.clone())
            .collect();

        if matches.is_empty() {
            self.misses += 1;
        } else {
            self.hits += 1;
        }

        matches
    }

    /// Remove all `F_HOSTS | F_DHCP | F_CONFIG` records that carry `uid`.
    ///
    /// Returns the number of entries removed.
    /// Mirrors C `cache_remove_uid()` in `cache.c`.
    pub fn remove_by_uid(&mut self, uid: u32) -> u32 {
        if uid == UID_NONE {
            return 0;
        }
        let removable: Vec<CacheKey> = self
            .records
            .iter()
            .filter(|(_, r)| {
                r.uid == uid && (r.flags & (F_HOSTS | F_DHCP | F_CONFIG)) != 0
            })
            .map(|(k, _)| k.clone())
            .collect();
        let count = removable.len() as u32;
        for k in removable {
            self.records.pop(&k);
        }
        count
    }

    /// Iterate over all live (non-expired) records in the cache.
    ///
    /// Mirrors C `cache_enumerate()`.
    pub fn iter_live(&self, now: Instant) -> impl Iterator<Item = &CacheRecord> {
        self.records
            .iter()
            .map(|(_, r)| r)
            .filter(move |r| !record_is_expired(r, now))
    }

    /// Insert a record *and* create non-terminal placeholder entries for
    /// every parent label in its name that has no forward record yet.
    ///
    /// Non-terminals enable correct negative caching: a query for
    /// `x.foo.example.com` when only `foo.example.com` has records should
    /// return NXDOMAIN for `x.foo.example.com`, not for `example.com`.
    ///
    /// Mirrors C `make_non_terminals()` called after every `really_insert()`.
    pub fn insert_with_non_terminals(&mut self, rec: CacheRecord) {
        let source_flags  = rec.flags;
        let source_uid    = rec.uid;
        let source_immortal = (rec.flags & F_IMMORTAL) != 0;
        let source_expires  = rec.expires;
        let type_flags_mask =
            F_HOSTS | F_CONFIG | if source_flags & F_DHCP != 0 { F_DHCP } else { 0 };

        // Insert the real record first.
        let name = rec.name.clone();
        self.insert(rec);

        // Build the list of non-terminal parent names.
        let terminals = non_terminal_names(&name);

        for parent in terminals {
            let key = CacheKey {
                name:  parent.clone(),
                flags: type_flags(F_FORWARD | type_flags_mask),
            };

            if let Some(existing) = self.records.peek_mut(&key) {
                // Update expiry if the new source lives longer.
                if !source_immortal {
                    if existing.flags & F_IMMORTAL == 0
                        && source_expires > existing.expires
                    {
                        existing.expires = source_expires;
                    }
                } else {
                    existing.flags |= F_IMMORTAL;
                }
                continue; // Non-terminal already present — no need to insert.
            }

            // Create a new non-terminal placeholder.
            let nt = CacheRecord {
                name:    parent,
                flags:   (source_flags | F_FORWARD)
                    & !(F_IPV4 | F_IPV6 | F_CNAME | F_RR | F_DNSKEY | F_DS | F_REVERSE),
                ttl:     0,
                expires: source_expires,
                addr:    None,
                rdata:   None,
                uid:     source_uid,
            };
            self.insert(nt);
        }
    }
}

// ---------------------------------------------------------------------------
// DNS type-number ↔ name table  (rrtype / querystr)
// ---------------------------------------------------------------------------

/// Map a DNS type number to its IANA mnemonic (e.g. `1` → `"A"`).
///
/// Returns `None` when the type number is not in the table.
/// Mirrors the `typestr[]` lookup array in C's `cache.c`.
pub fn rrtype_name(rrtype: u16) -> Option<&'static str> {
    TYPESTR
        .iter()
        .find(|&&(t, _)| t == rrtype)
        .map(|&(_, name)| name)
}

/// Map a DNS type mnemonic to its IANA number (e.g. `"AAAA"` → `28`).
///
/// The comparison is case-insensitive.  Returns `0` when the name is unknown
/// (same sentinel as C's `rrtype()`).
pub fn rrtype(name: &str) -> u16 {
    TYPESTR
        .iter()
        .find(|&&(_, n)| n.eq_ignore_ascii_case(name))
        .map(|&(t, _)| t)
        .unwrap_or(0)
}

/// Format a DNS type for display:
///
/// - With `desc = None` → `"<A>"` or `"<type=99>"`
/// - With `desc = Some("query")` → `"query[A]"` or `"query[type=99]"`
///
/// Mirrors C's `querystr(desc, type)`.
pub fn querystr(desc: Option<&str>, rrtype: u16) -> String {
    match (desc, rrtype_name(rrtype)) {
        (None,       Some(name)) => format!("<{name}>"),
        (None,       None)       => format!("<type={rrtype}>"),
        (Some(desc), Some(name)) => format!("{desc}[{name}]"),
        (Some(desc), None)       => format!("{desc}[type={rrtype}]"),
    }
}

/// Format a DNS type for display using the type flags from a `CacheRecord`.
///
/// Convenience wrapper around [`querystr`] that picks the right rrtype from
/// `F_KEYTAG` vs plain `F_RR` variants.
pub fn querystr_flags(desc: Option<&str>, rec: &CacheRecord) -> String {
    use crate::types::constants::F_KEYTAG;
    let t = match &rec.addr {
        Some(crate::types::addr::AllAddr::RrBlock(b)) if rec.flags & F_KEYTAG != 0 => b.rrtype,
        Some(crate::types::addr::AllAddr::RrData(d))                               => d.rrtype,
        Some(crate::types::addr::AllAddr::RrBlock(b))                              => b.rrtype,
        _ => 0,
    };
    querystr(desc, t)
}

/// IANA DNS type table — `(type_number, mnemonic)`.
/// Mirrors the `typestr[]` array in C's `cache.c`.
const TYPESTR: &[(u16, &str)] = &[
    (1,     "A"),
    (2,     "NS"),
    (3,     "MD"),
    (4,     "MF"),
    (5,     "CNAME"),
    (6,     "SOA"),
    (7,     "MB"),
    (8,     "MG"),
    (9,     "MR"),
    (10,    "NULL"),
    (11,    "WKS"),
    (12,    "PTR"),
    (13,    "HINFO"),
    (14,    "MINFO"),
    (15,    "MX"),
    (16,    "TXT"),
    (17,    "RP"),
    (18,    "AFSDB"),
    (19,    "X25"),
    (20,    "ISDN"),
    (21,    "RT"),
    (22,    "NSAP"),
    (23,    "NSAP_PTR"),
    (24,    "SIG"),
    (25,    "KEY"),
    (26,    "PX"),
    (27,    "GPOS"),
    (28,    "AAAA"),
    (29,    "LOC"),
    (30,    "NXT"),
    (31,    "EID"),
    (32,    "NIMLOC"),
    (33,    "SRV"),
    (34,    "ATMA"),
    (35,    "NAPTR"),
    (36,    "KX"),
    (37,    "CERT"),
    (38,    "A6"),
    (39,    "DNAME"),
    (40,    "SINK"),
    (41,    "OPT"),
    (42,    "APL"),
    (43,    "DS"),
    (44,    "SSHFP"),
    (45,    "IPSECKEY"),
    (46,    "RRSIG"),
    (47,    "NSEC"),
    (48,    "DNSKEY"),
    (49,    "DHCID"),
    (50,    "NSEC3"),
    (51,    "NSEC3PARAM"),
    (52,    "TLSA"),
    (53,    "SMIMEA"),
    (55,    "HIP"),
    (56,    "NINFO"),
    (57,    "RKEY"),
    (58,    "TALINK"),
    (59,    "CDS"),
    (60,    "CDNSKEY"),
    (61,    "OPENPGPKEY"),
    (62,    "CSYNC"),
    (63,    "ZONEMD"),
    (64,    "SVCB"),
    (65,    "HTTPS"),
    (66,    "DSYNC"),
    (67,    "HHIT"),
    (68,    "BRID"),
    (99,    "SPF"),
    (100,   "UINFO"),
    (101,   "UID"),
    (102,   "GID"),
    (103,   "UNSPEC"),
    (104,   "NID"),
    (105,   "L32"),
    (106,   "L64"),
    (107,   "LP"),
    (108,   "EUI48"),
    (109,   "EUI64"),
    (128,   "NXNAME"),
    (249,   "TKEY"),
    (250,   "TSIG"),
    (251,   "IXFR"),
    (252,   "AXFR"),
    (253,   "MAILB"),
    (254,   "MAILA"),
    (255,   "ANY"),
    (256,   "URI"),
    (257,   "CAA"),
    (258,   "AVC"),
    (259,   "DOA"),
    (260,   "AMTRELAY"),
    (261,   "RESINFO"),
    (262,   "WALLET"),
    (263,   "CLA"),
    (264,   "IPN"),
    (32768, "TA"),
    (32769, "DLV"),
];

// ---------------------------------------------------------------------------
// Debug dump helpers
// ---------------------------------------------------------------------------

/// Format a single cache record as a human-readable log line.
///
/// Output format (mirrors C's `dump_cache_entry()`):
/// ```text
/// <name-30>  <addr-40>  <type><flags>  <expiry>
/// ```
///
/// Flag abbreviations: F=Forward R=Reverse I=Immortal D=DHCP N=Neg X=NXDOMAIN
/// H=Hosts C=Config V=DNSSECOK
/// Type characters: 4=A 6=AAAA C=CNAME T=RR S=DS K=DNSKEY !=non-terminal
pub fn format_cache_entry(rec: &CacheRecord, now: Instant) -> String {
    use crate::types::constants::{
        F_DNSSECOK, F_DNSKEY, F_DS, F_KEYTAG, F_RR,
    };
    use crate::types::addr::AllAddr;

    // Determine the display name.
    let display_name: &str = if rec.flags & F_REVERSE != 0 && rec.flags & F_NEG != 0 {
        ""
    } else if rec.name.is_empty() {
        "<Root>"
    } else {
        &rec.name
    };

    // Determine the address / RR-type string.
    let addr_str: String = if (rec.flags & F_CNAME) != 0 {
        match &rec.addr {
            Some(AllAddr::Cname(c)) => c.target_name.clone().unwrap_or_default(),
            _ => String::new(),
        }
    } else if (rec.flags & F_RR) != 0 {
        querystr_flags(None, rec)
    } else if (rec.flags & F_DS) != 0 {
        if rec.flags & F_NEG == 0 {
            match &rec.addr {
                Some(AllAddr::Ds(ds)) => {
                    format!("{:5} {:3} {:3}", ds.keytag, ds.algo, ds.digest)
                }
                _ => String::new(),
            }
        } else {
            String::new()
        }
    } else if (rec.flags & F_DNSKEY) != 0 {
        match &rec.addr {
            Some(AllAddr::Key(k)) => {
                format!("{:5} {:3} {:3}", k.keytag, k.algo, k.flags)
            }
            _ => String::new(),
        }
    } else if (rec.flags & F_NEG) == 0 || (rec.flags & F_FORWARD) == 0 {
        // Has an address.
        match &rec.addr {
            Some(AllAddr::Addr4(ip4)) => ip4.to_string(),
            Some(AllAddr::Addr6(ip6)) => ip6.to_string(),
            _ => String::new(),
        }
    } else {
        String::new()
    };

    // Type character.
    let type_char = if (rec.flags & F_IPV4) != 0 {
        "4"
    } else if (rec.flags & F_IPV6) != 0 {
        "6"
    } else if (rec.flags & F_CNAME) != 0 {
        "C"
    } else if (rec.flags & F_RR) != 0 {
        "T"
    } else if (rec.flags & F_DS) != 0 {
        "S"
    } else if (rec.flags & F_DNSKEY) != 0 {
        "K"
    } else if (rec.flags & F_NXDOMAIN) == 0 {
        "!" // non-terminal
    } else {
        " "
    };

    // Flag characters.
    let flags_str = format!(
        "{}{}{}{}{}{}{}{}{}{}",
        type_char,
        if rec.flags & F_FORWARD   != 0 { "F" } else { " " },
        if rec.flags & F_REVERSE   != 0 { "R" } else { " " },
        if rec.flags & F_IMMORTAL  != 0 { "I" } else { " " },
        if rec.flags & F_DHCP      != 0 { "D" } else { " " },
        if rec.flags & F_NEG       != 0 { "N" } else { " " },
        if rec.flags & F_NXDOMAIN  != 0 { "X" } else { " " },
        if rec.flags & F_HOSTS     != 0 { "H" } else { " " },
        if rec.flags & F_CONFIG    != 0 { "C" } else { " " },
        if rec.flags & F_DNSSECOK  != 0 { "V" } else { " " },
    );

    // Expiry: blank for immortal, relative seconds otherwise.
    let expiry_str = if rec.flags & F_IMMORTAL != 0 {
        String::new()
    } else {
        let secs = rec.expires.saturating_duration_since(now).as_secs();
        format!("{secs}s")
    };

    format!(
        "{:<30.30} {:<40.40} {:<12} {:<12}",
        display_name, addr_str, flags_str, expiry_str
    )
}

/// Dump the entire cache to a `Vec<String>`, one line per record.
///
/// Mirrors C's `dump_cache(now)` → iterates every bucket.
pub fn dump_cache(cache: &DnsCache, now: Instant) -> Vec<String> {
    cache
        .records
        .iter()
        .map(|(_, r)| format_cache_entry(r, now))
        .collect()
}

// ---------------------------------------------------------------------------
// extract_addresses integration
// ---------------------------------------------------------------------------

/// Process a raw DNS reply packet by:
/// 1. Parsing the wire-format packet.
/// 2. Calling [`crate::rfc1035::extract_addresses`] to populate `cache`.
///
/// Returns the [`ExtractResult`](crate::rfc1035::ExtractResult) so the caller
/// can act on it the way C's `process_reply()` acts on `extract_addresses()`'s
/// return code (`forward.c:824-841`): a non-zero code clears the RR sections,
/// `1` (rebind) is logged, `2` (bad packet) also becomes SERVFAIL.
///
/// This is the integration point between the forwarding engine and the DNS
/// cache; `forward::cache_upstream_reply` calls it for every accepted upstream
/// reply.
pub fn cache_reply(
    wire: &[u8],
    cache: &mut DnsCache,
    config: &crate::rfc1035::ExtractConfig,
) -> crate::rfc1035::ExtractResult {
    use std::time::Instant;
    use crate::rfc1035::{extract_addresses, ExtractResult, DnsPacket};

    let packet = match DnsPacket::parse(wire) {
        Ok(p) => p,
        Err(_) => return ExtractResult::BadPacket,
    };

    extract_addresses(&packet, cache, Instant::now(), config)
}

// ---------------------------------------------------------------------------
// /etc/hosts file loading
// ---------------------------------------------------------------------------

/// Format an IPv4 address as a PTR (reverse-lookup) name.
///
/// Example: `192.168.1.1` → `"1.1.168.192.in-addr.arpa"`
pub fn ipv4_ptr_name(addr: std::net::Ipv4Addr) -> String {
    let [a, b, c, d] = addr.octets();
    format!("{d}.{c}.{b}.{a}.in-addr.arpa")
}

/// Format an IPv6 address as a PTR (reverse-lookup) name.
///
/// Example: `::1` → `"1.0.0.0…0.ip6.arpa"` (32 nibbles, dot-separated, reversed)
pub fn ipv6_ptr_name(addr: std::net::Ipv6Addr) -> String {
    let segments = addr.octets();
    let nibbles: String = segments
        .iter()
        .rev()
        .flat_map(|byte| {
            let lo = byte & 0x0F;
            let hi = (byte >> 4) & 0x0F;
            [
                format!("{lo:x}."),
                format!("{hi:x}."),
            ]
        })
        .collect();
    format!("{nibbles}ip6.arpa")
}

/// Parse a single `/etc/hosts`-format line into cache records and append them
/// to `cache`.
///
/// Format: `ip_addr  hostname [alias ...]`  (with optional comment after `#`)
///
/// Inserts both forward (A/AAAA) and reverse (PTR) records.  All records are
/// tagged with `F_HOSTS | F_IMMORTAL` and grouped under `uid` so that stale
/// entries can later be removed by `uid`.
///
/// Returns the number of records inserted (forward + reverse).
pub fn parse_hosts_line(line: &str, ttl: u32, uid: u32, now: Instant, cache: &mut DnsCache) -> usize {
    // Strip comments.
    let line = if let Some(idx) = line.find('#') { &line[..idx] } else { line };
    let line = line.trim();
    if line.is_empty() { return 0; }

    let mut parts = line.split_whitespace();
    let ip_str = match parts.next() { Some(s) => s, None => return 0 };
    let expires = now + std::time::Duration::from_secs(u64::from(ttl) + 3600);
    let mut count = 0;

    let names: Vec<String> = parts.map(|n| n.to_ascii_lowercase()).collect();
    if names.is_empty() { return 0; }

    if let Ok(ip4) = ip_str.parse::<std::net::Ipv4Addr>() {
        let fwd_addr = AllAddr::Addr4(ip4);
        let ptr_name = ipv4_ptr_name(ip4);

        // Forward records: name → A (one per hostname)
        for name in &names {
            cache.insert(CacheRecord {
                name: name.clone(),
                flags: F_IPV4 | F_FORWARD | F_HOSTS | F_IMMORTAL,
                ttl,
                expires,
                addr: Some(fwd_addr.clone()),
                rdata: None,
                uid,
            });
            count += 1;
        }

        // Reverse record: PTR → first name (canonical)
        if let Some(canonical) = names.first() {
            cache.insert(CacheRecord {
                name: ptr_name,
                flags: F_IPV4 | F_REVERSE | F_HOSTS | F_IMMORTAL,
                ttl,
                expires,
                addr: Some(AllAddr::Addr4(ip4)),
                rdata: Some(canonical.clone().into_bytes()),
                uid,
            });
            count += 1;
        }
    } else if let Ok(ip6) = ip_str.parse::<std::net::Ipv6Addr>() {
        let fwd_addr = AllAddr::Addr6(ip6);
        let ptr_name = ipv6_ptr_name(ip6);

        // Forward records: name → AAAA (one per hostname)
        for name in &names {
            cache.insert(CacheRecord {
                name: name.clone(),
                flags: F_IPV6 | F_FORWARD | F_HOSTS | F_IMMORTAL,
                ttl,
                expires,
                addr: Some(fwd_addr.clone()),
                rdata: None,
                uid,
            });
            count += 1;
        }

        // Reverse record: PTR → first name
        if let Some(canonical) = names.first() {
            cache.insert(CacheRecord {
                name: ptr_name,
                flags: F_IPV6 | F_REVERSE | F_HOSTS | F_IMMORTAL,
                ttl,
                expires,
                addr: Some(AllAddr::Addr6(ip6)),
                rdata: Some(canonical.clone().into_bytes()),
                uid,
            });
            count += 1;
        }
    }

    count
}

/// Load `/etc/hosts` (or any hosts-format file at `path`) into `cache`.
///
/// All inserted entries use `F_IMMORTAL | F_HOSTS` and share a fresh UID so
/// that `reload_hosts` can remove them as a group.  Inserts both forward and
/// PTR records for each entry.
///
/// Returns `(uid, count)` on success, or an `io::Error` on read failure.
pub fn load_hosts_file(
    path: &str,
    ttl: u32,
    now: Instant,
    cache: &mut DnsCache,
) -> std::io::Result<(u32, usize)> {
    let uid = next_uid();
    let text = std::fs::read_to_string(path)?;
    let total = text.lines()
        .map(|l| parse_hosts_line(l, ttl, uid, now, cache))
        .sum();
    Ok((uid, total))
}

/// Reload all hosts files listed in `paths` into a (pre-cleared) cache.
///
/// Clears all `F_HOSTS` records first so stale entries from previous loads are
/// removed, then re-loads each file in order.  Returns the total records
/// inserted.
pub fn reload_hosts(
    paths: &[String],
    ttl: u32,
    cache: &mut DnsCache,
) -> usize {
    let now = Instant::now();
    // Remove all existing hosts-file records (uid != UID_NONE handled by clear).
    cache.clear();
    let mut total = 0;
    for path in paths {
        match load_hosts_file(path, ttl, now, cache) {
            Ok((_uid, n)) => total += n,
            Err(e) => {
                // Non-fatal: log and continue with remaining files.
                eprintln!("dnsmasq-rs: warning: could not read {path}: {e}");
            }
        }
    }
    total
}

/// Look up the first IPv4 address from hosts-file records (`F_HOSTS`) for
/// `name`.
///
/// Returns `None` if no matching record exists in the cache.
/// Mirrors C's `a_record_from_hosts()`.
pub fn a_record_from_hosts(name: &str, now: Instant, cache: &mut DnsCache) -> Option<std::net::Ipv4Addr> {
    let recs = cache.lookup_all_by_name(name, F_IPV4, now);
    recs.into_iter()
        .find(|r| r.flags & F_HOSTS != 0)
        .and_then(|r| r.addr)
        .and_then(|a| if let AllAddr::Addr4(ip) = a { Some(ip) } else { None })
}

/// Insert daemon-configured CNAME records into `cache`.
///
/// Each entry gets `F_FORWARD | F_CNAME | F_IMMORTAL | F_CONFIG` and
/// `uid = UID_NONE` (not tied to any source file).
///
/// `cnames` is a slice of `(alias, target)` pairs with an optional TTL.
///
/// Mirrors the CNAME-injection loop in C's `cache_reload()`.
pub fn insert_config_cnames(
    cnames: &[crate::types::dns_records::Cname],
    now: Instant,
    cache: &mut DnsCache,
) {
    for c in cnames {
        // Skip wildcard aliases (alias starts with '*' — C checks alias[1] != '*')
        if c.alias.starts_with('*') {
            continue;
        }
        let ttl = if c.ttl < 0 { 0u32 } else { c.ttl as u32 };
        let expires = now + std::time::Duration::from_secs(u64::from(ttl) + 3600);
        cache.insert(CacheRecord {
            name:   c.alias.clone(),
            flags:  F_FORWARD | F_CNAME | F_IMMORTAL | F_CONFIG,
            ttl,
            expires,
            addr:   Some(AllAddr::Cname(crate::types::addr::CnameAddr {
                is_name_ptr: true,
                target_name: Some(c.target.clone()),
                uid: UID_NONE,
            })),
            rdata:  None,
            uid:    UID_NONE,
        });
    }
}

/// Insert daemon-configured host records (`--host-record`) into `cache`.
///
/// Each `HostRecord` may carry IPv4 and/or IPv6 addresses; both forward and
/// reverse PTR records are inserted for each name/address pair.
/// Flags: `F_HOSTS | F_IMMORTAL | F_FORWARD | F_REVERSE | F_CONFIG`.
///
/// Mirrors the `host_records` loop in C's `cache_reload()`.
pub fn insert_host_records(
    host_records: &[crate::types::dns_records::HostRecord],
    now: Instant,
    cache: &mut DnsCache,
) {
    for hr in host_records {
        let ttl = if hr.ttl < 0 { 0u32 } else { hr.ttl as u32 };
        let expires = now + std::time::Duration::from_secs(u64::from(ttl) + 3600);

        for name in &hr.names {
            let name_lc = name.to_ascii_lowercase();

            if let Some(ip4) = hr.addr4 {
                let ptr_name = ipv4_ptr_name(ip4);
                cache.insert(CacheRecord {
                    name:   name_lc.clone(),
                    flags:  F_HOSTS | F_IMMORTAL | F_FORWARD | F_CONFIG | F_IPV4,
                    ttl,
                    expires,
                    addr:   Some(AllAddr::Addr4(ip4)),
                    rdata:  None,
                    uid:    UID_NONE,
                });
                cache.insert(CacheRecord {
                    name:   ptr_name,
                    flags:  F_HOSTS | F_IMMORTAL | F_REVERSE | F_CONFIG | F_IPV4,
                    ttl,
                    expires,
                    addr:   Some(AllAddr::Addr4(ip4)),
                    rdata:  Some(name_lc.clone().into_bytes()),
                    uid:    UID_NONE,
                });
            }

            if let Some(ip6) = hr.addr6 {
                let ptr_name = ipv6_ptr_name(ip6);
                cache.insert(CacheRecord {
                    name:   name_lc.clone(),
                    flags:  F_HOSTS | F_IMMORTAL | F_FORWARD | F_CONFIG | F_IPV6,
                    ttl,
                    expires,
                    addr:   Some(AllAddr::Addr6(ip6)),
                    rdata:  None,
                    uid:    UID_NONE,
                });
                cache.insert(CacheRecord {
                    name:   ptr_name,
                    flags:  F_HOSTS | F_IMMORTAL | F_REVERSE | F_CONFIG | F_IPV6,
                    ttl,
                    expires,
                    addr:   Some(AllAddr::Addr6(ip6)),
                    rdata:  Some(name_lc.clone().into_bytes()),
                    uid:    UID_NONE,
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns `true` if `haystack` matches `needle` by IP address.
fn addr_matches(haystack: &Option<AllAddr>, needle: &AllAddr) -> bool {
    match (haystack, needle) {
        (Some(AllAddr::Addr4(a)), AllAddr::Addr4(b)) => a == b,
        (Some(AllAddr::Addr6(a)), AllAddr::Addr6(b)) => a == b,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Non-terminal and DHCP record helpers (ported from cache.c)
// ---------------------------------------------------------------------------

/// Check if a name exists as an intermediate (non-terminal) domain in the cache.
///
/// Returns true if any non-expired, non-NXDOMAIN forward record exists for the name.
/// Port of `cache_find_non_terminal()` from cache.c:1150-1163.
pub fn cache_find_non_terminal(name: &str, now: Instant, cache: &DnsCache) -> bool {
    use crate::types::constants::{F_FORWARD, F_NXDOMAIN};
    cache.iter_live(now).any(|r| {
        r.flags & F_FORWARD != 0
            && r.flags & F_NXDOMAIN == 0
            && r.name.eq_ignore_ascii_case(name)
    })
}

/// Remove all DHCP-sourced records from the cache.
///
/// Returns the number of records removed.
/// Port of `cache_unhash_dhcp()` from cache.c:1732-1746.
pub fn cache_unhash_dhcp(cache: &mut DnsCache, now: Instant) -> usize {
    use crate::types::constants::F_DHCP;
    // Collect UIDs of DHCP entries then remove them.
    let dhcp_uids: Vec<u32> = cache.iter_live(now)
        .filter(|r| r.flags & F_DHCP != 0)
        .map(|r| r.uid)
        .collect();
    let mut removed = 0;
    for uid in dhcp_uids {
        removed += cache.remove_by_uid(uid) as usize;
    }
    removed
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::time::{Duration, Instant};

    fn make_a_record(name: &str, ip: Ipv4Addr, ttl: u32, expires: Instant) -> CacheRecord {
        CacheRecord {
            name: name.to_string(),
            flags: F_IPV4 | F_FORWARD,
            ttl,
            expires,
            addr: Some(AllAddr::Addr4(ip)),
            rdata: None,
            uid: UID_NONE,
        }
    }

    fn make_ptr_record(name: &str, ip: Ipv4Addr, ttl: u32, expires: Instant) -> CacheRecord {
        CacheRecord {
            name: name.to_string(),
            flags: F_IPV4 | F_REVERSE,
            ttl,
            expires,
            addr: Some(AllAddr::Addr4(ip)),
            rdata: None,
            uid: UID_NONE,
        }
    }

    // ------------------------------------------------------------------
    // type_flags
    // ------------------------------------------------------------------

    #[test]
    fn type_flags_masks_correctly() {
        use crate::types::constants::{F_DHCP, F_HOSTS};
        let all = F_IPV4 | F_IPV6 | F_CNAME | F_NEG | F_NXDOMAIN | F_REVERSE | F_DHCP | F_HOSTS;
        let result = type_flags(all);
        // DHCP and HOSTS are not type flags
        assert_eq!(result & F_IPV4,     F_IPV4);
        assert_eq!(result & F_IPV6,     F_IPV6);
        assert_eq!(result & F_CNAME,    F_CNAME);
        assert_eq!(result & F_NEG,      F_NEG);
        assert_eq!(result & F_NXDOMAIN, F_NXDOMAIN);
        assert_eq!(result & F_REVERSE,  F_REVERSE);
        assert_eq!(result & F_DHCP,     0);
        assert_eq!(result & F_HOSTS,    0);
    }

    // ------------------------------------------------------------------
    // record_is_expired
    // ------------------------------------------------------------------

    #[test]
    fn immortal_record_never_expires() {
        let rec = CacheRecord {
            name: "example.com".into(),
            flags: F_IMMORTAL | F_IPV4,
            ttl: 0,
            expires: Instant::now() - Duration::from_secs(9999),
            addr: None,
            rdata: None,
            uid: UID_NONE,
        };
        assert!(!record_is_expired(&rec, Instant::now()));
    }

    #[test]
    fn mortal_record_expires() {
        let past = Instant::now() - Duration::from_secs(1);
        let rec = CacheRecord {
            name: "example.com".into(),
            flags: F_IPV4,
            ttl: 60,
            expires: past,
            addr: None,
            rdata: None,
            uid: UID_NONE,
        };
        assert!(record_is_expired(&rec, Instant::now()));
    }

    // ------------------------------------------------------------------
    // insert / lookup_by_name hit and miss
    // ------------------------------------------------------------------

    #[test]
    fn insert_and_lookup_hit() {
        let mut cache = DnsCache::new(16);
        let future = Instant::now() + Duration::from_secs(300);
        cache.insert(make_a_record("example.com", Ipv4Addr::new(1, 2, 3, 4), 300, future));

        let result = cache.lookup_by_name("example.com", F_IPV4, Instant::now());
        assert!(result.is_some());
        assert_eq!(cache.hits,   1);
        assert_eq!(cache.misses, 0);
    }

    #[test]
    fn lookup_miss_returns_none() {
        let mut cache = DnsCache::new(16);
        let result = cache.lookup_by_name("missing.example.com", F_IPV4, Instant::now());
        assert!(result.is_none());
        assert_eq!(cache.misses, 1);
    }

    #[test]
    fn lookup_is_case_insensitive() {
        let mut cache = DnsCache::new(16);
        let future = Instant::now() + Duration::from_secs(300);
        cache.insert(make_a_record("Example.COM", Ipv4Addr::new(1, 2, 3, 4), 300, future));

        assert!(cache.lookup_by_name("example.com", F_IPV4, Instant::now()).is_some());
        assert!(cache.lookup_by_name("EXAMPLE.COM", F_IPV4, Instant::now()).is_some());
    }

    // ------------------------------------------------------------------
    // TTL expiry
    // ------------------------------------------------------------------

    #[test]
    fn expired_record_returns_none() {
        let mut cache = DnsCache::new(16);
        // Already expired
        let past = Instant::now() - Duration::from_millis(1);
        cache.insert(make_a_record("example.com", Ipv4Addr::new(1, 2, 3, 4), 0, past));

        let result = cache.lookup_by_name("example.com", F_IPV4, Instant::now());
        assert!(result.is_none());
        assert_eq!(cache.misses, 1);
        // Record should have been evicted
        assert!(cache.is_empty());
    }

    // ------------------------------------------------------------------
    // LRU eviction
    // ------------------------------------------------------------------

    #[test]
    fn lru_eviction_when_full() {
        let mut cache = DnsCache::new(3);
        let future = Instant::now() + Duration::from_secs(300);

        cache.insert(make_a_record("a.example.com", Ipv4Addr::new(1, 0, 0, 1), 300, future));
        cache.insert(make_a_record("b.example.com", Ipv4Addr::new(1, 0, 0, 2), 300, future));
        cache.insert(make_a_record("c.example.com", Ipv4Addr::new(1, 0, 0, 3), 300, future));

        // Access 'a' so it becomes recently used
        cache.lookup_by_name("a.example.com", F_IPV4, Instant::now());

        // Insert a 4th entry — 'b' (LRU) should be evicted
        cache.insert(make_a_record("d.example.com", Ipv4Addr::new(1, 0, 0, 4), 300, future));

        assert_eq!(cache.len(), 3);
        assert!(cache.lookup_by_name("b.example.com", F_IPV4, Instant::now()).is_none());
        assert!(cache.lookup_by_name("a.example.com", F_IPV4, Instant::now()).is_some());
        assert!(cache.lookup_by_name("c.example.com", F_IPV4, Instant::now()).is_some());
        assert!(cache.lookup_by_name("d.example.com", F_IPV4, Instant::now()).is_some());
        assert!(cache.evictions > 0);
    }

    // ------------------------------------------------------------------
    // lookup_by_addr
    // ------------------------------------------------------------------

    #[test]
    fn lookup_by_addr_finds_ptr_record() {
        let mut cache = DnsCache::new(16);
        let future = Instant::now() + Duration::from_secs(300);
        let ip = Ipv4Addr::new(192, 168, 1, 1);
        cache.insert(make_ptr_record("1.1.168.192.in-addr.arpa", ip, 300, future));

        let result = cache.lookup_by_addr(&AllAddr::Addr4(ip), Instant::now());
        assert!(result.is_some());
        assert_eq!(result.unwrap().name, "1.1.168.192.in-addr.arpa");
    }

    #[test]
    fn lookup_by_addr_miss() {
        let mut cache = DnsCache::new(16);
        let result = cache.lookup_by_addr(&AllAddr::Addr4(Ipv4Addr::new(10, 0, 0, 1)), Instant::now());
        assert!(result.is_none());
    }

    #[test]
    fn lookup_by_addr_skips_expired() {
        let mut cache = DnsCache::new(16);
        let past = Instant::now() - Duration::from_millis(1);
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        cache.insert(make_ptr_record("1.0.0.10.in-addr.arpa", ip, 0, past));

        let result = cache.lookup_by_addr(&AllAddr::Addr4(ip), Instant::now());
        assert!(result.is_none());
    }

    // ------------------------------------------------------------------
    // expire_old
    // ------------------------------------------------------------------

    #[test]
    fn expire_old_removes_stale_records() {
        let mut cache = DnsCache::new(16);
        let past   = Instant::now() - Duration::from_millis(1);
        let future = Instant::now() + Duration::from_secs(300);

        cache.insert(make_a_record("old.example.com",  Ipv4Addr::new(1,1,1,1), 0,   past));
        cache.insert(make_a_record("new.example.com",  Ipv4Addr::new(2,2,2,2), 300, future));

        cache.expire_old(Instant::now());

        assert_eq!(cache.len(), 1);
        assert!(cache.lookup_by_name("new.example.com", F_IPV4, Instant::now()).is_some());
    }

    // ------------------------------------------------------------------
    // clear
    // ------------------------------------------------------------------

    #[test]
    fn clear_empties_cache() {
        let mut cache = DnsCache::new(16);
        let future = Instant::now() + Duration::from_secs(300);
        cache.insert(make_a_record("a.example.com", Ipv4Addr::new(1,0,0,1), 300, future));
        cache.insert(make_a_record("b.example.com", Ipv4Addr::new(1,0,0,2), 300, future));

        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
    }

    // ------------------------------------------------------------------
    // DNSSEC feature
    // ------------------------------------------------------------------

    #[cfg(feature = "dnssec")]
    #[test]
    fn dnssec_record_stored_and_retrieved() {
        let mut cache = DnsCache::new(16);
        let future = Instant::now() + Duration::from_secs(300);
        let rdata = vec![0xDE, 0xAD, 0xBE, 0xEF];

        let rec = CacheRecord {
            name:    "example.com".into(),
            flags:   F_DNSKEY | F_DNSSEC,
            ttl:     300,
            expires: future,
            addr:    None,
            rdata:   Some(rdata.clone()),
            uid:     UID_NONE,
        };
        cache.insert(rec);

        let result = cache.lookup_by_name("example.com", F_DNSKEY | F_DNSSEC, Instant::now());
        assert!(result.is_some());
        assert_eq!(result.unwrap().rdata.as_deref(), Some(rdata.as_slice()));
    }

    // ------------------------------------------------------------------
    // hosts file loading
    // ------------------------------------------------------------------

    #[test]
    fn parse_hosts_line_ipv4() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        let count = parse_hosts_line("192.168.1.1  myhost myhost.local", 60, UID_NONE, now, &mut cache);
        assert_eq!(count, 3); // 2 forward + 1 PTR
        let found = cache.lookup_by_name("myhost", F_IPV4, now);
        assert!(found.is_some());
        assert_eq!(
            found.unwrap().addr.as_ref().unwrap().as_ipv4(),
            Some("192.168.1.1".parse().unwrap())
        );
    }

    #[test]
    fn parse_hosts_line_ipv6() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        let count = parse_hosts_line("::1  localhost6", 60, UID_NONE, now, &mut cache);
        assert_eq!(count, 2); // 1 forward + 1 PTR
        let found = cache.lookup_by_name("localhost6", F_IPV6, now);
        assert!(found.is_some());
    }

    #[test]
    fn parse_hosts_line_comment_stripped() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        // The hostname after '#' should not be inserted.
        let count = parse_hosts_line("10.0.0.1  real # ignored", 60, UID_NONE, now, &mut cache);
        assert_eq!(count, 2); // 1 forward + 1 PTR
        let found = cache.lookup_by_name("ignored", F_IPV4, now);
        assert!(found.is_none());
    }

    #[test]
    fn parse_hosts_line_blank_returns_zero() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(parse_hosts_line("", 60, UID_NONE, now, &mut cache), 0);
        assert_eq!(parse_hosts_line("  # comment only", 60, UID_NONE, now, &mut cache), 0);
    }

    #[test]
    fn load_hosts_file_real_etc_hosts() {
        let mut cache = DnsCache::new(1024);
        let now = Instant::now();
        // /etc/hosts always exists on Linux; at minimum 'localhost' should appear.
        let result = load_hosts_file("/etc/hosts", 60, now, &mut cache);
        assert!(result.is_ok(), "should read /etc/hosts");
        assert!(result.unwrap().1 > 0, "should load at least one record from /etc/hosts");
    }

    #[test]
    fn load_hosts_file_missing_returns_error() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        let result = load_hosts_file("/tmp/dnsmasq_rs_nonexistent_hosts_99999", 60, now, &mut cache);
        assert!(result.is_err());
    }

    #[test]
    fn reload_hosts_clears_old_entries() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        // Pre-populate the cache.
        parse_hosts_line("1.2.3.4  stale.example", 60, UID_NONE, now, &mut cache);
        assert!(cache.lookup_by_name("stale.example", F_IPV4, now).is_some());
        // reload_hosts with empty list → cache cleared.
        reload_hosts(&[], 60, &mut cache);
        assert!(cache.lookup_by_name("stale.example", F_IPV4, Instant::now()).is_none());
    }

    #[test]
    fn parse_hosts_line_inserts_ptr_record_ipv4() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        parse_hosts_line("192.168.1.5  myhost.example.com", 60, UID_NONE, now, &mut cache);
        // PTR name should be "5.1.168.192.in-addr.arpa"
        let ptr = cache.lookup_by_name("5.1.168.192.in-addr.arpa", F_IPV4 | F_REVERSE, now);
        assert!(ptr.is_some(), "should have PTR record");
        let rec = ptr.unwrap();
        assert!(rec.flags & F_REVERSE != 0);
        assert_eq!(rec.rdata.as_deref(), Some(b"myhost.example.com".as_ref()));
    }

    #[test]
    fn parse_hosts_line_inserts_ptr_record_ipv6() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        parse_hosts_line("::1  localhost6.example", 60, UID_NONE, now, &mut cache);
        let ptr_name = ipv6_ptr_name("::1".parse().unwrap());
        let ptr = cache.lookup_by_name(&ptr_name, F_IPV6 | F_REVERSE, now);
        assert!(ptr.is_some(), "should have IPv6 PTR record");
        let rec = ptr.unwrap();
        assert!(rec.flags & F_REVERSE != 0);
    }

    #[test]
    fn parse_hosts_line_has_hosts_flag() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        parse_hosts_line("10.0.0.7  flagtest", 60, UID_NONE, now, &mut cache);
        let rec = cache.lookup_by_name("flagtest", F_IPV4, now).unwrap();
        assert!(rec.flags & F_HOSTS != 0, "F_HOSTS flag should be set");
    }

    #[test]
    fn ipv4_ptr_name_format() {
        use std::net::Ipv4Addr;
        assert_eq!(ipv4_ptr_name(Ipv4Addr::new(192, 168, 1, 42)), "42.1.168.192.in-addr.arpa");
        assert_eq!(ipv4_ptr_name(Ipv4Addr::new(1, 2, 3, 4)), "4.3.2.1.in-addr.arpa");
    }

    #[test]
    fn ipv6_ptr_name_loopback() {
        use std::net::Ipv6Addr;
        let name = ipv6_ptr_name(Ipv6Addr::LOCALHOST);
        assert!(name.ends_with(".ip6.arpa"), "should end with .ip6.arpa");
        assert!(name.starts_with("1.0.0.0"), "loopback nibbles should be reversed");
    }

    #[test]
    fn a_record_from_hosts_finds_record() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        parse_hosts_line("10.1.2.3  findme.local", 60, UID_NONE, now, &mut cache);
        let ip = a_record_from_hosts("findme.local", now, &mut cache);
        assert_eq!(ip, Some("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn a_record_from_hosts_returns_none_for_missing() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        let ip = a_record_from_hosts("nosuchhost.local", now, &mut cache);
        assert_eq!(ip, None);
    }

    #[test]
    fn insert_config_cnames_basic() {
        use crate::types::dns_records::Cname;
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        let cnames = vec![
            Cname { ttl: 300, flag: 0, alias: "alias.example.com".into(), target: "real.example.com".into() },
        ];
        insert_config_cnames(&cnames, now, &mut cache);
        let rec = cache.lookup_by_name("alias.example.com", F_CNAME, now);
        assert!(rec.is_some(), "CNAME record should be inserted");
        let r = rec.unwrap();
        assert!(r.flags & F_CONFIG != 0, "F_CONFIG should be set");
        assert!(r.flags & F_CNAME != 0, "F_CNAME should be set");
    }

    #[test]
    fn insert_config_cnames_skips_wildcard() {
        use crate::types::dns_records::Cname;
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        let cnames = vec![
            Cname { ttl: 0, flag: 0, alias: "*.example.com".into(), target: "real.example.com".into() },
        ];
        insert_config_cnames(&cnames, now, &mut cache);
        // Wildcard aliases should be skipped
        assert!(cache.lookup_by_name("*.example.com", F_CNAME, now).is_none());
    }

    #[test]
    fn insert_host_records_basic() {
        use crate::types::dns_records::HostRecord;
        let mut cache = DnsCache::new(200);
        let now = Instant::now();
        let recs = vec![HostRecord {
            ttl: 60,
            flags: 0,
            names: vec!["hr.example.com".into()],
            addr4: Some("192.0.2.1".parse().unwrap()),
            addr6: None,
        }];
        insert_host_records(&recs, now, &mut cache);
        let fwd = cache.lookup_by_name("hr.example.com", F_IPV4, now);
        assert!(fwd.is_some(), "forward record should exist");
        let f = fwd.unwrap();
        assert!(f.flags & F_HOSTS != 0);
        assert!(f.flags & F_CONFIG != 0);
        // PTR record
        let ptr = cache.lookup_by_name("1.2.0.192.in-addr.arpa", F_IPV4 | F_REVERSE, now);
        assert!(ptr.is_some(), "PTR record should exist");
    }



    fn make_a_reply(name: &str, ip: std::net::Ipv4Addr) -> Vec<u8> {
        use crate::rfc1035::{DnsPacket, DnsQuestion, DnsRr};
        use crate::dns_protocol::DnsHeader;
        let pkt = DnsPacket {
            header: DnsHeader {
                // RA set, as the forwarding path sets it before extraction
                // (`forward.c:776`); `commit_staged` tests the bit.
                id: 1, hb3: 0x84, hb4: crate::dns_protocol::HB4_RA,
                qdcount: 1, ancount: 1, nscount: 0, arcount: 0,
            },
            questions: vec![DnsQuestion {
                name: name.to_string(), qtype: 1, qclass: 1,
            }],
            answers: vec![DnsRr {
                name: name.to_string(),
                rtype: 1, class: 1, ttl: 60,
                rdata: ip.octets().to_vec(),
            }],
            authority: vec![],
            additional: vec![],
        };
        pkt.write().to_vec()
    }

    #[test]
    fn cache_reply_populates_cache() {
        let mut cache = DnsCache::new(100);
        let wire = make_a_reply("example.com", "1.2.3.4".parse().unwrap());
        let cfg = crate::rfc1035::ExtractConfig::default();
        assert_eq!(
            cache_reply(&wire, &mut cache, &cfg),
            crate::rfc1035::ExtractResult::Cached,
        );
        let now = Instant::now();
        assert!(cache.lookup_by_name("example.com", F_IPV4, now).is_some());
    }

    #[test]
    fn cache_reply_bad_packet_reports_bad_packet() {
        let mut cache = DnsCache::new(100);
        let cfg = crate::rfc1035::ExtractConfig::default();
        assert_eq!(
            cache_reply(&[0u8; 3], &mut cache, &cfg),
            crate::rfc1035::ExtractResult::BadPacket,
        );
    }

    /// `cache-size=0` must keep the cache empty without breaking anything that
    /// runs around the insert — C reaches `really_insert()` and merely finds no
    /// free `crec`.
    #[test]
    fn cache_reply_with_caching_disabled_stores_nothing() {
        let mut cache = DnsCache::new(0);
        let wire = make_a_reply("example.com", "1.2.3.4".parse().unwrap());
        let cfg = crate::rfc1035::ExtractConfig::default();
        assert_eq!(
            cache_reply(&wire, &mut cache, &cfg),
            crate::rfc1035::ExtractResult::Cached,
            "a disabled cache must not turn a good reply into a bad one",
        );
        assert_eq!(cache.len(), 0);
        assert!(cache.lookup_by_name("example.com", F_IPV4, Instant::now()).is_none());
    }

    /// A rebind-blocked answer must be reported as such whether or not the
    /// cache has room for it: the check lives in `extract_addresses`, which C
    /// calls unconditionally (`forward.c:824`).
    #[test]
    fn cache_reply_reports_rebind_even_with_caching_disabled() {
        let wire = make_a_reply("evil.test", "192.168.1.5".parse().unwrap());
        let cfg = crate::rfc1035::ExtractConfig { check_rebind: true, ..Default::default() };
        for size in [0usize, 100] {
            let mut cache = DnsCache::new(size);
            assert_eq!(
                cache_reply(&wire, &mut cache, &cfg),
                crate::rfc1035::ExtractResult::RebindBlocked,
                "cache-size={size} must not change the rebind verdict",
            );
        }
    }

    // ------------------------------------------------------------------
    // Negative caching helpers
    // ------------------------------------------------------------------

    fn insert_nxdomain(cache: &mut DnsCache, name: &str, now: Instant) {
        cache.insert(CacheRecord {
            name: name.to_string(),
            flags: F_NEG | F_NXDOMAIN,
            ttl: 60,
            expires: now + Duration::from_secs(120),
            addr: None,
            rdata: None,
            uid: UID_NONE,
        });
    }

    #[test]
    fn is_nxdomain_true_when_cached() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        insert_nxdomain(&mut cache, "gone.example", now);
        assert!(cache.is_nxdomain("gone.example", now));
    }

    #[test]
    fn is_nxdomain_false_when_not_cached() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert!(!cache.is_nxdomain("unknown.example", now));
    }

    #[test]
    fn is_nxdomain_false_after_expiry() {
        let mut cache = DnsCache::new(100);
        let past = Instant::now() - Duration::from_secs(200);
        cache.insert(CacheRecord {
            name: "expired.example".to_string(),
            flags: F_NEG | F_NXDOMAIN,
            ttl: 60,
            expires: past,
            addr: None,
            rdata: None,
            uid: UID_NONE,
        });
        assert!(!cache.is_nxdomain("expired.example", Instant::now()));
    }

    // ------------------------------------------------------------------
    // next_uid / remove_by_uid
    // ------------------------------------------------------------------

    #[test]
    fn next_uid_never_returns_zero() {
        for _ in 0..100 {
            assert_ne!(next_uid(), UID_NONE);
        }
    }

    #[test]
    fn next_uid_monotonically_increases() {
        let a = next_uid();
        let b = next_uid();
        assert!(b > a, "UIDs should increase: {a} → {b}");
    }

    #[test]
    fn remove_by_uid_removes_matching_records() {
        let mut cache = DnsCache::new(64);
        let future    = Instant::now() + Duration::from_secs(600);
        let uid       = next_uid();

        let mut r1 = make_a_record("a.example.com", Ipv4Addr::new(1,1,1,1), 60, future);
        r1.flags |= F_HOSTS;
        r1.uid = uid;

        let mut r2 = make_a_record("b.example.com", Ipv4Addr::new(2,2,2,2), 60, future);
        r2.flags |= F_HOSTS;
        r2.uid = uid;

        let r3 = make_a_record("c.example.com", Ipv4Addr::new(3,3,3,3), 60, future);

        cache.insert(r1);
        cache.insert(r2);
        cache.insert(r3);
        assert_eq!(cache.len(), 3);

        let removed = cache.remove_by_uid(uid);
        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 1);
        assert!(cache.lookup_by_name("c.example.com", F_IPV4, Instant::now()).is_some());
    }

    #[test]
    fn remove_by_uid_none_removes_nothing() {
        let mut cache = DnsCache::new(16);
        let future    = Instant::now() + Duration::from_secs(300);
        cache.insert(make_a_record("x.example.com", Ipv4Addr::new(9,9,9,9), 60, future));
        assert_eq!(cache.remove_by_uid(UID_NONE), 0);
        assert_eq!(cache.len(), 1);
    }

    // ------------------------------------------------------------------
    // non_terminal_names / insert_with_non_terminals
    // ------------------------------------------------------------------

    #[test]
    fn non_terminal_names_multi_label() {
        let parents = non_terminal_names("foo.bar.example.com");
        assert_eq!(parents, vec!["bar.example.com", "example.com"]);
    }

    #[test]
    fn non_terminal_names_single_label() {
        assert!(non_terminal_names("example.com").is_empty());
    }

    #[test]
    fn insert_with_non_terminals_creates_parent_entries() {
        use crate::types::constants::F_HOSTS;
        let mut cache = DnsCache::new(64);
        let future    = Instant::now() + Duration::from_secs(300);
        let uid       = next_uid();

        let rec = CacheRecord {
            name:    "deep.inner.example.com".into(),
            flags:   F_IPV4 | F_FORWARD | F_HOSTS,
            ttl:     300,
            expires: future,
            addr:    Some(AllAddr::Addr4(Ipv4Addr::new(10, 0, 0, 1))),
            rdata:   None,
            uid,
        };
        cache.insert_with_non_terminals(rec);

        // Real record must be findable.
        assert!(cache.lookup_by_name("deep.inner.example.com", F_IPV4, Instant::now()).is_some());
        // There must be more entries than just the real record (non-terminals inserted).
        assert!(cache.len() > 1, "non-terminal entries expected, got {}", cache.len());
    }

    // ------------------------------------------------------------------
    // iter_live
    // ------------------------------------------------------------------

    #[test]
    fn iter_live_excludes_expired() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();

        cache.insert(make_a_record("live.example", Ipv4Addr::new(1,1,1,1), 300,
                                   now + Duration::from_secs(300)));
        cache.insert(make_a_record("dead.example", Ipv4Addr::new(2,2,2,2), 1,
                                   now - Duration::from_secs(1)));

        let live_names: Vec<&str> = cache.iter_live(now).map(|r| r.name.as_str()).collect();
        assert!(live_names.contains(&"live.example"));
        assert!(!live_names.contains(&"dead.example"));
    }

    // ------------------------------------------------------------------
    // really_insert / InsertOutcome / evict_expired
    // ------------------------------------------------------------------

    fn make_dns_record(name: &str, ip: Ipv4Addr, ttl: u32, now: Instant) -> CacheRecord {
        CacheRecord {
            name:    name.to_string(),
            flags:   F_IPV4 | F_FORWARD,
            ttl,
            expires: now + Duration::from_secs(u64::from(ttl)),
            addr:    Some(AllAddr::Addr4(ip)),
            rdata:   None,
            uid:     UID_NONE,
        }
    }

    /// A NODATA entry is stored with the queried type bit *plus* `F_NEG`.  C
    /// finds it again because `cache_find_by_name()` matches bitwise; here the
    /// key is exact, so `lookup_forward` has to probe the negative key too or
    /// every NODATA entry is written somewhere nothing ever reads.
    fn make_nodata_record(name: &str, type_flag: u32, ttl: u32, now: Instant) -> CacheRecord {
        CacheRecord {
            name:    name.to_string(),
            flags:   type_flag | F_NEG | F_FORWARD,
            ttl,
            expires: now + Duration::from_secs(u64::from(ttl)),
            addr:    None,
            rdata:   None,
            uid:     UID_NONE,
        }
    }

    #[test]
    fn lookup_forward_finds_a_nodata_negative_entry() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        cache.insert(make_nodata_record("v4only.test", F_IPV6, 300, now));

        assert!(
            cache.lookup_by_name("v4only.test", F_IPV6, now).is_none(),
            "the plain type key is genuinely empty — that is the bug being fixed",
        );
        let rec = cache
            .lookup_forward("v4only.test", F_IPV6, now)
            .expect("the NODATA entry must be reachable");
        assert!(rec.flags & F_NEG != 0);
        assert_eq!(cache.stats().hits, 1, "one probe, one hit");
    }

    #[test]
    fn lookup_forward_prefers_the_positive_record() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        cache.insert(make_nodata_record("both.test", F_IPV4, 300, now));
        cache.insert(make_dns_record("both.test", Ipv4Addr::new(9, 9, 9, 9), 300, now));

        let rec = cache
            .lookup_forward("both.test", F_IPV4, now)
            .expect("the positive record must win");
        assert_eq!(rec.flags & F_NEG, 0);
        assert_eq!(rec.addr.as_ref().and_then(|a| a.as_ipv4()), Some(Ipv4Addr::new(9, 9, 9, 9)));
    }

    #[test]
    fn lookup_forward_is_per_type() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        cache.insert(make_nodata_record("mixed.test", F_IPV6, 300, now));

        assert!(
            cache.lookup_forward("mixed.test", F_IPV4, now).is_none(),
            "an AAAA NODATA entry must not answer an A lookup",
        );
    }

    #[test]
    fn lookup_forward_counts_one_miss_on_an_empty_cache() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        assert!(cache.lookup_forward("nothing.test", F_IPV4, now).is_none());
        assert_eq!(cache.stats().misses, 1, "both probes together are a single miss");
    }

    #[test]
    fn lookup_forward_evicts_an_expired_negative_entry() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        cache.insert(make_nodata_record("gone.test", F_IPV4, 10, now));

        let later = now + Duration::from_secs(11);
        assert!(cache.lookup_forward("gone.test", F_IPV4, later).is_none());
        assert_eq!(cache.stats().size, 0, "the expired negative entry must be dropped");
    }

    #[test]
    fn really_insert_basic_inserts_record() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        let rec       = make_dns_record("a.test", Ipv4Addr::new(1,1,1,1), 300, now);
        let outcome   = cache.really_insert(rec, now);
        assert_eq!(outcome, InsertOutcome::Inserted);
        assert!(cache.lookup_by_name("a.test", F_IPV4, now).is_some());
    }

    /// `crec_ttl()` (`rfc1035.c:1570`) serves `ttd - now`, so a client never
    /// sees more lifetime than the record actually has left.
    #[test]
    fn crec_ttl_counts_down_for_dns_answers() {
        let now = Instant::now();
        let rec = make_dns_record("countdown.test", Ipv4Addr::new(1, 1, 1, 1), 300, now);

        assert_eq!(DnsCache::crec_ttl(&rec, now), 300, "fresh record serves its full TTL");
        assert_eq!(
            DnsCache::crec_ttl(&rec, now + Duration::from_secs(120)),
            180,
            "after 120s of a 300s TTL, 180s remain",
        );
        assert_eq!(
            DnsCache::crec_ttl(&rec, now + Duration::from_secs(500)),
            0,
            "an expired record must never report a negative or wrapped TTL",
        );
    }

    /// Immortal entries (config / hosts / DHCP) hold their configured TTL in
    /// the TTL field and are served with it verbatim — they do not count down.
    #[test]
    fn crec_ttl_is_constant_for_immortal_records() {
        let now = Instant::now();
        let mut rec = make_dns_record("static.test", Ipv4Addr::new(1, 1, 1, 1), 60, now);
        rec.flags |= F_IMMORTAL | F_HOSTS;

        assert_eq!(DnsCache::crec_ttl(&rec, now), 60);
        assert_eq!(DnsCache::crec_ttl(&rec, now + Duration::from_secs(9999)), 60);
    }

    /// `cache-size=0` keeps the cache empty, but the insert path still runs to
    /// completion so its callers' side effects are unaffected.
    #[test]
    fn really_insert_with_zero_size_stores_nothing() {
        let mut cache = DnsCache::new(0);
        let now = Instant::now();
        let rec = make_dns_record("nowhere.test", Ipv4Addr::new(3, 3, 3, 3), 300, now);

        assert_eq!(cache.really_insert(rec, now), InsertOutcome::CachingDisabled);
        assert!(cache.is_empty());
        assert!(cache.lookup_by_name("nowhere.test", F_IPV4, now).is_none());
    }

    #[test]
    fn really_insert_zero_ttl_dropped() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        let rec       = make_dns_record("zero.test", Ipv4Addr::new(2,2,2,2), 0, now);
        let outcome   = cache.really_insert(rec, now);
        assert_eq!(outcome, InsertOutcome::ZeroTtlDropped);
        assert!(cache.is_empty());
    }

    #[test]
    fn really_insert_clamps_max_ttl() {
        let mut cache = DnsCache::with_ttl_limits(16, 0, 60);
        let now       = Instant::now();
        let rec       = make_dns_record("big.ttl", Ipv4Addr::new(3,3,3,3), 9999, now);
        cache.really_insert(rec, now);
        let found = cache.lookup_by_name("big.ttl", F_IPV4, now).unwrap();
        assert_eq!(found.ttl, 60, "TTL should be clamped to max_cache_ttl");
    }

    #[test]
    fn really_insert_clamps_min_ttl() {
        let mut cache = DnsCache::with_ttl_limits(16, 120, 0);
        let now       = Instant::now();
        let rec       = make_dns_record("small.ttl", Ipv4Addr::new(4,4,4,4), 10, now);
        cache.really_insert(rec, now);
        let found = cache.lookup_by_name("small.ttl", F_IPV4, now).unwrap();
        assert_eq!(found.ttl, 120, "TTL should be raised to min_cache_ttl");
    }

    #[test]
    fn really_insert_blocked_same_addr() {
        use crate::types::constants::F_HOSTS;
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();

        // Insert a static hosts record.
        let mut static_rec = make_a_record("static.test", Ipv4Addr::new(5,5,5,5), 0,
                                            now + Duration::from_secs(9999));
        static_rec.flags = F_IPV4 | F_FORWARD | F_HOSTS | F_IMMORTAL;
        cache.insert(static_rec);

        // Try to insert a DNS answer with the same address.
        let dns_rec = make_dns_record("static.test", Ipv4Addr::new(5,5,5,5), 300, now);
        let outcome = cache.really_insert(dns_rec, now);
        assert_eq!(outcome, InsertOutcome::BlockedSameAddr);
        // Cache should still have exactly one record.
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn really_insert_blocked_conflict() {
        use crate::types::constants::F_HOSTS;
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();

        let mut static_rec = make_a_record("conflict.test", Ipv4Addr::new(6,6,6,6), 0,
                                            now + Duration::from_secs(9999));
        static_rec.flags = F_IPV4 | F_FORWARD | F_HOSTS | F_IMMORTAL;
        cache.insert(static_rec);

        // Try to overwrite with a different address.
        let dns_rec = make_dns_record("conflict.test", Ipv4Addr::new(7,7,7,7), 300, now);
        let outcome = cache.really_insert(dns_rec, now);
        assert_eq!(outcome, InsertOutcome::BlockedConflict);
        // The original address must still be there.
        let found = cache.lookup_by_name("conflict.test", F_IPV4, now).unwrap();
        assert_eq!(found.addr.as_ref().unwrap().as_ipv4(), Some(Ipv4Addr::new(6,6,6,6)));
    }

    #[test]
    fn evict_expired_removes_only_expired() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();

        cache.insert(make_a_record("live.e",    Ipv4Addr::new(1,1,1,1), 300, now + Duration::from_secs(300)));
        cache.insert(make_a_record("dead1.e",   Ipv4Addr::new(2,2,2,2), 1,   now - Duration::from_secs(1)));
        cache.insert(make_a_record("dead2.e",   Ipv4Addr::new(3,3,3,3), 1,   now - Duration::from_secs(2)));
        assert_eq!(cache.len(), 3);

        let removed = cache.evict_expired(now);
        assert_eq!(removed, 2);
        assert_eq!(cache.len(), 1);
        assert!(cache.lookup_by_name("live.e", F_IPV4, now).is_some());
    }

    #[test]
    fn dnssec_min_ttl_enforced() {
        use crate::types::constants::F_DNSKEY;
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        let rec = CacheRecord {
            name:    "example.com".into(),
            flags:   F_DNSKEY | F_FORWARD,
            ttl:     5, // below DNSSEC_MIN_TTL
            expires: now + Duration::from_secs(5),
            addr:    None,
            rdata:   Some(vec![0xDE, 0xAD]),
            uid:     UID_NONE,
        };
        cache.really_insert(rec, now);
        let found = cache.lookup_by_name("example.com", F_DNSKEY, now).unwrap();
        assert_eq!(found.ttl, DNSSEC_MIN_TTL, "DNSKEY TTL should be raised to DNSSEC_MIN_TTL");
    }

    // ------------------------------------------------------------------
    // lookup_all_by_name / lookup_prot / lookup_all_by_addr / CacheStats
    // ------------------------------------------------------------------

    #[test]
    fn lookup_all_by_name_returns_matching_types() {
        use std::net::Ipv6Addr;
        let mut cache = DnsCache::new(64);
        let now       = Instant::now();
        let future    = now + Duration::from_secs(300);

        // Insert both an A and AAAA record for the same name.
        cache.insert(make_a_record("dual.example", Ipv4Addr::new(1,2,3,4), 300, future));
        cache.insert(CacheRecord {
            name:    "dual.example".into(),
            flags:   F_IPV6 | F_FORWARD,
            ttl:     300,
            expires: future,
            addr:    Some(AllAddr::Addr6(Ipv6Addr::LOCALHOST)),
            rdata:   None,
            uid:     UID_NONE,
        });

        // Query with both IPv4 and IPv6 mask should return both.
        let results = cache.lookup_all_by_name("dual.example", F_IPV4 | F_IPV6, now);
        assert_eq!(results.len(), 2, "expected A and AAAA records");

        // Query with only IPv4 mask should return one.
        let results4 = cache.lookup_all_by_name("dual.example", F_IPV4, now);
        assert_eq!(results4.len(), 1);
        assert!(results4[0].flags & F_IPV4 != 0);
    }

    #[test]
    fn lookup_all_by_name_evicts_expired() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();

        cache.insert(make_a_record("ex.test", Ipv4Addr::new(1,1,1,1), 300,
                                   now + Duration::from_secs(300)));
        cache.insert(make_a_record("dead.test", Ipv4Addr::new(2,2,2,2), 1,
                                   now - Duration::from_secs(5)));
        assert_eq!(cache.len(), 2);

        // Querying any name triggers expiry sweep.
        let _ = cache.lookup_all_by_name("ex.test", F_IPV4, now);
        assert_eq!(cache.len(), 1, "expired record should have been evicted");
    }

    #[test]
    fn lookup_prot_returns_first_match() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        let future    = now + Duration::from_secs(300);
        cache.insert(make_a_record("first.test", Ipv4Addr::new(5,5,5,5), 300, future));

        let hit = cache.lookup_prot("first.test", F_IPV4, now);
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().addr.unwrap().as_ipv4(), Some(Ipv4Addr::new(5,5,5,5)));
    }

    #[test]
    fn lookup_prot_miss_returns_none() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        assert!(cache.lookup_prot("no.such.name", F_IPV4, now).is_none());
    }

    #[test]
    fn lookup_all_by_addr_finds_ptr_records() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        let future    = now + Duration::from_secs(300);
        let ip        = Ipv4Addr::new(10, 0, 0, 1);

        let mut ptr = make_ptr_record("host.example", ip, 300, future);
        cache.insert(ptr);

        let results = cache.lookup_all_by_addr(
            &AllAddr::Addr4(ip), F_IPV4, now);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].name, "host.example");
    }

    #[test]
    fn lookup_all_by_addr_empty_on_miss() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        let results   = cache.lookup_all_by_addr(
            &AllAddr::Addr4(Ipv4Addr::new(1,2,3,4)), F_IPV4, now);
        assert!(results.is_empty());
    }

    #[test]
    fn cache_stats_tracks_hits_and_misses() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        let future    = now + Duration::from_secs(300);
        cache.insert(make_a_record("stats.test", Ipv4Addr::new(1,1,1,1), 60, future));

        let _ = cache.lookup_by_name("stats.test", F_IPV4, now); // hit
        let _ = cache.lookup_by_name("nope.test",  F_IPV4, now); // miss

        let s = cache.stats();
        assert!(s.hits   >= 1);
        assert!(s.misses >= 1);
        assert_eq!(s.size, 1);
    }

    #[test]
    fn cache_count_excludes_expired() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        cache.insert(make_a_record("live2.test", Ipv4Addr::new(1,1,1,1), 300,
                                   now + Duration::from_secs(300)));
        cache.insert(make_a_record("dead3.test", Ipv4Addr::new(2,2,2,2), 1,
                                   now - Duration::from_secs(1)));
        assert_eq!(cache.cache_count(now), 1);
    }

    // ------------------------------------------------------------------
    // rrtype / rrtype_name / querystr / format_cache_entry
    // ------------------------------------------------------------------

    #[test]
    fn rrtype_name_known_types() {
        assert_eq!(rrtype_name(1),  Some("A"));
        assert_eq!(rrtype_name(28), Some("AAAA"));
        assert_eq!(rrtype_name(5),  Some("CNAME"));
        assert_eq!(rrtype_name(255),Some("ANY"));
        assert_eq!(rrtype_name(48), Some("DNSKEY"));
    }

    #[test]
    fn rrtype_name_unknown_returns_none() {
        assert_eq!(rrtype_name(65535), None);
    }

    #[test]
    fn rrtype_from_name_roundtrip() {
        for &(num, name) in &[
            (1u16,  "A"),
            (28,    "AAAA"),
            (12,    "PTR"),
            (15,    "MX"),
            (48,    "DNSKEY"),
            (43,    "DS"),
            (257,   "CAA"),
        ] {
            assert_eq!(rrtype(name), num, "rrtype({name}) should be {num}");
            assert_eq!(rrtype_name(num), Some(name), "rrtype_name({num}) should be {name}");
        }
    }

    #[test]
    fn rrtype_case_insensitive() {
        assert_eq!(rrtype("aaaa"), 28);
        assert_eq!(rrtype("AAAA"), 28);
        assert_eq!(rrtype("AaAa"), 28);
    }

    #[test]
    fn rrtype_unknown_name_returns_zero() {
        assert_eq!(rrtype("BOGUS"), 0);
    }

    #[test]
    fn querystr_known_type_no_desc() {
        assert_eq!(querystr(None, 1),  "<A>");
        assert_eq!(querystr(None, 28), "<AAAA>");
    }

    #[test]
    fn querystr_unknown_type_no_desc() {
        assert_eq!(querystr(None, 9999), "<type=9999>");
    }

    #[test]
    fn querystr_with_desc() {
        assert_eq!(querystr(Some("query"), 1),    "query[A]");
        assert_eq!(querystr(Some("query"), 9999), "query[type=9999]");
    }

    #[test]
    fn format_cache_entry_a_record() {
        let now = Instant::now();
        let rec = make_a_record("host.example.com", Ipv4Addr::new(1,2,3,4), 300,
                                now + Duration::from_secs(300));
        let line = format_cache_entry(&rec, now);
        assert!(line.contains("host.example.com"), "name missing: {line}");
        assert!(line.contains("1.2.3.4"),          "addr missing: {line}");
        assert!(line.contains("4F"),               "type+flag missing: {line}");
    }

    #[test]
    fn format_cache_entry_immortal_has_no_expiry() {
        let now = Instant::now();
        let mut rec = make_a_record("im.test", Ipv4Addr::new(9,9,9,9), 0,
                                   now + Duration::from_secs(9999));
        rec.flags |= F_IMMORTAL;
        let line = format_cache_entry(&rec, now);
        // Immortal records should not have an expiry time in the output.
        assert!(!line.trim_end().ends_with('s'), "immortal should have blank expiry: {line}");
    }

    #[test]
    fn dump_cache_returns_one_line_per_record() {
        let mut cache = DnsCache::new(16);
        let now       = Instant::now();
        let future    = now + Duration::from_secs(300);
        cache.insert(make_a_record("a.test", Ipv4Addr::new(1,1,1,1), 300, future));
        cache.insert(make_a_record("b.test", Ipv4Addr::new(2,2,2,2), 300, future));
        let lines = dump_cache(&cache, now);
        assert_eq!(lines.len(), 2);
    }

    // ── cache_find_non_terminal ──────────────────────────────────────────────

    #[test]
    fn cache_find_non_terminal_present() {
        let mut cache = DnsCache::new(16);
        let now = Instant::now();
        let future = now + Duration::from_secs(300);
        cache.insert(make_a_record("example.com", Ipv4Addr::new(1,2,3,4), 300, future));
        assert!(cache_find_non_terminal("example.com", now, &cache));
    }

    #[test]
    fn cache_find_non_terminal_absent() {
        let cache = DnsCache::new(16);
        let now = Instant::now();
        assert!(!cache_find_non_terminal("noexist.com", now, &cache));
    }

    #[test]
    fn cache_find_non_terminal_case_insensitive() {
        let mut cache = DnsCache::new(16);
        let now = Instant::now();
        let future = now + Duration::from_secs(300);
        cache.insert(make_a_record("Example.COM", Ipv4Addr::new(1,2,3,4), 300, future));
        assert!(cache_find_non_terminal("example.com", now, &cache));
    }

    // ── cache_unhash_dhcp ────────────────────────────────────────────────────

    #[test]
    fn cache_unhash_dhcp_removes_dhcp_entries() {
        use crate::types::constants::F_DHCP;
        let mut cache = DnsCache::new(16);
        let now = Instant::now();
        let future = now + Duration::from_secs(300);
        let mut rec = make_a_record("dhcp-host.lan", Ipv4Addr::new(10,0,0,1), 300, future);
        rec.flags |= F_DHCP;
        rec.uid = 99; // non-zero so remove_by_uid works
        cache.insert(rec);
        let mut rec2 = make_a_record("normal.com", Ipv4Addr::new(8,8,8,8), 300, future);
        rec2.uid = 100;
        cache.insert(rec2);
        assert_eq!(cache.len(), 2);
        let removed = cache_unhash_dhcp(&mut cache, now);
        assert_eq!(removed, 1);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_unhash_dhcp_empty_cache() {
        let mut cache = DnsCache::new(16);
        let now = Instant::now();
        assert_eq!(cache_unhash_dhcp(&mut cache, now), 0);
    }
}

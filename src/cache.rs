//! DNS cache — idiomatic Rust port of `cache.c` from dnsmasq.
//!
//! The cache is a bounded LRU map keyed by `(name, type-flags)`.  Expired
//! entries are evicted lazily on lookup and proactively via `expire_old`.

use std::num::NonZeroUsize;
use std::time::Instant;

use lru::LruCache;

use crate::metrics::{inc_metric, Metric};
use crate::types::addr::AllAddr;
use crate::types::constants::{
    F_CNAME, F_DNSSEC, F_DNSKEY, F_DS, F_FORWARD, F_IMMORTAL, F_IPV4, F_IPV6, F_NEG,
    F_NXDOMAIN, F_REVERSE, F_RR,
};

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
}

/// The DNS cache — bounded LRU map with per-query statistics.
pub struct DnsCache {
    max_size: usize,
    records:  LruCache<CacheKey, CacheRecord>,
    // statistics
    pub inserts:   u64,
    pub evictions: u64,
    pub hits:      u64,
    pub misses:    u64,
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

impl DnsCache {
    /// Create a new cache with the given maximum number of entries.
    ///
    /// # Panics
    /// Panics if `max_size` is zero.
    pub fn new(max_size: usize) -> Self {
        let capacity = NonZeroUsize::new(max_size)
            .expect("DnsCache max_size must be non-zero");
        Self {
            max_size,
            records: LruCache::new(capacity),
            inserts:   0,
            evictions: 0,
            hits:      0,
            misses:    0,
        }
    }

    /// Insert (or replace) a record in the cache.
    ///
    /// The LRU crate evicts the least-recently-used entry automatically when
    /// the cache is full; we track that as an eviction.
    pub fn insert(&mut self, rec: CacheRecord) {
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
}

// ---------------------------------------------------------------------------
// extract_addresses integration
// ---------------------------------------------------------------------------

/// Process a raw DNS reply packet by:
/// 1. Parsing the wire-format packet.
/// 2. Calling [`crate::rfc1035::extract_addresses`] to populate `cache`.
///
/// Returns `true` if the packet was successfully processed (even if nothing
/// was cached), `false` if the packet is malformed.
///
/// This is the primary integration point between the forwarding engine and
/// the DNS cache.  Call this every time an upstream reply is received.
pub fn cache_reply(
    wire: &[u8],
    cache: &mut DnsCache,
    config: &crate::rfc1035::ExtractConfig,
) -> bool {
    use std::time::Instant;
    use crate::rfc1035::{extract_addresses, ExtractResult, DnsPacket};

    let packet = match DnsPacket::parse(wire) {
        Ok(p) => p,
        Err(_) => return false,
    };

    let now = Instant::now();
    match extract_addresses(&packet, cache, now, config) {
        ExtractResult::BadPacket => false,
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// /etc/hosts file loading
// ---------------------------------------------------------------------------

/// Parse a single `/etc/hosts`-format line into cache records and append them
/// to `cache`.
///
/// Format: `ip_addr  hostname [alias ...]`  (with optional comment after `#`)
///
/// Returns the number of records inserted.
pub fn parse_hosts_line(line: &str, ttl: u32, now: Instant, cache: &mut DnsCache) -> usize {
    // Strip comments.
    let line = if let Some(idx) = line.find('#') { &line[..idx] } else { line };
    let line = line.trim();
    if line.is_empty() { return 0; }

    let mut parts = line.split_whitespace();
    let ip_str = match parts.next() { Some(s) => s, None => return 0 };
    let expires = now + std::time::Duration::from_secs(u64::from(ttl) + 3600);
    let mut count = 0;

    if let Ok(ip4) = ip_str.parse::<std::net::Ipv4Addr>() {
        let addr = AllAddr::Addr4(ip4);
        for name in parts {
            let name = name.to_ascii_lowercase();
            cache.insert(CacheRecord {
                name,
                flags: F_IPV4 | F_FORWARD | F_IMMORTAL,
                ttl,
                expires,
                addr: Some(addr.clone()),
                rdata: None,
            });
            count += 1;
        }
    } else if let Ok(ip6) = ip_str.parse::<std::net::Ipv6Addr>() {
        let addr = AllAddr::Addr6(ip6);
        for name in parts {
            let name = name.to_ascii_lowercase();
            cache.insert(CacheRecord {
                name,
                flags: F_IPV6 | F_FORWARD | F_IMMORTAL,
                ttl,
                expires,
                addr: Some(addr.clone()),
                rdata: None,
            });
            count += 1;
        }
    }

    count
}

/// Load `/etc/hosts` (or any hosts-format file at `path`) into `cache`.
///
/// All inserted entries use `F_IMMORTAL` so they are never expired by TTL.
/// Returns the number of records inserted, or an `io::Error` on read failure.
pub fn load_hosts_file(
    path: &str,
    ttl: u32,
    now: Instant,
    cache: &mut DnsCache,
) -> std::io::Result<usize> {
    let text = std::fs::read_to_string(path)?;
    let total = text.lines()
        .map(|l| parse_hosts_line(l, ttl, now, cache))
        .sum();
    Ok(total)
}

/// Reload all hosts files listed in `paths` into a (pre-cleared) cache.
///
/// Clears the cache first so stale entries from previous loads are removed,
/// then re-loads each file in order.  Returns the total records inserted.
pub fn reload_hosts(
    paths: &[String],
    ttl: u32,
    cache: &mut DnsCache,
) -> usize {
    let now = Instant::now();
    cache.clear();
    let mut total = 0;
    for path in paths {
        match load_hosts_file(path, ttl, now, cache) {
            Ok(n) => total += n,
            Err(e) => {
                // Non-fatal: log and continue with remaining files.
                eprintln!("dnsmasq-rs: warning: could not read {path}: {e}");
            }
        }
    }
    total
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
        let count = parse_hosts_line("192.168.1.1  myhost myhost.local", 60, now, &mut cache);
        assert_eq!(count, 2);
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
        let count = parse_hosts_line("::1  localhost6", 60, now, &mut cache);
        assert_eq!(count, 1);
        let found = cache.lookup_by_name("localhost6", F_IPV6, now);
        assert!(found.is_some());
    }

    #[test]
    fn parse_hosts_line_comment_stripped() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        // The hostname after '#' should not be inserted.
        let count = parse_hosts_line("10.0.0.1  real # ignored", 60, now, &mut cache);
        assert_eq!(count, 1);
        let found = cache.lookup_by_name("ignored", F_IPV4, now);
        assert!(found.is_none());
    }

    #[test]
    fn parse_hosts_line_blank_returns_zero() {
        let mut cache = DnsCache::new(100);
        let now = Instant::now();
        assert_eq!(parse_hosts_line("", 60, now, &mut cache), 0);
        assert_eq!(parse_hosts_line("  # comment only", 60, now, &mut cache), 0);
    }

    #[test]
    fn load_hosts_file_real_etc_hosts() {
        let mut cache = DnsCache::new(1024);
        let now = Instant::now();
        // /etc/hosts always exists on Linux; at minimum 'localhost' should appear.
        let result = load_hosts_file("/etc/hosts", 60, now, &mut cache);
        assert!(result.is_ok(), "should read /etc/hosts");
        assert!(result.unwrap() > 0, "should load at least one record from /etc/hosts");
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
        parse_hosts_line("1.2.3.4  stale.example", 60, now, &mut cache);
        assert!(cache.lookup_by_name("stale.example", F_IPV4, now).is_some());
        // reload_hosts with empty list → cache cleared.
        reload_hosts(&[], 60, &mut cache);
        assert!(cache.lookup_by_name("stale.example", F_IPV4, Instant::now()).is_none());
    }

    // ------------------------------------------------------------------
    // cache_reply / extract_addresses integration
    // ------------------------------------------------------------------

    fn make_a_reply(name: &str, ip: std::net::Ipv4Addr) -> Vec<u8> {
        use crate::rfc1035::{DnsPacket, DnsQuestion, DnsRr};
        use crate::dns_protocol::DnsHeader;
        let pkt = DnsPacket {
            header: DnsHeader {
                id: 1, hb3: 0x84, hb4: 0x00,
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
        let ok = cache_reply(&wire, &mut cache, &cfg);
        assert!(ok);
        let now = Instant::now();
        assert!(cache.lookup_by_name("example.com", F_IPV4, now).is_some());
    }

    #[test]
    fn cache_reply_bad_packet_returns_false() {
        let mut cache = DnsCache::new(100);
        let cfg = crate::rfc1035::ExtractConfig::default();
        assert!(!cache_reply(&[0u8; 3], &mut cache, &cfg));
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
        });
        assert!(!cache.is_nxdomain("expired.example", Instant::now()));
    }
}

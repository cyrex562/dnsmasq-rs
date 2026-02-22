//! Integration tests for the DNS cache.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use dnsmasq_rs::cache::{CacheRecord, DnsCache};
use dnsmasq_rs::types::addr::AllAddr;
use dnsmasq_rs::types::constants::{F_FORWARD, F_IMMORTAL, F_IPV4, F_IPV6};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn cache_insert_lookup_evict() {
    const MAX: usize = 3;
    let mut cache = DnsCache::new(MAX);
    let far_future = Instant::now() + Duration::from_secs(3600);

    // Fill the cache to capacity.
    for i in 0..MAX {
        let name = format!("host{}.example.com", i);
        cache.insert(make_a_record(&name, Ipv4Addr::new(10, 0, 0, i as u8), 300, far_future));
    }
    assert_eq!(cache.len(), MAX);
    assert_eq!(cache.inserts, MAX as u64);
    assert_eq!(cache.evictions, 0);

    // Insert one more — the LRU entry (host0) should be evicted.
    cache.insert(make_a_record("host3.example.com", Ipv4Addr::new(10, 0, 0, 3), 300, far_future));
    assert_eq!(cache.len(), MAX, "cache should stay at max_size");
    assert_eq!(cache.evictions, 1, "one eviction should have occurred");

    // The newly inserted entry must be reachable.
    let now = Instant::now();
    let found = cache.lookup_by_name("host3.example.com", F_IPV4 | F_FORWARD, now);
    assert!(found.is_some(), "host3 should be present after insertion");
}

#[test]
fn cache_ttl_expiry() {
    let mut cache = DnsCache::new(10);
    // Create a record whose expiry is in the past.
    let already_expired = Instant::now() - Duration::from_millis(100);
    cache.insert(make_a_record("expired.example.com", Ipv4Addr::new(1, 2, 3, 4), 1, already_expired));

    let now = Instant::now();
    let result = cache.lookup_by_name("expired.example.com", F_IPV4 | F_FORWARD, now);
    assert!(result.is_none(), "expired record should not be returned");
    assert_eq!(cache.misses, 1);

    // Also confirm the entry was actually removed.
    assert_eq!(cache.len(), 0, "expired entry should be removed on lookup");
}

#[test]
fn cache_reverse_lookup() {
    let mut cache = DnsCache::new(10);
    let far_future = Instant::now() + Duration::from_secs(3600);
    let ip = Ipv4Addr::new(192, 168, 1, 100);

    cache.insert(make_a_record("myhost.local", ip, 300, far_future));

    let now = Instant::now();
    let needle = AllAddr::Addr4(ip);
    let rec = cache.lookup_by_addr(&needle, now).expect("reverse lookup should find the record");
    assert_eq!(rec.name, "myhost.local");
}

#[test]
fn cache_clear() {
    let mut cache = DnsCache::new(20);
    let far_future = Instant::now() + Duration::from_secs(3600);

    for i in 0..5u8 {
        cache.insert(make_a_record(
            &format!("h{}.example.com", i),
            Ipv4Addr::new(10, 0, 0, i),
            300,
            far_future,
        ));
    }
    assert_eq!(cache.len(), 5);

    cache.clear();
    assert!(cache.is_empty(), "cache should be empty after clear");

    // Lookups after clear should all be misses.
    let now = Instant::now();
    assert!(cache.lookup_by_name("h0.example.com", F_IPV4 | F_FORWARD, now).is_none());
}

#[test]
fn cache_stats_tracking() {
    let mut cache = DnsCache::new(5);
    let far_future = Instant::now() + Duration::from_secs(3600);
    let now = Instant::now();

    // Initial state: all counters at zero.
    assert_eq!(cache.inserts, 0);
    assert_eq!(cache.hits, 0);
    assert_eq!(cache.misses, 0);
    assert_eq!(cache.evictions, 0);

    // One insert.
    cache.insert(make_a_record("stats.example.com", Ipv4Addr::new(1, 1, 1, 1), 300, far_future));
    assert_eq!(cache.inserts, 1);

    // Hit.
    assert!(cache.lookup_by_name("stats.example.com", F_IPV4 | F_FORWARD, now).is_some());
    assert_eq!(cache.hits, 1);

    // Miss (name not in cache).
    assert!(cache.lookup_by_name("notfound.example.com", F_IPV4 | F_FORWARD, now).is_none());
    assert_eq!(cache.misses, 1);

    // Fill to capacity then cause evictions.
    for i in 1..5u8 {
        cache.insert(make_a_record(
            &format!("e{}.example.com", i),
            Ipv4Addr::new(10, 0, 0, i),
            300,
            far_future,
        ));
    }
    // Cache is now full (5 entries). One more insert → one eviction.
    cache.insert(make_a_record("extra.example.com", Ipv4Addr::new(5, 5, 5, 5), 300, far_future));
    assert_eq!(cache.evictions, 1);
    assert_eq!(cache.inserts, 6);
}

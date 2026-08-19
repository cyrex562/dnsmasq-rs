//! Integration tests for the DNS cache.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use dnsmasq_rs::cache::{cache_reply, CacheRecord, DnsCache};
use dnsmasq_rs::dns_protocol::{DnsHeader, HB3_QR, HB3_RD, HB4_RA};
use dnsmasq_rs::rfc1035::{
    answer_request, DnsPacket, DnsQuestion, DnsRr, ExtractConfig, ExtractResult, LocalConfig,
};
use dnsmasq_rs::types::addr::AllAddr;
use dnsmasq_rs::types::constants::{F_FORWARD, F_IMMORTAL, F_IPV4, F_IPV6, UID_NONE};

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
        uid: UID_NONE,
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

// ---------------------------------------------------------------------------
// Reply → cache → answer round trip
//
// These drive the exact pair of functions the live forwarding loop uses —
// `cache::cache_reply` on the reply path and `rfc1035::answer_request` on the
// query path — so the hit/miss counters move for the same reasons they do at
// run time.
// ---------------------------------------------------------------------------

fn a_reply(name: &str, ip: Ipv4Addr, ttl: u32) -> Vec<u8> {
    DnsPacket {
        header: DnsHeader {
            id: 0x1234,
            hb3: HB3_QR | HB3_RD,
            // A recursive resolver sets RA, and nothing from a reply with it
            // clear is ever committed to the cache (`rfc1035.c:1124-1127`).
            hb4: HB4_RA,
            qdcount: 1,
            ancount: 1,
            ..Default::default()
        },
        questions: vec![DnsQuestion { name: name.to_string(), qtype: 1, qclass: 1 }],
        answers: vec![DnsRr {
            name: name.to_string(),
            rtype: 1,
            class: 1,
            ttl,
            rdata: ip.octets().to_vec(),
        }],
        authority: vec![],
        additional: vec![],
    }
    .write()
    .to_vec()
}

fn a_query(name: &str) -> DnsPacket {
    DnsPacket {
        header: DnsHeader { id: 0x4321, hb3: HB3_RD, qdcount: 1, ..Default::default() },
        questions: vec![DnsQuestion { name: name.to_string(), qtype: 1, qclass: 1 }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}

fn empty_local() -> LocalConfig<'static> {
    LocalConfig {
        local_ttl: 0,
        edns_pktsz: 4096,
        txt_records: &[],
        rr_records: &[],
        mx_records: &[],
        ptr_records: &[],
        host_records: &[],
        cnames: &[],
        naptr_records: &[],
        nodots_local: false,
        synth_domains: &[],
        literal_domains: &[],
    }
}

/// The acceptance criterion in counter form: the first query misses, and each
/// repeat is a hit that never needs an upstream answer.
#[test]
fn repeated_queries_move_hit_and_miss_counters() {
    let mut cache = DnsCache::new(150);
    let now = Instant::now();
    let query = a_query("counted.test");

    // First query: nothing cached yet, so the cache misses and the forwarding
    // loop would send the query upstream.  `answer_request` probes several
    // record types per query (CNAME, then NXDOMAIN, then A), so the miss
    // counter moves by more than one — the load-bearing assertion is that
    // nothing hit.
    assert!(answer_request(&query, &mut cache, now, &empty_local()).is_none());
    let after_miss = cache.stats();
    assert!(after_miss.misses > 0, "an empty cache must record the miss");
    assert_eq!(after_miss.hits, 0, "nothing can hit before anything is cached");

    // The upstream answer comes back and is cached.
    assert_eq!(
        cache_reply(
            &a_reply("counted.test", Ipv4Addr::new(192, 0, 2, 5), 300),
            &mut cache,
            &ExtractConfig::default(),
        ),
        ExtractResult::Cached,
    );
    assert_eq!(cache.stats().size, 1, "the reply must actually be stored");

    // Every repeat is now answered locally.
    for i in 0..3 {
        let reply = answer_request(&query, &mut cache, now, &empty_local())
            .unwrap_or_else(|| panic!("repeat {i} must be answered from cache"));
        assert_eq!(reply.answers.len(), 1);
        assert_eq!(reply.answers[0].rdata, vec![192, 0, 2, 5]);
    }

    // Exactly one lookup per repeat can hit — the A-record one.
    assert_eq!(cache.stats().hits, 3, "three repeats must be three cache hits");
}

/// Once the entry expires the counters go back to missing, which is what sends
/// the next query upstream again.
#[test]
fn expired_entry_misses_again() {
    let mut cache = DnsCache::new(150);
    let now = Instant::now();
    let query = a_query("expiring.test");

    cache_reply(
        &a_reply("expiring.test", Ipv4Addr::new(192, 0, 2, 6), 10),
        &mut cache,
        &ExtractConfig::default(),
    );

    assert!(answer_request(&query, &mut cache, now, &empty_local()).is_some());
    assert_eq!(cache.stats().hits, 1);

    let misses_before = cache.stats().misses;
    let later = now + Duration::from_secs(11);
    assert!(
        answer_request(&query, &mut cache, later, &empty_local()).is_none(),
        "a TTL-10 entry must not answer 11s later",
    );
    assert_eq!(cache.stats().hits, 1, "an expired entry is not a hit");
    assert!(cache.stats().misses > misses_before, "the expired lookup must count as a miss");
}

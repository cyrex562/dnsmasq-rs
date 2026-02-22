//! Property-based tests for the DNS cache.
//!
//! Verifies cache invariants using `proptest`:
//! - Inserted entries are always retrievable (before expiry)
//! - LRU eviction keeps size ≤ max_size
//! - Expired entries are never returned
//! - Type-flag masking is consistent

use dnsmasq_rs::cache::{CacheRecord, DnsCache, type_flags};
use dnsmasq_rs::types::addr::AllAddr;
use dnsmasq_rs::types::constants::{F_FORWARD, F_IPV4, F_IPV6, F_NEG, F_NXDOMAIN, F_IMMORTAL};
use proptest::prelude::*;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

// ── Strategies ────────────────────────────────────────────────────────────────

fn dns_label() -> impl Strategy<Value = String> {
    "[a-z][a-z0-9]{0,10}".prop_map(|s| s)
}

fn dns_name() -> impl Strategy<Value = String> {
    prop::collection::vec(dns_label(), 1..=3)
        .prop_map(|labels| labels.join("."))
}

fn ipv4_addr() -> impl Strategy<Value = Ipv4Addr> {
    (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
        .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
}

fn make_a_record(name: String, ip: Ipv4Addr, ttl: u32, now: Instant) -> CacheRecord {
    CacheRecord {
        name,
        flags: F_IPV4 | F_FORWARD,
        ttl,
        expires: now + Duration::from_secs(u64::from(ttl) + 60),
        addr: Some(AllAddr::Addr4(ip)),
        rdata: None,
    }
}

// ── Properties ────────────────────────────────────────────────────────────────

proptest! {
    /// An inserted record can always be looked up immediately after insertion.
    #[test]
    fn prop_insert_then_lookup(
        name in dns_name(),
        ip   in ipv4_addr(),
        ttl  in 1u32..3600u32,
    ) {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        let rec = make_a_record(name.clone(), ip, ttl, now);
        cache.insert(rec);

        let found = cache.lookup_by_name(&name, F_IPV4, now);
        prop_assert!(found.is_some(), "record should be found after insertion");
        let r = found.unwrap();
        prop_assert_eq!(r.addr.as_ref().unwrap().as_ipv4(), Some(ip));
    }

    /// Cache never exceeds max_size.
    #[test]
    fn prop_cache_size_bounded(
        names in prop::collection::vec(dns_name(), 1..=50),
        max_size in 1usize..=20usize,
    ) {
        let now = Instant::now();
        let mut cache = DnsCache::new(max_size);
        for name in &names {
            cache.insert(make_a_record(name.clone(), Ipv4Addr::new(1,2,3,4), 60, now));
        }
        prop_assert!(cache.len() <= max_size);
    }

    /// After inserting with a past expiry, lookup should return None.
    #[test]
    fn prop_expired_record_not_returned(name in dns_name()) {
        let now = Instant::now();
        let rec = CacheRecord {
            name:    name.clone(),
            flags:   F_IPV4 | F_FORWARD,
            ttl:     1,
            expires: now - Duration::from_secs(1), // already expired
            addr:    Some(AllAddr::Addr4(Ipv4Addr::new(1, 2, 3, 4))),
            rdata:   None,
        };
        let mut cache = DnsCache::new(100);
        cache.insert(rec);
        // Look up after the expiry time.
        let future = now + Duration::from_secs(2);
        let found = cache.lookup_by_name(&name, F_IPV4, future);
        prop_assert!(found.is_none(), "expired record should not be returned");
    }

    /// Immortal records are never reported as expired.
    #[test]
    fn prop_immortal_never_expires(name in dns_name()) {
        let now = Instant::now();
        let rec = CacheRecord {
            name:    name.clone(),
            flags:   F_IPV4 | F_FORWARD | F_IMMORTAL,
            ttl:     u32::MAX,
            // expires field is ignored for immortal records.
            expires: now - Duration::from_secs(999_999),
            addr:    Some(AllAddr::Addr4(Ipv4Addr::new(127, 0, 0, 1))),
            rdata:   None,
        };
        let mut cache = DnsCache::new(100);
        cache.insert(rec);
        let far_future = now + Duration::from_secs(100_000_000);
        let found = cache.lookup_by_name(&name, F_IPV4 | F_IMMORTAL, far_future);
        prop_assert!(found.is_some(), "immortal record should always be found");
    }

    /// type_flags is idempotent: type_flags(type_flags(x)) == type_flags(x).
    #[test]
    fn prop_type_flags_idempotent(flags in any::<u32>()) {
        let t = type_flags(flags);
        prop_assert_eq!(type_flags(t), t);
    }

    /// Lookup with wrong type flags returns None.
    #[test]
    fn prop_lookup_wrong_flags_returns_none(name in dns_name()) {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        cache.insert(make_a_record(name.clone(), Ipv4Addr::new(1,2,3,4), 60, now));
        // Look up as AAAA — should not find the A record.
        let found = cache.lookup_by_name(&name, F_IPV6, now);
        prop_assert!(found.is_none(), "A record should not match AAAA lookup");
    }

    /// Insert and lookup are case-insensitive.
    #[test]
    fn prop_lookup_case_insensitive(name in dns_name()) {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        cache.insert(make_a_record(name.to_uppercase(), Ipv4Addr::new(1,2,3,4), 60, now));
        let found = cache.lookup_by_name(&name.to_lowercase(), F_IPV4, now);
        prop_assert!(found.is_some(), "lookup should be case-insensitive");
    }

    /// Inserting two records with the same name and flags replaces the first.
    #[test]
    fn prop_insert_replaces_existing(name in dns_name()) {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        cache.insert(make_a_record(name.clone(), Ipv4Addr::new(1, 0, 0, 1), 60, now));
        cache.insert(make_a_record(name.clone(), Ipv4Addr::new(2, 0, 0, 2), 60, now));
        let found = cache.lookup_by_name(&name, F_IPV4, now).unwrap();
        // Second insert should have replaced the first.
        prop_assert_eq!(
            found.addr.as_ref().unwrap().as_ipv4(),
            Some(Ipv4Addr::new(2, 0, 0, 2))
        );
    }

    /// Cache stats: inserts counter increments monotonically.
    #[test]
    fn prop_inserts_counter_monotone(
        names in prop::collection::vec(dns_name(), 1..=20),
    ) {
        let now = Instant::now();
        let mut cache = DnsCache::new(100);
        let mut prev_inserts = 0u64;
        for name in &names {
            cache.insert(make_a_record(name.clone(), Ipv4Addr::new(1,2,3,4), 60, now));
            prop_assert!(cache.inserts >= prev_inserts);
            prev_inserts = cache.inserts;
        }
    }
}

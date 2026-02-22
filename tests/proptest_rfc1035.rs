//! Property-based tests for the DNS packet parser and utilities.
//!
//! Uses `proptest` to verify that invariants hold for all valid inputs and
//! that the parser never panics on arbitrary (possibly malformed) bytes.

use dnsmasq_rs::dns_protocol::DnsHeader;
use dnsmasq_rs::rfc1035::*;
use proptest::prelude::*;
use std::net::{Ipv4Addr, Ipv6Addr};

// ── Domain name strategy ─────────────────────────────────────────────────────

/// Generate a single DNS label: 1–63 alphanumeric/hyphen ASCII bytes.
fn dns_label() -> impl Strategy<Value = String> {
    "[a-z0-9]([a-z0-9\\-]{0,61}[a-z0-9])?"
        .prop_map(|s| s.to_string())
}

/// Generate a valid fully-qualified domain name of 1–4 labels.
fn dns_name() -> impl Strategy<Value = String> {
    prop::collection::vec(dns_label(), 1..=4)
        .prop_map(|labels| labels.join("."))
}

// ── Properties ───────────────────────────────────────────────────────────────

proptest! {
    /// write_name followed by extract_name produces the original name.
    #[test]
    fn prop_name_roundtrip(name in dns_name()) {
        let mut buf = bytes::BytesMut::new();
        write_name(&mut buf, &name);
        let mut off = 0usize;
        let decoded = extract_name(&buf, &mut off).expect("decode should succeed");
        prop_assert_eq!(decoded.to_lowercase(), name.to_lowercase());
        // The entire buffer should have been consumed.
        prop_assert_eq!(off, buf.len());
    }

    /// DnsPacket::write then DnsPacket::parse roundtrip preserves fields.
    #[test]
    fn prop_packet_roundtrip(name in dns_name(), id in 0u16..=u16::MAX, ttl in 0u32..86400u32) {
        let mut header = DnsHeader::default();
        header.id = id;
        header.hb3 = 0x01; // RD
        header.qdcount = 1;
        header.ancount = 1;

        // Build a minimal A-record response.
        let question = DnsQuestion {
            name:   name.clone(),
            qtype:  1,  // A
            qclass: 1,  // IN
        };
        let answer = DnsRr {
            name:  name.clone(),
            rtype: 1,
            class: 1,
            ttl,
            rdata: vec![1, 2, 3, 4],
        };

        let pkt = DnsPacket {
            header,
            questions:  vec![question],
            answers:    vec![answer],
            authority:  vec![],
            additional: vec![],
        };

        let wire = pkt.write();
        let parsed = DnsPacket::parse(&wire).expect("re-parse should succeed");

        prop_assert_eq!(parsed.header.id, id);
        prop_assert_eq!(parsed.questions.len(), 1);
        prop_assert_eq!(parsed.questions[0].name.to_lowercase(), name.to_lowercase());
        prop_assert_eq!(parsed.questions[0].qtype, 1);
        prop_assert_eq!(parsed.answers.len(), 1);
        prop_assert_eq!(parsed.answers[0].ttl, ttl);
        prop_assert_eq!(parsed.answers[0].rdata.as_slice(), &[1u8, 2, 3, 4][..]);
    }

    /// DnsPacket::parse never panics on arbitrary bytes.
    #[test]
    fn prop_parse_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        // Result can be Ok or Err — it must never panic.
        let _ = DnsPacket::parse(&bytes);
    }

    /// extract_name never panics on arbitrary bytes.
    #[test]
    fn prop_extract_name_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
        offset in 0usize..256usize,
    ) {
        let mut off = offset.min(bytes.len());
        let _ = extract_name(&bytes, &mut off);
    }

    /// skip_name never panics on arbitrary bytes.
    #[test]
    fn prop_skip_name_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..256),
        offset in 0usize..256usize,
    ) {
        let mut off = offset.min(bytes.len());
        let _ = skip_name(&bytes, &mut off);
    }

    /// resize_packet never panics on arbitrary bytes.
    #[test]
    fn prop_resize_packet_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..512)) {
        let _ = resize_packet(&bytes, None);
    }

    /// private_net: addresses in 10/8, 172.16/12, 192.168/16 are always private.
    #[test]
    fn prop_private_net_rfc1918(
        b in 16u8..=31u8,  // 172.16–31
        c in 0u8..=255u8,
        d in 0u8..=255u8,
    ) {
        // 172.16.0.0/12
        let ip = Ipv4Addr::new(172, b, c, d);
        prop_assert!(private_net(ip, false), "172.{b}.{c}.{d} should be private");
    }

    #[test]
    fn prop_private_net_10(b in 0u8..=255u8, c in 0u8..=255u8, d in 0u8..=255u8) {
        let ip = Ipv4Addr::new(10, b, c, d);
        prop_assert!(private_net(ip, false), "10.{b}.{c}.{d} should be private");
    }

    #[test]
    fn prop_private_net_192_168(c in 0u8..=255u8, d in 0u8..=255u8) {
        let ip = Ipv4Addr::new(192, 168, c, d);
        prop_assert!(private_net(ip, false), "192.168.{c}.{d} should be private");
    }

    /// in_arpa_name_2_addr roundtrip: convert IPv4 to arpa name, parse back.
    #[test]
    fn prop_arpa_ipv4_roundtrip(a in 0u8..=255u8, b in 0u8..=255u8, c in 0u8..=255u8, d in 0u8..=255u8) {
        let ip = Ipv4Addr::new(a, b, c, d);
        let arpa = format!("{d}.{c}.{b}.{a}.in-addr.arpa");
        let parsed = in_arpa_name_2_addr(&arpa).expect("should parse valid arpa name");
        prop_assert_eq!(parsed.as_ipv4(), Some(ip));
    }

    /// in_arpa_name_2_addr: invalid names return None without panicking.
    #[test]
    fn prop_arpa_invalid_no_panic(s in ".*") {
        let _ = in_arpa_name_2_addr(&s);
    }

    /// hostname_issubdomain reflexivity: a name is always a subdomain of itself.
    #[test]
    fn prop_issubdomain_reflexive(name in dns_name()) {
        prop_assert!(hostname_issubdomain(&name, &name));
    }

    /// hostname_issubdomain: "a.example.com" is a subdomain of "example.com".
    #[test]
    fn prop_issubdomain_strict(parent in dns_name(), child_label in dns_label()) {
        let child = format!("{child_label}.{parent}");
        prop_assert!(hostname_issubdomain(&child, &parent));
    }
}

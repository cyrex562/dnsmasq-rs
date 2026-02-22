//! Integration tests for DNS packet parsing and wire-format encoding.
//!
//! These tests operate on hardcoded bytes and synthesised packets — no running
//! DNS server is required.

use dnsmasq_rs::dns_protocol::{DnsHeader, HB3_QR, HB3_RD, HB4_RA};
use dnsmasq_rs::rfc1035::*;
use dnsmasq_rs::types::addr::AllAddr;
use std::net::{Ipv4Addr, Ipv6Addr};

// ---------------------------------------------------------------------------
// Real-world A query for "example.com." — captured wire bytes
// ---------------------------------------------------------------------------
// Header:  id=0x0001, flags=0x0100 (RD), qdcount=1, others=0
// Question: example.com A IN
#[rustfmt::skip]
const EXAMPLE_COM_QUERY: &[u8] = &[
    0x00, 0x01, // ID
    0x01, 0x00, // flags: RD=1, QR=0
    0x00, 0x01, // qdcount = 1
    0x00, 0x00, // ancount = 0
    0x00, 0x00, // nscount = 0
    0x00, 0x00, // arcount = 0
    // QNAME: example.com
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    0x03, b'c', b'o', b'm',
    0x00,
    0x00, 0x01, // QTYPE  = A
    0x00, 0x01, // QCLASS = IN
];

// ---------------------------------------------------------------------------
// Real-world A response for "example.com." → 93.184.216.34
// ---------------------------------------------------------------------------
// Header:  id=0x0001, flags=0x8180 (QR, RD, RA), qdcount=1, ancount=1
// Answer:  ptr to question name, A IN 3600, 93.184.216.34
#[rustfmt::skip]
const EXAMPLE_COM_RESPONSE: &[u8] = &[
    0x00, 0x01, // ID
    0x81, 0x80, // flags: QR=1, RD=1, RA=1
    0x00, 0x01, // qdcount = 1
    0x00, 0x01, // ancount = 1
    0x00, 0x00, // nscount = 0
    0x00, 0x00, // arcount = 0
    // Question QNAME: example.com (offset 12)
    0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
    0x03, b'c', b'o', b'm',
    0x00,
    0x00, 0x01, // QTYPE  = A
    0x00, 0x01, // QCLASS = IN
    // Answer RR
    0xC0, 0x0C, // NAME: pointer to offset 12 (example.com)
    0x00, 0x01, // TYPE  = A
    0x00, 0x01, // CLASS = IN
    0x00, 0x00, 0x0E, 0x10, // TTL = 3600
    0x00, 0x04, // RDLENGTH = 4
    0x5D, 0xB8, 0xD8, 0x22, // RDATA: 93.184.216.34
];

#[test]
fn parse_real_a_query() {
    let pkt = DnsPacket::parse(EXAMPLE_COM_QUERY).expect("should parse query");
    assert!(pkt.header.is_query(), "should be a query");
    assert!(pkt.header.is_rd(), "RD bit should be set");
    assert_eq!(pkt.questions.len(), 1);
    assert_eq!(pkt.questions[0].name, "example.com");
    assert_eq!(pkt.questions[0].qtype, 1, "QTYPE should be A (1)");
    assert_eq!(pkt.questions[0].qclass, 1, "QCLASS should be IN (1)");
    assert!(pkt.answers.is_empty());
}

#[test]
fn parse_real_a_response() {
    let pkt = DnsPacket::parse(EXAMPLE_COM_RESPONSE).expect("should parse response");
    assert!(pkt.header.is_response(), "should be a response");
    assert!(pkt.header.is_ra(), "RA bit should be set");
    assert_eq!(pkt.questions.len(), 1);
    assert_eq!(pkt.answers.len(), 1);

    let ans = &pkt.answers[0];
    assert_eq!(ans.name, "example.com");
    assert_eq!(ans.rtype, 1, "answer TYPE should be A (1)");
    assert_eq!(ans.ttl, 3600);
    assert_eq!(ans.rdata, &[0x5D, 0xB8, 0xD8, 0x22]);
    // Reconstruct the IPv4 address from rdata.
    let ip = Ipv4Addr::new(ans.rdata[0], ans.rdata[1], ans.rdata[2], ans.rdata[3]);
    assert_eq!(ip, Ipv4Addr::new(93, 184, 216, 34));
}

#[test]
fn dns_packet_roundtrip() {
    // Build a synthetic DNS query packet.
    let mut header = DnsHeader::default();
    header.id = 0xABCD;
    header.hb3 = HB3_RD; // recursion desired, query
    header.qdcount = 1;

    let question = DnsQuestion {
        name: "test.example.org".to_string(),
        qtype: 1,  // A
        qclass: 1, // IN
    };

    let pkt = DnsPacket {
        header,
        questions: vec![question],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    };

    // Serialise then parse back.
    let wire = pkt.write();
    let parsed = DnsPacket::parse(&wire).expect("roundtrip parse should succeed");

    assert_eq!(parsed.header.id, 0xABCD);
    assert!(parsed.header.is_query());
    assert!(parsed.header.is_rd());
    assert_eq!(parsed.questions.len(), 1);
    assert_eq!(parsed.questions[0].name, "test.example.org");
    assert_eq!(parsed.questions[0].qtype, 1);
    assert_eq!(parsed.questions[0].qclass, 1);
    assert!(parsed.answers.is_empty());
}

#[test]
fn arpa_reverse_lookup_ipv4() {
    // 192.168.1.42 → "42.1.168.192.in-addr.arpa"
    let name = "42.1.168.192.in-addr.arpa";
    let addr = in_arpa_name_2_addr(name).expect("should parse IPv4 PTR name");
    match addr {
        AllAddr::Addr4(ip) => assert_eq!(ip, Ipv4Addr::new(192, 168, 1, 42)),
        other => panic!("expected Addr4, got {:?}", other),
    }
}

#[test]
fn arpa_reverse_lookup_ipv6() {
    // 2001:db8::1 →
    // 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
    let name =
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa";
    let addr = in_arpa_name_2_addr(name).expect("should parse IPv6 PTR name");
    match addr {
        AllAddr::Addr6(ip) => {
            assert_eq!(ip, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        }
        other => panic!("expected Addr6, got {:?}", other),
    }
}

#[test]
fn private_net_ranges() {
    // RFC 1918 ranges
    assert!(private_net(Ipv4Addr::new(10, 0, 0, 1), false));
    assert!(private_net(Ipv4Addr::new(10, 255, 255, 255), false));
    assert!(private_net(Ipv4Addr::new(172, 16, 0, 1), false));
    assert!(private_net(Ipv4Addr::new(172, 31, 255, 255), false));
    assert!(private_net(Ipv4Addr::new(192, 168, 0, 1), false));
    assert!(private_net(Ipv4Addr::new(192, 168, 255, 255), false));
    // Link-local
    assert!(private_net(Ipv4Addr::new(169, 254, 1, 1), false));
    // Loopback — only when ban_localhost=true
    assert!(!private_net(Ipv4Addr::new(127, 0, 0, 1), false));
    assert!(private_net(Ipv4Addr::new(127, 0, 0, 1), true));
    // Public address
    assert!(!private_net(Ipv4Addr::new(8, 8, 8, 8), false));

    // IPv6 ULA (fc00::/7)
    assert!(private_net6(&Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1), false));
    assert!(private_net6(&Ipv6Addr::new(0xfd12, 0x3456, 0, 0, 0, 0, 0, 1), false));
    // IPv6 link-local (fe80::/10)
    assert!(private_net6(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), false));
    // IPv6 loopback — only when ban_localhost=true
    assert!(!private_net6(&Ipv6Addr::LOCALHOST, false));
    assert!(private_net6(&Ipv6Addr::LOCALHOST, true));
    // Public IPv6
    assert!(!private_net6(&Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888), false));
}

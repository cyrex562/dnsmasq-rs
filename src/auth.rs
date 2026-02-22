//! Authoritative DNS server module — Rust port of dnsmasq's `auth.c`.
//!
//! Handles answering DNS queries for zones that dnsmasq is configured to
//! serve authoritatively.

#![cfg(feature = "auth")]

use bytes::BytesMut;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::dns_protocol::{DnsHeader, RrType, HB3_AA, HB3_QR, HB3_RD, HB4_RCODE};
use crate::rfc1035::{write_name, DnsPacket, DnsQuestion, DnsRr};

// ──────────────────────────────────────────────────────────────────────────────
// Public types
// ──────────────────────────────────────────────────────────────────────────────

/// Zone configuration for the authoritative DNS server.
#[derive(Debug, Clone)]
pub struct AuthZoneConfig {
    pub name: String,
    pub serial: u32,
    pub refresh: u32,
    pub retry: u32,
    pub expire: u32,
    pub min_ttl: u32,
    pub ns: String,
    pub hostmaster: String,
    pub default_ttl: u32,
}

/// Local DNS records for a zone.
#[derive(Debug, Clone, Default)]
pub struct LocalRecords {
    pub a_records: Vec<(String, Ipv4Addr)>,
    pub aaaa_records: Vec<(String, Ipv6Addr)>,
    pub cname: Vec<(String, String)>,
    pub mx: Vec<(String, u16, String)>,
    pub txt: Vec<(String, Vec<u8>)>,
    pub ptr: Vec<(String, String)>,
}

// ──────────────────────────────────────────────────────────────────────────────
// in_zone
// ──────────────────────────────────────────────────────────────────────────────

/// Return `true` if `name` is equal to or a subdomain of `zone_name`
/// (case-insensitive).
pub fn in_zone(name: &str, zone_name: &str) -> bool {
    let name = name.to_lowercase();
    let zone = zone_name.to_lowercase();
    // Strip trailing dots for comparison.
    let name = name.trim_end_matches('.');
    let zone = zone.trim_end_matches('.');
    if name == zone {
        return true;
    }
    // name must end with ".<zone>"
    name.ends_with(&format!(".{}", zone))
}

// ──────────────────────────────────────────────────────────────────────────────
// make_soa_rr
// ──────────────────────────────────────────────────────────────────────────────

/// Build a SOA [`DnsRr`] for the given zone.
pub fn make_soa_rr(zone: &AuthZoneConfig, ttl: u32) -> DnsRr {
    let mut rdata = BytesMut::new();
    write_name(&mut rdata, &zone.ns);
    write_name(&mut rdata, &zone.hostmaster);
    // SOA fixed fields: serial, refresh, retry, expire, minimum.
    for &v in &[zone.serial, zone.refresh, zone.retry, zone.expire, zone.min_ttl] {
        rdata.extend_from_slice(&v.to_be_bytes());
    }
    DnsRr {
        name: zone.name.clone(),
        rtype: RrType::SOA as u16,
        class: 1, // IN
        ttl,
        rdata: rdata.to_vec(),
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// answer_auth
// ──────────────────────────────────────────────────────────────────────────────

/// Build an authoritative DNS reply for `question`.
///
/// Returns `None` if `question.name` is not within `zone`.
pub fn answer_auth(
    question: &DnsQuestion,
    zone: &AuthZoneConfig,
    records: &LocalRecords,
    _now_secs: u64,
) -> Option<Vec<u8>> {
    if !in_zone(&question.name, &zone.name) {
        return None;
    }

    let qname_lower = question.name.to_lowercase();
    let qtype = RrType::from_u16(question.qtype);
    let ttl = zone.default_ttl;

    // Collect answer RRs.
    let mut answers: Vec<DnsRr> = Vec::new();

    match qtype {
        Some(RrType::SOA) => {
            if qname_lower == zone.name.to_lowercase() {
                answers.push(make_soa_rr(zone, ttl));
            }
        }

        Some(RrType::NS) => {
            if qname_lower == zone.name.to_lowercase() {
                let mut rdata = BytesMut::new();
                write_name(&mut rdata, &zone.ns);
                answers.push(DnsRr {
                    name: zone.name.clone(),
                    rtype: RrType::NS as u16,
                    class: 1,
                    ttl,
                    rdata: rdata.to_vec(),
                });
            }
        }

        Some(RrType::A) => {
            for (n, addr) in &records.a_records {
                if n.to_lowercase() == qname_lower {
                    answers.push(DnsRr {
                        name: question.name.clone(),
                        rtype: RrType::A as u16,
                        class: 1,
                        ttl,
                        rdata: addr.octets().to_vec(),
                    });
                }
            }
        }

        Some(RrType::AAAA) => {
            for (n, addr) in &records.aaaa_records {
                if n.to_lowercase() == qname_lower {
                    answers.push(DnsRr {
                        name: question.name.clone(),
                        rtype: RrType::AAAA as u16,
                        class: 1,
                        ttl,
                        rdata: addr.octets().to_vec(),
                    });
                }
            }
        }

        Some(RrType::CNAME) => {
            for (n, target) in &records.cname {
                if n.to_lowercase() == qname_lower {
                    let mut rdata = BytesMut::new();
                    write_name(&mut rdata, target);
                    answers.push(DnsRr {
                        name: question.name.clone(),
                        rtype: RrType::CNAME as u16,
                        class: 1,
                        ttl,
                        rdata: rdata.to_vec(),
                    });
                }
            }
        }

        Some(RrType::MX) => {
            for (n, prio, target) in &records.mx {
                if n.to_lowercase() == qname_lower {
                    let mut rdata = BytesMut::new();
                    rdata.extend_from_slice(&prio.to_be_bytes());
                    write_name(&mut rdata, target);
                    answers.push(DnsRr {
                        name: question.name.clone(),
                        rtype: RrType::MX as u16,
                        class: 1,
                        ttl,
                        rdata: rdata.to_vec(),
                    });
                }
            }
        }

        Some(RrType::TXT) => {
            for (n, data) in &records.txt {
                if n.to_lowercase() == qname_lower {
                    // TXT RDATA: each string preceded by its 1-byte length.
                    let mut rdata = Vec::new();
                    // Encode as a single string segment (data may already be
                    // split; treat as one chunk here).
                    let chunks: Vec<&[u8]> = data.chunks(255).collect();
                    for chunk in chunks {
                        rdata.push(chunk.len() as u8);
                        rdata.extend_from_slice(chunk);
                    }
                    answers.push(DnsRr {
                        name: question.name.clone(),
                        rtype: RrType::TXT as u16,
                        class: 1,
                        ttl,
                        rdata,
                    });
                }
            }
        }

        Some(RrType::PTR) => {
            for (n, hostname) in &records.ptr {
                if n.to_lowercase() == qname_lower {
                    let mut rdata = BytesMut::new();
                    write_name(&mut rdata, hostname);
                    answers.push(DnsRr {
                        name: question.name.clone(),
                        rtype: RrType::PTR as u16,
                        class: 1,
                        ttl,
                        rdata: rdata.to_vec(),
                    });
                }
            }
        }

        Some(RrType::AXFR) => {
            // Zone transfer: SOA + all records + closing SOA.
            let soa = make_soa_rr(zone, ttl);
            answers.push(soa.clone());
            answers.extend(all_zone_rrs(zone, records, ttl));
            answers.push(soa);
        }

        Some(RrType::ANY) | None => {
            // Return all matching records of any type.
            answers.extend(matching_rrs(&qname_lower, question, zone, records, ttl));
        }

        _ => {}
    }

    // Determine RCODE and whether the name exists.
    let name_exists = name_has_any_record(&qname_lower, zone, records);

    let rcode: u8 = if answers.is_empty() && !name_exists {
        3 // NXDOMAIN
    } else {
        0 // NOERROR
    };

    Some(build_reply(question, answers, rcode))
}

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Return `true` if `name` has at least one record of any type in the zone.
fn name_has_any_record(name_lower: &str, zone: &AuthZoneConfig, records: &LocalRecords) -> bool {
    if name_lower == zone.name.to_lowercase() {
        return true; // zone apex always "exists" (SOA / NS)
    }
    records.a_records.iter().any(|(n, _)| n.to_lowercase() == name_lower)
        || records.aaaa_records.iter().any(|(n, _)| n.to_lowercase() == name_lower)
        || records.cname.iter().any(|(n, _)| n.to_lowercase() == name_lower)
        || records.mx.iter().any(|(n, _, _)| n.to_lowercase() == name_lower)
        || records.txt.iter().any(|(n, _)| n.to_lowercase() == name_lower)
        || records.ptr.iter().any(|(n, _)| n.to_lowercase() == name_lower)
}

/// Collect all RRs matching `name` across all record types (for ANY queries).
fn matching_rrs(
    qname_lower: &str,
    question: &DnsQuestion,
    zone: &AuthZoneConfig,
    records: &LocalRecords,
    ttl: u32,
) -> Vec<DnsRr> {
    let mut out = Vec::new();

    // SOA / NS at zone apex.
    if qname_lower == zone.name.to_lowercase() {
        out.push(make_soa_rr(zone, ttl));
        let mut rdata = BytesMut::new();
        write_name(&mut rdata, &zone.ns);
        out.push(DnsRr {
            name: question.name.clone(),
            rtype: RrType::NS as u16,
            class: 1,
            ttl,
            rdata: rdata.to_vec(),
        });
    }

    for (n, addr) in &records.a_records {
        if n.to_lowercase() == qname_lower {
            out.push(DnsRr {
                name: question.name.clone(),
                rtype: RrType::A as u16,
                class: 1,
                ttl,
                rdata: addr.octets().to_vec(),
            });
        }
    }
    for (n, addr) in &records.aaaa_records {
        if n.to_lowercase() == qname_lower {
            out.push(DnsRr {
                name: question.name.clone(),
                rtype: RrType::AAAA as u16,
                class: 1,
                ttl,
                rdata: addr.octets().to_vec(),
            });
        }
    }
    for (n, target) in &records.cname {
        if n.to_lowercase() == qname_lower {
            let mut rdata = BytesMut::new();
            write_name(&mut rdata, target);
            out.push(DnsRr {
                name: question.name.clone(),
                rtype: RrType::CNAME as u16,
                class: 1,
                ttl,
                rdata: rdata.to_vec(),
            });
        }
    }
    for (n, prio, target) in &records.mx {
        if n.to_lowercase() == qname_lower {
            let mut rdata = BytesMut::new();
            rdata.extend_from_slice(&prio.to_be_bytes());
            write_name(&mut rdata, target);
            out.push(DnsRr {
                name: question.name.clone(),
                rtype: RrType::MX as u16,
                class: 1,
                ttl,
                rdata: rdata.to_vec(),
            });
        }
    }
    for (n, data) in &records.txt {
        if n.to_lowercase() == qname_lower {
            let mut rdata = Vec::new();
            for chunk in data.chunks(255) {
                rdata.push(chunk.len() as u8);
                rdata.extend_from_slice(chunk);
            }
            out.push(DnsRr {
                name: question.name.clone(),
                rtype: RrType::TXT as u16,
                class: 1,
                ttl,
                rdata,
            });
        }
    }
    for (n, hostname) in &records.ptr {
        if n.to_lowercase() == qname_lower {
            let mut rdata = BytesMut::new();
            write_name(&mut rdata, hostname);
            out.push(DnsRr {
                name: question.name.clone(),
                rtype: RrType::PTR as u16,
                class: 1,
                ttl,
                rdata: rdata.to_vec(),
            });
        }
    }
    out
}

/// Collect every RR in the zone (used for AXFR).
fn all_zone_rrs(zone: &AuthZoneConfig, records: &LocalRecords, ttl: u32) -> Vec<DnsRr> {
    let mut out = Vec::new();
    // NS at apex.
    let mut rdata = BytesMut::new();
    write_name(&mut rdata, &zone.ns);
    out.push(DnsRr {
        name: zone.name.clone(),
        rtype: RrType::NS as u16,
        class: 1,
        ttl,
        rdata: rdata.to_vec(),
    });

    for (n, addr) in &records.a_records {
        out.push(DnsRr {
            name: n.clone(),
            rtype: RrType::A as u16,
            class: 1,
            ttl,
            rdata: addr.octets().to_vec(),
        });
    }
    for (n, addr) in &records.aaaa_records {
        out.push(DnsRr {
            name: n.clone(),
            rtype: RrType::AAAA as u16,
            class: 1,
            ttl,
            rdata: addr.octets().to_vec(),
        });
    }
    for (n, target) in &records.cname {
        let mut rdata = BytesMut::new();
        write_name(&mut rdata, target);
        out.push(DnsRr {
            name: n.clone(),
            rtype: RrType::CNAME as u16,
            class: 1,
            ttl,
            rdata: rdata.to_vec(),
        });
    }
    for (n, prio, target) in &records.mx {
        let mut rdata = BytesMut::new();
        rdata.extend_from_slice(&prio.to_be_bytes());
        write_name(&mut rdata, target);
        out.push(DnsRr {
            name: n.clone(),
            rtype: RrType::MX as u16,
            class: 1,
            ttl,
            rdata: rdata.to_vec(),
        });
    }
    for (n, data) in &records.txt {
        let mut rdata = Vec::new();
        for chunk in data.chunks(255) {
            rdata.push(chunk.len() as u8);
            rdata.extend_from_slice(chunk);
        }
        out.push(DnsRr {
            name: n.clone(),
            rtype: RrType::TXT as u16,
            class: 1,
            ttl,
            rdata,
        });
    }
    for (n, hostname) in &records.ptr {
        let mut rdata = BytesMut::new();
        write_name(&mut rdata, hostname);
        out.push(DnsRr {
            name: n.clone(),
            rtype: RrType::PTR as u16,
            class: 1,
            ttl,
            rdata: rdata.to_vec(),
        });
    }
    out
}

/// Serialise a DNS reply packet from a question and collected answer RRs.
fn build_reply(question: &DnsQuestion, answers: Vec<DnsRr>, rcode: u8) -> Vec<u8> {
    let mut hdr = DnsHeader::default();
    hdr.id = 0; // caller should overwrite if needed
    hdr.hb3 = HB3_QR | HB3_AA; // response, authoritative
    hdr.hb4 = rcode & HB4_RCODE;
    hdr.qdcount = 1;
    hdr.ancount = answers.len() as u16;
    hdr.nscount = 0;
    hdr.arcount = 0;

    let pkt = DnsPacket {
        header: hdr,
        questions: vec![question.clone()],
        answers,
        authority: vec![],
        additional: vec![],
    };
    pkt.write().to_vec()
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_protocol::RrType;
    use crate::rfc1035::{extract_name, DnsPacket};

    fn test_zone() -> AuthZoneConfig {
        AuthZoneConfig {
            name: "example.com".into(),
            serial: 2024010101,
            refresh: 3600,
            retry: 900,
            expire: 604800,
            min_ttl: 300,
            ns: "ns1.example.com".into(),
            hostmaster: "hostmaster.example.com".into(),
            default_ttl: 300,
        }
    }

    fn test_records() -> LocalRecords {
        LocalRecords {
            a_records: vec![
                ("www.example.com".into(), "93.184.216.34".parse().unwrap()),
                ("mail.example.com".into(), "93.184.216.35".parse().unwrap()),
            ],
            aaaa_records: vec![("www.example.com".into(), "2001:db8::1".parse().unwrap())],
            cname: vec![("alias.example.com".into(), "www.example.com".into())],
            mx: vec![("example.com".into(), 10, "mail.example.com".into())],
            txt: vec![("example.com".into(), b"v=spf1 -all".to_vec())],
            ptr: vec![("34.216.184.93.in-addr.arpa".into(), "www.example.com".into())],
        }
    }

    fn make_question(name: &str, qtype: RrType) -> DnsQuestion {
        DnsQuestion {
            name: name.into(),
            qtype: qtype as u16,
            qclass: 1,
        }
    }

    // ── in_zone ───────────────────────────────────────────────────────────────

    #[test]
    fn in_zone_exact_match() {
        assert!(in_zone("example.com", "example.com"));
    }

    #[test]
    fn in_zone_subdomain() {
        assert!(in_zone("www.example.com", "example.com"));
        assert!(in_zone("deep.sub.example.com", "example.com"));
    }

    #[test]
    fn in_zone_different_zone() {
        assert!(!in_zone("example.org", "example.com"));
        assert!(!in_zone("notexample.com", "example.com"));
    }

    #[test]
    fn in_zone_case_insensitive() {
        assert!(in_zone("WWW.EXAMPLE.COM", "example.com"));
    }

    // ── make_soa_rr ───────────────────────────────────────────────────────────

    #[test]
    fn make_soa_rr_structure() {
        let zone = test_zone();
        let rr = make_soa_rr(&zone, 300);
        assert_eq!(rr.rrtype(), Some(RrType::SOA));
        assert_eq!(rr.name, "example.com");
        assert_eq!(rr.ttl, 300);
        assert_eq!(rr.class, 1);
        // Check that serial is encoded in rdata.
        // SOA rdata layout: MNAME + RNAME + serial(4) + refresh(4) + retry(4)
        //                    + expire(4) + minimum(4)
        // Parse past the two wire-format names to reach the serial.
        let mut off = 0;
        let _mname = extract_name(&rr.rdata, &mut off).unwrap();
        let _rname = extract_name(&rr.rdata, &mut off).unwrap();
        let serial = u32::from_be_bytes(rr.rdata[off..off + 4].try_into().unwrap());
        assert_eq!(serial, zone.serial);
    }

    // ── answer_auth: A record ─────────────────────────────────────────────────

    #[test]
    fn answer_auth_a_record() {
        let zone = test_zone();
        let records = test_records();
        let q = make_question("www.example.com", RrType::A);
        let bytes = answer_auth(&q, &zone, &records, 0).expect("should be authoritative");
        let pkt = DnsPacket::parse(&bytes).expect("valid packet");
        assert_eq!(pkt.answers.len(), 1);
        let rr = &pkt.answers[0];
        assert_eq!(rr.rrtype(), Some(RrType::A));
        let addr = Ipv4Addr::new(rr.rdata[0], rr.rdata[1], rr.rdata[2], rr.rdata[3]);
        assert_eq!(addr, Ipv4Addr::new(93, 184, 216, 34));
    }

    // ── answer_auth: NXDOMAIN ─────────────────────────────────────────────────

    #[test]
    fn answer_auth_nxdomain() {
        let zone = test_zone();
        let records = test_records();
        let q = make_question("nosuchname.example.com", RrType::A);
        let bytes = answer_auth(&q, &zone, &records, 0).expect("should be authoritative");
        let pkt = DnsPacket::parse(&bytes).expect("valid packet");
        assert!(pkt.answers.is_empty());
        assert_eq!(pkt.header.rcode(), 3); // NXDOMAIN
    }

    // ── answer_auth: out of zone → None ──────────────────────────────────────

    #[test]
    fn answer_auth_out_of_zone() {
        let zone = test_zone();
        let records = test_records();
        let q = make_question("example.org", RrType::A);
        assert!(answer_auth(&q, &zone, &records, 0).is_none());
    }

    // ── answer_auth: SOA ──────────────────────────────────────────────────────

    #[test]
    fn answer_auth_soa() {
        let zone = test_zone();
        let records = test_records();
        let q = make_question("example.com", RrType::SOA);
        let bytes = answer_auth(&q, &zone, &records, 0).expect("authoritative");
        let pkt = DnsPacket::parse(&bytes).expect("valid packet");
        assert_eq!(pkt.answers.len(), 1);
        assert_eq!(pkt.answers[0].rrtype(), Some(RrType::SOA));
    }

    // ── answer_auth: AXFR returns all records ─────────────────────────────────

    #[test]
    fn answer_auth_axfr() {
        let zone = test_zone();
        let records = test_records();
        let q = make_question("example.com", RrType::AXFR);
        let bytes = answer_auth(&q, &zone, &records, 0).expect("authoritative");
        let pkt = DnsPacket::parse(&bytes).expect("valid packet");
        // Must start and end with SOA, plus at least NS + A + AAAA + CNAME + MX + TXT + PTR.
        assert!(pkt.answers.len() >= 3);
        assert_eq!(pkt.answers.first().unwrap().rrtype(), Some(RrType::SOA));
        assert_eq!(pkt.answers.last().unwrap().rrtype(), Some(RrType::SOA));
    }

    // ── answer_auth: NODATA (name exists, wrong type) ─────────────────────────

    #[test]
    fn answer_auth_nodata() {
        let zone = test_zone();
        let records = test_records();
        // www.example.com has A+AAAA but no MX.
        let q = make_question("www.example.com", RrType::MX);
        let bytes = answer_auth(&q, &zone, &records, 0).expect("authoritative");
        let pkt = DnsPacket::parse(&bytes).expect("valid packet");
        assert!(pkt.answers.is_empty());
        assert_eq!(pkt.header.rcode(), 0); // NOERROR (NODATA)
    }
}

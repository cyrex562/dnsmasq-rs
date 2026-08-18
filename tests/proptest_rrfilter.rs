//! Property-based tests for `rrfilter`'s safe-elision algorithm.
//!
//! The whole point of the four-pass algorithm in `rrfilter.rs` is that eliding
//! records from the middle of a message must never leave a surviving
//! compression pointer dangling into the removed bytes — the packet must
//! either come back with the pointer correctly rescaled, or come back
//! completely unchanged.
//!
//! Checking only "does `DnsPacket::parse` return `Ok`" is not enough: `parse_rr`
//! (`rfc1035.rs`) swallows a bad in-RDATA pointer and falls back to storing the
//! raw, still-corrupt bytes rather than erroring, so a mis-rescaled pointer
//! would silently produce a packet that "parses" but decodes to the wrong name.
//! These properties additionally decode the surviving pointer and check it
//! resolves to what it must — the same test an adversary probing for cache
//! poisoning via a dangling pointer would run.

use bytes::BytesMut;
use dnsmasq_rs::dns_protocol::RrType;
use dnsmasq_rs::rfc1035::{extract_name, write_rr, DnsPacket, DnsRr};
use dnsmasq_rs::rrfilter::{filter_configured_rr_types, filter_rr_types, strip_dnssec_if_not_requested};
use proptest::prelude::*;

// ── Packet construction helpers ─────────────────────────────────────────────

/// The two RR types randomly assigned to each filler record: one is on every
/// filter list used below, the other never is.
const REMOVE_TYPE: u16 = RrType::TXT as u16;
const KEEP_TYPE:   u16 = RrType::A   as u16;

fn make_rr(name: &str, rtype: u16, rdata: &[u8]) -> Vec<u8> {
    let rr = DnsRr { name: name.to_owned(), rtype, class: 1, ttl: 300, rdata: rdata.to_vec() };
    let mut buf = BytesMut::new();
    write_rr(&mut buf, &rr);
    buf.to_vec()
}

/// Header(12) + `example.com` question(17, matching rrfilter.rs's own tests).
const QUESTION_LEN: usize = 17;

/// One filler record: `removed` picks its RR type, which picks whether a
/// filter list keyed on `REMOVE_TYPE` will elide it.
fn filler(index: usize, removed: bool, remove_type: u16) -> Vec<u8> {
    let name = format!("f{index}.example.com");
    if removed {
        make_rr(&name, remove_type, b"\x05hello")
    } else {
        make_rr(&name, KEEP_TYPE, &[1, 2, 3, 4])
    }
}

/// An NS record whose RDATA is a compression pointer at `target_offset`. Never
/// itself a candidate for elision (its type is neither `REMOVE_TYPE` nor
/// `RRSIG`), so it is always in the surviving set.
fn pointer_rr(target_offset: usize) -> Vec<u8> {
    let mut rdata = BytesMut::new();
    rdata.extend_from_slice(&[
        0xC0 | (target_offset >> 8) as u8,
        (target_offset & 0xFF) as u8,
    ]);
    make_rr("ns.example.com", RrType::NS as u16, &rdata)
}

/// Assemble a minimal response: `example.com IN <qtype>` question, and the
/// given records placed verbatim into one section.
fn response_with_section(records: &[Vec<u8>], section: &str, qtype: u16) -> Vec<u8> {
    let (an, ns, ar): (u16, u16, u16) = match section {
        "answer" => (records.len() as u16, 0, 0),
        "additional" => (0, 0, records.len() as u16),
        _ => unreachable!(),
    };
    let mut pkt = vec![0x00, 0x01, 0x81, 0x80, 0x00, 0x01];
    pkt.extend_from_slice(&an.to_be_bytes());
    pkt.extend_from_slice(&ns.to_be_bytes());
    pkt.extend_from_slice(&ar.to_be_bytes());
    pkt.extend_from_slice(b"\x07example\x03com\x00");
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&[0x00, 0x01]);
    for rr in records {
        pkt.extend_from_slice(rr);
    }
    pkt
}

/// Build `removed_flags.len()` filler records (type `remove_type` where the
/// flag is set, `KEEP_TYPE` otherwise) plus a trailing NS record whose RDATA
/// compression pointer targets the `pointer_target`th filler's owner name, all
/// in one section.
fn packet_with_pointer(
    removed_flags:  &[bool],
    pointer_target: usize,
    remove_type:    u16,
    section:        &str,
    qtype:          u16,
) -> Vec<u8> {
    let mut records: Vec<Vec<u8>> = Vec::new();
    let mut offset = 12 + QUESTION_LEN;
    let mut target_offset = offset;
    for (i, &removed) in removed_flags.iter().enumerate() {
        if i == pointer_target {
            target_offset = offset;
        }
        let rr = filler(i, removed, remove_type);
        offset += rr.len();
        records.push(rr);
    }
    records.push(pointer_rr(target_offset));
    response_with_section(&records, section, qtype)
}

/// Decode the name the NS record's (the last record in `records`) RDATA
/// pointer resolves to, in a packet already known to parse.
fn ns_pointer_target(records: &[DnsRr]) -> String {
    let ns = records.iter().rev().find(|rr| rr.rtype == RrType::NS as u16)
        .expect("packet must contain the NS pointer record");
    let mut pos = 0usize;
    extract_name(&ns.rdata, &mut pos).expect("NS rdata must decode to a name")
}

/// The property shared by all three filter entry points: given a packet whose
/// only compression pointer targets either a surviving or an about-to-be-
/// elided record, filtering must either rescale the pointer correctly (target
/// survived) or leave the packet completely untouched (target was elided) —
/// never anything in between.
fn assert_pointer_handled_safely(
    pkt:      &[u8],
    filtered: &[u8],
    target_index: usize,
    target_was_removed: bool,
    section:  &str,
) {
    DnsPacket::parse(pkt).expect("test packet itself must be well-formed");

    if target_was_removed {
        assert_eq!(filtered, pkt, "a pointer into an elided record must abandon filtering entirely");
        return;
    }

    let parsed_after = DnsPacket::parse(filtered).expect("filtered packet must still parse");
    let records = match section {
        "answer" => &parsed_after.answers,
        "additional" => &parsed_after.additional,
        _ => unreachable!(),
    };
    let target = ns_pointer_target(records);
    let expected = format!("f{target_index}.example.com");
    assert_eq!(target, expected, "surviving pointer must resolve to the record it names, not garbage");
}

// ── Strategies ───────────────────────────────────────────────────────────────

/// 1–5 filler records' removal flags, plus a valid index into them to aim the
/// compression pointer at.
fn removed_flags_and_target() -> impl Strategy<Value = (Vec<bool>, usize)> {
    prop::collection::vec(any::<bool>(), 1..=5)
        .prop_flat_map(|flags| {
            let len = flags.len();
            (Just(flags), 0..len)
        })
}

// ── Properties ───────────────────────────────────────────────────────────────

proptest! {
    /// `filter_rr_types` (EDNS0-style: additional section, type-keyed).
    #[test]
    fn prop_filter_rr_types_handles_pointers_safely((flags, target) in removed_flags_and_target()) {
        let pkt = packet_with_pointer(&flags, target, REMOVE_TYPE, "additional", 1);
        let filtered = filter_rr_types(&pkt, &[REMOVE_TYPE]).expect("well-formed input must not error");
        assert_pointer_handled_safely(&pkt, &filtered, target, flags[target], "additional");
    }

    /// `filter_configured_rr_types` (CONF mode: answer section, type-keyed).
    #[test]
    fn prop_filter_configured_rr_types_handles_pointers_safely((flags, target) in removed_flags_and_target()) {
        let pkt = packet_with_pointer(&flags, target, REMOVE_TYPE, "answer", 1);
        let (filtered, _) = filter_configured_rr_types(&pkt, &[REMOVE_TYPE])
            .expect("well-formed input must not error");
        assert_pointer_handled_safely(&pkt, &filtered, target, flags[target], "answer");
    }

    /// `strip_dnssec_if_not_requested` (DNSSEC mode: RRSIG only, no OPT so the
    /// DO-bit short-circuit never applies).
    #[test]
    fn prop_strip_dnssec_handles_pointers_safely((flags, target) in removed_flags_and_target()) {
        let pkt = packet_with_pointer(&flags, target, RrType::RRSIG as u16, "answer", 1);
        let stripped = strip_dnssec_if_not_requested(&pkt).expect("well-formed input must not error");
        assert_pointer_handled_safely(&pkt, &stripped, target, flags[target], "answer");
    }
}

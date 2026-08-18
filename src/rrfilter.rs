//! DNS resource record filtering.
//!
//! Port of `rrfilter.c` — "Code to safely remove RRs from a DNS answer".
//!
//! *Safely* is the whole point of the file.  Removing bytes from the middle of
//! a DNS message shifts everything after them, so every compression pointer in
//! a record we keep either has to be rewritten or the removal has to be
//! abandoned.  Upstream does this in four passes (`rrfilter.c:160`):
//!
//! 1. find the records to elide;
//! 2. check that no surviving name points *into* one of them — if one does,
//!    give up and return the answer unchanged;
//! 3. rewrite the surviving pointers to their post-removal offsets;
//! 4. move the kept bytes down and fix the section counts.
//!
//! This module does the same, on a copy rather than in place.

use crate::dns_protocol::{DnsHeader, RrType};
use crate::rfc1035::{DnsError, skip_name};

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Advance `*offset` past `count` DNS questions and return the new offset.
fn skip_questions_to(pkt: &[u8], offset: &mut usize, count: u16) -> Result<(), DnsError> {
    for _ in 0..count {
        skip_name(pkt, offset)?;
        if *offset + 4 > pkt.len() {
            return Err(DnsError::PacketTooShort);
        }
        *offset += 4;
    }
    Ok(())
}

/// Byte ranges (start, end) of the records being elided, in ascending order.
type Elided = [(usize, usize)];

/// Where a byte offset into the original packet ends up once `elided` is
/// removed, or `None` if it lands *inside* an elided record.
///
/// Port of the pointer-scaling loop in `check_name()` (`rrfilter.c:49-60`),
/// which walks the flattened start/end array and gives up on an odd index —
/// i.e. between a start and its matching end.
fn shift_offset(elided: &Elided, off: usize) -> Option<usize> {
    let mut delta = 0usize;
    for &(start, end) in elided {
        if off < start {
            break;
        }
        if off < end {
            return None;
        }
        delta += end - start;
    }
    Some(off - delta)
}

/// Walk one wire-format name, checking (and optionally rewriting) any
/// compression pointer in it.
///
/// Returns `false` — "give up, leave the answer alone" — for a malformed name
/// or a pointer into an elided record.  Port of `check_name()`
/// (`rrfilter.c:23`).
fn check_name(pkt: &mut [u8], pos: &mut usize, elided: &Elided, fixup: bool) -> bool {
    loop {
        if *pos >= pkt.len() {
            return false;
        }
        match pkt[*pos] & 0xC0 {
            0xC0 => {
                // Compression pointer.
                if *pos + 2 > pkt.len() {
                    return false;
                }
                let offset = ((usize::from(pkt[*pos]) & 0x3F) << 8) | usize::from(pkt[*pos + 1]);
                let Some(shifted) = shift_offset(elided, offset) else { return false };
                if fixup {
                    pkt[*pos]     = ((shifted >> 8) as u8) | 0xC0;
                    pkt[*pos + 1] = (shifted & 0xFF) as u8;
                }
                *pos += 2;
                return true;
            }
            0x80 => return false, // reserved label type
            0x40 => {
                // Extended label type; only bitstrings (RFC 2673) are understood.
                if *pos + 2 > pkt.len() || pkt[*pos] & 0x3F != 1 {
                    return false;
                }
                let count = usize::from(pkt[*pos + 1]);
                *pos += 2;
                let bytes = if count == 0 { 32 } else { ((count - 1) >> 3) + 1 };
                if *pos + bytes > pkt.len() {
                    return false;
                }
                *pos += bytes;
            }
            _ => {
                let len = usize::from(pkt[*pos] & 0x3F);
                *pos += 1;
                if *pos + len > pkt.len() {
                    return false;
                }
                *pos += len;
                if len == 0 {
                    return true; // root label ends the name
                }
            }
        }
    }
}

/// RR types that carry domain names inside their RDATA, and where.
///
/// `0` means "a name starts here", a positive value means "skip this many
/// fixed bytes".  Port of `rrfilter_desc()` (`rrfilter.c:296`); an empty slice
/// is C's catch-all entry for types that need no mangling.
fn rrfilter_desc(rtype: u16) -> &'static [i16] {
    match rtype {
        // NS, MD, MF, CNAME, MB, MG, MR, PTR, NXT, DNAME
        2 | 3 | 4 | 5 | 7 | 8 | 9 | 12 | 30 | 39 => &[0],
        6  => &[0, 0],    // SOA
        14 => &[0, 0],    // MINFO
        15 => &[2, 0],    // MX
        17 => &[0, 0],    // RP
        18 => &[2, 0],    // AFSDB
        21 => &[2, 0],    // RT
        24 => &[18, 0],   // SIG
        26 => &[2, 0, 0], // PX
        33 => &[6, 0],    // SRV
        36 => &[2, 0],    // KX
        _  => &[],
    }
}

/// Walk every surviving RR, checking (or fixing) the names it contains.
///
/// Port of `check_rrs()` (`rrfilter.c:105`).  Records that are themselves being
/// elided are skipped — their contents no longer matter.
fn check_rrs(
    pkt:    &mut [u8],
    mut pos: usize,
    total:  usize,
    elided: &Elided,
    fixup:  bool,
) -> bool {
    for _ in 0..total {
        let rr_start = pos;
        if skip_name(pkt, &mut pos).is_err() || pos + 10 > pkt.len() {
            return false;
        }
        let rtype = u16::from_be_bytes([pkt[pos],     pkt[pos + 1]]);
        let class = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]);
        let rdlen = usize::from(u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]));
        pos += 10;

        if !elided.iter().any(|&(start, _)| start == rr_start) {
            let mut name_pos = rr_start;
            if !check_name(pkt, &mut name_pos, elided, fixup) {
                return false;
            }
            if class == 1 {
                let mut rdata_pos = pos;
                for &step in rrfilter_desc(rtype) {
                    if step != 0 {
                        rdata_pos += step as usize;
                        if rdata_pos > pkt.len() {
                            return false;
                        }
                    } else if !check_name(pkt, &mut rdata_pos, elided, fixup) {
                        return false;
                    }
                }
            }
        }

        if pos + rdlen > pkt.len() {
            return false;
        }
        pos += rdlen;
    }
    true
}

/// What the caller wants done with one record.
enum Verdict {
    Keep,
    Remove,
    /// Stop scanning entirely; every remaining record is kept.  C's `break` out
    /// of the first pass once it is past the answer section (`rrfilter.c:228`).
    Stop,
}

/// The parts of the question a filtering decision may depend on.
struct Question {
    qtype:  u16,
    qclass: u16,
}

/// Shared core of the three public filters: decide per record, then elide
/// safely.
///
/// `decide` is called with the record's index across the concatenated
/// answer/authority/additional sections, its TYPE and CLASS, and the section
/// boundaries.  Returns the rewritten packet and the number of records removed.
///
/// A packet whose records cannot be walked, or one where a surviving name
/// points into a record being removed, comes back unchanged — this is C's
/// "we give up and leave the answer unchanged" (`rrfilter.c:255-257`).
fn filter_with<F>(pkt: &[u8], mut decide: F) -> Result<(Vec<u8>, usize), DnsError>
where
    F: FnMut(usize, u16, u16, &Question) -> Verdict,
{
    let hdr = DnsHeader::from_bytes(pkt).ok_or(DnsError::PacketTooShort)?;

    // C refuses to touch a packet that doesn't have exactly one question
    // (`rrfilter.c:173-175`) rather than try to reason about which question a
    // multi-question or question-less packet's answers belong to.
    if hdr.qdcount != 1 {
        return Ok((pkt.to_vec(), 0));
    }

    let mut pos = 12usize;
    skip_questions_to(pkt, &mut pos, hdr.qdcount)?;

    let question = {
        let mut qpos = 12usize;
        skip_name(pkt, &mut qpos)?;
        if qpos + 4 > pkt.len() {
            return Err(DnsError::PacketTooShort);
        }
        Question {
            qtype:  u16::from_be_bytes([pkt[qpos],     pkt[qpos + 1]]),
            qclass: u16::from_be_bytes([pkt[qpos + 2], pkt[qpos + 3]]),
        }
    };

    let an = usize::from(hdr.ancount);
    let ns = usize::from(hdr.nscount);
    let total = an + ns + usize::from(hdr.arcount);

    // ── Pass 1: which records go? ────────────────────────────────────────────
    let mut elided: Vec<(usize, usize)> = Vec::new();
    let (mut chop_an, mut chop_ns, mut chop_ar) = (0u16, 0u16, 0u16);

    for i in 0..total {
        let start = pos;
        skip_name(pkt, &mut pos)?;
        if pos + 10 > pkt.len() {
            return Err(DnsError::PacketTooShort);
        }
        let rtype = u16::from_be_bytes([pkt[pos],     pkt[pos + 1]]);
        let class = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]);
        let rdlen = usize::from(u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]));
        pos += 10 + rdlen;
        if pos > pkt.len() {
            return Err(DnsError::UnexpectedEof);
        }

        match decide(i, rtype, class, &question) {
            Verdict::Keep => continue,
            Verdict::Stop => break,
            Verdict::Remove => {}
        }
        elided.push((start, pos));
        if i < an {
            chop_an += 1;
        } else if i < an + ns {
            chop_ns += 1;
        } else {
            chop_ar += 1;
        }
    }

    if elided.is_empty() {
        return Ok((pkt.to_vec(), 0));
    }
    let removed = elided.len();
    let mut work = pkt.to_vec();

    // ── Pass 2: would any surviving name break? ──────────────────────────────
    // ── Pass 3: if not, rewrite the pointers.  ───────────────────────────────
    for fixup in [false, true] {
        let mut p = 12usize;
        let mut ok = true;
        for _ in 0..hdr.qdcount {
            if !check_name(&mut work, &mut p, &elided, fixup) {
                ok = false;
                break;
            }
            p += 4;
        }
        if ok {
            ok = check_rrs(&mut work, p, total, &elided, fixup);
        }
        if !ok {
            // Only reachable on the checking pass — the fixing pass walks the
            // exact same ground.  Leave the answer alone.
            return Ok((pkt.to_vec(), 0));
        }
    }

    // ── Pass 4: move the kept bytes down. ────────────────────────────────────
    let mut out = Vec::with_capacity(work.len());
    let mut cursor = 0usize;
    for &(start, end) in &elided {
        out.extend_from_slice(&work[cursor..start]);
        cursor = end;
    }
    out.extend_from_slice(&work[cursor..]);

    let new_an = hdr.ancount - chop_an;
    let new_ns = hdr.nscount - chop_ns;
    let new_ar = hdr.arcount - chop_ar;
    out[6..8].copy_from_slice(&new_an.to_be_bytes());
    out[8..10].copy_from_slice(&new_ns.to_be_bytes());
    out[10..12].copy_from_slice(&new_ar.to_be_bytes());

    Ok((out, removed))
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Remove all RRs whose wire TYPE value is in `remove_types` from the
/// answer, authority, and additional sections of `pkt`.
///
/// Returns the new (possibly shorter) packet bytes.  Compression pointers in
/// the surviving records are rewritten; if one of them points into a record
/// being removed the packet comes back unchanged, as upstream does.
///
/// This is how the reply path performs C's `RRFILTER_EDNS0` — stripping the
/// OPT pseudo-RR from a reply whose client never sent one (`forward.c:738`).
///
/// Only the **additional** section is considered, matching C's
/// `i < ancount+nscount || type != T_OPT` skip (`rrfilter.c:200-205`): a record
/// of a "removed" type sitting in the answer or authority section is left
/// alone, since a real OPT RR never appears there.
pub fn filter_rr_types(pkt: &[u8], remove_types: &[u16]) -> Result<Vec<u8>, DnsError> {
    if pkt.len() < 12 {
        return Err(DnsError::PacketTooShort);
    }
    if remove_types.is_empty() {
        return Ok(pkt.to_vec());
    }
    let hdr = DnsHeader::from_bytes(pkt).ok_or(DnsError::PacketTooShort)?;
    let additional_start = usize::from(hdr.ancount) + usize::from(hdr.nscount);
    filter_with(pkt, |i, rtype, _, _| {
        if i < additional_start || !remove_types.contains(&rtype) {
            Verdict::Keep
        } else {
            Verdict::Remove
        }
    })
    .map(|(out, _)| out)
}

/// Remove the DNSSEC records a client that did not set the DO bit must not be
/// sent — C's `RRFILTER_DNSSEC` (`rrfilter.c:206-214`).
///
/// RRSIG, NSEC and NSEC3 go from all three sections.  DNSKEY does *not*:
/// upstream leaves it alone, since it is ordinary data a client may have asked
/// for.  An answer-section record that is exactly what was asked for is kept
/// for the same reason — a query *for* RRSIG still gets its RRSIG back.
pub fn strip_dnssec_if_not_requested(pkt: &[u8]) -> Result<Vec<u8>, DnsError> {
    // The DO bit is in the OPT RR's flags word; set means "send me DNSSEC".
    if let Some(info) = crate::edns0::find_pseudoheader(pkt) {
        if info.flags & 0x8000 != 0 {
            return Ok(pkt.to_vec());
        }
    }

    let ancount = usize::from(DnsHeader::from_bytes(pkt).ok_or(DnsError::PacketTooShort)?.ancount);

    filter_with(pkt, |i, rtype, class, q| {
        let is_dnssec = rtype == RrType::RRSIG as u16
            || rtype == RrType::NSEC  as u16
            || rtype == RrType::NSEC3 as u16;
        if !is_dnssec {
            return Verdict::Keep;
        }
        // Don't remove the answer.
        if i < ancount && rtype == q.qtype && class == q.qclass {
            return Verdict::Keep;
        }
        Verdict::Remove
    })
    .map(|(out, _)| out)
}

/// Apply `--filter-rr` / `--filter-a` / `--filter-aaaa` to a reply — C's
/// `RRFILTER_CONF` (`rrfilter.c:216-235`), called from `process_reply()`
/// (`forward.c:848`).
///
/// Two distinct behaviours, exactly as upstream:
///
/// * For a plain query, only the **answer** section is filtered, and only
///   class-IN records whose type is on the list.
/// * For an `ANY` query when `ANY` is itself on the list, the reply is trimmed
///   to A/AAAA/MX/CNAME "in the spirit of RFC 8482 para 4.3" — everything else
///   in class IN goes, from every section.
///
/// Returns the rewritten packet and how many records were removed; a non-zero
/// count is what makes the reply report `EDE_FILTERED`.
pub fn filter_configured_rr_types(
    pkt:       &[u8],
    filter_rr: &[u16],
) -> Result<(Vec<u8>, usize), DnsError> {
    if pkt.len() < 12 {
        return Err(DnsError::PacketTooShort);
    }
    if filter_rr.is_empty() {
        return Ok((pkt.to_vec(), 0));
    }
    let ancount = usize::from(DnsHeader::from_bytes(pkt).ok_or(DnsError::PacketTooShort)?.ancount);
    let any_query = filter_rr.contains(&(RrType::ANY as u16));

    filter_with(pkt, |i, rtype, class, q| {
        if q.qtype == RrType::ANY as u16 && any_query {
            let keep = class != 1
                || rtype == RrType::A     as u16
                || rtype == RrType::AAAA  as u16
                || rtype == RrType::MX    as u16
                || rtype == RrType::CNAME as u16;
            return if keep { Verdict::Keep } else { Verdict::Remove };
        }
        if i >= ancount {
            return Verdict::Stop;
        }
        if class == 1 && filter_rr.contains(&rtype) { Verdict::Remove } else { Verdict::Keep }
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns_protocol::RrType;
    use crate::rfc1035::{write_rr, DnsRr};
    use bytes::BytesMut;

    // ── helpers ───────────────────────────────────────────────────────────────

    fn make_rr(name: &str, rtype: u16, rdata: &[u8]) -> Vec<u8> {
        let rr = DnsRr {
            name: name.to_owned(),
            rtype,
            class: 1,
            ttl: 300,
            rdata: rdata.to_vec(),
        };
        let mut buf = BytesMut::new();
        write_rr(&mut buf, &rr);
        buf.to_vec()
    }

    /// Build a minimal response packet with the given RRs in the answer section.
    fn response_with_answers(rrs: &[Vec<u8>]) -> Vec<u8> {
        response_with(rrs, &[], &[], 1)
    }

    /// Build a response with explicit answer / authority / additional sections
    /// and a chosen QTYPE.  The question is always `example.com IN`.
    fn response_with(
        answers:    &[Vec<u8>],
        authority:  &[Vec<u8>],
        additional: &[Vec<u8>],
        qtype:      u16,
    ) -> Vec<u8> {
        let counts = [answers.len() as u16, authority.len() as u16, additional.len() as u16];
        let mut pkt = vec![
            0x00, 0x01, // ID
            0x81, 0x80, // flags: QR+RD+RA
            0x00, 0x01, // QDCOUNT=1
        ];
        for c in counts {
            pkt.extend_from_slice(&c.to_be_bytes());
        }
        pkt.extend_from_slice(b"\x07example\x03com\x00");
        pkt.extend_from_slice(&qtype.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        for rr in answers.iter().chain(authority).chain(additional) {
            pkt.extend_from_slice(rr);
        }
        pkt
    }

    /// Build a response whose QDCOUNT does not match the number of questions
    /// actually present, for exercising C's `qdcount != 1` bailout
    /// (`rrfilter.c:173-175`).
    fn response_with_qdcount(answers: &[Vec<u8>], qdcount: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x00, 0x01, // ID
            0x81, 0x80, // flags: QR+RD+RA
        ];
        pkt.extend_from_slice(&qdcount.to_be_bytes());
        pkt.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
        pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT
        for _ in 0..qdcount {
            pkt.extend_from_slice(b"\x07example\x03com\x00");
            pkt.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
            pkt.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
        }
        for rr in answers {
            pkt.extend_from_slice(rr);
        }
        pkt
    }

    // ── filter_rr_types ───────────────────────────────────────────────────────

    #[test]
    fn filter_removes_matching_rr() {
        // filter_rr_types mirrors C's EDNS0 mode, which only ever inspects the
        // additional section (rrfilter.c:200-205).
        let a_rr   = make_rr("example.com", RrType::A as u16, &[1, 2, 3, 4]);
        let txt_rr = make_rr("example.com", RrType::TXT as u16, b"\x05hello");
        let pkt = response_with(&[a_rr], &[], &[txt_rr], 1);

        let hdr_before = DnsHeader::from_bytes(&pkt).unwrap();
        assert_eq!(hdr_before.arcount, 1);

        let filtered = filter_rr_types(&pkt, &[RrType::TXT as u16]).unwrap();
        let hdr_after = DnsHeader::from_bytes(&filtered).unwrap();
        assert_eq!(hdr_after.arcount, 0);
    }

    #[test]
    fn filter_is_idempotent() {
        let a_rr   = make_rr("example.com", RrType::A as u16, &[1, 2, 3, 4]);
        let txt_rr = make_rr("example.com", RrType::TXT as u16, b"\x05hello");
        let pkt = response_with(&[a_rr], &[], &[txt_rr], 1);

        let once  = filter_rr_types(&pkt, &[RrType::TXT as u16]).unwrap();
        let twice = filter_rr_types(&once, &[RrType::TXT as u16]).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn filter_absent_type_returns_unchanged() {
        let a_rr = make_rr("example.com", RrType::A as u16, &[1, 2, 3, 4]);
        let pkt = response_with_answers(&[a_rr]);

        let filtered = filter_rr_types(&pkt, &[RrType::TXT as u16]).unwrap();
        // Packet bytes should be identical when nothing was removed.
        assert_eq!(pkt, filtered);
    }

    #[test]
    fn filter_empty_remove_list() {
        let pkt = response_with_answers(&[]);
        let result = filter_rr_types(&pkt, &[]).unwrap();
        assert_eq!(pkt, result);
    }

    #[test]
    fn filter_too_short_returns_err() {
        assert!(filter_rr_types(&[0u8; 4], &[1]).is_err());
    }

    /// C's EDNS0 mode only ever looks at the additional section
    /// (`rrfilter.c:200-205`: `i < ancount+nscount || type != T_OPT` is skipped).
    /// A record of the "removed" type sitting in the answer section — malformed
    /// or adversarial, since real OPT RRs only ever live in additional — must
    /// survive untouched.
    #[test]
    fn filter_rr_types_only_touches_the_additional_section() {
        let a      = make_rr("example.com", RrType::A as u16, &[1, 2, 3, 4]);
        let rogue  = make_rr("example.com", 41, &[]); // type 41 in the ANSWER section
        let pkt = response_with_answers(&[a, rogue]);

        let filtered = filter_rr_types(&pkt, &[41]).unwrap();
        assert_eq!(filtered, pkt, "EDNS0 stripping must not touch the answer section");
    }

    // ── compression-pointer safety ────────────────────────────────────────────

    /// The four-pass dance exists for this case: a record that survives carries
    /// a compression pointer to a name that sits *after* the removed record, so
    /// the pointer has to be rewritten or the answer is corrupt.
    #[test]
    fn a_surviving_pointer_past_an_elided_record_is_rewritten() {
        // Additional record 1: TXT (to be removed) — its owner name is a literal.
        // (filter_rr_types mirrors C's EDNS0 mode, which only ever looks at the
        // additional section, so the elided record has to live there.)
        let txt = make_rr("example.com", RrType::TXT as u16, b"\x05hello");
        // Additional record 2: NS whose *name* is a literal at a known offset,
        // and whose RDATA is a pointer back to that name.
        let ns_name_offset = 12 + 17 + txt.len(); // header + question + TXT
        let mut ns_rdata = BytesMut::new();
        ns_rdata.extend_from_slice(&[0xC0 | (ns_name_offset >> 8) as u8, (ns_name_offset & 0xFF) as u8]);
        let ns = make_rr("ns.example.com", RrType::NS as u16, &ns_rdata);

        let pkt = response_with(&[], &[], &[txt, ns], 1);
        let filtered = filter_rr_types(&pkt, &[RrType::TXT as u16]).unwrap();

        // The NS record must still parse, and its RDATA pointer must resolve to
        // its own owner name at the new offset.  Left un-rescaled the pointer
        // still *looks* like a pointer — it just addresses the wrong bytes —
        // so the assertion has to be on the name it resolves to.
        let parsed = crate::rfc1035::DnsPacket::parse(&filtered).expect("filtered packet must parse");
        assert_eq!(parsed.additional.len(), 1);
        let mut pos = 0usize;
        let target = crate::rfc1035::extract_name(&parsed.additional[0].rdata, &mut pos)
            .expect("NS rdata must decode");
        assert_eq!(target, "ns.example.com", "pointer must be rescaled to the moved record");
    }

    /// A pointer *into* a record being removed cannot be rescaled, so upstream
    /// abandons the whole filtering operation rather than emit a broken answer.
    #[test]
    fn a_pointer_into_an_elided_record_abandons_the_filter() {
        let txt = make_rr("example.com", RrType::TXT as u16, b"\x05hello");
        // Point at the TXT record's owner name, which is about to disappear.
        let txt_name_offset = 12 + 17;
        let mut ns_rdata = BytesMut::new();
        ns_rdata.extend_from_slice(&[
            0xC0 | (txt_name_offset >> 8) as u8,
            (txt_name_offset & 0xFF) as u8,
        ]);
        let ns = make_rr("ns.example.com", RrType::NS as u16, &ns_rdata);

        let pkt = response_with(&[], &[], &[txt, ns], 1);
        let filtered = filter_rr_types(&pkt, &[RrType::TXT as u16]).unwrap();
        assert_eq!(filtered, pkt, "the answer must be left exactly as it arrived");
    }

    // ── strip_dnssec_if_not_requested ─────────────────────────────────────────

    /// Append an OPT RR with the given flags to a packet.
    fn append_opt(mut pkt: Vec<u8>, udp_size: u16, flags: u16) -> Vec<u8> {
        pkt.push(0x00); // root name
        pkt.extend_from_slice(&(RrType::OPT as u16).to_be_bytes());
        pkt.extend_from_slice(&udp_size.to_be_bytes());
        pkt.push(0); pkt.push(0); // ext_rcode + version
        pkt.extend_from_slice(&flags.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes()); // rdlen=0
        let ar = u16::from_be_bytes([pkt[10], pkt[11]]) + 1;
        pkt[10] = (ar >> 8) as u8;
        pkt[11] = (ar & 0xFF) as u8;
        pkt
    }

    #[test]
    fn strip_dnssec_removes_rrsig_when_do_not_set() {
        let a_rr     = make_rr("example.com", RrType::A     as u16, &[1, 2, 3, 4]);
        let rrsig_rr = make_rr("example.com", RrType::RRSIG as u16, &[0xde, 0xad]);
        let base = response_with_answers(&[a_rr, rrsig_rr]);
        // OPT with DO=0
        let pkt = append_opt(base, 4096, 0x0000);

        let stripped = strip_dnssec_if_not_requested(&pkt).unwrap();
        let hdr = DnsHeader::from_bytes(&stripped).unwrap();
        assert_eq!(hdr.ancount, 1); // only A record remains
    }

    #[test]
    fn strip_dnssec_keeps_rrsig_when_do_set() {
        let a_rr     = make_rr("example.com", RrType::A     as u16, &[1, 2, 3, 4]);
        let rrsig_rr = make_rr("example.com", RrType::RRSIG as u16, &[0xde, 0xad]);
        let base = response_with_answers(&[a_rr, rrsig_rr]);
        // OPT with DO=1 (flags = 0x8000)
        let pkt = append_opt(base, 4096, 0x8000);

        let result = strip_dnssec_if_not_requested(&pkt).unwrap();
        let hdr = DnsHeader::from_bytes(&result).unwrap();
        assert_eq!(hdr.ancount, 2); // both records kept
    }

    #[test]
    fn strip_dnssec_no_opt_removes_dnssec() {
        let a_rr    = make_rr("example.com", RrType::A    as u16, &[1, 2, 3, 4]);
        let nsec_rr = make_rr("example.com", RrType::NSEC as u16, &[0xbe, 0xef]);
        let pkt = response_with_answers(&[a_rr, nsec_rr]);

        let stripped = strip_dnssec_if_not_requested(&pkt).unwrap();
        let hdr = DnsHeader::from_bytes(&stripped).unwrap();
        assert_eq!(hdr.ancount, 1);
    }

    /// RRSIG, NSEC and NSEC3 go — DNSKEY stays.  C's `RRFILTER_DNSSEC` lists
    /// exactly three types (`rrfilter.c:208`); DNSKEY is ordinary queryable
    /// data, not validation scaffolding added on our behalf.
    #[test]
    fn strip_dnssec_removes_the_three_validation_types_but_keeps_dnskey() {
        let rrs = vec![
            make_rr("example.com", RrType::A      as u16, &[1, 2, 3, 4]),
            make_rr("example.com", RrType::RRSIG  as u16, &[0x01]),
            make_rr("example.com", RrType::NSEC   as u16, &[0x02]),
            make_rr("example.com", RrType::NSEC3  as u16, &[0x03]),
            make_rr("example.com", RrType::DNSKEY as u16, &[0x04]),
        ];
        let pkt = response_with_answers(&rrs);
        let stripped = strip_dnssec_if_not_requested(&pkt).unwrap();
        let hdr = DnsHeader::from_bytes(&stripped).unwrap();
        assert_eq!(hdr.ancount, 2, "A and DNSKEY remain");
    }

    /// A client asking *for* RRSIG gets its answer, DO bit or not.
    #[test]
    fn strip_dnssec_keeps_an_rrsig_that_was_the_question() {
        let rrsig = make_rr("example.com", RrType::RRSIG as u16, &[0x01]);
        let pkt = response_with(&[rrsig], &[], &[], RrType::RRSIG as u16);

        let stripped = strip_dnssec_if_not_requested(&pkt).unwrap();
        let hdr = DnsHeader::from_bytes(&stripped).unwrap();
        assert_eq!(hdr.ancount, 1, "the answer to the question must survive");
    }

    /// The same RRSIG in the authority section is not the answer, so it goes.
    #[test]
    fn strip_dnssec_removes_an_rrsig_from_the_authority_section() {
        let a     = make_rr("example.com", RrType::A     as u16, &[1, 2, 3, 4]);
        let rrsig = make_rr("example.com", RrType::RRSIG as u16, &[0x01]);
        let pkt = response_with(&[a], &[rrsig], &[], RrType::RRSIG as u16);

        let stripped = strip_dnssec_if_not_requested(&pkt).unwrap();
        let hdr = DnsHeader::from_bytes(&stripped).unwrap();
        assert_eq!(hdr.ancount, 1);
        assert_eq!(hdr.nscount, 0);
    }

    // ── filter_configured_rr_types (RRFILTER_CONF) ────────────────────────────

    #[test]
    fn conf_filter_removes_a_listed_type_from_the_answer() {
        let a   = make_rr("example.com", RrType::A   as u16, &[1, 2, 3, 4]);
        let caa = make_rr("example.com", RrType::CAA as u16, b"\x00\x05issue");
        let pkt = response_with_answers(&[a, caa]);

        let (out, n) = filter_configured_rr_types(&pkt, &[RrType::CAA as u16]).unwrap();
        assert_eq!(n, 1);
        assert_eq!(DnsHeader::from_bytes(&out).unwrap().ancount, 1);
    }

    /// Only the answer section: C `break`s out of the scan once it is past it.
    #[test]
    fn conf_filter_leaves_the_authority_section_alone() {
        let a   = make_rr("example.com", RrType::A   as u16, &[1, 2, 3, 4]);
        let caa = make_rr("example.com", RrType::CAA as u16, b"\x00\x05issue");
        let pkt = response_with(&[a], &[caa], &[], 1);

        let (out, n) = filter_configured_rr_types(&pkt, &[RrType::CAA as u16]).unwrap();
        assert_eq!(n, 0);
        assert_eq!(out, pkt);
        assert_eq!(DnsHeader::from_bytes(&out).unwrap().nscount, 1);
    }

    #[test]
    fn conf_filter_ignores_a_non_internet_class_record() {
        let mut chaos = make_rr("example.com", RrType::TXT as u16, b"\x05hello");
        // Rewrite CLASS (2 bytes after the 2-byte TYPE, which follows the name).
        let class_at = chaos.len() - 2 - 4 - 2 - 6;
        chaos[class_at] = 0x00;
        chaos[class_at + 1] = 0x03; // CH
        let pkt = response_with_answers(&[chaos]);

        let (_, n) = filter_configured_rr_types(&pkt, &[RrType::TXT as u16]).unwrap();
        assert_eq!(n, 0, "only class IN is filtered");
    }

    /// RFC 8482: an `ANY` query with `ANY` on the filter list is trimmed to
    /// A/AAAA/MX/CNAME, across every section.
    #[test]
    fn conf_filter_trims_an_any_query_to_the_rfc8482_set() {
        let a    = make_rr("example.com", RrType::A     as u16, &[1, 2, 3, 4]);
        let txt  = make_rr("example.com", RrType::TXT   as u16, b"\x05hello");
        let soa  = make_rr("example.com", RrType::SOA   as u16, b"\x00\x00");
        let pkt = response_with(&[a, txt], &[soa], &[], RrType::ANY as u16);

        let (out, n) = filter_configured_rr_types(&pkt, &[RrType::ANY as u16]).unwrap();
        assert_eq!(n, 2, "TXT and SOA both go");
        let hdr = DnsHeader::from_bytes(&out).unwrap();
        assert_eq!(hdr.ancount, 1);
        assert_eq!(hdr.nscount, 0);
    }

    #[test]
    fn conf_filter_with_an_empty_list_is_a_no_op() {
        let a = make_rr("example.com", RrType::A as u16, &[1, 2, 3, 4]);
        let pkt = response_with_answers(&[a]);
        let (out, n) = filter_configured_rr_types(&pkt, &[]).unwrap();
        assert_eq!(n, 0);
        assert_eq!(out, pkt);
    }

    /// C bails out of the whole filter — no elision, no error, unchanged bytes
    /// back — unless there is exactly one question (`rrfilter.c:173-175`).
    #[test]
    fn conf_filter_leaves_packet_unchanged_when_there_is_no_question() {
        let caa = make_rr("example.com", RrType::CAA as u16, b"\x00\x05issue");
        let pkt = response_with_qdcount(&[caa], 0);

        let (out, n) = filter_configured_rr_types(&pkt, &[RrType::CAA as u16]).unwrap();
        assert_eq!(n, 0, "a packet with no question must not be filtered");
        assert_eq!(out, pkt);
    }

    #[test]
    fn conf_filter_leaves_packet_unchanged_when_there_are_two_questions() {
        let caa = make_rr("example.com", RrType::CAA as u16, b"\x00\x05issue");
        let pkt = response_with_qdcount(&[caa], 2);

        let (out, n) = filter_configured_rr_types(&pkt, &[RrType::CAA as u16]).unwrap();
        assert_eq!(n, 0, "a packet with more than one question must not be filtered");
        assert_eq!(out, pkt);
    }

    #[test]
    fn conf_filter_too_short_returns_err() {
        assert!(filter_configured_rr_types(&[0u8; 4], &[1]).is_err());
    }
}

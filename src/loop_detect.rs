//! DNS forwarding-loop detection via probe queries.
//!
//! Port of `loop.c`. When `--dns-loop-detect` (`OPT_LOOP_DETECT`) is set, this
//! resolver periodically sends an identifiable probe query to each general
//! upstream server. If a probe ever comes back to us as an incoming client
//! query, that upstream server is forwarding back to us — a loop — and it is
//! marked [`ServFlags::LOOP`](crate::types::server::ServFlags::LOOP) so
//! [`ForwardEngine`](crate::forward::ForwardEngine)
//! stops selecting it.
#![cfg(feature = "loop")]

use crate::types::server::{Server, ServFlags};
use std::net::SocketAddr;

// ---------------------------------------------------------------------------
// Wire-format constants (config.h: LOOP_TEST_DOMAIN / LOOP_TEST_TYPE)
// ---------------------------------------------------------------------------

/// Domain used for loop-testing probes. `"test"` is reserved by RFC 2606 and
/// therefore never clashes with a real name.
pub const LOOP_TEST_DOMAIN: &str = "test";
/// RR type used for loop-testing probes (`T_TXT`).
pub const LOOP_TEST_TYPE: u16 = 16;

// ---------------------------------------------------------------------------
// Probe construction (loop_make_probe, loop.c:51-77)
// ---------------------------------------------------------------------------

/// Build a DNS query probe embedding `uid` in its qname, exactly as
/// `loop_make_probe()` does: a first label of the 8 lowercase-hex digits of
/// `uid` (`"%.8x"`), followed by the [`LOOP_TEST_DOMAIN`] label, querying
/// [`LOOP_TEST_TYPE`]/IN with the RD bit set and no other header flags.
pub fn loop_make_probe(uid: u32, id: u16) -> Vec<u8> {
    let label = format!("{uid:08x}");

    let mut pkt = Vec::new();
    pkt.extend_from_slice(&id.to_be_bytes()); // ID
    pkt.push(0x01); // hb3: RD=1, opcode=QUERY, QR=0
    pkt.push(0x00); // hb4: no flags
    pkt.extend_from_slice(&[0x00, 0x01]); // QDCOUNT = 1
    pkt.extend_from_slice(&[0x00, 0x00]); // ANCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // NSCOUNT
    pkt.extend_from_slice(&[0x00, 0x00]); // ARCOUNT

    pkt.push(label.len() as u8);
    pkt.extend_from_slice(label.as_bytes());
    pkt.push(LOOP_TEST_DOMAIN.len() as u8);
    pkt.extend_from_slice(LOOP_TEST_DOMAIN.as_bytes());
    pkt.push(0); // root label

    pkt.extend_from_slice(&LOOP_TEST_TYPE.to_be_bytes()); // QTYPE
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    pkt
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// One probe ready to be sent to a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeSend {
    /// Index into the `servers` slice [`loop_send_probes`] was called with.
    pub server_idx: usize,
    /// The server's address, to send the probe to.
    pub addr: SocketAddr,
    /// The wire-format probe query.
    pub packet: Vec<u8>,
}

/// Build one probe per eligible upstream server (`loop_send_probes()`,
/// `loop.c:22-49`).
///
/// A server is eligible when it is a general resolver: no per-domain
/// restriction (`domain` empty) and not restricted to unqualified names
/// (`ServFlags::FOR_NODOTS`). Each eligible server's
/// [`ServFlags::LOOP`] flag is cleared
/// before a fresh probe is built for it — exactly as C does — so a server
/// that stops looping recovers on the next probe round.
///
/// This only builds the packets; sending them is the caller's job (see
/// [`send_probes`]), matching how this module has no socket of its own to
/// send from.
pub fn loop_send_probes(servers: &mut [Server]) -> Vec<ProbeSend> {
    let mut out = Vec::new();
    for (idx, serv) in servers.iter_mut().enumerate() {
        if !serv.domain.is_empty() || serv.flags.contains(ServFlags::FOR_NODOTS) {
            continue;
        }
        serv.flags.remove(ServFlags::LOOP);
        let id = rand::random::<u16>();
        out.push(ProbeSend {
            server_idx: idx,
            addr: SocketAddr::from(serv.addr.clone()),
            packet: loop_make_probe(serv.uid, id),
        });
    }
    out
}

/// Actually send the probes [`loop_send_probes`] built, over throwaway
/// ephemeral UDP sockets. Returns how many were sent successfully.
///
/// Mirrors `loop_send_probes()`'s `sendto()` calls (`loop.c:44-45`); C uses a
/// pooled `randfd` per server, but nothing here ever needs to recognise which
/// socket a reply arrived on — a looping probe comes back as an ordinary
/// incoming client query, matched purely by the uid encoded in its qname (see
/// [`detect_loop`]) — so a one-shot socket per probe is equivalent.
pub async fn send_probes(servers: &mut [Server]) -> usize {
    let probes = loop_send_probes(servers);
    let mut sent = 0;
    for probe in probes {
        let bind_addr: SocketAddr = if probe.addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };
        let Ok(sock) = tokio::net::UdpSocket::bind(bind_addr).await else { continue };
        if sock.send_to(&probe.packet, probe.addr).await.is_ok() {
            sent += 1;
        }
    }
    sent
}

/// Check whether an incoming query `query`/`qtype` is one of our own loop
/// probes coming back, and if so mark the offending server (`detect_loop()`,
/// `loop.c:80-111`).
///
/// `query` is the extracted, dotted qname (as
/// [`extract_request`](crate::rfc1035::extract_request) returns it) — C's
/// `daemon->namebuff`. Returns `true` (and sets [`ServFlags::LOOP`] on the matching
/// server) exactly when the query is a probe this resolver could have sent:
/// right type, right shape (`"<8 hex digits>.test"`), and the embedded uid
/// belongs to a general server not already marked as looping.
pub fn detect_loop(query: &str, qtype: u16, servers: &mut [Server]) -> bool {
    if qtype != LOOP_TEST_TYPE {
        return false;
    }

    let bytes = query.as_bytes();
    let suffix = LOOP_TEST_DOMAIN.as_bytes();
    if bytes.len() != suffix.len() + 9 || &bytes[9..] != suffix {
        return false;
    }
    if !bytes[..8].iter().all(u8::is_ascii_hexdigit) {
        return false;
    }
    // Safe: the loop above just proved every byte in this range is an ASCII
    // hex digit.
    let hex = std::str::from_utf8(&bytes[..8]).unwrap();
    let Ok(uid) = u32::from_str_radix(hex, 16) else { return false };

    for serv in servers.iter_mut() {
        if serv.domain.is_empty() && !serv.flags.contains(ServFlags::LOOP) && serv.uid == uid {
            serv.flags.insert(ServFlags::LOOP);
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::addr::MySockAddr;
    use std::net::{Ipv4Addr, SocketAddrV4};

    fn test_addr(port: u16) -> MySockAddr {
        MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), port))
    }

    fn make_server(domain: &str, flags: ServFlags, uid: u32) -> Server {
        let mut s = crate::option::new_server(flags, domain.to_string(), test_addr(53), test_addr(0));
        s.uid = uid;
        s
    }

    // ── loop_make_probe ─────────────────────────────────────────────────────

    #[test]
    fn loop_make_probe_wire_format() {
        let pkt = loop_make_probe(0x1a2b3c4d, 0xbeef);
        assert_eq!(&pkt[0..2], &0xbeefu16.to_be_bytes());
        assert_eq!(pkt[2], 0x01); // RD set, opcode QUERY, QR=0
        assert_eq!(pkt[3], 0x00);
        assert_eq!(&pkt[4..6], &[0x00, 0x01]); // QDCOUNT
        assert_eq!(&pkt[6..12], &[0, 0, 0, 0, 0, 0]); // AN/NS/AR counts

        // Question: label "1a2b3c4d", label "test", root, QTYPE, QCLASS.
        assert_eq!(pkt[12], 8);
        assert_eq!(&pkt[13..21], b"1a2b3c4d");
        assert_eq!(pkt[21], 4);
        assert_eq!(&pkt[22..26], b"test");
        assert_eq!(pkt[26], 0);
        assert_eq!(&pkt[27..29], &LOOP_TEST_TYPE.to_be_bytes());
        assert_eq!(&pkt[29..31], &1u16.to_be_bytes());
        assert_eq!(pkt.len(), 31);
    }

    #[test]
    fn loop_make_probe_roundtrips_through_extract_request() {
        let pkt = loop_make_probe(0xdeadbeef, 42);
        let (name, rtype) = crate::rfc1035::extract_request(&pkt).unwrap();
        assert_eq!(name, "deadbeef.test");
        assert_eq!(rtype as u16, LOOP_TEST_TYPE);
    }

    // ── loop_send_probes ────────────────────────────────────────────────────

    #[test]
    fn loop_send_probes_builds_one_probe_per_general_server() {
        let mut servers = vec![
            make_server("", ServFlags::empty(), 111),
            make_server("example.com", ServFlags::empty(), 222),
            make_server("", ServFlags::FOR_NODOTS, 333),
        ];
        let probes = loop_send_probes(&mut servers);
        assert_eq!(probes.len(), 1);
        assert_eq!(probes[0].server_idx, 0);
        let (name, _) = crate::rfc1035::extract_request(&probes[0].packet).unwrap();
        assert_eq!(name, "0000006f.test"); // 111 = 0x6f
    }

    #[test]
    fn loop_send_probes_clears_stale_serv_loop() {
        let mut servers = vec![make_server("", ServFlags::LOOP, 1)];
        let probes = loop_send_probes(&mut servers);
        assert_eq!(probes.len(), 1);
        assert!(!servers[0].flags.contains(ServFlags::LOOP));
    }

    #[test]
    fn loop_send_probes_empty_when_no_eligible_servers() {
        let mut servers = vec![make_server("example.com", ServFlags::empty(), 1)];
        assert!(loop_send_probes(&mut servers).is_empty());
    }

    // ── detect_loop ─────────────────────────────────────────────────────────

    #[test]
    fn detect_loop_marks_the_matching_server() {
        let mut servers = vec![make_server("", ServFlags::empty(), 0x1a2b3c4d)];
        assert!(detect_loop("1a2b3c4d.test", LOOP_TEST_TYPE, &mut servers));
        assert!(servers[0].flags.contains(ServFlags::LOOP));
    }

    #[test]
    fn detect_loop_wrong_type_does_not_match() {
        let mut servers = vec![make_server("", ServFlags::empty(), 0x1a2b3c4d)];
        assert!(!detect_loop("1a2b3c4d.test", 1 /* T_A */, &mut servers));
        assert!(!servers[0].flags.contains(ServFlags::LOOP));
    }

    #[test]
    fn detect_loop_wrong_domain_suffix_does_not_match() {
        let mut servers = vec![make_server("", ServFlags::empty(), 0x1a2b3c4d)];
        assert!(!detect_loop("1a2b3c4d.nope", LOOP_TEST_TYPE, &mut servers));
    }

    #[test]
    fn detect_loop_non_hex_uid_does_not_match() {
        let mut servers = vec![make_server("", ServFlags::empty(), 0)];
        assert!(!detect_loop("zzzzzzzz.test", LOOP_TEST_TYPE, &mut servers));
    }

    #[test]
    fn detect_loop_wrong_length_does_not_match() {
        let mut servers = vec![make_server("", ServFlags::empty(), 0x1a2b3c4d)];
        assert!(!detect_loop("1a2b3c4.test", LOOP_TEST_TYPE, &mut servers));
        assert!(!detect_loop("1a2b3c4dd.test", LOOP_TEST_TYPE, &mut servers));
    }

    #[test]
    fn detect_loop_ignores_domain_scoped_servers() {
        // A domain-scoped server can never have sent this probe, even if its
        // uid happens to match (it wasn't eligible in loop_send_probes).
        let mut servers = vec![make_server("example.com", ServFlags::empty(), 0x1a2b3c4d)];
        assert!(!detect_loop("1a2b3c4d.test", LOOP_TEST_TYPE, &mut servers));
    }

    #[test]
    fn detect_loop_no_uid_match_returns_false() {
        let mut servers = vec![make_server("", ServFlags::empty(), 0xffffffff)];
        assert!(!detect_loop("1a2b3c4d.test", LOOP_TEST_TYPE, &mut servers));
    }

    #[test]
    fn detect_loop_already_looping_server_not_matched_again() {
        let mut servers = vec![
            make_server("", ServFlags::LOOP, 0x1a2b3c4d),
            make_server("", ServFlags::empty(), 0x1a2b3c4d),
        ];
        // The already-flagged server is skipped; the second, identical-uid
        // server (a pathological config, but C's loop has no dedup either)
        // is the one that ends up matched.
        assert!(detect_loop("1a2b3c4d.test", LOOP_TEST_TYPE, &mut servers));
        assert!(servers[1].flags.contains(ServFlags::LOOP));
    }

    #[test]
    fn detect_loop_empty_servers_returns_false() {
        let mut servers: Vec<Server> = vec![];
        assert!(!detect_loop("1a2b3c4d.test", LOOP_TEST_TYPE, &mut servers));
    }

    // ── send_probes (async, real UDP loopback) ──────────────────────────────

    #[tokio::test]
    async fn send_probes_delivers_to_a_real_loopback_listener() {
        let listener = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut servers = vec![make_server("", ServFlags::empty(), 0xcafef00d)];
        servers[0].addr = test_addr(port);

        let sent = send_probes(&mut servers).await;
        assert_eq!(sent, 1);

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(std::time::Duration::from_secs(2), listener.recv_from(&mut buf))
            .await
            .expect("probe did not arrive")
            .unwrap();
        let (name, rtype) = crate::rfc1035::extract_request(&buf[..len]).unwrap();
        assert_eq!(name, "cafef00d.test");
        assert_eq!(rtype as u16, LOOP_TEST_TYPE);
    }

    #[tokio::test]
    async fn send_probes_skips_domain_scoped_servers() {
        let mut servers = vec![make_server("example.com", ServFlags::empty(), 1)];
        assert_eq!(send_probes(&mut servers).await, 0);
    }
}

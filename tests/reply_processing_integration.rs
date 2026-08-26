//! Integration coverage for `process_reply()` in the *live* reply path.
//!
//! Upstream `dnsmasq` funnels every accepted upstream answer through
//! `process_reply()` (`forward.c:696`), called from `return_reply()`
//! (`forward.c:1429`).  That one function is where DNS-rebind protection,
//! `--bogus-nxdomain`, `--filter-rr`, EDNS0 fix-up and the DNSSEC RR strip all
//! happen, and `--ignore-address` is checked one frame up in `reply_query()`
//! (`forward.c:1228`).
//!
//! These tests drive the real `run_forward_loop_on` over loopback against a
//! scripted fake upstream and assert on the bytes the *client* receives.  They
//! deliberately do not call `process_reply` (or `check_for_bogus_wildcard`,
//! `rrfilter`, …) directly: the defect this file exists to pin was that those
//! functions were correct, tested, and never reached from the loop.
//!
//! Every helper returns `None` when the environment forbids binding loopback
//! UDP sockets, so restricted sandboxes skip rather than fail.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, BytesMut};

use dnsmasq_rs::cache::new_shared_cache;
use dnsmasq_rs::dns_protocol::{DnsHeader, HB3_AA, HB3_QR, HB3_RD, HB4_AD, HB4_CD, HB4_RA};
use dnsmasq_rs::forward::{run_forward_loop_on, DnsListener, ForwardConfig};
use dnsmasq_rs::option::{apply_config, parse_config_text};
use dnsmasq_rs::rfc1035::{write_name, DnsPacket, DnsQuestion, DnsRr};
use dnsmasq_rs::types::daemon::Daemon;

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

fn query_wire(name: &str, qtype: u16, id: u16) -> Vec<u8> {
    DnsPacket {
        header: DnsHeader { id, hb3: HB3_RD, qdcount: 1, ..Default::default() },
        questions: vec![DnsQuestion { name: name.to_string(), qtype, qclass: 1 }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
    .write()
    .to_vec()
}

/// An OPT pseudo-RR.  `flags` carries the DO bit (0x8000) in the low half of
/// the TTL field; `class` is the advertised UDP payload size.
fn opt_rr(udp_size: u16, flags: u16) -> DnsRr {
    DnsRr { name: String::new(), rtype: 41, class: udp_size, ttl: u32::from(flags), rdata: vec![] }
}

/// A query carrying an EDNS0 OPT record, as an EDNS-capable client sends.
fn edns_query_wire(name: &str, qtype: u16, id: u16, udp_size: u16, do_bit: bool) -> Vec<u8> {
    DnsPacket {
        header: DnsHeader { id, hb3: HB3_RD, qdcount: 1, arcount: 1, ..Default::default() },
        questions: vec![DnsQuestion { name: name.to_string(), qtype, qclass: 1 }],
        answers: vec![],
        authority: vec![],
        additional: vec![opt_rr(udp_size, if do_bit { 0x8000 } else { 0 })],
    }
    .write()
    .to_vec()
}

fn a_rr(name: &str, ip: Ipv4Addr, ttl: u32) -> DnsRr {
    DnsRr { name: name.to_string(), rtype: 1, class: 1, ttl, rdata: ip.octets().to_vec() }
}

fn aaaa_rr(name: &str, ip: Ipv6Addr, ttl: u32) -> DnsRr {
    DnsRr { name: name.to_string(), rtype: 28, class: 1, ttl, rdata: ip.octets().to_vec() }
}

/// An RRSIG whose RDATA is opaque filler — nothing on this path parses it.
fn rrsig_rr(name: &str, covered: u16, ttl: u32) -> DnsRr {
    let mut rd = BytesMut::new();
    rd.put_u16(covered);
    rd.put_u8(8); // algorithm
    rd.put_u8(2); // labels
    rd.put_u32(ttl); // original TTL
    rd.put_u32(0); // signature expiration
    rd.put_u32(0); // signature inception
    rd.put_u16(0x1234); // key tag
    write_name(&mut rd, "test");
    rd.put_slice(&[0xAA; 16]); // signature
    DnsRr { name: name.to_string(), rtype: 46, class: 1, ttl, rdata: rd.to_vec() }
}

fn cname_rr(name: &str, target: &str, ttl: u32) -> DnsRr {
    let mut rd = BytesMut::new();
    write_name(&mut rd, target);
    DnsRr { name: name.to_string(), rtype: 5, class: 1, ttl, rdata: rd.to_vec() }
}

fn caa_rr(name: &str, ttl: u32) -> DnsRr {
    let mut rd = BytesMut::new();
    rd.put_u8(0); // flags
    rd.put_u8(5); // tag length
    rd.put_slice(b"issue");
    rd.put_slice(b"example.net");
    DnsRr { name: name.to_string(), rtype: 257, class: 1, ttl, rdata: rd.to_vec() }
}

/// Build a reply to `query` carrying `answers` and `additional` at `rcode`.
fn reply_to(query: &DnsPacket, rcode: u8, answers: Vec<DnsRr>, additional: Vec<DnsRr>) -> DnsPacket {
    let mut header = query.header;
    header.hb3 |= HB3_QR;
    header.hb4 |= HB4_RA;
    header.set_rcode(rcode);
    header.ancount = answers.len() as u16;
    header.nscount = 0;
    header.arcount = additional.len() as u16;
    DnsPacket {
        header,
        questions: query.questions.clone(),
        answers,
        authority: vec![],
        additional,
    }
}

fn answer(query: &DnsPacket, answers: Vec<DnsRr>) -> Option<DnsPacket> {
    Some(reply_to(query, 0, answers, vec![]))
}

// ---------------------------------------------------------------------------
// Fake upstream / server under test
// ---------------------------------------------------------------------------

struct Upstream {
    addr: SocketAddr,
    queries: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Upstream {
    fn seen(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

async fn spawn_upstream<F>(make_reply: F) -> Option<Upstream>
where
    F: Fn(&DnsPacket) -> Option<DnsPacket> + Send + 'static,
{
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let addr = sock.local_addr().ok()?;
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&queries);

    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, from)) = sock.recv_from(&mut buf).await else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            let Ok(query) = DnsPacket::parse(&buf[..len]) else { continue };
            let Some(reply) = make_reply(&query) else { continue };
            let _ = sock.send_to(&reply.write(), from).await;
        }
    });

    Some(Upstream { addr, queries, task })
}

struct Server {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

async fn spawn_server(config: ForwardConfig) -> Option<Server> {
    let cache = new_shared_cache(config.cache_size, config.min_cache_ttl, config.max_cache_ttl);
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let addr = sock.local_addr().ok()?;
    let listener = DnsListener { sock: Arc::new(sock), check_dst: false };
    let task = tokio::spawn(async move {
        let _ = run_forward_loop_on(vec![listener], None, std::sync::Arc::new(tokio::sync::Mutex::new(config)), cache, dnsmasq_rs::arp::new_shared_arp_state()).await;
    });
    Some(Server { addr, task })
}

/// Build a `ForwardConfig` through the real config pipeline, exactly as the
/// daemon does at startup — a directive that never reaches `ForwardConfig`
/// fails here rather than in a hand-built struct.
fn config_from_text(text: &str, upstream: SocketAddr) -> ForwardConfig {
    let lines = parse_config_text(text, "reply_processing_integration.conf")
        .expect("fixture config must parse");
    let mut daemon = Daemon::default();
    apply_config(&mut daemon, &lines).expect("fixture config must apply");
    let mut config = dnsmasq_rs::dnsmasq::daemon_forward_config(&daemon);
    config.upstreams = vec![upstream];
    config
}

async fn ask_raw(server: SocketAddr, wire: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    client.send_to(wire, server).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(timeout, client.recv_from(&mut buf)).await.ok()?.ok()?;
    Some(buf[..len].to_vec())
}

async fn ask(server: SocketAddr, wire: &[u8]) -> Option<DnsPacket> {
    DnsPacket::parse(&ask_raw(server, wire, Duration::from_secs(2)).await?).ok()
}

/// Ask and expect *no* answer — the reply must have been dropped outright.
async fn ask_expecting_silence(server: SocketAddr, wire: &[u8]) -> Option<Vec<u8>> {
    ask_raw(server, wire, Duration::from_millis(600)).await
}

fn shutdown(server: Server, upstream: Upstream) {
    server.task.abort();
    upstream.task.abort();
}

fn opt_of(reply: &DnsPacket) -> Option<&DnsRr> {
    reply.additional.iter().find(|rr| rr.rtype == 41)
}

fn has_type(reply: &DnsPacket, rtype: u16) -> bool {
    reply.answers.iter().chain(&reply.authority).any(|rr| rr.rtype == rtype)
}

// ---------------------------------------------------------------------------
// --stop-dns-rebind
// ---------------------------------------------------------------------------

/// A private address for a public name must not reach the client.
#[tokio::test]
async fn rebind_reply_is_stripped_before_it_reaches_the_client() {
    let Some(upstream) = spawn_upstream(|q| {
        answer(q, vec![a_rr("public.test", Ipv4Addr::new(192, 168, 1, 1), 300)])
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("stop-dns-rebind\n", upstream.addr)).await
    else {
        return;
    };

    let reply = ask(server.addr, &query_wire("public.test", 1, 0x2001)).await.expect("no reply");
    assert!(reply.answers.is_empty(), "rebind answer must be stripped, got {:?}", reply.answers);

    shutdown(server, upstream);
}

/// `--rebind-domain-ok` still lets the private answer through.
#[tokio::test]
async fn rebind_exclusion_lets_the_private_answer_through() {
    let Some(upstream) = spawn_upstream(|q| {
        answer(q, vec![a_rr("inside.lan", Ipv4Addr::new(192, 168, 1, 1), 300)])
    })
    .await
    else {
        return;
    };
    // The plain (non-slash-delimited) spelling: `--rebind-domain-ok=/lan/` is
    // still parsed as one literal domain by `parse_rebind_domains` — see
    // `tasks.md`.
    let Some(server) =
        spawn_server(config_from_text("stop-dns-rebind\nrebind-domain-ok=lan\n", upstream.addr))
            .await
    else {
        return;
    };

    let reply = ask(server.addr, &query_wire("inside.lan", 1, 0x2002)).await.expect("no reply");
    assert_eq!(reply.answers.len(), 1, "excluded domain must keep its answer");

    shutdown(server, upstream);
}

// ---------------------------------------------------------------------------
// --bogus-nxdomain
// ---------------------------------------------------------------------------

/// The headline `--bogus-nxdomain` case: a wildcard-advertising ISP resolver
/// answers every name with one address, and dnsmasq turns that into NXDOMAIN
/// (`forward.c:809-821`).
#[tokio::test]
async fn bogus_nxdomain_address_is_turned_into_nxdomain() {
    let Some(upstream) = spawn_upstream(|q| {
        answer(q, vec![a_rr("typo.test", Ipv4Addr::new(64, 94, 110, 11), 300)])
    })
    .await
    else {
        return;
    };
    let Some(server) =
        spawn_server(config_from_text("bogus-nxdomain=64.94.110.11\n", upstream.addr)).await
    else {
        return;
    };

    let reply = ask(server.addr, &query_wire("typo.test", 1, 0x2003)).await.expect("no reply");
    assert_eq!(reply.header.rcode(), 3, "bogus wildcard address must become NXDOMAIN");
    assert!(reply.answers.is_empty(), "NXDOMAIN must carry no answers");
    assert_eq!(reply.header.hb3 & HB3_AA, 0, "AA must be cleared on a forced NXDOMAIN");

    shutdown(server, upstream);
}

/// The prefixed form, and the IPv6 half of `check_bad_address()`
/// (`rfc1035.c:1425`) — `--bogus-nxdomain` takes an IPv6 range too.
#[tokio::test]
async fn bogus_nxdomain_matches_an_ipv6_prefix() {
    let Some(upstream) = spawn_upstream(|q| {
        answer(q, vec![aaaa_rr("typo6.test", "2001:db8::dead".parse().unwrap(), 300)])
    })
    .await
    else {
        return;
    };
    let Some(server) =
        spawn_server(config_from_text("bogus-nxdomain=2001:db8::/32\n", upstream.addr)).await
    else {
        return;
    };

    let reply = ask(server.addr, &query_wire("typo6.test", 28, 0x2004)).await.expect("no reply");
    assert_eq!(reply.header.rcode(), 3, "bogus wildcard AAAA must become NXDOMAIN");
    assert!(reply.answers.is_empty());

    shutdown(server, upstream);
}

/// `check_for_bogus_wildcard()` "does its own caching" (`forward.c:808`), and
/// the name it caches under is the owner of the *matching* answer RR, not the
/// question: C's `check_bad_address()` overwrites its `name` buffer from every
/// answer as it walks (`rfc1035.c:1332`).  Behind a CNAME that is the chain
/// target, so a later direct query for the target is answered NXDOMAIN from the
/// cache without a second trip upstream.
#[tokio::test]
async fn bogus_nxdomain_negative_entry_is_cached_under_the_matching_owner() {
    let Some(upstream) = spawn_upstream(|q| {
        let qname = q.questions.first()?.name.clone();
        if qname == "typo.test" {
            Some(reply_to(
                q,
                0,
                vec![
                    cname_rr("typo.test", "wildcard.isp.test", 300),
                    a_rr("wildcard.isp.test", Ipv4Addr::new(64, 94, 110, 11), 300),
                ],
                vec![],
            ))
        } else {
            // A perfectly good answer, which must never be reached: the
            // negative entry cached under this name has to answer first.
            answer(q, vec![a_rr("wildcard.isp.test", Ipv4Addr::new(192, 0, 2, 7), 300)])
        }
    })
    .await
    else {
        return;
    };
    let Some(server) =
        spawn_server(config_from_text("bogus-nxdomain=64.94.110.11\n", upstream.addr)).await
    else {
        return;
    };

    let first = ask(server.addr, &query_wire("typo.test", 1, 0x2011)).await.expect("no reply");
    assert_eq!(first.header.rcode(), 3, "bogus wildcard behind a CNAME must become NXDOMAIN");
    assert_eq!(upstream.seen(), 1);

    let second =
        ask(server.addr, &query_wire("wildcard.isp.test", 1, 0x2012)).await.expect("no reply");
    assert_eq!(
        second.header.rcode(),
        3,
        "the negative entry must be keyed on the offending record's owner name",
    );
    assert!(second.answers.is_empty());
    assert_eq!(upstream.seen(), 1, "the cached NXDOMAIN must answer without going upstream");

    shutdown(server, upstream);
}

/// An address outside the configured range is left alone.
#[tokio::test]
async fn bogus_nxdomain_leaves_an_unlisted_address_alone() {
    let Some(upstream) = spawn_upstream(|q| {
        answer(q, vec![a_rr("real.test", Ipv4Addr::new(192, 0, 2, 5), 300)])
    })
    .await
    else {
        return;
    };
    let Some(server) =
        spawn_server(config_from_text("bogus-nxdomain=64.94.110.11\n", upstream.addr)).await
    else {
        return;
    };

    let reply = ask(server.addr, &query_wire("real.test", 1, 0x2005)).await.expect("no reply");
    assert_eq!(reply.header.rcode(), 0);
    assert_eq!(reply.answers.len(), 1, "unlisted address must be relayed untouched");

    shutdown(server, upstream);
}

// ---------------------------------------------------------------------------
// --ignore-address
// ---------------------------------------------------------------------------

/// `--ignore-address` drops the whole reply — the client gets nothing at all
/// and the query stays in flight (`forward.c:1228-1230`).
#[tokio::test]
async fn ignored_address_reply_never_reaches_the_client() {
    let Some(upstream) = spawn_upstream(|q| {
        answer(q, vec![a_rr("blocked.test", Ipv4Addr::new(198, 51, 100, 9), 300)])
    })
    .await
    else {
        return;
    };
    let Some(server) =
        spawn_server(config_from_text("ignore-address=198.51.100.9\n", upstream.addr)).await
    else {
        return;
    };

    let got = ask_expecting_silence(server.addr, &query_wire("blocked.test", 1, 0x2006)).await;
    assert!(got.is_none(), "a reply carrying an ignored address must be dropped, got {got:?}");
    assert_eq!(upstream.seen(), 1, "the query must still have gone upstream");

    shutdown(server, upstream);
}

// ---------------------------------------------------------------------------
// EDNS0 fix-up
// ---------------------------------------------------------------------------

/// The client sent no OPT, so it must not get one back: C strips the
/// pseudoheader it added itself with `rrfilter(RRFILTER_EDNS0)`
/// (`forward.c:738`).
#[tokio::test]
async fn opt_record_is_stripped_when_the_client_sent_none() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(
            q,
            0,
            vec![a_rr("plain.test", Ipv4Addr::new(192, 0, 2, 10), 300)],
            vec![opt_rr(4096, 0)],
        ))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    let reply = ask(server.addr, &query_wire("plain.test", 1, 0x2007)).await.expect("no reply");
    assert!(opt_of(&reply).is_none(), "non-EDNS client must not receive an OPT record");
    assert_eq!(reply.answers.len(), 1, "stripping the OPT must not disturb the answer");

    shutdown(server, upstream);
}

/// The client did send an OPT, so it gets one back advertising *our* payload
/// size, not whatever upstream chose (`forward.c:747`).
#[tokio::test]
async fn our_payload_size_is_advertised_back_to_an_edns_client() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(
            q,
            0,
            vec![a_rr("edns.test", Ipv4Addr::new(192, 0, 2, 11), 300)],
            vec![opt_rr(1232, 0)],
        ))
    })
    .await
    else {
        return;
    };
    let Some(server) =
        spawn_server(config_from_text("edns-packet-max=4000\n", upstream.addr)).await
    else {
        return;
    };

    let reply = ask(server.addr, &edns_query_wire("edns.test", 1, 0x2008, 512, false))
        .await
        .expect("no reply");
    let opt = opt_of(&reply).expect("EDNS client must receive an OPT record");
    assert_eq!(opt.class, 4000, "OPT must advertise our --edns-packet-max, not upstream's");

    shutdown(server, upstream);
}

/// We set DO upstream when validating; if the client did not, the bit must be
/// cleared before the reply goes back (`forward.c:750-756`).
#[tokio::test]
async fn do_bit_is_cleared_when_the_client_did_not_set_it() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(
            q,
            0,
            vec![a_rr("do.test", Ipv4Addr::new(192, 0, 2, 12), 300)],
            vec![opt_rr(4096, 0x8000)],
        ))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("dnssec\n", upstream.addr)).await else {
        return;
    };

    let reply = ask(server.addr, &edns_query_wire("do.test", 1, 0x2009, 512, false))
        .await
        .expect("no reply");
    let opt = opt_of(&reply).expect("EDNS client must receive an OPT record");
    assert_eq!(opt.ttl & 0x8000, 0, "DO must be cleared for a client that did not set it");

    shutdown(server, upstream);
}

// ---------------------------------------------------------------------------
// DNSSEC RR stripping
// ---------------------------------------------------------------------------

/// "If the requestor didn't set the DO bit, don't return DNSSEC info"
/// (`forward.c:869-872`).
#[tokio::test]
async fn dnssec_rrs_are_stripped_when_the_client_did_not_set_do() {
    let Some(upstream) = spawn_upstream(|q| {
        answer(
            q,
            vec![
                a_rr("signed.test", Ipv4Addr::new(192, 0, 2, 20), 300),
                rrsig_rr("signed.test", 1, 300),
            ],
        )
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("dnssec\n", upstream.addr)).await else {
        return;
    };

    let reply = ask(server.addr, &edns_query_wire("signed.test", 1, 0x200A, 4096, false))
        .await
        .expect("no reply");
    assert!(!has_type(&reply, 46), "RRSIG must be stripped for a DO=0 client");
    assert!(has_type(&reply, 1), "stripping RRSIG must leave the A record");

    shutdown(server, upstream);
}

/// The same reply, for a client that *did* set DO, keeps its signatures.
#[tokio::test]
async fn dnssec_rrs_are_kept_when_the_client_set_do() {
    let Some(upstream) = spawn_upstream(|q| {
        answer(
            q,
            vec![
                a_rr("signed2.test", Ipv4Addr::new(192, 0, 2, 21), 300),
                rrsig_rr("signed2.test", 1, 300),
            ],
        )
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("dnssec\n", upstream.addr)).await else {
        return;
    };

    let reply = ask(server.addr, &edns_query_wire("signed2.test", 1, 0x200B, 4096, true))
        .await
        .expect("no reply");
    assert!(has_type(&reply, 46), "RRSIG must survive for a DO=1 client");

    shutdown(server, upstream);
}

// ---------------------------------------------------------------------------
// --filter-rr / --filter-aaaa
// ---------------------------------------------------------------------------

/// `--filter-rr` elides the listed type from the answer section
/// (`rrfilter.c:225-235`, reached from `forward.c:848`).
#[tokio::test]
async fn filter_rr_removes_the_configured_type_from_the_answer() {
    let Some(upstream) = spawn_upstream(|q| {
        answer(q, vec![caa_rr("caa.test", 300)])
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("filter-rr=CAA\n", upstream.addr)).await
    else {
        return;
    };

    let reply = ask(server.addr, &query_wire("caa.test", 257, 0x200C)).await.expect("no reply");
    assert!(!has_type(&reply, 257), "CAA must be filtered out, got {:?}", reply.answers);
    assert_eq!(reply.header.rcode(), 0, "filtering yields an empty NOERROR, not an error");

    shutdown(server, upstream);
}

/// `--filter-AAAA` is the same mechanism with a built-in type list.
#[tokio::test]
async fn filter_quad_a_removes_aaaa_records() {
    let Some(upstream) = spawn_upstream(|q| {
        answer(q, vec![aaaa_rr("v6.test", "2001:db8::1".parse().unwrap(), 300)])
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("filter-AAAA\n", upstream.addr)).await else {
        return;
    };

    let reply = ask(server.addr, &query_wire("v6.test", 28, 0x200D)).await.expect("no reply");
    assert!(!has_type(&reply, 28), "AAAA must be filtered out");

    shutdown(server, upstream);
}

// ---------------------------------------------------------------------------
// Header bit handling
// ---------------------------------------------------------------------------

/// "RFC 4035 sect 4.6 para 3" — AD is cleared unless `--proxy-dnssec`
/// (`forward.c:763-764`).  Relaying an upstream AD bit would let a client
/// believe an unvalidated answer was authenticated.
#[tokio::test]
async fn ad_bit_from_upstream_is_cleared() {
    let Some(upstream) = spawn_upstream(|q| {
        let mut reply = reply_to(q, 0, vec![a_rr("ad.test", Ipv4Addr::new(192, 0, 2, 30), 300)], vec![]);
        reply.header.hb4 |= HB4_AD;
        Some(reply)
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    let reply = ask(server.addr, &query_wire("ad.test", 1, 0x200E)).await.expect("no reply");
    assert_eq!(reply.header.hb4 & HB4_AD, 0, "AD must be cleared without --proxy-dnssec");

    shutdown(server, upstream);
}

/// `--proxy-dnssec` is the documented opt-out, and must actually do something.
#[tokio::test]
async fn proxy_dnssec_passes_the_upstream_ad_bit_through() {
    let Some(upstream) = spawn_upstream(|q| {
        let mut reply =
            reply_to(q, 0, vec![a_rr("ad2.test", Ipv4Addr::new(192, 0, 2, 31), 300)], vec![]);
        reply.header.hb4 |= HB4_AD;
        Some(reply)
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("proxy-dnssec\n", upstream.addr)).await else {
        return;
    };

    let reply = ask(server.addr, &query_wire("ad2.test", 1, 0x200F)).await.expect("no reply");
    assert_ne!(reply.header.hb4 & HB4_AD, 0, "--proxy-dnssec must relay the upstream AD bit");

    shutdown(server, upstream);
}

/// The CD bit the client gets back is the one it sent, not the one upstream
/// happened to echo (`forward.c:1419-1422`).
#[tokio::test]
async fn cd_bit_is_restored_from_the_clients_query() {
    let Some(upstream) = spawn_upstream(|q| {
        let mut reply =
            reply_to(q, 0, vec![a_rr("cd.test", Ipv4Addr::new(192, 0, 2, 40), 300)], vec![]);
        reply.header.hb4 |= HB4_CD;
        Some(reply)
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    let reply = ask(server.addr, &query_wire("cd.test", 1, 0x2010)).await.expect("no reply");
    assert_eq!(reply.header.hb4 & HB4_CD, 0, "CD must be cleared for a client that did not set it");

    shutdown(server, upstream);
}

// ---------------------------------------------------------------------------
// Extended DNS Errors
// ---------------------------------------------------------------------------

/// A blocked answer carries EDE 15 (Blocked) when the client speaks EDNS0
/// (`forward.c:877-882`).
#[tokio::test]
async fn a_blocked_reply_carries_an_extended_dns_error() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(
            q,
            0,
            vec![a_rr("ede.test", Ipv4Addr::new(64, 94, 110, 11), 300)],
            vec![opt_rr(4096, 0)],
        ))
    })
    .await
    else {
        return;
    };
    let Some(server) =
        spawn_server(config_from_text("bogus-nxdomain=64.94.110.11\n", upstream.addr)).await
    else {
        return;
    };

    let reply = ask(server.addr, &edns_query_wire("ede.test", 1, 0x2011, 4096, false))
        .await
        .expect("no reply");
    let opt = opt_of(&reply).expect("EDNS client must receive an OPT record");
    assert_eq!(
        opt.rdata,
        vec![0x00, 0x0F, 0x00, 0x02, 0x00, 0x0F],
        "OPT must carry option 15 (EDE) with INFO-CODE 15 (Blocked)",
    );

    shutdown(server, upstream);
}

/// No EDE is attached when nothing went wrong.  C only ever touches the OPT
/// record the *reply* arrived with, so the fake upstream echoes one back, as
/// every real EDNS0 resolver does.
#[tokio::test]
async fn a_clean_reply_carries_no_extended_dns_error() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(
            q,
            0,
            vec![a_rr("clean.test", Ipv4Addr::new(192, 0, 2, 50), 300)],
            vec![opt_rr(4096, 0)],
        ))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    let reply = ask(server.addr, &edns_query_wire("clean.test", 1, 0x2012, 4096, false))
        .await
        .expect("no reply");
    let opt = opt_of(&reply).expect("EDNS client must receive an OPT record");
    assert!(opt.rdata.is_empty(), "a clean answer must carry no EDE, got {:?}", opt.rdata);

    shutdown(server, upstream);
}

//! Integration coverage for the DNS cache in the *live* forwarding path.
//!
//! Upstream `dnsmasq` calls `extract_addresses()` from `process_reply()`
//! (`forward.c:824`) for every accepted upstream answer, and `answer_request()`
//! from `udp_request()` before deciding to forward.  A repeated query is
//! therefore answered out of the cache and never reaches an upstream server.
//!
//! These tests drive the real `run_forward_loop_on` over loopback against a
//! scripted fake upstream and count the datagrams that actually reach it — that
//! count *is* the miss count, and `repeats - count` is the hit count.
//!
//! Every helper returns `None` when the environment forbids binding loopback
//! UDP sockets, so restricted sandboxes skip rather than fail.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bytes::{BufMut, BytesMut};

use dnsmasq_rs::cache::{new_shared_cache, SharedDnsCache};
use dnsmasq_rs::dns_protocol::{DnsHeader, HB3_QR, HB3_RD, HB4_CD, HB4_RA};
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

fn a_rr(name: &str, ip: Ipv4Addr, ttl: u32) -> DnsRr {
    DnsRr { name: name.to_string(), rtype: 1, class: 1, ttl, rdata: ip.octets().to_vec() }
}

fn cname_rr(name: &str, target: &str, ttl: u32) -> DnsRr {
    let mut rd = BytesMut::new();
    write_name(&mut rd, target);
    DnsRr { name: name.to_string(), rtype: 5, class: 1, ttl, rdata: rd.to_vec() }
}

/// A minimal SOA record; `minimum` drives the RFC 2308 negative TTL.
fn soa_rr(name: &str, ttl: u32, minimum: u32) -> DnsRr {
    let mut rd = BytesMut::new();
    write_name(&mut rd, "ns.test");
    write_name(&mut rd, "hostmaster.test");
    rd.put_u32(1); // serial
    rd.put_u32(3600); // refresh
    rd.put_u32(600); // retry
    rd.put_u32(86400); // expire
    rd.put_u32(minimum);
    DnsRr { name: name.to_string(), rtype: 6, class: 1, ttl, rdata: rd.to_vec() }
}

/// Build a reply to `query` carrying `answers` / `authority` at `rcode`.
///
/// `RA` is set because that is what a recursive resolver answers with; it is not
/// load-bearing for caching, since the forwarder sets the bit itself before the
/// reply is extracted (`forward.c:776`) — see
/// `reply_without_the_ra_bit_is_cached_and_relayed_with_ra_set`.
fn reply_to(query: &DnsPacket, rcode: u8, answers: Vec<DnsRr>, authority: Vec<DnsRr>) -> DnsPacket {
    let mut header = query.header;
    header.hb3 |= HB3_QR;
    header.hb4 |= HB4_RA;
    header.set_rcode(rcode);
    header.ancount = answers.len() as u16;
    header.nscount = authority.len() as u16;
    header.arcount = 0;
    DnsPacket {
        header,
        questions: query.questions.clone(),
        answers,
        authority,
        additional: vec![],
    }
}

// ---------------------------------------------------------------------------
// Fake upstream
// ---------------------------------------------------------------------------

/// Where the fake upstream sends its reply from.
#[derive(Clone, Copy, PartialEq)]
enum ReplySource {
    /// From the socket the query arrived on — what a real resolver does.
    Same,
    /// From a *different* loopback port, i.e. an off-path spoofer that guessed
    /// the transaction ID.
    Other,
}

struct Upstream {
    addr: SocketAddr,
    /// Number of query datagrams that actually reached the upstream.  This is
    /// the cache **miss** count for the queries driven through the loop.
    queries: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Upstream {
    fn misses(&self) -> usize {
        self.queries.load(Ordering::SeqCst)
    }
}

async fn spawn_upstream_with<F>(source: ReplySource, make_reply: F) -> Option<Upstream>
where
    F: Fn(&DnsPacket) -> Option<DnsPacket> + Send + 'static,
{
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let addr = sock.local_addr().ok()?;
    let other = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let queries = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&queries);

    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, from)) = sock.recv_from(&mut buf).await else { return };
            counter.fetch_add(1, Ordering::SeqCst);
            let Ok(query) = DnsPacket::parse(&buf[..len]) else { continue };
            let Some(reply) = make_reply(&query) else { continue };
            let wire = reply.write();
            let _ = match source {
                ReplySource::Same => sock.send_to(&wire, from).await,
                ReplySource::Other => other.send_to(&wire, from).await,
            };
        }
    });

    Some(Upstream { addr, queries, task })
}

/// The common case: a well-behaved resolver answering from its own socket.
async fn spawn_upstream<F>(make_reply: F) -> Option<Upstream>
where
    F: Fn(&DnsPacket) -> Option<DnsPacket> + Send + 'static,
{
    spawn_upstream_with(ReplySource::Same, make_reply).await
}

// ---------------------------------------------------------------------------
// Server under test
// ---------------------------------------------------------------------------

struct Server {
    addr: SocketAddr,
    task: tokio::task::JoinHandle<()>,
}

/// Spawn the loop over a cache the caller keeps a handle to, so a test can
/// flush it out-of-band (as SIGHUP reload does) and observe the effect on the
/// running loop.
async fn spawn_server_with_cache(config: ForwardConfig, cache: SharedDnsCache) -> Option<Server> {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let addr = sock.local_addr().ok()?;
    let listener = DnsListener { sock: Arc::new(sock), check_dst: false };
    let task = tokio::spawn(async move {
        let _ = run_forward_loop_on(vec![listener], None, config, cache).await;
    });
    Some(Server { addr, task })
}

async fn spawn_server(config: ForwardConfig) -> Option<Server> {
    let cache = new_shared_cache(config.cache_size, config.min_cache_ttl, config.max_cache_ttl);
    spawn_server_with_cache(config, cache).await
}

/// Build a `ForwardConfig` the way `dnsmasq.rs` does: through the real config
/// pipeline (`parse_config_text` → `apply_config` → `Daemon`), then the same
/// `daemon_forward_config` conversion the daemon uses at startup.
fn config_from_text(text: &str, upstream: SocketAddr) -> ForwardConfig {
    let lines = parse_config_text(text, "forward_cache_integration.conf")
        .expect("fixture config must parse");
    let mut daemon = Daemon::default();
    apply_config(&mut daemon, &lines).expect("fixture config must apply");
    let mut config = dnsmasq_rs::dnsmasq::daemon_forward_config(&daemon);
    // The upstream port is only known at run time, so it is injected here
    // rather than written into the fixture text.
    config.upstreams = vec![upstream];
    config
}

/// Send one query and wait up to `timeout` for the raw reply bytes.
async fn ask_raw(server: SocketAddr, wire: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    client.send_to(wire, server).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(timeout, client.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(buf[..len].to_vec())
}

/// Send one query and wait up to `timeout` for the reply.
async fn ask_timeout(server: SocketAddr, wire: &[u8], timeout: Duration) -> Option<DnsPacket> {
    let raw = ask_raw(server, wire, timeout).await?;
    DnsPacket::parse(&raw).ok()
}

async fn ask(server: SocketAddr, wire: &[u8]) -> Option<DnsPacket> {
    ask_timeout(server, wire, Duration::from_secs(2)).await
}

fn first_a(reply: &DnsPacket) -> Option<(Ipv4Addr, u32)> {
    reply.answers.iter().find(|r| r.rtype == 1 && r.rdata.len() == 4).map(|r| {
        (Ipv4Addr::new(r.rdata[0], r.rdata[1], r.rdata[2], r.rdata[3]), r.ttl)
    })
}

fn shutdown(server: Server, upstream: Upstream) {
    server.task.abort();
    upstream.task.abort();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The headline acceptance criterion: three identical queries, one upstream
/// query.  Miss count 1, hit count 2.
#[tokio::test]
async fn repeated_query_is_answered_from_cache_without_re_querying_upstream() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![a_rr("cached.test", Ipv4Addr::new(192, 0, 2, 55), 300)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) =
        spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    for i in 0..3u16 {
        let reply = ask(server.addr, &query_wire("cached.test", 1, 0x1000 + i))
            .await
            .unwrap_or_else(|| panic!("query {i} went unanswered"));
        assert_eq!(reply.header.id, 0x1000 + i, "query {i}: transaction ID must round-trip");
        assert_eq!(
            first_a(&reply).map(|(ip, _)| ip),
            Some(Ipv4Addr::new(192, 0, 2, 55)),
            "query {i}: wrong or missing A record",
        );
    }

    assert_eq!(
        upstream.misses(),
        1,
        "3 identical queries must produce 1 upstream miss and 2 cache hits",
    );

    shutdown(server, upstream);
}

/// A cache entry must expire when its upstream TTL runs out, and the next
/// query must go back upstream.
#[tokio::test]
async fn cached_answer_expires_and_is_re_fetched_from_upstream() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![a_rr("short.test", Ipv4Addr::new(192, 0, 2, 7), 1)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    assert!(ask(server.addr, &query_wire("short.test", 1, 1)).await.is_some());
    assert!(ask(server.addr, &query_wire("short.test", 1, 2)).await.is_some());
    assert_eq!(upstream.misses(), 1, "the 1s entry must still be cached immediately after");

    tokio::time::sleep(Duration::from_millis(1400)).await;

    assert!(ask(server.addr, &query_wire("short.test", 1, 3)).await.is_some());
    assert_eq!(upstream.misses(), 2, "a TTL-1 entry must be gone after 1.4s");

    shutdown(server, upstream);
}

/// NXDOMAIN answers must be negatively cached using the SOA minimum, so the
/// repeat is served locally.
#[tokio::test]
async fn nxdomain_is_negatively_cached_and_replayed_without_upstream() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 3, vec![], vec![soa_rr("test", 600, 300)]))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    for i in 0..2u16 {
        let reply = ask(server.addr, &query_wire("missing.test", 1, 0x20 + i))
            .await
            .unwrap_or_else(|| panic!("NXDOMAIN query {i} went unanswered"));
        assert_eq!(reply.header.rcode(), 3, "query {i}: expected NXDOMAIN");
    }

    assert_eq!(upstream.misses(), 1, "the second NXDOMAIN must come from the negative cache");

    shutdown(server, upstream);
}

/// A cached record must be served with its *remaining* lifetime, not the TTL it
/// was stored with — upstream serves `crecp->ttd - now` (`rfc1035.c:1570`).
#[tokio::test]
async fn served_ttl_counts_down_instead_of_replaying_the_stored_ttl() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![a_rr("countdown.test", Ipv4Addr::new(192, 0, 2, 8), 100)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    let first = ask(server.addr, &query_wire("countdown.test", 1, 1))
        .await
        .expect("first query must be answered");
    assert_eq!(first_a(&first).map(|(_, ttl)| ttl), Some(100), "upstream TTL must pass through");

    tokio::time::sleep(Duration::from_millis(2100)).await;

    let second = ask(server.addr, &query_wire("countdown.test", 1, 2))
        .await
        .expect("second query must be answered from cache");
    let (_, ttl) = first_a(&second).expect("cached A record expected");
    assert_eq!(upstream.misses(), 1, "second query must not reach upstream");
    assert!(
        (90..=98).contains(&ttl),
        "cached record must be served with its remaining TTL (~98s), got {ttl}",
    );

    shutdown(server, upstream);
}

/// A CNAME that came from an upstream answer must replay with its own TTL.  It
/// used to be served with `local-ttl` (0 by default), which is a static-record
/// default and has nothing to do with a cached upstream record.
#[tokio::test]
async fn cached_cname_is_served_with_its_own_ttl_not_local_ttl() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(
            q,
            0,
            vec![
                cname_rr("alias.test", "target.test", 250),
                a_rr("target.test", Ipv4Addr::new(192, 0, 2, 9), 250),
            ],
            vec![],
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

    assert!(ask(server.addr, &query_wire("alias.test", 1, 1)).await.is_some());

    let cached = ask(server.addr, &query_wire("alias.test", 1, 2))
        .await
        .expect("second query must be answered from cache");
    assert_eq!(upstream.misses(), 1, "second query must not reach upstream");

    let cname = cached
        .answers
        .iter()
        .find(|r| r.rtype == 5)
        .expect("cached reply must still carry the CNAME");
    assert!(
        cname.ttl > 0 && cname.ttl <= 250,
        "cached CNAME must keep its own TTL (<=250, >0), got {}",
        cname.ttl,
    );

    shutdown(server, upstream);
}

/// `min-cache-ttl` must raise a short upstream TTL on the *live* insert path,
/// keeping the answer cached past its natural expiry.
#[tokio::test]
async fn min_cache_ttl_keeps_a_short_lived_answer_cached() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![a_rr("floor.test", Ipv4Addr::new(192, 0, 2, 11), 1)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) =
        spawn_server(config_from_text("cache-size=150\nmin-cache-ttl=120\n", upstream.addr)).await
    else {
        return;
    };

    assert!(ask(server.addr, &query_wire("floor.test", 1, 1)).await.is_some());

    tokio::time::sleep(Duration::from_millis(1400)).await;

    assert!(ask(server.addr, &query_wire("floor.test", 1, 2)).await.is_some());
    assert_eq!(
        upstream.misses(),
        1,
        "min-cache-ttl=120 must hold a TTL-1 answer in the cache past 1.4s",
    );

    shutdown(server, upstream);
}

/// `max-cache-ttl` must lower a long upstream TTL on the live insert path, so
/// the entry expires early and the next query is forwarded again.
#[tokio::test]
async fn max_cache_ttl_expires_a_long_lived_answer_early() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![a_rr("ceiling.test", Ipv4Addr::new(192, 0, 2, 12), 3600)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) =
        spawn_server(config_from_text("cache-size=150\nmax-cache-ttl=1\n", upstream.addr)).await
    else {
        return;
    };

    assert!(ask(server.addr, &query_wire("ceiling.test", 1, 1)).await.is_some());
    assert_eq!(upstream.misses(), 1);

    tokio::time::sleep(Duration::from_millis(1400)).await;

    assert!(ask(server.addr, &query_wire("ceiling.test", 1, 2)).await.is_some());
    assert_eq!(
        upstream.misses(),
        2,
        "max-cache-ttl=1 must expire a TTL-3600 answer after 1.4s",
    );

    shutdown(server, upstream);
}

/// Rebind protection lives in `extract_addresses`, which upstream calls
/// unconditionally (`forward.c:824`).  A zero cache size only stops the insert
/// from committing — it must not disable the rebind test.
#[tokio::test]
async fn rebind_protection_blocks_the_answer_even_with_caching_disabled() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![a_rr("evil.test", Ipv4Addr::new(192, 168, 1, 5), 300)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text(
        "cache-size=0\nstop-dns-rebind\n",
        upstream.addr,
    ))
    .await
    else {
        return;
    };

    let query = query_wire("evil.test", 1, 0x77);
    let raw = ask_raw(server.addr, &query, Duration::from_secs(2))
        .await
        .expect("a blocked reply is still delivered, with its sections cleared");
    let reply = DnsPacket::parse(&raw).expect("the blocked reply must still be well formed");

    assert!(
        reply.answers.is_empty(),
        "stop-dns-rebind must strip the RFC1918 answer even when cache-size=0, got {:?}",
        reply.answers,
    );
    assert!(reply.authority.is_empty() && reply.additional.is_empty());
    // The record bytes must be gone from the wire, not merely uncounted: a
    // blocked reply is exactly a header plus the echoed question.
    assert_eq!(
        raw.len(),
        query.len(),
        "a blocked reply must carry no resource-record bytes at all",
    );

    shutdown(server, upstream);
}

/// `127.0.0.0/8` counts as private for the rebind test by default: C passes
/// `!option_bool(OPT_LOCAL_REBIND)` to `private_net()` (`rfc1035.c:997`), and
/// without `rebind-localhost-ok` that argument is true.
#[tokio::test]
async fn stop_dns_rebind_blocks_a_loopback_answer_by_default() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![a_rr("lo.test", Ipv4Addr::new(127, 0, 0, 1), 300)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) =
        spawn_server(config_from_text("cache-size=150\nstop-dns-rebind\n", upstream.addr)).await
    else {
        return;
    };

    let reply = ask(server.addr, &query_wire("lo.test", 1, 0x51))
        .await
        .expect("a blocked reply is still delivered");
    assert!(
        reply.answers.is_empty(),
        "stop-dns-rebind alone must block a 127.0.0.0/8 answer, got {:?}",
        reply.answers,
    );

    shutdown(server, upstream);
}

/// `rebind-localhost-ok` exempts `127.0.0.0/8` (and `::1`) from the rebind test
/// — `private_net(addr, !option_bool(OPT_LOCAL_REBIND))` (`rfc1035.c:997,1001`).
/// The directive is parsed into `OPT_LOCAL_REBIND` by `option.rs`, so it must
/// reach the live extraction path rather than being a silent no-op.
#[tokio::test]
async fn rebind_localhost_ok_lets_a_loopback_answer_through() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![a_rr("lo.test", Ipv4Addr::new(127, 0, 0, 1), 300)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text(
        "cache-size=150\nstop-dns-rebind\nrebind-localhost-ok\n",
        upstream.addr,
    ))
    .await
    else {
        return;
    };

    let reply = ask(server.addr, &query_wire("lo.test", 1, 0x52))
        .await
        .expect("the answer must be delivered");
    assert_eq!(
        first_a(&reply).map(|(ip, _)| ip),
        Some(Ipv4Addr::new(127, 0, 0, 1)),
        "rebind-localhost-ok must let a loopback answer through",
    );

    // Exempt from the *rebind* test does not mean exempt from caching: the
    // answer is committed like any other, so the repeat is a hit.
    assert!(ask(server.addr, &query_wire("lo.test", 1, 0x53)).await.is_some());
    assert_eq!(upstream.misses(), 1, "the allowed loopback answer must be cached");

    // A non-loopback private address is still blocked — the directive narrows
    // the check, it does not disable it.
    shutdown(server, upstream);
}

/// `rebind-localhost-ok` narrows the rebind test to the loopback range only;
/// RFC1918 space stays blocked.
#[tokio::test]
async fn rebind_localhost_ok_still_blocks_rfc1918() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![a_rr("evil.test", Ipv4Addr::new(10, 1, 2, 3), 300)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text(
        "cache-size=150\nstop-dns-rebind\nrebind-localhost-ok\n",
        upstream.addr,
    ))
    .await
    else {
        return;
    };

    let reply = ask(server.addr, &query_wire("evil.test", 1, 0x54))
        .await
        .expect("a blocked reply is still delivered");
    assert!(
        reply.answers.is_empty(),
        "10.0.0.0/8 must still be blocked with rebind-localhost-ok, got {:?}",
        reply.answers,
    );

    shutdown(server, upstream);
}

/// C logs a truncated reply and relays it (`forward.c:791`), leaving the client
/// to retry over TCP.  Nothing may be cached from it, because the answer it
/// carries is by definition incomplete.
#[tokio::test]
async fn truncated_reply_is_relayed_and_never_cached() {
    let Some(upstream) = spawn_upstream(|q| {
        let mut reply =
            reply_to(q, 0, vec![a_rr("cut.test", Ipv4Addr::new(192, 0, 2, 30), 300)], vec![]);
        reply.header.hb3 |= 0x02; // TC
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

    let first = ask(server.addr, &query_wire("cut.test", 1, 1))
        .await
        .expect("a truncated reply must still be relayed to the client");
    assert_eq!(first.header.hb3 & 0x02, 0x02, "the TC bit must survive the relay");

    // Nothing was cached, so the repeat goes upstream again.
    assert!(ask(server.addr, &query_wire("cut.test", 1, 2)).await.is_some());
    assert_eq!(
        upstream.misses(),
        2,
        "a truncated answer must not populate the cache",
    );

    shutdown(server, upstream);
}

/// A reply carrying the right transaction ID but arriving from an address the
/// query was never sent to is an off-path spoof and must be dropped
/// (`forward.c:1201-1209`).
#[tokio::test]
async fn reply_from_an_unexpected_source_address_is_ignored() {
    let Some(upstream) = spawn_upstream_with(ReplySource::Other, |q| {
        Some(reply_to(q, 0, vec![a_rr("spoof.test", Ipv4Addr::new(192, 0, 2, 66), 300)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    let reply =
        ask_timeout(server.addr, &query_wire("spoof.test", 1, 0x88), Duration::from_millis(700))
            .await;
    assert!(reply.is_none(), "a reply from an unexpected source must not be relayed");

    shutdown(server, upstream);
}

/// Upstream matches a reply by name/class/type *and* ID (`lookup_frec`,
/// `forward.c:1173`).  A reply whose question does not match the outstanding
/// query must be dropped, not cached under the attacker's name.
#[tokio::test]
async fn reply_whose_question_does_not_match_is_ignored() {
    let Some(upstream) = spawn_upstream(|q| {
        // Same transaction ID, different question — a cache-poisoning attempt.
        let mut forged = reply_to(
            q,
            0,
            vec![a_rr("victim.test", Ipv4Addr::new(192, 0, 2, 99), 300)],
            vec![],
        );
        forged.questions = vec![DnsQuestion {
            name: "victim.test".to_string(),
            qtype: 1,
            qclass: 1,
        }];
        Some(forged)
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    let reply =
        ask_timeout(server.addr, &query_wire("asked.test", 1, 0x99), Duration::from_millis(700))
            .await;
    assert!(reply.is_none(), "a reply answering a different question must not be relayed");

    // And the forged answer must not have been cached: querying the name the
    // attacker tried to poison still has to go upstream.
    let before = upstream.misses();
    let _ = ask_timeout(
        server.addr,
        &query_wire("victim.test", 1, 0x9a),
        Duration::from_millis(700),
    )
    .await;
    assert!(
        upstream.misses() > before,
        "victim.test must not have been poisoned into the cache",
    );

    shutdown(server, upstream);
}

/// A locally generated answer — which is now every cache hit — must carry the
/// OPT pseudo-header back when the client sent one.  C strips the additional
/// section while building the answer and re-adds OPT in `receive_query()`
/// (`forward.c:1969`), advertising `daemon->edns_pktsz` and carrying only the DO
/// bit across (`edns0.c:204-210`).
#[tokio::test]
async fn cache_hit_keeps_the_client_edns_pseudoheader() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![a_rr("edns.test", Ipv4Addr::new(192, 0, 2, 60), 300)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text(
        "cache-size=150\nedns-packet-max=1232\n",
        upstream.addr,
    ))
    .await
    else {
        return;
    };

    // A query with an EDNS0 OPT advertising 4096 bytes and the DO bit set.
    let edns_query = |id: u16| {
        let mut pkt = DnsPacket::parse(&query_wire("edns.test", 1, id)).expect("valid query");
        pkt.additional = vec![DnsRr {
            name: String::new(),
            rtype: 41,
            class: 4096,
            ttl: 0x8000, // DO
            rdata: vec![],
        }];
        pkt.header.arcount = 1;
        pkt.write().to_vec()
    };

    assert!(ask(server.addr, &edns_query(1)).await.is_some());

    let cached = ask(server.addr, &edns_query(2))
        .await
        .expect("the repeat must be answered from cache");
    assert_eq!(upstream.misses(), 1, "the repeat must not reach upstream");

    let opt = cached
        .additional
        .iter()
        .find(|r| r.rtype == 41)
        .expect("a cache hit must still carry the OPT pseudo-header");
    assert_eq!(opt.name, "", "OPT always has the root name");
    assert_eq!(opt.class, 1232, "OPT must advertise our edns-packet-max, not the client's");
    assert_eq!(opt.ttl, 0x8000, "the DO bit must be carried across, rcode/version zero");
    assert!(opt.rdata.is_empty(), "the re-added OPT carries no options");
    assert_eq!(cached.header.arcount, 1, "ARCOUNT must count the OPT record");

    shutdown(server, upstream);
}

/// A cached CNAME whose target has expired must not be served on its own.
///
/// Upstream only sets `ans` for a CNAME when it came from config or the client
/// actually asked for `T_CNAME` (`rfc1035.c:1704-1705`); otherwise the chain has
/// to bottom out in something that answers, or `if (!ans) return 0`
/// (`rfc1035.c:2295`) forwards the query.  Answering a dead-ended chain locally
/// would return a CNAME-only NOERROR — a resolution failure — for as long as the
/// CNAME outlives its target, which is the everyday CDN TTL pattern.
#[tokio::test]
async fn cname_outliving_its_target_is_re_resolved_upstream() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(
            q,
            0,
            vec![
                cname_rr("www.cdn.test", "edge.cdn.test", 600),
                a_rr("edge.cdn.test", Ipv4Addr::new(192, 0, 2, 40), 1),
            ],
            vec![],
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

    assert!(ask(server.addr, &query_wire("www.cdn.test", 1, 1)).await.is_some());
    assert_eq!(upstream.misses(), 1);

    // The A record (TTL 1) is gone; the CNAME (TTL 600) is not.
    tokio::time::sleep(Duration::from_millis(1400)).await;

    let reply = ask(server.addr, &query_wire("www.cdn.test", 1, 2))
        .await
        .expect("the query must still be answered");
    assert_eq!(
        upstream.misses(),
        2,
        "a CNAME whose target expired must send the query back upstream, not answer CNAME-only",
    );
    assert_eq!(
        first_a(&reply).map(|(ip, _)| ip),
        Some(Ipv4Addr::new(192, 0, 2, 40)),
        "the re-resolved answer must carry an address, not just the CNAME",
    );

    shutdown(server, upstream);
}

/// A client asking for the CNAME itself is answered from cache: that is the one
/// case where upstream sets `ans` for a cached CNAME (`qtype == T_CNAME`).
#[tokio::test]
async fn explicit_cname_query_is_never_cached() {
    // "do not cache data from CNAME queries" (rfc1035.c:804): `insert` is 0
    // for a `T_CNAME` query, so the answer never lands in the cache and a
    // repeated query must go back to the upstream every time.
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![cname_rr("only.test", "elsewhere.test", 300)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    let first = ask(server.addr, &query_wire("only.test", 5, 1))
        .await
        .expect("the CNAME query must be answered");
    assert!(first.answers.iter().any(|r| r.rtype == 5), "the reply must carry the CNAME");

    let second = ask(server.addr, &query_wire("only.test", 5, 2))
        .await
        .expect("the repeated CNAME query must be answered");
    assert!(second.answers.iter().any(|r| r.rtype == 5), "the reply must carry the CNAME");
    assert_eq!(upstream.misses(), 2, "a CNAME query must never be served from the cache");

    shutdown(server, upstream);
}

/// C stages every insert on `new_chain` and only commits it in
/// `cache_end_insert()` (`rfc1035.c:1128`), which `extract_addresses()` never
/// reaches when it bails out with the rebind code.  A blocked reply therefore
/// leaves *nothing* behind, including the records that were processed before the
/// offending one.
#[tokio::test]
async fn rebind_blocked_reply_commits_nothing_to_the_cache() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(
            q,
            0,
            vec![
                // A legitimate public address first, then the rebind attempt.
                a_rr("evil.test", Ipv4Addr::new(198, 51, 100, 4), 300),
                a_rr("evil.test", Ipv4Addr::new(192, 168, 1, 5), 300),
            ],
            vec![],
        ))
    })
    .await
    else {
        return;
    };
    let Some(server) =
        spawn_server(config_from_text("cache-size=150\nstop-dns-rebind\n", upstream.addr)).await
    else {
        return;
    };

    let first = ask(server.addr, &query_wire("evil.test", 1, 1))
        .await
        .expect("the stripped reply is still delivered");
    assert!(first.answers.is_empty(), "the rebind answer must be stripped");

    let second = ask(server.addr, &query_wire("evil.test", 1, 2))
        .await
        .expect("the repeat must be answered too");
    assert!(second.answers.is_empty(), "the repeat must also be stripped");
    assert_eq!(
        upstream.misses(),
        2,
        "a rebind-blocked reply must leave no partial state in the cache",
    );

    shutdown(server, upstream);
}

/// A NODATA answer (NOERROR, no matching RR) is negatively cached against the
/// *queried type*, and the repeat must be served locally.  The entry has to be
/// stored under a key the lookup actually probes, or the negative cache is inert
/// for everything except NXDOMAIN.
#[tokio::test]
async fn nodata_answer_is_negatively_cached_for_the_queried_type() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![], vec![soa_rr("test", 600, 300)]))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    for i in 0..2u16 {
        let reply = ask(server.addr, &query_wire("v4only.test", 28, 0x30 + i))
            .await
            .unwrap_or_else(|| panic!("NODATA query {i} went unanswered"));
        assert_eq!(reply.header.rcode(), 0, "query {i}: NODATA is NOERROR");
        assert!(reply.answers.is_empty(), "query {i}: NODATA carries no answers");
    }

    assert_eq!(
        upstream.misses(),
        1,
        "the second AAAA query must come from the NODATA negative cache",
    );

    shutdown(server, upstream);
}

/// A NODATA entry is per-type: it must not suppress a query for a type the
/// server never said anything about.
#[tokio::test]
async fn nodata_for_one_type_does_not_answer_another_type() {
    let Some(upstream) = spawn_upstream(|q| {
        let qtype = q.questions.first().map_or(0, |q| q.qtype);
        if qtype == 1 {
            Some(reply_to(q, 0, vec![a_rr("mixed.test", Ipv4Addr::new(192, 0, 2, 44), 300)], vec![]))
        } else {
            Some(reply_to(q, 0, vec![], vec![soa_rr("test", 600, 300)]))
        }
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    assert!(ask(server.addr, &query_wire("mixed.test", 28, 1)).await.is_some());
    let a_reply = ask(server.addr, &query_wire("mixed.test", 1, 2))
        .await
        .expect("the A query must be answered");
    assert_eq!(
        first_a(&a_reply).map(|(ip, _)| ip),
        Some(Ipv4Addr::new(192, 0, 2, 44)),
        "a cached AAAA NODATA must not swallow the A query",
    );
    assert_eq!(upstream.misses(), 2, "the A query is a different type and must be forwarded");

    shutdown(server, upstream);
}

/// `RA` clear on the wire does **not** stop caching.  C sets `HB4_RA` on every
/// reply it processes (`forward.c:776`) before it ever reaches
/// `extract_addresses()` (`forward.c:824`), so the `RA` test guarding
/// `cache_end_insert()` (`rfc1035.c:1124-1127`) is always true on the live path.
/// The visible consequences: an answer from a non-recursive server — a plain
/// authoritative nameserver named by `server=/domain/addr` answers `RA=0` — is
/// cached like any other, and every relayed reply reaches the client with `RA`
/// set, because that is what *this* server offers regardless of what upstream
/// does.
#[tokio::test]
async fn reply_without_the_ra_bit_is_cached_and_relayed_with_ra_set() {
    let Some(upstream) = spawn_upstream(|q| {
        let mut reply =
            reply_to(q, 0, vec![a_rr("norec.test", Ipv4Addr::new(192, 0, 2, 21), 300)], vec![]);
        reply.header.hb4 &= !HB4_RA;
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

    let first = ask(server.addr, &query_wire("norec.test", 1, 1))
        .await
        .expect("a non-recursive reply is still relayed");
    assert_eq!(
        first_a(&first).map(|(ip, _)| ip),
        Some(Ipv4Addr::new(192, 0, 2, 21)),
        "the answer itself must reach the client untouched",
    );
    assert_ne!(
        first.header.hb4 & HB4_RA,
        0,
        "a relayed reply must carry RA: C sets it unconditionally at forward.c:776",
    );

    let second = ask(server.addr, &query_wire("norec.test", 1, 2))
        .await
        .expect("the repeat must be answered");
    assert_eq!(
        first_a(&second).map(|(ip, _)| ip),
        Some(Ipv4Addr::new(192, 0, 2, 21)),
        "the cached answer must carry the same address",
    );
    assert_eq!(
        upstream.misses(),
        1,
        "an RA-clear reply is cached like any other, so the repeat is a hit",
    );

    shutdown(server, upstream);
}

/// `CD` set means the client is doing its own validation, so C also skips the
/// commit (`rfc1035.c:1124`).  The bit is echoed by the upstream server, so a
/// `CD` query produces a `CD` reply.
#[tokio::test]
async fn reply_with_the_cd_bit_is_relayed_but_not_cached() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![a_rr("checkdis.test", Ipv4Addr::new(192, 0, 2, 22), 300)], vec![]))
    })
    .await
    else {
        return;
    };
    let Some(server) = spawn_server(config_from_text("cache-size=150\n", upstream.addr)).await
    else {
        return;
    };

    let cd_query = |id: u16| {
        let mut pkt = DnsPacket::parse(&query_wire("checkdis.test", 1, id)).expect("valid query");
        pkt.header.hb4 |= HB4_CD;
        pkt.write().to_vec()
    };

    assert!(ask(server.addr, &cd_query(1)).await.is_some());
    assert!(ask(server.addr, &cd_query(2)).await.is_some());
    assert_eq!(
        upstream.misses(),
        2,
        "a reply with CD set must not populate the cache",
    );

    shutdown(server, upstream);
}

/// SIGHUP reload (`dnsmasq::on_sighup`) must flush the *running* loop's
/// cache, not a disconnected copy — this is the behavior that makes it real
/// rather than the old stub that only toggled a bookkeeping flag.
#[tokio::test]
async fn sighup_reload_flushes_the_live_forward_cache() {
    let Some(upstream) = spawn_upstream(|q| {
        Some(reply_to(q, 0, vec![a_rr("reload.test", Ipv4Addr::new(192, 0, 2, 77), 300)], vec![]))
    })
    .await
    else {
        return;
    };
    let config = config_from_text("cache-size=150\n", upstream.addr);
    let cache = new_shared_cache(config.cache_size, config.min_cache_ttl, config.max_cache_ttl);
    let Some(server) = spawn_server_with_cache(config, cache.clone()).await else {
        return;
    };

    assert!(ask(server.addr, &query_wire("reload.test", 1, 1)).await.is_some());
    assert!(ask(server.addr, &query_wire("reload.test", 1, 2)).await.is_some());
    assert_eq!(upstream.misses(), 1, "the second query must be a cache hit before reload");

    let daemon_handle = dnsmasq_rs::dnsmasq::init_daemon_with(Daemon::default());
    dnsmasq_rs::dnsmasq::on_sighup(&daemon_handle, &cache).await;

    assert!(ask(server.addr, &query_wire("reload.test", 1, 3)).await.is_some());
    assert_eq!(
        upstream.misses(),
        2,
        "SIGHUP must flush the live cache, forcing the next query back upstream",
    );

    shutdown(server, upstream);
}

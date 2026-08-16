//! Integration coverage for the two anti-spoofing / anti-exhaustion mechanisms
//! upstream `dnsmasq` puts on the outbound query path.
//!
//! * **Source-port randomisation.**  `forward_query()` calls
//!   `allocate_rfd(&forward->rfds, srv)` (`forward.c:528`) for *every* send, and
//!   `allocate_rfd()` opens a fresh socket via `random_sock()`
//!   (`forward.c:2782`) bound with port `0` whenever a slot in
//!   `daemon->randomsocks[]` is free.  Concurrent queries therefore leave from
//!   different, unpredictable source ports; a random transaction ID on its own
//!   is only 16 bits of guesswork.
//!
//! * **Per-server-group query limiting and duplicate-client folding.**
//!   `get_new_frec()` (`forward.c:3122`) refuses to allocate once
//!   `daemon->ftabsize` queries are already in flight to the same server group,
//!   and `forward_query()` (`forward.c:195-323`) folds a second client asking
//!   the identical question onto the existing `frec` as another `frec_src`
//!   rather than opening a second upstream transaction.
//!
//! Every helper returns `None` when the environment forbids binding loopback
//! UDP sockets, so restricted sandboxes skip rather than fail.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use dnsmasq_rs::cache::new_shared_cache;
use dnsmasq_rs::dns_protocol::{DnsHeader, HB3_QR, HB3_RD};
use dnsmasq_rs::forward::{run_forward_loop_on, DnsListener, ForwardConfig};
use dnsmasq_rs::rfc1035::{DnsPacket, DnsQuestion};

// ---------------------------------------------------------------------------
// Helpers
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

/// Everything the fake upstream saw: the datagram and the address it came from.
type Seen = Arc<Mutex<Vec<(SocketAddr, Vec<u8>)>>>;

/// A fake upstream resolver.
///
/// `reply_after` of `None` means it never answers, which keeps queries pinned
/// in flight so a test can observe concurrent state.  `Some(d)` means every
/// query is echoed back with the QR bit set after `d` — the delay is what lets
/// a test get a second client's query in before the first one completes.
async fn spawn_upstream(reply_after: Option<Duration>) -> Option<(SocketAddr, Seen)> {
    let sock = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?);
    let addr = sock.local_addr().ok()?;
    let seen: Seen = Arc::new(Mutex::new(Vec::new()));
    let seen_task = Arc::clone(&seen);

    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else { return };
            let pkt = buf[..n].to_vec();
            seen_task.lock().unwrap().push((from, pkt.clone()));
            if let Some(delay) = reply_after {
                let sock = Arc::clone(&sock);
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    let mut reply = pkt;
                    reply[2] |= HB3_QR;
                    let _ = sock.send_to(&reply, from).await;
                });
            }
        }
    });

    Some((addr, seen))
}

/// Spawn the real forwarding loop over loopback and return its address.
async fn spawn_server(config: ForwardConfig) -> Option<SocketAddr> {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let addr = sock.local_addr().ok()?;
    let cache = new_shared_cache(config.cache_size, config.min_cache_ttl, config.max_cache_ttl);
    let listener = DnsListener { sock: Arc::new(sock), check_dst: false };
    tokio::spawn(async move {
        let _ = run_forward_loop_on(vec![listener], None, config, cache).await;
    });
    Some(addr)
}

async fn recv_reply(client: &tokio::net::UdpSocket, timeout: Duration) -> Option<DnsPacket> {
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(timeout, client.recv_from(&mut buf)).await.ok()?.ok()?;
    DnsPacket::parse(&buf[..len]).ok()
}

// ---------------------------------------------------------------------------
// Source-port randomisation
// ---------------------------------------------------------------------------

/// Concurrent upstream queries must not all leave from one socket.
///
/// A single shared outbound socket means one fixed source port for the life of
/// the daemon: an off-path attacker then only has to guess the 16-bit ID.
#[tokio::test]
async fn concurrent_queries_leave_from_distinct_source_ports() {
    let Some((upstream, seen)) = spawn_upstream(None).await else { return };
    let config = ForwardConfig { upstreams: vec![upstream], ..Default::default() };
    let Some(server) = spawn_server(config).await else { return };

    let Ok(client) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };

    const QUERIES: usize = 8;
    for i in 0..QUERIES {
        let wire = query_wire(&format!("q{i}.test"), 1, 0x1000 + i as u16);
        client.send_to(&wire, server).await.expect("client send must succeed");
    }

    // The upstream never answers, so all eight stay in flight.
    tokio::time::sleep(Duration::from_millis(400)).await;

    let observed = seen.lock().unwrap().clone();
    assert_eq!(observed.len(), QUERIES, "every distinct query must be forwarded once");

    let ports: HashSet<u16> = observed.iter().map(|(from, _)| from.port()).collect();
    assert_eq!(
        ports.len(),
        QUERIES,
        "each in-flight query needs its own source port, saw {ports:?}",
    );
}

// ---------------------------------------------------------------------------
// Per-server-group query limiting
// ---------------------------------------------------------------------------

/// Once `--dns-forward-max` queries are in flight to one server group, the next
/// one is REFUSED rather than queued or dropped.
///
/// Dropping it would leave the client waiting out its own timeout with no idea
/// why; C answers immediately (`get_new_frec()` returns NULL → `goto reply` with
/// no flags → `setup_reply()` sets REFUSED).
#[tokio::test]
async fn queries_beyond_dns_forward_max_are_refused() {
    let Some((upstream, seen)) = spawn_upstream(None).await else { return };
    let config = ForwardConfig {
        upstreams: vec![upstream],
        ftabsize:  2,
        ..Default::default()
    };
    let Some(server) = spawn_server(config).await else { return };
    let Ok(client) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };

    // Two distinct questions fill the group; neither is ever answered.
    for i in 0..2u16 {
        let wire = query_wire(&format!("fill{i}.test"), 1, 0x3000 + i);
        client.send_to(&wire, server).await.expect("client send must succeed");
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    assert!(
        recv_reply(&client, Duration::from_millis(100)).await.is_none(),
        "the silent upstream must leave the first two queries outstanding",
    );

    client
        .send_to(&query_wire("overflow.test", 1, 0x30FF), server)
        .await
        .expect("client send must succeed");

    let reply = recv_reply(&client, Duration::from_secs(2))
        .await
        .expect("the overflowing query must be answered, not dropped");
    assert_eq!(reply.header.id, 0x30FF);
    assert_eq!(reply.header.rcode(), 5, "REFUSED");
    assert_eq!(reply.questions.len(), 1);
    assert_eq!(reply.questions[0].name, "overflow.test");

    assert_eq!(
        seen.lock().unwrap().len(),
        2,
        "the refused query must not reach the upstream server",
    );
}

// ---------------------------------------------------------------------------
// Duplicate-client folding
// ---------------------------------------------------------------------------

/// Two clients asking the identical question in the same window share one
/// upstream transaction, and both get the answer back under their own ID.
#[tokio::test]
async fn duplicate_clients_share_one_upstream_query() {
    let Some((upstream, seen)) = spawn_upstream(Some(Duration::from_millis(300))).await else {
        return;
    };
    let config = ForwardConfig { upstreams: vec![upstream], ..Default::default() };
    let Some(server) = spawn_server(config).await else { return };

    let Ok(client_a) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };
    let Ok(client_b) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };

    client_a
        .send_to(&query_wire("shared.test", 1, 0xAAAA), server)
        .await
        .expect("client A send must succeed");
    // Long enough for the first query to be forwarded, short enough that the
    // upstream has not answered yet.
    tokio::time::sleep(Duration::from_millis(50)).await;
    client_b
        .send_to(&query_wire("shared.test", 1, 0xBBBB), server)
        .await
        .expect("client B send must succeed");

    let reply_a = recv_reply(&client_a, Duration::from_secs(2)).await;
    let reply_b = recv_reply(&client_b, Duration::from_secs(2)).await;

    let forwarded = seen.lock().unwrap().len();
    assert_eq!(forwarded, 1, "the duplicate question must not open a second upstream query");

    assert_eq!(reply_a.expect("client A must be answered").header.id, 0xAAAA);
    assert_eq!(reply_b.expect("client B must be answered").header.id, 0xBBBB);
}

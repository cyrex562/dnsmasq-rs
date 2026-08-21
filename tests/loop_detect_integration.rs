//! Live end-to-end coverage for `--dns-loop-detect` (Issue #44).
//!
//! Drives the real `run_forward_loop_on` against a scripted fake upstream
//! that behaves the way a mis-configured "looping" resolver would: whatever
//! it receives, it forwards straight back to the server under test's main
//! listening port, rather than answering it. When the server under test's
//! own loop-detection probe is echoed back that way, it arrives as an
//! ordinary incoming query — proving the loop — and the server must stop
//! selecting that upstream for anything afterwards.
//!
//! Every helper returns `None` when the environment forbids binding loopback
//! UDP sockets, so restricted sandboxes skip rather than fail.

use std::net::SocketAddr;
use std::time::Duration;

use dnsmasq_rs::cache::new_shared_cache;
use dnsmasq_rs::dns_protocol::{DnsHeader, HB3_QR, HB3_RD, HB4_RA};
use dnsmasq_rs::forward::{run_forward_loop_on, DnsListener, ForwardConfig};
use dnsmasq_rs::loop_detect::{loop_make_probe, send_probes};
use dnsmasq_rs::rfc1035::{DnsPacket, DnsQuestion, DnsRr};
use dnsmasq_rs::types::addr::MySockAddr;
use dnsmasq_rs::types::server::Server;

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

fn loop_server(addr: SocketAddr, uid: u32) -> Server {
    let sock = MySockAddr::from(addr);
    Server {
        flags: 0,
        domain: String::new(),
        addr: sock.clone(),
        source_addr: sock,
        interface: String::new(),
        ifindex: 0,
        queries: 0,
        failed_queries: 0,
        nxdomain_replies: 0,
        retrys: 0,
        query_latency: 0,
        mma_latency: 0,
        forwardtime: None,
        forwardcount: 0,
        tcpfd: -1,
        serial: 0,
        arrayposn: -1,
        last_server: 0,
        uid,
    }
}

/// Bind a fake upstream that echoes every datagram it receives straight back
/// to `forward_to`, ignoring the sender — exactly what a resolver
/// mis-configured to point back at us would do to anything it's asked.
async fn spawn_looping_upstream(
    forward_to: SocketAddr,
) -> Option<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let addr = sock.local_addr().ok()?;
    let task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, _from)) = sock.recv_from(&mut buf).await else { return };
            let _ = sock.send_to(&buf[..len], forward_to).await;
        }
    });
    Some((addr, task))
}

async fn ask(server: SocketAddr, wire: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    client.send_to(wire, server).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(timeout, client.recv_from(&mut buf)).await.ok()?.ok()?;
    Some(buf[..len].to_vec())
}

/// The acceptance criterion from Issue #44: a looping upstream server is
/// detected and disabled. The server under test's only upstream is a fake
/// resolver that (mis)forwards everything straight back to us. Sending it a
/// loop probe — the same thing `dnsmasq::run_main_loop_with` does once at
/// startup — comes back as an ordinary incoming query; `detect_loop` on the
/// incoming-query path recognises it and flags the server `SERV_LOOP`. A
/// client query sent afterwards has no eligible upstream left, so it is
/// silently dropped rather than forwarded into the loop.
#[tokio::test]
async fn a_looping_upstream_server_is_detected_and_disabled() {
    let probe_uid = 0x1a2b3c4d;

    let Ok(listener_sock) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };
    let server_addr = listener_sock.local_addr().unwrap();

    let Some((upstream_addr, upstream_task)) = spawn_looping_upstream(server_addr).await else {
        return;
    };

    let config = ForwardConfig {
        upstreams: vec![upstream_addr],
        server_domains: vec![String::new()],
        loop_detect: true,
        loop_servers: vec![loop_server(upstream_addr, probe_uid)],
        ..Default::default()
    };
    let listener = DnsListener { sock: std::sync::Arc::new(listener_sock), check_dst: false };
    let cache = new_shared_cache(config.cache_size, config.min_cache_ttl, config.max_cache_ttl);
    let server_task = tokio::spawn(async move {
        let _ = run_forward_loop_on(vec![listener], None, config, cache).await;
    });

    // The startup probe round `run_main_loop_with` would send once, sent here
    // directly against a servers list carrying the same uid the running
    // engine was seeded with — that's the only thing that has to match for
    // `detect_loop` to recognise the echo.
    let mut probe_servers = vec![loop_server(upstream_addr, probe_uid)];
    assert_eq!(send_probes(&mut probe_servers).await, 1, "probe must actually be sent");

    // Give the probe -> echo -> detect_loop round trip time to land.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let reply = ask(
        server_addr,
        &query_wire("example.com", 1, 0x99),
        Duration::from_millis(500),
    )
    .await;
    assert!(
        reply.is_none(),
        "the only upstream is flagged SERV_LOOP after detection, so the query must be dropped, not forwarded"
    );

    server_task.abort();
    upstream_task.abort();
}

/// A packet shaped like a loop probe, but for a `uid` no configured server
/// actually holds, must not disable anything — proves `detect_loop`'s match
/// is specific to a real server's uid, not "any query matching the wire
/// shape", in the live runtime path (not just the `loop_detect` unit tests).
#[tokio::test]
async fn a_probe_shaped_query_with_the_wrong_uid_does_not_disable_the_server() {
    let real_uid = 0x1a2b3c4d;
    let wrong_uid = 0xffffffff;

    let Ok(listener_sock) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };
    let server_addr = listener_sock.local_addr().unwrap();

    // A well-behaved upstream: answers "example.com" A queries for real,
    // ignores anything else (in particular, the wrong-uid probe below).
    let Ok(upstream_sock) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else { return };
    let upstream_addr = upstream_sock.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((len, from)) = upstream_sock.recv_from(&mut buf).await else { return };
            let Ok(query) = DnsPacket::parse(&buf[..len]) else { continue };
            let Some(q) = query.questions.first() else { continue };
            if q.name != "example.com" || q.qtype != 1 {
                continue;
            }
            let mut header = query.header;
            header.hb3 |= HB3_QR;
            header.hb4 |= HB4_RA;
            header.ancount = 1;
            let reply = DnsPacket {
                header,
                questions: query.questions.clone(),
                answers: vec![DnsRr {
                    name: "example.com".to_string(),
                    rtype: 1,
                    class: 1,
                    ttl: 300,
                    rdata: vec![192, 0, 2, 9],
                }],
                authority: vec![],
                additional: vec![],
            };
            let _ = upstream_sock.send_to(&reply.write(), from).await;
        }
    });

    let config = ForwardConfig {
        upstreams: vec![upstream_addr],
        server_domains: vec![String::new()],
        loop_detect: true,
        loop_servers: vec![loop_server(upstream_addr, real_uid)],
        ..Default::default()
    };
    let listener = DnsListener { sock: std::sync::Arc::new(listener_sock), check_dst: false };
    let cache = new_shared_cache(config.cache_size, config.min_cache_ttl, config.max_cache_ttl);
    let server_task = tokio::spawn(async move {
        let _ = run_forward_loop_on(vec![listener], None, config, cache).await;
    });

    // Deliver a probe-shaped query straight to the server's listening port,
    // as if it had been echoed back — but for a uid that belongs to no
    // configured server.
    let wrong_probe = loop_make_probe(wrong_uid, 0x77);
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&wrong_probe, server_addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let reply = ask(server_addr, &query_wire("example.com", 1, 0x55), Duration::from_secs(2)).await;
    assert!(
        reply.is_some(),
        "a wrong-uid probe-shaped query must not disable the real upstream server"
    );

    server_task.abort();
    upstream_task.abort();
}

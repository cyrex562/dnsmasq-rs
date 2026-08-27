//! Host-side reproduction of the `parity/fixtures/dns/basic` suite.
//!
//! `./parity/run-major.sh` compares this fixture against the real upstream
//! `dnsmasq` binary inside containers, which needs Docker.  This test drives
//! the same fixture config through the real pipeline — `parse_config_text` →
//! `apply_config` → `daemon_local_data` → `run_forward_loop` — over loopback,
//! with **no upstream servers configured**, and asserts the answer set upstream
//! produces for each of the eight query cases.
//!
//! The expectations were derived from `answer_request()` in upstream's
//! `src/rfc1035.c` (not vendored in this repo — see `NOTICE.md`):
//!
//! * config CNAMEs are followed before the type-specific lookups, so
//!   `alias.test A` yields CNAME + A;
//! * a matching `ptr-record` short-circuits the reverse-lookup else-if chain,
//!   so exactly one PTR is returned even though the address also has a
//!   `host-record`;
//! * MX/SRV additional-section glue is only emitted for targets present in the
//!   cache, and this fixture configures none, so the additional section is
//!   empty for every case.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use dnsmasq_rs::dns_protocol::{DnsHeader, HB3_RD};
use dnsmasq_rs::dnsmasq::{daemon_cache_size, daemon_local_data, init_daemon_with, run_main_loop};
use dnsmasq_rs::forward::{run_forward_loop, ForwardConfig};
use dnsmasq_rs::option::{apply_config, parse_config_text, resolve_config};
use dnsmasq_rs::rfc1035::{write_name, DnsPacket, DnsQuestion};
use dnsmasq_rs::types::daemon::Daemon;

const FIXTURE_CONF: &str = include_str!("../parity/fixtures/dns/basic/dnsmasq.conf");

fn encoded_name(name: &str) -> Vec<u8> {
    let mut buf = bytes::BytesMut::new();
    write_name(&mut buf, name);
    buf.to_vec()
}

/// Build the forwarding config the daemon would build for this fixture.
fn fixture_forward_config() -> ForwardConfig {
    let lines = parse_config_text(FIXTURE_CONF, "dnsmasq.conf").expect("fixture must parse");
    let mut daemon = Daemon::default();
    apply_config(&mut daemon, &lines).expect("fixture must apply");

    assert_eq!(daemon.local_ttl, 60, "fixture sets local-ttl=60");
    assert!(daemon.servers.is_empty(), "fixture configures no upstreams");

    ForwardConfig {
        upstreams:  Vec::new(),
        local:      daemon_local_data(&daemon),
        cache_size: daemon_cache_size(&daemon),
        ..Default::default()
    }
}

async fn spawn_fixture_server() -> Option<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let addr = sock.local_addr().ok()?;
    let config = fixture_forward_config();
    let handle = tokio::spawn(async move {
        let _ = run_forward_loop(Arc::new(sock), config).await;
    });
    Some((addr, handle))
}

async fn try_ask(server: SocketAddr, name: &str, qtype: u16) -> Option<DnsPacket> {
    let wire = DnsPacket {
        header: DnsHeader { id: 0x4242, hb3: HB3_RD, qdcount: 1, ..Default::default() },
        questions: vec![DnsQuestion { name: name.to_string(), qtype, qclass: 1 }],
        answers:    vec![],
        authority:  vec![],
        additional: vec![],
    }
    .write();

    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    client.send_to(&wire, server).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    Some(DnsPacket::parse(&buf[..len]).expect("reply must parse"))
}

async fn ask(server: SocketAddr, name: &str, qtype: u16) -> DnsPacket {
    try_ask(server, name, qtype).await.unwrap_or_else(|| {
        panic!("no reply for {name} type {qtype}: query was forwarded, not answered locally")
    })
}

/// One fixture case: query name, qtype, and the `(rtype, rdata)` pairs the
/// answer section must contain, in order.
type ExpectedCase = (&'static str, u16, Vec<(u16, Vec<u8>)>);

/// The eight cases from `parity/fixtures/dns/basic/queries.txt`.
fn expected_answers() -> Vec<ExpectedCase> {
    let host_a = vec![192, 0, 2, 10];
    let host_aaaa = "2001:db8::10".parse::<std::net::Ipv6Addr>().unwrap().octets().to_vec();

    let mut mx = vec![0x00, 0x0a]; // preference 10
    mx.extend_from_slice(&encoded_name("mail-sink.test"));

    let mut srv = vec![0x00, 0x0a, 0x00, 0x05, 0x13, 0xc4]; // prio 10, weight 5, port 5060
    srv.extend_from_slice(&encoded_name("sip.service.test"));

    vec![
        ("host.test", 1, vec![(1, host_a.clone())]),
        ("host.test", 28, vec![(28, host_aaaa)]),
        ("alias.test", 5, vec![(5, encoded_name("host.test"))]),
        ("alias.test", 1, vec![(5, encoded_name("host.test")), (1, host_a)]),
        ("txt.test", 16, vec![(16, b"\x0chello-parity".to_vec())]),
        ("mail.test", 15, vec![(15, mx)]),
        ("_sip._tcp.service.test", 33, vec![(33, srv)]),
        ("10.2.0.192.in-addr.arpa", 12, vec![(12, encoded_name("host.test"))]),
    ]
}

/// Ask the kernel for a free UDP port, then release it.  `run_main_loop` binds
/// `0.0.0.0:{daemon.port}` itself, so the port has to be chosen up front; the
/// caller retries on a lost race.
async fn free_port() -> Option<u16> {
    let probe = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    let port = probe.local_addr().ok()?.port();
    drop(probe);
    Some(port)
}

/// End-to-end through the real startup path: `parse_config_text` →
/// `resolve_config` → `into_daemon` → `init_daemon_with` → `run_main_loop`.
///
/// The other tests here build a `ForwardConfig` themselves, which leaves the
/// `Daemon`-to-`ForwardConfig` hand-off inside `run_main_loop` untested — and
/// that hand-off is the gap this change exists to close.  This test covers it
/// with no upstream servers configured, so an unanswered query means the local
/// data never reached the query loop.
#[tokio::test]
async fn run_main_loop_answers_host_record_with_no_upstream_configured() {
    let lines = parse_config_text(FIXTURE_CONF, "dnsmasq.conf").expect("fixture must parse");

    // Retry across ports: the bind is racy by construction, and a lost race
    // makes `run_main_loop` return `IoError` immediately rather than answer.
    for _ in 0..5 {
        let Some(port) = free_port().await else { return }; // sandbox forbids UDP: skip
        let mut daemon = resolve_config(&lines).expect("fixture must resolve").into_daemon();
        assert!(daemon.servers.is_empty(), "fixture configures no upstreams");
        daemon.port = port;

        let task = tokio::spawn(run_main_loop(init_daemon_with(daemon)));
        let server: SocketAddr = ([127, 0, 0, 1], port).into();
        let reply = try_ask(server, "host.test", 1).await;
        let bind_failed = task.is_finished();
        task.abort();

        if bind_failed {
            continue; // port was taken between probe and bind; try another
        }

        let reply = reply.expect("host-record query must be answered without any upstream");
        assert_eq!(reply.header.rcode(), 0);
        assert_eq!(reply.answers.len(), 1, "expected exactly one A record");
        assert_eq!(reply.answers[0].rtype, 1);
        assert_eq!(reply.answers[0].ttl, 60, "fixture sets local-ttl=60");
        assert_eq!(reply.answers[0].rdata, vec![192, 0, 2, 10]);
        return;
    }

    panic!("could not secure a free UDP port in 5 attempts");
}

#[tokio::test]
async fn dns_basic_fixture_answered_entirely_from_local_data() {
    let Some((server, task)) = spawn_fixture_server().await else { return };

    for (name, qtype, expected) in expected_answers() {
        let reply = ask(server, name, qtype).await;

        assert_eq!(reply.header.rcode(), 0, "{name}/{qtype}: rcode");
        assert!(!reply.header.is_tc(), "{name}/{qtype}: TC must be clear");
        assert!(reply.authority.is_empty(), "{name}/{qtype}: authority must be empty");
        assert!(reply.additional.is_empty(), "{name}/{qtype}: additional must be empty");
        assert_eq!(reply.questions.len(), 1, "{name}/{qtype}: question echoed");

        let got: Vec<(u16, Vec<u8>)> =
            reply.answers.iter().map(|r| (r.rtype, r.rdata.clone())).collect();
        assert_eq!(got, expected, "{name}/{qtype}: answer section");

        for rr in &reply.answers {
            assert_eq!(rr.class, 1, "{name}/{qtype}: answers must be class IN");
            assert_eq!(rr.ttl, 60, "{name}/{qtype}: answers use local-ttl");
        }
    }

    task.abort();
}

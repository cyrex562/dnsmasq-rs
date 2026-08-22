//! Integration coverage for local-data answering in the live query path.
//!
//! Upstream `dnsmasq` calls `answer_request()` from `udp_request()` *before*
//! deciding to forward (`forward.c`); a query satisfied from local config data
//! never reaches an upstream server.  These tests drive the real
//! `run_forward_loop` over loopback with **no upstreams configured** and assert
//! the same ordering.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dnsmasq_rs::dns_protocol::{DnsHeader, HB3_RD};
use dnsmasq_rs::forward::{run_forward_loop, ForwardConfig, LocalData};
use dnsmasq_rs::rfc1035::{DnsPacket, DnsQuestion};
use dnsmasq_rs::types::dns_records::{Cname, HostRecord};

/// Build a `LocalData` snapshot mirroring the `parity/fixtures/dns/basic`
/// host-record and cname directives.
fn fixture_local_data() -> LocalData {
    LocalData {
        local_ttl: 60,
        host_records: vec![HostRecord {
            ttl:   60,
            flags: 0,
            names: vec!["host.test".to_string()],
            addr4: Some(Ipv4Addr::new(192, 0, 2, 10)),
            addr6: Some("2001:db8::10".parse::<Ipv6Addr>().unwrap()),
        }],
        cnames: vec![Cname {
            ttl:    60,
            flag:   0,
            alias:  "alias.test".to_string(),
            target: "host.test".to_string(),
        }],
        ..Default::default()
    }
}

fn query_wire(name: &str, qtype: u16, id: u16) -> Vec<u8> {
    DnsPacket {
        header: DnsHeader { id, hb3: HB3_RD, qdcount: 1, ..Default::default() },
        questions: vec![DnsQuestion { name: name.to_string(), qtype, qclass: 1 }],
        answers:    vec![],
        authority:  vec![],
        additional: vec![],
    }
    .write()
    .to_vec()
}

/// Spawn `run_forward_loop` on a loopback socket with no upstreams and the
/// fixture's local data.  Returns the server address the client should query.
///
/// Returns `None` when the environment forbids binding loopback UDP sockets, so
/// restricted sandboxes skip rather than fail.
async fn spawn_local_only_server() -> Option<(SocketAddr, tokio::task::JoinHandle<()>)> {
    let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let addr = sock.local_addr().ok()?;
    let config = ForwardConfig {
        upstreams: Vec::new(), // deliberately empty: nothing to forward to
        local: fixture_local_data(),
        ..Default::default()
    };
    let handle = tokio::spawn(async move {
        let _ = run_forward_loop(Arc::new(sock), config).await;
    });
    Some((addr, handle))
}

async fn ask(server: SocketAddr, wire: &[u8]) -> Option<DnsPacket> {
    let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    client.send_to(wire, server).await.ok()?;
    let mut buf = vec![0u8; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
        .await
        .ok()?
        .ok()?;
    DnsPacket::parse(&buf[..len]).ok()
}

#[tokio::test]
async fn host_record_answered_with_no_upstream_configured() {
    let Some((server, task)) = spawn_local_only_server().await else { return };

    let reply = ask(server, &query_wire("host.test", 1, 0x4242))
        .await
        .expect("host-record query must be answered locally, not forwarded");

    assert_eq!(reply.header.id, 0x4242);
    assert_eq!(reply.header.rcode(), 0);
    assert_eq!(reply.answers.len(), 1, "expected exactly one A record");
    let a = &reply.answers[0];
    assert_eq!(a.rtype, 1);
    assert_eq!(a.class, 1);
    assert_eq!(a.rdata, vec![192, 0, 2, 10]);

    task.abort();
}

#[tokio::test]
async fn cname_chain_answered_with_no_upstream_configured() {
    let Some((server, task)) = spawn_local_only_server().await else { return };

    let reply = ask(server, &query_wire("alias.test", 1, 0x1111))
        .await
        .expect("cname alias query must be answered locally");

    assert_eq!(reply.header.rcode(), 0);
    let types: Vec<u16> = reply.answers.iter().map(|r| r.rtype).collect();
    assert_eq!(types, vec![5, 1], "expected CNAME followed by A");
    assert_eq!(reply.answers[1].rdata, vec![192, 0, 2, 10]);

    task.abort();
}

#[tokio::test]
async fn unknown_name_is_not_answered_locally() {
    let Some((server, task)) = spawn_local_only_server().await else { return };

    // Not in local data: upstream would forward this. With no upstream
    // configured there is nowhere to send it — C's `lookup_domain()` fails to
    // find any server-array entry at all, sets `flags = 0`/`ede =
    // EDE_NOT_READY`, and `setup_reply()`'s catch-all "nowhere to forward to"
    // branch answers REFUSED rather than staying silent (`forward.c:344-350`,
    // `rfc1035.c:1291-1298`). This also proves local answering did not
    // fabricate a positive reply: the rcode is REFUSED, not NOERROR.
    let reply = ask(server, &query_wire("not-local.test", 1, 0x2222))
        .await
        .expect("a query with nowhere to forward to must still get a REFUSED reply");
    assert_eq!(reply.header.id, 0x2222);
    assert_eq!(reply.header.rcode(), 5, "RCODE REFUSED");

    task.abort();
}

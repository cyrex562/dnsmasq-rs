//! Integration coverage for `--interface` / `--except-interface` /
//! `--listen-address` / `--bind-interfaces` / `--bind-dynamic`.
//!
//! Upstream applies these in two places (`dnsmasq.c:378-409`):
//!
//! * `--bind-interfaces` / `--bind-dynamic` bind one socket per allowed
//!   interface address, so the access control is the bind itself.
//! * the default wildcard mode binds `0.0.0.0`/`::` and re-checks the arrival
//!   interface of every datagram against `iface_check()` (`forward.c:1771-1780`).
//!
//! Both have to hold for a config that names a single interface or address to
//! actually be honoured.  Everything here that needs real sockets is gated so a
//! restricted sandbox skips rather than fails.

use std::net::SocketAddr;
use std::time::Duration;

use dnsmasq_rs::dnsmasq::{bind_listeners, init_daemon_with, run_main_loop};
use dnsmasq_rs::option::{parse_config_text, resolve_config};
use dnsmasq_rs::types::daemon::Daemon;

/// Build a `Daemon` from config text, as the real startup path does.
fn daemon_from(text: &str) -> Daemon {
    let lines = parse_config_text(text, "test.conf").expect("config must parse");
    resolve_config(&lines).expect("config must resolve").into_daemon()
}

/// Ask the kernel for a free UDP port, then release it.
async fn free_port() -> Option<u16> {
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.ok()?;
    let port = probe.local_addr().ok()?.port();
    drop(probe);
    Some(port)
}

/// A minimal A query for `host.test`, id 0x1234.
fn query_host_test() -> Vec<u8> {
    let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
    for label in ["host", "test"] {
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.extend_from_slice(&[0, 0, 1, 0, 1]); // root, A, IN
    q
}

/// Send one query to `server` and wait briefly for a reply.
///
/// `Ok(None)` means "the daemon did not answer", which is the interesting
/// outcome here.  `Err(())` means the sandbox would not let us try at all.
async fn probe(server: SocketAddr) -> Result<Option<Vec<u8>>, ()> {
    let bind = if server.is_ipv4() { "127.0.0.1:0" } else { "[::1]:0" };
    let sock = tokio::net::UdpSocket::bind(bind).await.map_err(|_| ())?;
    sock.send_to(&query_host_test(), server).await.map_err(|_| ())?;
    let mut buf = vec![0u8; 512];
    match tokio::time::timeout(Duration::from_millis(400), sock.recv_from(&mut buf)).await {
        Ok(Ok((len, _))) => Ok(Some(buf[..len].to_vec())),
        Ok(Err(_)) => Ok(None),
        Err(_) => Ok(None), // timed out — no answer
    }
}

/// Config body shared by the runtime tests: one local host record and no
/// upstreams, so an answer proves the query reached the query loop.
const LOCAL_DATA: &str = "host-record=host.test,192.0.2.10\nlocal-ttl=60\nno-resolv\n";

/// Start the daemon on a free port with `extra` appended to the base config.
/// Returns the port, or `None` when the environment will not let us bind.
async fn spawn(extra: &str) -> Option<(u16, tokio::task::JoinHandle<()>)> {
    for _ in 0..5 {
        let port = free_port().await?;
        let mut daemon = daemon_from(&format!("{LOCAL_DATA}{extra}"));
        daemon.port = port;
        let handle = tokio::spawn(async move {
            let _ = run_main_loop(init_daemon_with(daemon), None).await;
        });
        // Give the loop a moment to bind before probing.
        tokio::time::sleep(Duration::from_millis(120)).await;
        if handle.is_finished() {
            continue; // lost the port race, or bind refused
        }
        return Some((port, handle));
    }
    None
}

// ── --listen-address ─────────────────────────────────────────────────────────

/// `--listen-address=127.0.0.1` must answer on 127.0.0.1 and nowhere else.
///
/// 127.0.0.0/8 is entirely local on Linux, so 127.0.0.2 reaches a daemon bound
/// to the wildcard address while *not* matching the configured listen address —
/// exactly the case the issue describes.
#[tokio::test]
async fn listen_address_does_not_answer_on_other_addresses() {
    let Some((port, task)) = spawn("listen-address=127.0.0.1\n").await else { return };

    let allowed: SocketAddr = ([127, 0, 0, 1], port).into();
    let other: SocketAddr = ([127, 0, 0, 2], port).into();

    let on_allowed = probe(allowed).await;
    let on_other = probe(other).await;
    task.abort();

    let (Ok(Some(_)), Ok(other_reply)) = (on_allowed, on_other) else {
        return; // no usable loopback aliasing here — skip rather than fail
    };
    assert!(
        other_reply.is_none(),
        "query to {other} was answered even though --listen-address=127.0.0.1 \
         restricts the daemon to 127.0.0.1"
    );
}

// ── --interface / --except-interface ─────────────────────────────────────────

/// `--interface=lo` includes the loopback interface: queries are answered.
#[tokio::test]
async fn interface_lo_includes_loopback() {
    let Some((port, task)) = spawn("interface=lo\n").await else { return };
    let reply = probe(([127, 0, 0, 1], port).into()).await;
    task.abort();

    let Ok(reply) = reply else { return };
    assert!(
        reply.is_some(),
        "--interface=lo must keep answering on the loopback interface"
    );
}

/// `--except-interface=lo` excludes it again, even when `--interface=lo` also
/// names it (upstream `network.c:150-152`: the except list wins unless the
/// destination address itself was an explicit `--listen-address`).
#[tokio::test]
async fn except_interface_lo_excludes_loopback() {
    let Some((port, task)) = spawn("interface=lo\nexcept-interface=lo\n").await else { return };
    let reply = probe(([127, 0, 0, 1], port).into()).await;
    task.abort();

    let Ok(reply) = reply else { return };
    assert!(
        reply.is_none(),
        "--except-interface=lo must stop the daemon answering on loopback"
    );
}

/// Restricting the interface set never drops loopback: upstream adds any
/// loopback interface to `if_names` during enumeration (`network.c:500-519`),
/// so `--interface=<something else>` still answers on 127.0.0.1.
///
/// This is the rule that keeps a `--interface=eth0` box able to resolve names
/// for itself, and it is easy to lose when wiring the filter up.
#[tokio::test]
async fn restricted_interface_set_still_serves_loopback() {
    let Some((port, task)) = spawn("interface=nosuchif0\n").await else { return };
    let reply = probe(([127, 0, 0, 1], port).into()).await;
    task.abort();

    let Ok(reply) = reply else { return };
    assert!(
        reply.is_some(),
        "loopback must stay in a restricted --interface set"
    );
}

/// `--local-service=host` is upstream's "emulate `--interface=lo`
/// `--bind-interfaces`" shorthand (`option.c:6310-6315`): it pushes a NULL-named
/// `iname` and sets `OPT_NOWILD`, so the daemon binds loopback and nothing else.
#[tokio::test]
async fn local_service_host_binds_loopback_only() {
    let Some(port) = free_port().await else { return };
    let mut daemon = daemon_from("local-service=host\n");
    daemon.port = port;

    let Ok(listeners) = bind_listeners(&daemon) else { return };
    let addrs = listeners.dns_addrs();
    assert!(!addrs.is_empty(), "loopback must still be bound");
    for addr in &addrs {
        assert!(
            addr.ip().is_loopback(),
            "--local-service=host bound a non-loopback address: {addr}"
        );
    }
}

// ── bind mode dispatch (no sockets needed) ───────────────────────────────────

/// `--bind-interfaces` with an unmatched `--interface` is fatal upstream
/// (`dnsmasq.c:396-398`, "unknown interface %s").
#[test]
fn bind_interfaces_rejects_unknown_interface() {
    let mut daemon = daemon_from("bind-interfaces\ninterface=nosuchif0\n");
    daemon.port = 0;
    let err = bind_listeners(&daemon).expect_err("unknown interface must fail startup");
    let msg = err.to_string();
    assert!(
        msg.contains("nosuchif0"),
        "error should name the unknown interface, got: {msg}"
    );
}

/// `--bind-dynamic` tolerates the same config, because interfaces may appear
/// later (`dnsmasq.c:394-398` only dies when `OPT_CLEVERBIND` is clear).
#[test]
fn bind_dynamic_tolerates_unknown_interface() {
    let mut daemon = daemon_from("bind-dynamic\ninterface=nosuchif0\n");
    daemon.port = 0;
    assert!(
        bind_listeners(&daemon).is_ok(),
        "--bind-dynamic must not die on an interface that is not up yet"
    );
}

/// The two bind modes are mutually exclusive (`dnsmasq.c:378-379`).
#[test]
fn bind_interfaces_and_bind_dynamic_conflict() {
    let mut daemon = daemon_from("bind-interfaces\nbind-dynamic\n");
    daemon.port = 0;
    let err = bind_listeners(&daemon).expect_err("the two bind modes must conflict");
    let msg = err.to_string();
    assert!(
        msg.contains("bind-interfaces") && msg.contains("bind-dynamic"),
        "error should name both options, got: {msg}"
    );
}

/// `--bind-interfaces --interface=lo` binds the loopback address itself rather
/// than the wildcard address.
#[tokio::test]
async fn bind_interfaces_binds_loopback_address_not_wildcard() {
    let Some(port) = free_port().await else { return };
    let mut daemon = daemon_from("bind-interfaces\ninterface=lo\n");
    daemon.port = port;

    let Ok(listeners) = bind_listeners(&daemon) else { return }; // restricted env
    let addrs = listeners.dns_addrs();
    assert!(!addrs.is_empty(), "at least the loopback address must be bound");
    for addr in &addrs {
        assert!(
            addr.ip().is_loopback(),
            "--interface=lo bound a non-loopback address: {addr}"
        );
        assert_eq!(addr.port(), port);
    }
}

/// The default (no bind flag) mode uses the wildcard listeners upstream does.
#[tokio::test]
async fn default_mode_binds_wildcard_listeners() {
    let Some(port) = free_port().await else { return };
    let mut daemon = daemon_from("listen-address=127.0.0.1\n");
    daemon.port = port;

    let Ok(listeners) = bind_listeners(&daemon) else { return };
    let addrs = listeners.dns_addrs();
    assert!(
        addrs.iter().any(|a| a.ip().is_unspecified()),
        "default mode should bind the wildcard address, got {addrs:?}"
    );
}

/// `--listen-address` in bound mode binds exactly that address, even when no
/// interface carries it (upstream `network.c:1219-1233`).
#[tokio::test]
async fn bind_interfaces_binds_explicit_listen_address() {
    let Some(port) = free_port().await else { return };
    let mut daemon = daemon_from("bind-interfaces\nlisten-address=127.0.0.1\n");
    daemon.port = port;

    let Ok(listeners) = bind_listeners(&daemon) else { return };
    let addrs = listeners.dns_addrs();
    assert!(
        addrs.contains(&SocketAddr::from(([127, 0, 0, 1], port))),
        "expected 127.0.0.1:{port} to be bound, got {addrs:?}"
    );
    assert!(
        !addrs.iter().any(|a| a.ip().is_unspecified()),
        "bound mode must not fall back to the wildcard address: {addrs:?}"
    );
}

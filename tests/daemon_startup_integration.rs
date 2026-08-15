//! Integration coverage for the process startup sequence driven by
//! `src/main.rs`, mirroring `dnsmasq.c:610-820`:
//!
//! ```text
//! chdir("/") → fork/setsid/fork → write pidfile → stdio to /dev/null → drop privileges
//! ```
//!
//! Everything here spawns the real binary as a subprocess: `fork()`,
//! `setsid()`, `setuid()` and friends cannot be exercised in-process without
//! wrecking the test harness.
//!
//! Upstream flag semantics (option.c:428,456) that these tests pin down:
//! - `-d` / `--no-daemon`  → `OPT_DEBUG`: no fork, **no pidfile**, no privilege drop.
//! - `-k` / `--keep-in-foreground` → `OPT_NO_FORK`: no fork, but pidfile and
//!   privilege drop still happen.
//! - neither → double-fork into the background.

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use dnsmasq_rs::dns_protocol::{DnsHeader, HB3_RD};
use dnsmasq_rs::rfc1035::{DnsPacket, DnsQuestion};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_dnsmasq-rs")
}

/// Grab a port the kernel just handed out, then release it.  Racy in
/// principle, but the window is small and the alternative (a fixed port) is
/// worse in a parallel test runner.
fn free_udp_port() -> u16 {
    let sock = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral port");
    sock.local_addr().expect("local_addr").port()
}

/// Wait for `child` to exit, failing the test rather than hanging forever.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> std::process::ExitStatus {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(status) => return status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("process did not exit within {timeout:?}");
            }
            None => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// Poll for `path` to appear and parse as a pid.
fn wait_for_pid_file(path: &std::path::Path, timeout: Duration) -> u32 {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(text) = std::fs::read_to_string(path) {
            if let Ok(pid) = text.trim().parse::<u32>() {
                return pid;
            }
        }
        if Instant::now() >= deadline {
            panic!("pid file {} never appeared", path.display());
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn process_alive(pid: u32) -> bool {
    nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None).is_ok()
}

fn terminate(pid: u32) {
    let _ = nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pid as i32),
        nix::sys::signal::Signal::SIGTERM,
    );
}

fn session_of(pid: u32) -> nix::unistd::Pid {
    nix::unistd::getsid(Some(nix::unistd::Pid::from_raw(pid as i32))).expect("getsid")
}

/// A config file with one `host-record`, so a detached daemon can be proven to
/// still answer queries.
fn write_conf(dir: &std::path::Path, port: u16) -> std::path::PathBuf {
    let path = dir.join("dnsmasq.conf");
    let mut f = std::fs::File::create(&path).expect("create conf");
    writeln!(f, "no-resolv\nno-hosts\nport={port}\nlocal-ttl=60").unwrap();
    writeln!(f, "host-record=host.test,192.0.2.10,60").unwrap();
    path
}

/// Send an A query for `host.test` and return the parsed reply, if any.
fn ask_host_test(port: u16) -> Option<DnsPacket> {
    let wire = DnsPacket {
        header: DnsHeader { id: 0x4242, hb3: HB3_RD, qdcount: 1, ..Default::default() },
        questions: vec![DnsQuestion { name: "host.test".into(), qtype: 1, qclass: 1 }],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
    .write()
    .to_vec();

    let client = std::net::UdpSocket::bind("127.0.0.1:0").ok()?;
    client.set_read_timeout(Some(Duration::from_millis(500))).ok()?;
    let server = format!("127.0.0.1:{port}");

    // The daemon binds its socket after we are released, so retry briefly.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        client.send_to(&wire, &server).ok()?;
        let mut buf = vec![0u8; 4096];
        if let Ok((len, _)) = client.recv_from(&mut buf) {
            return DnsPacket::parse(&buf[..len]).ok();
        }
        if Instant::now() >= deadline {
            return None;
        }
    }
}

// ── default: fork into the background ────────────────────────────────────────

#[test]
fn without_no_daemon_the_process_detaches_and_writes_its_pid() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_path = dir.path().join("dnsmasq.pid");
    let port = free_udp_port();
    let conf = write_conf(dir.path(), port);

    let mut child = Command::new(bin())
        .args([
            "--conf-file",
            conf.to_str().unwrap(),
            "--pid-file",
            pid_path.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dnsmasq-rs");

    // The invoking process is released only once startup has finished, so the
    // pid file must already be there (dnsmasq.c:625-641 — the err_pipe read).
    let status = wait_with_timeout(&mut child, Duration::from_secs(10));
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).ok();
    assert!(status.success(), "foreground process exited with {status:?}: {stderr}");

    let daemon_pid = std::fs::read_to_string(&pid_path)
        .unwrap_or_else(|e| panic!("pid file not written by the time the parent exited: {e}"))
        .trim()
        .parse::<u32>()
        .expect("pid file holds a pid");

    assert_ne!(daemon_pid, child.id(), "pid file holds the forked daemon's pid, not the parent's");
    assert!(process_alive(daemon_pid), "the daemon should still be running");

    // Detached: the daemon leads its own session, not ours.
    assert_ne!(
        session_of(daemon_pid),
        session_of(std::process::id()),
        "daemon should have called setsid()"
    );

    // ...and it is a working daemon, not just a surviving process: chdir("/"),
    // the /dev/null stdio and the (no-op, unprivileged) privilege drop must not
    // have broken the query path.
    let reply = ask_host_test(port).expect("the detached daemon should answer queries");
    assert_eq!(reply.header.rcode(), 0);
    assert_eq!(reply.answers.len(), 1, "expected the configured host-record");
    assert_eq!(reply.answers[0].rdata, vec![192, 0, 2, 10]);

    terminate(daemon_pid);
}

// ── -d / --no-daemon: debug mode ─────────────────────────────────────────────

#[test]
fn no_daemon_stays_in_the_foreground_and_skips_the_pid_file() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_path = dir.path().join("dnsmasq.pid");
    let port = free_udp_port();

    let mut child = Command::new(bin())
        .args([
            "--no-daemon",
            "--port",
            &port.to_string(),
            "--pid-file",
            pid_path.to_str().unwrap(),
            "--no-resolv",
            "--no-hosts",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dnsmasq-rs");

    std::thread::sleep(Duration::from_millis(500));
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "--no-daemon must not fork; the spawned process is the daemon"
    );
    // Debug mode never writes a pidfile (the block is inside `if (!OPT_DEBUG)`).
    assert!(!pid_path.exists(), "--no-daemon (debug mode) must not write a pid file");

    let _ = child.kill();
    let _ = child.wait();
}

// ── -k / --keep-in-foreground ────────────────────────────────────────────────

#[test]
fn keep_in_foreground_writes_the_pid_file_without_forking() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_path = dir.path().join("dnsmasq.pid");
    let port = free_udp_port();

    let mut child = Command::new(bin())
        .args([
            "--keep-in-foreground",
            "--port",
            &port.to_string(),
            "--pid-file",
            pid_path.to_str().unwrap(),
            "--no-resolv",
            "--no-hosts",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dnsmasq-rs");

    let pid = wait_for_pid_file(&pid_path, Duration::from_secs(10));
    assert_eq!(pid, child.id(), "-k does not fork, so the pid is our direct child's");
    assert!(child.try_wait().expect("try_wait").is_none(), "-k must stay in the foreground");

    let _ = child.kill();
    let _ = child.wait();
}

// ── the default pid file must not be fatal when unprivileged ─────────────────

/// `pid-file=` defaults to `RUNFILE` (option.c:5977), which an ordinary user
/// cannot write.  Upstream "silently ignores failure to write the pid-file"
/// when it was not started as root (dnsmasq.c:679-683), and so must we — a
/// hard failure here would break every unprivileged run.
#[test]
fn the_default_pid_file_does_not_stop_an_unprivileged_start() {
    if nix::unistd::getuid().is_root() {
        // Deliberately not run as root: it would write the machine's real
        // /var/run/dnsmasq.pid and could stomp on a running dnsmasq.
        eprintln!("skipping: would write the real /var/run/dnsmasq.pid");
        return;
    }

    let dir = tempfile::tempdir().expect("tempdir");
    let port = free_udp_port();
    let conf = write_conf(dir.path(), port);

    let mut child = Command::new(bin())
        .args(["--keep-in-foreground", "--conf-file", conf.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dnsmasq-rs");

    let reply = ask_host_test(port)
        .expect("an unwritable default pid file must not stop the daemon serving");
    assert_eq!(reply.answers.len(), 1, "expected the configured host-record");
    assert!(
        child.try_wait().expect("try_wait").is_none(),
        "the daemon should still be running"
    );

    let _ = child.kill();
    let _ = child.wait();
}

// ── log-facility survives the /dev/null redirect ─────────────────────────────

/// Upstream calls `log_start()` (dnsmasq.c:717) *before* pointing stdio at
/// `/dev/null`, precisely so that a daemon which no longer has a terminal still
/// has somewhere to talk.  Without that, `-k` and the forking default are both
/// silent and `log-facility=<file>` is a no-op — which the porting rules forbid.
#[test]
fn log_facility_captures_output_after_the_stdio_redirect() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pid_path = dir.path().join("dnsmasq.pid");
    let log_path = dir.path().join("dnsmasq.log");
    let port = free_udp_port();

    let mut child = Command::new(bin())
        .args([
            "--keep-in-foreground",
            "--port",
            &port.to_string(),
            "--pid-file",
            pid_path.to_str().unwrap(),
            "--log-facility",
            log_path.to_str().unwrap(),
            "--no-resolv",
            "--no-hosts",
        ])
        // Both are /dev/null inside the daemon anyway under -k; null them here
        // too so a regression cannot pass by leaking onto the test's stderr.
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dnsmasq-rs");

    wait_for_pid_file(&pid_path, Duration::from_secs(10));

    // Two records, on purpose.  "starting on port" is emitted before the
    // redirect and proves `log-facility` is wired up at all; "listening for DNS
    // queries" comes from inside the tokio runtime, i.e. after stdio has become
    // /dev/null and after the privilege drop, and is the one that proves the
    // sink actually survives daemonization.
    let deadline = Instant::now() + Duration::from_secs(10);
    let log = loop {
        let text = std::fs::read_to_string(&log_path).unwrap_or_default();
        if text.contains("listening for DNS queries") {
            break text;
        }
        if Instant::now() >= deadline {
            panic!("log-facility file never received the daemon's output, got: {text:?}");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    assert!(
        log.contains("starting on port"),
        "the pre-fork startup banner should be in the log too, got: {log}"
    );
    assert!(
        log.contains(&port.to_string()),
        "the log lines should name the port the daemon bound, got: {log}"
    );

    let _ = child.kill();
    let _ = child.wait();
}

// ── the parity harness must not be daemonized out from under itself ──────────

/// `parity/docker/rust.Dockerfile` makes the binary the container's PID 1, so
/// the default double-fork would exit PID 1 the moment the daemon signalled
/// readiness and Docker would tear the container down.  The `upstream` service
/// already passes `-k` for exactly this reason.
///
/// Checked here rather than in a container run because the parity lane needs
/// Docker and this invariant does not: if it ever breaks, the failure mode is a
/// parity suite that reports "candidate unavailable" rather than a test failure.
#[test]
fn parity_compose_keeps_the_candidate_in_the_foreground() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("parity/compose.major.yaml");
    let text = std::fs::read_to_string(&path).expect("read parity/compose.major.yaml");

    let rust_service = text
        .split_once("\n  rust:")
        .expect("compose file should define a `rust` service")
        .1;
    // Only the `rust:` service body — it is the last one in the file today, but
    // stop at the next top-level service key if that changes.
    let rust_service = rust_service
        .split("\n  ")
        .take_while(|chunk| !chunk.starts_with("upstream:"))
        .collect::<Vec<_>>()
        .join("\n  ");

    assert!(
        rust_service.lines().any(|l| l.trim() == "- -k" || l.trim() == "- --keep-in-foreground"),
        "the parity candidate must run with -k or it forks and kills its own container:\n{rust_service}"
    );
}

/// An unopenable `log-facility` is fatal and says so on the terminal.  It has
/// to be caught here, before the fork: upstream's `log_start` failure path
/// (log.c) can only `send_event(EVENT_LOG_ERR)` and `_exit`, because by then
/// the terminal is gone.
#[test]
fn an_unopenable_log_facility_is_a_fatal_startup_error() {
    let port = free_udp_port();

    let mut child = Command::new(bin())
        .args([
            "--no-daemon",
            "--port",
            &port.to_string(),
            "--log-facility",
            "/proc/dnsmasq-rs-no-such-dir/dnsmasq.log",
            "--no-resolv",
            "--no-hosts",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dnsmasq-rs");

    let status = wait_with_timeout(&mut child, Duration::from_secs(10));
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).ok();

    assert!(!status.success(), "an unopenable log file must not start the daemon");
    assert!(
        stderr.contains("failed to open log file"),
        "expected a log-file diagnostic, got: {stderr}"
    );
}

// ── user/group resolution ────────────────────────────────────────────────────

#[test]
fn unknown_user_is_a_fatal_startup_error() {
    let port = free_udp_port();
    // Deliberately not `Command::output()`: it waits forever, so a regression
    // that turns `--user` back into a no-op would hang the suite instead of
    // failing it.
    let mut child = Command::new(bin())
        .args([
            "--no-daemon",
            "--port",
            &port.to_string(),
            "--user",
            "dnsmasq-rs-definitely-no-such-user",
            "--no-resolv",
            "--no-hosts",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn dnsmasq-rs");

    let status = wait_with_timeout(&mut child, Duration::from_secs(10));
    let mut stderr = String::new();
    child.stderr.take().unwrap().read_to_string(&mut stderr).ok();

    assert!(!status.success(), "an unknown --user must not start the daemon");
    assert!(
        stderr.contains("unknown user or group"),
        "expected an 'unknown user or group' diagnostic, got: {stderr}"
    );
}

// ── privilege drop (needs root) ──────────────────────────────────────────────

/// Parse a `/proc/<pid>/status` line such as `Uid:\t0\t0\t0\t0`.
fn proc_status_field(pid: u32, key: &str) -> Vec<u32> {
    let text = std::fs::read_to_string(format!("/proc/{pid}/status")).expect("read proc status");
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            return rest
                .split_whitespace()
                .filter_map(|f| f.parse::<u32>().ok())
                .collect();
        }
    }
    panic!("no {key} line in /proc/{pid}/status");
}

#[test]
fn user_and_group_change_the_running_ids_and_clear_supplementary_groups() {
    if !nix::unistd::getuid().is_root() {
        eprintln!("skipping: privilege drop needs root");
        return;
    }
    let Ok(Some(target)) = nix::unistd::User::from_name("nobody") else {
        eprintln!("skipping: no 'nobody' user on this system");
        return;
    };
    let group = match ["nogroup", "nobody"]
        .into_iter()
        .find_map(|name| nix::unistd::Group::from_name(name).ok().flatten())
    {
        Some(g) => g,
        None => {
            eprintln!("skipping: no 'nogroup'/'nobody' group on this system");
            return;
        }
    };

    let dir = tempfile::tempdir().expect("tempdir");
    let pid_path = dir.path().join("dnsmasq.pid");
    let port = free_udp_port();

    let mut child = Command::new(bin())
        .args([
            "--keep-in-foreground",
            "--port",
            &port.to_string(),
            "--pid-file",
            pid_path.to_str().unwrap(),
            "--user",
            "nobody",
            "--group",
            group.name.as_str(),
            "--no-resolv",
            "--no-hosts",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn dnsmasq-rs");

    let pid = wait_for_pid_file(&pid_path, Duration::from_secs(10));

    let uids = proc_status_field(pid, "Uid:");
    let gids = proc_status_field(pid, "Gid:");
    assert!(
        uids.iter().all(|u| *u == target.uid.as_raw()),
        "real/effective/saved uid should all be {}, got {uids:?}",
        target.uid
    );
    assert!(
        gids.iter().all(|g| *g == group.gid.as_raw()),
        "real/effective/saved gid should all be {}, got {gids:?}",
        group.gid
    );

    // dnsmasq.c:752 — setgroups(0, &dummy) strips every supplementary group.
    let groups = proc_status_field(pid, "Groups:");
    assert!(groups.is_empty(), "supplementary groups should be cleared, got {groups:?}");

    // The pid file is chowned to the target user while still root
    // (dnsmasq.c:697) so the daemon's own directory stays consistent.
    let meta = std::fs::metadata(&pid_path).expect("stat pid file");
    use std::os::unix::fs::MetadataExt as _;
    assert_eq!(meta.uid(), target.uid.as_raw(), "pid file should be chowned to the run user");
    // `fchown(fd, ent_pw->pw_uid, ent_pw->pw_gid)` — the run user's *primary*
    // group, which need not be the `--group` the daemon itself runs under.
    assert_eq!(
        meta.gid(),
        target.gid.as_raw(),
        "pid file group should be the run user's primary group, not --group"
    );

    let _ = child.kill();
    let _ = child.wait();
}

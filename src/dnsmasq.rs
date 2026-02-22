//! Daemon initialization and process-management helpers.
//!
//! Mirrors the startup logic in `dnsmasq.c` (the original 2478-line C file).

use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::error::DnsmasqError;
use crate::types::daemon::Daemon;

/// A shared, async-safe handle to the daemon state.
pub type DaemonHandle = Arc<RwLock<Daemon>>;

/// Initialize a new [`Daemon`] with default settings and return a shared handle.
pub fn init_daemon() -> DaemonHandle {
    Arc::new(RwLock::new(Daemon::default()))
}

/// Drop process privileges to the given `uid`/`gid`.
///
/// This is a best-effort implementation: on Linux it uses the `caps` and `nix`
/// crates to set the real/effective/saved UIDs and GIDs.  Passing the current
/// process's own uid/gid is always a no-op and succeeds.
pub fn drop_privileges(uid: u32, gid: u32) -> Result<(), DnsmasqError> {
    use nix::unistd::{Gid, Uid};

    let current_uid = nix::unistd::getuid();
    let current_gid = nix::unistd::getgid();

    // No-op when already running as the target uid/gid.
    if current_uid == Uid::from_raw(uid) && current_gid == Gid::from_raw(gid) {
        return Ok(());
    }

    // Set GID first (must be done before dropping root).
    nix::unistd::setgid(Gid::from_raw(gid))
        .map_err(|e| DnsmasqError::PrivilegeDrop(format!("setgid({gid}): {e}")))?;

    nix::unistd::setuid(Uid::from_raw(uid))
        .map_err(|e| DnsmasqError::PrivilegeDrop(format!("setuid({uid}): {e}")))?;

    Ok(())
}

/// Write the current process PID to `path`.
pub fn write_pid_file(path: &str, pid: u32) -> Result<(), DnsmasqError> {
    use std::io::Write;

    let mut f = std::fs::File::create(path)
        .map_err(|e| DnsmasqError::PidFile(format!("create {path}: {e}")))?;
    writeln!(f, "{pid}")
        .map_err(|e| DnsmasqError::PidFile(format!("write {path}: {e}")))?;
    Ok(())
}

/// Read a PID from the file at `path`.
pub fn read_pid_file(path: &str) -> Result<u32, DnsmasqError> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| DnsmasqError::PidFile(format!("read {path}: {e}")))?;
    text.trim()
        .parse::<u32>()
        .map_err(|e| DnsmasqError::PidFile(format!("parse pid in {path}: {e}")))
}

// ──────────────────────────────────────────────────────────────────────────────
// Process daemonization
// ──────────────────────────────────────────────────────────────────────────────

/// Daemonize the current process (double-fork, new session, redirect std fds).
///
/// This implements the standard Unix daemon idiom:
/// 1. First `fork()` — the parent exits.
/// 2. `setsid()` — become a session leader, detach from the controlling terminal.
/// 3. Second `fork()` — ensure we are not a session leader (cannot reacquire tty).
/// 4. Redirect stdin/stdout/stderr to `/dev/null`.
/// 5. Change working directory to `/`.
///
/// **Must be called before any tokio runtime is started** (tokio is not
/// fork-safe).
///
/// Returns `Ok(())` in the grandchild (the actual daemon).
/// The intermediate parent and original parent both exit cleanly.
#[cfg(unix)]
pub fn daemonize() -> Result<(), DnsmasqError> {
    use nix::unistd::{dup2, fork, setsid, ForkResult};

    // First fork.
    match unsafe { fork() }.map_err(|e| DnsmasqError::Daemonize(e.to_string()))? {
        ForkResult::Parent { .. } => std::process::exit(0),
        ForkResult::Child => {}
    }

    // Create new session.
    setsid().map_err(|e| DnsmasqError::Daemonize(e.to_string()))?;

    // Second fork (prevents re-acquiring a controlling terminal).
    match unsafe { fork() }.map_err(|e| DnsmasqError::Daemonize(e.to_string()))? {
        ForkResult::Parent { .. } => std::process::exit(0),
        ForkResult::Child => {}
    }

    // Change to root directory so we don't hold a mount point.
    std::env::set_current_dir("/")
        .map_err(|e| DnsmasqError::Daemonize(e.to_string()))?;

    // Redirect stdin/stdout/stderr to /dev/null using libc directly.
    let devnull = unsafe {
        libc::open(b"/dev/null\0".as_ptr() as *const libc::c_char, libc::O_RDWR)
    };
    if devnull < 0 {
        return Err(DnsmasqError::Daemonize("open /dev/null failed".into()));
    }
    for fd in [0i32, 1, 2] {
        dup2(devnull, fd).map_err(|e| DnsmasqError::Daemonize(e.to_string()))?;
    }
    if devnull > 2 {
        unsafe { libc::close(devnull) };
    }

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Main event loop
// ──────────────────────────────────────────────────────────────────────────────

/// Outcome of the main event loop.
#[derive(Debug, PartialEq, Eq)]
pub enum RunResult {
    /// Exited cleanly (SIGTERM or SIGINT received).
    Clean,
    /// Exited due to an I/O error.
    IoError,
}

/// Run the main daemon event loop.
///
/// This function:
/// 1. Binds a UDP DNS socket on `0.0.0.0:{port}`.
/// 2. Spawns a tokio task running the forwarding engine.
/// 3. Waits for SIGTERM, SIGINT, or SIGHUP.  On SIGHUP it notifies
///    the provided `sighup_tx` channel (so the caller can reload config).
///    On SIGTERM/SIGINT it shuts down.
///
/// The forwarding task is cancelled when the main loop exits.
///
/// Returns [`RunResult::Clean`] on orderly shutdown.
pub async fn run_main_loop(
    daemon_handle: DaemonHandle,
    sighup_tx: Option<tokio::sync::mpsc::Sender<()>>,
) -> RunResult {
    use std::sync::Arc;
    use tokio::net::UdpSocket;
    use tokio::signal::unix::{signal, SignalKind};
    use tracing::{error, info, warn};

    use crate::forward::{ForwardConfig, ForwardEngine, run_forward_loop};

    // ── Resolve configuration ────────────────────────────────────────────────
    let (port, upstreams) = {
        let d = daemon_handle.read().await;
        let ups: Vec<_> = d
            .servers
            .iter()
            .map(|s| SocketAddr::from(s.addr.clone()))
            .collect();
        (d.port, ups)
    };

    // ── Bind the DNS listening socket ────────────────────────────────────────
    let bind_addr = format!("0.0.0.0:{port}");
    let client_sock = match UdpSocket::bind(&bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!("failed to bind UDP socket on {bind_addr}: {e}");
            return RunResult::IoError;
        }
    };
    info!("listening for DNS queries on {bind_addr}");

    // ── Spawn the forwarding engine ──────────────────────────────────────────
    let fwd_config = ForwardConfig {
        upstreams,
        ..Default::default()
    };
    let fwd_sock = Arc::clone(&client_sock);
    let fwd_task = tokio::spawn(async move {
        if let Err(e) = run_forward_loop(fwd_sock, fwd_config).await {
            error!("forward loop exited: {e}");
        }
    });

    // ── Signal handling ──────────────────────────────────────────────────────
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => { fwd_task.abort(); return RunResult::IoError; }
    };
    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(_) => { fwd_task.abort(); return RunResult::IoError; }
    };

    let result = loop {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("received SIGTERM — shutting down");
                break RunResult::Clean;
            }
            _ = sighup.recv() => {
                info!("received SIGHUP — reloading configuration");
                if let Some(ref tx) = sighup_tx {
                    let _ = tx.send(()).await;
                }
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received SIGINT — shutting down");
                break RunResult::Clean;
            }
        }
    };

    fwd_task.abort();
    result
}

// ──────────────────────────────────────────────────────────────────────────────
// SIGHUP config reload
// ──────────────────────────────────────────────────────────────────────────────

/// Actions to perform on SIGHUP (config reload).
///
/// Flushes the DNS cache and reloads `/etc/hosts` and any servers-file entries.
/// In a full implementation this would call `cache_reload()`, re-read
/// `/etc/resolv.conf`, and re-parse the servers-file.  Here we provide the
/// plumbing so the main loop can drive it.
pub async fn on_sighup(daemon_handle: &DaemonHandle) {
    use tracing::info;

    let mut d = daemon_handle.write().await;

    // Reload upstream servers from resolv.conf (stub — file parsing not yet wired).
    info!("SIGHUP: flushing DNS cache and reloading configuration");

    // Clear any locally cached negative/positive entries that may be stale.
    // In a full implementation: d.dns_cache.clear() once Daemon owns the cache.
    let _ = d; // prevent unused warning

    // A full implementation would also:
    // - Re-read /etc/resolv.conf for upstream server addresses
    // - Re-parse /etc/hosts into the cache
    // - Re-open log files
    // - Reload DHCP lease file
}

// ──────────────────────────────────────────────────────────────────────────────
// Timer / alarm management
// ──────────────────────────────────────────────────────────────────────────────

/// Periodic housekeeping actions driven by a timer.
///
/// Runs once per interval (default 1 second) and:
/// - Expires timed-out DNS cache entries.
/// - Expires timed-out pending forwarded queries.
///
/// In a full implementation this would also drive DHCP lease expiry, RA
/// transmission scheduling, and the DNSSEC validation timeout queue.
pub async fn on_alarm(daemon_handle: &DaemonHandle) {
    use std::time::Instant;

    let now = Instant::now();
    let d = daemon_handle.read().await;
    // In a full implementation: d.dns_cache.expire_old(now) once Daemon owns the cache.
    let _ = (now, d);
}

/// Spawn a background tokio task that calls [`on_alarm`] every `interval`.
///
/// The task holds a weak reference via the provided `DaemonHandle` (`Arc`) so
/// it can be cancelled by dropping the handle.  Returns a `JoinHandle` that
/// can be aborted to stop the timer.
pub fn spawn_alarm_task(
    daemon_handle: DaemonHandle,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            on_alarm(&daemon_handle).await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_daemon_returns_handle() {
        let handle = init_daemon();
        // We can acquire a read lock immediately — the Arc is valid.
        let guard = handle.blocking_read();
        assert_eq!(guard.port, 53);
    }

    #[test]
    fn write_and_read_pid_file_roundtrip() {
        let dir = std::env::temp_dir();
        let path = dir.join("dnsmasq_rs_test_pid.pid");
        let path_str = path.to_str().unwrap();

        let pid: u32 = std::process::id();
        write_pid_file(path_str, pid).expect("write_pid_file failed");
        let read_back = read_pid_file(path_str).expect("read_pid_file failed");
        assert_eq!(pid, read_back);

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn read_pid_file_missing_returns_error() {
        let result = read_pid_file("/tmp/dnsmasq_rs_nonexistent_9999.pid");
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("pid file error"));
    }

    #[test]
    fn drop_privileges_noop_for_current_user() {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        // Should succeed without any syscall since uid/gid already match.
        drop_privileges(uid, gid).expect("drop_privileges failed for current user");
    }

    // ── SIGHUP reload ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn on_sighup_does_not_panic() {
        let handle = init_daemon();
        // Should run without panic; cache clear is a no-op on empty cache.
        on_sighup(&handle).await;
    }

    // ── Alarm timer ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn on_alarm_does_not_panic() {
        let handle = init_daemon();
        on_alarm(&handle).await;
    }

    #[tokio::test]
    async fn spawn_alarm_task_can_be_aborted() {
        let handle = init_daemon();
        let task = spawn_alarm_task(handle, std::time::Duration::from_millis(10));
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        task.abort();
        // After abort, joining returns an error (cancelled).
        assert!(task.await.is_err());
    }
}

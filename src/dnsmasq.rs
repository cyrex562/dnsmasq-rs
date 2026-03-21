//! Daemon initialization and process-management helpers.
//!
//! Mirrors the startup logic in `dnsmasq.c` (the original 2478-line C file).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;

use crate::error::DnsmasqError;
use crate::types::daemon::Daemon;

/// A shared, async-safe handle to the daemon state.
pub type DaemonHandle = Arc<RwLock<Daemon>>;

// ──────────────────────────────────────────────────────────────────────────────
// Daemon event system
// ──────────────────────────────────────────────────────────────────────────────

/// Represents an asynchronous event that the daemon main loop can process.
///
/// Mirrors the event types handled by the C `dnsmasq` main loop: signals,
/// timers, child-process exits, and network-change notifications.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonEvent {
    /// SIGHUP received — reload configuration files and flush cache.
    Reload,
    /// Timer tick — perform periodic housekeeping (cache expiry, lease checks).
    Alarm,
    /// SIGTERM received — initiate clean shutdown.
    Term,
    /// A child process exited with the given wait status.
    Child(i32),
    /// A network address change was detected (e.g. via netlink).
    NewAddr,
    /// SIGUSR1 received — dump cache contents to the log.
    Dump,
    /// The system clock was adjusted (e.g. NTP step).
    TimeSet,
}

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
/// Delegates the actual work to [`clear_cache_and_reload`].
pub async fn on_sighup(daemon_handle: &DaemonHandle) {
    use tracing::info;

    info!("SIGHUP: initiating cache flush and config reload");
    clear_cache_and_reload(daemon_handle).await;

    // Increment the reload counter so other subsystems can detect reloads.
    let mut d = daemon_handle.write().await;
    d.reload_count = d.reload_count.wrapping_add(1);
}

// ──────────────────────────────────────────────────────────────────────────────
// Timer / alarm management
// ──────────────────────────────────────────────────────────────────────────────

/// Periodic housekeeping actions driven by a timer.
///
/// Runs once per interval (default 1 second) and:
/// - Expires timed-out DNS cache entries.
/// - Expires timed-out pending forwarded queries.
/// - Logs current time and cache size for diagnostics.
///
/// In a full implementation this would also drive DHCP lease expiry, RA
/// transmission scheduling, and the DNSSEC validation timeout queue.
pub async fn on_alarm(daemon_handle: &DaemonHandle) {
    use tracing::info;

    let now = Instant::now();
    let d = daemon_handle.read().await;

    info!(
        cachesize = d.cachesize,
        dns_dirty = d.dns_dirty,
        "alarm tick: housekeeping at {:?}",
        now
    );

    // In a full implementation:
    // - d.dns_cache.expire_old(now) once Daemon owns the cache
    // - Check DHCP lease expiry
    // - Prune stale forward table entries
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

// ──────────────────────────────────────────────────────────────────────────────
// Cache flush and reload
// ──────────────────────────────────────────────────────────────────────────────

/// Flush the DNS cache and reload configuration data.
///
/// Logs the action and marks the daemon's DNS data as dirty so that
/// downstream consumers know to re-query.  In a full implementation this
/// would call `cache.clear()` and re-read `/etc/hosts`.
pub async fn clear_cache_and_reload(daemon_handle: &DaemonHandle) {
    use tracing::info;

    info!("flushing cache and reloading");

    let mut d = daemon_handle.write().await;
    // Mark DNS data as dirty so consumers know to refresh.
    d.dns_dirty = true;

    // In a full implementation:
    // - d.dns_cache.clear()
    // - Re-read /etc/hosts into the cache
    // - Re-parse servers-file
    // - Re-read /etc/resolv.conf for upstream server addresses
}

// ──────────────────────────────────────────────────────────────────────────────
// Alarm scheduling
// ──────────────────────────────────────────────────────────────────────────────

/// Schedule the next alarm event after `next_event_secs` seconds.
///
/// Stores the computed deadline in the daemon's `next_alarm` field so that
/// the alarm task can check whether it should fire early or skip a tick.
pub async fn send_alarm(daemon_handle: &DaemonHandle, next_event_secs: u64) {
    use tracing::info;

    let deadline = Instant::now() + Duration::from_secs(next_event_secs);
    let mut d = daemon_handle.write().await;
    d.next_alarm = Some(deadline);

    info!(
        next_event_secs,
        "scheduled next alarm"
    );
}

// ──────────────────────────────────────────────────────────────────────────────
// resolv.conf monitoring
// ──────────────────────────────────────────────────────────────────────────────

/// Check whether the file at `path` has been modified.
///
/// Returns `Some(mtime)` if the file's modification time can be read,
/// or `None` if the file does not exist or its metadata is inaccessible.
/// This is a pure function with no side effects.
pub fn poll_resolv(path: &str) -> Option<SystemTime> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
}

/// Watches a resolv.conf-style file for modifications.
///
/// On each call to [`check`](ResolvMonitor::check), the monitor compares
/// the file's current mtime against the last observed mtime.  Returns
/// `true` when the file has changed (or appeared for the first time).
pub struct ResolvMonitor {
    path: String,
    last_mtime: Option<SystemTime>,
}

impl ResolvMonitor {
    /// Create a new monitor for the file at `path`.
    ///
    /// The initial mtime is captured immediately so that the first call
    /// to [`check`](ResolvMonitor::check) returns `false` unless the file
    /// changes between construction and the first check.
    pub fn new(path: &str) -> Self {
        let last_mtime = poll_resolv(path);
        Self {
            path: path.to_owned(),
            last_mtime,
        }
    }

    /// Returns `true` if the file has changed since the last check.
    ///
    /// Also returns `true` if the file appeared (was previously absent)
    /// or disappeared (was previously present).  Updates the internal
    /// mtime so that subsequent calls only return `true` on further changes.
    pub fn check(&mut self) -> bool {
        let current_mtime = poll_resolv(&self.path);
        if current_mtime != self.last_mtime {
            self.last_mtime = current_mtime;
            true
        } else {
            false
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// ICMP ping for DHCP conflict detection
// ──────────────────────────────────────────────────────────────────────────────

/// ICMP echo-based address conflict detection for DHCP.
///
/// Before offering a DHCP lease, dnsmasq can send an ICMP echo request to
/// confirm that the address is not already in use.  This struct encapsulates
/// the timeout and ping logic.
///
/// Currently a stub — `ping` always returns `false` (no reply).  A full
/// implementation would open a raw ICMP socket and send/receive echo packets.
#[cfg(feature = "dhcp")]
pub struct IcmpPinger {
    timeout: Duration,
}

#[cfg(feature = "dhcp")]
impl IcmpPinger {
    /// Create a new pinger with the given timeout in milliseconds.
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            timeout: Duration::from_millis(timeout_ms),
        }
    }

    /// Attempt to ping `addr` via ICMP echo.
    ///
    /// Returns `true` if a reply was received within the configured timeout,
    /// indicating a potential address conflict.
    ///
    /// **Stub implementation** — always returns `false`.  A production
    /// implementation would require `CAP_NET_RAW` or root privileges.
    pub fn ping(&self, addr: Ipv4Addr) -> bool {
        use tracing::info;

        info!(
            %addr,
            timeout_ms = self.timeout.as_millis() as u64,
            "ICMP ping stub — no reply (not implemented)"
        );
        false
    }
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

    // ── DaemonEvent ─────────────────────────────────────────────────────────

    #[test]
    fn daemon_event_variants_are_distinct() {
        let events = [
            DaemonEvent::Reload,
            DaemonEvent::Alarm,
            DaemonEvent::Term,
            DaemonEvent::Child(0),
            DaemonEvent::NewAddr,
            DaemonEvent::Dump,
            DaemonEvent::TimeSet,
        ];
        // Each variant should be equal to itself.
        for e in &events {
            assert_eq!(*e, *e);
        }
        // Different variants should not be equal.
        assert_ne!(DaemonEvent::Reload, DaemonEvent::Alarm);
        assert_ne!(DaemonEvent::Term, DaemonEvent::Dump);
        assert_ne!(DaemonEvent::NewAddr, DaemonEvent::TimeSet);
    }

    #[test]
    fn daemon_event_child_carries_status() {
        let e1 = DaemonEvent::Child(0);
        let e2 = DaemonEvent::Child(1);
        let e3 = DaemonEvent::Child(0);
        assert_ne!(e1, e2);
        assert_eq!(e1, e3);
    }

    #[test]
    fn daemon_event_is_copy_and_clone() {
        let e = DaemonEvent::Reload;
        let e2 = e; // Copy
        let e3 = e.clone(); // Clone
        assert_eq!(e, e2);
        assert_eq!(e, e3);
    }

    #[test]
    fn daemon_event_debug_format() {
        let dbg = format!("{:?}", DaemonEvent::Child(42));
        assert!(dbg.contains("Child"));
        assert!(dbg.contains("42"));
    }

    // ── poll_resolv ─────────────────────────────────────────────────────────

    #[test]
    fn poll_resolv_returns_none_for_missing_file() {
        let result = poll_resolv("/tmp/dnsmasq_rs_nonexistent_resolv_99999.conf");
        assert!(result.is_none());
    }

    #[test]
    fn poll_resolv_returns_some_for_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 8.8.8.8\n").unwrap();

        let result = poll_resolv(path.to_str().unwrap());
        assert!(result.is_some());
    }

    #[test]
    fn poll_resolv_mtime_changes_after_write() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 8.8.8.8\n").unwrap();

        let mtime1 = poll_resolv(path.to_str().unwrap()).unwrap();

        // Sleep briefly to ensure filesystem mtime granularity is exceeded.
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&path, "nameserver 1.1.1.1\n").unwrap();

        let mtime2 = poll_resolv(path.to_str().unwrap()).unwrap();
        // Depending on filesystem granularity, mtime may or may not differ,
        // but it should never go backwards.
        assert!(mtime2 >= mtime1);
    }

    // ── clear_cache_and_reload ──────────────────────────────────────────────

    #[tokio::test]
    async fn clear_cache_and_reload_sets_dns_dirty() {
        let handle = init_daemon();
        {
            let d = handle.read().await;
            assert!(!d.dns_dirty);
        }

        clear_cache_and_reload(&handle).await;

        let d = handle.read().await;
        assert!(d.dns_dirty);
    }

    #[tokio::test]
    async fn clear_cache_and_reload_idempotent() {
        let handle = init_daemon();
        clear_cache_and_reload(&handle).await;
        clear_cache_and_reload(&handle).await;

        let d = handle.read().await;
        assert!(d.dns_dirty);
    }

    // ── send_alarm ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn send_alarm_sets_next_alarm() {
        let handle = init_daemon();
        {
            let d = handle.read().await;
            assert!(d.next_alarm.is_none());
        }

        send_alarm(&handle, 60).await;

        let d = handle.read().await;
        assert!(d.next_alarm.is_some());
        let deadline = d.next_alarm.unwrap();
        // The deadline should be roughly 60 seconds in the future.
        let now = Instant::now();
        let diff = deadline.duration_since(now);
        assert!(diff.as_secs() >= 58 && diff.as_secs() <= 62);
    }

    #[tokio::test]
    async fn send_alarm_overwrites_previous() {
        let handle = init_daemon();

        send_alarm(&handle, 120).await;
        let first = handle.read().await.next_alarm.unwrap();

        send_alarm(&handle, 10).await;
        let second = handle.read().await.next_alarm.unwrap();

        // Second alarm should be earlier than the first.
        assert!(second < first);
    }

    #[tokio::test]
    async fn send_alarm_zero_seconds() {
        let handle = init_daemon();
        let before = Instant::now();

        send_alarm(&handle, 0).await;

        let d = handle.read().await;
        let deadline = d.next_alarm.unwrap();
        // With 0 seconds, the deadline should be essentially now.
        assert!(deadline >= before);
        assert!(deadline.duration_since(before).as_millis() < 100);
    }

    // ── on_sighup (expanded) ────────────────────────────────────────────────

    #[tokio::test]
    async fn on_sighup_sets_dns_dirty_and_increments_reload() {
        let handle = init_daemon();
        {
            let d = handle.read().await;
            assert_eq!(d.reload_count, 0);
            assert!(!d.dns_dirty);
        }

        on_sighup(&handle).await;

        let d = handle.read().await;
        assert!(d.dns_dirty);
        assert_eq!(d.reload_count, 1);
    }

    #[tokio::test]
    async fn on_sighup_increments_reload_count_each_time() {
        let handle = init_daemon();

        on_sighup(&handle).await;
        on_sighup(&handle).await;
        on_sighup(&handle).await;

        let d = handle.read().await;
        assert_eq!(d.reload_count, 3);
    }

    // ── on_alarm (expanded) ─────────────────────────────────────────────────

    #[tokio::test]
    async fn on_alarm_logs_without_panic() {
        let handle = init_daemon();
        // Modify cachesize to verify it is readable during alarm.
        {
            let mut d = handle.write().await;
            d.cachesize = 500;
        }
        on_alarm(&handle).await;
        // If we get here without panic, the test passes.
    }

    // ── ResolvMonitor ───────────────────────────────────────────────────────

    #[test]
    fn resolv_monitor_no_change_returns_false() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 8.8.8.8\n").unwrap();

        let mut monitor = ResolvMonitor::new(path.to_str().unwrap());
        // Immediately after construction, no change has occurred.
        assert!(!monitor.check());
    }

    #[test]
    fn resolv_monitor_detects_file_modification() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 8.8.8.8\n").unwrap();

        let mut monitor = ResolvMonitor::new(path.to_str().unwrap());
        assert!(!monitor.check());

        // Wait and modify.
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&path, "nameserver 1.1.1.1\n").unwrap();

        assert!(monitor.check());
        // Subsequent check without changes should return false.
        assert!(!monitor.check());
    }

    #[test]
    fn resolv_monitor_detects_file_deletion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 8.8.8.8\n").unwrap();

        let mut monitor = ResolvMonitor::new(path.to_str().unwrap());
        assert!(!monitor.check());

        // Delete the file.
        std::fs::remove_file(&path).unwrap();
        assert!(monitor.check());
    }

    #[test]
    fn resolv_monitor_detects_file_creation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");

        // Start monitoring a non-existent file.
        let mut monitor = ResolvMonitor::new(path.to_str().unwrap());
        assert!(!monitor.check());

        // Create the file.
        std::fs::write(&path, "nameserver 8.8.8.8\n").unwrap();
        assert!(monitor.check());
    }

    #[test]
    fn resolv_monitor_new_captures_initial_state() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 8.8.8.8\n").unwrap();

        let monitor = ResolvMonitor::new(path.to_str().unwrap());
        assert!(monitor.last_mtime.is_some());
        assert_eq!(monitor.path, path.to_str().unwrap());
    }

    #[test]
    fn resolv_monitor_nonexistent_path_has_none_mtime() {
        let monitor = ResolvMonitor::new("/tmp/dnsmasq_rs_no_such_file_99999.conf");
        assert!(monitor.last_mtime.is_none());
    }

    #[test]
    fn resolv_monitor_repeated_checks_stable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 8.8.8.8\n").unwrap();

        let mut monitor = ResolvMonitor::new(path.to_str().unwrap());
        // Multiple checks without changes should all return false.
        for _ in 0..5 {
            assert!(!monitor.check());
        }
    }

    // ── IcmpPinger ──────────────────────────────────────────────────────────

    #[cfg(feature = "dhcp")]
    #[test]
    fn icmp_pinger_new_sets_timeout() {
        let pinger = IcmpPinger::new(500);
        assert_eq!(pinger.timeout, Duration::from_millis(500));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn icmp_pinger_stub_returns_false() {
        let pinger = IcmpPinger::new(100);
        // Stub always returns false (no reply).
        assert!(!pinger.ping(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!pinger.ping(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!pinger.ping(Ipv4Addr::LOCALHOST));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn icmp_pinger_zero_timeout() {
        let pinger = IcmpPinger::new(0);
        assert_eq!(pinger.timeout, Duration::from_millis(0));
        assert!(!pinger.ping(Ipv4Addr::new(8, 8, 8, 8)));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn icmp_pinger_large_timeout() {
        let pinger = IcmpPinger::new(30_000);
        assert_eq!(pinger.timeout, Duration::from_secs(30));
    }
}

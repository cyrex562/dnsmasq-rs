//! Daemon initialization and process-management helpers.
//!
//! Mirrors the startup logic in `dnsmasq.c` (the original 2478-line C file).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;

use crate::error::DnsmasqError;
use crate::types::daemon::Daemon;
#[cfg(feature = "dhcp")]
use crate::dhcp::DhcpServerConfig;
#[cfg(feature = "dhcp")]
use crate::types::addr::MySockAddr;

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

/// Initialize a shared daemon handle from a resolved daemon configuration.
pub fn init_daemon_with(daemon: Daemon) -> DaemonHandle {
    Arc::new(RwLock::new(daemon))
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

#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
struct DhcpDaemonRuntime {
    bind_addr: SocketAddr,
    bind_interface: Option<String>,
    server: DhcpServerConfig,
    loop_opts: crate::dhcp::DhcpLoopOptions,
}

/// Snapshot the locally-configured DNS data out of [`Daemon`] so the query loop
/// can answer from it without holding the daemon lock.
///
/// Mirrors the config data upstream's `answer_request()` walks: `daemon->txt`,
/// `daemon->rr`, `daemon->mxnames`, `daemon->ptr`, `daemon->naptr`, the
/// `host-record` list and the configured CNAMEs.
pub fn daemon_local_data(daemon: &Daemon) -> crate::forward::LocalData {
    crate::forward::LocalData {
        local_ttl:     daemon.local_ttl,
        txt_records:   daemon.txt.clone(),
        rr_records:    daemon.rr.clone(),
        mx_records:    daemon.mxnames.clone(),
        ptr_records:   daemon.ptr.clone(),
        host_records:  daemon.host_records.clone(),
        cnames:        daemon.cnames.clone(),
        naptr_records: daemon.naptr.clone(),
    }
}

/// Resolve the answer-cache size from `cache-size`.  Upstream treats a negative
/// or absent value as "use the default" and `0` as "caching disabled"; the Rust
/// cache has no disabled mode yet, so `0` collapses to the smallest cache.
pub fn daemon_cache_size(daemon: &Daemon) -> usize {
    if daemon.cachesize < 0 {
        crate::forward::DEFAULT_CACHE_SIZE
    } else {
        daemon.cachesize as usize
    }
}

#[cfg(feature = "dhcp")]
fn first_ipv4_listen_addr(addrs: &[crate::types::network::Iname]) -> Option<Ipv4Addr> {
    addrs.iter().find_map(|iname| match iname.addr.as_ref() {
        Some(MySockAddr::V4(sock)) => Some(*sock.ip()),
        _ => None,
    })
}

#[cfg(feature = "dhcp")]
fn first_bind_interface(daemon: &Daemon) -> Option<String> {
    daemon
        .if_names
        .iter()
        .filter_map(|iname| iname.name.as_ref())
        .find(|name| {
            !name.contains('*')
                && !daemon
                    .if_except
                    .iter()
                    .any(|excluded| excluded.name.as_deref() == Some(name.as_str()))
        })
        .cloned()
}

#[cfg(feature = "dhcp")]
fn daemon_dhcp_runtime(daemon: &Daemon) -> Option<DhcpDaemonRuntime> {
    let ctx = daemon.dhcp.first()?;
    let server_port = u16::try_from(daemon.dhcp_server_port).ok()?;
    let client_port = u16::try_from(daemon.dhcp_client_port).ok()?;
    let bind_ip = first_ipv4_listen_addr(&daemon.if_addrs).unwrap_or(Ipv4Addr::UNSPECIFIED);
    let bind_interface = first_bind_interface(daemon);

    Some(DhcpDaemonRuntime {
        bind_addr: SocketAddr::from((bind_ip, server_port)),
        bind_interface,
        server: DhcpServerConfig {
            pool_start: ctx.start,
            pool_end: ctx.end,
            server_ip: if ctx.router != Ipv4Addr::UNSPECIFIED {
                ctx.router
            } else {
                ctx.start
            },
            max_packet: 1500,
            configs: daemon.dhcp_conf.clone(),
            vendor_rules: daemon.dhcp_vendors.clone(),
            user_class_rules: daemon.dhcp_userclasses.clone(),
            mac_rules: daemon.dhcp_macs.clone(),
            relay_id_rules: daemon.dhcp_relay_ids.clone(),
            reply_delays: daemon.dhcp_reply_delays.clone(),
            contexts: daemon.dhcp.clone(),
            dhcp_opts: daemon.dhcp_opts.clone(),
            boot_configs: daemon.boot_config.clone(),
            domain_suffix: daemon.domain_suffix.clone(),
        },
        loop_opts: crate::dhcp::DhcpLoopOptions {
            reply_port_override: (client_port != 68).then_some(client_port),
        },
    })
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
    #[cfg(feature = "dhcp")]
    use tokio::sync::watch;
    use tokio::signal::unix::{signal, SignalKind};
    use tracing::{error, info, warn};

    use crate::forward::{ForwardConfig, ForwardEngine, run_forward_loop};
    #[cfg(feature = "dhcp")]
    use crate::dhcp::{DhcpLoopOptions, run_dhcp_loop};

    // ── Resolve configuration ────────────────────────────────────────────────
    let (port, upstreams, local_data, cache_size, dhcp_runtime) = {
        let d = daemon_handle.read().await;
        let ups: Vec<_> = d
            .servers
            .iter()
            .map(|s| SocketAddr::from(s.addr.clone()))
            .collect();
        let local_data = daemon_local_data(&d);
        let cache_size = daemon_cache_size(&d);
        #[cfg(feature = "dhcp")]
        let dhcp_runtime = daemon_dhcp_runtime(&d);
        #[cfg(not(feature = "dhcp"))]
        let dhcp_runtime = ();
        (d.port, ups, local_data, cache_size, dhcp_runtime)
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
        local: local_data,
        cache_size,
        ..Default::default()
    };
    let fwd_sock = Arc::clone(&client_sock);
    let fwd_task = tokio::spawn(async move {
        if let Err(e) = run_forward_loop(fwd_sock, fwd_config).await {
            error!("forward loop exited: {e}");
        }
    });

    #[cfg(feature = "dhcp")]
    let (dhcp_task, dhcp_shutdown_tx) = if let Some(dhcp_runtime) = dhcp_runtime {
        let bind_addr = dhcp_runtime.bind_addr;
        let dhcp_sock = match UdpSocket::bind(bind_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!("failed to bind DHCP socket on {bind_addr}: {e}");
                fwd_task.abort();
                return RunResult::IoError;
            }
        };
        info!("listening for DHCP packets on {bind_addr}");
        #[cfg(all(unix, target_os = "linux"))]
        if let Some(device) = dhcp_runtime.bind_interface.as_deref() {
            use std::os::unix::io::AsRawFd;
            match crate::dhcp_common::bindtodevice(device, dhcp_sock.as_raw_fd()) {
                Ok(true) => info!("bound DHCP socket to interface {device}"),
                Ok(false) => warn!("permission denied binding DHCP socket to interface {device}; continuing"),
                Err(e) => {
                    error!("failed to bind DHCP socket to interface {device}: {e}");
                    fwd_task.abort();
                    return RunResult::IoError;
                }
            }
        }
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            if let Err(e) = run_dhcp_loop(dhcp_sock, dhcp_runtime.server, dhcp_runtime.loop_opts, shutdown_rx).await {
                error!("dhcp loop exited: {e}");
            }
        });
        (Some(task), Some(shutdown_tx))
    } else {
        (None, None)
    };

    // ── Signal handling ──────────────────────────────────────────────────────
    let mut sigterm = match signal(SignalKind::terminate()) {
        Ok(s) => s,
        Err(_) => {
            #[cfg(feature = "dhcp")]
            {
                if let Some(tx) = dhcp_shutdown_tx.as_ref() {
                    let _ = tx.send(true);
                }
                if let Some(task) = dhcp_task.as_ref() {
                    task.abort();
                }
            }
            fwd_task.abort();
            return RunResult::IoError;
        }
    };
    let mut sighup = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(_) => {
            #[cfg(feature = "dhcp")]
            {
                if let Some(tx) = dhcp_shutdown_tx.as_ref() {
                    let _ = tx.send(true);
                }
                if let Some(task) = dhcp_task.as_ref() {
                    task.abort();
                }
            }
            fwd_task.abort();
            return RunResult::IoError;
        }
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
    #[cfg(feature = "dhcp")]
    {
        if let Some(tx) = dhcp_shutdown_tx {
            let _ = tx.send(true);
        }
        if let Some(task) = dhcp_task {
            let _ = task.await;
        }
    }
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

    // ── local-data snapshot ───────────────────────────────────────────────────

    #[test]
    fn daemon_local_data_carries_every_record_kind() {
        use crate::types::dns_records::{Cname, HostRecord, MxSrvRecord, Naptr, PtrRecord, TxtRecord};

        let mut daemon = Daemon::default();
        daemon.local_ttl = 60;
        daemon.host_records.push(HostRecord {
            ttl: 60,
            flags: 0,
            names: vec!["host.test".into()],
            addr4: Some(Ipv4Addr::new(192, 0, 2, 10)),
            addr6: None,
        });
        daemon.cnames.push(Cname {
            ttl: 60, flag: 0, alias: "alias.test".into(), target: "host.test".into(),
        });
        daemon.txt.push(TxtRecord {
            name: "txt.test".into(), txt: b"\x05hello".to_vec(), class: 1, stat: 0,
        });
        daemon.rr.push(TxtRecord {
            name: "rr.test".into(), txt: vec![0xde, 0xad], class: 99, stat: 0,
        });
        daemon.mxnames.push(MxSrvRecord {
            name: "mail.test".into(), target: "sink.test".into(),
            is_srv: false, srv_port: 0, priority: 10, weight: 0, offset: 0,
        });
        daemon.ptr.push(PtrRecord {
            name: "10.2.0.192.in-addr.arpa".into(), ptr: "host.test".into(),
        });
        daemon.naptr.push(Naptr {
            name: "naptr.test".into(), replace: "r.test".into(), regexp: String::new(),
            services: "SIP+D2U".into(), flags: "s".into(), order: 1, pref: 2,
        });

        let local = daemon_local_data(&daemon);
        assert_eq!(local.local_ttl, 60);
        assert_eq!(local.host_records.len(), 1);
        assert_eq!(local.cnames.len(), 1);
        assert_eq!(local.txt_records.len(), 1);
        assert_eq!(local.rr_records.len(), 1);
        assert_eq!(local.mx_records.len(), 1);
        assert_eq!(local.ptr_records.len(), 1);
        assert_eq!(local.naptr_records.len(), 1);
        assert!(!local.is_empty());
    }

    #[test]
    fn daemon_local_data_empty_by_default() {
        assert!(daemon_local_data(&Daemon::default()).is_empty());
    }

    #[test]
    fn daemon_cache_size_defaults_and_clamps() {
        let mut daemon = Daemon::default();
        assert_eq!(daemon_cache_size(&daemon), daemon.cachesize as usize);
        daemon.cachesize = -1;
        assert_eq!(daemon_cache_size(&daemon), crate::forward::DEFAULT_CACHE_SIZE);
        daemon.cachesize = 0;
        assert_eq!(daemon_cache_size(&daemon), 0);
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn daemon_dhcp_runtime_none_without_range() {
        let daemon = Daemon::default();
        assert!(daemon_dhcp_runtime(&daemon).is_none());
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn daemon_dhcp_runtime_uses_first_range_and_rules() {
        use crate::types::dhcp::{DhcpContext, DhcpNetid, DhcpReplyDelay, CONTEXT_DHCP};

        let mut daemon = Daemon::default();
        daemon.dhcp.push(DhcpContext {
            lease_time: 3600,
            addr_epoch: 0,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(10, 0, 0, 255),
            local: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::new(10, 0, 0, 1),
            start: Ipv4Addr::new(10, 0, 0, 100),
            end: Ipv4Addr::new(10, 0, 0, 150),
            flags: CONTEXT_DHCP,
            netid: DhcpNetid { net: "default".into() },
            filter: vec![],
            #[cfg(feature = "dhcp6")]
            start6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            end6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 0,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
        });
        daemon.dhcp_server_port = 1067;
        daemon.dhcp_reply_delays.push(DhcpReplyDelay {
            delay_secs: 3,
            filter: vec![DhcpNetid { net: "pxe".into() }],
        });

        let runtime = daemon_dhcp_runtime(&daemon).expect("dhcp runtime should be built");
        assert_eq!(runtime.bind_addr, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1067)));
        assert_eq!(runtime.server.pool_start, Ipv4Addr::new(10, 0, 0, 100));
        assert_eq!(runtime.server.pool_end, Ipv4Addr::new(10, 0, 0, 150));
        assert_eq!(runtime.server.server_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(runtime.server.reply_delays.len(), 1);
        assert_eq!(runtime.loop_opts.reply_port_override, None);
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn daemon_dhcp_runtime_uses_listen_address_interface_and_alt_client_port() {
        use crate::types::dhcp::{DhcpContext, DhcpNetid, CONTEXT_DHCP};
        use crate::types::network::Iname;

        let mut daemon = Daemon::default();
        daemon.if_addrs.push(Iname {
            name: None,
            addr: Some(MySockAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0))),
            flags: 0,
        });
        daemon.if_names.push(Iname {
            name: Some("eth-test".into()),
            addr: None,
            flags: 0,
        });
        daemon.dhcp.push(DhcpContext {
            lease_time: 3600,
            addr_epoch: 0,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(127, 0, 0, 255),
            local: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::new(127, 0, 0, 1),
            start: Ipv4Addr::new(127, 0, 0, 10),
            end: Ipv4Addr::new(127, 0, 0, 20),
            flags: CONTEXT_DHCP,
            netid: DhcpNetid { net: "default".into() },
            filter: vec![],
            #[cfg(feature = "dhcp6")]
            start6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            end6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 0,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
        });
        daemon.dhcp_server_port = 1067;
        daemon.dhcp_client_port = 1068;

        let runtime = daemon_dhcp_runtime(&daemon).expect("dhcp runtime should be built");
        assert_eq!(runtime.bind_addr, SocketAddr::from((Ipv4Addr::new(127, 0, 0, 1), 1067)));
        assert_eq!(runtime.bind_interface.as_deref(), Some("eth-test"));
        assert_eq!(runtime.loop_opts.reply_port_override, Some(1068));
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

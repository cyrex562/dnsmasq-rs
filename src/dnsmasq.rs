//! Daemon initialization and process-management helpers.
//!
//! Mirrors the startup logic in `dnsmasq.c` (the original 2478-line C file).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;

use crate::error::DnsmasqError;
use crate::types::constants::CHGRP;
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

// ──────────────────────────────────────────────────────────────────────────────
// Run-as identity (dnsmasq.c:499-517)
// ──────────────────────────────────────────────────────────────────────────────

/// The uid/gid the daemon will run as once it has dropped root — upstream's
/// `ent_pw` and `gp` locals, resolved from `user=`/`group=` before the fork so
/// that an unknown name is still reportable on the invoking terminal.
///
/// Either half may be absent: `uid` is `None` when no run user is configured at
/// all, and `gid` is `None` when neither `group=`, `CHGRP` nor the run user's
/// primary group could be resolved.  Upstream tolerates both and simply skips
/// the corresponding `setuid`/`setgid`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RunAs {
    /// The name `uid` was resolved from, for diagnostics.
    pub username:  Option<String>,
    pub uid:       Option<u32>,
    /// The name `gid` was resolved from — either `group=` or the default that
    /// upstream substitutes into `daemon->groupname` for its error messages.
    pub groupname: Option<String>,
    pub gid:       Option<u32>,
    /// The run user's *primary* group (`ent_pw->pw_gid`), which is not
    /// necessarily [`gid`](Self::gid): the daemon runs under `group=`/`CHGRP`,
    /// but upstream chowns the pid file to `pw_uid:pw_gid` (dnsmasq.c:697).
    pub user_gid:  Option<u32>,
}

/// Resolve `user=`/`group=` into numeric ids, mirroring dnsmasq.c:499-517.
///
/// An unrecognised name is fatal (`die(_("unknown user or group: %s"))`) — it
/// is not silently ignored, because that would leave the daemon running as root.
/// The group default follows upstream exactly: when `group=` is absent, try
/// [`CHGRP`], and failing that the run user's primary group.
pub fn resolve_run_as(daemon: &Daemon) -> Result<RunAs, DnsmasqError> {
    use nix::unistd::{Group, User};

    let unknown = |name: &str| DnsmasqError::PrivilegeDrop(format!("unknown user or group: {name}"));

    let mut run_as = RunAs::default();

    let pw = match daemon.username.as_deref() {
        Some(name) => {
            let pw = User::from_name(name)
                .map_err(|e| DnsmasqError::PrivilegeDrop(format!("getpwnam({name}): {e}")))?
                .ok_or_else(|| unknown(name))?;
            run_as.username = Some(name.to_string());
            run_as.uid = Some(pw.uid.as_raw());
            run_as.user_gid = Some(pw.gid.as_raw());
            Some(pw)
        }
        None => None,
    };

    match daemon.groupname.as_deref() {
        Some(name) => {
            let gr = Group::from_name(name)
                .map_err(|e| DnsmasqError::PrivilegeDrop(format!("getgrnam({name}): {e}")))?
                .ok_or_else(|| unknown(name))?;
            run_as.groupname = Some(name.to_string());
            run_as.gid = Some(gr.gid.as_raw());
        }
        // "implement group defaults, CHGRP if available, or group associated
        // with uid" — a missing default group is not an error upstream.
        None => {
            if let Ok(Some(gr)) = Group::from_name(CHGRP) {
                run_as.groupname = Some(gr.name);
                run_as.gid = Some(gr.gid.as_raw());
            } else if let Some(pw) = pw.as_ref() {
                if let Ok(Some(gr)) = Group::from_gid(pw.gid) {
                    run_as.groupname = Some(gr.name);
                }
                run_as.gid = Some(pw.gid.as_raw());
            }
        }
    }

    Ok(run_as)
}

// ──────────────────────────────────────────────────────────────────────────────
// Capability retention (dnsmasq.c:519-597, 747-819)
// ──────────────────────────────────────────────────────────────────────────────

/// The Linux capabilities upstream keeps across the `setuid()` so that the
/// unprivileged daemon can still do the privileged things it needs to.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NeededCaps {
    /// `CAP_NET_ADMIN` — injecting ARP cache entries for DHCP replies.
    pub net_admin: bool,
    /// `CAP_NET_RAW` — the ICMP ping used for DHCP address-conflict detection,
    /// and `SO_BINDTODEVICE` on per-interface upstream servers.
    pub net_raw: bool,
    /// `CAP_NET_BIND_SERVICE` — binding privileged ports after the drop.
    pub net_bind_service: bool,
}

impl NeededCaps {
    /// True when no capability at all has to survive the `setuid()`.
    pub fn is_empty(&self) -> bool {
        !self.net_admin && !self.net_raw && !self.net_bind_service
    }
}

/// Work out which capabilities must survive the privilege drop.
///
/// Mirrors dnsmasq.c:326-333 (DHCP needs `NET_RAW` for the conflict-detection
/// ping unless `--no-ping`, and `NET_ADMIN` for ARP injection) and dnsmasq.c:539
/// (an upstream server pinned to an interface re-issues `SO_BINDTODEVICE` per
/// TCP connection).  `CAP_NET_BIND_SERVICE` is *not* requested for the ordinary
/// listening sockets: those are bound before the drop, exactly as upstream does.
pub fn needed_capabilities(daemon: &Daemon) -> NeededCaps {
    let mut caps = NeededCaps::default();

    #[cfg(feature = "dhcp")]
    if !daemon.dhcp.is_empty() {
        if !daemon.option_bool(crate::types::constants::OPT_NO_PING) {
            caps.net_raw = true;
        }
        caps.net_admin = true;
    }

    if daemon.servers.iter().any(|s| !s.interface.is_empty()) {
        caps.net_raw = true;
    }

    caps
}

/// Restrict the process's permitted and effective capability sets to `caps`
/// (plus `CAP_SETUID` while the `setuid()` is still pending).
///
/// The two sets are narrowed effective-first: the kernel requires the effective
/// set to stay a subset of the permitted set, and the `caps` crate issues one
/// `capset(2)` per set rather than upstream's single combined call.
#[cfg(target_os = "linux")]
fn apply_capabilities(wanted: NeededCaps, keep_setuid: bool) -> Result<(), DnsmasqError> {
    use caps::{CapSet, Capability, CapsHashSet};

    let mut set = CapsHashSet::new();
    if wanted.net_admin {
        set.insert(Capability::CAP_NET_ADMIN);
    }
    if wanted.net_raw {
        set.insert(Capability::CAP_NET_RAW);
    }
    if wanted.net_bind_service {
        set.insert(Capability::CAP_NET_BIND_SERVICE);
    }
    if keep_setuid {
        set.insert(Capability::CAP_SETUID);
    }

    for which in [CapSet::Effective, CapSet::Permitted] {
        caps::set(None, which, &set)
            .map_err(|e| DnsmasqError::PrivilegeDrop(format!("capset({which:?}): {e}")))?;
    }
    Ok(())
}

/// Drop process privileges to the given `uid`/`gid`, keeping no capabilities.
///
/// Passing the current process's own uid/gid is always a no-op and succeeds.
/// See [`drop_privileges_with`] for the full upstream sequence.
pub fn drop_privileges(uid: u32, gid: u32) -> Result<(), DnsmasqError> {
    drop_privileges_with(&RunAs {
        uid: Some(uid),
        gid: Some(gid),
        ..Default::default()
    }, NeededCaps::default())
}

/// Drop to `run_as`, retaining `caps` across the `setuid()`.
///
/// Follows dnsmasq.c:747-819 step for step:
/// 1. `setgroups(0, …)` — strip every supplementary group, so a group the
///    invoking root shell happened to be in cannot be used afterwards.
/// 2. `setgid()`.
/// 3. `capset()` + `prctl(PR_SET_KEEPCAPS, 1)` — ask the kernel not to clear
///    the permitted set when the euid stops being 0.
/// 4. `setuid()`.
/// 5. `capset()` again, now without `CAP_SETUID`, so root cannot be regained.
///
/// Steps 3 and 5 are Linux-only; elsewhere this is just setgroups/setgid/setuid.
/// Upstream skips the uid half entirely when the target uid is 0.
pub fn drop_privileges_with(run_as: &RunAs, caps: NeededCaps) -> Result<(), DnsmasqError> {
    use nix::unistd::{Gid, Uid};

    let current_uid = nix::unistd::getuid();
    let current_gid = nix::unistd::getgid();

    // Upstream only reaches this code as root (dnsmasq.c:747).  When we are
    // not, asking for the identity we already have is a no-op — setgroups(2)
    // would only fail with EPERM, and there is nothing to strip that we could
    // not simply re-acquire.  Note the guard is deliberately *not* applied when
    // we are root: `--user root --group root` must still clear the
    // supplementary groups inherited from the invoking shell, exactly as
    // upstream's unconditional `setgroups(0, &dummy)` does.
    let already_there = run_as.uid.is_none_or(|u| current_uid == Uid::from_raw(u))
        && run_as.gid.is_none_or(|g| current_gid == Gid::from_raw(g));
    if already_there && !current_uid.is_root() {
        return Ok(());
    }

    if let Some(gid) = run_as.gid {
        nix::unistd::setgroups(&[])
            .map_err(|e| DnsmasqError::PrivilegeDrop(format!("setgroups(0): {e}")))?;
        nix::unistd::setgid(Gid::from_raw(gid))
            .map_err(|e| DnsmasqError::PrivilegeDrop(format!("setgid({gid}): {e}")))?;
    }

    // "if (ent_pw && ent_pw->pw_uid != 0)" — dropping to root is not a drop.
    let Some(uid) = run_as.uid.filter(|u| *u != 0) else {
        return Ok(());
    };

    #[cfg(target_os = "linux")]
    {
        apply_capabilities(caps, true)?;
        if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) } == -1 {
            return Err(DnsmasqError::PrivilegeDrop(format!(
                "prctl(PR_SET_KEEPCAPS): {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    nix::unistd::setuid(Uid::from_raw(uid))
        .map_err(|e| DnsmasqError::PrivilegeDrop(format!("setuid({uid}): {e}")))?;

    #[cfg(target_os = "linux")]
    apply_capabilities(caps, false)?;

    Ok(())
}

/// Write `pid` to `path`, mirroring the pid-file handling at dnsmasq.c:658-717.
///
/// `owner` is the `(uid, gid)` the file is `fchown`ed to while we are still
/// root, so that systemd sees a pid file owned by the same user as the daemon.
///
/// The file is `unlink`ed and then created with `O_EXCL`: if an attacker with
/// the run user's privileges replaced the pid file with a symlink, the open
/// fails rather than truncating the symlink's target as root.
pub fn write_pid_file_as(path: &str, pid: u32, owner: Option<(u32, u32)>) -> Result<(), DnsmasqError> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt as _;
    use std::os::unix::io::AsRawFd as _;

    let _ = std::fs::remove_file(path);

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o644)
        .open(path)
        .map_err(|e| DnsmasqError::PidFile(format!("create {path}: {e}")))?;

    if let Some((uid, gid)) = owner {
        // Best effort, exactly as upstream: a failed fchown is warned about,
        // not fatal (dnsmasq.c:698 sets chown_warn).
        if let Err(e) = nix::unistd::fchown(
            f.as_raw_fd(),
            Some(nix::unistd::Uid::from_raw(uid)),
            Some(nix::unistd::Gid::from_raw(gid)),
        ) {
            tracing::warn!("cannot chown pid file {path} to {uid}:{gid}: {e}");
        }
    }

    writeln!(f, "{pid}")
        .map_err(|e| DnsmasqError::PidFile(format!("write {path}: {e}")))?;
    Ok(())
}

/// Write the current process PID to `path`, leaving its ownership alone.
pub fn write_pid_file(path: &str, pid: u32) -> Result<(), DnsmasqError> {
    write_pid_file_as(path, pid, None)
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

/// Change the working directory to `/` so the daemon does not pin a mount
/// point (dnsmasq.c:615).
pub fn chdir_root() -> Result<(), DnsmasqError> {
    std::env::set_current_dir("/").map_err(|e| DnsmasqError::Daemonize(e.to_string()))
}

/// Point stdin/stdout/stderr at `/dev/null` (dnsmasq.c:724-733).
pub fn redirect_stdio_to_devnull() -> Result<(), DnsmasqError> {
    use nix::unistd::dup2;

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

/// The write end of upstream's `err_pipe` (dnsmasq.c:625-641).
///
/// After the fork the process the user invoked is still alive, blocked reading
/// the other end.  It stays blocked — so `dnsmasq &&  something-else` and
/// systemd's `Type=forking` both see startup as complete only when it really
/// is — until the daemon either calls [`ready`](StartupPipe::ready) or reports
/// a fatal error through [`fail`](StartupPipe::fail).
///
/// A [`disabled`](StartupPipe::disabled) pipe is the `-d`/`-k` case, where
/// there was no fork and stderr still belongs to the user.
#[derive(Debug)]
pub struct StartupPipe {
    write_fd: Option<std::os::fd::OwnedFd>,
}

impl StartupPipe {
    /// A pipe for a process that never forked: errors go straight to stderr.
    pub fn disabled() -> Self {
        Self { write_fd: None }
    }

    /// Report a fatal startup error to the invoking process and exit.
    ///
    /// Never returns.  Upstream's equivalent (`send_event` then `_exit`) is
    /// likewise terminal: past the fork there is nobody left to unwind to.
    ///
    /// The message always goes to the log as well.  By the time this can fire,
    /// stderr may already be `/dev/null` — that is true of the `-k` path, which
    /// never forks and so has no pipe either — and upstream does not lose the
    /// diagnostic there: `fatal_event` reaches `die`, which reaches syslog.
    pub fn fail(self, msg: &str) -> ! {
        crate::log::my_syslog(crate::log::LOG_CRIT, msg);
        match self.write_fd {
            Some(fd) => {
                use std::io::Write as _;
                let mut f = std::fs::File::from(fd);
                let _ = f.write_all(msg.as_bytes());
                let _ = f.flush();
            }
            // Without a log sink the record above went nowhere; say it plainly.
            None if !crate::log::sink_installed() => eprintln!("dnsmasq-rs: {msg}"),
            None => {}
        }
        std::process::exit(1);
    }

    /// Startup finished: release the invoking process with a success status.
    pub fn ready(self) {
        drop(self.write_fd);
    }
}

/// Fork into the background: `fork` → `setsid` → `fork` (dnsmasq.c:617-655).
///
/// Only the grandchild returns; it gets the [`StartupPipe`] that keeps the
/// original process waiting.  The two ancestors exit — the first once the
/// grandchild signals it is up, the second immediately.
///
/// **Must be called before any tokio runtime is started**: `fork()` gives the
/// child only the calling thread, so a forked reactor would deadlock.
#[cfg(unix)]
pub fn fork_into_background() -> Result<StartupPipe, DnsmasqError> {
    use nix::unistd::{fork, pipe, setsid, ForkResult};
    use std::io::Read as _;

    let (read_fd, write_fd) =
        pipe().map_err(|e| DnsmasqError::Daemonize(format!("pipe: {e}")))?;

    match unsafe { fork() }.map_err(|e| DnsmasqError::Daemonize(e.to_string()))? {
        ForkResult::Parent { .. } => {
            drop(write_fd);
            let mut msg = String::new();
            let _ = std::fs::File::from(read_fd).read_to_string(&mut msg);
            if msg.is_empty() {
                std::process::exit(0);
            }
            eprintln!("dnsmasq-rs: {}", msg.trim_end());
            std::process::exit(1);
        }
        ForkResult::Child => {}
    }
    drop(read_fd);

    setsid().map_err(|e| DnsmasqError::Daemonize(e.to_string()))?;

    // Second fork: the daemon must not be a session leader, or it could
    // reacquire a controlling terminal.
    match unsafe { fork() }.map_err(|e| DnsmasqError::Daemonize(e.to_string()))? {
        // The intermediate parent must not run any cleanup the grandchild
        // still owns — `_exit` skips atexit handlers and stdio flushing.
        ForkResult::Parent { .. } => unsafe { libc::_exit(0) },
        ForkResult::Child => {}
    }

    Ok(StartupPipe { write_fd: Some(write_fd) })
}

/// Daemonize the current process (double-fork, new session, `chdir("/")`,
/// redirect std fds) and release the invoking process immediately.
///
/// This is the whole-sequence convenience form.  `src/main.rs` drives the
/// individual steps instead, because upstream interleaves the pid-file write
/// between the fork and the stdio redirect.
///
/// **Must be called before any tokio runtime is started** (tokio is not
/// fork-safe).
///
/// Returns `Ok(())` in the grandchild (the actual daemon).
#[cfg(unix)]
pub fn daemonize() -> Result<(), DnsmasqError> {
    // chdir first, as upstream does (dnsmasq.c:615) — the fork inherits it.
    chdir_root()?;
    let startup = fork_into_background()?;
    redirect_stdio_to_devnull()?;
    startup.ready();
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
        edns_pktsz:    daemon.edns_pktsz,
        txt_records:   daemon.txt.clone(),
        rr_records:    daemon.rr.clone(),
        mx_records:    daemon.mxnames.clone(),
        ptr_records:   daemon.ptr.clone(),
        host_records:  daemon.host_records.clone(),
        cnames:        daemon.cnames.clone(),
        naptr_records: daemon.naptr.clone(),
        int_names:     daemon.int_names.clone(),
        nodots_local:  daemon.option_bool(crate::types::constants::OPT_NODOTS_LOCAL),
        synth_domains: daemon.synth_domains.clone(),
        literal_domains: literal_server_domains(daemon),
    }
}

/// Domains from `daemon.servers` entries with `SERV_LITERAL_ADDRESS` set
/// (no real upstream) — these are never forwarded.  Shared by
/// [`daemon_local_data`] (answers them NXDOMAIN) and [`daemon_forward_config`]
/// (excludes them from the upstream list).
fn literal_server_domains(daemon: &Daemon) -> Vec<String> {
    use crate::types::server::SERV_LITERAL_ADDRESS;
    daemon
        .servers
        .iter()
        .filter(|s| s.flags & SERV_LITERAL_ADDRESS != 0 && !s.domain.is_empty())
        .map(|s| s.domain.clone())
        .collect()
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

/// Build the [`SharedDnsCache`] the forwarding loop and SIGHUP reload share.
///
/// Sized and TTL-bounded from `daemon` exactly like [`daemon_forward_config`],
/// so the two must be built from the same snapshot to stay consistent.
pub async fn build_shared_cache(daemon_handle: &DaemonHandle) -> crate::cache::SharedDnsCache {
    let d = daemon_handle.read().await;
    crate::cache::new_shared_cache(daemon_cache_size(&d), d.min_cache_ttl, d.max_cache_ttl)
}

/// Build the [`ForwardConfig`](crate::forward::ForwardConfig) the forwarding
/// loop runs with from a resolved [`Daemon`].
///
/// Every knob that reaches the cache or the reply path is copied here.  A field
/// left at its default is a directive that silently does nothing at run time,
/// so anything added to `ForwardConfig` has to be threaded through this
/// function as well.
pub fn daemon_forward_config(daemon: &Daemon) -> crate::forward::ForwardConfig {
    use crate::types::constants::{
        OPT_CONNTRACK, OPT_DNSSEC_PROXY, OPT_DNSSEC_VALID, OPT_LOCAL_REBIND, OPT_NO_NEG,
        OPT_NO_REBIND,
    };

    // `SERV_LITERAL_ADDRESS` entries (`local=/domain/` with no address,
    // `rev-server` with the server part omitted) carry a dummy address and
    // are never forwarded to — `literal_server_domains` routes them to a
    // local NXDOMAIN answer instead (see `daemon_local_data`).
    let forwardable: Vec<&crate::types::server::Server> = daemon
        .servers
        .iter()
        .filter(|s| s.flags & crate::types::server::SERV_LITERAL_ADDRESS == 0)
        .collect();

    crate::forward::ForwardConfig {
        upstreams: forwardable
            .iter()
            .map(|s| SocketAddr::from(s.addr.clone()))
            .collect(),
        server_domains: forwardable.iter().map(|s| s.domain.clone()).collect(),
        local:         daemon_local_data(daemon),
        cache_size:    daemon_cache_size(daemon),
        min_cache_ttl: daemon.min_cache_ttl,
        max_cache_ttl: daemon.max_cache_ttl,
        max_ttl:       daemon.max_ttl,
        neg_ttl:       daemon.neg_ttl,
        no_neg_cache:  daemon.option_bool(OPT_NO_NEG),
        check_rebind:  daemon.option_bool(OPT_NO_REBIND),
        local_rebind_ok: daemon.option_bool(OPT_LOCAL_REBIND),
        no_rebind:     daemon.no_rebind.clone(),
        // Reply-side answer policy: `--bogus-nxdomain`, `--ignore-address` and
        // the `--filter-rr` family all act in `process_reply()`.
        bogus_addr:    daemon.bogus_addr.clone(),
        ignore_addr:   daemon.ignore_addr.clone(),
        filter_rr:     daemon.rrlist_filter.iter().map(|rr| rr.rr).collect(),
        cache_rr:      daemon.rrlist_cache.iter().map(|rr| rr.rr).collect(),
        dnssec_valid:  daemon.option_bool(OPT_DNSSEC_VALID),
        dnssec_proxy:  daemon.option_bool(OPT_DNSSEC_PROXY),
        // `--dns-forward-max` and `--port-limit`.  Both are clamped away from
        // zero: a zero query table would refuse every query, and a zero port
        // limit would make `allocate_rfd()` reuse a transaction's first socket
        // forever.  C rejects both at parse time.
        ftabsize:       daemon.ftabsize.max(1) as usize,
        randport_limit: daemon.randport_limit.max(1) as usize,
        port:           daemon.port,
        conntrack:      daemon.option_bool(OPT_CONNTRACK),
        ipsets:         daemon.ipsets.clone(),
        ..Default::default()
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
    let relay_iface_index = bind_interface
        .as_deref()
        .map_or(0, |name| crate::network::nametoindex(name) as i32);
    let relay_iface_name = bind_interface.clone();

    // Bind non-split relay entries to the interface owning `relay.local`,
    // mirroring upstream's `complete_context` (`dhcp.c:669-673`), which sets
    // `relay->iface_index` once at interface-enumeration time. Without this,
    // `relay_upstream4`'s `relay.iface_index != 0` guard never matches and a
    // configured `dhcp-relay` never fires. This runtime only tracks a single
    // bound interface, so only relays whose `local` equals that interface's
    // address are bound; split-mode relays match on address directly and
    // don't need `iface_index`.
    let mut relay4 = daemon.relay4.clone();
    for relay in relay4.iter_mut() {
        if relay.split_mode == 0 {
            if let crate::types::addr::AllAddr::Addr4(local4) = relay.local_addr {
                if local4 == bind_ip {
                    relay.iface_index = relay_iface_index;
                }
            }
        }
    }

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
            lease_file: daemon.lease_file.clone(),
            match_rules: daemon.dhcp_match.clone(),
            name_match_rules: daemon.dhcp_name_match.clone(),
            tag_rules: daemon.tag_if.clone(),
            relay4,
        },
        loop_opts: crate::dhcp::DhcpLoopOptions {
            reply_port_override: (client_port != 68).then_some(client_port),
            relay_iface_addr: bind_ip,
            relay_iface_index,
            relay_iface_name,
        },
    })
}

/// Sockets bound up-front by [`bind_listeners`].
///
/// Upstream creates its listeners (dnsmasq.c:393-409) and DHCP sockets
/// (dnsmasq.c:325) long before it forks or drops root, so that privileged
/// ports are claimed while it is still root and a bind failure can still be
/// reported on the invoking terminal.  Holding them in a plain value lets
/// `main` do the same and hand them to [`run_main_loop_with`] afterwards.
///
/// The sockets are `std` rather than `tokio` types on purpose: they are bound
/// before the runtime exists, and they have to survive a `fork()`.
#[derive(Debug)]
pub struct Listeners {
    dns: Vec<BoundDnsSocket>,
    /// Per-datagram arrival check, `None` only when no listener needs one.
    arrival_filter: Option<crate::network::ArrivalFilter>,
    #[cfg(feature = "dhcp")]
    dhcp: Option<std::net::UdpSocket>,
}

/// A DNS socket bound before the fork, plus what the query loop needs to know
/// about it.
#[derive(Debug)]
struct BoundDnsSocket {
    sock: std::net::UdpSocket,
    addr: SocketAddr,
    /// Upstream's `check_dst` (`forward.c:1612`): re-check the arrival
    /// interface of every datagram against the interface config.
    check_dst: bool,
}

impl Listeners {
    /// Addresses the DNS listeners are bound to, in creation order.
    pub fn dns_addrs(&self) -> Vec<SocketAddr> {
        self.dns.iter().map(|l| l.addr).collect()
    }

    /// `(address, checks-arrival-interface)` per DNS listener, in creation
    /// order.
    ///
    /// Upstream's `check_dst = !option_bool(OPT_NOWILD) || family == AF_INET6`
    /// (`forward.c:1612`): binding an address is not by itself access control,
    /// so only IPv4 under plain `--bind-interfaces` skips the check.
    pub fn dns_arrival_checks(&self) -> Vec<(SocketAddr, bool)> {
        self.dns.iter().map(|l| (l.addr, l.check_dst)).collect()
    }
}

/// The `--interface` / `--except-interface` / `--listen-address` filter, in the
/// form `network.rs` consumes.
///
/// A `None` name in `daemon.if_names` is upstream's NULL-named `struct iname`
/// (`--local-service=host`): it restricts the served set without naming an
/// interface, so it is tracked as a flag rather than a pattern.
fn iface_check_config(daemon: &Daemon) -> crate::network::IfaceCheckConfig {
    use crate::types::addr::MySockAddr as Msa;

    crate::network::IfaceCheckConfig {
        allow: daemon.if_names.iter().filter_map(|i| i.name.clone()).collect(),
        deny:  daemon.if_except.iter().filter_map(|i| i.name.clone()).collect(),
        addrs: daemon
            .if_addrs
            .iter()
            .filter_map(|i| match i.addr.as_ref()? {
                Msa::V4(s) => Some(std::net::IpAddr::V4(*s.ip())),
                Msa::V6(s) => Some(std::net::IpAddr::V6(*s.ip())),
            })
            .collect(),
        unnamed_iface: daemon.if_names.iter().any(|i| i.name.is_none()),
    }
}

/// Per-interface DHCP/TFTP permissions, for `iface_allowed_v4`/`_v6`.
fn iface_allowed_config(daemon: &Daemon) -> crate::network::IfaceAllowedConfig {
    let _ = daemon;
    #[allow(unused_mut)] // both fields below are feature-gated
    let mut config = crate::network::IfaceAllowedConfig::default();
    #[cfg(feature = "dhcp")]
    {
        config.dhcp_except = daemon.dhcp_except.iter()
            .filter_map(|i| i.name.clone().map(|n| (n, i.flags)))
            .collect();
    }
    #[cfg(feature = "tftp")]
    {
        config.tftp_ifaces =
            daemon.tftp_interfaces.iter().filter_map(|i| i.name.clone()).collect();
    }
    config
}

/// Turn `network::Listener`s into owned std sockets.
///
/// The TCP and TFTP descriptors are not requested (see
/// [`crate::network::ListenerKinds`]), so only the UDP one is ever present.
///
/// `nowild` is `--bind-interfaces`; it decides `check_dst` per socket exactly as
/// `forward.c:1612` does.
fn adopt_dns_listeners(
    listeners: Vec<crate::network::Listener>,
    nowild: bool,
) -> Result<Vec<BoundDnsSocket>, DnsmasqError> {
    use std::os::unix::io::FromRawFd;

    let mut out = Vec::with_capacity(listeners.len());
    for mut l in listeners {
        // Nothing serves these yet, and the `Listener` is about to be dropped
        // without running `release()`, so close them here rather than leak.
        for fd in [std::mem::replace(&mut l.tcp_fd, -1), std::mem::replace(&mut l.tftp_fd, -1)] {
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        }
        if l.udp_fd < 0 {
            continue;
        }
        // Safety: `create_listeners` just returned this fd and we take sole
        // ownership of it; the `Listener` is consumed here and never released.
        let sock = unsafe { std::net::UdpSocket::from_raw_fd(l.udp_fd) };
        sock.set_nonblocking(true)?;
        // Report what the kernel actually gave us, which differs from the
        // requested address whenever port 0 was asked for.
        let addr = sock.local_addr().unwrap_or(l.addr);
        // forward.c:1612 — the arrival interface is always available for IPv6,
        // so only IPv4 under --bind-interfaces goes unchecked.
        let check_dst = !nowild || addr.is_ipv6();
        out.push(BoundDnsSocket { sock, addr, check_dst });
    }
    Ok(out)
}

/// Bind the DNS listening sockets, mirroring the dispatch in
/// `dnsmasq.c:378-409`.
///
/// * `--bind-interfaces` / `--bind-dynamic` enumerate the live interfaces,
///   filter them through `iface_allowed_v4`/`_v6`, and bind one socket per
///   allowed address plus one per `--listen-address` no interface carries.
///   Under plain `--bind-interfaces` an unmatched `--interface` is fatal.
/// * Everything else binds the two wildcard sockets.
///
/// Either way it returns a [`crate::network::ArrivalFilter`], because binding an
/// address is not by itself access control: a query addressed to an internal
/// interface can still arrive via an external one.  Upstream re-checks the
/// arrival interface of every datagram unless `--bind-interfaces` is set, and
/// even then for IPv6 (`forward.c:1612`).  Which listeners consult the filter is
/// recorded per socket as `check_dst`.
fn bind_dns_listeners(
    daemon: &Daemon,
) -> Result<(Vec<BoundDnsSocket>, Option<crate::network::ArrivalFilter>), DnsmasqError> {
    use crate::network::{self, ListenerKinds};
    use crate::types::constants::{OPT_CLEVERBIND, OPT_NOWILD};

    let nowild     = daemon.option_bool(OPT_NOWILD);
    let cleverbind = daemon.option_bool(OPT_CLEVERBIND);
    if nowild && cleverbind {
        return Err(DnsmasqError::BadConfig(
            "cannot set --bind-interfaces and --bind-dynamic".to_string(),
        ));
    }

    let port = daemon.port;
    // Only UDP: there is no TCP DNS serving loop yet, and binding a listening
    // TCP socket nothing accepts would open a port that swallows connections.
    let kinds = ListenerKinds::UDP_ONLY;

    let mut check   = iface_check_config(daemon);
    let allowed_cfg = iface_allowed_config(daemon);
    let enumerated  = network::enumerate_allowed_interfaces(&mut check, &allowed_cfg)
        .map_err(|e| DnsmasqError::BadNet(format!("failed to find list of interfaces: {e}")))?;

    if !nowild && !cleverbind {
        let listeners = network::create_wildcard_listeners_checked(port, kinds)
            .map_err(|e| DnsmasqError::Bind(format!("0.0.0.0:{port}"), e.to_string()))?;
        if listeners.is_empty() {
            return Err(DnsmasqError::Bind(
                format!("0.0.0.0:{port}"),
                "could not create any wildcard listener".to_string(),
            ));
        }
        let filter = network::ArrivalFilter::new(
            check, allowed_cfg, enumerated.interfaces, cleverbind,
        );
        return Ok((adopt_dns_listeners(listeners, nowild)?, Some(filter)));
    }

    // ── --bind-interfaces / --bind-dynamic ───────────────────────────────────
    // `listen_addr` carries the interface index into `sin6_scope_id` for
    // link-local addresses; without it the bind fails with EINVAL
    // (`network.c:617-620`).
    let iface_addrs: Vec<(SocketAddr, String)> = enumerated
        .interfaces
        .iter()
        .map(|i| (i.listen_addr(port), i.name.clone()))
        .collect();

    let mut listeners = Vec::new();
    network::create_bound_listeners_checked(
        &mut listeners, &iface_addrs, kinds, nowild, cleverbind,
    )
    .map_err(|e| DnsmasqError::Bind(format!("port {port}"), e.to_string()))?;

    // --listen-address values no interface carries are still bound: it is legal
    // to listen on 127.0.1.1 when loopback only advertises 127.0.0.1
    // (network.c:1219-1233).  A bind failure is fatal except under
    // --bind-dynamic, where the address may appear later.
    for addr in enumerated.unmatched_addrs(&check) {
        let sock_addr = SocketAddr::new(addr, port);
        if network::find_listener(&mut listeners, sock_addr).is_some() {
            continue;
        }
        match network::create_listeners_checked(sock_addr, kinds, nowild, cleverbind) {
            Ok(Some(l)) => listeners.push(l),
            Ok(None) if cleverbind => {
                tracing::warn!("cannot bind {sock_addr} yet; --bind-dynamic will retry");
            }
            Ok(None) => {
                return Err(DnsmasqError::Bind(
                    sock_addr.to_string(),
                    "address family not supported".to_string(),
                ))
            }
            Err(e) => return Err(DnsmasqError::Bind(sock_addr.to_string(), e.to_string())),
        }
    }

    // dnsmasq.c:395-398 — under plain --bind-interfaces a named interface that
    // matched nothing is fatal.  --bind-dynamic tolerates it.
    if !cleverbind {
        if let Some(name) = enumerated.unmatched_names(&check).first() {
            return Err(DnsmasqError::BadNet(format!("unknown interface {name}")));
        }
    }

    // Bound listeners are arrival-checked too, except IPv4 under plain
    // --bind-interfaces (`forward.c:1612`).  Under --bind-dynamic that check is
    // the entire point of the option (`network.c:1240-1250`).
    let filter = network::ArrivalFilter::new(
        check, allowed_cfg, enumerated.interfaces, cleverbind,
    );
    Ok((adopt_dns_listeners(listeners, nowild)?, Some(filter)))
}

/// Bind every socket the daemon serves from, before forking and before the
/// privilege drop.
pub fn bind_listeners(daemon: &Daemon) -> Result<Listeners, DnsmasqError> {
    let (dns, arrival_filter) = bind_dns_listeners(daemon)?;

    #[cfg(feature = "dhcp")]
    let dhcp = match daemon_dhcp_runtime(daemon) {
        Some(runtime) => {
            let addr = runtime.bind_addr;
            let sock = std::net::UdpSocket::bind(addr)
                .map_err(|e| DnsmasqError::Bind(addr.to_string(), e.to_string()))?;
            sock.set_nonblocking(true)?;
            #[cfg(target_os = "linux")]
            if let Some(device) = runtime.bind_interface.as_deref() {
                bind_dhcp_socket_to_device(&sock, device)?;
            }
            Some(sock)
        }
        None => None,
    };

    Ok(Listeners {
        dns,
        arrival_filter,
        #[cfg(feature = "dhcp")]
        dhcp,
    })
}

/// Adopt a socket that was bound before the runtime existed, or bind one now.
///
/// The DNS listeners always come pre-bound now (see [`bind_dns_listeners`]);
/// only the DHCP socket still takes this path.
#[cfg(feature = "dhcp")]
async fn adopt_or_bind(
    prebound: Option<std::net::UdpSocket>,
    bind_addr: &str,
) -> std::io::Result<tokio::net::UdpSocket> {
    match prebound {
        Some(sock) => tokio::net::UdpSocket::from_std(sock),
        None => tokio::net::UdpSocket::bind(bind_addr).await,
    }
}

#[cfg(all(feature = "dhcp", target_os = "linux"))]
fn bind_dhcp_socket_to_device(
    sock: &impl std::os::unix::io::AsRawFd,
    device: &str,
) -> Result<(), DnsmasqError> {
    use tracing::{info, warn};

    match crate::dhcp_common::bindtodevice(device, sock.as_raw_fd()) {
        Ok(true) => info!("bound DHCP socket to interface {device}"),
        Ok(false) => warn!("permission denied binding DHCP socket to interface {device}; continuing"),
        Err(e) => {
            return Err(DnsmasqError::Bind(
                format!("interface {device}"),
                e.to_string(),
            ))
        }
    }
    Ok(())
}

/// Run the main daemon event loop, binding its own sockets.
///
/// This function:
/// 1. Binds the DNS listening sockets via [`bind_listeners`], which honours
///    `--interface`, `--except-interface`, `--listen-address` and the
///    `--bind-interfaces` / `--bind-dynamic` mode.
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
    let cache = build_shared_cache(&daemon_handle).await;
    run_main_loop_with(daemon_handle, sighup_tx, None, cache).await
}

/// Run the main daemon event loop over sockets that were bound earlier.
///
/// `listeners` is `Some` when `main` bound them before forking and dropping
/// root (the upstream order); `None` makes this bind them itself, which is what
/// [`run_main_loop`] and the in-process tests do.
///
/// `cache` is the [`SharedDnsCache`](crate::cache::SharedDnsCache) the
/// forwarding task answers and caches through; the caller keeps its own clone
/// so SIGHUP reload ([`on_sighup`]) can flush the very cache the running
/// forward loop is reading from, rather than a disconnected copy.
pub async fn run_main_loop_with(
    daemon_handle: DaemonHandle,
    sighup_tx: Option<tokio::sync::mpsc::Sender<()>>,
    listeners: Option<Listeners>,
    cache: crate::cache::SharedDnsCache,
) -> RunResult {
    use std::sync::Arc;
    #[cfg(feature = "dhcp")]
    use tokio::sync::watch;
    use tokio::signal::unix::{signal, SignalKind};
    use tracing::{error, info};

    use crate::forward::{DnsListener, run_forward_loop_on};
    #[cfg(feature = "dhcp")]
    use crate::dhcp::{DhcpLoopOptions, run_dhcp_loop};

    // ── Resolve configuration ────────────────────────────────────────────────
    let (fwd_config, dhcp_runtime) = {
        let d = daemon_handle.read().await;
        let fwd_config = daemon_forward_config(&d);
        #[cfg(feature = "dhcp")]
        let dhcp_runtime = daemon_dhcp_runtime(&d);
        #[cfg(not(feature = "dhcp"))]
        let dhcp_runtime = ();
        (fwd_config, dhcp_runtime)
    };

    // ── Adopt sockets bound before the fork, or bind them now ────────────────
    //
    // `main` binds while still privileged and hands them over; the in-process
    // callers get here with `None` and go through the very same code path, so
    // there is exactly one place that decides what the daemon listens on.
    let mut listeners = match listeners {
        Some(l) => l,
        None => {
            let d = daemon_handle.read().await;
            match bind_listeners(&d) {
                Ok(l) => l,
                Err(e) => {
                    error!("failed to bind DNS listening sockets: {e}");
                    return RunResult::IoError;
                }
            }
        }
    };

    #[cfg(feature = "dhcp")]
    let prebound_dhcp = listeners.dhcp.take();
    let bound_dns = std::mem::take(&mut listeners.dns);
    let arrival_filter = listeners.arrival_filter.take();

    let mut dns_listeners = Vec::with_capacity(bound_dns.len());
    for bound in bound_dns {
        let addr = bound.addr;
        let sock = match tokio::net::UdpSocket::from_std(bound.sock) {
            Ok(s) => s,
            Err(e) => {
                error!("failed to adopt the DNS socket bound on {addr}: {e}");
                return RunResult::IoError;
            }
        };
        info!("listening for DNS queries on {addr}");
        dns_listeners.push(DnsListener { sock: Arc::new(sock), check_dst: bound.check_dst });
    }
    if dns_listeners.is_empty() {
        error!("no DNS listening sockets were bound; check --interface/--listen-address");
        return RunResult::IoError;
    }

    // ── Spawn the forwarding engine ──────────────────────────────────────────
    let fwd_task = tokio::spawn(async move {
        if let Err(e) = run_forward_loop_on(dns_listeners, arrival_filter, fwd_config, cache).await {
            error!("forward loop exited: {e}");
        }
    });

    #[cfg(feature = "dhcp")]
    let (dhcp_task, dhcp_shutdown_tx) = if let Some(dhcp_runtime) = dhcp_runtime {
        let bind_addr = dhcp_runtime.bind_addr;
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        let already_bound = prebound_dhcp.is_some();
        let dhcp_sock = match adopt_or_bind(prebound_dhcp, &bind_addr.to_string()).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!("failed to bind DHCP socket on {bind_addr}: {e}");
                fwd_task.abort();
                return RunResult::IoError;
            }
        };
        info!("listening for DHCP packets on {bind_addr}");
        // A pre-bound socket already went through `bind_listeners`, which does
        // the SO_BINDTODEVICE while the process is still privileged.
        #[cfg(target_os = "linux")]
        if !already_bound {
            if let Some(device) = dhcp_runtime.bind_interface.as_deref() {
                if let Err(e) = bind_dhcp_socket_to_device(dhcp_sock.as_ref(), device) {
                    error!("failed to bind DHCP socket to interface {device}: {e}");
                    fwd_task.abort();
                    return RunResult::IoError;
                }
            }
        }
        let lease_db = match dhcp_runtime.server.lease_file.as_deref() {
            Some(path) => match crate::lease::LeaseDb::load_from_file(path) {
                Ok(db) => {
                    info!("using DHCP lease file {path} ({} leases)", db.count());
                    db
                }
                Err(_) => crate::lease::LeaseDb::new(),
            },
            None => crate::lease::LeaseDb::new(),
        };
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            if let Err(e) = run_dhcp_loop(dhcp_sock, dhcp_runtime.server, dhcp_runtime.loop_opts, lease_db, shutdown_rx).await {
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
///
/// `cache` must be the same [`SharedDnsCache`](crate::cache::SharedDnsCache)
/// the running forward loop was started with (see [`run_main_loop_with`]) —
/// flushing a disconnected copy would leave the live cache untouched.
pub async fn on_sighup(daemon_handle: &DaemonHandle, cache: &crate::cache::SharedDnsCache) {
    use tracing::info;

    info!("SIGHUP: initiating cache flush and config reload");
    clear_cache_and_reload(daemon_handle, cache).await;

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
    // - cache.expire_old(now) against the running loop's SharedDnsCache
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
/// Mirrors upstream's `EVENT_RELOAD`/`EVENT_INIT` handling in `async_event()`
/// (`dnsmasq.c:1546-1565`):
/// * `clear_cache_and_reload()` (`dnsmasq.c:1807`) → flush and rebuild the
///   `F_HOSTS` cache entries from `/etc/hosts` and `--addn-hosts`, here via
///   [`crate::cache::reload_hosts`].
/// * `reload_servers()` (`network.c:1699`) → re-read each `--resolv-file`
///   into `daemon->servers`, replacing only the previous `SERV_FROM_RESOLV`
///   entries so explicitly configured (`--server=`) servers survive.
///
/// Two deliberate simplifications versus upstream, both tracked in
/// `tasks.md`:
/// * Upstream only preserves `F_DHCP` cache entries across the flush; this
///   port's cache never receives `F_DHCP` records yet, so a full flush is
///   currently equivalent and needs revisiting once DHCP leases feed the
///   cache.
/// * Upstream gates the resolv-file re-read on `OPT_NO_POLL`, because without
///   it a periodic poll/inotify watch is expected to pick up the change
///   instead; this port has no such watch, so SIGHUP always re-reads.
pub async fn clear_cache_and_reload(daemon_handle: &DaemonHandle, cache: &crate::cache::SharedDnsCache) {
    use tracing::{info, warn};
    use crate::types::constants::OPT_NO_HOSTS;

    info!("flushing cache and reloading");

    let (hosts_paths, local_ttl, resolv_paths) = {
        let d = daemon_handle.read().await;
        let mut hosts_paths = Vec::new();
        if !d.option_bool(OPT_NO_HOSTS) {
            hosts_paths.push("/etc/hosts".to_string());
        }
        hosts_paths.extend(d.addn_hosts.iter().map(|h| h.fname.clone()));
        let resolv_paths: Vec<String> = d.resolv_files.iter().map(|r| r.name.clone()).collect();
        (hosts_paths, d.local_ttl, resolv_paths)
    };

    // Flush and rebuild the F_HOSTS entries.
    {
        let mut c = cache.lock().await;
        crate::cache::reload_hosts(&hosts_paths, local_ttl, &mut c);
    }

    // Re-read resolv-file-style server lists, if any are configured.  A file
    // that fails to read (temporarily missing, permission change, mid-rewrite)
    // must leave the existing server list untouched rather than emptying it —
    // upstream's `reload_servers()` does the equivalent by `fopen`ing and
    // returning early, before `mark_servers()` touches anything
    // (`network.c:1699-1709`).
    let mut any_resolv_read = false;
    let mut discovered = Vec::new();
    for path in &resolv_paths {
        match std::fs::read_to_string(path) {
            // 53 is the standard nameserver port (`NAMESERVER_PORT` in C);
            // resolv.conf entries never carry an explicit port.
            Ok(text) => {
                any_resolv_read = true;
                discovered.extend(crate::network::parse_resolv_conf(&text, 53));
            }
            Err(e) => warn!("could not read {path}: {e}"),
        }
    }

    let mut d = daemon_handle.write().await;
    if any_resolv_read {
        use crate::types::addr::MySockAddr;
        use crate::types::server::{SERV_4ADDR, SERV_6ADDR, SERV_FROM_RESOLV};

        let dummy_source = MySockAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        d.servers.retain(|s| s.flags & SERV_FROM_RESOLV == 0);
        for addr in discovered {
            let flags = SERV_FROM_RESOLV | if addr.is_ipv6() { SERV_6ADDR } else { SERV_4ADDR };
            d.servers.push(crate::option::new_server(
                flags,
                String::new(),
                MySockAddr::from(addr),
                dummy_source.clone(),
            ));
        }
    }

    // Mark DNS data as dirty so consumers know to refresh.
    d.dns_dirty = true;
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

    /// A minimal upstream server entry; `Server` has no `Default`.
    fn test_server(interface: &str) -> crate::types::server::Server {
        use crate::types::addr::MySockAddr;
        use crate::types::server::Server;

        let addr = MySockAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
        Server {
            flags: 0,
            domain: String::new(),
            source_addr: addr.clone(),
            addr,
            interface: interface.to_string(),
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
            #[cfg(feature = "loop")]
            uid: 0,
        }
    }

    #[cfg(feature = "dhcp")]
    fn test_dhcp_context() -> crate::types::dhcp::DhcpContext {
        use crate::types::dhcp::{DhcpContext, DhcpNetid, CONTEXT_DHCP};

        DhcpContext {
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
        }
    }

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
    fn drop_privileges_succeeds_for_the_current_user() {
        let uid = nix::unistd::getuid().as_raw();
        let gid = nix::unistd::getgid().as_raw();
        // Unprivileged: a pure no-op, since there is nothing to drop to.  As
        // root it really does run setgroups(0)/setgid, which is upstream's
        // behavior for `--user root` and must still succeed.
        drop_privileges(uid, gid).expect("drop_privileges failed for current user");
    }

    #[test]
    fn drop_privileges_with_empty_run_as_is_a_noop() {
        // Nothing configured — upstream skips both setgid and setuid.
        drop_privileges_with(&RunAs::default(), NeededCaps::default())
            .expect("an empty RunAs should not attempt any syscall");
    }

    // ── pid file ─────────────────────────────────────────────────────────────

    #[test]
    fn write_pid_file_replaces_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dnsmasq.pid");
        let path_str = path.to_str().unwrap();

        std::fs::write(&path, "99999\n").unwrap();
        write_pid_file(path_str, 4242).expect("write_pid_file failed");
        assert_eq!(read_pid_file(path_str).unwrap(), 4242);
    }

    /// dnsmasq.c:680-694 — the pid file is unlinked and reopened with `O_EXCL`
    /// so that a symlink planted by the (unprivileged) run user cannot be
    /// followed and have its target overwritten as root.
    #[test]
    fn write_pid_file_does_not_follow_a_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join("victim");
        let link = dir.path().join("dnsmasq.pid");
        std::fs::write(&victim, "precious\n").unwrap();
        std::os::unix::fs::symlink(&victim, &link).unwrap();

        write_pid_file(link.to_str().unwrap(), 4242).expect("write_pid_file failed");

        assert_eq!(
            std::fs::read_to_string(&victim).unwrap(),
            "precious\n",
            "the symlink target must not have been written through"
        );
        assert_eq!(read_pid_file(link.to_str().unwrap()).unwrap(), 4242);
        assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    }

    #[test]
    fn write_pid_file_is_world_readable() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dnsmasq.pid");
        write_pid_file(path.to_str().unwrap(), 1).expect("write_pid_file failed");

        // S_IWUSR|S_IRUSR|S_IRGRP|S_IROTH (dnsmasq.c:684).  The umask still
        // applies — it does to upstream's `open()` too — so assert on what the
        // umask cannot add rather than on the exact 0644: the owner must be
        // able to read and write it, and nobody may gain write or execute.
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o600, 0o600, "owner needs rw on the pid file, got {mode:o}");
        assert_eq!(mode & 0o133, 0, "pid file must not be executable or group/other-writable, got {mode:o}");
        assert_eq!(mode & !0o644, 0, "pid file mode must be a subset of 0644, got {mode:o}");
    }

    #[test]
    fn write_pid_file_reports_an_unwritable_directory() {
        let err = write_pid_file("/proc/dnsmasq_rs_no_such_dir/pid", 1).unwrap_err();
        assert!(matches!(err, DnsmasqError::PidFile(_)));
    }

    // ── run-as resolution (dnsmasq.c:499-517) ────────────────────────────────

    #[test]
    fn resolve_run_as_rejects_an_unknown_user() {
        let daemon = Daemon {
            username: Some("dnsmasq-rs-definitely-no-such-user".into()),
            ..Default::default()
        };
        let err = resolve_run_as(&daemon).unwrap_err().to_string();
        assert!(err.contains("unknown user or group"), "unexpected message: {err}");
    }

    #[test]
    fn resolve_run_as_rejects_an_unknown_group() {
        let daemon = Daemon {
            username: None,
            groupname: Some("dnsmasq-rs-definitely-no-such-group".into()),
            ..Default::default()
        };
        let err = resolve_run_as(&daemon).unwrap_err().to_string();
        assert!(err.contains("unknown user or group"), "unexpected message: {err}");
    }

    /// With no `user=` there is no uid to drop to, and no primary group to fall
    /// back to either — but upstream still looks `CHGRP` up unconditionally, so
    /// a gid may or may not come out depending on whether the host has it.
    #[test]
    fn resolve_run_as_without_a_user_resolves_no_uid() {
        let run_as = resolve_run_as(&Daemon::default()).expect("no user is not an error");
        assert_eq!(run_as.uid, None);
        assert_eq!(run_as.username, None);
        match nix::unistd::Group::from_name(CHGRP).ok().flatten() {
            Some(gr) => assert_eq!(run_as.gid, Some(gr.gid.as_raw()), "expected the {CHGRP} group"),
            None => assert_eq!(run_as.gid, None, "no {CHGRP} and no user: nothing to fall back to"),
        }
    }

    /// "root" is the one account guaranteed to exist, so it is what we can pin
    /// the happy path against without depending on the host's user database.
    #[test]
    fn resolve_run_as_resolves_a_known_user_and_defaults_the_group() {
        let daemon = Daemon { username: Some("root".into()), ..Default::default() };
        let run_as = resolve_run_as(&daemon).expect("root should resolve");
        assert_eq!(run_as.uid, Some(0));
        assert_eq!(run_as.username.as_deref(), Some("root"));
        // Either CHGRP exists, or we fall back to root's primary group; both
        // yield a gid.  Which one it is depends on the host.
        assert!(run_as.gid.is_some(), "the group should have been defaulted");
        if nix::unistd::Group::from_name(CHGRP).ok().flatten().is_none() {
            assert_eq!(run_as.gid, Some(0), "no {CHGRP} group: expected root's primary group");
        }
    }

    #[test]
    fn resolve_run_as_prefers_an_explicit_group_over_the_default() {
        let Ok(Some(root_group)) = nix::unistd::Group::from_gid(nix::unistd::Gid::from_raw(0))
        else {
            eprintln!("skipping: gid 0 has no name on this system");
            return;
        };
        let daemon = Daemon {
            username: Some("root".into()),
            groupname: Some(root_group.name.clone()),
            ..Default::default()
        };
        let run_as = resolve_run_as(&daemon).expect("root group should resolve");
        assert_eq!(run_as.gid, Some(0));
        assert_eq!(run_as.groupname.as_deref(), Some(root_group.name.as_str()));
    }

    // ── capability requirements (dnsmasq.c:326-333, 537-540) ─────────────────

    #[test]
    fn needed_capabilities_empty_for_a_plain_resolver() {
        assert!(needed_capabilities(&Daemon::default()).is_empty());
    }

    #[test]
    fn needed_capabilities_wants_net_raw_for_an_interface_bound_server() {
        let mut daemon = Daemon::default();
        daemon.servers.push(test_server(""));
        assert!(needed_capabilities(&daemon).is_empty(), "a plain server needs nothing");

        daemon.servers.push(test_server("eth0"));
        let caps = needed_capabilities(&daemon);
        assert!(caps.net_raw, "SO_BINDTODEVICE per TCP connection needs CAP_NET_RAW");
        assert!(!caps.net_admin);
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn needed_capabilities_for_dhcp_follows_no_ping() {
        use crate::types::constants::OPT_NO_PING;

        let mut daemon = Daemon::default();
        daemon.dhcp.push(test_dhcp_context());

        let caps = needed_capabilities(&daemon);
        assert!(caps.net_admin, "ARP injection needs CAP_NET_ADMIN");
        assert!(caps.net_raw, "the conflict-detection ping needs CAP_NET_RAW");

        daemon.set_option(OPT_NO_PING);
        let caps = needed_capabilities(&daemon);
        assert!(caps.net_admin);
        assert!(!caps.net_raw, "--no-ping removes the only CAP_NET_RAW user");
    }

    // ── pre-bound listeners ──────────────────────────────────────────────────

    /// Binding is what `main` does before the fork and before `setuid`.  Port 0
    /// keeps this runnable without privileges.
    #[test]
    fn bind_listeners_binds_the_dns_socket_before_the_runtime_exists() {
        let daemon = Daemon { port: 0, ..Default::default() };
        let listeners = bind_listeners(&daemon).expect("binding port 0 should always work");
        let addrs = listeners.dns_addrs();
        assert!(!addrs.is_empty(), "at least one DNS socket must be bound");
        assert!(
            addrs.iter().all(|a| a.port() != 0),
            "the kernel should have assigned a port: {addrs:?}"
        );
    }

    /// With no interface config at all the daemon listens on the wildcard
    /// addresses, exactly as upstream's `create_wildcard_listeners()` does.
    #[test]
    fn bind_listeners_defaults_to_the_wildcard_addresses() {
        let listeners = bind_listeners(&Daemon { port: 0, ..Default::default() }).unwrap();
        let addrs = listeners.dns_addrs();
        assert!(
            addrs.iter().all(|a| a.ip().is_unspecified()),
            "an unconfigured daemon binds only wildcard addresses, got {addrs:?}"
        );
    }

    #[test]
    fn bind_listeners_reports_a_port_already_in_use() {
        let held = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
        let port = held.local_addr().unwrap().port();

        let daemon = Daemon { port, ..Default::default() };
        let err = bind_listeners(&daemon).unwrap_err();
        assert!(matches!(err, DnsmasqError::Bind(..)), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn run_main_loop_serves_on_a_pre_bound_socket() {
        let listeners = bind_listeners(&Daemon { port: 0, ..Default::default() }).unwrap();
        let port = listeners
            .dns_addrs()
            .first()
            .map(|a| a.port())
            .expect("a socket must be bound");

        let daemon = Daemon { port, ..Default::default() };
        let daemon_handle = init_daemon_with(daemon);
        let cache = build_shared_cache(&daemon_handle).await;
        let task = tokio::spawn(run_main_loop_with(
            daemon_handle,
            None,
            Some(listeners),
            cache,
        ));

        // If the pre-bound socket were dropped and rebound, this would race or
        // fail; if it is adopted, the port stays claimed for the whole run.
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!task.is_finished(), "the loop should still be serving");
        assert!(
            std::net::UdpSocket::bind(("0.0.0.0", port)).is_err(),
            "port {port} should still be held by the adopted socket"
        );
        task.abort();
    }

    #[test]
    fn startup_pipe_disabled_has_no_write_end() {
        assert!(StartupPipe::disabled().write_fd.is_none());
    }

    // ── local-data snapshot ───────────────────────────────────────────────────

    #[test]
    fn daemon_local_data_carries_every_record_kind() {
        use crate::types::dns_records::{
            Cname, HostRecord, InterfaceName, MxSrvRecord, Naptr, PtrRecord, TxtRecord,
        };

        let mut daemon = Daemon { local_ttl: 60, ..Default::default() };
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
        daemon.int_names.push(InterfaceName {
            name: "router.lan".into(), intr: "eth0".into(), flags: 0,
            proto4: None, proto6: None, addrs: vec![],
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
        assert_eq!(local.int_names.len(), 1);
        assert!(!local.is_empty());
    }

    #[test]
    fn daemon_local_data_empty_by_default() {
        assert!(daemon_local_data(&Daemon::default()).is_empty());
    }

    /// Every knob `process_reply` consults has to survive the trip from a
    /// parsed `Daemon` into `ForwardConfig`, or the directive behind it is a
    /// silent no-op at run time.
    ///
    /// The end-to-end coverage for these lives in
    /// `tests/reply_processing_integration.rs`, but every test there skips when
    /// the environment forbids binding loopback sockets — this one does not, so
    /// the threading stays pinned in a restricted sandbox.
    #[test]
    fn daemon_forward_config_carries_the_reply_policy() {
        let lines = crate::option::parse_config_text(
            "bogus-nxdomain=64.94.110.11\n\
             ignore-address=198.51.100.9\n\
             filter-rr=CAA\n\
             filter-AAAA\n\
             dnssec\n\
             proxy-dnssec\n\
             stop-dns-rebind\n",
            "test",
        )
        .unwrap();
        let mut daemon = Daemon::default();
        crate::option::apply_config(&mut daemon, &lines).unwrap();

        let config = daemon_forward_config(&daemon);
        assert_eq!(config.bogus_addr.len(), 1, "--bogus-nxdomain must reach the reply path");
        assert_eq!(config.ignore_addr.len(), 1, "--ignore-address must reach the reply path");
        assert_eq!(config.filter_rr, vec![257, 28], "--filter-rr and --filter-AAAA both land");
        assert!(config.dnssec_valid, "--dnssec gates the reply-side DNSSEC handling");
        assert!(config.dnssec_proxy, "--proxy-dnssec must be readable");
        assert!(config.check_rebind);
    }

    /// End-to-end: `rev-server=192.168.1.0/24,10.0.0.1` must make a
    /// `ForwardEngine` built from `daemon_forward_config` actually pick
    /// `10.0.0.1` for a PTR query in that subnet — not round-robin it
    /// against whatever other upstream happens to be configured.  This is
    /// the acceptance bar for `rev-server`: parsing into `Daemon.servers`
    /// alone is not enough without this wiring.
    #[test]
    fn rev_server_delegates_reverse_lookups_to_its_own_upstream() {
        let lines = crate::option::parse_config_text(
            "server=8.8.8.8\nrev-server=192.168.1.0/24,10.0.0.1\n",
            "test",
        )
        .unwrap();
        let mut daemon = Daemon::default();
        crate::option::apply_config(&mut daemon, &lines).unwrap();

        let config = daemon_forward_config(&daemon);
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.server_domains, vec![String::new(), "1.168.192.in-addr.arpa".to_string()]);

        let mut engine = crate::forward::ForwardEngine::new(config);
        let mut ptr_query: Vec<u8> = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        for label in "1.1.168.192.in-addr.arpa".split('.') {
            ptr_query.push(label.len() as u8);
            ptr_query.extend_from_slice(label.as_bytes());
        }
        ptr_query.push(0);
        ptr_query.extend_from_slice(&12u16.to_be_bytes()); // PTR
        ptr_query.extend_from_slice(&1u16.to_be_bytes());  // IN

        let candidates = engine.candidate_servers(&ptr_query);
        assert_eq!(candidates.len(), 1);
        assert_eq!(engine.config.upstreams[candidates[0]], "10.0.0.1:53".parse::<std::net::SocketAddr>().unwrap());
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

        daemon.lease_file = Some("/tmp/test-dnsmasq.leases".into());

        let runtime = daemon_dhcp_runtime(&daemon).expect("dhcp runtime should be built");
        assert_eq!(runtime.bind_addr, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 1067)));
        assert_eq!(runtime.server.pool_start, Ipv4Addr::new(10, 0, 0, 100));
        assert_eq!(runtime.server.pool_end, Ipv4Addr::new(10, 0, 0, 150));
        assert_eq!(runtime.server.server_ip, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(runtime.server.reply_delays.len(), 1);
        assert_eq!(runtime.loop_opts.reply_port_override, None);
        assert_eq!(runtime.server.lease_file.as_deref(), Some("/tmp/test-dnsmasq.leases"));
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

    /// Regression test for a bug where a configured non-split `dhcp-relay`
    /// never fired: `relay_upstream4`'s `relay.iface_index != 0` guard
    /// (`src/rfc2131.rs`) only matches once something binds `iface_index` to
    /// the interface owning `relay.local`, mirroring upstream's
    /// `complete_context` (`dhcp.c:669-673`). `daemon_dhcp_runtime` must do
    /// that binding itself since nothing else in this runtime does.
    #[cfg(feature = "dhcp")]
    #[test]
    fn daemon_dhcp_runtime_binds_relay_iface_index_to_matching_local_addr() {
        use crate::types::addr::AllAddr;
        use crate::types::dhcp::{DhcpContext, DhcpNetid, DhcpRelay, CONTEXT_DHCP};
        use crate::types::network::Iname;

        let mut daemon = Daemon::default();
        daemon.if_addrs.push(Iname {
            name: None,
            addr: Some(MySockAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
            flags: 0,
        });
        daemon.if_names.push(Iname { name: Some("lo".into()), addr: None, flags: 0 });
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

        // Matches the bound interface's own address: should get iface_index bound.
        daemon.relay4.push(DhcpRelay {
            local_addr: AllAddr::Addr4(Ipv4Addr::LOCALHOST),
            server_addr: AllAddr::Addr4(Ipv4Addr::new(10, 0, 0, 1)),
            uplink_addr: AllAddr::Addr4(Ipv4Addr::UNSPECIFIED),
            interface: None,
            iface_index: 0,
            port: i32::from(crate::dhcp_protocol::DHCP_SERVER_PORT),
            split_mode: 0,
            warned: 0,
            matchcount: 0,
        });
        // Doesn't match the bound interface's address: must stay unbound.
        daemon.relay4.push(DhcpRelay {
            local_addr: AllAddr::Addr4(Ipv4Addr::new(10, 9, 9, 9)),
            server_addr: AllAddr::Addr4(Ipv4Addr::new(10, 0, 0, 1)),
            uplink_addr: AllAddr::Addr4(Ipv4Addr::UNSPECIFIED),
            interface: None,
            iface_index: 0,
            port: i32::from(crate::dhcp_protocol::DHCP_SERVER_PORT),
            split_mode: 0,
            warned: 0,
            matchcount: 0,
        });

        let runtime = daemon_dhcp_runtime(&daemon).expect("dhcp runtime should be built");
        let expected_index = crate::network::nametoindex("lo") as i32;
        if expected_index == 0 {
            // No usable "lo" in this sandbox; nothing to assert against.
            return;
        }
        assert_eq!(runtime.server.relay4[0].iface_index, expected_index);
        assert_eq!(runtime.server.relay4[1].iface_index, 0);
    }

    // ── SIGHUP reload ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn on_sighup_does_not_panic() {
        let handle = init_daemon();
        let cache = crate::cache::new_shared_cache(150, 0, 0);
        // Should run without panic; cache clear is a no-op on empty cache.
        on_sighup(&handle, &cache).await;
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
        let cache = crate::cache::new_shared_cache(150, 0, 0);
        {
            let d = handle.read().await;
            assert!(!d.dns_dirty);
        }

        clear_cache_and_reload(&handle, &cache).await;

        let d = handle.read().await;
        assert!(d.dns_dirty);
    }

    #[tokio::test]
    async fn clear_cache_and_reload_flushes_a_live_forwarded_answer() {
        use crate::cache::CacheRecord;
        use crate::types::addr::AllAddr;
        use crate::types::constants::{F_IPV4, OPT_NO_HOSTS};

        let handle = init_daemon();
        // Isolate this test from whatever /etc/hosts happens to contain on
        // the machine running it.
        handle.write().await.set_option(OPT_NO_HOSTS);
        let cache = crate::cache::new_shared_cache(150, 0, 0);
        {
            let mut c = cache.lock().await;
            c.insert(CacheRecord {
                name: "forwarded.test".to_string(),
                flags: F_IPV4,
                addr: Some(AllAddr::Addr4(Ipv4Addr::new(192, 0, 2, 1))),
                rdata: None,
                ttl: 300,
                expires: Instant::now() + Duration::from_secs(300),
                uid: 0,
            });
            assert_eq!(c.len(), 1, "the answer must be in the cache before reload");
        }

        clear_cache_and_reload(&handle, &cache).await;

        let c = cache.lock().await;
        assert_eq!(c.len(), 0, "reload must flush a forwarded answer out of the live cache");
    }

    #[tokio::test]
    async fn clear_cache_and_reload_reloads_addn_hosts_into_the_cache() {
        use crate::types::network::HostsFile;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("extra.hosts");
        std::fs::write(&path, "192.0.2.9 reloaded.test\n").unwrap();

        let handle = init_daemon();
        {
            let mut d = handle.write().await;
            d.set_option(crate::types::constants::OPT_NO_HOSTS); // skip the real /etc/hosts
            d.addn_hosts.push(HostsFile {
                flags: 0,
                fname: path.to_str().unwrap().to_string(),
                index: 0,
            });
        }
        let cache = crate::cache::new_shared_cache(150, 0, 0);

        clear_cache_and_reload(&handle, &cache).await;

        let mut c = cache.lock().await;
        let now = Instant::now();
        assert!(
            c.lookup_by_name("reloaded.test", crate::types::constants::F_IPV4, now).is_some(),
            "reload must load --addn-hosts entries into the cache",
        );
    }

    #[tokio::test]
    async fn clear_cache_and_reload_reloads_resolv_file_servers() {
        use crate::types::network::Resolvc;
        use crate::types::server::SERV_FROM_RESOLV;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 198.51.100.9\n").unwrap();

        let handle = init_daemon();
        {
            let mut d = handle.write().await;
            d.resolv_files.push(Resolvc {
                is_default: false,
                logged: false,
                mtime: 0,
                ino: 0,
                name: path.to_str().unwrap().to_string(),
                #[cfg(feature = "inotify")]
                wd: -1,
                #[cfg(feature = "inotify")]
                file: None,
            });
        }
        let cache = crate::cache::new_shared_cache(150, 0, 0);

        clear_cache_and_reload(&handle, &cache).await;

        let d = handle.read().await;
        assert!(
            d.servers.iter().any(|s| {
                s.flags & SERV_FROM_RESOLV != 0
                    && SocketAddr::from(s.addr.clone())
                        == SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)), 53)
            }),
            "reload must add the resolv-file server, got {:?}",
            d.servers.iter().map(|s| (s.flags, s.addr.clone())).collect::<Vec<_>>(),
        );
    }

    /// A resolv-file read failure must not wipe the servers a previous,
    /// successful reload already discovered — upstream's `reload_servers()`
    /// leaves the list untouched when `fopen` fails, before `mark_servers()`
    /// ever runs (`network.c:1699-1709`).
    #[tokio::test]
    async fn clear_cache_and_reload_preserves_servers_when_resolv_file_becomes_unreadable() {
        use crate::types::network::Resolvc;
        use crate::types::server::SERV_FROM_RESOLV;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 198.51.100.9\n").unwrap();

        let handle = init_daemon();
        {
            let mut d = handle.write().await;
            d.resolv_files.push(Resolvc {
                is_default: false,
                logged: false,
                mtime: 0,
                ino: 0,
                name: path.to_str().unwrap().to_string(),
                #[cfg(feature = "inotify")]
                wd: -1,
                #[cfg(feature = "inotify")]
                file: None,
            });
        }
        let cache = crate::cache::new_shared_cache(150, 0, 0);

        clear_cache_and_reload(&handle, &cache).await;
        {
            let d = handle.read().await;
            assert_eq!(
                d.servers.iter().filter(|s| s.flags & SERV_FROM_RESOLV != 0).count(),
                1,
                "the server must be discovered on the first, successful reload",
            );
        }

        // The file goes away between reloads (e.g. a momentarily-missing,
        // mid-rewrite resolv.conf): the read fails, and the previously
        // discovered server must survive rather than being wiped.
        std::fs::remove_file(&path).unwrap();
        clear_cache_and_reload(&handle, &cache).await;

        let d = handle.read().await;
        assert_eq!(
            d.servers.iter().filter(|s| s.flags & SERV_FROM_RESOLV != 0).count(),
            1,
            "a failed resolv-file read must not empty the existing resolv-derived server list",
        );
    }

    #[tokio::test]
    async fn clear_cache_and_reload_idempotent() {
        let handle = init_daemon();
        let cache = crate::cache::new_shared_cache(150, 0, 0);
        clear_cache_and_reload(&handle, &cache).await;
        clear_cache_and_reload(&handle, &cache).await;

        let d = handle.read().await;
        assert!(d.dns_dirty);
    }

    /// A no-op reload (nothing on disk changed) must leave the resolv-derived
    /// server list stable rather than duplicating it — the acceptance
    /// criterion for "repeated SIGHUP is stable and idempotent".
    #[tokio::test]
    async fn clear_cache_and_reload_resolv_servers_do_not_accumulate_across_reloads() {
        use crate::types::network::Resolvc;
        use crate::types::server::SERV_FROM_RESOLV;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 198.51.100.9\n").unwrap();

        let handle = init_daemon();
        {
            let mut d = handle.write().await;
            d.resolv_files.push(Resolvc {
                is_default: false,
                logged: false,
                mtime: 0,
                ino: 0,
                name: path.to_str().unwrap().to_string(),
                #[cfg(feature = "inotify")]
                wd: -1,
                #[cfg(feature = "inotify")]
                file: None,
            });
        }
        let cache = crate::cache::new_shared_cache(150, 0, 0);

        clear_cache_and_reload(&handle, &cache).await;
        clear_cache_and_reload(&handle, &cache).await;
        clear_cache_and_reload(&handle, &cache).await;

        let d = handle.read().await;
        let resolv_derived =
            d.servers.iter().filter(|s| s.flags & SERV_FROM_RESOLV != 0).count();
        assert_eq!(
            resolv_derived, 1,
            "an unchanged resolv file must not accumulate duplicate server entries",
        );
    }

    /// Explicit `--server=` entries are not `SERV_FROM_RESOLV` and must survive
    /// a reload untouched, even when a resolv-file is also configured.
    #[tokio::test]
    async fn clear_cache_and_reload_keeps_explicitly_configured_servers() {
        let handle = init_daemon();
        {
            let mut d = handle.write().await;
            d.servers.push(test_server("eth0"));
        }
        let cache = crate::cache::new_shared_cache(150, 0, 0);

        clear_cache_and_reload(&handle, &cache).await;

        let d = handle.read().await;
        assert_eq!(d.servers.len(), 1, "an explicit server must not be dropped by reload");
        assert_eq!(d.servers[0].interface, "eth0");
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
        let cache = crate::cache::new_shared_cache(150, 0, 0);
        {
            let d = handle.read().await;
            assert_eq!(d.reload_count, 0);
            assert!(!d.dns_dirty);
        }

        on_sighup(&handle, &cache).await;

        let d = handle.read().await;
        assert!(d.dns_dirty);
        assert_eq!(d.reload_count, 1);
    }

    #[tokio::test]
    async fn on_sighup_increments_reload_count_each_time() {
        let handle = init_daemon();
        let cache = crate::cache::new_shared_cache(150, 0, 0);

        on_sighup(&handle, &cache).await;
        on_sighup(&handle, &cache).await;
        on_sighup(&handle, &cache).await;

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

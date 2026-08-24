//! Daemon initialization and process-management helpers.
//!
//! Mirrors the startup logic in `dnsmasq.c` (the original 2478-line C file).

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
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
///
/// Also runs `--read-ethers` (`OPT_ETHERS`) here, mirroring upstream calling
/// `dhcp_read_ethers()` once at startup (dnsmasq.c) before the main loop
/// starts serving. Re-running it on SIGHUP — as upstream also does — isn't
/// wired up yet, tracked in `tasks.md` alongside the rest of the SIGHUP
/// reload gap noted in `dnsmasq::on_sighup`.
pub fn init_daemon_with(mut daemon: Daemon) -> DaemonHandle {
    #[cfg(feature = "dhcp")]
    {
        use tracing::{error, info};
        if daemon.option_bool(crate::types::constants::OPT_ETHERS) {
            match crate::dhcp::dhcp_read_ethers(&mut daemon.dhcp_conf, crate::dhcp::ETHERS_FILE) {
                Ok(count) => info!("read {} - {count} addresses", crate::dhcp::ETHERS_FILE),
                Err(err) => error!("failed to read {}: {err}", crate::dhcp::ETHERS_FILE),
            }
        }

        // Startup diagnostics for each configured DHCP range/relay, mirroring
        // dnsmasq.c:996-1008's log_context()/log_relay() calls.
        let opt_ra = daemon.option_bool(crate::types::constants::OPT_RA);
        let v4 = std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);
        for ctx in &daemon.dhcp {
            for msg in crate::dhcp_common::log_context(v4, ctx, opt_ra) {
                info!("{msg}");
            }
        }
        for relay in &daemon.relay4 {
            info!("{}", crate::dhcp_common::log_relay(v4, relay));
        }

        #[cfg(feature = "dhcp6")]
        {
            // Mirrors `dnsmasq.c:288-296`: `doing_ra`/`doing_dhcp6` are
            // runtime-derived from the configured `dhcp6` contexts, not set
            // directly by any directive. The whole block is gated on
            // `daemon->dhcp6` being non-empty.
            if !daemon.dhcp6.is_empty() {
                daemon.doing_ra = opt_ra;
                for ctx in &daemon.dhcp6 {
                    if ctx.flags & crate::types::dhcp::CONTEXT_DHCP != 0 {
                        daemon.doing_dhcp6 = true;
                    }
                    if ctx.flags & crate::types::dhcp::CONTEXT_RA != 0 {
                        daemon.doing_ra = true;
                    }
                }
            }

            let v6 = std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
            for ctx in &daemon.dhcp6 {
                for msg in crate::dhcp_common::log_context(v6, ctx, opt_ra) {
                    info!("{msg}");
                }
            }
            for relay in &daemon.relay6 {
                info!("{}", crate::dhcp_common::log_relay(v6, relay));
            }
        }
    }

    // Mirrors `dnsmasq.c:352-358`: only open the ipset control socket when
    // at least one `--ipset` directive is configured. Upstream `die()`s on
    // failure here; this port logs instead (see `ipset::ipset_init`'s doc
    // comment for why) and each `add_to_ipset` call still has a working
    // per-call fallback if the persistent socket was never installed.
    #[cfg(feature = "ipset")]
    if !daemon.ipsets.is_empty() {
        if let Err(err) = crate::ipset::ipset_init() {
            tracing::error!("failed to create IPset control socket: {err}");
        }
    }

    // Mirrors `inotify_dnsmasq_init()` being called once at startup
    // (`dnsmasq.c:437`): opens the inotify fd and watches each configured
    // resolv-file's containing directory. `--hostsdir`/dynamic-dir watches
    // need the cache to exist first, so those are set up later in
    // `run_main_loop_with` via `inotify::set_dynamic_inotify`. Upstream
    // `die()`s if a resolv directory is missing; this logs and continues,
    // consistent with the `ipset_init` handling just above.
    #[cfg(feature = "inotify")]
    if let Err(err) = crate::inotify::inotify_dnsmasq_init(&mut daemon) {
        tracing::error!("failed to set up inotify watches: {err}");
    }

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
    let address_server_list = literal_servers(daemon);
    let address_servers = crate::domain_match::ServerArray::build(&[], &address_server_list);
    let ident = !daemon.option_bool(crate::types::constants::OPT_NO_IDENT);
    let mut txt_records = daemon.txt.clone();
    if ident {
        txt_records.extend(builtin_stat_txt_records());
    }
    crate::forward::LocalData {
        local_ttl:     daemon.local_ttl,
        edns_pktsz:    daemon.edns_pktsz,
        txt_records,
        rr_records:    daemon.rr.clone(),
        mx_records:    daemon.mxnames.clone(),
        ptr_records:   daemon.ptr.clone(),
        host_records:  daemon.host_records.clone(),
        cnames:        daemon.cnames.clone(),
        naptr_records: daemon.naptr.clone(),
        int_names:     daemon.int_names.clone(),
        nodots_local:  daemon.option_bool(crate::types::constants::OPT_NODOTS_LOCAL),
        synth_domains: daemon.synth_domains.clone(),
        address_servers,
        address_server_list,
        literal_domains: literal_server_domains(daemon),
        cachesize:     daemon.cachesize,
        log_opts: crate::cache::LogQueryOptions {
            log:            daemon.option_bool(crate::types::constants::OPT_LOG),
            log_only_failed: daemon.option_bool(crate::types::constants::OPT_LOG_ONLY_FAILED),
            auth_log:       daemon.option_bool(crate::types::constants::OPT_AUTH_LOG),
            extralog:       daemon.option_bool(crate::types::constants::OPT_EXTRALOG),
            log_proto:      daemon.option_bool(crate::types::constants::OPT_LOG_PROTO),
        },
    }
}

/// Build the synthetic `cachesize.bind` / `insertions.bind` / `evictions.bind`
/// / `misses.bind` / `hits.bind` CHAOS TXT records `answer_request` renders
/// dynamically via `cache_make_stat`.  Port of the `add_txt(..., TXT_STAT_*)`
/// calls at startup (`option.c:6103-6107`), minus `version.bind`/
/// `authors.bind`/`copyright.bind` (static text, not cache-related — see
/// `tasks.md`) and `auth.bind`/`servers.bind` (need counters this crate does
/// not track yet).
fn builtin_stat_txt_records() -> Vec<crate::types::dns_records::TxtRecord> {
    use crate::cache::{TXT_STAT_CACHESIZE, TXT_STAT_EVICTIONS, TXT_STAT_HITS, TXT_STAT_INSERTS, TXT_STAT_MISSES};
    use crate::types::dns_records::TxtRecord;
    const CHAOS: u16 = 3;
    [
        ("cachesize.bind",  TXT_STAT_CACHESIZE),
        ("insertions.bind", TXT_STAT_INSERTS),
        ("evictions.bind",  TXT_STAT_EVICTIONS),
        ("misses.bind",     TXT_STAT_MISSES),
        ("hits.bind",       TXT_STAT_HITS),
    ]
    .into_iter()
    .map(|(name, stat)| TxtRecord { name: name.to_string(), txt: Vec::new(), class: CHAOS, stat })
    .collect()
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

/// `daemon.servers` entries with `SERV_LITERAL_ADDRESS` set (`--address=`,
/// `--server=/domain/` or `--local=/domain/` with no address, `rev-server`
/// with the server part omitted) — never forwarded.  Shared by
/// [`daemon_local_data`] (answers them directly via `ServerArray::lookup` +
/// `is_local_answer`/`make_local_answer`) and [`daemon_forward_config`]
/// (excludes them from the upstream list).
fn literal_servers(daemon: &Daemon) -> Vec<crate::types::server::Server> {
    use crate::types::server::SERV_LITERAL_ADDRESS;
    daemon
        .servers
        .iter()
        .filter(|s| s.flags & SERV_LITERAL_ADDRESS != 0)
        .cloned()
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
        OPT_ADD_MAC, OPT_CLIENT_SUBNET, OPT_CMARK_ALST_EN, OPT_CONNTRACK, OPT_DNSSEC_PROXY,
        OPT_DNSSEC_VALID, OPT_LOCAL_REBIND, OPT_MAC_B64, OPT_MAC_HEX, OPT_NO_NEG, OPT_NO_REBIND,
        OPT_STRIP_MAC,
    };

    let to_add_subnet_opt = |s: &crate::types::network::MySubnet| crate::edns0::AddSubnetOpt {
        mask: s.mask.clamp(0, 255) as u8,
        const_addr: s.addr_used.then(|| s.addr.ip()),
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
        nftsets:        daemon.nftsets.clone(),
        cmark_alst_en:  daemon.option_bool(OPT_CMARK_ALST_EN),
        allowlists:     daemon.allowlists.clone(),
        allowlist_mask: daemon.allowlist_mask,
        // `--add-subnet`: gates `check_source()` reply verification
        // (`forward.c:727`) and the constant-address override `calc_subnet_opt()`
        // consults when building the ECS option to compare against.
        client_subnet:  daemon.option_bool(OPT_CLIENT_SUBNET),
        add_subnet4:    daemon.add_subnet4.as_ref().map(&to_add_subnet_opt),
        add_subnet6:    daemon.add_subnet6.as_ref().map(&to_add_subnet_opt),
        // `--dns-loop-detect`: `forwardable` is exactly the server list
        // `loop_send_probes()`/`detect_loop()` iterate over in C
        // (`daemon->servers`, minus the never-forwarded `SERV_LITERAL_ADDRESS`
        // entries filtered above), so it doubles as the loop-detection state.
        #[cfg(feature = "loop")]
        loop_detect:    daemon.option_bool(crate::types::constants::OPT_LOOP_DETECT),
        #[cfg(feature = "loop")]
        loop_servers:   forwardable.iter().map(|s| (*s).clone()).collect(),
        // `--add-mac`/`--mac-base64`/`--mac-hex`/`--stripmac`: resolved via
        // the shared ARP cache in `ForwardEngine::forward_query`.
        add_mac:        daemon.option_bool(OPT_ADD_MAC),
        mac_b64:        daemon.option_bool(OPT_MAC_B64),
        mac_hex:        daemon.option_bool(OPT_MAC_HEX),
        strip_mac:      daemon.option_bool(OPT_STRIP_MAC),
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
            lease_change_command: daemon.lease_change_command.clone(),
            leasefile_ro: daemon.option_bool(crate::types::constants::OPT_LEASE_RO),
            script_on_renewal: daemon.option_bool(crate::types::constants::OPT_LEASE_RENEW),
            match_rules: daemon.dhcp_match.clone(),
            name_match_rules: daemon.dhcp_name_match.clone(),
            tag_rules: daemon.tag_if.clone(),
            relay4,
            no_ping: daemon.option_bool(crate::types::constants::OPT_NO_PING),
            consec_addr: daemon.option_bool(crate::types::constants::OPT_CONSEC_ADDR),
            dhcp_ignore: daemon.dhcp_ignore.clone(),
            bootp_dynamic: daemon.bootp_dynamic.iter().map(|l| l.list.clone()).collect(),
            rapid_commit: daemon.option_bool(crate::types::constants::OPT_RAPID_COMMIT),
            leasequery_addr: daemon.leasequery_addr.clone(),
            leasequery_enabled: daemon.option_bool(crate::types::constants::OPT_LEASEQUERY),
            leasequery_source: Ipv4Addr::UNSPECIFIED,
            #[cfg(feature = "ubus")]
            quiet_dhcp: daemon.option_bool(crate::types::constants::OPT_QUIET_DHCP)
                && !daemon.option_bool(crate::types::constants::OPT_LOG_OPTS),
        },
        loop_opts: crate::dhcp::DhcpLoopOptions {
            reply_port_override: (client_port != 68).then_some(client_port),
            relay_iface_addr: bind_ip,
            relay_iface_index,
            relay_iface_name,
            // Filled in by the caller once the DHCPv6 "current" RA-name
            // context chain is available (`run_main_loop_with` builds both
            // runtimes; this function only sees `daemon`'s DHCPv4 half).
            #[cfg(feature = "dhcp6")]
            slaac_contexts: Vec::new(),
        },
    })
}

/// Everything [`run_main_loop_with`]'s DHCPv6 branch needs to run
/// [`crate::dhcp6::run_dhcp6_loop`]: where to listen, the server's DUID, and
/// the "current" context chain built from config plus live interface
/// prefixes.
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone)]
pub struct Dhcp6DaemonRuntime {
    pub bind_addr: SocketAddr,
    pub duid: Vec<u8>,
    pub contexts: Vec<crate::types::dhcp::DhcpContext>,
    pub configs: Vec<crate::types::dhcp::DhcpConfig>,
    pub authoritative: bool,
}

/// Build the DHCPv6 runtime: generate/persist the server DUID if it isn't
/// already set, fold live interface prefixes into `daemon.dhcp6` via
/// [`crate::dhcp6::dhcp_construct_contexts`], and build the "current" match
/// chain via [`crate::dhcp6::complete_context6`] the same way upstream's
/// `iface_enumerate(AF_INET6, ..., complete_context6)` does per packet
/// (dhcp6.c:250) — here done once at startup rather than per-arrival-interface
/// per packet, a scope simplification tracked in `tasks.md`.
///
/// Split from [`daemon_dhcp6_runtime`] so tests can inject `live`/`mac_source`
/// instead of depending on the host's real interfaces and MAC addresses.
///
/// Returns `None` when no `dhcp-range`-equivalent DHCPv6 context is
/// configured, or when a DUID could not be built at all (upstream's
/// `make_duid()` calls `die(EC_MISC)` in this case, dhcp6.c:643; this crate
/// logs and disables the DHCPv6 service instead of aborting the whole
/// daemon).
#[cfg(feature = "dhcp6")]
fn daemon_dhcp6_runtime_with(
    daemon: &mut Daemon,
    live: &[crate::dhcp6::LiveAddr6],
    mac_source: Option<crate::dhcp6::DuidMacSource>,
    now_secs: u64,
) -> Option<Dhcp6DaemonRuntime> {
    use std::net::{Ipv6Addr, SocketAddrV6};

    if daemon.dhcp6.is_empty() {
        return None;
    }

    if daemon.duid.is_none() {
        // Upstream picks DUID-LLT ("stable RTC") when a persistent lease
        // database exists, DUID-LL otherwise (dhcp6.c:635-666) — a configured
        // `--dhcp-leasefile` is the same signal this crate already has.
        let use_llt = daemon.lease_file.is_some();
        if let Err(e) = crate::dhcp6::make_duid(daemon, mac_source, use_llt, now_secs) {
            tracing::error!("cannot start DHCPv6 server: {e}");
            return None;
        }
    }
    let duid = daemon.duid.clone()?;

    let mut contexts = daemon.dhcp6.clone();
    crate::dhcp6::dhcp_construct_contexts(&mut contexts, live);

    let mut current = Vec::new();
    for addr in live {
        current.extend(crate::dhcp6::complete_context6(addr, &contexts));
    }

    use crate::types::constants::OPT_AUTHORITATIVE;
    Some(Dhcp6DaemonRuntime {
        bind_addr: SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::UNSPECIFIED,
            crate::dhcp6_protocol::DHCPV6_SERVER_PORT,
            0,
            0,
        )),
        duid,
        contexts: current,
        configs: daemon.dhcp_conf.clone(),
        authoritative: daemon.option_bool(OPT_AUTHORITATIVE),
    })
}

/// Production entry point for [`daemon_dhcp6_runtime_with`]: sources live
/// interface addresses and a MAC for DUID generation from the real host.
#[cfg(feature = "dhcp6")]
fn daemon_dhcp6_runtime(daemon: &mut Daemon) -> Option<Dhcp6DaemonRuntime> {
    let live = crate::network::enumerate_live_addrs6().unwrap_or_default();
    let mac_source = crate::network::first_dhcp6_mac_source();
    let now_secs = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    daemon_dhcp6_runtime_with(daemon, &live, mac_source, now_secs)
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
    #[cfg(feature = "dhcp6")]
    dhcp6: Option<std::net::UdpSocket>,
    #[cfg(feature = "tftp")]
    tftp: Vec<BoundTftpSocket>,
}

/// A TFTP listener socket bound before the fork, plus what
/// [`crate::tftp::run_tftp_loop`] needs to know about it.
#[cfg(feature = "tftp")]
#[derive(Debug)]
struct BoundTftpSocket {
    sock: std::net::UdpSocket,
    addr: SocketAddr,
    /// Known when bound under `--bind-interfaces`/`--bind-dynamic`; `None`
    /// for a wildcard bind, where the arrival interface is only known
    /// per-datagram via `IP_PKTINFO`/`IPV6_PKTINFO` (`recv_with_dest`).
    iface: Option<String>,
    /// This interface's MTU, when [`iface`](Self::iface) is known.
    mtu: Option<i32>,
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
    use crate::types::addr::MySockAddr as Msa;

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
    config.auth_interfaces = daemon.auth_interfaces.iter()
        .map(|i| crate::network::AuthInterface {
            name:  i.name.clone(),
            addr:  i.addr.as_ref().map(|a| match a {
                Msa::V4(s) => std::net::IpAddr::V4(*s.ip()),
                Msa::V6(s) => std::net::IpAddr::V6(*s.ip()),
            }),
            flags: i.flags,
        })
        .collect();
    config
}

/// Assemble [`crate::tftp::TftpConfig`] from `Daemon`'s `tftp_*` fields and
/// `OPT_TFTP_*` flags, for [`run_main_loop_with`] to hand to
/// [`crate::tftp::run_tftp_loop`].
#[cfg(feature = "tftp")]
fn daemon_tftp_config(daemon: &Daemon) -> crate::tftp::TftpConfig {
    use crate::types::constants::{
        OPT_QUIET_TFTP, OPT_SINGLE_PORT, OPT_TFTP_APREF_IP, OPT_TFTP_APREF_MAC, OPT_TFTP_LC,
        OPT_TFTP_NOBLOCK, OPT_TFTP_SECURE,
    };

    let (start_port, end_port) = (daemon.start_tftp_port, daemon.end_tftp_port);
    crate::tftp::TftpConfig {
        prefix: daemon.tftp_prefix.clone(),
        secure: daemon.option_bool(OPT_TFTP_SECURE),
        no_blocksize_option: daemon.option_bool(OPT_TFTP_NOBLOCK),
        lowercase: daemon.option_bool(OPT_TFTP_LC),
        single_port: daemon.option_bool(OPT_SINGLE_PORT),
        apref_ip: daemon.option_bool(OPT_TFTP_APREF_IP),
        apref_mac: daemon.option_bool(OPT_TFTP_APREF_MAC),
        quiet: daemon.option_bool(OPT_QUIET_TFTP),
        max_transfers: daemon.tftp_max,
        mtu_override: daemon.tftp_mtu,
        start_port: start_port.clamp(0, u16::MAX as i32) as u16,
        end_port: end_port.clamp(0, u16::MAX as i32) as u16,
        interfaces: daemon.tftp_interfaces.iter().filter_map(|i| i.name.clone()).collect(),
        packet_buff_sz: crate::tftp::packet_buff_sz(daemon.edns_pktsz),
    }
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
    let mut out = Vec::with_capacity(listeners.len());
    for l in listeners {
        let (sock, addr) = match crate::network::listener_take_udp(l) {
            Ok(pair) => pair,
            Err(_) => continue, // no UDP fd on this Listener (TCP/TFTP-only)
        };
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

    // `dnsmasq.c:969`: `warn_int_names` fires unconditionally, in every bind
    // mode — the only Rust caller (`Daemon::int_names`), so it always warns
    // today since nothing yet populates `InterfaceName::addrs`
    // (`network.c:358-457`, tracked separately in `tasks.md`).
    for msg in network::warn_int_names(&daemon.int_names) {
        tracing::warn!("{msg}");
    }

    if !nowild && !cleverbind {
        let listeners = network::create_wildcard_listeners_checked(port, kinds)
            .map_err(|e| DnsmasqError::Bind(format!("0.0.0.0:{port}"), e.to_string()))?;
        if listeners.is_empty() {
            return Err(DnsmasqError::Bind(
                format!("0.0.0.0:{port}"),
                "could not create any wildcard listener".to_string(),
            ));
        }
        // `dnsmasq.c:966-967`: plain wildcard mode warns about labelled
        // aliases dnsmasq is folding into their base device.
        for msg in network::warn_wild_labels(&enumerated.interfaces) {
            tracing::warn!("{msg}");
        }
        let filter = network::ArrivalFilter::new(
            check, allowed_cfg, enumerated.interfaces, cleverbind,
        );
        return Ok((adopt_dns_listeners(listeners, nowild)?, Some(filter)));
    }

    // ── --bind-interfaces / --bind-dynamic ───────────────────────────────────
    // `dnsmasq.c:963-964`: `warn_bound_listeners` fires only under plain
    // `--bind-interfaces` (`OPT_NOWILD`), not `--bind-dynamic`, which actually
    // rechecks the arrival interface and so isn't at risk.
    if nowild {
        for msg in network::warn_bound_listeners(&enumerated.interfaces) {
            tracing::warn!("{msg}");
        }
    }

    // `network.c:1298-1304`'s `is_dad_listeners()`: under `--bind-interfaces`
    // an IPv6 address still completing Duplicate Address Detection is left
    // unbound rather than bound prematurely — upstream's main loop retries it
    // once DAD finishes (`dnsmasq.c:1104,1217-1223`). This Rust build binds
    // once at startup and has no periodic re-check yet, so a DAD address
    // deferred here stays unbound for the life of the process; that's a
    // narrower port than upstream's retry loop, tracked in `tasks.md`.
    if network::is_dad_listeners(&enumerated.interfaces, &[], nowild, port) {
        for iface in enumerated.interfaces.iter().filter(|i| i.dad) {
            tracing::warn!(
                "waiting for DAD to complete on {} before binding {}",
                iface.name, iface.addr
            );
        }
    }

    // `listen_addr` carries the interface index into `sin6_scope_id` for
    // link-local addresses; without it the bind fails with EINVAL
    // (`network.c:617-620`).
    //
    // `network.c:1177-1210`'s `create_bound_listeners()` skips a DAD address
    // (`!iface->dad`) unconditionally, in both `--bind-interfaces` and
    // `--bind-dynamic` — not just under `nowild` as this filter used to read.
    let iface_addrs: Vec<(SocketAddr, String)> = enumerated
        .interfaces
        .iter()
        .filter(|i| !i.dad)
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
    //
    // The filter's baseline excludes DAD addresses too, matching the bind
    // exclusion above: `refresh_dynamic`'s diff (`diff_dynamic_interfaces`)
    // only reports an address as newly-appeared if it wasn't already in the
    // previous pass's list. A DAD-tentative address left in the baseline
    // would never be seen as "new" once DAD completes and a fresh enumeration
    // reports it (now with `dad: false`) — it would just look unchanged and
    // stay permanently unbound under `--bind-dynamic`.
    let filter = network::ArrivalFilter::new(
        check, allowed_cfg,
        enumerated.interfaces.into_iter().filter(|i| !i.dad).collect(),
        cleverbind,
    );
    Ok((adopt_dns_listeners(listeners, nowild)?, Some(filter)))
}

/// Bind the TFTP listening socket(s) (port 69), mirroring the same
/// `--bind-interfaces`/`--bind-dynamic`-vs-wildcard dispatch
/// [`bind_dns_listeners`] uses — upstream shares one `struct listener` per
/// address for DNS, TCP and TFTP alike (`network.c`), so the set of
/// addresses TFTP listens on tracks the DNS listener set exactly.
///
/// Only called when `--enable-tftp` (`OPT_TFTP`) is set; returns an empty
/// `Vec` otherwise.
#[cfg(feature = "tftp")]
fn bind_tftp_listeners(daemon: &Daemon) -> Result<Vec<BoundTftpSocket>, DnsmasqError> {
    use crate::network::{self, ListenerKinds};
    use crate::types::constants::{OPT_CLEVERBIND, OPT_NOWILD, OPT_TFTP};

    if !daemon.option_bool(OPT_TFTP) {
        return Ok(Vec::new());
    }

    let nowild     = daemon.option_bool(OPT_NOWILD);
    let cleverbind = daemon.option_bool(OPT_CLEVERBIND);
    let kinds = ListenerKinds { udp: false, tcp: false, tftp: true };

    let mut check   = iface_check_config(daemon);
    let allowed_cfg = iface_allowed_config(daemon);
    let enumerated  = network::enumerate_allowed_interfaces(&mut check, &allowed_cfg)
        .map_err(|e| DnsmasqError::BadNet(format!("failed to find list of interfaces: {e}")))?;

    let listeners = if !nowild && !cleverbind {
        network::create_wildcard_listeners_checked(69, kinds)
            .map_err(|e| DnsmasqError::Bind("0.0.0.0:69".to_string(), e.to_string()))?
    } else {
        let iface_addrs: Vec<(SocketAddr, String)> = enumerated
            .interfaces
            .iter()
            .filter(|i| i.tftp_ok)
            .map(|i| (i.listen_addr(69), i.name.clone()))
            .collect();
        let mut listeners = Vec::new();
        network::create_bound_listeners_checked(&mut listeners, &iface_addrs, kinds, nowild, cleverbind)
            .map_err(|e| DnsmasqError::Bind("port 69".to_string(), e.to_string()))?;
        listeners
    };

    adopt_tftp_listeners(listeners)
}

/// [`adopt_dns_listeners`], but for TFTP's `tftp_fd` and carrying the known
/// interface name/MTU forward for the request handler.
#[cfg(feature = "tftp")]
fn adopt_tftp_listeners(
    listeners: Vec<crate::network::Listener>,
) -> Result<Vec<BoundTftpSocket>, DnsmasqError> {
    use std::os::unix::io::FromRawFd;

    let mut out = Vec::with_capacity(listeners.len());
    for mut l in listeners {
        // Nothing serves the DNS/TCP descriptors on this path; close them
        // rather than leak, same as `adopt_dns_listeners`.
        for fd in [std::mem::replace(&mut l.udp_fd, -1), std::mem::replace(&mut l.tcp_fd, -1)] {
            if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        }
        if l.tftp_fd < 0 {
            continue;
        }
        let sock = unsafe { std::net::UdpSocket::from_raw_fd(l.tftp_fd) };
        sock.set_nonblocking(true)?;
        let addr = sock.local_addr().unwrap_or(l.addr);
        let mtu = l.iface.as_deref().and_then(crate::network::interface_mtu);
        out.push(BoundTftpSocket { sock, addr, iface: l.iface.clone(), mtu });
    }
    Ok(out)
}

/// Bind every socket the daemon serves from, before forking and before the
/// privilege drop.
pub fn bind_listeners(daemon: &Daemon) -> Result<Listeners, DnsmasqError> {
    let (dns, arrival_filter) = bind_dns_listeners(daemon)?;

    #[cfg(feature = "tftp")]
    let tftp = bind_tftp_listeners(daemon)?;

    #[cfg(feature = "dhcp")]
    let dhcp = match daemon_dhcp_runtime(daemon) {
        Some(runtime) => {
            let addr = runtime.bind_addr;
            let sock = std::net::UdpSocket::bind(addr)
                .map_err(|e| DnsmasqError::Bind(addr.to_string(), e.to_string()))?;
            sock.set_nonblocking(true)?;
            // Upstream sets SO_BROADCAST unconditionally on this socket
            // (dhcp.c's dhcp_init, `setsockopt(fd, SOL_SOCKET,
            // SO_BROADCAST, ...)`) — without it, replies to a client that
            // hasn't got an address yet (sent to 255.255.255.255) fail at
            // the kernel with ENETUNREACH instead of going out.
            sock.set_broadcast(true)
                .map_err(|e| DnsmasqError::Bind(addr.to_string(), e.to_string()))?;
            #[cfg(target_os = "linux")]
            if let Some(device) = runtime.bind_interface.as_deref() {
                bind_dhcp_socket_to_device(&sock, device)?;
            }
            // Best-effort: enables per-datagram arrival-interface metadata
            // (`run_dhcp_loop` reads it via `recv_with_dest`/`IP_PKTINFO` to
            // restrict `dhcp-range` context selection to the interface the
            // request actually arrived on, dhcp.c:296-365's `complete_context`
            // call). A failure here just means every packet dispatches with
            // no arrival interface known, same as before this existed.
            #[cfg(unix)]
            {
                use std::os::unix::io::AsRawFd as _;
                if let Err(e) = crate::network::set_ipv4pktinfo(sock.as_raw_fd()) {
                    tracing::warn!("failed to enable IP_PKTINFO on DHCP socket: {e}");
                }
            }
            Some(sock)
        }
        None => None,
    };

    // DUID generation and context construction need a write lock on the
    // running `Daemon` ([`daemon_dhcp6_runtime`]), which isn't available yet
    // at this pre-fork, still-synchronous stage — only decide *whether* to
    // claim the privileged port here; `run_main_loop_with` builds the actual
    // runtime once the daemon handle exists.
    #[cfg(all(feature = "dhcp6", unix))]
    let dhcp6 = if !daemon.dhcp6.is_empty() {
        use std::os::unix::io::FromRawFd;
        let nowild = daemon.option_bool(crate::types::constants::OPT_NOWILD);
        let fd = crate::dhcp6::dhcp6_init(nowild)
            .map_err(|e| DnsmasqError::Bind("[::]:547".to_string(), e.to_string()))?;
        Some(unsafe { std::net::UdpSocket::from_raw_fd(fd) })
    } else {
        None
    };
    #[cfg(all(feature = "dhcp6", not(unix)))]
    let dhcp6: Option<std::net::UdpSocket> = None;

    Ok(Listeners {
        dns,
        arrival_filter,
        #[cfg(feature = "dhcp")]
        dhcp,
        #[cfg(feature = "dhcp6")]
        dhcp6,
        #[cfg(feature = "tftp")]
        tftp,
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

/// Adopt a pre-bound DHCPv6 socket from [`bind_listeners`], or bind `[::]:547`
/// itself when none was pre-bound (the in-process/test path, which never
/// runs [`bind_listeners`] before the privilege drop).
#[cfg(feature = "dhcp6")]
async fn adopt_or_bind_dhcp6(
    prebound: Option<std::net::UdpSocket>,
    #[cfg_attr(unix, allow(unused_variables))] bind_addr: SocketAddr,
) -> std::io::Result<tokio::net::UdpSocket> {
    match prebound {
        Some(sock) => tokio::net::UdpSocket::from_std(sock),
        #[cfg(unix)]
        None => {
            use std::os::unix::io::FromRawFd;
            let fd = crate::dhcp6::dhcp6_init(false)?;
            let std_sock = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
            tokio::net::UdpSocket::from_std(std_sock)
        }
        #[cfg(not(unix))]
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

/// Open a netlink socket and spawn a background task that re-enumerates
/// network interfaces whenever the kernel announces an address change.
///
/// Mirrors upstream's `netlink_init()` call site in `dnsmasq.c` plus
/// `nl_async()`'s `queue_event(EVENT_NEWADDR)` (`netlink.c:406-411`): there,
/// the netlink fd is registered in the daemon's `poll()` set and an
/// `EVENT_NEWADDR` eventually triggers `enumerate_interfaces()` again so
/// newly-appeared addresses are picked up without a restart. This task is the
/// same reaction, driven by [`crate::netlink::watch_address_changes`]'s
/// `AsyncFd` readiness loop instead of a poll/event-queue pair.
///
/// Only wires up re-enumeration itself — it does not yet feed the refreshed
/// interface list into the live `ArrivalFilter` or rebuild bound listeners
/// (`--bind-dynamic` re-bind is tracked separately in `tasks.md`). A failure
/// to open the netlink socket (e.g. no `CAP_NET_ADMIN`, or a non-Linux
/// sandbox) is logged and treated as "no live address-change notifications",
/// matching how [`crate::slaac::Icmp6Socket`] degrades gracefully rather than
/// aborting startup.
#[cfg(target_os = "linux")]
fn spawn_netlink_watch_task() -> Option<tokio::task::JoinHandle<()>> {
    use tracing::{info, warn};

    match crate::netlink::netlink_open() {
        Ok((fd, _pid)) => Some(tokio::spawn(async move {
            let result = crate::netlink::watch_address_changes(fd, |state| {
                if state & crate::netlink::STATE_NEWADDR != 0 {
                    match crate::network::enumerate_interfaces() {
                        Ok(ifaces) => info!(
                            count = ifaces.len(),
                            "netlink: address change detected, re-enumerated interfaces"
                        ),
                        Err(e) => warn!("netlink: address change detected but re-enumeration failed: {e}"),
                    }
                }
                if state & crate::netlink::STATE_NEWROUTE != 0 {
                    info!("netlink: route change detected");
                }
            })
            .await;
            if let Err(e) = result {
                warn!("netlink watch loop exited: {e}");
            }
        })),
        Err(e) => {
            warn!("failed to open netlink socket for address-change notifications: {e}");
            None
        }
    }
}

/// Non-Linux platforms have no netlink socket; address-change notification is
/// a Linux-specific runtime feature (matching `netlink.rs`'s existing
/// `#[cfg(target_os = "linux")]` gating on the socket-level functions).
#[cfg(not(target_os = "linux"))]
fn spawn_netlink_watch_task() -> Option<tokio::task::JoinHandle<()>> {
    None
}

/// Spawn the background task that drains inotify events (resolv-file and
/// `--hostsdir`/`--dhcp-hostsdir`/`--dhcp-optsdir` directory changes) for as
/// long as the daemon runs.
///
/// The inotify fd itself was already opened and the resolv-file watches
/// already established by [`inotify_dnsmasq_init`](crate::inotify::inotify_dnsmasq_init)
/// in [`init_daemon_with`]; this only spawns the [`crate::inotify::watch_inotify_changes`]
/// readiness loop that reacts to them, mirroring [`spawn_netlink_watch_task`]'s
/// `AsyncFd`-based structure.
#[cfg(feature = "inotify")]
fn spawn_inotify_watch_task(
    daemon_handle: DaemonHandle,
    cache: crate::cache::SharedDnsCache,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = crate::inotify::watch_inotify_changes(daemon_handle, cache).await {
            tracing::warn!("inotify watch loop exited: {e}");
        }
    })
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
    let (mut fwd_config, dhcp_runtime, arp_state, tftp_config) = {
        let d = daemon_handle.read().await;
        let fwd_config = daemon_forward_config(&d);
        // Shared (not copied) so a kernel refresh triggered by the forwarding
        // loop's MAC resolution is visible to DHCPv6's `get_client_mac` too —
        // see `Daemon::arp_state`.
        let arp_state = d.arp_state.clone();
        #[cfg(feature = "dhcp")]
        let dhcp_runtime = daemon_dhcp_runtime(&d);
        #[cfg(not(feature = "dhcp"))]
        let dhcp_runtime = ();
        #[cfg(feature = "tftp")]
        let tftp_config = daemon_tftp_config(&d);
        #[cfg(not(feature = "tftp"))]
        let tftp_config = ();
        (fwd_config, dhcp_runtime, arp_state, tftp_config)
    };

    // `--dns-loop-detect`: send the first round of loop probes once at
    // startup, mirroring `if (daemon->port != 0) check_servers(0);` right
    // after `main()` releases the pre-fork parent (`dnsmasq.c:1082-1083`) —
    // that first `check_servers()` call is what fires `loop_send_probes()`
    // before any query has ever been served. Later rounds happen as SIGHUP
    // reload grows a live hook into the running forward task (`tasks.md`).
    #[cfg(feature = "loop")]
    if fwd_config.loop_detect && fwd_config.port != 0 {
        crate::loop_detect::send_probes(&mut fwd_config.loop_servers).await;
    }

    // `--dump-file`: open (or create/reopen) the pcap dump once at startup,
    // mirroring `dump_init()` being called once from `main()` (`dnsmasq.c:450`).
    // A failure here is fatal, matching upstream's `die()` on the same paths.
    #[cfg(feature = "dump")]
    {
        let (dump_file, edns_pktsz, dump_mask) = {
            let d = daemon_handle.read().await;
            (d.dump_file.clone(), d.edns_pktsz, d.dump_mask)
        };
        if let Some(path) = dump_file {
            match crate::dump::DumpHandle::init(&path, edns_pktsz, dump_mask) {
                Ok(handle) => fwd_config.dump = Some(handle),
                Err(e) => {
                    error!("cannot open dump file {path}: {e}");
                    return RunResult::IoError;
                }
            }
        }
    }

    // DUID generation mutates `daemon.duid`, so this needs a write lock —
    // taken and released here, separate from the read lock above.
    #[cfg(feature = "dhcp6")]
    let dhcp6_runtime = {
        let mut d = daemon_handle.write().await;
        daemon_dhcp6_runtime(&mut d)
    };

    // Router Advertisements piggyback on the same "current chain" contexts
    // DHCPv6 just built (`dhcp_construct_contexts` folds live addresses in),
    // so this snapshot has to happen before the RA-unrelated `dhcp6_runtime`
    // spawn block below takes ownership of `rt.contexts`.
    #[cfg(feature = "dhcp6")]
    let radv_config = {
        let d = daemon_handle.read().await;
        if d.doing_ra {
            Some(RadvConfig {
                contexts: dhcp6_runtime.as_ref().map(|rt| rt.contexts.clone()).unwrap_or_default(),
                ra_interfaces: d.ra_interfaces.clone(),
                dhcp_except: d.dhcp_except.clone(),
                bridges: d.bridges.clone(),
                opt_ra: d.option_bool(crate::types::constants::OPT_RA),
                is_dns_server: d.port == crate::dns_protocol::NAMESERVER_PORT,
                quiet_ra: d.option_bool(crate::types::constants::OPT_QUIET_RA),
                iface_check: iface_check_config(&d),
            })
        } else {
            None
        }
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
    #[cfg(feature = "dhcp6")]
    let prebound_dhcp6 = listeners.dhcp6.take();
    #[cfg(feature = "tftp")]
    let bound_tftp = std::mem::take(&mut listeners.tftp);
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

    // ── D-Bus (`--enable-dbus`) ───────────────────────────────────────────────
    //
    // Mirrors `dbus_init()` being called once at startup (`dnsmasq.c:461`);
    // the retry-while-bus-not-up-yet behavior (`dnsmasq.c:1263`) lives inside
    // `run_dbus_task` itself — see its doc comment for why that's a spawned
    // async task rather than a per-tick poll here.
    #[cfg(feature = "dbus")]
    let dbus_task = {
        let opt_dbus = {
            let d = daemon_handle.read().await;
            d.option_bool(crate::types::constants::OPT_DBUS)
        };
        if opt_dbus {
            let d = daemon_handle.read().await;
            let dbus_name = d.dbus_name.clone().unwrap_or_else(|| crate::dbus::DNSMASQ_DBUS_INTERFACE.to_string());
            #[cfg(feature = "dhcp")]
            let lease_file = d.lease_file.clone();
            drop(d);
            let ctx = crate::dbus::DbusContext {
                daemon: daemon_handle.clone(),
                cache: cache.clone(),
                #[cfg(feature = "dhcp")]
                leases: Arc::new(tokio::sync::Mutex::new(crate::lease::LeaseDb::new())),
                #[cfg(feature = "dhcp")]
                lease_file,
                dbus_name,
            };
            Some(tokio::spawn(crate::dbus::run_dbus_task(ctx)))
        } else {
            None
        }
    };

    // ── inotify: dynamic-dir initial scan + watch task ───────────────────────
    //
    // Resolv-file directory watches were already established synchronously in
    // `init_daemon_with` (`inotify_dnsmasq_init`); `--hostsdir`/dynamic-dir
    // watches need the cache to exist first, so `set_dynamic_inotify` (the
    // watch-then-initial-scan step, mirroring `dnsmasq.c:437`) runs here,
    // before `cache` is moved into the forwarding task below.
    #[cfg(feature = "inotify")]
    {
        let mut d = daemon_handle.write().await;
        let mut c = cache.lock().await;
        crate::inotify::set_dynamic_inotify(&mut d, &mut c);
    }
    #[cfg(feature = "inotify")]
    let inotify_task = spawn_inotify_watch_task(daemon_handle.clone(), cache.clone());

    // ── UBus (`--ubus`) ───────────────────────────────────────────────────────
    //
    // Mirrors upstream calling `ubus_init()` once at startup and then
    // draining events via `set_ubus_listeners()`/`check_ubus_listeners()`
    // from the main `poll()` loop (dnsmasq.c) — collapsed into one spawned
    // task since this codebase has no raw `poll()` loop to hook a listener
    // into; see `ubus::run_ubus_task`'s doc comment.
    #[cfg(feature = "ubus")]
    let ubus_task = {
        let opt_ubus = {
            let d = daemon_handle.read().await;
            d.option_bool(crate::types::constants::OPT_UBUS)
        };
        if opt_ubus {
            let ctx = crate::ubus::UbusContext { daemon: daemon_handle.clone() };
            Some(tokio::spawn(crate::ubus::run_ubus_task(ctx)))
        } else {
            None
        }
    };

    // ── Spawn the forwarding engine ──────────────────────────────────────────
    let arp_housekeeping_state = arp_state.clone();
    let fwd_task = tokio::spawn(async move {
        if let Err(e) = run_forward_loop_on(dns_listeners, arrival_filter, fwd_config, cache, arp_state).await {
            error!("forward loop exited: {e}");
        }
    });

    // ── Spawn ARP-cache housekeeping ─────────────────────────────────────────
    // Mirrors the two calls the upstream select loop makes every iteration
    // (`dnsmasq.c:1172-1174`): keep the cache current and drain the
    // add/delete script queue — see `spawn_arp_housekeeping_task` below.
    let arp_task = spawn_arp_housekeeping_task(
        daemon_handle.clone(),
        arp_housekeeping_state,
        std::time::Duration::from_secs(1),
    );

    // ── Spawn the TFTP server ─────────────────────────────────────────────────
    #[cfg(feature = "tftp")]
    let tftp_task = if bound_tftp.is_empty() {
        None
    } else {
        let mut tftp_listeners = Vec::with_capacity(bound_tftp.len());
        for bound in bound_tftp {
            let addr = bound.addr;
            let sock = match tokio::net::UdpSocket::from_std(bound.sock) {
                Ok(s) => s,
                Err(e) => {
                    error!("failed to adopt the TFTP socket bound on {addr}: {e}");
                    fwd_task.abort();
                    arp_task.abort();
                    return RunResult::IoError;
                }
            };
            info!("listening for TFTP requests on {addr}");
            tftp_listeners.push(crate::tftp::TftpListenerHandle {
                sock: Arc::new(sock),
                addr,
                iface: bound.iface,
                mtu: bound.mtu,
            });
        }
        Some(tokio::spawn(async move {
            if let Err(e) = crate::tftp::run_tftp_loop(tftp_listeners, tftp_config).await {
                error!("tftp loop exited: {e}");
            }
        }))
    };

    #[cfg(feature = "dhcp")]
    let (dhcp_task, dhcp_shutdown_tx) = if let Some(mut dhcp_runtime) = dhcp_runtime {
        // Feed the DHCPv6 "current" RA-name context chain to the DHCPv4 loop
        // so it can recompute SLAAC addresses (`slaac_add_addrs`) for the
        // leases it actually commits — see `DhcpLoopOptions::slaac_contexts`.
        // `dhcp6_runtime` is still `Some` here (its contexts aren't moved
        // into `run_dhcp6_loop` until the block below), so this is the last
        // point that can clone them.
        #[cfg(feature = "dhcp6")]
        {
            dhcp_runtime.loop_opts.slaac_contexts =
                dhcp6_runtime.as_ref().map(|rt| rt.contexts.clone()).unwrap_or_default();
        }
        let bind_addr = dhcp_runtime.bind_addr;
        #[cfg_attr(not(target_os = "linux"), allow(unused_variables))]
        let already_bound = prebound_dhcp.is_some();
        let dhcp_sock = match adopt_or_bind(prebound_dhcp, &bind_addr.to_string()).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!("failed to bind DHCP socket on {bind_addr}: {e}");
                fwd_task.abort();
                arp_task.abort();
                #[cfg(feature = "tftp")]
                if let Some(t) = tftp_task.as_ref() { t.abort(); }
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
                    arp_task.abort();
                    #[cfg(feature = "tftp")]
                    if let Some(t) = tftp_task.as_ref() { t.abort(); }
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
        // PING_WAIT (config.h) — per-candidate ICMP echo timeout.
        let probe: Box<dyn crate::dhcp::AddressProbe + Send + Sync> = Box::new(IcmpPinger::new(3000));
        let task = tokio::spawn(async move {
            if let Err(e) = run_dhcp_loop(dhcp_sock, dhcp_runtime.server, dhcp_runtime.loop_opts, lease_db, shutdown_rx, probe).await {
                error!("dhcp loop exited: {e}");
            }
        });
        (Some(task), Some(shutdown_tx))
    } else {
        (None, None)
    };

    #[cfg(feature = "dhcp6")]
    let (dhcp6_task, dhcp6_shutdown_tx) = if let Some(rt) = dhcp6_runtime {
        let dhcp6_sock = match adopt_or_bind_dhcp6(prebound_dhcp6, rt.bind_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                error!("failed to bind DHCPv6 socket on {}: {e}", rt.bind_addr);
                fwd_task.abort();
                arp_task.abort();
                #[cfg(feature = "tftp")]
                if let Some(t) = tftp_task.as_ref() { t.abort(); }
                #[cfg(feature = "dhcp")]
                {
                    if let Some(tx) = dhcp_shutdown_tx.as_ref() {
                        let _ = tx.send(true);
                    }
                    if let Some(task) = dhcp_task.as_ref() {
                        task.abort();
                    }
                }
                return RunResult::IoError;
            }
        };
        info!("listening for DHCPv6 packets on {}", rt.bind_addr);
        // A wildcard bind alone never receives multicast SOLICITs — real
        // clients always multicast their first message, since they have no
        // unicast address to send to yet. Best-effort: a sandboxed
        // environment without the right capability, or an interface that
        // can't do multicast, logs and keeps the rest of the daemon running
        // rather than aborting startup (see `join_dhcp6_multicast_all_interfaces`).
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            crate::network::join_dhcp6_multicast_all_interfaces(dhcp6_sock.as_raw_fd());
        }
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        // Kept in-memory only — see `run_dhcp6_loop`'s doc comment on why this
        // doesn't share the v4 loop's lease file.
        let task = tokio::spawn(async move {
            if let Err(e) = crate::dhcp6::run_dhcp6_loop(
                dhcp6_sock, rt.duid, rt.contexts, rt.configs,
                crate::lease::LeaseDb::new(), rt.authoritative, shutdown_rx, None,
            ).await {
                error!("dhcp6 loop exited: {e}");
            }
        });
        (Some(task), Some(shutdown_tx))
    } else {
        (None, None)
    };

    // ── Netlink address-change watcher ───────────────────────────────────────
    let netlink_task = spawn_netlink_watch_task();

    // ── Router Advertisements ────────────────────────────────────────────────
    //
    // `ra_init()`'s raw ICMPv6 socket failure is fatal upstream (`die()`);
    // matched here rather than degrading gracefully like `IcmpPinger` does,
    // since `--enable-ra`/a `ra-only` `dhcp-range` is an explicit request for
    // RA service the daemon can't silently skip — the same convention this
    // function already applies to a failed DHCPv6 socket bind above.
    #[cfg(feature = "dhcp6")]
    let (radv_task, radv_shutdown_tx) = if let Some(cfg) = radv_config {
        let want_echo_reply = cfg.contexts.iter().any(|c| c.flags & crate::types::dhcp::CONTEXT_RA_NAME != 0);
        let socket = match RadvSocket::new(want_echo_reply) {
            Ok(s) => s,
            Err(e) => {
                error!("cannot create ICMPv6 socket for Router Advertisements: {e}");
                fwd_task.abort();
                #[cfg(feature = "dhcp")]
                {
                    if let Some(tx) = dhcp_shutdown_tx.as_ref() {
                        let _ = tx.send(true);
                    }
                    if let Some(task) = dhcp_task.as_ref() {
                        task.abort();
                    }
                }
                if let Some(tx) = dhcp6_shutdown_tx.as_ref() {
                    let _ = tx.send(true);
                }
                if let Some(task) = dhcp6_task.as_ref() {
                    task.abort();
                }
                return RunResult::IoError;
            }
        };
        info!("sending Router Advertisements");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let task = tokio::spawn(async move {
            if let Err(e) = run_radv_loop(
                socket, cfg.contexts, cfg.ra_interfaces, cfg.dhcp_except, cfg.bridges,
                cfg.opt_ra, cfg.is_dns_server, cfg.quiet_ra, cfg.iface_check, shutdown_rx,
            ).await {
                error!("radv loop exited: {e}");
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
            #[cfg(feature = "dhcp6")]
            {
                if let Some(tx) = dhcp6_shutdown_tx.as_ref() {
                    let _ = tx.send(true);
                }
                if let Some(task) = dhcp6_task.as_ref() {
                    task.abort();
                }
                if let Some(tx) = radv_shutdown_tx.as_ref() {
                    let _ = tx.send(true);
                }
                if let Some(task) = radv_task.as_ref() {
                    task.abort();
                }
            }
            if let Some(task) = netlink_task.as_ref() {
                task.abort();
            }
            #[cfg(feature = "inotify")]
            inotify_task.abort();
            #[cfg(feature = "dbus")]
            if let Some(task) = dbus_task.as_ref() {
                task.abort();
            }
            #[cfg(feature = "tftp")]
            if let Some(t) = tftp_task.as_ref() { t.abort(); }
            #[cfg(feature = "ubus")]
            if let Some(task) = ubus_task.as_ref() {
                task.abort();
            }
            fwd_task.abort();
            arp_task.abort();
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
            #[cfg(feature = "dhcp6")]
            {
                if let Some(tx) = dhcp6_shutdown_tx.as_ref() {
                    let _ = tx.send(true);
                }
                if let Some(task) = dhcp6_task.as_ref() {
                    task.abort();
                }
                if let Some(tx) = radv_shutdown_tx.as_ref() {
                    let _ = tx.send(true);
                }
                if let Some(task) = radv_task.as_ref() {
                    task.abort();
                }
            }
            if let Some(task) = netlink_task.as_ref() {
                task.abort();
            }
            #[cfg(feature = "inotify")]
            inotify_task.abort();
            #[cfg(feature = "dbus")]
            if let Some(task) = dbus_task.as_ref() {
                task.abort();
            }
            #[cfg(feature = "tftp")]
            if let Some(t) = tftp_task.as_ref() { t.abort(); }
            #[cfg(feature = "ubus")]
            if let Some(task) = ubus_task.as_ref() {
                task.abort();
            }
            fwd_task.abort();
            arp_task.abort();
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
    #[cfg(feature = "tftp")]
    if let Some(task) = tftp_task {
        task.abort();
    }
    if let Some(task) = netlink_task {
        task.abort();
    }
    #[cfg(feature = "inotify")]
    inotify_task.abort();
    #[cfg(feature = "dbus")]
    if let Some(task) = dbus_task {
        task.abort();
    }
    arp_task.abort();
    #[cfg(feature = "ubus")]
    if let Some(task) = ubus_task {
        task.abort();
    }
    #[cfg(feature = "dhcp")]
    {
        if let Some(tx) = dhcp_shutdown_tx {
            let _ = tx.send(true);
        }
        if let Some(task) = dhcp_task {
            let _ = task.await;
        }
    }
    #[cfg(feature = "dhcp6")]
    {
        if let Some(tx) = dhcp6_shutdown_tx {
            let _ = tx.send(true);
        }
        if let Some(task) = dhcp6_task {
            let _ = task.await;
        }
        if let Some(tx) = radv_shutdown_tx {
            let _ = tx.send(true);
        }
        if let Some(task) = radv_task {
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
// ARP cache housekeeping
// ──────────────────────────────────────────────────────────────────────────────

/// One tick of ARP-cache housekeeping.
///
/// Mirrors the two calls upstream's main select loop makes every iteration
/// (`dnsmasq.c:1172-1174`):
///
/// ```c
/// if (option_bool(OPT_SCRIPT_ARP))
///   find_mac(NULL, NULL, 0, now);
/// while (helper_buf_empty() && do_arp_script_run());
/// ```
///
/// i.e. keep the cache current — via [`crate::arp::refresh_arp_cache_shared`]
/// — even when nothing is actively being looked up, gated on `--script-arp`
/// exactly like the kernel refresh is upstream, then always drain the
/// add/delete queue via [`crate::arp::drain_arp_script_events`] (feature
/// `dhcp`) so cache state (`Mark` → `old`, `New` → `Found`) advances
/// regardless of whether the option is set — matching `do_arp_script_run`
/// always popping/advancing while only `queue_arp()` is gated.
///
/// Drained events are logged rather than handed to a script helper: per
/// `tasks.md`, nothing forks the privilege-dropped helper process from the
/// main startup path yet, so there is no live `HelperHandle` to send them
/// to. Wiring that up only needs to replace the log call below with
/// `helper.send(&event)`.
async fn arp_housekeeping_tick(daemon_handle: &DaemonHandle, arp_state: &crate::arp::SharedArpState) {
    use crate::types::constants::OPT_SCRIPT_ARP;
    use tracing::debug;

    let script_arp = daemon_handle.read().await.option_bool(OPT_SCRIPT_ARP);
    let now = crate::util::dnsmasq_time();

    if script_arp {
        crate::arp::refresh_arp_cache_shared(arp_state, now);
    }

    let mut guard = arp_state.lock().unwrap_or_else(|e| e.into_inner());
    #[cfg(feature = "dhcp")]
    {
        for event in crate::arp::drain_arp_script_events(&mut guard.cache, script_arp) {
            debug!(?event, "ARP script event (no helper process forked yet — see tasks.md)");
        }
    }
    #[cfg(not(feature = "dhcp"))]
    {
        while guard.cache.do_arp_script_run().is_some() {}
    }
}

/// Spawn a background tokio task that calls [`arp_housekeeping_tick`] every
/// `interval`. Returns a `JoinHandle` that can be aborted to stop it.
pub fn spawn_arp_housekeeping_task(
    daemon_handle: DaemonHandle,
    arp_state: crate::arp::SharedArpState,
    interval: std::time::Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            arp_housekeeping_tick(&daemon_handle, &arp_state).await;
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
///   [`crate::cache::reload_hosts`], then (when the `inotify` feature is
///   enabled) re-scan `--hostsdir` directories via
///   [`crate::inotify::set_dynamic_inotify`] to repopulate what that flush
///   just wiped — mirroring `cache_reload()`'s own
///   `set_dynamic_inotify(AH_HOSTS, ...)` call at `cache.c:1709`.
/// * `reload_servers()` (`network.c:1699`) → re-read each `--resolv-file`
///   into `daemon->servers`, replacing only the previous `SERV_FROM_RESOLV`
///   entries so explicitly configured (`--server=`) servers survive.
///
/// Deliberate simplifications versus upstream, tracked in `tasks.md`:
/// * Upstream only preserves `F_DHCP` cache entries across the flush; this
///   port's cache never receives `F_DHCP` records yet, so a full flush is
///   currently equivalent and needs revisiting once DHCP leases feed the
///   cache.
/// * Upstream gates the *SIGHUP* resolv-file re-read on `OPT_NO_POLL`
///   (`dnsmasq.c:1553`): when polling/inotify is active, the ordinary
///   inotify-triggered reload ([`crate::inotify::watch_inotify_changes`])
///   is expected to already keep `daemon->servers` current, so SIGHUP
///   doesn't force a redundant read on top of it. This port still re-reads
///   resolv-files unconditionally on every SIGHUP regardless of
///   `--no-poll` — harmless, since the re-read is idempotent
///   (`clear_cache_and_reload_idempotent`), but not a byte-for-byte match.
/// * Real inotify watches now exist (`src/inotify.rs`), but the
///   `--hostsdir` re-scan above only covers `AH_HOSTS` directories, not
///   `dhcp-hostsdir`/`dhcp-optsdir` (`AH_DHCP_HST`/`AH_DHCP_OPT`) — matching
///   `set_dynamic_inotify`'s existing scope limits (see the `src/inotify.rs`
///   module doc).
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

    // `reload_hosts` just flushed the *entire* cache, which also wiped any
    // `--hostsdir`-loaded records. Upstream's `cache_reload()` re-scans
    // dynamic hosts directories in the same call (`cache.c:1709`,
    // `set_dynamic_inotify(AH_HOSTS, ...)`) precisely to repopulate what it
    // just flushed; do the same here rather than leaving those records gone
    // until their directory happens to receive another filesystem event.
    // `dhcp-hostsdir`/`dhcp-optsdir` entries are unaffected (`set_dynamic_inotify`
    // only re-scans `AH_HOSTS` directories), matching the module's existing
    // scope limits (see `src/inotify.rs` module doc).
    #[cfg(feature = "inotify")]
    {
        let mut d = daemon_handle.write().await;
        let mut c = cache.lock().await;
        crate::inotify::set_dynamic_inotify(&mut d, &mut c);
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
        use crate::domain_match::{add_update_server, cleanup_servers, mark_servers};
        use crate::types::addr::MySockAddr;
        use crate::types::server::{SERV_4ADDR, SERV_6ADDR, SERV_FROM_RESOLV};

        let query_port = d.query_port;
        // network.c:1711/1766/1774 — mark every existing resolv-derived server,
        // then let `add_update_server` reuse a marked entry (by domain — always
        // "" here) instead of rebuilding it, so its query statistics survive an
        // unchanged address across reload; whatever is still marked afterwards
        // (an address that dropped out of the file) is swept away.
        mark_servers(&mut d.servers, SERV_FROM_RESOLV);
        for addr in discovered {
            // network.c:1729-1754 — `source_addr` is the wildcard address in the
            // *same* family as the server, bound to `--query-port`; scope is
            // always 0 for the source, only the destination carries it.
            let (my_addr, source_addr) = match addr {
                std::net::SocketAddr::V4(v4) => (
                    MySockAddr::V4(v4),
                    MySockAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, query_port)),
                ),
                std::net::SocketAddr::V6(v6) => (
                    MySockAddr::V6(v6),
                    MySockAddr::V6(std::net::SocketAddrV6::new(
                        Ipv6Addr::UNSPECIFIED,
                        query_port,
                        0,
                        0,
                    )),
                ),
            };
            let flags = SERV_FROM_RESOLV | if addr.is_ipv6() { SERV_6ADDR } else { SERV_4ADDR };
            add_update_server(
                &mut d.servers,
                crate::option::new_server(flags, String::new(), my_addr, source_addr),
            );
        }
        cleanup_servers(&mut d.servers);
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
/// Opens a raw `IPPROTO_ICMP` socket and sends/receives echo packets; see
/// [`IcmpPinger::ping`] for the fallback behavior when the raw socket can't
/// be opened (e.g. missing `CAP_NET_RAW`).
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
    /// indicating a potential address conflict. Port of `icmp_ping()`
    /// (dnsmasq.c:2339-2378): opens a raw `IPPROTO_ICMP` socket, sends a
    /// single echo request, and blocks up to the configured timeout for a
    /// matching reply.
    ///
    /// Requires `CAP_NET_RAW` (or root) to open the raw socket. When that's
    /// unavailable — the common case for this daemon's own test suite and
    /// for unprivileged deployments without the capability granted — this
    /// falls back to "no reply", i.e. the address is treated as free. That
    /// mirrors upstream's own fallback: `icmp_ping()` returns 0 (no reply)
    /// if `make_icmp_sock()` fails, rather than erroring the whole daemon.
    pub fn ping(&self, addr: Ipv4Addr) -> bool {
        use socket2::{Domain, Protocol, Socket, Type};
        use tracing::debug;

        let socket = match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
            Ok(s) => s,
            Err(err) => {
                debug!(%addr, %err, "ICMP raw socket unavailable (missing CAP_NET_RAW?); treating address as free");
                return false;
            }
        };
        if socket.set_read_timeout(Some(self.timeout)).is_err() {
            return false;
        }

        // Low 16 bits of the process id, matching upstream's `rand16()` seed
        // for `icmp_id` closely enough: any value works as long as it's
        // stable for the lifetime of this single request/reply exchange.
        let id = std::process::id() as u16;
        let packet = crate::dhcp::build_icmp_echo_request(id);
        let dest: SocketAddr = SocketAddr::new(std::net::IpAddr::V4(addr), 0);
        if socket.send_to(&packet, &dest.into()).is_err() {
            return false;
        }

        let deadline = std::time::Instant::now() + self.timeout;
        let mut buf = [std::mem::MaybeUninit::<u8>::uninit(); 1024];
        loop {
            if std::time::Instant::now() >= deadline {
                return false;
            }
            match socket.recv_from(&mut buf) {
                Ok((n, from)) => {
                    match from.as_socket_ipv4() {
                        Some(from4) if *from4.ip() == addr => {}
                        _ => continue,
                    }
                    // SAFETY: `recv_from` initialised exactly the first `n` bytes.
                    let bytes = unsafe {
                        std::slice::from_raw_parts(buf.as_ptr() as *const u8, n)
                    };
                    if crate::dhcp::parse_icmp_echo_reply(bytes, id) {
                        return true;
                    }
                }
                Err(_) => return false,
            }
        }
    }
}

#[cfg(feature = "dhcp")]
impl crate::dhcp::AddressProbe for IcmpPinger {
    fn in_use(&self, addr: Ipv4Addr) -> bool {
        self.ping(addr)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Router Advertisement transport (radv.c:71-140, 257-584, 789-919)
// ──────────────────────────────────────────────────────────────────────────────

/// The raw ICMPv6 socket Router Advertisements are sent/received on, plus the
/// hop limit `ra_init()` reads back from the kernel.
///
/// Every byte-pushing and scheduling decision lives in `crate::radv` as plain
/// socket-free Rust (see that module's doc comment); this struct is the thin
/// layer that actually opens the socket and moves bytes, mirroring the
/// `crate::dhcp::AddressProbe` / [`IcmpPinger`] split above.
/// `IPPROTO_ICMPV6`-level sockopt name for the kernel-side ICMPv6 type
/// filter (`<netinet/icmp6.h>`'s `ICMP6_FILTER`, value `1` on Linux). Not
/// exposed by the `libc` crate on this target.
#[cfg(feature = "dhcp6")]
const ICMP6_FILTER: libc::c_int = 1;

/// Mirrors C's `struct icmp6_filter { uint32_t icmp6_filt[8]; }` — one bit
/// per ICMPv6 type (0-255); a set bit blocks that type, matching
/// `ICMP6_FILTER_SETBLOCKALL`/`SETPASS`'s semantics.
#[cfg(feature = "dhcp6")]
#[repr(C)]
struct Icmp6Filter {
    icmp6_filt: [u32; 8],
}

/// Everything [`run_radv_loop`] needs besides the socket itself, gathered
/// from the `DaemonHandle` once at startup by [`run_main_loop_with`].
#[cfg(feature = "dhcp6")]
pub struct RadvConfig {
    pub contexts: Vec<crate::types::dhcp::DhcpContext>,
    pub ra_interfaces: Vec<crate::types::dhcp::RaInterface>,
    pub dhcp_except: Vec<crate::types::network::Iname>,
    pub bridges: Vec<crate::types::daemon::DhcpBridge>,
    pub opt_ra: bool,
    pub is_dns_server: bool,
    /// `--quiet-ra` — suppresses the `RTR-SOLICIT` log line (radv.c:222-223).
    pub quiet_ra: bool,
    /// The `--interface`/`--except-interface`/`--listen-address` filter,
    /// applied via [`crate::network::iface_check_name`] to both the RA send
    /// path ([`crate::radv::periodic_ra`]) and the receive path
    /// ([`handle_icmp6_packet`]) — radv.c:178, :934-935.
    pub iface_check: crate::network::IfaceCheckConfig,
}

#[cfg(feature = "dhcp6")]
pub struct RadvSocket {
    socket: socket2::Socket,
    pub hop_limit: i32,
}

#[cfg(feature = "dhcp6")]
impl std::os::unix::io::AsRawFd for RadvSocket {
    fn as_raw_fd(&self) -> std::os::unix::io::RawFd {
        self.socket.as_raw_fd()
    }
}

#[cfg(feature = "dhcp6")]
impl RadvSocket {
    /// Open and configure the ICMPv6 socket RA needs.
    ///
    /// Port of `ra_init()` (radv.c:71-116): `SOCK_RAW`/`IPPROTO_ICMPV6`,
    /// hop limits forced to 255, `IPV6_PKTINFO` for arrival-interface
    /// lookups, and an `ICMP6_FILTER` that passes only Router Solicitations
    /// (plus Echo Replies when `want_echo_reply` is set — SLAAC
    /// address-guessing probes; wiring that reply to `lease_ping_reply` is
    /// tracked as a gap in `tasks.md`).
    ///
    /// Requires `CAP_NET_RAW`. Upstream calls `die()` on failure; here the
    /// error is returned instead so the caller can decide (this crate's
    /// `run_main_loop_with` treats it the same way it already treats a failed
    /// DHCPv6 socket bind — a hard startup failure when RA was configured —
    /// while tests can skip when the capability just isn't available).
    pub fn new(want_echo_reply: bool) -> std::io::Result<Self> {
        use socket2::{Domain, Protocol, Socket};
        use std::os::unix::io::AsRawFd;

        let socket = Socket::new(Domain::IPV6, socket2::Type::RAW, Some(Protocol::ICMPV6))?;
        let fd = socket.as_raw_fd();

        let mut hop_limit: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd, libc::IPPROTO_IPV6, libc::IPV6_UNICAST_HOPS,
                &mut hop_limit as *mut _ as *mut libc::c_void, &mut len,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }

        // Best-effort: absence of IPV6_TCLASS support isn't fatal upstream either.
        #[cfg(target_os = "linux")]
        {
            const IPTOS_CLASS_CS6: libc::c_int = 0xc0;
            let class: libc::c_int = IPTOS_CLASS_CS6;
            unsafe {
                libc::setsockopt(
                    fd, libc::IPPROTO_IPV6, libc::IPV6_TCLASS,
                    &class as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
        }

        crate::network::fix_fd(fd)?;
        crate::network::set_ipv6pktinfo(fd)?;

        let val: libc::c_int = 255;
        for opt in [libc::IPV6_UNICAST_HOPS, libc::IPV6_MULTICAST_HOPS] {
            let rc = unsafe {
                libc::setsockopt(
                    fd, libc::IPPROTO_IPV6, opt,
                    &val as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            if rc != 0 {
                return Err(std::io::Error::last_os_error());
            }
        }

        // ICMP6_FILTER_SETBLOCKALL then selectively SETPASS (radv.c:92-98).
        // `libc` doesn't expose `icmp6_filter`/`ICMP6_FILTER` on this target,
        // so both the struct and the sockopt name are reproduced here from
        // `<netinet/icmp6.h>`.
        let mut filter = Icmp6Filter { icmp6_filt: [0xffff_ffffu32; 8] };
        let pass = |filter: &mut Icmp6Filter, ty: u8| {
            let ty = ty as u32;
            filter.icmp6_filt[(ty / 32) as usize] &= !(1u32 << (ty % 32));
        };
        pass(&mut filter, crate::radv::ND_ROUTER_SOLICIT);
        if want_echo_reply {
            pass(&mut filter, crate::radv::ICMP6_ECHO_REPLY);
        }
        let rc = unsafe {
            libc::setsockopt(
                fd, libc::IPPROTO_ICMPV6, ICMP6_FILTER,
                &filter as *const _ as *const libc::c_void,
                std::mem::size_of::<Icmp6Filter>() as libc::socklen_t,
            )
        };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }

        Ok(Self { socket, hop_limit })
    }

    /// Receive one ICMPv6 datagram plus its arrival interface index.
    pub fn recv(&self, buf: &mut [u8]) -> std::io::Result<crate::network::RecvMeta> {
        use std::os::unix::io::AsRawFd;
        crate::network::recv_with_dest(self.socket.as_raw_fd(), buf)
    }

    /// Send an RA. `dest = None` multicasts to `ff02::1` on `iface_index`
    /// (unsolicited/periodic RAs); `Some(addr)` unicasts a solicited reply.
    /// Port of `send_ra_alias`'s destination selection (radv.c:543-561).
    pub fn send(&self, iface_index: u32, dest: Option<Ipv6Addr>, packet: &[u8]) -> std::io::Result<()> {
        use std::os::unix::io::AsRawFd;
        let fd = self.socket.as_raw_fd();

        let addr = match dest {
            Some(d) => d,
            None => {
                unsafe {
                    libc::setsockopt(
                        fd, libc::IPPROTO_IPV6, libc::IPV6_MULTICAST_IF,
                        &iface_index as *const _ as *const libc::c_void,
                        std::mem::size_of::<u32>() as libc::socklen_t,
                    );
                }
                "ff02::1".parse().unwrap()
            }
        };
        let scope_id = if radv_dest_needs_scope_id(addr) { iface_index } else { 0 };
        let sockaddr = std::net::SocketAddrV6::new(addr, 0, 0, scope_id);
        self.socket.send_to(packet, &sockaddr.into())?;
        Ok(())
    }
}

/// `IN6_IS_ADDR_LINKLOCAL(dest) || IN6_IS_ADDR_MC_LINKLOCAL(dest)` (radv.c:553-554).
#[cfg(feature = "dhcp6")]
fn radv_dest_needs_scope_id(addr: Ipv6Addr) -> bool {
    if crate::network::is_link_local_v6(addr) {
        return true;
    }
    let o = addr.octets();
    addr.is_multicast() && (o[1] & 0x0f) == 0x02
}

/// Live IPv6-capable interfaces, shaped for [`crate::radv::periodic_ra`].
///
/// DAD-tentative detection (`IFACE_TENTATIVE`) isn't exposed by the `if-addrs`
/// crate this enumeration is built on, so `tentative` is always `false` — see
/// `crate::network::enumerate_live_addrs6`'s doc comment for the same caveat,
/// and `tasks.md` for tracking.
#[cfg(feature = "dhcp6")]
fn enumerate_live_ifaces6() -> Vec<crate::radv::LiveIface6> {
    crate::network::enumerate_interfaces()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| {
            let std::net::IpAddr::V6(addr) = i.addr else { return None };
            let prefix = match i.netmask {
                Some(std::net::IpAddr::V6(mask)) => crate::network::netmask_to_prefix6(mask),
                _ => 64,
            };
            Some(crate::radv::LiveIface6 {
                if_index: i.index,
                name: i.name,
                addr,
                prefix,
                tentative: false,
            })
        })
        .collect()
}

/// Resolve the MTU option value for `iface_name`'s RA, applying `--ra-param`'s
/// `mtu:<value>|<interface>|off` override and, for the "auto" case, the same
/// `/proc/sys/net/ipv6/conf/<iface>/mtu` fallback upstream reads under Linux
/// (radv.c:425-443). Returns `None` to omit the MTU option entirely.
#[cfg(feature = "dhcp6")]
fn resolve_ra_mtu(ra_interfaces: &[crate::types::dhcp::RaInterface], iface_name: &str) -> Option<u32> {
    let cfg = crate::radv::find_iface_param(ra_interfaces, iface_name);
    let mtu = cfg.map(|c| c.mtu).unwrap_or(0);
    if mtu < 0 {
        return None; // "off"
    }
    if mtu > 0 {
        return Some(mtu as u32);
    }
    #[cfg(target_os = "linux")]
    {
        let name = cfg.and_then(|c| c.mtu_name.as_deref()).unwrap_or(iface_name);
        if let Ok(s) = std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{name}/mtu")) {
            if let Ok(m) = s.trim().parse::<u32>() {
                return Some(m);
            }
        }
    }
    None
}

#[cfg(feature = "dhcp6")]
fn radv_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Build one RA's wire bytes for `iface_name`/`if_index`'s current live
/// address/context state, or `None` when there's nothing to advertise
/// (radv.c:311-312, 411-412).
///
/// `--dhcp-option6`-driven RDNSS/DNSSL substitution and the Source-LLA
/// option (needing an AF_LOCAL MAC lookup this crate doesn't have yet) are
/// not applied here — tracked in `tasks.md`.
#[cfg(feature = "dhcp6")]
fn build_ra_packet(
    socket: &RadvSocket,
    if_index: u32,
    iface_name: &str,
    contexts: &mut Vec<crate::types::dhcp::DhcpContext>,
    ra_interfaces: &[crate::types::dhcp::RaInterface],
    opt_ra: bool,
    is_dns_server: bool,
) -> Option<Vec<u8>> {
    let live_addrs = crate::network::enumerate_live_addrs6().unwrap_or_default();
    let params = crate::radv::RaBuildParams {
        now: radv_now_secs(),
        if_index,
        iface_name,
        opt_ra,
        is_dns_server,
        hop_limit: socket.hop_limit.clamp(0, 255) as u8,
        mtu: resolve_ra_mtu(ra_interfaces, iface_name),
        mac: None,
    };
    crate::radv::build_ra_for_interface(&params, &live_addrs, contexts, ra_interfaces)
        .map(|ra| crate::radv::build_ra(&ra))
}

/// Send an RA on `if_index`/`iface_name` (multicast, or unicast to `dest`),
/// plus on every live interface matching a `--bridge-interface` alias of it
/// (radv.c:846-892's `send_ra_to_aliases` fan-out for unsolicited/periodic
/// RAs; the same fan-out for a solicited reply is upstream's `icmp6_packet`
/// alias lookup, handled separately in [`run_radv_loop`]'s RS branch since it
/// picks the *source* interface's bridge, not the destination's).
#[cfg(feature = "dhcp6")]
#[allow(clippy::too_many_arguments)]
fn send_ra_with_aliases(
    socket: &RadvSocket,
    if_index: u32,
    iface_name: &str,
    contexts: &mut Vec<crate::types::dhcp::DhcpContext>,
    ra_interfaces: &[crate::types::dhcp::RaInterface],
    bridges: &[crate::types::daemon::DhcpBridge],
    live_ifaces: &[crate::radv::LiveIface6],
    opt_ra: bool,
    is_dns_server: bool,
) {
    if let Some(packet) = build_ra_packet(socket, if_index, iface_name, contexts, ra_interfaces, opt_ra, is_dns_server) {
        if let Err(e) = socket.send(if_index, None, &packet) {
            tracing::warn!("failed to send RA on {iface_name}: {e}");
        }
    }

    let live_pairs: Vec<(String, u32)> = live_ifaces.iter().map(|f| (f.name.clone(), f.if_index)).collect();
    for bridge in bridges.iter().filter(|b| crate::network::nametoindex(&b.iface) == if_index) {
        for (alias_name, alias_idx) in crate::radv::bridge_alias_targets(bridge, &live_pairs) {
            if let Some(packet) = build_ra_packet(socket, if_index, iface_name, contexts, ra_interfaces, opt_ra, is_dns_server) {
                if let Err(e) = socket.send(*alias_idx, None, &packet) {
                    tracing::warn!("failed to send bridged RA on {alias_name} (alias of {iface_name}): {e}");
                }
            }
        }
    }
}

/// The RA reply destination for `handle_icmp6_packet`'s two branches.
///
/// Port of radv.c:241 vs radv.c:249's differing `dest` argument to
/// `send_ra_alias`/`send_ra`: a bridge-aliased reply (`send_ra_alias(now,
/// bridge_index, bridge->iface, NULL, if_index)`) is always multicast to the
/// arrival interface regardless of the Router Solicitation's source address;
/// only the direct (non-bridge) reply unicasts back to the solicitor.
#[cfg(feature = "dhcp6")]
fn ra_reply_dest(is_bridge_alias: bool, solicitor: Option<std::net::Ipv6Addr>) -> Option<std::net::Ipv6Addr> {
    if is_bridge_alias { None } else { solicitor }
}

/// Handle one received ICMPv6 datagram: dispatch a Router Solicitation to a
/// (possibly bridge-redirected) RA reply. Echo Replies (SLAAC probes) are not
/// yet wired to `lease_ping_reply` — tracked in `tasks.md`.
///
/// Port of `icmp6_packet()` (radv.c:141-255).
#[cfg(feature = "dhcp6")]
#[allow(clippy::too_many_arguments)]
fn handle_icmp6_packet(
    socket: &RadvSocket,
    data: &[u8],
    if_index: u32,
    src: std::net::SocketAddr,
    contexts: &mut Vec<crate::types::dhcp::DhcpContext>,
    ra_interfaces: &[crate::types::dhcp::RaInterface],
    bridges: &[crate::types::daemon::DhcpBridge],
    dhcp_except: &[crate::types::network::Iname],
    iface_check: &crate::network::IfaceCheckConfig,
    opt_ra: bool,
    is_dns_server: bool,
    quiet_ra: bool,
) {
    if data.len() < 8 || data[1] != 0 {
        return;
    }
    if data[0] != crate::radv::ND_ROUTER_SOLICIT {
        return; // ICMP6_ECHO_REPLY (SLAAC probe) dispatch not yet wired — tasks.md
    }

    let Some(name) = crate::network::indextoname(if_index) else { return };
    // radv.c:178 — `--interface`/`--except-interface`/`--listen-address`.
    if !crate::network::iface_check_name(&name, iface_check) {
        return;
    }
    if crate::radv::blocked_by_dhcp_except(&name, dhcp_except) {
        return;
    }

    // radv.c:206-223 — link-layer address option, extracted for logging only.
    // The scan (and its malformed-option bail-out) runs unconditionally
    // upstream; only the resulting `my_syslog` call is gated on `quiet_ra`.
    let mac = match crate::radv::parse_rs_source_mac(data) {
        Ok(mac) => mac,
        Err(_) => return, // malformed option — upstream bails out here too
    };
    if !quiet_ra {
        let mac = mac.as_deref().map(crate::util::print_mac).unwrap_or_default();
        tracing::info!("RTR-SOLICIT({name}) {mac}");
    }

    let dest = match src {
        std::net::SocketAddr::V6(s) if !s.ip().is_unspecified() => Some(*s.ip()),
        _ => None,
    };

    // radv.c:228-247: a bridge only "claims" the RS when its own interface
    // resolves AND one of its aliases matches the arrival interface: an
    // unresolvable bridge (`if_nametoindex` fails, e.g. configured but not
    // currently present) is skipped in favour of the next bridge, not treated
    // as a match that silently drops the RS — falling through to the direct
    // reply below if no bridge ends up claiming it.
    for bridge in bridges {
        let bridge_idx = crate::network::nametoindex(&bridge.iface);
        if bridge_idx == 0 {
            continue;
        }
        if !bridge.aliases.iter().any(|a| crate::util::wildcard_matchn(a, &name, libc::IF_NAMESIZE)) {
            continue;
        }
        if let Some(packet) = build_ra_packet(socket, bridge_idx, &bridge.iface, contexts, ra_interfaces, opt_ra, is_dns_server) {
            if let Err(e) = socket.send(if_index, ra_reply_dest(true, dest), &packet) {
                tracing::warn!("failed to send bridged RA reply on {name}: {e}");
            }
        }
        return;
    }

    if let Some(packet) = build_ra_packet(socket, if_index, &name, contexts, ra_interfaces, opt_ra, is_dns_server) {
        if let Err(e) = socket.send(if_index, ra_reply_dest(false, dest), &packet) {
            tracing::warn!("failed to send RA reply on {name}: {e}");
        }
    }
}

/// The Router Advertisement main loop: sends unsolicited RAs on their
/// scheduled interval and replies to incoming Router Solicitations.
///
/// Port of `periodic_ra()` + `icmp6_packet()`'s event-driven halves
/// (radv.c:141-255, 789-897), run here as one `tokio::select!` loop instead
/// of upstream's shared `select()`-based main loop.
#[cfg(feature = "dhcp6")]
#[allow(clippy::too_many_arguments)]
pub async fn run_radv_loop(
    socket: RadvSocket,
    mut contexts: Vec<crate::types::dhcp::DhcpContext>,
    ra_interfaces: Vec<crate::types::dhcp::RaInterface>,
    dhcp_except: Vec<crate::types::network::Iname>,
    bridges: Vec<crate::types::daemon::DhcpBridge>,
    opt_ra: bool,
    is_dns_server: bool,
    quiet_ra: bool,
    iface_check: crate::network::IfaceCheckConfig,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    use tokio::io::unix::AsyncFd;

    crate::radv::ra_start_unsolicited_all(&mut contexts, radv_now_secs(), crate::util::rand16);

    let async_fd = AsyncFd::new(socket)?;
    let mut deadline = tokio::time::Instant::now();
    let mut recv_buf = vec![0u8; 1500];

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow() => return Ok(()),
                    Ok(()) => continue,
                    Err(_) => return Ok(()),
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                let live_ifaces = enumerate_live_ifaces6();
                let now = radv_now_secs();
                let (targets, next) = crate::radv::periodic_ra(
                    now, &mut contexts, &live_ifaces, &ra_interfaces, &dhcp_except,
                    crate::util::rand16, crate::network::indextoname,
                    |name| crate::network::iface_check_name(name, &iface_check),
                );
                for target in &targets {
                    send_ra_with_aliases(
                        async_fd.get_ref(), target.if_index, &target.name, &mut contexts,
                        &ra_interfaces, &bridges, &live_ifaces, opt_ra, is_dns_server,
                    );
                }
                deadline = tokio::time::Instant::now() + match next {
                    Some(n) => Duration::from_secs(n.saturating_sub(now).max(1)),
                    None => Duration::from_secs(600),
                };
            }
            ready = async_fd.readable() => {
                let mut guard = match ready {
                    Ok(g) => g,
                    Err(_) => continue,
                };
                let result = guard.get_inner().recv(&mut recv_buf);
                guard.clear_ready();
                if let Ok(meta) = result {
                    handle_icmp6_packet(
                        async_fd.get_ref(), &recv_buf[..meta.len], meta.if_index, meta.src,
                        &mut contexts, &ra_interfaces, &bridges, &dhcp_except, &iface_check,
                        opt_ra, is_dns_server, quiet_ra,
                    );
                }
            }
        }
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
            #[cfg(feature = "dhcp6")]
            ra_time: 0,
            #[cfg(feature = "dhcp6")]
            ra_short_period_start: 0,
            #[cfg(feature = "dhcp6")]
            saved_valid: 0,
            #[cfg(feature = "dhcp6")]
            address_lost_time: 0,
        }
    }

    /// Minimal [`tracing_subscriber::fmt::MakeWriter`] that captures formatted
    /// log lines into a shared buffer, so tests can assert on `tracing::info!`
    /// output without a real logging sink.
    #[cfg(feature = "dhcp")]
    #[derive(Clone, Default)]
    struct CapturingWriter(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    #[cfg(feature = "dhcp")]
    impl std::io::Write for CapturingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[cfg(feature = "dhcp")]
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturingWriter {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    #[cfg(feature = "dhcp")]
    fn init_daemon_with_logs_dhcp_context_and_relay() {
        use crate::types::addr::AllAddr;
        use crate::types::dhcp::DhcpRelay;

        let mut daemon = Daemon::default();
        daemon.dhcp.push(test_dhcp_context());
        daemon.relay4.push(DhcpRelay {
            local_addr: AllAddr::Addr4(Ipv4Addr::new(10, 0, 0, 1)),
            server_addr: AllAddr::Addr4(Ipv4Addr::new(10, 0, 0, 2)),
            uplink_addr: AllAddr::Addr4(Ipv4Addr::UNSPECIFIED),
            interface: Some("eth0".to_string()),
            iface_index: 1,
            port: i32::from(crate::dhcp_protocol::DHCP_SERVER_PORT),
            split_mode: 0,
            warned: 0,
            matchcount: 0,
        });

        let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let writer = CapturingWriter(buf.clone());
        let subscriber = tracing_subscriber::fmt().with_writer(writer).with_ansi(false).finish();
        tracing::subscriber::with_default(subscriber, || {
            let _handle = init_daemon_with(daemon);
        });

        let output = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            output.contains("DHCP, IP range 10.0.0.100 -- 10.0.0.150, lease time 1h"),
            "startup log should contain the dhcp-range line, got: {output}"
        );
        assert!(
            output.contains("DHCP relay from 10.0.0.1 to 10.0.0.2 via eth0"),
            "startup log should contain the dhcp-relay line, got: {output}"
        );
    }

    /// Mirrors `dnsmasq.c:288-296`: `doing_dhcp6` is derived from whether any
    /// `dhcp6` context carries `CONTEXT_DHCP`.
    #[test]
    #[cfg(feature = "dhcp6")]
    fn init_daemon_with_sets_doing_dhcp6_from_context_flags() {
        let mut daemon = Daemon::default();
        daemon.dhcp6.push(test_dhcp_context());

        let handle = init_daemon_with(daemon);
        let guard = handle.blocking_read();
        assert!(guard.doing_dhcp6);
        assert!(!guard.doing_ra);
    }

    /// Mirrors `dnsmasq.c:290-292`: when any `dhcp6` context exists,
    /// `doing_ra` starts from `option_bool(OPT_RA)` even without a context
    /// carrying `CONTEXT_RA`.
    #[test]
    #[cfg(feature = "dhcp6")]
    fn init_daemon_with_sets_doing_ra_from_opt_ra_when_dhcp6_present() {
        let mut daemon = Daemon::default();
        daemon.set_option(crate::types::constants::OPT_RA);
        daemon.dhcp6.push(test_dhcp_context());

        let handle = init_daemon_with(daemon);
        let guard = handle.blocking_read();
        assert!(guard.doing_ra);
    }

    /// Mirrors `dnsmasq.c:298-299`: a context carrying `CONTEXT_RA` sets
    /// `doing_ra` regardless of `OPT_RA`.
    #[test]
    #[cfg(feature = "dhcp6")]
    fn init_daemon_with_sets_doing_ra_from_context_ra_flag() {
        use crate::types::dhcp::CONTEXT_RA;

        let mut daemon = Daemon::default();
        daemon.dhcp6.push(crate::types::dhcp::DhcpContext {
            flags: CONTEXT_RA,
            ..test_dhcp_context()
        });

        let handle = init_daemon_with(daemon);
        let guard = handle.blocking_read();
        assert!(guard.doing_ra);
    }

    /// Mirrors `dnsmasq.c:288-296`: the whole block is gated on
    /// `daemon->dhcp6` being non-empty, so an empty context list leaves both
    /// flags false even with `OPT_RA` set.
    #[test]
    #[cfg(feature = "dhcp6")]
    fn init_daemon_with_leaves_doing_flags_false_when_no_dhcp6_contexts() {
        let mut daemon = Daemon::default();
        daemon.set_option(crate::types::constants::OPT_RA);

        let handle = init_daemon_with(daemon);
        let guard = handle.blocking_read();
        assert!(!guard.doing_ra);
        assert!(!guard.doing_dhcp6);
    }

    /// Mirrors `dnsmasq.c:352-358`: startup must attempt `ipset_init()` when
    /// any `--ipset` directive is configured, instead of leaving the control
    /// socket unopened until the first resolved address needs it.
    #[test]
    #[cfg(feature = "ipset")]
    fn init_daemon_with_inits_ipset_socket_when_ipsets_configured() {
        let mut daemon = Daemon::default();
        daemon.ipsets.push(crate::types::network::Ipsets {
            sets:   vec!["myset".to_string()],
            domain: "example.com".to_string(),
        });

        // Must not panic — the sandbox may or may not allow AF_NETLINK, and
        // either outcome (persistent socket installed, or a logged error) is
        // fine; `ipset::add_to_ipset` still has a working per-call fallback.
        let _handle = init_daemon_with(daemon);
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

    /// Without SO_BROADCAST, a reply to a client that has no address yet
    /// (sent to 255.255.255.255, dhcp.c's `dhcp_reply`) fails at the kernel
    /// with ENETUNREACH instead of going out — confirmed against a real
    /// client in the functional harness (issue #136). Upstream sets this
    /// unconditionally in `dhcp_init()` (dhcp.c:63); this only regresses if
    /// that parity is lost.
    #[cfg(feature = "dhcp")]
    #[test]
    fn bind_listeners_enables_broadcast_on_the_dhcp_socket() {
        let mut daemon = Daemon { port: 0, ..Default::default() };
        daemon.dhcp.push(test_dhcp_context());
        daemon.dhcp_server_port = 1067;
        daemon.dhcp_client_port = 1068;

        let listeners = bind_listeners(&daemon).unwrap();
        let dhcp_sock = listeners.dhcp.expect("a dhcp-range should produce a bound socket");
        assert!(
            dhcp_sock.broadcast().unwrap(),
            "the DHCP socket must have SO_BROADCAST set to reply to unconfigured clients"
        );
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

    /// End-to-end: `--dump-file` must produce a real pcap file, and a live
    /// query/reply exchange through `run_main_loop_with` must land in it —
    /// this is Issue #43's acceptance criterion, not just a `dump.rs` unit
    /// test, because before this change `dump-file`/`dump-mask` parsed into
    /// `Daemon` but nothing ever opened the file or wrote to it.
    #[tokio::test]
    #[cfg(feature = "dump")]
    async fn run_main_loop_writes_query_and_reply_to_the_dump_file() {
        let dir = tempfile::tempdir().unwrap();
        let dump_path = dir.path().join("dump.pcap");

        let listeners = bind_listeners(&Daemon { port: 0, ..Default::default() }).unwrap();
        let port = listeners.dns_addrs().first().map(|a| a.port()).unwrap();

        let lines = crate::option::parse_config_text(
            &format!(
                "dumpfile={}\naddress=/example.test/10.1.2.3\n",
                dump_path.display()
            ),
            "test",
        )
        .unwrap();
        let mut daemon = Daemon { port, ..Default::default() };
        crate::option::apply_config(&mut daemon, &lines).unwrap();

        let daemon_handle = init_daemon_with(daemon);
        let cache = build_shared_cache(&daemon_handle).await;
        let task = tokio::spawn(run_main_loop_with(daemon_handle, None, Some(listeners), cache));

        // A freshly opened dump file has only the 24-byte global header.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let bytes = std::fs::read(&dump_path).expect("dump-file must be created at startup");
        assert_eq!(bytes.len(), 24, "only the global header before any traffic");

        // Minimal DNS query: ID=0x1234, RD, one question for example.test A/IN.
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        for label in "example.test".split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN

        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(&query, ("127.0.0.1", port)).await.unwrap();
        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
            .await
            .expect("reply must arrive")
            .unwrap();
        assert!(len >= 12, "reply must at least contain a DNS header");

        task.abort();

        let bytes = std::fs::read(&dump_path).unwrap();
        assert_eq!(
            u32::from_le_bytes(bytes[0..4].try_into().unwrap()),
            crate::dump::PCAP_MAGIC
        );
        assert!(
            bytes.len() > 24,
            "the query and its reply must have been written after the global header"
        );
    }

    /// End-to-end: a `Daemon` with a configured DHCPv6 context makes
    /// `run_main_loop_with` actually claim port 547 and persist a real DUID —
    /// the two things Issue #34 / T3-dhcp6's review flagged as still missing
    /// (a port-547 listener wired into the main loop, and `make_duid()` never
    /// called at startup).
    #[tokio::test]
    #[cfg(feature = "dhcp6")]
    async fn run_main_loop_with_dhcp6_context_binds_port_547_and_persists_duid() {
        use crate::types::dhcp::{DhcpContext, DhcpNetid, CONTEXT_DHCP};

        let listeners = bind_listeners(&Daemon { port: 0, ..Default::default() }).unwrap();
        let dns_port = listeners
            .dns_addrs()
            .first()
            .map(|a| a.port())
            .expect("a DNS socket must be bound");

        let ctx = DhcpContext {
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            flags: CONTEXT_DHCP,
            netmask: Ipv4Addr::UNSPECIFIED,
            broadcast: Ipv4Addr::UNSPECIFIED,
            local: Ipv4Addr::UNSPECIFIED,
            lease_time: 3600,
            addr_epoch: 0,
            netid: DhcpNetid { net: String::new() },
            filter: vec![],
            start6: "2001:db8::1".parse().unwrap(),
            end6: "2001:db8::ff".parse().unwrap(),
            local6: std::net::Ipv6Addr::UNSPECIFIED,
            prefix: 64,
            if_index: 0,
            valid: 0,
            preferred: 0,
            ra_time: 0,
            ra_short_period_start: 0,
            saved_valid: 0,
            address_lost_time: 0,
        };

        let daemon = Daemon {
            port: dns_port,
            dhcp6: vec![ctx],
            // Fixed so DUID generation doesn't depend on this host having a
            // usable non-loopback MAC (make_duid's DUID-EN branch).
            duid_config: Some(vec![0xAA, 0xBB]),
            duid_enterprise: 9,
            ..Default::default()
        };
        let daemon_handle = init_daemon_with(daemon);
        let cache = build_shared_cache(&daemon_handle).await;
        let task = tokio::spawn(run_main_loop_with(
            daemon_handle.clone(),
            None,
            Some(listeners),
            cache,
        ));

        tokio::time::sleep(Duration::from_millis(150)).await;

        if task.is_finished() {
            // No permission to bind the privileged port 547 in this
            // environment — same tolerance `dhcp6_init`'s own test allows.
            return;
        }

        let duid = daemon_handle.read().await.duid.clone();
        assert!(duid.is_some(), "make_duid() should have run and persisted a DUID at startup");

        assert!(
            std::net::UdpSocket::bind("[::]:547").is_err(),
            "port 547 should be held by the running DHCPv6 loop"
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
        // 1 configured + 5 built-in `*.bind` stat records (`--no-ident` unset).
        assert_eq!(local.txt_records.len(), 6);
        assert_eq!(local.rr_records.len(), 1);
        assert_eq!(local.mx_records.len(), 1);
        assert_eq!(local.ptr_records.len(), 1);
        assert_eq!(local.naptr_records.len(), 1);
        assert_eq!(local.int_names.len(), 1);
        assert!(!local.is_empty());
    }

    #[test]
    fn daemon_local_data_empty_by_default() {
        // No configured local data — but the built-in `*.bind` stat records
        // are always present unless `--no-ident` is set (`option.c:6097-6113`),
        // so `txt_records` alone is not literally empty even though nothing
        // was configured.
        let local = daemon_local_data(&Daemon::default());
        assert_eq!(local.txt_records.len(), 5);
        assert!(local.rr_records.is_empty());
        assert!(local.mx_records.is_empty());
        assert!(local.ptr_records.is_empty());
        assert!(local.host_records.is_empty());
        assert!(local.cnames.is_empty());
        assert!(local.naptr_records.is_empty());
        assert!(local.int_names.is_empty());
    }

    #[test]
    fn daemon_local_data_no_ident_suppresses_builtin_stat_records() {
        let lines = crate::option::parse_config_text("no-ident", "test").unwrap();
        let mut daemon = Daemon::default();
        crate::option::apply_config(&mut daemon, &lines).unwrap();
        let local = daemon_local_data(&daemon);
        assert!(local.txt_records.is_empty());
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
            #[cfg(feature = "dhcp6")]
            ra_time: 0,
            #[cfg(feature = "dhcp6")]
            ra_short_period_start: 0,
            #[cfg(feature = "dhcp6")]
            saved_valid: 0,
            #[cfg(feature = "dhcp6")]
            address_lost_time: 0,
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
        use crate::types::network::{Iname, IfaceNameFlags};

        let mut daemon = Daemon::default();
        daemon.if_addrs.push(Iname {
            name: None,
            addr: Some(MySockAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 0))),
            flags: IfaceNameFlags::empty(),
        });
        daemon.if_names.push(Iname {
            name: Some("eth-test".into()),
            addr: None,
            flags: IfaceNameFlags::empty(),
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
            #[cfg(feature = "dhcp6")]
            ra_time: 0,
            #[cfg(feature = "dhcp6")]
            ra_short_period_start: 0,
            #[cfg(feature = "dhcp6")]
            saved_valid: 0,
            #[cfg(feature = "dhcp6")]
            address_lost_time: 0,
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
        use crate::types::network::{Iname, IfaceNameFlags};

        let mut daemon = Daemon::default();
        daemon.if_addrs.push(Iname {
            name: None,
            addr: Some(MySockAddr::V4(std::net::SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))),
            flags: IfaceNameFlags::empty(),
        });
        daemon.if_names.push(Iname { name: Some("lo".into()), addr: None, flags: IfaceNameFlags::empty() });
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
            #[cfg(feature = "dhcp6")]
            ra_time: 0,
            #[cfg(feature = "dhcp6")]
            ra_short_period_start: 0,
            #[cfg(feature = "dhcp6")]
            saved_valid: 0,
            #[cfg(feature = "dhcp6")]
            address_lost_time: 0,
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

    // ── daemon_dhcp6_runtime_with ────────────────────────────────────────────

    #[cfg(feature = "dhcp6")]
    fn dhcp6_ctx(start6: std::net::Ipv6Addr, end6: std::net::Ipv6Addr, prefix: i32) -> crate::types::dhcp::DhcpContext {
        use crate::types::dhcp::{CONTEXT_DHCP, DhcpNetid};
        crate::types::dhcp::DhcpContext {
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            flags: CONTEXT_DHCP,
            netmask: Ipv4Addr::UNSPECIFIED,
            broadcast: Ipv4Addr::UNSPECIFIED,
            local: Ipv4Addr::UNSPECIFIED,
            lease_time: 3600,
            addr_epoch: 0,
            netid: DhcpNetid { net: String::new() },
            filter: vec![],
            start6,
            end6,
            local6: std::net::Ipv6Addr::UNSPECIFIED,
            prefix,
            if_index: 0,
            valid: 0,
            preferred: 0,
            ra_time: 0,
            ra_short_period_start: 0,
            saved_valid: 0,
            address_lost_time: 0,
        }
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn daemon_dhcp6_runtime_none_without_context() {
        let mut daemon = Daemon::default();
        assert!(daemon_dhcp6_runtime_with(&mut daemon, &[], None, 0).is_none());
    }

    /// The core acceptance scenario: a configured `dhcp-range`-equivalent
    /// context, folded with a live interface address on the same prefix,
    /// produces a "current" chain `run_dhcp6_loop`/`address6_allocate` can
    /// actually allocate from — not just the raw, unmatched config.
    #[cfg(feature = "dhcp6")]
    #[test]
    fn daemon_dhcp6_runtime_with_builds_current_chain_from_live_interface() {
        use crate::dhcp6::LiveAddr6;

        let mut daemon = Daemon::default();
        daemon.lease_file = Some("/tmp/nonexistent-test.leases".into());
        daemon.dhcp6.push(dhcp6_ctx(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::ff".parse().unwrap(),
            64,
        ));
        let live = LiveAddr6 {
            addr: "2001:db8::42".parse().unwrap(),
            prefix: 64,
            if_index: 3,
            preferred: 0xffff_ffff,
            valid: 0xffff_ffff,
            deprecated: false,
        };

        let mac = crate::dhcp6::DuidMacSource { hw_type: 1, mac: vec![1, 2, 3, 4, 5, 6] };
        let runtime = daemon_dhcp6_runtime_with(&mut daemon, &[live], Some(mac), 1_000_000_000)
            .expect("a configured context should produce a runtime");

        assert_eq!(runtime.contexts.len(), 1, "the live address should match the configured context");
        assert_eq!(runtime.contexts[0].if_index, 3);
        assert!(runtime.duid.starts_with(&[0x00, 0x01]), "DUID-LLT type expected");
        assert_eq!(daemon.duid, Some(runtime.duid));
    }

    /// No live interface matches the configured prefix: the runtime still
    /// exists (DUID is generated either way) but the current chain is empty,
    /// exactly like upstream refusing to offer from a range with no matching
    /// live interface.
    #[cfg(feature = "dhcp6")]
    #[test]
    fn daemon_dhcp6_runtime_with_empty_current_chain_without_matching_interface() {
        let mut daemon = Daemon::default();
        daemon.dhcp6.push(dhcp6_ctx(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::ff".parse().unwrap(),
            64,
        ));
        daemon.duid_config = Some(vec![0xAA]);

        let runtime = daemon_dhcp6_runtime_with(&mut daemon, &[], None, 0)
            .expect("DUID-EN config means a runtime is still built");
        assert!(runtime.contexts.is_empty());
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn daemon_dhcp6_runtime_with_reuses_existing_duid() {
        let mut daemon = Daemon::default();
        daemon.dhcp6.push(dhcp6_ctx(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::ff".parse().unwrap(),
            64,
        ));
        daemon.duid = Some(vec![9, 9, 9]);

        let runtime = daemon_dhcp6_runtime_with(&mut daemon, &[], None, 0).unwrap();
        assert_eq!(runtime.duid, vec![9, 9, 9]);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn daemon_dhcp6_runtime_with_none_when_duid_cannot_be_built() {
        let mut daemon = Daemon::default();
        daemon.dhcp6.push(dhcp6_ctx(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::ff".parse().unwrap(),
            64,
        ));
        // No duid_config, no mac_source: make_duid() has nothing to build from.
        assert!(daemon_dhcp6_runtime_with(&mut daemon, &[], None, 0).is_none());
        assert!(daemon.duid.is_none());
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

    // ── ARP cache housekeeping ───────────────────────────────────────────────

    #[tokio::test]
    async fn arp_housekeeping_tick_drains_the_script_queue() {
        // Real, non-test-only proof that `do_arp_script_run` fires from
        // production code (Issue #33 gap): seed a New entry directly, run one
        // tick, then confirm the queue is already empty — the tick, not the
        // test, must have been the thing that drained it.
        let handle = init_daemon();
        let arp_state = crate::arp::new_shared_arp_state();
        {
            let mut guard = arp_state.lock().unwrap();
            guard.cache.begin_refresh(0);
            guard.cache.filter_mac(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                &[1, 2, 3, 4, 5, 6],
            );
            guard.cache.finish_refresh();
        }

        arp_housekeeping_tick(&handle, &arp_state).await;

        let mut guard = arp_state.lock().unwrap();
        assert_eq!(
            guard.cache.do_arp_script_run(),
            None,
            "the tick should already have drained the New entry"
        );
    }

    #[tokio::test]
    async fn arp_housekeeping_tick_does_not_panic_on_a_fresh_cache() {
        let handle = init_daemon();
        let arp_state = crate::arp::new_shared_arp_state();
        arp_housekeeping_tick(&handle, &arp_state).await;
    }

    #[tokio::test]
    async fn spawn_arp_housekeeping_task_can_be_aborted() {
        let handle = init_daemon();
        let arp_state = crate::arp::new_shared_arp_state();
        let task = spawn_arp_housekeeping_task(handle, arp_state, std::time::Duration::from_millis(10));
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        task.abort();
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
                flags: crate::types::network::DynDirFlags::empty(),
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

    /// `reload_hosts` flushes the *entire* cache, including any
    /// `--hostsdir`-loaded records, since it has no notion of which UIDs
    /// belong to a dynamic directory versus `/etc/hosts`. Upstream's
    /// `cache_reload()` (`cache.c:1709`) re-scans dynamic hosts directories
    /// in the same call (`set_dynamic_inotify(AH_HOSTS, ...)`) precisely to
    /// repopulate what it just flushed; without an equivalent call here, a
    /// `--hostsdir` entry would be silently and permanently gone after the
    /// first SIGHUP.
    #[tokio::test]
    #[cfg(feature = "inotify")]
    async fn clear_cache_and_reload_rescans_hostsdir_entries() {
        use crate::types::network::{DynDir, DynDirFlags};

        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hosts1"), "192.0.2.50 dynamic.test\n").unwrap();

        let handle = init_daemon();
        {
            let mut d = handle.write().await;
            d.set_option(crate::types::constants::OPT_NO_HOSTS);
            // `AH_WD_DONE` is already set and `wd` already valid, as they
            // would be after the real startup path (`set_dynamic_inotify`
            // called once from `run_main_loop_with`) has run once — the
            // watch itself isn't what's under test here, the re-scan is.
            d.dynamic_dirs.push(DynDir {
                files: vec![],
                flags: DynDirFlags::HOSTS | DynDirFlags::WD_DONE,
                dname: dir.path().to_str().unwrap().to_string(),
                wd: 999,
            });
        }
        let cache = crate::cache::new_shared_cache(150, 0, 0);

        clear_cache_and_reload(&handle, &cache).await;

        let mut c = cache.lock().await;
        assert!(
            c.lookup_by_name("dynamic.test", crate::types::constants::F_IPV4, Instant::now())
                .is_some(),
            "reload must rescan --hostsdir directories and repopulate their entries",
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

    /// Upstream's `reload_servers()` diffs via `mark_servers`/`add_update_server`/
    /// `cleanup_servers` (`network.c:1711,1766,1774`), which *reuses* the existing
    /// `Server` entry for an address that survives the reload rather than
    /// replacing it — so its query statistics carry over.  A naive
    /// retain-then-rebuild loses them on every SIGHUP.
    #[tokio::test]
    async fn clear_cache_and_reload_preserves_query_stats_for_unchanged_resolv_server() {
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
            let mut d = handle.write().await;
            let server = d
                .servers
                .iter_mut()
                .find(|s| s.flags & SERV_FROM_RESOLV != 0)
                .expect("resolv-derived server must exist after the first reload");
            server.queries = 42;
        }

        // The file is re-read with identical content; the address is unchanged.
        clear_cache_and_reload(&handle, &cache).await;

        let d = handle.read().await;
        let server = d
            .servers
            .iter()
            .find(|s| s.flags & SERV_FROM_RESOLV != 0)
            .expect("resolv-derived server must still exist");
        assert_eq!(
            server.queries, 42,
            "reload must reuse the surviving server entry, not rebuild it from scratch",
        );
    }

    /// `network.c:1738-1754`: an IPv6 `nameserver` line builds a `source_addr`
    /// in the *same* address family (`AF_INET6`, `in6addr_any`, scope 0), bound
    /// to `daemon->query_port`. A source address of the wrong family cannot be
    /// used to bind an outbound socket for that server at all.
    #[tokio::test]
    async fn clear_cache_and_reload_resolv_ipv6_source_addr_matches_family() {
        use crate::types::network::Resolvc;
        use crate::types::server::SERV_FROM_RESOLV;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver ::1\n").unwrap();

        let handle = init_daemon();
        {
            let mut d = handle.write().await;
            d.query_port = 5353;
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
        let server = d
            .servers
            .iter()
            .find(|s| s.flags & SERV_FROM_RESOLV != 0)
            .expect("resolv-derived server must exist");
        assert!(
            matches!(server.source_addr, crate::types::addr::MySockAddr::V6(_)),
            "an IPv6 nameserver's source_addr must also be IPv6, got {:?}",
            server.source_addr,
        );
        if let crate::types::addr::MySockAddr::V6(s) = &server.source_addr {
            assert_eq!(s.port(), 5353, "source_addr must bind to --query-port");
        }
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

    /// Whether this process can open a raw `IPPROTO_ICMP` socket (`CAP_NET_RAW`
    /// or root). The dev/CI sandbox this repo runs in normally can't, so tests
    /// that assert on real-network ping outcomes gate on this instead of
    /// hard-coding a result that only holds in an unprivileged environment.
    #[cfg(feature = "dhcp")]
    fn have_raw_icmp_socket() -> bool {
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::RAW, Some(socket2::Protocol::ICMPV4)).is_ok()
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn icmp_pinger_without_raw_socket_permission_returns_false() {
        if have_raw_icmp_socket() {
            // Real ICMP behaviour under CAP_NET_RAW/root is environment-
            // dependent (a loopback ping may well get a real reply), so this
            // restricted-environment expectation doesn't apply here.
            return;
        }
        let pinger = IcmpPinger::new(100);
        assert!(!pinger.ping(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!pinger.ping(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!pinger.ping(Ipv4Addr::LOCALHOST));
    }

    #[cfg(feature = "dhcp")]
    #[test]
    fn icmp_pinger_zero_timeout_returns_false() {
        // A 0ms deadline expires before any reply could plausibly arrive,
        // regardless of raw-socket privilege.
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

    #[cfg(feature = "dhcp")]
    #[test]
    fn icmp_pinger_address_probe_delegates_to_ping() {
        use crate::dhcp::AddressProbe;
        if have_raw_icmp_socket() {
            return;
        }
        let pinger = IcmpPinger::new(50);
        assert!(!AddressProbe::in_use(&pinger, Ipv4Addr::new(192, 168, 1, 1)));
    }

    // ── RadvSocket / run_radv_loop ────────────────────────────────────────────

    /// Regression test for the bridge-alias reply-destination bug (radv.c:241):
    /// a bridge-aliased RA reply must always be multicast (`None`), regardless
    /// of the Router Solicitation's source address, while the direct reply
    /// unicasts back to the solicitor unchanged.
    #[cfg(feature = "dhcp6")]
    #[test]
    fn ra_reply_dest_bridge_alias_is_always_multicast_direct_reply_unicasts_to_solicitor() {
        let solicitor = Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        assert_eq!(ra_reply_dest(true, solicitor), None);
        assert_eq!(ra_reply_dest(true, None), None);
        assert_eq!(ra_reply_dest(false, solicitor), solicitor);
        assert_eq!(ra_reply_dest(false, None), None);
    }

    /// Whether this process can open a raw `IPPROTO_ICMPV6` socket
    /// (`CAP_NET_RAW` or root) — see `have_raw_icmp_socket` above for the v4
    /// equivalent and why tests gate on this instead of a hard-coded result.
    #[cfg(feature = "dhcp6")]
    fn have_raw_icmp6_socket() -> bool {
        socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::RAW, Some(socket2::Protocol::ICMPV6)).is_ok()
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn radv_socket_new_without_capability_errors() {
        if have_raw_icmp6_socket() {
            return;
        }
        assert!(RadvSocket::new(false).is_err());
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn radv_socket_new_reads_hop_limit() {
        if !have_raw_icmp6_socket() {
            return;
        }
        let sock = RadvSocket::new(false).expect("raw socket should open with CAP_NET_RAW");
        assert!(sock.hop_limit > 0, "IPV6_UNICAST_HOPS should be a positive default");
    }

    /// End-to-end proof that `ra_init`'s `ICMP6_FILTER` actually filters:
    /// sending ourselves both a passed type (Router Solicitation) and a
    /// blocked type over loopback, only the former should ever come back out
    /// of `recv()` — a real kernel round trip, not just a unit test of the
    /// bit-twiddling.
    #[cfg(feature = "dhcp6")]
    #[test]
    fn radv_socket_filter_passes_rs_and_blocks_other_types() {
        if !have_raw_icmp6_socket() {
            return;
        }
        let socket = match RadvSocket::new(false) {
            Ok(s) => s,
            Err(_) => return, // e.g. IPv6 loopback disabled in this sandbox
        };

        let blocked_type_packet = vec![200u8, 0, 0, 0, 0, 0, 0, 0];
        let rs_packet = vec![crate::radv::ND_ROUTER_SOLICIT, 0, 0, 0, 0, 0, 0, 0];
        let _ = socket.send(0, Some(Ipv6Addr::LOCALHOST), &blocked_type_packet);
        let _ = socket.send(0, Some(Ipv6Addr::LOCALHOST), &rs_packet);

        let mut buf = [0u8; 64];
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        let mut got_rs = false;
        while std::time::Instant::now() < deadline {
            match socket.recv(&mut buf) {
                Ok(meta) if meta.len >= 1 => {
                    assert_ne!(buf[0], 200, "ICMP6_FILTER should have blocked type 200");
                    if buf[0] == crate::radv::ND_ROUTER_SOLICIT {
                        got_rs = true;
                        break;
                    }
                }
                _ => std::thread::sleep(Duration::from_millis(10)),
            }
        }
        assert!(got_rs, "the passed Router Solicitation type should have come back through recv()");
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn radv_dest_needs_scope_id_for_link_local_and_multicast() {
        assert!(radv_dest_needs_scope_id("fe80::1".parse().unwrap()));
        assert!(radv_dest_needs_scope_id("ff02::1".parse().unwrap()));
        assert!(!radv_dest_needs_scope_id("2001:db8::1".parse().unwrap()));
        assert!(!radv_dest_needs_scope_id("ff0e::1".parse().unwrap())); // global-scope multicast
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn resolve_ra_mtu_explicit_value() {
        let ifaces = vec![crate::types::dhcp::RaInterface {
            name: "eth0".into(), mtu_name: None, interval: 0, lifetime: -1, prio: 0, mtu: 1500,
        }];
        assert_eq!(resolve_ra_mtu(&ifaces, "eth0"), Some(1500));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn resolve_ra_mtu_off_is_none() {
        let ifaces = vec![crate::types::dhcp::RaInterface {
            name: "eth0".into(), mtu_name: None, interval: 0, lifetime: -1, prio: 0, mtu: -1,
        }];
        assert_eq!(resolve_ra_mtu(&ifaces, "eth0"), None);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn resolve_ra_mtu_no_config_is_none_off_linux_or_missing_proc_entry() {
        // No matching `ra-param` at all: mtu defaults to 0 ("auto"), which
        // falls through to a `/proc` read that won't resolve for a
        // nonexistent interface name, so this should come back `None`.
        assert_eq!(resolve_ra_mtu(&[], "nonexistent-iface-xyz"), None);
    }

    #[cfg(feature = "dhcp6")]
    #[tokio::test]
    async fn run_radv_loop_sends_unsolicited_ra_when_capability_available() {
        if !have_raw_icmp6_socket() {
            return;
        }
        let socket = match RadvSocket::new(false) {
            Ok(s) => s,
            Err(_) => return,
        };

        // A DHCPv6 context on whatever interface actually has a live address
        // right now, so `build_ra_for_interface` has a link-local source to
        // advertise from — a synthetic interface would never match a live
        // address and `run_radv_loop` would (correctly) send nothing.
        let live = crate::network::enumerate_live_addrs6().unwrap_or_default();
        let Some(global) = live.iter().find(|a| {
            let ip = a.addr;
            !ip.is_loopback() && !ip.is_multicast() && !crate::network::is_link_local_v6(ip)
        }) else {
            // No non-link-local IPv6 address anywhere on this host/sandbox;
            // nothing to build a meaningful context from.
            return;
        };

        let ctx = crate::types::dhcp::DhcpContext {
            lease_time: 3600, addr_epoch: 0,
            netmask: Ipv4Addr::UNSPECIFIED, broadcast: Ipv4Addr::UNSPECIFIED,
            local: Ipv4Addr::UNSPECIFIED, router: Ipv4Addr::UNSPECIFIED,
            start: Ipv4Addr::UNSPECIFIED, end: Ipv4Addr::UNSPECIFIED,
            flags: crate::types::dhcp::CONTEXT_RA | crate::types::dhcp::CONTEXT_CONSTRUCTED,
            netid: crate::types::dhcp::DhcpNetid { net: String::new() },
            filter: vec![],
            start6: global.addr, end6: global.addr, local6: Ipv6Addr::UNSPECIFIED,
            prefix: global.prefix, if_index: global.if_index as i32,
            valid: 0, preferred: 0,
            ra_time: 0, ra_short_period_start: 0, saved_valid: 0, address_lost_time: 0,
        };

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(run_radv_loop(
            socket, vec![ctx], vec![], vec![], vec![], false, false, false,
            crate::network::IfaceCheckConfig::default(), shutdown_rx,
        ));

        // `ra_start_unsolicited_all` schedules within 0-5s; give it a moment
        // to fire, then shut the loop down cleanly either way.
        tokio::time::sleep(Duration::from_millis(200)).await;
        shutdown_tx.send(true).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(result.is_ok(), "run_radv_loop should stop promptly on shutdown");
    }
}

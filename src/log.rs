/// Logging subsystem.
/// Ported from `log.c` — replaces syslog/vsyslog with `tracing` plus an
/// optional file backend, and adds a real `/dev/log` client with the bounded
/// async queue that makes writes to syslogd non-blocking.

use tracing::{debug, error, info, warn};
use std::collections::VecDeque;
use std::io::Write;
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

// ── Syslog priority constants ─────────────────────────────────────────────────
pub const LOG_EMERG:   u32 = 0;
pub const LOG_ALERT:   u32 = 1;
pub const LOG_CRIT:    u32 = 2;
pub const LOG_ERR:     u32 = 3;
pub const LOG_WARNING: u32 = 4;
pub const LOG_NOTICE:  u32 = 5;
pub const LOG_INFO:    u32 = 6;
pub const LOG_DEBUG:   u32 = 7;

/// Mask for the priority (severity) bits in a syslog priority value.
pub const LOG_PRIMASK: u32 = 0x07;

// ── Syslog facility constants ─────────────────────────────────────────────────
// Standard glibc `<sys/syslog.h>` facility numbers, needed both for the
// `MS_*` subsystem tags below and for `--log-facility=<name>` (option.c:2279-2298).
pub const LOG_KERN:     u32 = 0;
pub const LOG_USER:     u32 = 1  << 3;   //   8
pub const LOG_MAIL:     u32 = 2  << 3;   //  16
pub const LOG_DAEMON:   u32 = 3  << 3;   //  24
pub const LOG_AUTH:     u32 = 4  << 3;   //  32
pub const LOG_SYSLOG:   u32 = 5  << 3;   //  40
pub const LOG_LPR:      u32 = 6  << 3;   //  48
pub const LOG_NEWS:     u32 = 7  << 3;   //  56
pub const LOG_UUCP:     u32 = 8  << 3;   //  64
pub const LOG_CRON:     u32 = 9  << 3;   //  72
pub const LOG_AUTHPRIV: u32 = 10 << 3;   //  80
pub const LOG_FTP:      u32 = 11 << 3;   //  88
pub const LOG_LOCAL0:   u32 = 16 << 3;   // 128
pub const LOG_LOCAL1:   u32 = 17 << 3;   // 136
pub const LOG_LOCAL2:   u32 = 18 << 3;   // 144
pub const LOG_LOCAL3:   u32 = 19 << 3;   // 152
pub const LOG_LOCAL4:   u32 = 20 << 3;   // 160
pub const LOG_LOCAL5:   u32 = 21 << 3;   // 168
pub const LOG_LOCAL6:   u32 = 22 << 3;   // 176
pub const LOG_LOCAL7:   u32 = 23 << 3;   // 184

/// Mask for the facility bits in a syslog priority value.
pub const LOG_FACMASK: u32 = 0x03F8;

/// Look up a `--log-facility=<name>` facility name, mirroring glibc's
/// `facilitynames[]` table (used by `option.c:2292`'s `FindB` lookup).
/// Returns `None` for anything that isn't a recognised facility name — the
/// caller falls back to treating the value as invalid, matching upstream's
/// "bad log facility" rejection.
pub fn facility_by_name(name: &str) -> Option<u32> {
    Some(match name {
        "kern"     => LOG_KERN,
        "user"     => LOG_USER,
        "mail"     => LOG_MAIL,
        "daemon"   => LOG_DAEMON,
        "auth"     => LOG_AUTH,
        "syslog"   => LOG_SYSLOG,
        "lpr"      => LOG_LPR,
        "news"     => LOG_NEWS,
        "uucp"     => LOG_UUCP,
        "cron"     => LOG_CRON,
        "authpriv" => LOG_AUTHPRIV,
        "ftp"      => LOG_FTP,
        "local0"   => LOG_LOCAL0,
        "local1"   => LOG_LOCAL1,
        "local2"   => LOG_LOCAL2,
        "local3"   => LOG_LOCAL3,
        "local4"   => LOG_LOCAL4,
        "local5"   => LOG_LOCAL5,
        "local6"   => LOG_LOCAL6,
        "local7"   => LOG_LOCAL7,
        _ => return None,
    })
}

// ── Dnsmasq subsystem facility tags ──────────────────────────────────────────
/// OR these into the `priority` argument of `my_syslog` to tag the subsystem.
/// Values match the C source: `MS_TFTP = LOG_USER`, `MS_DHCP = LOG_DAEMON`, …
pub const MS_TFTP:   u32 = LOG_USER;   //  8
pub const MS_DHCP:   u32 = LOG_DAEMON; // 24
pub const MS_SCRIPT: u32 = LOG_MAIL;   // 16
pub const MS_DEBUG:  u32 = LOG_NEWS;   // 56

// ── Runtime log configuration ─────────────────────────────────────────────────

/// Maximum log message length (mirrors C `MAX_MESSAGE`).
pub const MAX_MESSAGE: usize = 1024;

/// Default path for the syslog datagram socket (mirrors `_PATH_LOG`, log.c:140).
const DEFAULT_SYSLOG_PATH: &str = "/dev/log";

/// Upper bound on `flush_log`'s drain loop, so a syslogd that never empties
/// its socket buffer can't hang process shutdown. Upstream's C loop
/// (log.c:461-473) is unbounded because it trusts the OS to eventually error
/// the fd out; this is the same idea with a safety net.
const MAX_FLUSH_ATTEMPTS: u32 = 1000;

/// Runtime logging configuration, initialised by `log_start`.
pub struct LogConfig {
    /// Default syslog facility (e.g. `LOG_DAEMON`).
    pub log_fac:     u32,
    /// Whether to echo messages to stderr.
    pub echo_stderr: bool,
    /// Optional file for log output. `None` → use tracing/syslog.
    log_file:        Option<std::fs::File>,
    /// True when output goes to a file rather than the syslog socket.
    pub log_to_file: bool,
    /// `--log-facility=stdout` (dnsmasq-rs extension — upstream has no
    /// stdout logging concept): `tracing` output goes to stdout instead of
    /// the default stderr, and real syslog delivery is bypassed the same
    /// way a file destination bypasses it.
    pub log_to_stdout: bool,
    /// `--log-facility=-`: explicit stderr, matching upstream's
    /// `dup(STDERR_FILENO)` (`log.c:75-79`). Distinct from the *default*
    /// no-destination-configured case, which also lands on stderr via
    /// [`LogSink`]'s fallback but — unlike this explicit choice — does not
    /// bypass real syslog delivery.
    pub log_explicit_stderr: bool,
    /// `--log-facility=journald` (`journald` feature; dnsmasq-rs extension).
    /// `Some(_)` once connected.
    #[cfg(feature = "journald")]
    journald: Option<JournaldClient>,
    /// Whether MS_DEBUG messages are printed (mirrors `OPT_LOG_DEBUG`).
    pub log_debug:   bool,
    /// Number of log entries dropped because the queue was full.
    pub entries_lost: u32,
    /// The `/dev/log` client and its deadlock-avoidance queue (log.c:23-28).
    /// Only used when `log_to_file` is false — a file backend can't deadlock
    /// against dnsmasq the way a blocking syslogd connection can.
    syslog: SyslogQueue,
}

impl std::fmt::Debug for LogConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogConfig")
            .field("log_fac",     &self.log_fac)
            .field("echo_stderr", &self.echo_stderr)
            .field("log_to_file", &self.log_to_file)
            .field("log_to_stdout", &self.log_to_stdout)
            .field("log_explicit_stderr", &self.log_explicit_stderr)
            .field("log_debug",   &self.log_debug)
            .field("entries_lost",&self.entries_lost)
            .finish()
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            log_fac:     LOG_DAEMON,
            echo_stderr: false,
            log_file:    None,
            log_to_file: false,
            log_to_stdout: false,
            log_explicit_stderr: false,
            #[cfg(feature = "journald")]
            journald: None,
            log_debug:   false,
            entries_lost: 0,
            // `log_fd == -1` "in case we die() before log_start()" (log.c:39):
            // `SyslogQueue::new` doesn't open anything, so `my_syslog` takes
            // the blocking openlog()/syslog() fallback until `log_start` runs.
            syslog: SyslogQueue::new(DEFAULT_SYSLOG_PATH, 5),
        }
    }
}

/// Where `log_start` should route `tracing`/`my_syslog` output, resolved by
/// the caller (`main.rs`) from `--log-facility=<value>`'s parsed string —
/// keeping the "what does this string mean" decision in one place rather
/// than smuggling sentinel strings (`-`, `stdout`, `journald`) through
/// `log.rs`'s own API.
pub enum LogTarget {
    /// No `--log-facility` given: `tracing` output falls back to stderr
    /// (see [`LogSink`]), but real syslog delivery still happens too —
    /// today's existing default behavior, unchanged.
    Default,
    /// `--log-facility=<path>`.
    File(std::path::PathBuf),
    /// `--log-facility=-`.
    Stderr,
    /// `--log-facility=stdout` (dnsmasq-rs extension).
    Stdout,
    /// `--log-facility=journald` (dnsmasq-rs extension, `journald` feature).
    #[cfg(feature = "journald")]
    Journald,
}

/// Global log configuration, set once by `log_start`.
static LOG_STATE: OnceLock<Mutex<LogConfig>> = OnceLock::new();

fn log_state() -> &'static Mutex<LogConfig> {
    LOG_STATE.get_or_init(|| Mutex::new(LogConfig::default()))
}

/// Zero-sized handle to the global [`LogConfig`] singleton.
///
/// The multi-field, deadlock-sensitive critical sections below (`log_start`,
/// `log_reopen`, `my_syslog`'s file-write block, `deliver_to_syslog`,
/// `flush_log`, `LogSink`) keep locking `log_state()` directly — their exact
/// lock-drop timing (releasing before a recursive `my_syslog` call, or before
/// a backoff sleep) is part of their documented correctness and doesn't
/// simplify by going through a named wrapper. `LogHandle` exists for the
/// handful of call sites that only need one field, so they read as "what do
/// I want" instead of "lock, map, unwrap_or".
#[derive(Clone, Copy)]
struct LogHandle;

impl LogHandle {
    fn current() -> Self {
        LogHandle
    }

    /// Whether `MS_DEBUG`-tagged messages should be emitted.
    fn is_debug_enabled(self) -> bool {
        log_state().lock().map(|c| c.log_debug).unwrap_or(false)
    }

    /// The configured syslog facility, or `LOG_DAEMON` if the lock is
    /// poisoned.
    fn facility(self) -> u32 {
        log_state().lock().map(|c| c.log_fac).unwrap_or(LOG_DAEMON)
    }

    /// Force stderr echoing on, unconditionally — `die()`'s "always print to
    /// stderr when dying" step.
    fn force_echo_stderr(self) {
        if let Ok(mut cfg) = log_state().lock() {
            cfg.echo_stderr = true;
        }
    }
}

/// Set once [`log_start`] has successfully installed [`LogSink`] as the global
/// `tracing` writer.  Sticky: a subscriber cannot be replaced once installed.
static SINK_INSTALLED: AtomicBool = AtomicBool::new(false);

/// Whether `tracing` output is being routed through the log backend.
///
/// When this is true, an ordinary `info!`/`warn!` from anywhere in the daemon
/// reaches the `log-facility` file, and code that must be heard after the
/// daemon's stdio has gone to `/dev/null` can rely on `tracing` alone.
pub fn sink_installed() -> bool {
    SINK_INSTALLED.load(Ordering::Relaxed)
}

/// The `tracing` output sink: the configured log file if there is one, else
/// stderr.
///
/// The target is resolved per write rather than captured at install time, so
/// [`log_reopen`] (SIGHUP log rotation) redirects `tracing` too.  Upstream gets
/// this for free by having exactly one `log_fd`.
struct LogSink;

impl Write for LogSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut cfg) = log_state().lock() {
            if let Some(ref mut file) = cfg.log_file {
                file.write_all(buf)?;
                return Ok(buf.len());
            }
            if cfg.log_to_stdout {
                return std::io::stdout().write(buf);
            }
            #[cfg(feature = "journald")]
            if let Some(ref journald) = cfg.journald {
                // `tracing_subscriber::fmt()` formats one line per write,
                // including the trailing newline; journald's `MESSAGE`
                // field is the line's text, without it. No structured
                // level is available at this layer (unlike `my_syslog`,
                // which knows its exact priority) — LOG_INFO is a
                // reasonable default for ordinary operational diagnostics.
                let text = String::from_utf8_lossy(buf);
                let _ = journald.submit(LOG_INFO, text.trim_end_matches('\n'));
                return Ok(buf.len());
            }
        }
        std::io::stderr().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Ok(mut cfg) = log_state().lock() {
            if let Some(ref mut file) = cfg.log_file {
                return file.flush();
            }
            if cfg.log_to_stdout {
                return std::io::stdout().flush();
            }
            #[cfg(feature = "journald")]
            if cfg.journald.is_some() {
                return Ok(());
            }
        }
        std::io::stderr().flush()
    }
}

// ── /dev/log client + deadlock-avoidance queue (log.c:23-28, 47-55, 124-284) ──

/// Which kind of AF_UNIX socket the syslog client is using. Starts as
/// `Dgram`; `log_write`'s reconnect logic flips it to `Stream` on
/// `EPROTOTYPE`, matching `connection_type` (log.c:45, 269-274).
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnType {
    Dgram,
    Stream,
}

enum LogFd {
    Dgram(UnixDatagram),
    Stream(UnixStream),
}

/// One queued, partially-or-not-yet-written log line. Mirrors `struct
/// log_entry` (log.c:47-52); `offset`/`length` become a slice into `payload`.
struct LogEntry {
    payload: Vec<u8>,
    offset:  usize,
    pid:     u32,
}

/// What `write_queue` should do next after a failed write.
enum RecoverOutcome {
    /// The fd is usable again (or was just replaced) — try the write again now.
    Retry,
    /// Transient: leave the entry queued and stop for this call.
    WaitForNextCall,
    /// Unrecoverable: the fd is being abandoned; carries the message for the
    /// `LOG_CRIT "log failed: %s"` report (log.c:280-282).
    GiveUp(String),
}

/// What happened while draining the queue, deferred so the caller can call
/// back into `my_syslog` (which needs the lock) only after releasing it.
#[derive(Default)]
struct DrainOutcome {
    /// `Some(n)` once an entry that had `entries_lost != 0` behind it finally
    /// drained, mirroring log.c:199-204's "overflow: N log entries lost".
    overflow_cleared: Option<u32>,
    /// Set when `write_queue` gave up on the fd entirely (log.c:280-282).
    fatal_error: Option<String>,
}

/// The `/dev/log` client and its bounded queue. This exists so that if
/// syslogd is itself making a DNS query through dnsmasq, dnsmasq blocking on
/// a write to syslogd can't deadlock the two daemons (log.c:23-28) — every
/// write here is non-blocking (when `max_logs != 0`) and failures queue
/// instead of stalling the caller.
///
/// Deliberately free of any reference to the global `LOG_STATE` mutex, so it
/// can be constructed and driven directly in tests without touching shared
/// process state.
struct SyslogQueue {
    path:            PathBuf,
    connection_type: ConnType,
    log_fd:          Option<LogFd>,
    connection_good: bool,
    entries:         VecDeque<LogEntry>,
    /// Mirrors `daemon->max_logs`: `0` means queuing is disabled (a single
    /// blocking slot); nonzero is the queue cap and enables `O_NONBLOCK`.
    max_logs:        usize,
    entries_lost:    u32,
}

impl SyslogQueue {
    fn new(path: impl Into<PathBuf>, max_logs: i32) -> Self {
        Self {
            path: path.into(),
            connection_type: ConnType::Dgram,
            log_fd: None,
            connection_good: true,
            entries: VecDeque::new(),
            max_logs: max_logs.max(0) as usize,
            entries_lost: 0,
        }
    }

    /// Queue capacity: `max_logs`, or 1 when queuing is disabled ("if
    /// queuing is inhibited, make sure we allocate the one required buffer
    /// now", log.c:91-98).
    fn capacity(&self) -> usize {
        self.max_logs.max(1)
    }

    /// Whether the socket should be non-blocking — upstream only sets
    /// `O_NONBLOCK` "if max_logs is zero, leave the socket blocking"
    /// (log.c:146-148), inverted.
    fn nonblocking(&self) -> bool {
        self.max_logs != 0
    }

    fn is_open(&self) -> bool {
        self.log_fd.is_some()
    }

    fn queue_len(&self) -> usize {
        self.entries.len()
    }

    fn close(&mut self) {
        self.log_fd = None;
    }

    /// Mirrors `log_reopen()`'s socket branch (log.c:124-154): drop whatever
    /// fd is open and create a fresh one of `connection_type`.
    ///
    /// The datagram case is left *unconnected* here, same as upstream, which
    /// calls `socket()` but never `connect()` in `log_reopen`. The first
    /// `write_queue()` attempt then fails with `EDESTADDRREQ` ("no peer
    /// address"), and the reconnect branch below (which upstream also uses
    /// for a `syslogd` restart) performs the actual `connect()`. That is a
    /// real upstream mechanism, not a Rust shortcut: it's how the initial
    /// connection to `/dev/log` gets made at all.
    fn reopen(&mut self) -> bool {
        self.log_fd = None;
        match self.connection_type {
            ConnType::Dgram => {
                if let Ok(sock) = UnixDatagram::unbound() {
                    if self.nonblocking() {
                        let _ = sock.set_nonblocking(true);
                    }
                    self.log_fd = Some(LogFd::Dgram(sock));
                }
            }
            ConnType::Stream => {
                // `std` has no unconnected-stream-socket constructor, unlike
                // libc's bare `socket(AF_UNIX, SOCK_STREAM, 0)`. Connecting
                // eagerly here instead of lazily on first write is the one
                // deliberate deviation from upstream in this file: the
                // observable result (a connected fd before the next write)
                // is the same either way.
                if let Ok(sock) = UnixStream::connect(&self.path) {
                    if self.nonblocking() {
                        let _ = sock.set_nonblocking(true);
                    }
                    self.log_fd = Some(LogFd::Stream(sock));
                }
            }
        }
        self.log_fd.is_some()
    }

    /// Mirrors the allocation half of `my_syslog()` (log.c:366-372): queue
    /// the payload if there's room, else count it as lost. Returns `true` if
    /// it was queued.
    fn enqueue(&mut self, payload: Vec<u8>, pid: u32) -> bool {
        if self.entries.len() >= self.capacity() {
            self.entries_lost += 1;
            return false;
        }
        self.entries.push_back(LogEntry { payload, offset: 0, pid });
        true
    }

    /// Mirrors `log_write()` (log.c:164-284): drain the queue, stopping on
    /// `EAGAIN`/`EWOULDBLOCK` (never blocks) rather than looping forever.
    fn write_queue(&mut self) -> DrainOutcome {
        let mut outcome = DrainOutcome::default();
        let my_pid = std::process::id();

        loop {
            let Some(front_pid) = self.entries.front().map(|e| e.pid) else { break };
            // "Avoid duplicates over a fork()" (log.c:183-188): a queued
            // entry from a parent process that then forked is dropped rather
            // than sent by the child.
            if front_pid != my_pid {
                self.entries.pop_front();
                continue;
            }
            if self.log_fd.is_none() {
                break;
            }
            self.connection_good = true;

            let total_len = self.entries.front().unwrap().payload.len();
            let result = {
                let entry = self.entries.front().unwrap();
                let buf = &entry.payload[entry.offset..];
                match self.log_fd.as_ref().unwrap() {
                    LogFd::Dgram(sock) => sock.send(buf),
                    LogFd::Stream(sock) => (&*sock).write(buf),
                }
            };

            match result {
                Ok(n) => {
                    let entry = self.entries.front_mut().unwrap();
                    entry.offset += n;
                    if entry.offset >= total_len {
                        self.entries.pop_front();
                        if self.entries_lost != 0 {
                            outcome.overflow_cleared = Some(self.entries_lost);
                            self.entries_lost = 0;
                        }
                    }
                    continue;
                }
                Err(e) => match self.handle_write_error(e) {
                    RecoverOutcome::Retry => continue,
                    RecoverOutcome::WaitForNextCall => break,
                    RecoverOutcome::GiveUp(msg) => {
                        self.log_fd = None;
                        outcome.fatal_error = Some(msg);
                        break;
                    }
                },
            }
        }

        outcome
    }

    fn handle_write_error(&mut self, e: std::io::Error) -> RecoverOutcome {
        use std::io::ErrorKind;

        if e.kind() == ErrorKind::Interrupted {
            return RecoverOutcome::Retry;
        }
        if e.kind() == ErrorKind::WouldBlock {
            // "syslogd busy, go again when select() or poll() says so" (log.c:213)
            return RecoverOutcome::WaitForNextCall;
        }
        let raw = e.raw_os_error();
        if raw == Some(libc::ENOBUFS) {
            self.connection_good = false;
            return RecoverOutcome::WaitForNextCall;
        }

        let is_epipe = raw == Some(libc::EPIPE);
        let is_gone = matches!(raw, Some(code) if code == libc::ECONNREFUSED
            || code == libc::ENOTCONN
            || code == libc::EDESTADDRREQ
            || code == libc::ECONNRESET);

        if is_epipe {
            // "Once a stream socket hits EPIPE, we have to close and re-open" (log.c:224-226)
            return if self.reopen() {
                RecoverOutcome::Retry
            } else {
                RecoverOutcome::GiveUp(format!("log failed: {e}"))
            };
        }
        if !is_gone {
            return RecoverOutcome::GiveUp(format!("log failed: {e}"));
        }

        self.try_reconnect(&e)
    }

    /// Mirrors the `connect()` retry block (log.c:242-274): try to
    /// (re)connect the existing socket to `/dev/log`; on `EPROTOTYPE`, flip
    /// between `SOCK_DGRAM`/`SOCK_STREAM` and reopen.
    fn try_reconnect(&mut self, original: &std::io::Error) -> RecoverOutcome {
        let path = self.path.clone();
        match self.log_fd.as_ref() {
            Some(LogFd::Dgram(sock)) => match sock.connect(&path) {
                Ok(()) => RecoverOutcome::Retry,
                Err(e) => {
                    let raw = e.raw_os_error();
                    if raw == Some(libc::EPROTOTYPE) {
                        self.connection_type = match self.connection_type {
                            ConnType::Dgram => ConnType::Stream,
                            ConnType::Stream => ConnType::Dgram,
                        };
                        return if self.reopen() {
                            RecoverOutcome::Retry
                        } else {
                            RecoverOutcome::GiveUp(format!("log failed: {original}"))
                        };
                    }
                    let keep_trying = matches!(raw, Some(code) if code == libc::ENOENT
                        || code == libc::EALREADY
                        || code == libc::ECONNREFUSED
                        || code == libc::EISCONN
                        || code == libc::EINTR)
                        || e.kind() == std::io::ErrorKind::WouldBlock;
                    if keep_trying {
                        self.connection_good = false;
                        RecoverOutcome::WaitForNextCall
                    } else {
                        RecoverOutcome::GiveUp(format!("log failed: {original}"))
                    }
                }
            },
            Some(LogFd::Stream(_)) => {
                if self.reopen() {
                    RecoverOutcome::Retry
                } else {
                    RecoverOutcome::GiveUp(format!("log failed: {original}"))
                }
            }
            None => RecoverOutcome::GiveUp(format!("log failed: {original}")),
        }
    }
}

/// Build the RFC 3164 wire payload for the syslog socket: `<pri>timestamp
/// dnsmasqTAG[pid]: message`. Mirrors the socket branch of `my_syslog()`
/// (log.c:386-401). This prefix is wire-protocol only — the file backend
/// (`write_message`, below) never has one, matching upstream turning the
/// trailing zero-terminator into a newline instead for `log_to_file`.
fn format_syslog_payload(level: u32, log_fac: u32, tag: &str, pid: u32, message: &str) -> Vec<u8> {
    let pri = (level & LOG_PRIMASK) | log_fac;
    let ts = rfc3164_timestamp();
    format!("<{pri}>{ts} dnsmasq{tag}[{pid}]: {message}").into_bytes()
}

/// `%b %e %H:%M:%S` in the local timezone — the same substring `ctime(&time_now)
/// + 4` truncated to 15 chars produces (log.c:393), gotten via `strftime`
/// instead of hand-rolled month/weekday tables.
fn rfc3164_timestamp() -> String {
    unsafe {
        let mut t: libc::time_t = 0;
        libc::time(&mut t);
        let mut tm: libc::tm = std::mem::zeroed();
        libc::localtime_r(&t, &mut tm);
        let mut buf = [0i8; 32];
        let fmt = std::ffi::CString::new("%b %e %H:%M:%S").unwrap();
        let len = libc::strftime(buf.as_mut_ptr(), buf.len(), fmt.as_ptr(), &tm);
        let bytes: Vec<u8> = buf[..len].iter().map(|&c| c as u8).collect();
        String::from_utf8(bytes).unwrap_or_default()
    }
}

/// Pre-init / permanently-broken-socket fallback: a single blocking
/// `openlog()`/`syslog()` call, matching `my_syslog`'s `log_fd == -1` branch
/// (log.c:329, 348-361) — "fall-back to syslog if we die during startup or
/// fail during running". This is the one place either implementation
/// deliberately blocks; it's reached rarely (before `log_start`, or after
/// `write_queue` gives up for good) so upstream accepts it there too.
static SYSLOG_OPENED: AtomicBool = AtomicBool::new(false);

fn blocking_syslog_fallback(level: u32, log_fac: u32, message: &str) {
    unsafe {
        if !SYSLOG_OPENED.swap(true, Ordering::SeqCst) {
            if let Ok(ident) = std::ffi::CString::new("dnsmasq") {
                libc::openlog(ident.as_ptr(), libc::LOG_PID, log_fac as libc::c_int);
            }
        }
        if let Ok(msg) = std::ffi::CString::new(message) {
            if let Ok(fmt) = std::ffi::CString::new("%s") {
                libc::syslog((level & LOG_PRIMASK) as libc::c_int, fmt.as_ptr(), msg.as_ptr());
            }
        }
    }
}

// ── journald client (no upstream counterpart; dnsmasq-rs extension) ───────────

/// A minimal client for journald's native protocol: a connected
/// `AF_UNIX SOCK_DGRAM` to `/run/systemd/journal/socket`, sending
/// newline-separated `KEY=value` fields per datagram (`sd_journal_send(3)`'s
/// wire format). Hand-rolled rather than depending on `tracing-journald`, so
/// there's one dependency-free logging-integration pattern in this codebase
/// rather than two (mirrors [`SyslogQueue`]'s own hand-rolled `/dev/log`
/// client).
///
/// Deliberately does not implement journald's memfd/`SCM_RIGHTS` fallback
/// for messages too large for a single datagram (journald's own practical
/// limit is in the hundreds of KB) — a dnsmasq-rs log line is never
/// realistically that large, and this is a known, documented limit rather
/// than a silent truncation: [`JournaldClient::submit`] simply returns the
/// `EMSGSIZE` error up to its caller, who logs it once via
/// `blocking_syslog_fallback`-style degradation rather than panicking.
#[cfg(feature = "journald")]
struct JournaldClient {
    sock: UnixDatagram,
}

#[cfg(feature = "journald")]
impl JournaldClient {
    const SOCKET_PATH: &'static str = "/run/systemd/journal/socket";

    fn connect() -> std::io::Result<Self> {
        Self::connect_to(Self::SOCKET_PATH)
    }

    /// Split out from [`Self::connect`] so tests can point this at a
    /// throwaway `UnixDatagram` instead of the real, host-dependent
    /// `/run/systemd/journal/socket` — mirroring how [`SyslogQueue::new`]
    /// takes its socket path as a parameter for the same reason.
    fn connect_to(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let sock = UnixDatagram::unbound()?;
        sock.connect(path)?;
        Ok(Self { sock })
    }

    /// Append one journald field. Values containing a newline use the
    /// binary framing journald requires (`KEY\n<8-byte LE length><value>\n`);
    /// everything else uses the plain `KEY=value\n` text framing.
    fn push_field(buf: &mut Vec<u8>, key: &str, value: &str) {
        if value.contains('\n') {
            buf.extend_from_slice(key.as_bytes());
            buf.push(b'\n');
            buf.extend_from_slice(&(value.len() as u64).to_le_bytes());
            buf.extend_from_slice(value.as_bytes());
            buf.push(b'\n');
        } else {
            buf.extend_from_slice(key.as_bytes());
            buf.push(b'=');
            buf.extend_from_slice(value.as_bytes());
            buf.push(b'\n');
        }
    }

    /// Send one journal entry. `priority` is a syslog level (0-7, `LOG_*`
    /// from this module), mapped straight across to journald's own
    /// `PRIORITY` field, which uses the same 0-7 scale.
    fn submit(&self, priority: u32, message: &str) -> std::io::Result<()> {
        let mut buf = Vec::with_capacity(message.len() + 64);
        Self::push_field(&mut buf, "MESSAGE", message);
        Self::push_field(&mut buf, "PRIORITY", &(priority & LOG_PRIMASK).to_string());
        Self::push_field(&mut buf, "SYSLOG_IDENTIFIER", "dnsmasq-rs");
        Self::push_field(&mut buf, "SYSLOG_PID", &std::process::id().to_string());
        self.sock.send(&buf)?;
        Ok(())
    }
}

// ── Initialisation ────────────────────────────────────────────────────────────

/// Initialise the logging subsystem.
///
/// Mirrors `log_start()` from the C source.  Sets up the tracing subscriber
/// for console/test output, optionally opens a log file, and — when no log
/// file is configured — opens the `/dev/log` client used by default.
///
/// - `log_file`: path to a log file; `None` → log to syslog (`/dev/log`).
/// - `log_fac`:  syslog facility; `None` → `LOG_DAEMON`.
/// - `echo_stderr`: if `true` all messages are also printed to stderr.
/// - `log_debug`: if `true` `MS_DEBUG` messages are not suppressed.
/// - `max_logs`: queue depth for the syslog client (mirrors `daemon->max_logs`,
///   `--log-async`); `0` disables queuing (a single blocking slot).
///
/// Returns `Ok(())` on success, or an IO error if the log file cannot be opened.
pub fn log_start(
    target:      LogTarget,
    log_fac:     Option<u32>,
    echo_stderr: bool,
    log_debug:   bool,
    max_logs:    i32,
) -> std::io::Result<()> {
    // Resolve the destination *before* installing the subscriber, so that a
    // bad `log-facility` path (or an unreachable journald socket) is
    // reported to the caller instead of being swallowed by the first log
    // line.
    let mut file = None;
    let mut to_stdout = false;
    let mut explicit_stderr = false;
    #[cfg(feature = "journald")]
    let mut journald = None;
    match target {
        LogTarget::Default => {}
        LogTarget::File(path) => {
            file = Some(
                std::fs::OpenOptions::new().write(true).create(true).append(true).open(&path)?,
            );
        }
        LogTarget::Stderr => explicit_stderr = true,
        LogTarget::Stdout => to_stdout = true,
        #[cfg(feature = "journald")]
        LogTarget::Journald => journald = Some(JournaldClient::connect()?),
    }
    let is_default = file.is_none() && !to_stdout && !explicit_stderr;
    #[cfg(feature = "journald")]
    let is_default = is_default && journald.is_none();

    let state = log_state();
    if let Ok(mut cfg) = state.lock() {
        cfg.log_fac     = log_fac.unwrap_or(LOG_DAEMON);
        cfg.echo_stderr = echo_stderr;
        cfg.log_to_file = file.is_some();
        cfg.log_file    = file;
        cfg.log_to_stdout = to_stdout;
        cfg.log_explicit_stderr = explicit_stderr;
        #[cfg(feature = "journald")]
        {
            cfg.journald = journald;
        }
        cfg.log_debug   = log_debug;
        cfg.entries_lost = 0;
        cfg.syslog = SyslogQueue::new(DEFAULT_SYSLOG_PATH, max_logs);
        if is_default {
            cfg.syslog.reopen();
        }
    }

    // Route `tracing` at the log backend rather than at stdout.  Upstream calls
    // `log_start()` from the middle of the daemonization sequence (dnsmasq.c:717)
    // — after the fork, before stdio goes to /dev/null — for exactly this
    // reason: past that point the process has no terminal, and anything still
    // writing to stdout is talking to nobody.
    let installed = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| {
                    let level = if log_debug { "debug" } else { "info" };
                    tracing_subscriber::EnvFilter::new(level)
                }),
        )
        .with_ansi(false)
        .with_writer(|| LogSink)
        .try_init()
        .is_ok();
    if installed {
        SINK_INSTALLED.store(true, Ordering::Relaxed);
    }

    Ok(())
}

/// Re-open the log file (or the syslog socket, when there is no log file)
/// after a SIGHUP (log rotation). Mirrors `log_reopen()` from the C source.
pub fn log_reopen(log_file: Option<&std::path::Path>) -> std::io::Result<()> {
    let state = log_state();
    let mut cfg = state.lock().unwrap();

    if let Some(path) = log_file {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .append(true)
            .open(path)?;
        cfg.log_file    = Some(f);
        cfg.log_to_file = true;
    } else {
        cfg.log_file    = None;
        cfg.log_to_file = false;
        cfg.syslog.reopen();
    }
    Ok(())
}

// ── Logging ───────────────────────────────────────────────────────────────────

/// Map a syslog priority to the subsystem tag string used in log messages.
fn subsystem_tag(priority: u32) -> &'static str {
    match priority & LOG_FACMASK {
        f if f == MS_TFTP   => "-tftp",
        f if f == MS_DHCP   => "-dhcp",
        f if f == MS_SCRIPT => "-script",
        f if f == MS_DEBUG  => "-debug",
        _                   => "",
    }
}

/// Extract the raw severity level (0–7) from a syslog priority.
#[inline]
pub fn log_priority(priority: u32) -> u32 {
    priority & LOG_PRIMASK
}

/// Emit a log message, mirroring `my_syslog(priority, fmt, ...)`.
///
/// Priority is a syslog priority (e.g. `LOG_INFO`, `LOG_ERR`) optionally
/// OR'd with an `MS_*` facility tag.
///
/// Routing:
/// - `MS_DEBUG` facility — suppressed unless `log_debug` is set; routed to `debug!`
/// - `LOG_DEBUG` (7)   → `tracing::debug!`
/// - `LOG_INFO`  (6) / `LOG_NOTICE` (5) → `tracing::info!`
/// - `LOG_WARNING` (4) → `tracing::warn!`
/// - `LOG_ERR` (3) and below → `tracing::error!`
///
/// If a log file is configured the message is also written there (one line per
/// entry) — either directly, or, once [`log_start`] has installed the `tracing`
/// sink, through `tracing`, which means the process-wide `RUST_LOG` filter
/// applies.  That is one deviation from upstream, whose `my_syslog` filters
/// only on `MS_DEBUG`; it keeps `my_syslog` and the rest of the daemon's output
/// under a single, consistent level control.
///
/// When there is no log file, the message *also* goes to the real `/dev/log`
/// socket via the bounded queue in [`SyslogQueue`] — `tracing` alone would
/// mean nothing ever reached the system log, which is the behavior this
/// function exists to avoid.
pub fn my_syslog(priority: u32, message: &str) {
    let fac   = priority & LOG_FACMASK;
    let level = priority & LOG_PRIMASK;
    let tag   = subsystem_tag(priority);

    // Check whether MS_DEBUG messages are enabled
    if fac == MS_DEBUG && !LogHandle::current().is_debug_enabled() {
        return;
    }

    // Build the final log line (tracing macros already add context).
    // For file output we need the full string.
    let line = if tag.is_empty() {
        message.to_string()
    } else {
        format!("dnsmasq{}: {}", tag, message)
    };

    // Route to tracing
    match level {
        LOG_DEBUG                          => debug!("{}", line),
        LOG_INFO | LOG_NOTICE              => info!("{}", line),
        LOG_WARNING                        => warn!("{}", line),
        _                                  => error!("{}", line),
    }

    // Also write to the log file — unless the tracing sink is already writing
    // there, in which case the record above has been delivered and a second
    // copy would duplicate every line.
    let mut bypass_real_syslog = false;
    let state = log_state();
    if let Ok(mut cfg) = state.lock() {
        // An explicit non-default destination (file, stdout, explicit
        // stderr, or journald) replaces real syslog delivery entirely,
        // matching upstream's single-`log_fd` model — only the *default*
        // (nothing configured) case delivers to both stderr (via the
        // tracing record above) and the real `/dev/log` socket below.
        #[cfg(feature = "journald")]
        let journald_active = cfg.journald.is_some();
        #[cfg(not(feature = "journald"))]
        let journald_active = false;
        bypass_real_syslog =
            cfg.log_to_file || cfg.log_to_stdout || cfg.log_explicit_stderr || journald_active;
        // With no log file/stdout/journald destination the sink is stderr,
        // so the record above already landed there and echoing would print
        // every line twice.
        let sink_is_stderr =
            sink_installed() && cfg.log_file.is_none() && !cfg.log_to_stdout && !journald_active;
        if cfg.echo_stderr && !sink_is_stderr {
            eprintln!("dnsmasq{}: {}", tag, message);
        }
        if !sink_installed() {
            if let Some(ref mut file) = cfg.log_file {
                let _ = writeln!(file, "dnsmasq{}: {}", tag, message);
            }
        }
    }

    // Real syslog delivery: upstream always queues through exactly one
    // `log_fd`, a file or `/dev/log`, never both. The file/stdout/stderr/
    // journald cases are handled above via the tracing sink; the default
    // (nothing configured) case reaches the actual syslog socket here.
    if !bypass_real_syslog {
        deliver_to_syslog(level, LogHandle::current().facility(), tag, message);
    }
}

/// Queue `message` for `/dev/log` and try to write it now, mirroring the
/// tail of `my_syslog()` (log.c:366-442): enqueue, attempt a write
/// immediately ("almost always, logging won't block"), then — if a backlog
/// remains and queuing is enabled — a short exponential backoff and one more
/// attempt, so a fast burst (a cache dump, say) doesn't blow through the
/// queue in a handful of calls.
fn deliver_to_syslog(level: u32, log_fac: u32, tag: &str, message: &str) {
    let pid = std::process::id();
    let mut pending: Vec<(u32, String)> = Vec::new();

    {
        let state = log_state();
        let Ok(mut cfg) = state.lock() else { return };

        if !cfg.syslog.is_open() {
            drop(cfg);
            blocking_syslog_fallback(level, log_fac, message);
            return;
        }

        let payload = format_syslog_payload(level, log_fac, tag, pid, message);
        cfg.syslog.enqueue(payload, pid);
        let outcome = cfg.syslog.write_queue();
        collect_outcome(outcome, &mut pending);

        if cfg.syslog.nonblocking() {
            let depth = cfg.syslog.queue_len() as i32;
            let cap = cfg.syslog.capacity() as i32;
            let mut d = depth;
            if d == cap {
                d = 0;
            } else if cap > 8 {
                d -= cap - 8;
            }
            if d > 0 {
                let shift = (d - 1).clamp(0, 7) as u32;
                drop(cfg);
                std::thread::sleep(Duration::from_micros(1000u64 << shift));
                if let Ok(mut cfg) = log_state().lock() {
                    let outcome = cfg.syslog.write_queue();
                    collect_outcome(outcome, &mut pending);
                }
            }
        }
    }

    for (lvl, msg) in pending {
        my_syslog(lvl, &msg);
    }
}

fn collect_outcome(outcome: DrainOutcome, pending: &mut Vec<(u32, String)>) {
    if let Some(n) = outcome.overflow_cleared {
        pending.push((LOG_WARNING, format!("overflow: {n} log entries lost")));
    }
    if let Some(msg) = outcome.fatal_error {
        pending.push((LOG_CRIT, msg));
    }
}

/// Write a formatted log line directly to a `Write` implementation.
/// This is the pure-I/O core used by `my_syslog`'s file backend.
/// Exposed as `pub(crate)` so unit tests can exercise it without global state.
pub(crate) fn write_message<W: Write>(w: &mut W, tag: &str, message: &str) -> std::io::Result<()> {
    writeln!(w, "dnsmasq{}: {}", tag, message)
}

// ── Poll-loop integration ────────────────────────────────────────────────────

/// Register the log file descriptor with the poll loop when entries are queued.
///
/// In the C source this calls `poll_listen(log_fd, POLLOUT)` so `select()`
/// wakes the process exactly when the syslog socket becomes writable
/// (log.c:445-449). `dnsmasq-rs`'s forward loop has no generic fd-readiness
/// registration to hook into, so [`check_log_writer`] is instead driven from
/// that loop's existing 1-second ticker (`forward.rs`'s `run_forward_loop_on`)
/// — since every write attempt here is already non-blocking by construction,
/// polling periodically rather than on exact readiness costs at most one
/// tick of latency, never correctness.
pub fn set_log_writer() {
    // No fd-readiness registration to perform — see doc comment above.
}

/// Drain the log queue. Mirrors `check_log_writer()` (log.c:451-455), which
/// only calls `log_write()` when the fd is open; `force` upstream means
/// "the poll loop said this fd is writable or the caller wants a write
/// attempt regardless" — both cases just mean "try now" here, since a
/// non-blocking write either succeeds, drains partially, or returns
/// immediately with `WouldBlock`.
pub fn check_log_writer(_force: bool) {
    let mut pending = Vec::new();
    if let Ok(mut cfg) = log_state().lock() {
        if cfg.syslog.is_open() {
            let outcome = cfg.syslog.write_queue();
            collect_outcome(outcome, &mut pending);
        }
    }
    for (lvl, msg) in pending {
        my_syslog(lvl, &msg);
    }
}

/// Flush all queued log entries before shutdown.
///
/// Mirrors `flush_log()` from the C source: keep writing until the syslog
/// queue empties or the connection goes bad, then close the socket, bounded
/// by [`MAX_FLUSH_ATTEMPTS`] so a wedged syslogd can't hang shutdown.
pub fn flush_log() {
    {
        let state = log_state();
        if let Ok(mut cfg) = state.lock() {
            if let Some(ref mut file) = cfg.log_file {
                let _ = file.flush();
            }
            if cfg.entries_lost > 0 {
                let n = cfg.entries_lost;
                cfg.entries_lost = 0;
                drop(cfg); // release lock before calling my_syslog
                my_syslog(LOG_WARNING, &format!("overflow: {} log entries lost", n));
            }
        }
    }

    for _ in 0..MAX_FLUSH_ATTEMPTS {
        let mut pending = Vec::new();
        let keep_going = {
            let state = log_state();
            let Ok(mut cfg) = state.lock() else { return };
            if !cfg.syslog.is_open() {
                false
            } else {
                let outcome = cfg.syslog.write_queue();
                collect_outcome(outcome, &mut pending);
                if cfg.syslog.queue_len() == 0 || !cfg.syslog.connection_good {
                    cfg.syslog.close();
                    false
                } else {
                    true
                }
            }
        };
        for (lvl, msg) in pending {
            my_syslog(lvl, &msg);
        }
        if !keep_going {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

// ── Fatal error ───────────────────────────────────────────────────────────────

/// Log a fatal error to the log and terminate the process.
///
/// Mirrors `die()` from the C source.
/// `arg` is substituted for `%s` in the message (like the C `arg1` parameter).
pub fn die(message: &str, arg: Option<&str>, exit_code: i32) -> ! {
    LogHandle::current().force_echo_stderr(); // always print to stderr when dying
    let full = match arg {
        Some(a) => format!("{}: {}", message, a),
        None    => message.to_string(),
    };
    my_syslog(LOG_CRIT, &full);
    my_syslog(LOG_CRIT, "FAILED to start up");
    flush_log();
    std::process::exit(exit_code);
}

// ── Exit codes (mirrors C EC_* constants) ────────────────────────────────────
pub const EC_MISC:  i32 = 5;
pub const EC_NOMEM: i32 = 6;
pub const EC_BADCONF: i32 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ms_flags_use_syslog_facilities() {
        // MS_* values must be distinct syslog facility codes
        assert_eq!(MS_TFTP,   LOG_USER);
        assert_eq!(MS_DHCP,   LOG_DAEMON);
        assert_eq!(MS_SCRIPT, LOG_MAIL);
        assert_eq!(MS_DEBUG,  LOG_NEWS);
    }

    #[test]
    fn ms_flags_distinct() {
        assert_ne!(MS_TFTP, MS_DHCP);
        assert_ne!(MS_DHCP, MS_SCRIPT);
        assert_ne!(MS_SCRIPT, MS_DEBUG);
    }

    #[test]
    fn log_priority_extracts_severity() {
        assert_eq!(log_priority(LOG_INFO),              LOG_INFO);
        assert_eq!(log_priority(MS_DHCP | LOG_WARNING), LOG_WARNING);
        assert_eq!(log_priority(MS_DEBUG | LOG_DEBUG),  LOG_DEBUG);
    }

    #[test]
    fn subsystem_tag_correct() {
        assert_eq!(subsystem_tag(MS_TFTP   | LOG_INFO), "-tftp");
        assert_eq!(subsystem_tag(MS_DHCP   | LOG_INFO), "-dhcp");
        assert_eq!(subsystem_tag(MS_SCRIPT | LOG_INFO), "-script");
        assert_eq!(subsystem_tag(MS_DEBUG  | LOG_DEBUG), "-debug");
        assert_eq!(subsystem_tag(LOG_INFO),             "");
    }

    #[test]
    fn my_syslog_does_not_panic() {
        // Verify no panic on any priority level or subsystem tag
        for p in [
            LOG_EMERG, LOG_ALERT, LOG_CRIT, LOG_ERR,
            LOG_WARNING, LOG_NOTICE, LOG_INFO, LOG_DEBUG,
            MS_TFTP | LOG_INFO,
            MS_DHCP | LOG_INFO,
            MS_SCRIPT | LOG_WARNING,
            MS_DEBUG | LOG_DEBUG,
        ] {
            my_syslog(p, "test message");
        }
    }

    #[test]
    fn log_start_no_file_succeeds() {
        // Should succeed even if called multiple times (try_init is idempotent)
        let _ = log_start(LogTarget::Default, None, false, false, 5);
    }

    #[test]
    fn write_message_appends_to_writer() {
        // Test the pure file-write path without relying on global state
        let mut buf = Vec::<u8>::new();
        write_message(&mut buf, "-dhcp", "lease acquired").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("dnsmasq-dhcp: lease acquired"));
    }

    #[test]
    fn write_message_empty_tag() {
        let mut buf = Vec::<u8>::new();
        write_message(&mut buf, "", "plain message").unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("dnsmasq: plain message"));
    }

    #[test]
    fn log_reopen_switches_file() {
        let dir   = tempfile::tempdir().unwrap();
        let path2 = dir.path().join("b.log");
        // Set up a fresh file on path2 without using global state
        let mut f = std::fs::File::create(&path2).unwrap();
        write_message(&mut f, "-dhcp", "second file").unwrap();
        drop(f);
        let c2 = std::fs::read_to_string(&path2).unwrap();
        assert!(c2.contains("second file"));
    }

    #[test]
    fn set_check_log_writer_do_not_panic() {
        set_log_writer();
        check_log_writer(true);
        check_log_writer(false);
    }

    #[test]
    fn ec_constants_distinct() {
        assert_ne!(EC_MISC, EC_NOMEM);
        assert_ne!(EC_MISC, EC_BADCONF);
    }

    // ── facility name table (option.c:2279-2298's `facilitynames[]` lookup) ──

    #[test]
    fn facility_by_name_known_names() {
        assert_eq!(facility_by_name("kern"),     Some(LOG_KERN));
        assert_eq!(facility_by_name("daemon"),   Some(LOG_DAEMON));
        assert_eq!(facility_by_name("user"),     Some(LOG_USER));
        assert_eq!(facility_by_name("authpriv"), Some(LOG_AUTHPRIV));
        assert_eq!(facility_by_name("local0"),   Some(LOG_LOCAL0));
        assert_eq!(facility_by_name("local7"),   Some(LOG_LOCAL7));
    }

    #[test]
    fn facility_by_name_rejects_unknown() {
        assert_eq!(facility_by_name("not-a-facility"), None);
        assert_eq!(facility_by_name(""), None);
    }

    // ── SyslogQueue: pure queue-capacity behavior, no global state, no I/O ──

    #[test]
    fn enqueue_respects_capacity_and_counts_losses() {
        let mut q = SyslogQueue::new("/nonexistent/path/for/test.sock", 2);
        assert!(q.enqueue(b"one".to_vec(), 1));
        assert!(q.enqueue(b"two".to_vec(), 1));
        assert!(!q.enqueue(b"three".to_vec(), 1)); // over capacity: dropped
        assert_eq!(q.queue_len(), 2);
        assert_eq!(q.entries_lost, 1);
    }

    #[test]
    fn zero_max_logs_forces_single_slot_capacity() {
        // "if queuing is inhibited, make sure we allocate the one required
        // buffer now" (log.c:91-98).
        let mut q = SyslogQueue::new("/nonexistent/path/for/test.sock", 0);
        assert!(q.enqueue(b"one".to_vec(), 1));
        assert!(!q.enqueue(b"two".to_vec(), 1));
        assert_eq!(q.entries_lost, 1);
        assert!(!q.nonblocking());
    }

    // ── SyslogQueue: real AF_UNIX SOCK_DGRAM delivery ──────────────────────

    #[test]
    fn write_queue_delivers_to_a_listening_unix_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.sock");
        let listener = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        listener.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

        let mut q = SyslogQueue::new(&path, 5);
        assert!(q.reopen());
        let payload = format_syslog_payload(LOG_INFO, LOG_DAEMON, "", std::process::id(), "hello");
        assert!(q.enqueue(payload.clone(), std::process::id()));
        let outcome = q.write_queue();
        assert!(outcome.fatal_error.is_none());
        assert_eq!(q.queue_len(), 0);

        let mut buf = [0u8; 256];
        let n = listener.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], payload.as_slice());
    }

    /// The core deadlock-avoidance guarantee (log.c:23-28): when syslogd
    /// isn't there yet, the write must not block, entries must queue up to
    /// the cap and report loss beyond it, and delivery must resume once the
    /// socket appears — matching "queue up to MAX_LOGS messages... if more
    /// are queued, they will be dropped, and the drop event itself logged."
    #[test]
    fn write_queue_reconnects_once_the_socket_appears_and_reports_overflow() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("late.sock");

        let mut q = SyslogQueue::new(&path, 2);
        assert!(q.reopen());
        assert!(q.enqueue(b"a".to_vec(), std::process::id()));
        assert!(q.enqueue(b"b".to_vec(), std::process::id()));

        // No listener yet: the write must fail without blocking and leave
        // the fd open so a later call can retry.
        let start = std::time::Instant::now();
        let first = q.write_queue();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(first.fatal_error.is_none());
        assert_eq!(q.queue_len(), 2);

        // Queue is now full: the next message is dropped and counted.
        assert!(!q.enqueue(b"c".to_vec(), std::process::id()));
        assert_eq!(q.entries_lost, 1);

        let listener = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        listener.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

        let outcome = q.write_queue();
        assert_eq!(outcome.overflow_cleared, Some(1));
        assert_eq!(q.queue_len(), 0);

        let mut buf = [0u8; 256];
        assert!(listener.recv(&mut buf).is_ok());
        assert!(listener.recv(&mut buf).is_ok());
    }

    #[test]
    fn format_syslog_payload_matches_rfc3164_shape() {
        let payload = format_syslog_payload(LOG_INFO, LOG_DAEMON, "-dhcp", 42, "lease acquired");
        let s = String::from_utf8(payload).unwrap();
        assert!(s.starts_with(&format!("<{}>", LOG_INFO | LOG_DAEMON)));
        assert!(s.contains("dnsmasq-dhcp[42]: lease acquired"));
    }

    /// The whole point of the queue: a burst of `my_syslog` calls against an
    /// unreachable syslog socket must return promptly rather than stall the
    /// caller (log.c:23-28's deadlock-avoidance rationale).
    #[test]
    fn my_syslog_does_not_block_when_syslog_is_unreachable() {
        {
            let mut cfg = log_state().lock().unwrap();
            cfg.log_to_file = false;
            cfg.syslog = SyslogQueue::new("/nonexistent/definitely/not/a/socket.sock", 5);
            cfg.syslog.reopen();
        }
        let start = std::time::Instant::now();
        for _ in 0..20 {
            my_syslog(LOG_INFO, "unreachable syslog burst");
        }
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    // ── journald client (feature-gated; no upstream counterpart) ──────────────

    #[cfg(feature = "journald")]
    #[test]
    fn journald_push_field_plain_value_uses_text_framing() {
        let mut buf = Vec::new();
        JournaldClient::push_field(&mut buf, "MESSAGE", "lease acquired");
        assert_eq!(buf, b"MESSAGE=lease acquired\n");
    }

    #[cfg(feature = "journald")]
    #[test]
    fn journald_push_field_multiline_value_uses_binary_framing() {
        let mut buf = Vec::new();
        JournaldClient::push_field(&mut buf, "MESSAGE", "line one\nline two");
        let mut expected = b"MESSAGE\n".to_vec();
        expected.extend_from_slice(&("line one\nline two".len() as u64).to_le_bytes());
        expected.extend_from_slice(b"line one\nline two");
        expected.push(b'\n');
        assert_eq!(buf, expected);
    }

    /// End-to-end against a throwaway datagram socket standing in for
    /// `/run/systemd/journal/socket` — mirrors
    /// `write_queue_delivers_to_a_listening_unix_socket`'s pattern for the
    /// real `/dev/log` client, so this doesn't depend on the test host
    /// actually running systemd-journald.
    #[cfg(feature = "journald")]
    #[test]
    fn journald_submit_sends_expected_fields() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.sock");
        let listener = std::os::unix::net::UnixDatagram::bind(&path).unwrap();
        listener.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

        let client = JournaldClient::connect_to(&path).unwrap();
        client.submit(LOG_WARNING, "disk almost full").unwrap();

        let mut buf = [0u8; 512];
        let n = listener.recv(&mut buf).unwrap();
        let payload = String::from_utf8_lossy(&buf[..n]);
        assert!(payload.contains("MESSAGE=disk almost full\n"));
        assert!(payload.contains(&format!("PRIORITY={}\n", LOG_WARNING)));
        assert!(payload.contains("SYSLOG_IDENTIFIER=dnsmasq-rs\n"));
        assert!(payload.contains(&format!("SYSLOG_PID={}\n", std::process::id())));
    }

    #[cfg(feature = "journald")]
    #[test]
    fn journald_connect_to_missing_socket_fails() {
        assert!(JournaldClient::connect_to("/nonexistent/definitely/not/a/journal.sock").is_err());
    }
}

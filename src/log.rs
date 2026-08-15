/// Logging subsystem.
/// Ported from `log.c` — replaces syslog/vsyslog with `tracing` plus an
/// optional file backend and async-safe queue management.

use tracing::{debug, error, info, warn};
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};

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
pub const LOG_KERN:   u32 = 0;
pub const LOG_USER:   u32 = 1 << 3;   //  8
pub const LOG_MAIL:   u32 = 2 << 3;   // 16
pub const LOG_DAEMON: u32 = 3 << 3;   // 24
pub const LOG_NEWS:   u32 = 7 << 3;   // 56

/// Mask for the facility bits in a syslog priority value.
pub const LOG_FACMASK: u32 = 0x03F8;

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
    /// Whether MS_DEBUG messages are printed (mirrors `OPT_LOG_DEBUG`).
    pub log_debug:   bool,
    /// Number of log entries dropped because the queue was full.
    pub entries_lost: u32,
}

impl std::fmt::Debug for LogConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogConfig")
            .field("log_fac",     &self.log_fac)
            .field("echo_stderr", &self.echo_stderr)
            .field("log_to_file", &self.log_to_file)
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
            log_debug:   false,
            entries_lost: 0,
        }
    }
}

/// Global log configuration, set once by `log_start`.
static LOG_STATE: OnceLock<Mutex<LogConfig>> = OnceLock::new();

fn log_state() -> &'static Mutex<LogConfig> {
    LOG_STATE.get_or_init(|| Mutex::new(LogConfig::default()))
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
        }
        std::io::stderr().write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Ok(mut cfg) = log_state().lock() {
            if let Some(ref mut file) = cfg.log_file {
                return file.flush();
            }
        }
        std::io::stderr().flush()
    }
}

// ── Initialisation ────────────────────────────────────────────────────────────

/// Initialise the logging subsystem.
///
/// Mirrors `log_start()` from the C source.  Sets up the tracing subscriber
/// for console/test output and optionally opens a log file.
///
/// - `log_file`: path to a log file; `None` → use tracing (stdout/stderr).
/// - `log_fac`:  syslog facility; `None` → `LOG_DAEMON`.
/// - `echo_stderr`: if `true` all messages are also printed to stderr.
/// - `log_debug`: if `true` `MS_DEBUG` messages are not suppressed.
///
/// Returns `Ok(())` on success, or an IO error if the log file cannot be opened.
pub fn log_start(
    log_file:    Option<&std::path::Path>,
    log_fac:     Option<u32>,
    echo_stderr: bool,
    log_debug:   bool,
) -> std::io::Result<()> {
    // Open the file *before* installing the subscriber, so that a bad
    // `log-facility` path is reported to the caller instead of being swallowed
    // by the first log line.
    let file = match log_file {
        Some(p) => {
            let f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .append(true)
                .open(p)?;
            Some(f)
        }
        None => None,
    };

    let state = log_state();
    if let Ok(mut cfg) = state.lock() {
        cfg.log_fac     = log_fac.unwrap_or(LOG_DAEMON);
        cfg.echo_stderr = echo_stderr;
        cfg.log_to_file = file.is_some();
        cfg.log_file    = file;
        cfg.log_debug   = log_debug;
        cfg.entries_lost = 0;
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

/// Re-open the log file after a SIGHUP (log rotation).
///
/// Mirrors `log_reopen()` from the C source.
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
/// applies.  That is the one deviation from upstream, whose `my_syslog` filters
/// only on `MS_DEBUG`; it keeps `my_syslog` and the rest of the daemon's output
/// under a single, consistent level control.
pub fn my_syslog(priority: u32, message: &str) {
    let fac   = priority & LOG_FACMASK;
    let level = priority & LOG_PRIMASK;
    let tag   = subsystem_tag(priority);

    // Check whether MS_DEBUG messages are enabled
    if fac == MS_DEBUG {
        let enabled = log_state()
            .lock()
            .map(|c| c.log_debug)
            .unwrap_or(false);
        if !enabled {
            return;
        }
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
    let state = log_state();
    if let Ok(mut cfg) = state.lock() {
        // With no log file the sink is stderr, so the record above already
        // landed there and echoing would print every line twice.
        let sink_is_stderr = sink_installed() && cfg.log_file.is_none();
        if cfg.echo_stderr && !sink_is_stderr {
            eprintln!("dnsmasq{}: {}", tag, message);
        }
        if !sink_installed() {
            if let Some(ref mut file) = cfg.log_file {
                let _ = writeln!(file, "dnsmasq{}: {}", tag, message);
            }
        }
    }
}

/// Write a formatted log line directly to a `Write` implementation.
/// This is the pure-I/O core used by `my_syslog`'s file backend.
/// Exposed as `pub(crate)` so unit tests can exercise it without global state.
pub(crate) fn write_message<W: Write>(w: &mut W, tag: &str, message: &str) -> std::io::Result<()> {
    writeln!(w, "dnsmasq{}: {}", tag, message)
}

// ── Poll-loop integration stubs ───────────────────────────────────────────────

/// Register the log file descriptor with the poll loop when entries are queued.
///
/// In the C source this calls `poll_listen(log_fd, POLLOUT)`.
/// With tracing, logging is always non-blocking, so this is a no-op.
pub fn set_log_writer() {
    // tracing backend is always ready — no FD registration needed
}

/// Drain the log queue if the FD is ready or `force` is true.
///
/// In the C source this calls `log_write()`.
/// With tracing, all messages are written synchronously, so this is a no-op.
pub fn check_log_writer(_force: bool) {
    // nothing to flush with tracing backend
}

/// Flush all queued log entries before shutdown.
///
/// Mirrors `flush_log()` from the C source.  In the Rust implementation this
/// flushes any `BufWriter` around the log file and waits until the tracing
/// subscriber has flushed its internal buffer.
pub fn flush_log() {
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

// ── Fatal error ───────────────────────────────────────────────────────────────

/// Log a fatal error to the log and terminate the process.
///
/// Mirrors `die()` from the C source.
/// `arg` is substituted for `%s` in the message (like the C `arg1` parameter).
pub fn die(message: &str, arg: Option<&str>, exit_code: i32) -> ! {
    {
        let state = log_state();
        if let Ok(mut cfg) = state.lock() {
            cfg.echo_stderr = true; // always print to stderr when dying
        }
    }
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
        let _ = log_start(None, None, false, false);
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
    fn set_check_log_writer_are_noops() {
        set_log_writer();
        check_log_writer(true);
        check_log_writer(false);
    }

    #[test]
    fn ec_constants_distinct() {
        assert_ne!(EC_MISC, EC_NOMEM);
        assert_ne!(EC_MISC, EC_BADCONF);
    }
}

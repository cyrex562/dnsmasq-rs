/// Logging subsystem.
/// Ported from `log.c` — replaces syslog/vsyslog with `tracing`.

use tracing::{debug, error, info, warn};

// Log facility codes (mirroring syslog priorities used in C code)
pub const MS_TFTP:   u32 = 0x0001;
pub const MS_DHCP:   u32 = 0x0002;
pub const MS_SCRIPT: u32 = 0x0004;
pub const MS_DEBUG:  u32 = 0x0008;

/// Initialise the tracing subscriber.  Call once at startup.
/// Level is controlled by the `RUST_LOG` environment variable,
/// defaulting to `info`.
pub fn log_start() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();
}

/// Emit a log message, mirroring `my_syslog(priority, fmt, ...)`.
///
/// The `facility` parameter accepts the `MS_*` constants above as well as
/// standard syslog priority values.  We map them to tracing levels:
///   - MS_DEBUG / LOG_DEBUG  → `debug!`
///   - LOG_INFO / LOG_NOTICE → `info!`
///   - LOG_WARNING           → `warn!`
///   - LOG_ERR and above     → `error!`
pub fn my_syslog(priority: u32, message: &str) {
    // Syslog priorities: 0=EMERG 1=ALERT 2=CRIT 3=ERR 4=WARNING 5=NOTICE 6=INFO 7=DEBUG
    let level = priority & 0x07;
    match level {
        7 | _ if priority & MS_DEBUG != 0 => debug!("{}", message),
        6 | 5 => info!("{}", message),
        4     => warn!("{}", message),
        _     => error!("{}", message),
    }
}

/// Log a fatal error and terminate the process.
/// Mirrors `die()` from the C code.
pub fn die(message: &str, arg: Option<&str>, exit_code: i32) -> ! {
    let full = match arg {
        Some(a) => format!("{message}: {a}"),
        None    => message.to_string(),
    };
    error!("FATAL: {}", full);
    std::process::exit(exit_code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ms_flags_distinct() {
        assert_ne!(MS_TFTP, MS_DHCP);
        assert_ne!(MS_DHCP, MS_SCRIPT);
        assert_ne!(MS_SCRIPT, MS_DEBUG);
    }

    #[test]
    fn my_syslog_does_not_panic() {
        // Just verify no panic on any priority level
        for p in [0u32, 3, 4, 5, 6, 7, MS_DEBUG, MS_DHCP] {
            my_syslog(p, "test message");
        }
    }
}

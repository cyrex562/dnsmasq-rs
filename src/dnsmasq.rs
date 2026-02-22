//! Daemon initialization and process-management helpers.
//!
//! Mirrors the startup logic in `dnsmasq.c` (the original 2478-line C file).

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
}

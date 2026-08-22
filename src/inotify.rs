#![cfg(feature = "inotify")]

//! Real inotify-based watching of resolv-file directories and dynamic
//! hosts directories (`--hostsdir` / `--dhcp-hostsdir` / `--dhcp-optsdir`),
//! mirroring dnsmasq's `inotify.c`.
//!
//! Implemented:
//! - [`inotify_dnsmasq_init`] — opens the inotify fd and, for each configured
//!   `resolv-file`, follows symlinks (bounded, mirroring `my_readlink` +
//!   `MAXSYMLINKS`) and watches the containing directory for
//!   `IN_CLOSE_WRITE | IN_MOVED_TO`.
//! - [`set_dynamic_inotify`] — watches each `daemon.dynamic_dirs` entry
//!   (`IN_CLOSE_WRITE | IN_MOVED_TO | IN_DELETE`), then — watch-then-scan, to
//!   avoid missing a file that lands mid-startup — does the initial
//!   directory scan for `AH_HOSTS` (`--hostsdir`) entries, loading existing
//!   files into the cache.
//! - [`inotify_check`] — drains pending events and dispatches: a hit on a
//!   watched resolv-file sets the returned `hit` flag (the caller decides
//!   whether to force a resolv reload); a hit on an `AH_HOSTS` dynamic
//!   directory flushes the previous load's cache entries
//!   (`DnsCache::remove_by_uid`) and, unless the event was a deletion,
//!   reloads the file (`cache::load_hosts_file`).
//! - [`watch_inotify_changes`] — the runtime consumer: an `AsyncFd` readiness
//!   loop (mirroring `netlink::watch_address_changes`'s pattern) that calls
//!   `inotify_check` on wakeup and, on a resolv-file hit, forces
//!   [`crate::dnsmasq::clear_cache_and_reload`] — unless `--no-poll`
//!   (`OPT_NO_POLL`) is set, matching upstream's gate at
//!   `dnsmasq.c:1236` (`daemon->port != 0 && !option_bool(OPT_NO_POLL)`).
//!
//! Not implemented: `dhcp-hostsdir`/`dhcp-optsdir` (`AH_DHCP_HST`/
//! `AH_DHCP_OPT`) directories are watched (so `inotify_check` recognizes
//! their `wd` and doesn't error) but not scanned or read back on change,
//! because this port has no `option_read_dynfile` /
//! `dhcp_update_configs`/`lease_update_*` equivalent yet — only whole-config
//! `reread_dhcp` (SIGHUP) exists. Tracked in `tasks.md`.

use crate::cache::DnsCache;
use crate::types::constants::{OPT_NO_POLL, OPT_NO_RESOLV, UID_NONE};
use crate::types::daemon::Daemon;
use crate::types::network::{DynDir, HostsFile, AH_HOSTS, AH_WD_DONE};

/// Which file event triggered a reload.
#[derive(Debug, Clone, PartialEq)]
pub enum WatchEvent {
    Modified(String),
    Moved(String),
    Deleted(String),
}

pub mod mask {
    pub const IN_MODIFY:      u32 = 0x0000_0002;
    pub const IN_CLOSE_WRITE: u32 = 0x0000_0008;
    pub const IN_MOVED_TO:    u32 = 0x0000_0080;
    pub const IN_DELETE:      u32 = 0x0000_0200;
}

// inotify_event layout (little-endian, as from the kernel):
//   i32  wd      (4 bytes)
//   u32  mask    (4 bytes)
//   u32  cookie  (4 bytes)
//   u32  len     (4 bytes)
//   u8   name[len]
const HEADER_LEN: usize = 16;

/// Parse a raw inotify event from a byte buffer.
/// Returns `(watch_descriptor, mask, filename)` or `None` on truncation.
pub fn parse_inotify_event(buf: &[u8]) -> Option<(i32, u32, String)> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let wd = i32::from_ne_bytes(buf[0..4].try_into().ok()?);
    let mask = u32::from_ne_bytes(buf[4..8].try_into().ok()?);
    let len = u32::from_ne_bytes(buf[12..16].try_into().ok()?) as usize;

    if buf.len() < HEADER_LEN + len {
        return None;
    }

    let name_bytes = &buf[HEADER_LEN..HEADER_LEN + len];
    // The kernel pads the name with NUL bytes up to `len`; trim them.
    let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(len);
    let name = std::str::from_utf8(&name_bytes[..name_end]).ok()?.to_string();

    Some((wd, mask, name))
}

/// Total on-wire size (header + padded name) of the event starting at the
/// front of `buf`, used to step through a buffer holding multiple packed
/// events. Returns `None` if `buf` doesn't even hold a full header.
fn inotify_event_size(buf: &[u8]) -> Option<usize> {
    if buf.len() < HEADER_LEN {
        return None;
    }
    let len = u32::from_ne_bytes(buf[12..16].try_into().ok()?) as usize;
    Some(HEADER_LEN + len)
}

/// Convert raw inotify event to a [`WatchEvent`].
/// Returns `None` if the mask doesn't match a tracked event.
pub fn to_watch_event(mask: u32, path: &str) -> Option<WatchEvent> {
    if mask & (self::mask::IN_MODIFY | self::mask::IN_CLOSE_WRITE) != 0 {
        Some(WatchEvent::Modified(path.to_string()))
    } else if mask & self::mask::IN_MOVED_TO != 0 {
        Some(WatchEvent::Moved(path.to_string()))
    } else if mask & self::mask::IN_DELETE != 0 {
        Some(WatchEvent::Deleted(path.to_string()))
    } else {
        None
    }
}

/// Ignore emacs backups (`foo~`), lock files (`#foo#`) and dotfiles, matching
/// the filters in upstream `inotify_check`/`set_dynamic_inotify`.
fn is_ignorable_filename(name: &str) -> bool {
    if name.is_empty() || name.starts_with('.') {
        return true;
    }
    if name.ends_with('~') {
        return true;
    }
    let bytes = name.as_bytes();
    bytes.len() >= 2 && bytes[0] == b'#' && bytes[bytes.len() - 1] == b'#'
}

/// Bound on symlink-following depth, mirroring `MAXSYMLINKS` (`sys/param.h`).
const MAXSYMLINKS: u32 = 40;

/// Follow a (possibly relative) symlink chain to its final target.
///
/// Mirrors the `my_readlink` loop in upstream `inotify_dnsmasq_init`
/// (`inotify.c:39-86,107-114`): each relative link target is resolved
/// against the directory of the path it was found in. Returns the original
/// path unchanged once it stops being a symlink (or doesn't exist — upstream
/// treats `ENOENT` the same as "not a link", since the resolv directory
/// still needs to exist even if the file inside it doesn't yet). Errors if
/// the chain exceeds `MAXSYMLINKS` or a `readlink` fails for any other
/// reason (upstream calls `die()` in both cases; this returns `Err` instead
/// so the caller can log and continue rather than aborting the process).
pub fn resolve_symlink_chain(path: &str) -> std::io::Result<String> {
    let mut current = path.to_string();
    let mut links_left = MAXSYMLINKS;

    loop {
        match std::fs::read_link(&current) {
            Ok(target) => {
                if links_left == 0 {
                    return Err(std::io::Error::other(format!(
                        "too many symlinks following {path}"
                    )));
                }
                links_left -= 1;

                current = if target.is_absolute() {
                    target.to_string_lossy().to_string()
                } else {
                    let dir = std::path::Path::new(&current).parent();
                    match dir {
                        Some(d) if !d.as_os_str().is_empty() => {
                            d.join(&target).to_string_lossy().to_string()
                        }
                        _ => target.to_string_lossy().to_string(),
                    }
                };
            }
            Err(e) => {
                let raw = e.raw_os_error();
                if raw == Some(libc::EINVAL) || raw == Some(libc::ENOENT) {
                    return Ok(current);
                }
                return Err(e);
            }
        }
    }
}

/// Open a non-blocking, close-on-exec inotify instance.
/// Mirrors `inotify_init1(IN_NONBLOCK | IN_CLOEXEC)` (`inotify.c:92`).
pub fn open_inotify() -> std::io::Result<i32> {
    let fd = unsafe { libc::inotify_init1(libc::IN_NONBLOCK | libc::IN_CLOEXEC) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// Add a watch for `mask` on `path`. Mirrors `inotify_add_watch`.
pub fn add_watch(fd: i32, path: &str, mask: u32) -> std::io::Result<i32> {
    let c_path = std::ffi::CString::new(path).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "path contains a NUL byte")
    })?;
    let wd = unsafe { libc::inotify_add_watch(fd, c_path.as_ptr(), mask) };
    if wd == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(wd)
}

/// Split a resolved path into `(containing directory, file name)`.
fn split_dir_file(path: &str) -> (String, String) {
    match path.rfind('/') {
        Some(0) => ("/".to_string(), path[1..].to_string()),
        Some(idx) => (path[..idx].to_string(), path[idx + 1..].to_string()),
        None => (".".to_string(), path.to_string()),
    }
}

/// Open the inotify fd and, for each configured resolv-file, watch its
/// containing directory. Mirrors `inotify_dnsmasq_init()` (`inotify.c:88-134`).
///
/// Unlike upstream (which calls `die()` fatally when a resolv directory is
/// missing or the initial `inotify_init1` fails), failures here are
/// returned to the caller, which logs and continues — consistent with how
/// `init_daemon_with` already handles `ipset_init` failures.
pub fn inotify_dnsmasq_init(daemon: &mut Daemon) -> std::io::Result<()> {
    let fd = open_inotify()?;
    daemon.inotify_fd = fd;

    if daemon.port == 0 || daemon.option_bool(OPT_NO_RESOLV) {
        return Ok(());
    }

    for res in daemon.resolv_files.iter_mut() {
        let resolved = resolve_symlink_chain(&res.name)?;
        let (dir, file) = split_dir_file(&resolved);

        match add_watch(fd, &dir, mask::IN_CLOSE_WRITE | mask::IN_MOVED_TO) {
            Ok(wd) => {
                res.wd = wd;
                res.file = Some(file);
            }
            Err(e) => {
                res.wd = -1;
                return Err(e);
            }
        }
    }

    Ok(())
}

/// Find the [`HostsFile`] tracking `file` within `dd`, creating it if this is
/// the first time it's been seen. Mirrors `dyndir_addhosts` (`inotify.c:136-174`).
///
/// `index` doubles here as "the cache UID last used to load this file" (`0`
/// / `UID_NONE` meaning "never loaded"), rather than upstream's
/// once-assigned `daemon->host_index` counter — this port's
/// `cache::load_hosts_file` always mints a fresh UID per load rather than
/// accepting a caller-supplied one, so the last-used UID has to be tracked
/// per file to remove the right entries on the next change.
fn dyndir_find_or_add(dd: &mut DynDir, file: &str) -> usize {
    if let Some(pos) = dd.files.iter().position(|h| {
        h.fname
            .strip_prefix(&dd.dname)
            .and_then(|rest| rest.strip_prefix('/'))
            == Some(file)
    }) {
        return pos;
    }
    dd.files.push(HostsFile {
        flags: dd.flags,
        fname: format!("{}/{file}", dd.dname),
        index: UID_NONE,
    });
    dd.files.len() - 1
}

/// Watch each `daemon.dynamic_dirs` entry and, for `AH_HOSTS` directories,
/// do the initial scan — loading any pre-existing files into `cache`.
///
/// Mirrors `set_dynamic_inotify()` (`inotify.c:178-263`): watch is
/// established *before* the directory is read, to avoid a race where a file
/// added between "read directory" and "add watch" would be missed.
///
/// `AH_DHCP_HST`/`AH_DHCP_OPT` directories are watched (so later events on
/// them are recognized rather than silently unmatched) but not scanned —
/// see the module doc for why.
pub fn set_dynamic_inotify(daemon: &mut Daemon, cache: &mut DnsCache) {
    let ttl = daemon.local_ttl;
    let fd = daemon.inotify_fd;
    let now = std::time::Instant::now();

    for dd in daemon.dynamic_dirs.iter_mut() {
        let meta = match std::fs::metadata(&dd.dname) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!("bad dynamic directory {}: {e}", dd.dname);
                continue;
            }
        };
        if !meta.is_dir() {
            tracing::error!("bad dynamic directory {}: not a directory", dd.dname);
            continue;
        }

        if dd.flags & AH_WD_DONE == 0 {
            match add_watch(
                fd,
                &dd.dname,
                mask::IN_CLOSE_WRITE | mask::IN_MOVED_TO | mask::IN_DELETE,
            ) {
                Ok(wd) => dd.wd = wd,
                Err(_) => dd.wd = -1,
            }
            dd.flags |= AH_WD_DONE;
        }

        if dd.wd == -1 {
            tracing::error!("failed to create inotify for {}", dd.dname);
            continue;
        }

        let entries = match std::fs::read_dir(&dd.dname) {
            Ok(e) => e,
            Err(e) => {
                tracing::error!("failed to create inotify for {}: {e}", dd.dname);
                continue;
            }
        };

        if dd.flags & AH_HOSTS == 0 {
            continue;
        }

        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if is_ignorable_filename(&name) {
                continue;
            }
            let idx = dyndir_find_or_add(dd, &name);
            let path = dd.files[idx].fname.clone();
            if std::fs::metadata(&path).map(|m| m.is_file()).unwrap_or(false) {
                if let Ok((uid, _count)) = crate::cache::load_hosts_file(&path, ttl, now, cache) {
                    dd.files[idx].index = uid;
                }
            }
        }
    }
}

/// Drain and dispatch pending inotify events.
///
/// Mirrors `inotify_check()` (`inotify.c:265-370`) minus the DHCP cascade
/// (`dhcp_update_configs`/`lease_update_*`), which has no equivalent in this
/// port (see the module doc). Returns `true` if a watched resolv-file
/// changed (upstream's `hit`), leaving the decision of whether to force a
/// resolv reload to the caller.
pub fn inotify_check(daemon: &mut Daemon, cache: &mut DnsCache) -> bool {
    let fd = daemon.inotify_fd;
    if fd < 0 {
        return false;
    }

    let mut hit = false;
    let mut buf = [0u8; 4096];

    loop {
        let rc = loop {
            let r = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
            if r == -1 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break r;
        };
        if rc <= 0 {
            break;
        }

        let data = &buf[..rc as usize];
        let mut offset = 0usize;

        while offset < data.len() {
            let Some(size) = inotify_event_size(&data[offset..]) else { break };
            if offset + size > data.len() {
                break;
            }
            let event = parse_inotify_event(&data[offset..offset + size]);
            offset += size;

            let Some((wd, ev_mask, name)) = event else { continue };
            if is_ignorable_filename(&name) {
                continue;
            }

            if daemon
                .resolv_files
                .iter()
                .any(|r| r.wd == wd && r.file.as_deref() == Some(name.as_str()))
            {
                hit = true;
            }

            for dd in daemon.dynamic_dirs.iter_mut() {
                if dd.wd != wd || dd.flags & AH_HOSTS == 0 {
                    continue;
                }

                let idx = dyndir_find_or_add(dd, &name);
                let removed = cache.remove_by_uid(dd.files[idx].index);
                let is_delete = ev_mask & mask::IN_DELETE != 0;

                if is_delete {
                    tracing::info!("inotify: {} removed", dd.files[idx].fname);
                } else {
                    tracing::info!("inotify: {} new or modified", dd.files[idx].fname);
                }
                if removed > 0 {
                    tracing::info!(
                        "inotify: flushed {removed} names read from {}",
                        dd.files[idx].fname
                    );
                }

                if is_delete {
                    dd.files[idx].index = UID_NONE;
                } else {
                    let path = dd.files[idx].fname.clone();
                    match crate::cache::load_hosts_file(&path, daemon.local_ttl, std::time::Instant::now(), cache) {
                        Ok((uid, _n)) => dd.files[idx].index = uid,
                        Err(_) => dd.files[idx].index = UID_NONE,
                    }
                }
            }
        }
    }

    hit
}

/// Whether a resolv-file inotify hit should force a resolv reload.
///
/// Mirrors the gate at `dnsmasq.c:1236`:
/// `daemon->port != 0 && !option_bool(OPT_NO_POLL)`. `--no-poll` disables
/// *all* automatic resolv-file re-reading outside of SIGHUP, including the
/// inotify-triggered kind — the "polling" it suppresses, in an
/// inotify-enabled build, is exactly this reactive reload.
fn should_force_resolv_reload(daemon: &Daemon, hit: bool) -> bool {
    hit && daemon.port != 0 && !daemon.option_bool(OPT_NO_POLL)
}

/// Await inotify readiness and dispatch events as they arrive, forcing a
/// resolv-file reload when a resolv watch fires (see
/// [`should_force_resolv_reload`]). `AH_HOSTS` dynamic-directory updates are
/// applied unconditionally inside `inotify_check` regardless of
/// `--no-poll`, matching upstream, since that flag only ever gated
/// resolv-file polling.
///
/// Returns immediately (without erroring) if no inotify fd was ever opened
/// (`inotify_dnsmasq_init` never ran or failed) — mirrors
/// [`crate::netlink::watch_address_changes`]'s "no live notifications rather
/// than a hard failure" degradation.
pub async fn watch_inotify_changes(
    daemon_handle: crate::dnsmasq::DaemonHandle,
    cache: crate::cache::SharedDnsCache,
) -> std::io::Result<()> {
    use std::os::fd::{FromRawFd, OwnedFd};

    let fd = daemon_handle.read().await.inotify_fd;
    if fd < 0 {
        return Ok(());
    }

    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let async_fd = tokio::io::unix::AsyncFd::new(owned)?;

    loop {
        let mut guard = async_fd.readable().await?;

        let hit = {
            let mut d = daemon_handle.write().await;
            let mut c = cache.lock().await;
            inotify_check(&mut d, &mut c)
        };
        guard.clear_ready();

        let should_reload = {
            let d = daemon_handle.read().await;
            should_force_resolv_reload(&d, hit)
        };
        if should_reload {
            crate::dnsmasq::clear_cache_and_reload(&daemon_handle, &cache).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::constants::F_IPV4;
    use crate::types::network::{Resolvc, AH_DHCP_HST};
    use std::time::Instant;

    fn make_raw_event(wd: i32, mask: u32, cookie: u32, name: &str) -> Vec<u8> {
        let mut buf = Vec::new();
        // name field: padded to multiple of 4 with NUL bytes (at least 1 NUL terminator)
        let name_bytes = name.as_bytes();
        let len = ((name_bytes.len() + 1 + 3) / 4) * 4; // round up to multiple of 4
        buf.extend_from_slice(&wd.to_ne_bytes());
        buf.extend_from_slice(&mask.to_ne_bytes());
        buf.extend_from_slice(&cookie.to_ne_bytes());
        buf.extend_from_slice(&(len as u32).to_ne_bytes());
        buf.extend_from_slice(name_bytes);
        buf.resize(buf.len() + (len - name_bytes.len()), 0u8);
        buf
    }

    #[test]
    fn parse_valid_event() {
        let raw = make_raw_event(3, mask::IN_CLOSE_WRITE, 0, "dnsmasq.conf");
        let (wd, m, name) = parse_inotify_event(&raw).unwrap();
        assert_eq!(wd, 3);
        assert_eq!(m, mask::IN_CLOSE_WRITE);
        assert_eq!(name, "dnsmasq.conf");
    }

    #[test]
    fn parse_truncated_header_returns_none() {
        assert!(parse_inotify_event(&[0u8; 10]).is_none());
    }

    #[test]
    fn parse_truncated_name_returns_none() {
        // Claim len=100 but only supply 16 bytes total
        let mut buf = vec![0u8; 16];
        buf[12..16].copy_from_slice(&100u32.to_ne_bytes());
        assert!(parse_inotify_event(&buf).is_none());
    }

    #[test]
    fn to_watch_event_modify() {
        assert_eq!(
            to_watch_event(mask::IN_MODIFY, "/etc/dnsmasq.conf"),
            Some(WatchEvent::Modified("/etc/dnsmasq.conf".to_string()))
        );
    }

    #[test]
    fn to_watch_event_close_write() {
        assert_eq!(
            to_watch_event(mask::IN_CLOSE_WRITE, "/etc/dnsmasq.conf"),
            Some(WatchEvent::Modified("/etc/dnsmasq.conf".to_string()))
        );
    }

    #[test]
    fn to_watch_event_moved_to() {
        assert_eq!(
            to_watch_event(mask::IN_MOVED_TO, "/etc/hosts"),
            Some(WatchEvent::Moved("/etc/hosts".to_string()))
        );
    }

    #[test]
    fn to_watch_event_delete() {
        assert_eq!(
            to_watch_event(mask::IN_DELETE, "/etc/hosts"),
            Some(WatchEvent::Deleted("/etc/hosts".to_string()))
        );
    }

    #[test]
    fn to_watch_event_untracked_returns_none() {
        // IN_ACCESS = 0x1 — not tracked
        assert_eq!(to_watch_event(0x0000_0001, "/etc/hosts"), None);
    }

    // ── resolve_symlink_chain ────────────────────────────────────────────

    #[test]
    fn resolve_symlink_chain_returns_path_unchanged_for_non_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.conf");
        std::fs::write(&path, "nameserver 1.1.1.1\n").unwrap();

        let resolved = resolve_symlink_chain(path.to_str().unwrap()).unwrap();
        assert_eq!(resolved, path.to_str().unwrap());
    }

    #[test]
    fn resolve_symlink_chain_returns_path_unchanged_for_missing_file() {
        let path = "/nonexistent-inotify-test-dir-xyz/resolv.conf";
        let resolved = resolve_symlink_chain(path).unwrap();
        assert_eq!(resolved, path);
    }

    #[test]
    fn resolve_symlink_chain_follows_relative_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real.conf");
        std::fs::write(&target, "nameserver 1.1.1.1\n").unwrap();
        let link = dir.path().join("link.conf");
        std::os::unix::fs::symlink("real.conf", &link).unwrap();

        let resolved = resolve_symlink_chain(link.to_str().unwrap()).unwrap();
        assert_eq!(resolved, target.to_str().unwrap());
    }

    #[test]
    fn resolve_symlink_chain_errors_on_symlink_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::os::unix::fs::symlink("b", &a).unwrap();
        std::os::unix::fs::symlink("a", &b).unwrap();

        assert!(resolve_symlink_chain(a.to_str().unwrap()).is_err());
    }

    // ── inotify_dnsmasq_init ─────────────────────────────────────────────

    fn make_resolvc(name: &str) -> Resolvc {
        Resolvc {
            is_default: false,
            logged: false,
            mtime: 0,
            ino: 0,
            name: name.to_string(),
            wd: -1,
            file: None,
        }
    }

    #[test]
    fn inotify_dnsmasq_init_sets_wd_and_file_on_resolvc() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 1.1.1.1\n").unwrap();

        let mut daemon = Daemon { port: 53, ..Daemon::default() };
        daemon.resolv_files.push(make_resolvc(path.to_str().unwrap()));

        inotify_dnsmasq_init(&mut daemon).unwrap();

        assert!(daemon.inotify_fd >= 0);
        assert!(daemon.resolv_files[0].wd >= 0);
        assert_eq!(daemon.resolv_files[0].file.as_deref(), Some("resolv.conf"));
    }

    #[test]
    fn inotify_dnsmasq_init_errors_when_resolv_dir_missing() {
        let mut daemon = Daemon { port: 53, ..Daemon::default() };
        daemon
            .resolv_files
            .push(make_resolvc("/nonexistent-inotify-test-dir-xyz/resolv.conf"));

        assert!(inotify_dnsmasq_init(&mut daemon).is_err());
        assert_eq!(daemon.resolv_files[0].wd, -1);
    }

    #[test]
    fn inotify_dnsmasq_init_skips_resolv_setup_when_port_zero() {
        let mut daemon = Daemon { port: 0, ..Daemon::default() };
        daemon
            .resolv_files
            .push(make_resolvc("/nonexistent-inotify-test-dir-xyz/resolv.conf"));

        inotify_dnsmasq_init(&mut daemon).unwrap();

        assert!(daemon.inotify_fd >= 0);
        assert_eq!(daemon.resolv_files[0].wd, -1);
    }

    #[test]
    fn inotify_dnsmasq_init_skips_resolv_setup_when_no_resolv_option_set() {
        let mut daemon = Daemon { port: 53, ..Daemon::default() };
        daemon.set_option(OPT_NO_RESOLV);
        daemon
            .resolv_files
            .push(make_resolvc("/nonexistent-inotify-test-dir-xyz/resolv.conf"));

        inotify_dnsmasq_init(&mut daemon).unwrap();

        assert!(daemon.inotify_fd >= 0);
        assert_eq!(daemon.resolv_files[0].wd, -1);
    }

    // ── set_dynamic_inotify ──────────────────────────────────────────────

    fn make_hosts_dyndir(dname: &str) -> DynDir {
        DynDir { files: vec![], flags: AH_HOSTS, dname: dname.to_string(), wd: -1 }
    }

    fn init_test_daemon_with_fd() -> Daemon {
        let mut daemon = Daemon { port: 0, ..Daemon::default() };
        inotify_dnsmasq_init(&mut daemon).unwrap();
        daemon
    }

    #[test]
    fn set_dynamic_inotify_loads_existing_hosts_file_into_cache() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hosts1"), "1.2.3.4 foo.example\n").unwrap();

        let mut daemon = init_test_daemon_with_fd();
        daemon.dynamic_dirs.push(make_hosts_dyndir(dir.path().to_str().unwrap()));
        let mut cache = DnsCache::new(1000);

        set_dynamic_inotify(&mut daemon, &mut cache);

        assert!(daemon.dynamic_dirs[0].wd >= 0);
        assert_ne!(daemon.dynamic_dirs[0].flags & AH_WD_DONE, 0);
        assert_eq!(daemon.dynamic_dirs[0].files.len(), 1);
        assert_ne!(daemon.dynamic_dirs[0].files[0].index, UID_NONE);

        let hits = cache.lookup_all_by_name("foo.example", F_IPV4, Instant::now());
        assert_eq!(hits.len(), 1);
    }

    #[test]
    fn set_dynamic_inotify_skips_dotfiles_and_backups() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hosts1"), "1.2.3.4 foo.example\n").unwrap();
        std::fs::write(dir.path().join(".hidden"), "5.6.7.8 hidden.example\n").unwrap();
        std::fs::write(dir.path().join("hosts1~"), "9.9.9.9 backup.example\n").unwrap();
        std::fs::write(dir.path().join("#hosts1#"), "9.9.9.9 lock.example\n").unwrap();

        let mut daemon = init_test_daemon_with_fd();
        daemon.dynamic_dirs.push(make_hosts_dyndir(dir.path().to_str().unwrap()));
        let mut cache = DnsCache::new(1000);

        set_dynamic_inotify(&mut daemon, &mut cache);

        assert_eq!(daemon.dynamic_dirs[0].files.len(), 1);
        assert!(daemon.dynamic_dirs[0].files[0].fname.ends_with("hosts1"));
    }

    #[test]
    fn set_dynamic_inotify_watches_but_does_not_scan_dhcp_dir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("host1.conf"), "dhcp-host=aa:bb:cc:dd:ee:ff,10.0.0.5\n").unwrap();

        let mut daemon = init_test_daemon_with_fd();
        daemon.dynamic_dirs.push(DynDir {
            files: vec![],
            flags: AH_DHCP_HST,
            dname: dir.path().to_str().unwrap().to_string(),
            wd: -1,
        });
        let mut cache = DnsCache::new(1000);

        set_dynamic_inotify(&mut daemon, &mut cache);

        assert!(daemon.dynamic_dirs[0].wd >= 0);
        assert!(daemon.dynamic_dirs[0].files.is_empty());
    }

    #[test]
    fn set_dynamic_inotify_logs_and_skips_missing_directory() {
        let mut daemon = init_test_daemon_with_fd();
        daemon.dynamic_dirs.push(make_hosts_dyndir("/nonexistent-inotify-test-dir-xyz"));
        let mut cache = DnsCache::new(1000);

        // Must not panic.
        set_dynamic_inotify(&mut daemon, &mut cache);

        assert_eq!(daemon.dynamic_dirs[0].wd, -1);
        assert!(daemon.dynamic_dirs[0].files.is_empty());
    }

    // ── inotify_check ────────────────────────────────────────────────────

    #[test]
    fn inotify_check_picks_up_new_file_in_watched_hosts_dir_without_sighup() {
        let dir = tempfile::tempdir().unwrap();
        let mut daemon = init_test_daemon_with_fd();
        daemon.dynamic_dirs.push(make_hosts_dyndir(dir.path().to_str().unwrap()));
        let mut cache = DnsCache::new(1000);
        set_dynamic_inotify(&mut daemon, &mut cache);

        std::fs::write(dir.path().join("hosts2"), "5.6.7.8 bar.example\n").unwrap();

        inotify_check(&mut daemon, &mut cache);

        let hits = cache.lookup_all_by_name("bar.example", F_IPV4, Instant::now());
        assert_eq!(hits.len(), 1);
        assert_eq!(daemon.dynamic_dirs[0].files.len(), 1);
    }

    #[test]
    fn inotify_check_reloads_cache_on_modified_hosts_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts1");
        std::fs::write(&path, "1.2.3.4 foo.example\n").unwrap();

        let mut daemon = init_test_daemon_with_fd();
        daemon.dynamic_dirs.push(make_hosts_dyndir(dir.path().to_str().unwrap()));
        let mut cache = DnsCache::new(1000);
        set_dynamic_inotify(&mut daemon, &mut cache);

        std::fs::write(&path, "9.9.9.9 foo.example\n").unwrap();
        inotify_check(&mut daemon, &mut cache);

        let hits = cache.lookup_all_by_name("foo.example", F_IPV4, Instant::now());
        assert_eq!(hits.len(), 1);
        match hits[0].addr {
            Some(crate::types::addr::AllAddr::Addr4(ip)) => {
                assert_eq!(ip, std::net::Ipv4Addr::new(9, 9, 9, 9));
            }
            _ => panic!("expected an IPv4 record"),
        }
    }

    #[test]
    fn inotify_check_removes_cache_entries_on_deleted_hosts_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hosts1");
        std::fs::write(&path, "1.2.3.4 foo.example\n").unwrap();

        let mut daemon = init_test_daemon_with_fd();
        daemon.dynamic_dirs.push(make_hosts_dyndir(dir.path().to_str().unwrap()));
        let mut cache = DnsCache::new(1000);
        set_dynamic_inotify(&mut daemon, &mut cache);

        std::fs::remove_file(&path).unwrap();
        inotify_check(&mut daemon, &mut cache);

        let hits = cache.lookup_all_by_name("foo.example", F_IPV4, Instant::now());
        assert!(hits.is_empty());
        assert_eq!(daemon.dynamic_dirs[0].files[0].index, UID_NONE);
    }

    #[test]
    fn inotify_check_reports_hit_for_watched_resolv_file_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resolv.conf");
        std::fs::write(&path, "nameserver 1.1.1.1\n").unwrap();

        let mut daemon = Daemon { port: 53, ..Daemon::default() };
        daemon.resolv_files.push(make_resolvc(path.to_str().unwrap()));
        inotify_dnsmasq_init(&mut daemon).unwrap();
        let mut cache = DnsCache::new(1000);

        std::fs::write(&path, "nameserver 8.8.8.8\n").unwrap();

        assert!(inotify_check(&mut daemon, &mut cache));
    }

    #[test]
    fn inotify_check_ignores_dotfile_events() {
        let dir = tempfile::tempdir().unwrap();
        let mut daemon = init_test_daemon_with_fd();
        daemon.dynamic_dirs.push(make_hosts_dyndir(dir.path().to_str().unwrap()));
        let mut cache = DnsCache::new(1000);
        set_dynamic_inotify(&mut daemon, &mut cache);

        std::fs::write(dir.path().join(".hidden"), "5.6.7.8 hidden.example\n").unwrap();
        inotify_check(&mut daemon, &mut cache);

        assert!(daemon.dynamic_dirs[0].files.is_empty());
        let hits = cache.lookup_all_by_name("hidden.example", F_IPV4, Instant::now());
        assert!(hits.is_empty());
    }

    // ── should_force_resolv_reload / --no-poll ──────────────────────────

    #[test]
    fn should_force_resolv_reload_true_by_default_on_hit() {
        let daemon = Daemon { port: 53, ..Daemon::default() };
        assert!(should_force_resolv_reload(&daemon, true));
    }

    #[test]
    fn should_force_resolv_reload_false_without_a_hit() {
        let daemon = Daemon { port: 53, ..Daemon::default() };
        assert!(!should_force_resolv_reload(&daemon, false));
    }

    #[test]
    fn should_force_resolv_reload_false_when_no_poll_set() {
        let mut daemon = Daemon { port: 53, ..Daemon::default() };
        daemon.set_option(OPT_NO_POLL);
        assert!(!should_force_resolv_reload(&daemon, true));
    }

    #[test]
    fn should_force_resolv_reload_false_when_port_zero() {
        let daemon = Daemon { port: 0, ..Daemon::default() };
        assert!(!should_force_resolv_reload(&daemon, true));
    }
}

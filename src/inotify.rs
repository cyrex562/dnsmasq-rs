#![cfg(feature = "inotify")]

//! inotify-based config file watching.
//! Mirrors the watch logic from dnsmasq's inotify.c.

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

#[cfg(test)]
mod tests {
    use super::*;

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
}

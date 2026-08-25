/// General utility functions.
/// Ported from `util.c`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::types::addr::MySockAddr;
use crate::types::dns_records::RrList;

#[allow(unused_imports)]
use libc;

// ── Random number generation ──────────────────────────────────────────────────
// We delegate to the `rand` crate rather than re-implementing SURF.

use rand::Rng;

pub fn rand16() -> u16 {
    rand::thread_rng().gen()
}

pub fn rand32() -> u32 {
    rand::thread_rng().gen()
}

pub fn rand64() -> u64 {
    rand::thread_rng().gen()
}

// ── RR list helpers ───────────────────────────────────────────────────────────

/// Return true if `rr` appears in `list`.
pub fn rr_on_list(list: &[RrList], rr: u16) -> bool {
    list.iter().any(|e| e.rr != 0 && e.rr == rr)
}

// ── Time helpers ──────────────────────────────────────────────────────────────

/// Return current time as a Unix timestamp (seconds).
pub fn dnsmasq_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

/// Return current time in milliseconds (wraps at u32::MAX).
pub fn dnsmasq_milliseconds() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_millis() as u32
}

/// Format a duration in seconds as human-readable (e.g. "1d2h3m4s").
pub fn prettyprint_time(t: u32) -> String {
    if t == 0xffff_ffff {
        return "infinite".to_string();
    }
    let mut s = String::new();
    let days  = t / 86400;
    let hours = (t / 3600) % 24;
    let mins  = (t / 60) % 60;
    let secs  = t % 60;
    if days  > 0 { s.push_str(&format!("{days}d")); }
    if hours > 0 { s.push_str(&format!("{hours}h")); }
    if mins  > 0 { s.push_str(&format!("{mins}m")); }
    if secs  > 0 || s.is_empty() { s.push_str(&format!("{secs}s")); }
    s
}

// ── Wildcard matching ─────────────────────────────────────────────────────────

/// Returns true if `wildcard` matches `target`, where `*` matches any prefix.
pub fn wildcard_match(wildcard: &str, target: &str) -> bool {
    let mut wi = wildcard.chars();
    let mut ti = target.chars();
    loop {
        match (wi.next(), ti.next()) {
            (Some('*'), _) => return true,
            (Some(w), Some(t)) if w == t => {}
            (None, None)   => return true,
            _              => return false,
        }
    }
}

/// Like `wildcard_match` but compares at most `n` characters.
pub fn wildcard_matchn(wildcard: &str, target: &str, n: usize) -> bool {
    let wi = wildcard.chars().take(n);
    let ti = target.chars().take(n);
    for (w, t) in wi.zip(ti) {
        if w == '*' { return true; }
        if w != t   { return false; }
    }
    true
}

// ── Hex parsing ───────────────────────────────────────────────────────────────

/// A hex digit in the input to [`parse_hex`] wasn't `0-9`/`a-f`/`A-F`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HexParseError;

impl std::fmt::Display for HexParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "invalid hex digit")
    }
}

impl std::error::Error for HexParseError {}

/// Parse a colon/hyphen/space-separated hex string into bytes.
///
/// `*` tokens produce a zero byte and set the corresponding bit (in token
/// order) of the returned wildcard mask. Stops after `maxlen` bytes if
/// given.
pub fn parse_hex(input: &str, maxlen: Option<usize>) -> Result<(Vec<u8>, u32), HexParseError> {
    let mut out = Vec::new();
    let mut mask: u32 = 0;

    'tokens: for token in input.split(|c| c == ':' || c == '-' || c == ' ') {
        if let Some(max) = maxlen {
            if out.len() >= max { break; }
        }
        if token == "*" {
            mask = (mask << 1) | 1;
            out.push(0);
        } else if !token.is_empty() {
            // parse one or two hex chars per byte
            let bytes_in_token = (token.len() + 1) / 2;
            for j in 0..bytes_in_token {
                let start = j * 2;
                let end   = (start + 2).min(token.len());
                let b = u8::from_str_radix(&token[start..end], 16).map_err(|_| HexParseError)?;
                mask <<= 1;
                out.push(b);
                if let Some(max) = maxlen {
                    if out.len() >= max { break 'tokens; }
                }
            }
        }
    }

    Ok((out, mask))
}

/// Format a MAC address as colon-separated hex (e.g. "aa:bb:cc:dd:ee:ff").
pub fn print_mac(mac: &[u8]) -> String {
    if mac.is_empty() {
        return "<null>".to_string();
    }
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

// ── Socket address helpers ─────────────────────────────────────────────────────

/// True if two socket addresses are equal (address + port + scope).
pub fn sockaddr_isequal(s1: &MySockAddr, s2: &MySockAddr) -> bool {
    s1 == s2
}

/// True if the socket address represents the unspecified (all-zero) address.
pub fn sockaddr_isnull(s: &MySockAddr) -> bool {
    match s {
        MySockAddr::V4(a)  => *a.ip() == Ipv4Addr::UNSPECIFIED,
        MySockAddr::V6(a)  => *a.ip() == Ipv6Addr::UNSPECIFIED,
    }
}

// ── Pretty-print address ──────────────────────────────────────────────────────

/// Format a socket address as a human-readable string.
///
/// Returns `(address_string, port)`.  For IPv6 link-local addresses that
/// have a non-zero scope-id the scope interface name is appended (e.g.
/// `"fe80::1%eth0"`).
pub fn prettyprint_addr(addr: &MySockAddr) -> (String, u16) {
    match addr {
        MySockAddr::V4(a) => (a.ip().to_string(), a.port()),
        MySockAddr::V6(a) => {
            let mut s = a.ip().to_string();
            // Append scope-id as interface name when present
            if a.scope_id() != 0 {
                // Try to resolve scope id to interface name via /sys on Linux;
                // fall back to numeric scope id on other platforms.
                let iface = interface_name_from_index(a.scope_id())
                    .unwrap_or_else(|| a.scope_id().to_string());
                if s.len() + 1 + iface.len() <= 46 {
                    s.push('%');
                    s.push_str(&iface);
                }
            }
            (s, a.port())
        }
    }
}

#[cfg(target_os = "linux")]
fn interface_name_from_index(idx: u32) -> Option<String> {
    use std::ffi::CStr;
    let mut buf = [0i8; libc::IF_NAMESIZE];
    unsafe {
        if libc::if_indextoname(idx, buf.as_mut_ptr()).is_null() {
            return None;
        }
        let cstr = CStr::from_ptr(buf.as_ptr());
        cstr.to_str().ok().map(|s| s.to_owned())
    }
}

#[cfg(not(target_os = "linux"))]
fn interface_name_from_index(_idx: u32) -> Option<String> {
    None
}

// ── Byte-array comparison with mask ──────────────────────────────────────────

/// Compare byte arrays `a` and `b`, ignoring positions where the corresponding
/// bit in `mask` is **set**.
///
/// Returns 0 if any unmasked byte differs; otherwise returns a positive count
/// (1 + number of matched unmasked bytes), mirroring the C `memcmp_masked`.
pub fn memcmp_masked(a: &[u8], b: &[u8], mask: u32) -> usize {
    let len = a.len().min(b.len());
    let mut count: usize = 1;
    let mut m = mask;
    for i in (0..len).rev() {
        if m & 1 == 0 {
            if a[i] == b[i] {
                count += 1;
            } else {
                return 0;
            }
        }
        m >>= 1;
    }
    count
}

// ── Workspace buffer helpers ──────────────────────────────────────────────────

/// Ensure `workspace` has at least `needed + 1` slots, growing by 5 if needed.
///
/// New slots are initialised to empty `Vec<u8>`.  Returns `false` only if
/// `needed + 1` overflows — in practice this cannot happen.
pub fn expand_workspace(workspace: &mut Vec<Vec<u8>>, needed: usize) -> bool {
    if workspace.len() >= needed + 1 {
        return true;
    }
    let new_len = needed + 1 + 5;
    workspace.resize_with(new_len, Vec::new);
    true
}



#[cfg(target_os = "linux")]
pub fn kernel_version() -> u32 {
    use std::ffi::CStr;

    unsafe {
        let mut utsname: libc::utsname = std::mem::zeroed();
        if libc::uname(&mut utsname) < 0 {
            // uname failed (should never happen on Linux), return 0.0.0
            return 0;
        }

        let release_cstr = CStr::from_ptr(utsname.release.as_ptr());
        let release = release_cstr.to_string_lossy();

        let mut version = 0u32;
        let mut part_count = 0;

        for part in release.split('.') {
            if part_count >= 3 {
                break;
            }

            let num_str = part.chars()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>();

            let num = num_str.parse::<u32>().unwrap_or(0);
            version = (version << 8) | (num & 0xFF);
            part_count += 1;
        }

        // Shift left to account for any missing parts
        while part_count < 3 {
            version = version << 8;
            part_count += 1;
        }

        version
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn prettyprint_time_cases() {
        assert_eq!(prettyprint_time(0xffffffff), "infinite");
        assert_eq!(prettyprint_time(3661), "1h1m1s");
        assert_eq!(prettyprint_time(86400), "1d");
        assert_eq!(prettyprint_time(0), "0s");
    }

    #[test]
    fn wildcard_match_basic() {
        assert!(wildcard_match("foo*", "foobar"));
        assert!(wildcard_match("foo", "foo"));
        assert!(!wildcard_match("foo", "bar"));
        assert!(!wildcard_match("foo", "foob"));
    }

    #[test]
    fn print_mac_basic() {
        assert_eq!(print_mac(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]), "aa:bb:cc:dd:ee:ff");
        assert_eq!(print_mac(&[]), "<null>");
    }

    #[test]
    fn parse_hex_basic() {
        let (out, _mask) = parse_hex("aa:bb:cc", None).unwrap();
        assert_eq!(out, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn parse_hex_wildcard_mask() {
        let (out, mask) = parse_hex("aa:*:cc", None).unwrap();
        assert_eq!(out, vec![0xaa, 0x00, 0xcc]);
        // The '*' token is the middle of 3, so it sets bit 1 (mask built via
        // `(mask << 1) | 1` in wildcard position order).
        assert_eq!(mask, 0b010);
    }

    #[test]
    fn parse_hex_maxlen_truncates() {
        let (out, _mask) = parse_hex("aa:bb:cc:dd", Some(2)).unwrap();
        assert_eq!(out, vec![0xaa, 0xbb]);
    }

    #[test]
    fn parse_hex_invalid_digit_errors() {
        assert!(parse_hex("zz", None).is_err());
    }

    #[test]
    fn sockaddr_isnull_v4() {
        use std::net::SocketAddrV4;
        let s = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0));
        assert!(sockaddr_isnull(&s));
        let s2 = MySockAddr::V4(SocketAddrV4::new("1.2.3.4".parse().unwrap(), 53));
        assert!(!sockaddr_isnull(&s2));
    }

    #[test]
    fn memcmp_masked_all_bits_set() {
        // mask=0xFF → all bits set → all bytes are "masked out" → match
        let a = [1u8, 2, 3];
        let b = [4u8, 5, 6];
        assert_ne!(memcmp_masked(&a, &b, 0xFF), 0);
    }

    #[test]
    fn memcmp_masked_no_bits_set() {
        // mask=0 → no bits set → all bytes compared
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3];
        let c = [1u8, 2, 4];
        assert_ne!(memcmp_masked(&a, &b, 0), 0); // equal
        assert_eq!(memcmp_masked(&a, &c, 0), 0); // differ at index 2
    }

    #[test]
    fn prettyprint_addr_v4() {
        use std::net::SocketAddrV4;
        let addr = MySockAddr::V4(SocketAddrV4::new("192.168.1.1".parse().unwrap(), 53));
        let (s, port) = prettyprint_addr(&addr);
        assert_eq!(s, "192.168.1.1");
        assert_eq!(port, 53);
    }

    #[test]
    fn prettyprint_addr_v6() {
        use std::net::SocketAddrV6;
        let addr = MySockAddr::V6(SocketAddrV6::new("::1".parse().unwrap(), 53, 0, 0));
        let (s, port) = prettyprint_addr(&addr);
        assert_eq!(s, "::1");
        assert_eq!(port, 53);
    }

    #[test]
    fn expand_workspace_grows() {
        let mut ws: Vec<Vec<u8>> = Vec::new();
        assert!(expand_workspace(&mut ws, 3));
        // Should have at least 4 slots (needed+1), rounded up by 5 = 9
        assert!(ws.len() >= 4);
    }

    #[test]
    fn expand_workspace_no_shrink() {
        let mut ws: Vec<Vec<u8>> = vec![vec![1], vec![2], vec![3], vec![4], vec![5]];
        // already has 5 slots; requesting index 3 (needed=3, so len>=4) → no change
        assert!(expand_workspace(&mut ws, 3));
        assert_eq!(ws.len(), 5);
    }

    // ── kernel_version ───────────────────────────────────────────────────────

    #[test]
    #[cfg(target_os = "linux")]
    fn kernel_version_returns_valid_version() {
        let version = kernel_version();
        // Should return a non-zero packed version int (major.minor.patch)
        // At minimum, should be > 0 on any real Linux system
        assert!(version > 0, "kernel_version should return non-zero on Linux");
        // Sanity check: major version should be at most 2 bytes (< 256 << 16)
        assert!(version < (256u32 << 16), "major version seems unreasonably high");
    }
}

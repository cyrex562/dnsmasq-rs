/// General utility functions.
/// Ported from `util.c`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::dns_protocol::{MAXLABEL, NAME_ESCAPE};
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

// ── Hostname / domain name helpers ───────────────────────────────────────────

/// Case-insensitive hostname comparison that does not depend on locale.
pub fn hostname_order(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.chars().map(|c| c.to_ascii_lowercase());
    let mut bi = b.chars().map(|c| c.to_ascii_lowercase());
    loop {
        match (ai.next(), bi.next()) {
            (Some(ca), Some(cb)) => {
                let ord = ca.cmp(&cb);
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            (None, None) => return std::cmp::Ordering::Equal,
            (None, _)    => return std::cmp::Ordering::Less,
            (_, None)    => return std::cmp::Ordering::Greater,
        }
    }
}

/// Case-insensitive hostname equality (locale-independent).
pub fn hostname_isequal(a: &str, b: &str) -> bool {
    a.len() == b.len() && hostname_order(a, b) == std::cmp::Ordering::Equal
}

/// Returns `Some(2)` if `b == a`, `Some(1)` if `b` is a subdomain of `a`, `None` otherwise.
pub fn hostname_issubdomain(a: &str, b: &str) -> Option<u8> {
    let a = a.to_ascii_lowercase();
    let b = b.to_ascii_lowercase();

    if b.len() < a.len() {
        return None;
    }

    // Compare from the right
    let mut ai = a.chars().rev();
    let mut bi = b.chars().rev();

    loop {
        match (ai.next(), bi.next()) {
            (None, None)          => return Some(2), // equal
            (None, Some('.'))     => return Some(1), // b is subdomain
            (None, _)             => return None,    // b is a.foo (no dot separator)
            (Some(ca), Some(cb)) if ca == cb => {}
            _                    => return None,
        }
    }
}

/// Returns true if `name` is a legal DNS hostname (first label only checked strictly).
pub fn legal_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }

    let label = name.split('.').next().unwrap_or("");
    if label.is_empty() || label.len() > MAXLABEL {
        return false;
    }

    for (i, c) in label.chars().enumerate() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' => {}
            '-' | '_' if i > 0 => {}
            _ => return false,
        }
    }
    true
}

/// Canonicalise a domain name: strip trailing dot, lowercase.
/// Returns `None` if the name is illegal.
pub fn canonicalise(input: &str) -> Option<String> {
    let s = input.trim_end_matches('.');
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > MAXLABEL {
            return None;
        }
    }
    Some(s.to_ascii_lowercase())
}

// ── Address helpers ───────────────────────────────────────────────────────────

/// Returns the prefix length of an IPv4 netmask (e.g. 255.255.255.0 → 24).
pub fn netmask_length(mask: Ipv4Addr) -> u32 {
    let m = u32::from(mask);
    m.count_ones()
}

/// True if `a` and `b` are in the same IPv4 subnet defined by `mask`.
pub fn is_same_net(a: Ipv4Addr, b: Ipv4Addr, mask: Ipv4Addr) -> bool {
    let ma = u32::from(mask);
    (u32::from(a) & ma) == (u32::from(b) & ma)
}

/// Same as `is_same_net` but takes a prefix length instead of a mask.
pub fn is_same_net_prefix(a: Ipv4Addr, b: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 { return true; }
    if prefix >= 32 { return u32::from(a) == u32::from(b); }
    let mask = !((1u32 << (32 - prefix)) - 1);
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

/// True if `a` and `b` share the same IPv6 prefix.
pub fn is_same_net6(a: &Ipv6Addr, b: &Ipv6Addr, prefixlen: usize) -> bool {
    let ab = a.octets();
    let bb = b.octets();
    let pfbytes = prefixlen / 8;
    let pfbits  = prefixlen % 8;

    if ab[..pfbytes] != bb[..pfbytes] {
        return false;
    }
    if pfbits == 0 || pfbytes >= 16 {
        return true;
    }
    ab[pfbytes] >> (8 - pfbits) == bb[pfbytes] >> (8 - pfbits)
}

/// Extract the least-significant 64 bits of an IPv6 address.
pub fn addr6part(addr: &Ipv6Addr) -> u64 {
    let o = addr.octets();
    u64::from_be_bytes(o[8..16].try_into().unwrap())
}

/// Set the least-significant 64 bits of an IPv6 address.
pub fn setaddr6part(addr: &Ipv6Addr, host: u64) -> Ipv6Addr {
    let mut o = addr.octets();
    let hb = host.to_be_bytes();
    o[8..16].copy_from_slice(&hb);
    Ipv6Addr::from(o)
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

/// Parse a colon/hyphen/space-separated hex string into bytes.
/// `*` bytes set the corresponding bit in `wildcard_mask`.
/// Returns the number of bytes written, or -1 on error.
pub fn parse_hex(
    input: &str,
    out: &mut Vec<u8>,
    maxlen: Option<usize>,
    wildcard_mask: Option<&mut u32>,
) -> i32 {
    let mut mask: u32 = 0;
    let mut count = 0i32;

    for token in input.split(|c| c == ':' || c == '-' || c == ' ') {
        if let Some(max) = maxlen {
            if count as usize >= max { break; }
        }
        if token == "*" {
            mask = (mask << 1) | 1;
            out.push(0);
            count += 1;
        } else if !token.is_empty() {
            // parse one or two hex chars per byte
            let bytes_in_token = (token.len() + 1) / 2;
            for j in 0..bytes_in_token {
                let start = j * 2;
                let end   = (start + 2).min(token.len());
                match u8::from_str_radix(&token[start..end], 16) {
                    Ok(b) => {
                        mask <<= 1;
                        out.push(b);
                        count += 1;
                        if let Some(max) = maxlen {
                            if count as usize >= max { break; }
                        }
                    }
                    Err(_) => return -1,
                }
            }
        }
    }

    if let Some(wm) = wildcard_mask {
        *wm = mask;
    }
    count
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

// ── DNS wire-format helpers ───────────────────────────────────────────────────

/// Write a DNS name in wire format (RFC 1035 label encoding) into `buf`.
///
/// The name is written as a sequence of `<length><label>` pairs.
/// Characters that are `NAME_ESCAPE` are stored as escape sequences
/// (`NAME_ESCAPE` byte followed by original_byte+1), matching the C encoding.
/// Does **not** write the terminal zero-byte; the caller must append it.
///
/// Returns `false` if writing would exceed `limit` bytes in `buf`.
pub fn do_rfc1035_name(buf: &mut Vec<u8>, name: &str, limit: Option<usize>) -> bool {
    for label in name.split('.') {
        if label.is_empty() {
            // trailing dot or consecutive dots — skip
            continue;
        }
        // Reserve one byte for the length field
        let len_pos = buf.len();
        buf.push(0u8);
        if let Some(lim) = limit {
            if buf.len() > lim {
                return false;
            }
        }
        let mut label_len: u8 = 0;
        for b in label.bytes() {
            if b == NAME_ESCAPE {
                // Escape: write NAME_ESCAPE then (b + 1)
                buf.push(NAME_ESCAPE);
                buf.push(b.wrapping_add(1));
                label_len = label_len.saturating_add(2);
            } else {
                buf.push(b);
                label_len += 1;
            }
            if let Some(lim) = limit {
                if buf.len() > lim {
                    return false;
                }
            }
        }
        buf[len_pos] = label_len;
    }
    true
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

// ── File-descriptor management ───────────────────────────────────────────────

/// Close all open file descriptors except stdin/stdout/stderr and the three
/// `spare` descriptors.  Used during daemon startup to clean up inherited fds.
///
/// On Linux the `/proc/self/fd` directory is scanned for efficiency; on other
/// platforms we fall back to iterating `0..max_fd`.
pub fn close_fds(max_fd: i64, spare1: i32, spare2: i32, spare3: i32) {
    let spares = [
        libc::STDIN_FILENO,
        libc::STDOUT_FILENO,
        libc::STDERR_FILENO,
        spare1,
        spare2,
        spare3,
    ];

    #[cfg(target_os = "linux")]
    {
        unsafe {
            let d = libc::opendir(b"/proc/self/fd\0".as_ptr() as *const i8);
            if !d.is_null() {
                let dirfd = libc::dirfd(d);
                if dirfd >= 0 {
                    loop {
                        let entry_ptr = libc::readdir(d);
                        if entry_ptr.is_null() {
                            break;
                        }
                        let entry = &*entry_ptr;
                        // Try to parse the directory entry name as an fd number
                        let name_cstr = std::ffi::CStr::from_ptr(entry.d_name.as_ptr());
                        if let Ok(name) = name_cstr.to_str() {
                            if let Ok(fd) = name.parse::<i32>() {
                                // Skip the directory fd itself (matching util.c:848 "fd == dirfd(d)")
                                // and all the standard spare fds
                                let is_spare = spares.contains(&fd);
                                if fd != dirfd && !is_spare {
                                    libc::close(fd);
                                }
                            }
                        }
                    }
                }
                libc::closedir(d);
                return;
            }
        }
    }

    // Fallback: dumb iteration
    for fd in (0..max_fd as i32).rev() {
        if !spares.contains(&fd) {
            unsafe { libc::close(fd) };
        }
    }
}

// ── Retry-aware I/O helpers ───────────────────────────────────────────────────

/// Inspect the return value of `sendto`/`sendmsg` and decide whether to retry.
///
/// Mirrors the C `retry_send()`:
/// - Returns `false` (no retry needed) when `rc != -1` (success).
/// - On `EAGAIN`/`EWOULDBLOCK` sleeps 10 µs and retries up to 1000 times.
/// - On `EINTR` returns `true` immediately (caller should retry).
/// - On any other error returns `false`.
///
/// A thread-local counter tracks the retry budget, reset on each success.
pub fn retry_send(rc: isize) -> bool {
    use std::cell::Cell;
    thread_local! {
        static RETRIES: Cell<u32> = Cell::new(0);
    }

    if rc != -1 {
        RETRIES.with(|r| r.set(0));
        return false;
    }

    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => {
            std::thread::sleep(std::time::Duration::from_nanos(10_000));
            let retries = RETRIES.with(|r| {
                let v = r.get();
                r.set(v + 1);
                v
            });
            if retries < 1000 {
                return true;
            }
        }
        Some(e) if e == libc::EINTR => return true,
        _ => {}
    }

    RETRIES.with(|r| r.set(0));
    false
}

/// Blocking read or write of exactly `buf.len()` bytes on a raw file descriptor.
///
/// `rw = false` → write; `rw = true` → read.
/// Retries on `EINTR`/`ENOMEM`/`ENOBUFS`; returns `false` on any other error
/// or on EOF during a read.
pub fn read_write(fd: i32, buf: &mut [u8], rw: bool) -> bool {
    if buf.is_empty() {
        return true;
    }
    let mut done = 0usize;
    while done < buf.len() {
        let slice = &mut buf[done..];
        let n = if rw {
            unsafe {
                libc::read(fd, slice.as_mut_ptr() as *mut libc::c_void, slice.len())
            }
        } else {
            unsafe {
                libc::write(fd, slice.as_ptr() as *const libc::c_void, slice.len())
            }
        };
        if n < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::EINTR || e == libc::ENOMEM || e == libc::ENOBUFS {
                continue;
            }
            return false;
        }
        if n == 0 && rw {
            return false; // EOF
        }
        done += n as usize;
    }
    true
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

// ── Domain name validation (ported from util.c:137-202) ──────────────────────

/// Maximum DNS name length.
const MAXDNAME: usize = 1025;

/// Result of checking a domain name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameCheckResult {
    /// Invalid name (empty, too long, control chars, etc.).
    Invalid,
    /// Valid ASCII-only name.
    Valid,
    /// Valid name with non-ASCII characters requiring IDN encoding.
    NeedsIdn,
}

/// Validate a domain name string.
///
/// Checks: non-empty, total length ≤ MAXDNAME, labels ≤ 63 chars,
/// no control characters, not all whitespace. Non-ASCII chars return
/// `NeedsIdn`. Trailing dot is stripped.
/// Port of `check_name()` from util.c:137-202.
pub fn check_name(name: &str) -> NameCheckResult {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > MAXDNAME {
        return NameCheckResult::Invalid;
    }

    let mut has_idn = false;
    let mut has_non_space = name.ends_with('.');  // trailing dot counts as non-space input

    for label in trimmed.split('.') {
        if label.len() > MAXLABEL {
            return NameCheckResult::Invalid;
        }
        for c in label.chars() {
            if c.is_ascii_control() {
                return NameCheckResult::Invalid;
            }
            if !c.is_ascii() {
                has_idn = true;
            }
            if c != ' ' {
                has_non_space = true;
            }
        }
    }

    // Reject all-whitespace names
    if !has_non_space {
        return NameCheckResult::Invalid;
    }

    // Uppercase ASCII also suggests IDN processing might be needed
    if trimmed.chars().any(|c| c.is_ascii_uppercase()) {
        has_idn = true;
    }

    if has_idn {
        NameCheckResult::NeedsIdn
    } else {
        NameCheckResult::Valid
    }
}

/// Validate a hostname (more restricted than a domain name).
///
/// Only the first label is checked: allowed chars are a-z, A-Z, 0-9, '-', '_'.
/// Port of `legal_hostname()` from util.c:204+ (already partially ported).
pub fn check_hostname_label(name: &str) -> bool {
    let first_label = name.split('.').next().unwrap_or("");
    if first_label.is_empty() {
        return false;
    }
    first_label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn hostname_isequal_case_insensitive() {
        assert!(hostname_isequal("Example.COM", "example.com"));
        assert!(!hostname_isequal("example.com", "example.net"));
    }

    #[test]
    fn hostname_issubdomain_cases() {
        assert_eq!(hostname_issubdomain("example.com", "example.com"), Some(2));
        assert_eq!(hostname_issubdomain("example.com", "sub.example.com"), Some(1));
        assert_eq!(hostname_issubdomain("example.com", "other.com"), None);
        assert_eq!(hostname_issubdomain("example.com", "notexample.com"), None);
    }

    #[test]
    fn legal_hostname_valid() {
        assert!(legal_hostname("example"));
        assert!(legal_hostname("foo-bar"));
        assert!(legal_hostname("foo.bar.baz"));
    }

    #[test]
    fn legal_hostname_invalid() {
        assert!(!legal_hostname(""));
        assert!(!legal_hostname("-foo"));
        assert!(!legal_hostname("foo bar"));
    }

    #[test]
    fn canonicalise_strips_trailing_dot() {
        assert_eq!(canonicalise("example.com."), Some("example.com".to_string()));
        assert_eq!(canonicalise("EXAMPLE.COM"), Some("example.com".to_string()));
    }

    #[test]
    fn netmask_length_standard() {
        assert_eq!(netmask_length("255.255.255.0".parse().unwrap()), 24);
        assert_eq!(netmask_length("255.255.0.0".parse().unwrap()), 16);
        assert_eq!(netmask_length("255.255.255.255".parse().unwrap()), 32);
    }

    #[test]
    fn is_same_net_basic() {
        let a: Ipv4Addr = "192.168.1.100".parse().unwrap();
        let b: Ipv4Addr = "192.168.1.200".parse().unwrap();
        let c: Ipv4Addr = "192.168.2.1".parse().unwrap();
        let mask: Ipv4Addr = "255.255.255.0".parse().unwrap();
        assert!(is_same_net(a, b, mask));
        assert!(!is_same_net(a, c, mask));
    }

    #[test]
    fn is_same_net6_basic() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let c: Ipv6Addr = "2001:db9::1".parse().unwrap();
        assert!(is_same_net6(&a, &b, 32));
        assert!(!is_same_net6(&a, &c, 32));
    }

    #[test]
    fn addr6part_roundtrip() {
        let addr: Ipv6Addr = "2001:db8::cafe:babe".parse().unwrap();
        let part = addr6part(&addr);
        let reconstructed = setaddr6part(&"2001:db8::".parse().unwrap(), part);
        assert_eq!(reconstructed, addr);
    }

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
        let mut out = Vec::new();
        let n = parse_hex("aa:bb:cc", &mut out, None, None);
        assert_eq!(n, 3);
        assert_eq!(out, vec![0xaa, 0xbb, 0xcc]);
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
    fn do_rfc1035_name_basic() {
        let mut buf = Vec::new();
        assert!(do_rfc1035_name(&mut buf, "example.com", None));
        // "example" → [7, 'e','x','a','m','p','l','e'], "com" → [3, 'c','o','m']
        assert_eq!(&buf[..8], b"\x07example");
        assert_eq!(&buf[8..], b"\x03com");
    }

    #[test]
    fn do_rfc1035_name_single_label() {
        let mut buf = Vec::new();
        assert!(do_rfc1035_name(&mut buf, "localhost", None));
        assert_eq!(buf, b"\x09localhost");
    }

    #[test]
    fn do_rfc1035_name_trailing_dot() {
        // A trailing dot (FQDN) should produce the same output as without one
        let mut no_dot = Vec::new();
        let mut with_dot = Vec::new();
        do_rfc1035_name(&mut no_dot, "example.com", None);
        do_rfc1035_name(&mut with_dot, "example.com.", None);
        assert_eq!(no_dot, with_dot);
    }

    #[test]
    fn do_rfc1035_name_limit() {
        let mut buf = Vec::new();
        // limit of 5 bytes — cannot fit "example" label (8 bytes incl. length)
        let ok = do_rfc1035_name(&mut buf, "example.com", Some(5));
        assert!(!ok);
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

    // ── check_name ───────────────────────────────────────────────────────────

    #[test]
    fn check_name_valid_simple() {
        assert_eq!(check_name("example.com"), NameCheckResult::Valid);
    }

    #[test]
    fn check_name_valid_trailing_dot() {
        // Trailing dot should be stripped; result is valid
        assert_ne!(check_name("example.com."), NameCheckResult::Invalid);
    }

    #[test]
    fn check_name_empty() {
        assert_eq!(check_name(""), NameCheckResult::Invalid);
    }

    #[test]
    fn check_name_control_char() {
        assert_eq!(check_name("bad\x01name.com"), NameCheckResult::Invalid);
    }

    #[test]
    fn check_name_label_too_long() {
        let long_label = "a".repeat(64);
        assert_eq!(check_name(&format!("{}.com", long_label)), NameCheckResult::Invalid);
    }

    #[test]
    fn check_name_label_max_ok() {
        let label = "a".repeat(63);
        assert_ne!(check_name(&format!("{}.com", label)), NameCheckResult::Invalid);
    }

    #[test]
    fn check_name_uppercase_needs_idn() {
        assert_eq!(check_name("Example.COM"), NameCheckResult::NeedsIdn);
    }

    #[test]
    fn check_name_non_ascii_needs_idn() {
        assert_eq!(check_name("münchen.de"), NameCheckResult::NeedsIdn);
    }

    #[test]
    fn check_name_all_spaces_invalid() {
        assert_eq!(check_name("   "), NameCheckResult::Invalid);
    }

    #[test]
    fn check_name_single_label() {
        assert_eq!(check_name("localhost"), NameCheckResult::Valid);
    }

    // ── check_hostname_label ─────────────────────────────────────────────────

    #[test]
    fn check_hostname_label_valid() {
        assert!(check_hostname_label("my-host_1"));
    }

    #[test]
    fn check_hostname_label_fqdn() {
        // Only checks first label
        assert!(check_hostname_label("host.example.com"));
    }

    #[test]
    fn check_hostname_label_invalid_chars() {
        assert!(!check_hostname_label("host name")); // space
        assert!(!check_hostname_label("host@name")); // @
    }

    #[test]
    fn check_hostname_label_empty() {
        assert!(!check_hostname_label(""));
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

    // ── close_fds ────────────────────────────────────────────────────────────

    #[test]
    #[ignore] // Modifies global fd state; run with --ignored
    #[cfg(target_os = "linux")]
    fn close_fds_skips_directory_fd() {
        use std::os::unix::io::AsRawFd;

        // Create a pipe to have fds we want to spare
        let (read_fd, write_fd) = nix::unistd::pipe().expect("pipe failed");
        let spare_write_fd = write_fd.as_raw_fd();
        let spare_read_fd = read_fd.as_raw_fd();
        let max_fd = spare_write_fd as i64 + 10;

        // Verify spare_write_fd works before close_fds
        let test_write = unsafe { libc::write(spare_write_fd, b"test" as *const u8 as *const libc::c_void, 4) };
        assert_eq!(test_write, 4, "spare_write_fd should be writable initially");

        // Create some other fds that should get closed
        let fd1 = unsafe { libc::open(b"/dev/null\0".as_ptr() as *const i8, libc::O_WRONLY) };
        let fd2 = unsafe { libc::open(b"/dev/null\0".as_ptr() as *const i8, libc::O_WRONLY) };

        assert!(fd1 > 2 && fd1 != spare_write_fd, "test fd1 should be > 2 and != spare_write_fd");
        assert!(fd2 > 2 && fd2 != spare_write_fd, "test fd2 should be > 2 and != spare_write_fd");

        // Forget the OwnedFds so they don't try to close them (we'll do it manually or via close_fds)
        std::mem::forget(read_fd);
        std::mem::forget(write_fd);

        // Call close_fds, sparing stdin/stdout/stderr and both pipe ends
        close_fds(max_fd, spare_write_fd, spare_read_fd, -1);

        // Verify that fd1 and fd2 are closed (writing should fail with EBADF)
        let write_result = unsafe { libc::write(fd1, b"test" as *const u8 as *const libc::c_void, 4) };
        assert_eq!(write_result, -1, "fd1 should be closed after close_fds");

        // Verify that spare_write_fd is still open and functional (should be able to write to it)
        let write_result = unsafe {
            libc::write(spare_write_fd, b"X" as *const u8 as *const libc::c_void, 1)
        };
        assert_eq!(write_result, 1, "spare_write_fd should still be open and writable after close_fds");

        // Clean up spare_write_fd and spare_read_fd since we forgot them
        unsafe {
            libc::close(spare_write_fd);
            libc::close(spare_read_fd);
        }
    }
}

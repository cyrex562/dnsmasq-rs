/// General utility functions.
/// Ported from `util.c`.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::dns_protocol::MAXLABEL;
use crate::types::addr::MySockAddr;
use crate::types::dns_records::RrList;

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

// ── Linux kernel version ──────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
pub fn kernel_version() -> u32 {
    use std::process::Command;
    let output = Command::new("uname").arg("-r").output().ok();
    let release = output
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .unwrap_or_default();
    let parts: Vec<u32> = release.trim().splitn(4, '.').take(3)
        .map(|p| p.split(|c: char| !c.is_ascii_digit()).next().unwrap_or("0")
            .parse().unwrap_or(0))
        .collect();
    (parts.get(0).copied().unwrap_or(0) << 16)
        | (parts.get(1).copied().unwrap_or(0) << 8)
        | parts.get(2).copied().unwrap_or(0)
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
}

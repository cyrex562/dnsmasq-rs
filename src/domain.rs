/// Domain name utilities and synthetic name handling.
/// Ported from `domain.c`.

use std::net::{Ipv4Addr, Ipv6Addr};

/// A conditional domain mapping: maps a range of IP addresses to a domain.
#[derive(Debug, Clone)]
pub struct CondDomain {
    pub domain:  String,
    pub prefix:  Option<String>,
    pub start:   Ipv4Addr,
    pub end:     Ipv4Addr,
    pub start6:  Ipv6Addr,
    pub end6:    Ipv6Addr,
    pub is6:     bool,
    pub indexed: bool,
}

/// Returns true if `addr` falls in the range `[start, end]` (inclusive).
pub fn ipv4_in_range(addr: Ipv4Addr, start: Ipv4Addr, end: Ipv4Addr) -> bool {
    let a = u32::from(addr);
    let s = u32::from(start);
    let e = u32::from(end);
    a >= s && a <= e
}

/// Returns true if `addr` falls in the IPv6 range `[start, end]` (last 64 bits only).
pub fn ipv6_in_range(addr: Ipv6Addr, start: Ipv6Addr, end: Ipv6Addr) -> bool {
    let a = ipv6_low64(addr);
    let s = ipv6_low64(start);
    let e = ipv6_low64(end);
    a >= s && a <= e
}

/// Extract the lower 64 bits of an IPv6 address as a u64.
pub fn ipv6_low64(addr: Ipv6Addr) -> u64 {
    let o = addr.octets();
    u64::from_be_bytes(o[8..16].try_into().unwrap())
}

/// Set the lower 64 bits of an IPv6 address.
pub fn ipv6_set_low64(base: Ipv6Addr, low: u64) -> Ipv6Addr {
    let mut o = base.octets();
    let lb = low.to_be_bytes();
    o[8..16].copy_from_slice(&lb);
    Ipv6Addr::from(o)
}

/// Try to synthesise an IPv4 address from a name + list of conditional domains.
/// Returns `Some(Ipv4Addr)` if the name matches a synthetic domain.
pub fn synthesize_ipv4(name: &str, domains: &[CondDomain]) -> Option<Ipv4Addr> {
    for c in domains {
        if c.is6 {
            continue;
        }
        if let Some(addr) = try_synth_ipv4(name, c) {
            return Some(addr);
        }
    }
    None
}

fn try_synth_ipv4(name: &str, c: &CondDomain) -> Option<Ipv4Addr> {
    let tail = strip_prefix(name, c.prefix.as_deref())?;

    if c.indexed {
        let (idx_str, rest) = tail.split_once('.')?;
        if !rest.eq_ignore_ascii_case(&c.domain) {
            return None;
        }
        let idx: u32 = idx_str.parse().ok()?;
        let start = u32::from(c.start);
        let end = u32::from(c.end);
        if idx <= end - start {
            return Some(Ipv4Addr::from(start + idx));
        }
    } else {
        let (addr_str, rest) = tail.split_once('.')?;
        if !rest.eq_ignore_ascii_case(&c.domain) {
            return None;
        }
        // Replace '-' with '.' and parse
        let dotted = addr_str.replace('-', ".");
        let addr: Ipv4Addr = dotted.parse().ok()?;
        if ipv4_in_range(addr, c.start, c.end) {
            return Some(addr);
        }
    }
    None
}

/// Strip `prefix` from `name` case-insensitively; returns the tail or `None`.
fn strip_prefix<'a>(name: &'a str, prefix: Option<&str>) -> Option<&'a str> {
    match prefix {
        None => Some(name),
        Some(p) => {
            if name.len() < p.len() {
                return None;
            }
            let (head, tail) = name.split_at(p.len());
            if head.eq_ignore_ascii_case(p) {
                Some(tail)
            } else {
                None
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Reverse synthesis: address → hostname (ported from domain.c:153-215)
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a synthetic hostname from an IPv4 address and matching conditional domain.
///
/// For indexed domains: `<prefix><index>.<domain>` where index = addr - start.
/// For dashed domains: `<prefix><a-b-c-d>.<domain>`.
/// Port of the IPv4 path of `is_rev_synth()` from domain.c:153-182.
pub fn rev_synth_ipv4(addr: Ipv4Addr, domains: &[CondDomain]) -> Option<String> {
    for c in domains {
        if c.is6 {
            continue;
        }
        if !ipv4_in_range(addr, c.start, c.end) {
            continue;
        }
        let prefix = c.prefix.as_deref().unwrap_or("");
        let name = if c.indexed {
            let index = u32::from(addr) - u32::from(c.start);
            format!("{prefix}{index}.{}", c.domain)
        } else {
            let dotted = addr.to_string();
            let dashed = dotted.replace('.', "-");
            format!("{prefix}{dashed}.{}", c.domain)
        };
        return Some(name);
    }
    None
}

/// Generate a synthetic hostname from an IPv6 address and matching conditional domain.
///
/// For indexed domains: `<prefix><index>.<domain>` where index = low64(addr) - low64(start).
/// For hex domains: `<prefix><xxxx-xxxx-...-xxxx>.<domain>` (8 groups of 2 hex bytes).
/// Port of the IPv6 path of `is_rev_synth()` from domain.c:184-212.
pub fn rev_synth_ipv6(addr: Ipv6Addr, domains: &[CondDomain]) -> Option<String> {
    for c in domains {
        if !c.is6 {
            continue;
        }
        if !ipv6_in_range(addr, c.start6, c.end6) {
            continue;
        }
        let prefix = c.prefix.as_deref().unwrap_or("");
        let name = if c.indexed {
            let index = ipv6_low64(addr) - ipv6_low64(c.start6);
            format!("{prefix}{index}.{}", c.domain)
        } else {
            let octets = addr.octets();
            let hex_parts: Vec<String> = (0..8)
                .map(|i| format!("{:02x}{:02x}", octets[i * 2], octets[i * 2 + 1]))
                .collect();
            let hex_str = hex_parts.join("-");
            format!("{prefix}{hex_str}.{}", c.domain)
        };
        return Some(name);
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain matching and search (ported from domain.c:218-301)
// ─────────────────────────────────────────────────────────────────────────────

/// Check if an IPv4 address matches a conditional domain's range.
///
/// Port of `match_domain()` from domain.c:218-234.
pub fn match_domain(addr: Ipv4Addr, c: &CondDomain) -> bool {
    if c.is6 {
        return false;
    }
    let a = u32::from(addr);
    let s = u32::from(c.start);
    let e = u32::from(c.end);
    a >= s && a <= e
}

/// Search a list of conditional domains for one matching the IPv4 address.
///
/// Port of `search_domain()` from domain.c:236-243.
pub fn search_domain<'a>(addr: Ipv4Addr, domains: &'a [CondDomain]) -> Option<&'a CondDomain> {
    domains.iter().find(|c| match_domain(addr, c))
}

/// Get the domain suffix for an IPv4 address from conditional domains, with fallback.
///
/// Port of `get_domain()` from domain.c:245-253.
pub fn get_domain(addr: Ipv4Addr, domains: &[CondDomain], default: &str) -> String {
    match search_domain(addr, domains) {
        Some(c) => c.domain.clone(),
        None => default.to_string(),
    }
}

/// Check if an IPv6 address matches a conditional domain's range.
///
/// Port of `match_domain6()` from domain.c:255-282.
pub fn match_domain6(addr: Ipv6Addr, c: &CondDomain) -> bool {
    if !c.is6 {
        return false;
    }
    let a = ipv6_low64(addr);
    let s = ipv6_low64(c.start6);
    let e = ipv6_low64(c.end6);
    a >= s && a <= e
}

/// Search a list of conditional domains for one matching the IPv6 address.
///
/// Port of `search_domain6()` from domain.c:284-291.
pub fn search_domain6<'a>(addr: Ipv6Addr, domains: &'a [CondDomain]) -> Option<&'a CondDomain> {
    domains.iter().find(|c| match_domain6(addr, c))
}

/// Get the domain suffix for an IPv6 address from conditional domains, with fallback.
///
/// Port of `get_domain6()` from domain.c:293-301.
pub fn get_domain6(addr: Ipv6Addr, domains: &[CondDomain], default: &str) -> String {
    match search_domain6(addr, domains) {
        Some(c) => c.domain.clone(),
        None => default.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_domain(domain: &str, prefix: Option<&str>, start: Ipv4Addr, end: Ipv4Addr) -> CondDomain {
        CondDomain {
            domain: domain.to_string(),
            prefix: prefix.map(|s| s.to_string()),
            start,
            end,
            start6:  Ipv6Addr::UNSPECIFIED,
            end6:    Ipv6Addr::UNSPECIFIED,
            is6:     false,
            indexed: false,
        }
    }

    #[test]
    fn synth_ipv4_dashes() {
        let d = make_domain(
            "example.com",
            None,
            "192.168.1.0".parse().unwrap(),
            "192.168.1.255".parse().unwrap(),
        );
        let result = synthesize_ipv4("192-168-1-42.example.com", &[d]);
        assert_eq!(result, Some("192.168.1.42".parse().unwrap()));
    }

    #[test]
    fn synth_ipv4_out_of_range() {
        let d = make_domain(
            "example.com",
            None,
            "10.0.0.0".parse().unwrap(),
            "10.0.0.10".parse().unwrap(),
        );
        let result = synthesize_ipv4("192-168-1-42.example.com", &[d]);
        assert!(result.is_none());
    }

    #[test]
    fn synth_ipv4_indexed() {
        let mut d = make_domain(
            "example.com",
            None,
            "10.0.0.0".parse().unwrap(),
            "10.0.0.255".parse().unwrap(),
        );
        d.indexed = true;
        let result = try_synth_ipv4("5.example.com", &d);
        assert_eq!(result, Some("10.0.0.5".parse().unwrap()));
    }

    #[test]
    fn synth_ipv4_with_prefix() {
        let d = make_domain(
            "example.com",
            Some("ip-"),
            "10.0.0.0".parse().unwrap(),
            "10.0.0.255".parse().unwrap(),
        );
        let result = synthesize_ipv4("ip-10-0-0-7.example.com", &[d]);
        assert_eq!(result, Some("10.0.0.7".parse().unwrap()));
    }

    #[test]
    fn ipv6_low64_roundtrip() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let low = ipv6_low64(addr);
        assert_eq!(low, 1u64);
        let rebuilt = ipv6_set_low64("2001:db8::".parse().unwrap(), low);
        assert_eq!(rebuilt, addr);
    }

    // ── ipv4_in_range tests ──

    #[test]
    fn ipv4_in_range_within() {
        assert!(ipv4_in_range(
            "10.0.0.5".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            "10.0.0.255".parse().unwrap(),
        ));
    }

    #[test]
    fn ipv4_in_range_at_start() {
        assert!(ipv4_in_range(
            "10.0.0.0".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            "10.0.0.255".parse().unwrap(),
        ));
    }

    #[test]
    fn ipv4_in_range_at_end() {
        assert!(ipv4_in_range(
            "10.0.0.255".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            "10.0.0.255".parse().unwrap(),
        ));
    }

    #[test]
    fn ipv4_in_range_below() {
        assert!(!ipv4_in_range(
            "9.255.255.255".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            "10.0.0.255".parse().unwrap(),
        ));
    }

    #[test]
    fn ipv4_in_range_above() {
        assert!(!ipv4_in_range(
            "10.0.1.0".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            "10.0.0.255".parse().unwrap(),
        ));
    }

    // ── ipv6_in_range tests ──

    #[test]
    fn ipv6_in_range_within() {
        assert!(ipv6_in_range(
            "2001:db8::5".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            "2001:db8::ff".parse().unwrap(),
        ));
    }

    #[test]
    fn ipv6_in_range_at_boundaries() {
        let start: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let end: Ipv6Addr = "2001:db8::ff".parse().unwrap();
        assert!(ipv6_in_range(start, start, end));
        assert!(ipv6_in_range(end, start, end));
    }

    #[test]
    fn ipv6_in_range_below() {
        assert!(!ipv6_in_range(
            "2001:db8::0".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            "2001:db8::ff".parse().unwrap(),
        ));
    }

    // ── ipv6 helper edge cases ──

    #[test]
    fn ipv6_low64_all_zeros() {
        let addr: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert_eq!(ipv6_low64(addr), 0u64);
    }

    #[test]
    fn ipv6_low64_all_ones() {
        let addr: Ipv6Addr = "::ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(ipv6_low64(addr), u64::MAX);
    }

    #[test]
    fn ipv6_set_low64_preserves_upper() {
        let base: Ipv6Addr = "2001:db8:abcd:ef01::".parse().unwrap();
        let result = ipv6_set_low64(base, 42);
        // Upper 64 bits preserved
        assert_eq!(ipv6_low64(result), 42);
        let octets = result.octets();
        assert_eq!(&octets[..8], &base.octets()[..8]);
    }

    // ── synthesize_ipv4 edge cases ──

    #[test]
    fn synth_ipv4_skips_ipv6_domains() {
        let d = CondDomain {
            domain: "example.com".to_string(),
            prefix: None,
            start: "10.0.0.0".parse().unwrap(),
            end: "10.0.0.255".parse().unwrap(),
            start6: Ipv6Addr::UNSPECIFIED,
            end6: Ipv6Addr::UNSPECIFIED,
            is6: true,
            indexed: false,
        };
        assert!(synthesize_ipv4("10-0-0-1.example.com", &[d]).is_none());
    }

    #[test]
    fn synth_ipv4_no_match_wrong_domain() {
        let d = make_domain(
            "example.com",
            None,
            "10.0.0.0".parse().unwrap(),
            "10.0.0.255".parse().unwrap(),
        );
        assert!(synthesize_ipv4("10-0-0-1.other.com", &[d]).is_none());
    }

    #[test]
    fn synth_ipv4_indexed_out_of_range() {
        let mut d = make_domain(
            "example.com",
            None,
            "10.0.0.0".parse().unwrap(),
            "10.0.0.10".parse().unwrap(),
        );
        d.indexed = true;
        // Index 11 exceeds range (end - start = 10)
        assert!(synthesize_ipv4("11.example.com", &[d]).is_none());
    }

    #[test]
    fn synth_ipv4_prefix_case_insensitive() {
        let d = make_domain(
            "example.com",
            Some("IP-"),
            "10.0.0.0".parse().unwrap(),
            "10.0.0.255".parse().unwrap(),
        );
        let result = synthesize_ipv4("ip-10-0-0-7.example.com", &[d]);
        assert_eq!(result, Some("10.0.0.7".parse().unwrap()));
    }

    #[test]
    fn synth_ipv4_empty_domains_returns_none() {
        assert!(synthesize_ipv4("10-0-0-1.example.com", &[]).is_none());
    }

    // ── rev_synth_ipv4 ──────────────────────────────────────────────────────

    #[test]
    fn rev_synth_ipv4_dashed() {
        let d = make_domain("example.com", None, "10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        let name = rev_synth_ipv4("10.0.0.42".parse().unwrap(), &[d]);
        assert_eq!(name.as_deref(), Some("10-0-0-42.example.com"));
    }

    #[test]
    fn rev_synth_ipv4_indexed() {
        let mut d = make_domain("example.com", None, "10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        d.indexed = true;
        let name = rev_synth_ipv4("10.0.0.5".parse().unwrap(), &[d]);
        assert_eq!(name.as_deref(), Some("5.example.com"));
    }

    #[test]
    fn rev_synth_ipv4_with_prefix() {
        let d = make_domain("example.com", Some("ip-"), "10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        let name = rev_synth_ipv4("10.0.0.7".parse().unwrap(), &[d]);
        assert_eq!(name.as_deref(), Some("ip-10-0-0-7.example.com"));
    }

    #[test]
    fn rev_synth_ipv4_out_of_range() {
        let d = make_domain("example.com", None, "10.0.0.0".parse().unwrap(), "10.0.0.10".parse().unwrap());
        assert!(rev_synth_ipv4("10.0.0.50".parse().unwrap(), &[d]).is_none());
    }

    // ── rev_synth_ipv6 ──────────────────────────────────────────────────────

    fn make_v6_domain(domain: &str, prefix: Option<&str>, start6: Ipv6Addr, end6: Ipv6Addr, indexed: bool) -> CondDomain {
        CondDomain {
            domain: domain.to_string(),
            prefix: prefix.map(|s| s.to_string()),
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            start6,
            end6,
            is6: true,
            indexed,
        }
    }

    #[test]
    fn rev_synth_ipv6_hex() {
        let d = make_v6_domain("example.com", None, "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(), false);
        let name = rev_synth_ipv6("2001:db8::42".parse().unwrap(), &[d]);
        let n = name.unwrap();
        assert!(n.ends_with(".example.com"));
        assert!(n.contains("2001"));
    }

    #[test]
    fn rev_synth_ipv6_indexed() {
        let d = make_v6_domain("example.com", None, "2001:db8::100".parse().unwrap(), "2001:db8::200".parse().unwrap(), true);
        let name = rev_synth_ipv6("2001:db8::105".parse().unwrap(), &[d]);
        assert_eq!(name.as_deref(), Some("5.example.com"));
    }

    #[test]
    fn rev_synth_ipv6_with_prefix() {
        let d = make_v6_domain("example.com", Some("host-"), "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(), true);
        let name = rev_synth_ipv6("2001:db8::3".parse().unwrap(), &[d]);
        assert_eq!(name.as_deref(), Some("host-2.example.com"));
    }

    #[test]
    fn rev_synth_ipv6_out_of_range() {
        let d = make_v6_domain("example.com", None, "2001:db8::1".parse().unwrap(), "2001:db8::10".parse().unwrap(), false);
        assert!(rev_synth_ipv6("2001:db8::ff".parse().unwrap(), &[d]).is_none());
    }

    // ── match_domain / search_domain ─────────────────────────────────────────

    #[test]
    fn match_domain_in_range() {
        let d = make_domain("example.com", None, "10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        assert!(match_domain("10.0.0.42".parse().unwrap(), &d));
    }

    #[test]
    fn match_domain_out_of_range() {
        let d = make_domain("example.com", None, "10.0.0.0".parse().unwrap(), "10.0.0.10".parse().unwrap());
        assert!(!match_domain("10.0.0.50".parse().unwrap(), &d));
    }

    #[test]
    fn match_domain_skips_v6() {
        let d = make_v6_domain("example.com", None, "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(), false);
        assert!(!match_domain("10.0.0.1".parse().unwrap(), &d));
    }

    #[test]
    fn search_domain_finds_match() {
        let d = make_domain("example.com", None, "10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        assert!(search_domain("10.0.0.42".parse().unwrap(), &[d]).is_some());
    }

    #[test]
    fn search_domain_no_match() {
        let d = make_domain("example.com", None, "10.0.0.0".parse().unwrap(), "10.0.0.10".parse().unwrap());
        assert!(search_domain("192.168.1.1".parse().unwrap(), &[d]).is_none());
    }

    #[test]
    fn get_domain_match() {
        let d = make_domain("my.lan", None, "10.0.0.0".parse().unwrap(), "10.0.0.255".parse().unwrap());
        assert_eq!(get_domain("10.0.0.1".parse().unwrap(), &[d], "default.lan"), "my.lan");
    }

    #[test]
    fn get_domain_fallback() {
        assert_eq!(get_domain("192.168.1.1".parse().unwrap(), &[], "default.lan"), "default.lan");
    }

    // ── match_domain6 / search_domain6 ───────────────────────────────────────

    #[test]
    fn match_domain6_in_range() {
        let d = make_v6_domain("example.com", None, "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(), false);
        assert!(match_domain6("2001:db8::42".parse().unwrap(), &d));
    }

    #[test]
    fn match_domain6_out_of_range() {
        let d = make_v6_domain("example.com", None, "2001:db8::1".parse().unwrap(), "2001:db8::10".parse().unwrap(), false);
        assert!(!match_domain6("2001:db8::ff".parse().unwrap(), &d));
    }

    #[test]
    fn search_domain6_finds_match() {
        let d = make_v6_domain("v6.lan", None, "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(), false);
        assert!(search_domain6("2001:db8::42".parse().unwrap(), &[d]).is_some());
    }

    #[test]
    fn get_domain6_match() {
        let d = make_v6_domain("v6.lan", None, "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(), false);
        assert_eq!(get_domain6("2001:db8::5".parse().unwrap(), &[d], "default.lan"), "v6.lan");
    }

    #[test]
    fn get_domain6_fallback() {
        assert_eq!(get_domain6("fe80::1".parse().unwrap(), &[], "default.lan"), "default.lan");
    }
}

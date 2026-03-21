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
}

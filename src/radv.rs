//! IPv6 Router Advertisement builder and parser.
//! Ported from `radv.c`.

#[cfg(feature = "dhcp6")]
use std::net::Ipv6Addr;
#[cfg(feature = "dhcp6")]
use crate::radv_protocol::{ICMP6_OPT_PREFIX, ICMP6_OPT_RDNSS};

// ICMPv6 type 134 = Router Advertisement
#[cfg(feature = "dhcp6")]
const ICMPV6_RA: u8 = 134;

// RA flags
#[cfg(feature = "dhcp6")]
const RA_FLAG_MANAGED: u8 = 0x80;
#[cfg(feature = "dhcp6")]
const RA_FLAG_OTHER:   u8 = 0x40;

// Prefix Information option flags
#[cfg(feature = "dhcp6")]
const PREFIX_FLAG_ONLINK: u8    = 0x80;
#[cfg(feature = "dhcp6")]
const PREFIX_FLAG_AUTONOMOUS: u8 = 0x40;

/// One prefix advertised in a Router Advertisement.
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaPrefix {
    pub prefix:       Ipv6Addr,
    pub prefix_len:   u8,
    pub on_link:      bool,
    pub autonomous:   bool,
    pub valid_lt:     u32,
    pub preferred_lt: u32,
}

/// A Router Advertisement message (ICMPv6 type 134).
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone)]
pub struct RouterAdvertisement {
    pub hop_limit:   u8,
    /// M flag — clients should use DHCPv6 for address assignment.
    pub managed:     bool,
    /// O flag — clients should use DHCPv6 for other configuration.
    pub other:       bool,
    /// Router lifetime in seconds (0 = not a default router).
    pub router_lt:   u16,
    pub prefixes:    Vec<RaPrefix>,
    pub dns_servers: Vec<Ipv6Addr>,
}

/// Errors returned by [`parse_ra`].
#[cfg(feature = "dhcp6")]
#[derive(Debug, thiserror::Error)]
pub enum RadvError {
    #[error("data too short")]
    TooShort,
    #[error("invalid ICMPv6 type: {0}")]
    InvalidType(u8),
}

/// Build a Router Advertisement ICMPv6 payload (type byte through options).
///
/// Wire format (RFC 4861 §4.2):
///   1 type(134) | 1 code(0) | 2 checksum(0) | 1 hop-limit | 1 flags |
///   2 router-lifetime | 4 reachable-time | 4 retrans-time | options …
///
/// Prefix Information option (type 3, len 4 units = 32 bytes):
///   1 type | 1 len | 1 prefix-len | 1 flags | 4 valid-lt | 4 preferred-lt |
///   4 reserved | 16 prefix
///
/// RDNSS option (type 25):
///   1 type | 1 len | 2 reserved | 4 lifetime | 16*N addresses
#[cfg(feature = "dhcp6")]
pub fn build_ra(ra: &RouterAdvertisement) -> Vec<u8> {
    let mut buf = Vec::new();

    // Fixed header (16 bytes)
    buf.push(ICMPV6_RA);               // type
    buf.push(0u8);                     // code
    buf.extend_from_slice(&0u16.to_be_bytes()); // checksum (caller fills in)
    buf.push(ra.hop_limit);
    let mut flags = 0u8;
    if ra.managed { flags |= RA_FLAG_MANAGED; }
    if ra.other   { flags |= RA_FLAG_OTHER;   }
    buf.push(flags);
    buf.extend_from_slice(&ra.router_lt.to_be_bytes());
    buf.extend_from_slice(&0u32.to_be_bytes()); // reachable time
    buf.extend_from_slice(&0u32.to_be_bytes()); // retrans time

    // Prefix Information options (type 3, each 32 bytes = 4 units of 8)
    for pfx in &ra.prefixes {
        buf.push(ICMP6_OPT_PREFIX); // type 3
        buf.push(4u8);              // length in units of 8 bytes = 32 bytes
        buf.push(pfx.prefix_len);
        let mut pflags = 0u8;
        if pfx.on_link    { pflags |= PREFIX_FLAG_ONLINK; }
        if pfx.autonomous { pflags |= PREFIX_FLAG_AUTONOMOUS; }
        buf.push(pflags);
        buf.extend_from_slice(&pfx.valid_lt.to_be_bytes());
        buf.extend_from_slice(&pfx.preferred_lt.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // reserved
        buf.extend_from_slice(&pfx.prefix.octets());
    }

    // RDNSS option (type 25) — only emitted when there are DNS servers
    if !ra.dns_servers.is_empty() {
        // length = 1 (header) + 1 (reserved/lifetime) + N*2 units of 8 bytes
        let opt_len = 1u8 + 2 * ra.dns_servers.len() as u8;
        buf.push(ICMP6_OPT_RDNSS);
        buf.push(opt_len);
        buf.extend_from_slice(&0u16.to_be_bytes()); // reserved
        buf.extend_from_slice(&3600u32.to_be_bytes()); // lifetime
        for addr in &ra.dns_servers {
            buf.extend_from_slice(&addr.octets());
        }
    }

    buf
}

/// Parse a Router Advertisement ICMPv6 payload.
#[cfg(feature = "dhcp6")]
pub fn parse_ra(data: &[u8]) -> Result<RouterAdvertisement, RadvError> {
    // Minimum RA header is 16 bytes
    if data.len() < 16 {
        return Err(RadvError::TooShort);
    }
    if data[0] != ICMPV6_RA {
        return Err(RadvError::InvalidType(data[0]));
    }
    let hop_limit = data[4];
    let flags     = data[5];
    let managed   = (flags & RA_FLAG_MANAGED) != 0;
    let other     = (flags & RA_FLAG_OTHER)   != 0;
    let router_lt = u16::from_be_bytes([data[6], data[7]]);
    // bytes 8..11 = reachable time, 12..15 = retrans time — not stored

    let mut prefixes    = Vec::new();
    let mut dns_servers = Vec::new();

    let mut pos = 16usize;
    while pos < data.len() {
        if pos + 2 > data.len() {
            return Err(RadvError::TooShort);
        }
        let opt_type = data[pos];
        let opt_len  = data[pos + 1] as usize * 8; // length in bytes
        if opt_len == 0 || pos + opt_len > data.len() {
            return Err(RadvError::TooShort);
        }
        let opt_data = &data[pos + 2..pos + opt_len];

        match opt_type {
            t if t == ICMP6_OPT_PREFIX => {
                // Prefix Information: prefix_len(1) flags(1) valid(4) preferred(4) reserved(4) prefix(16)
                if opt_data.len() < 30 {
                    return Err(RadvError::TooShort);
                }
                let prefix_len   = opt_data[0];
                let pflags       = opt_data[1];
                let valid_lt     = u32::from_be_bytes([opt_data[2], opt_data[3], opt_data[4], opt_data[5]]);
                let preferred_lt = u32::from_be_bytes([opt_data[6], opt_data[7], opt_data[8], opt_data[9]]);
                // opt_data[10..13] = reserved
                let prefix_bytes: [u8; 16] = opt_data[14..30].try_into().unwrap();
                let prefix = Ipv6Addr::from(prefix_bytes);
                prefixes.push(RaPrefix {
                    prefix,
                    prefix_len,
                    on_link:      (pflags & PREFIX_FLAG_ONLINK)    != 0,
                    autonomous:   (pflags & PREFIX_FLAG_AUTONOMOUS) != 0,
                    valid_lt,
                    preferred_lt,
                });
            }
            t if t == ICMP6_OPT_RDNSS => {
                // RDNSS: reserved(2) lifetime(4) addresses(16*N)
                if opt_data.len() < 6 {
                    return Err(RadvError::TooShort);
                }
                let mut i = 6usize; // skip reserved(2) + lifetime(4)
                while i + 16 <= opt_data.len() {
                    let addr_bytes: [u8; 16] = opt_data[i..i + 16].try_into().unwrap();
                    dns_servers.push(Ipv6Addr::from(addr_bytes));
                    i += 16;
                }
            }
            _ => {} // ignore unknown options
        }

        pos += opt_len;
    }

    Ok(RouterAdvertisement { hop_limit, managed, other, router_lt, prefixes, dns_servers })
}

#[cfg(all(test, feature = "dhcp6"))]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

    fn sample_ra() -> RouterAdvertisement {
        RouterAdvertisement {
            hop_limit: 64,
            managed:   false,
            other:     true,
            router_lt: 1800,
            prefixes:  vec![RaPrefix {
                prefix:       Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                prefix_len:   64,
                on_link:      true,
                autonomous:   true,
                valid_lt:     86400,
                preferred_lt: 14400,
            }],
            dns_servers: vec![Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)],
        }
    }

    #[test]
    fn roundtrip() {
        let ra  = sample_ra();
        let buf = build_ra(&ra);
        let parsed = parse_ra(&buf).unwrap();
        assert_eq!(parsed.hop_limit,  ra.hop_limit);
        assert_eq!(parsed.managed,    ra.managed);
        assert_eq!(parsed.other,      ra.other);
        assert_eq!(parsed.router_lt,  ra.router_lt);
        assert_eq!(parsed.prefixes.len(),    1);
        assert_eq!(parsed.dns_servers.len(), 1);
        let p = &parsed.prefixes[0];
        assert_eq!(p.prefix,       ra.prefixes[0].prefix);
        assert_eq!(p.prefix_len,   ra.prefixes[0].prefix_len);
        assert_eq!(p.on_link,      ra.prefixes[0].on_link);
        assert_eq!(p.autonomous,   ra.prefixes[0].autonomous);
        assert_eq!(p.valid_lt,     ra.prefixes[0].valid_lt);
        assert_eq!(p.preferred_lt, ra.prefixes[0].preferred_lt);
        assert_eq!(parsed.dns_servers[0], ra.dns_servers[0]);
    }

    #[test]
    fn multiple_prefixes_roundtrip() {
        let mut ra = sample_ra();
        ra.prefixes.push(RaPrefix {
            prefix:       Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0),
            prefix_len:   48,
            on_link:      false,
            autonomous:   true,
            valid_lt:     3600,
            preferred_lt: 1800,
        });
        let buf = build_ra(&ra);
        let parsed = parse_ra(&buf).unwrap();
        assert_eq!(parsed.prefixes.len(), 2);
        assert_eq!(parsed.prefixes[1].prefix, ra.prefixes[1].prefix);
        assert_eq!(parsed.prefixes[1].prefix_len, 48);
    }

    #[test]
    fn truncated_input_is_error() {
        assert!(matches!(parse_ra(&[]), Err(RadvError::TooShort)));
        assert!(matches!(parse_ra(&[134u8; 4]), Err(RadvError::TooShort)));
    }

    #[test]
    fn wrong_type_is_error() {
        let mut buf = build_ra(&sample_ra());
        buf[0] = 133; // Router Solicitation — not an RA
        assert!(matches!(parse_ra(&buf), Err(RadvError::InvalidType(133))));
    }
}

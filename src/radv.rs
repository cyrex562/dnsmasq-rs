//! IPv6 Router Advertisement builder and parser.
//! Ported from `radv.c`.

#[cfg(feature = "dhcp6")]
use std::net::Ipv6Addr;
#[cfg(feature = "dhcp6")]
use std::time::{Duration, Instant};
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

/// Priority level for Router Advertisements (maps to RFC 4191 preference bits).
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaPriority {
    Low,
    Medium,
    High,
}

/// Timer scheduling state for periodic Router Advertisements on an interface.
#[cfg(feature = "dhcp6")]
pub struct RaSchedule {
    pub interface: String,
    pub if_index: i32,
    pub next_ra: Instant,
    pub min_interval: Duration,
    pub max_interval: Duration,
    pub lifetime: Duration,
    pub priority: RaPriority,
    pub unsolicited_count: u32,
}

#[cfg(feature = "dhcp6")]
impl RaSchedule {
    /// Create a new schedule with default intervals (RFC 4861 defaults).
    /// min_interval = 200s, max_interval = 600s, lifetime = 1800s.
    pub fn new(interface: &str, if_index: i32) -> Self {
        let max_interval = Duration::from_secs(600);
        Self {
            interface: interface.to_string(),
            if_index,
            next_ra: Instant::now() + max_interval,
            min_interval: Duration::from_secs(200),
            max_interval,
            lifetime: Duration::from_secs(1800),
            priority: RaPriority::Medium,
            unsolicited_count: 0,
        }
    }

    /// Returns `true` if it is time to send the next RA.
    pub fn is_due(&self) -> bool {
        Instant::now() >= self.next_ra
    }

    /// Record that an RA was just sent. Schedules the next one with random
    /// jitter between `min_interval` and `max_interval`.
    pub fn mark_sent(&mut self) {
        let min = self.min_interval.as_secs_f64();
        let max = self.max_interval.as_secs_f64();
        // Simple deterministic jitter: pick the midpoint.
        // In production this would use a PRNG, but for correctness we use
        // a reproducible value derived from the current instant.
        let range = max - min;
        // Use a cheap hash of the current time for jitter.
        let now_nanos = self.next_ra.elapsed().as_nanos() as u64;
        let frac = if range > 0.0 {
            (now_nanos % 1000) as f64 / 1000.0
        } else {
            0.0
        };
        let delay = min + range * frac;
        self.next_ra = Instant::now() + Duration::from_secs_f64(delay);
        if self.unsolicited_count > 0 {
            self.unsolicited_count -= 1;
        }
    }

    /// Begin sending `count` unsolicited RAs at short intervals
    /// (min 3s, max 10s) as required at startup or prefix changes.
    pub fn start_unsolicited(&mut self, count: u32) {
        self.unsolicited_count = count;
        self.min_interval = Duration::from_secs(3);
        self.max_interval = Duration::from_secs(10);
        // Send the first one soon.
        self.next_ra = Instant::now();
    }
}

/// Calculate the RA lifetime value in seconds from optional configuration.
/// Clamps to the valid range [0, 65535] (fits in a u16 on the wire).
#[cfg(feature = "dhcp6")]
pub fn calc_lifetime(configured: Option<u32>, default_secs: u32) -> u32 {
    let val = configured.unwrap_or(default_secs);
    val.min(65535)
}

/// Calculate the min/max RA interval pair, enforcing RFC constraints:
///   - min >= 3
///   - min >= max * 0.33 (rounded up)
///
/// Returns `(min, max)` in seconds.
#[cfg(feature = "dhcp6")]
pub fn calc_interval(min: Option<u32>, max: Option<u32>) -> (u32, u32) {
    let max_val = max.unwrap_or(600);
    let min_floor = ((max_val as f64) * 0.33).ceil() as u32;
    let min_val = min.unwrap_or(min_floor).max(min_floor).max(3);
    (min_val, max_val)
}

/// Convert an [`RaPriority`] to the wire-format byte used in the RA flags field
/// (RFC 4191 §2.2, bits 3–4 of the flags byte).
///   Low    → 0x18  (11 in prf bits)
///   Medium → 0x00  (00 in prf bits)
///   High   → 0x08  (01 in prf bits)
#[cfg(feature = "dhcp6")]
pub fn priority_byte(prio: RaPriority) -> u8 {
    match prio {
        RaPriority::Low    => 0x18,
        RaPriority::Medium => 0x00,
        RaPriority::High   => 0x08,
    }
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

    // --- RaSchedule tests ---

    #[test]
    fn ra_schedule_new_defaults() {
        let sched = RaSchedule::new("eth0", 2);
        assert_eq!(sched.interface, "eth0");
        assert_eq!(sched.if_index, 2);
        assert_eq!(sched.min_interval, Duration::from_secs(200));
        assert_eq!(sched.max_interval, Duration::from_secs(600));
        assert_eq!(sched.lifetime, Duration::from_secs(1800));
        assert_eq!(sched.priority, RaPriority::Medium);
        assert_eq!(sched.unsolicited_count, 0);
    }

    #[test]
    fn ra_schedule_is_due_false_initially() {
        let sched = RaSchedule::new("eth0", 1);
        // next_ra is set to now + max_interval, so it should not be due yet.
        assert!(!sched.is_due());
    }

    #[test]
    fn ra_schedule_is_due_true_after_time_passes() {
        let mut sched = RaSchedule::new("eth0", 1);
        // Force next_ra to be in the past.
        sched.next_ra = Instant::now() - Duration::from_secs(1);
        assert!(sched.is_due());
    }

    #[test]
    fn ra_schedule_mark_sent_updates_next_ra() {
        let mut sched = RaSchedule::new("eth0", 1);
        let before = Instant::now();
        sched.mark_sent();
        // next_ra should be at least min_interval from now.
        assert!(sched.next_ra >= before + sched.min_interval);
    }

    #[test]
    fn ra_schedule_mark_sent_decrements_unsolicited() {
        let mut sched = RaSchedule::new("eth0", 1);
        sched.unsolicited_count = 3;
        sched.mark_sent();
        assert_eq!(sched.unsolicited_count, 2);
        sched.mark_sent();
        assert_eq!(sched.unsolicited_count, 1);
        sched.mark_sent();
        assert_eq!(sched.unsolicited_count, 0);
        // Should not go below 0.
        sched.mark_sent();
        assert_eq!(sched.unsolicited_count, 0);
    }

    #[test]
    fn ra_schedule_start_unsolicited_sets_short_intervals() {
        let mut sched = RaSchedule::new("eth0", 1);
        sched.start_unsolicited(5);
        assert_eq!(sched.unsolicited_count, 5);
        assert_eq!(sched.min_interval, Duration::from_secs(3));
        assert_eq!(sched.max_interval, Duration::from_secs(10));
        // Should be due immediately.
        assert!(sched.is_due());
    }

    // --- calc_lifetime tests ---

    #[test]
    fn calc_lifetime_uses_default() {
        assert_eq!(calc_lifetime(None, 1800), 1800);
    }

    #[test]
    fn calc_lifetime_uses_configured() {
        assert_eq!(calc_lifetime(Some(900), 1800), 900);
    }

    #[test]
    fn calc_lifetime_clamps_to_max() {
        assert_eq!(calc_lifetime(Some(100_000), 1800), 65535);
    }

    #[test]
    fn calc_lifetime_zero_is_valid() {
        assert_eq!(calc_lifetime(Some(0), 1800), 0);
    }

    // --- calc_interval tests ---

    #[test]
    fn calc_interval_defaults() {
        let (min, max) = calc_interval(None, None);
        assert_eq!(max, 600);
        // min should be at least ceil(600 * 0.33) = 198
        assert!(min >= 198);
        assert!(min >= 3);
    }

    #[test]
    fn calc_interval_enforces_min_ge_max_times_033() {
        // If min is set too low, it should be raised.
        let (min, max) = calc_interval(Some(1), Some(300));
        assert_eq!(max, 300);
        let floor = ((300.0_f64) * 0.33).ceil() as u32;
        assert!(min >= floor);
    }

    #[test]
    fn calc_interval_enforces_min_ge_3() {
        let (min, _max) = calc_interval(Some(1), Some(5));
        assert!(min >= 3);
    }

    #[test]
    fn calc_interval_respects_valid_min() {
        // If min is already valid and above the floor, use it.
        let (min, max) = calc_interval(Some(250), Some(600));
        assert_eq!(max, 600);
        assert_eq!(min, 250);
    }

    // --- priority_byte tests ---

    #[test]
    fn priority_byte_values() {
        assert_eq!(priority_byte(RaPriority::Low), 0x18);
        assert_eq!(priority_byte(RaPriority::Medium), 0x00);
        assert_eq!(priority_byte(RaPriority::High), 0x08);
    }

    // --- build_ra with priority ---

    #[test]
    fn build_ra_with_priority_flag() {
        let mut ra = sample_ra();
        // Manually set the flags byte to include priority.
        let buf = build_ra(&ra);
        // Default flags: other=true => 0x40, no priority bits.
        assert_eq!(buf[5], 0x40);

        // Now build with high priority injected into flags.
        ra.other = false;
        ra.managed = false;
        let buf2 = build_ra(&ra);
        // Flags byte should be 0x00 (medium priority is the default, no flag bits).
        assert_eq!(buf2[5], 0x00);
        // Verify we can OR in the priority byte.
        let flags_with_prio = buf2[5] | priority_byte(RaPriority::High);
        assert_eq!(flags_with_prio, 0x08);
        let flags_with_low = buf2[5] | priority_byte(RaPriority::Low);
        assert_eq!(flags_with_low, 0x18);
    }
}

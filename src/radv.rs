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

// ─────────────────────────────────────────────────────────────────────────────
// RA interface config (ported from radv.c types)
// ─────────────────────────────────────────────────────────────────────────────

/// Per-interface RA configuration parameters.
///
/// Mirrors C `struct ra_interface` from dnsmasq.h.
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone)]
pub struct RaInterfaceParam {
    pub name: String,
    pub interval: u32,   // MaxRtrAdvInterval, 0 = default 600
    pub lifetime: i32,   // -1 = not specified
    pub prio: u32,       // 0=medium, 1=high, 2=low
    pub mtu: u32,        // 0 = not set
}

// ─────────────────────────────────────────────────────────────────────────────
// Pure helper functions (ported from radv.c:973-1037)
// ─────────────────────────────────────────────────────────────────────────────

/// Calculate the RA interval (MaxRtrAdvInterval) in seconds.
///
/// Defaults to 600. If `ra` is set and its `interval` is non-zero, that value
/// is used, clamped to `[4, 1800]`.
///
/// Port of `calc_interval()` from radv.c:997-1011.
#[cfg(feature = "dhcp6")]
pub fn calc_interval(ra: Option<&RaInterfaceParam>) -> u32 {
    let mut interval: i32 = 600;

    if let Some(p) = ra {
        if p.interval != 0 {
            interval = p.interval as i32;
            if interval > 1800 {
                interval = 1800;
            } else if interval < 4 {
                interval = 4;
            }
        }
    }

    interval as u32
}

/// Calculate the RA router lifetime in seconds.
///
/// Defaults to `3 * interval` when `ra` is absent or `lifetime == -1`
/// ("not specified"). Otherwise uses `ra.lifetime`, raised to `interval` if
/// smaller (unless it is `0`, meaning "no default route"), and clamped to a
/// maximum of `9000`.
///
/// Port of `calc_lifetime()` from radv.c:1013-1029.
#[cfg(feature = "dhcp6")]
pub fn calc_lifetime(ra: Option<&RaInterfaceParam>) -> u32 {
    let interval = calc_interval(ra) as i32;
    let mut lifetime: i32;

    if ra.is_none() || ra.map(|p| p.lifetime) == Some(-1) {
        lifetime = 3 * interval;
    } else {
        lifetime = ra.unwrap().lifetime;
        if lifetime < interval && lifetime != 0 {
            lifetime = interval;
        } else if lifetime > 9000 {
            lifetime = 9000;
        }
    }

    lifetime as u32
}

/// Extract priority value from RA interface config.
///
/// Port of `calc_prio()` from radv.c:1031-1037.
#[cfg(feature = "dhcp6")]
pub fn calc_prio(ra: Option<&RaInterfaceParam>) -> u32 {
    match ra {
        Some(p) => p.prio,
        None => 0, // medium
    }
}

/// Find RA interface config matching an interface name (with wildcard support).
///
/// Port of `find_iface_param()` from radv.c:986-995.
#[cfg(feature = "dhcp6")]
pub fn find_iface_param<'a>(
    ra_interfaces: &'a [RaInterfaceParam],
    iface: &str,
) -> Option<&'a RaInterfaceParam> {
    ra_interfaces.iter().find(|p| crate::pattern::glob_match(iface, &p.name))
}

/// Calculate the next RA transmission timeout with jitter.
///
/// During the "short period" (first 60 seconds), uses 5-20 second range.
/// After that, uses 3/4 to 1× `adv_interval`.
/// `rand_val` provides randomness (0-65535) for jitter.
/// Port of `new_timeout()` from radv.c:973-984.
#[cfg(feature = "dhcp6")]
pub fn new_timeout(
    elapsed_since_start: Duration,
    adv_interval: u32,
    rand_val: u16,
) -> Duration {
    let short_period = Duration::from_secs(60);
    if elapsed_since_start < short_period {
        // Short period: 5 + rand(0..15)
        let jitter = ((rand_val as u64) * 15) / 65536;
        Duration::from_secs(5 + jitter)
    } else {
        // Normal: 3/4 * interval + rand(0..1/4 * interval)
        let interval = if adv_interval == 0 { 600 } else { adv_interval } as u64;
        let base = (interval * 3) / 4;
        let range = interval / 4;
        let jitter = if range > 0 { ((rand_val as u64) * range) / 65536 } else { 0 };
        Duration::from_secs(base + jitter)
    }
}

/// Append an ICMPv6 Source Link-Layer Address option to a buffer.
///
/// Type = 1 (Source Link-Layer Address), length in 8-byte units, padded with zeros.
/// Port of `add_lla()` from radv.c:766-787.
#[cfg(feature = "dhcp6")]
pub fn add_lla(buf: &mut Vec<u8>, mac: &[u8]) {
    use crate::radv_protocol::ICMP6_OPT_SOURCE_MAC;
    // Option: type(1) + len(1) + mac(N) + padding to 8-byte boundary
    let total = 2 + mac.len();
    let padded = ((total + 7) / 8) * 8;
    let len_field = (padded / 8) as u8;
    buf.push(ICMP6_OPT_SOURCE_MAC);
    buf.push(len_field);
    buf.extend_from_slice(mac);
    // Pad with zeros
    for _ in 0..(padded - total) {
        buf.push(0);
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

    // --- calc_interval tests (radv.c:997-1011) ---

    fn ra_with(interval: u32, lifetime: i32) -> RaInterfaceParam {
        RaInterfaceParam { name: "eth0".to_string(), interval, lifetime, prio: 0, mtu: 0 }
    }

    #[test]
    fn calc_interval_none_defaults_to_600() {
        assert_eq!(calc_interval(None), 600);
    }

    #[test]
    fn calc_interval_zero_means_unset_defaults_to_600() {
        assert_eq!(calc_interval(Some(&ra_with(0, -1))), 600);
    }

    #[test]
    fn calc_interval_clamps_below_min_to_4() {
        assert_eq!(calc_interval(Some(&ra_with(2, -1))), 4);
    }

    #[test]
    fn calc_interval_clamps_above_max_to_1800() {
        assert_eq!(calc_interval(Some(&ra_with(5000, -1))), 1800);
    }

    #[test]
    fn calc_interval_boundary_4_passes_through() {
        assert_eq!(calc_interval(Some(&ra_with(4, -1))), 4);
    }

    #[test]
    fn calc_interval_boundary_1800_passes_through() {
        assert_eq!(calc_interval(Some(&ra_with(1800, -1))), 1800);
    }

    #[test]
    fn calc_interval_valid_value_passes_through() {
        assert_eq!(calc_interval(Some(&ra_with(250, -1))), 250);
    }

    // --- calc_lifetime tests (radv.c:1013-1029) ---

    #[test]
    fn calc_lifetime_none_defaults_to_3x_interval() {
        assert_eq!(calc_lifetime(None), 1800); // 3 * 600
    }

    #[test]
    fn calc_lifetime_unspecified_defaults_to_3x_interval() {
        // lifetime == -1 means "not specified"; interval is clamped first.
        assert_eq!(calc_lifetime(Some(&ra_with(100, -1))), 300); // 3 * 100
    }

    #[test]
    fn calc_lifetime_zero_means_no_default_route_and_is_preserved() {
        assert_eq!(calc_lifetime(Some(&ra_with(600, 0))), 0);
    }

    #[test]
    fn calc_lifetime_below_interval_is_raised_to_interval() {
        assert_eq!(calc_lifetime(Some(&ra_with(600, 2))), 600);
    }

    #[test]
    fn calc_lifetime_above_9000_is_clamped() {
        assert_eq!(calc_lifetime(Some(&ra_with(600, 20_000))), 9000);
    }

    #[test]
    fn calc_lifetime_boundary_9000_passes_through() {
        assert_eq!(calc_lifetime(Some(&ra_with(600, 9000))), 9000);
    }

    #[test]
    fn calc_lifetime_equal_to_interval_is_not_raised() {
        // lifetime < interval is false at equality, so it passes through unchanged.
        assert_eq!(calc_lifetime(Some(&ra_with(600, 600))), 600);
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

    // ── calc_prio ────────────────────────────────────────────────────────────

    fn make_ra_param(name: &str, prio: u32) -> RaInterfaceParam {
        RaInterfaceParam { name: name.to_string(), interval: 0, lifetime: -1, prio, mtu: 0 }
    }

    #[test]
    fn calc_prio_none_returns_zero() {
        assert_eq!(calc_prio(None), 0);
    }

    #[test]
    fn calc_prio_medium() {
        let p = make_ra_param("eth0", 0);
        assert_eq!(calc_prio(Some(&p)), 0);
    }

    #[test]
    fn calc_prio_high() {
        let p = make_ra_param("eth0", 1);
        assert_eq!(calc_prio(Some(&p)), 1);
    }

    #[test]
    fn calc_prio_low() {
        let p = make_ra_param("eth0", 2);
        assert_eq!(calc_prio(Some(&p)), 2);
    }

    // ── find_iface_param ─────────────────────────────────────────────────────

    #[test]
    fn find_iface_param_exact() {
        let params = vec![make_ra_param("eth0", 1)];
        assert!(find_iface_param(&params, "eth0").is_some());
    }

    #[test]
    fn find_iface_param_wildcard() {
        let params = vec![make_ra_param("eth*", 1)];
        assert!(find_iface_param(&params, "eth0").is_some());
        assert!(find_iface_param(&params, "eth1").is_some());
    }

    #[test]
    fn find_iface_param_no_match() {
        let params = vec![make_ra_param("eth0", 1)];
        assert!(find_iface_param(&params, "wlan0").is_none());
    }

    #[test]
    fn find_iface_param_empty_list() {
        assert!(find_iface_param(&[], "eth0").is_none());
    }

    #[test]
    fn find_iface_param_first_wins() {
        let params = vec![make_ra_param("eth*", 1), make_ra_param("eth0", 2)];
        let found = find_iface_param(&params, "eth0").unwrap();
        assert_eq!(found.prio, 1); // first match
    }

    // ── new_timeout ──────────────────────────────────────────────────────────

    #[test]
    fn new_timeout_short_period_min() {
        let d = new_timeout(Duration::from_secs(0), 600, 0);
        assert_eq!(d.as_secs(), 5);
    }

    #[test]
    fn new_timeout_short_period_max() {
        let d = new_timeout(Duration::from_secs(0), 600, 65535);
        assert!(d.as_secs() >= 19 && d.as_secs() <= 20);
    }

    #[test]
    fn new_timeout_short_period_mid() {
        let d = new_timeout(Duration::from_secs(30), 600, 32768);
        assert!(d.as_secs() >= 12 && d.as_secs() <= 13);
    }

    #[test]
    fn new_timeout_long_period_min() {
        let d = new_timeout(Duration::from_secs(120), 600, 0);
        assert_eq!(d.as_secs(), 450); // 3/4 * 600
    }

    #[test]
    fn new_timeout_long_period_max() {
        let d = new_timeout(Duration::from_secs(120), 600, 65535);
        assert!(d.as_secs() >= 599 && d.as_secs() <= 600);
    }

    #[test]
    fn new_timeout_default_interval() {
        // interval=0 should use default 600
        let d = new_timeout(Duration::from_secs(120), 0, 0);
        assert_eq!(d.as_secs(), 450);
    }

    #[test]
    fn new_timeout_boundary_at_60s() {
        // At exactly 59s → short period
        let d59 = new_timeout(Duration::from_secs(59), 600, 0);
        assert_eq!(d59.as_secs(), 5);
        // At 60s → long period
        let d60 = new_timeout(Duration::from_secs(60), 600, 0);
        assert_eq!(d60.as_secs(), 450);
    }

    // ── add_lla ──────────────────────────────────────────────────────────────

    #[test]
    fn add_lla_6byte_mac() {
        use crate::radv_protocol::ICMP6_OPT_SOURCE_MAC;
        let mut buf = Vec::new();
        add_lla(&mut buf, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(buf.len(), 8); // 2 + 6 = 8 (already aligned)
        assert_eq!(buf[0], ICMP6_OPT_SOURCE_MAC);
        assert_eq!(buf[1], 1); // 8/8 = 1
    }

    #[test]
    fn add_lla_8byte_mac() {
        let mut buf = Vec::new();
        add_lla(&mut buf, &[0; 8]);
        assert_eq!(buf.len(), 16); // 2 + 8 = 10, padded to 16
        assert_eq!(buf[1], 2); // 16/8 = 2
    }

    #[test]
    fn add_lla_mac_bytes_preserved() {
        let mut buf = Vec::new();
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        add_lla(&mut buf, &mac);
        assert_eq!(&buf[2..8], &mac);
    }

    #[test]
    fn add_lla_padding_is_zero() {
        let mut buf = Vec::new();
        add_lla(&mut buf, &[0xFF; 5]); // 2+5=7, padded to 8
        assert_eq!(buf.len(), 8);
        assert_eq!(buf[7], 0); // padding byte
    }

    #[test]
    fn add_lla_appends_to_existing() {
        use crate::radv_protocol::ICMP6_OPT_SOURCE_MAC;
        let mut buf = vec![0xDE, 0xAD];
        add_lla(&mut buf, &[0; 6]);
        assert_eq!(buf[0], 0xDE);
        assert_eq!(buf[1], 0xAD);
        assert_eq!(buf[2], ICMP6_OPT_SOURCE_MAC);
    }
}

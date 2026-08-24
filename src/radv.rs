//! IPv6 Router Advertisement builder, prefix construction, and scheduling.
//! Ported from `radv.c`.
//!
//! The raw ICMPv6 socket (`ra_init`/`icmp6_packet`/`send_ra_alias`'s `sendto`)
//! lives in `dnsmasq.rs`'s `RadvTransport`, mirroring the split already used
//! for DHCPv4's ICMP conflict probe (`crate::dhcp::AddressProbe` /
//! `dnsmasq::IcmpPinger`): this module holds every byte-pushing and
//! state-scheduling decision as plain, socket-free Rust so it can be tested
//! without `CAP_NET_RAW`; the transport just moves bytes.

#[cfg(feature = "dhcp6")]
use std::net::Ipv6Addr;
#[cfg(feature = "dhcp6")]
use crate::radv_protocol::{ICMP6_OPT_PREFIX, ICMP6_OPT_RDNSS, ICMP6_OPT_MTU, ICMP6_OPT_ADV_INTERVAL};
#[cfg(feature = "dhcp6")]
use crate::types::dhcp::{
    DhcpContext, RaInterface, CONTEXT_TEMPLATE, CONTEXT_OLD, CONTEXT_RA, CONTEXT_DHCP,
    CONTEXT_RA_STATELESS, CONTEXT_RA_ROUTER, CONTEXT_SETLEASE, CONTEXT_DEPRECATE,
    CONTEXT_CONSTRUCTED, CONTEXT_RA_DONE, CONTEXT_RA_OFF_LINK,
};
#[cfg(feature = "dhcp6")]
use crate::types::daemon::DhcpBridge;
#[cfg(feature = "dhcp6")]
use crate::types::network::{Iname, IfaceNameFlags};
#[cfg(feature = "dhcp6")]
use crate::dhcp6::{LiveAddr6, is_same_net6};
#[cfg(feature = "dhcp6")]
use crate::util::{addr6part, setaddr6part, wildcard_match, wildcard_matchn};

// ICMPv6 type 134 = Router Advertisement
#[cfg(feature = "dhcp6")]
const ICMPV6_RA: u8 = 134;

// RA flags
#[cfg(feature = "dhcp6")]
const RA_FLAG_MANAGED: u8 = 0x80;
#[cfg(feature = "dhcp6")]
const RA_FLAG_OTHER:   u8 = 0x40;
/// Preference bits (RFC 4191 §2.2), bits 3-4 of the flags byte: `0x18` = low,
/// `0x08` = high, `0x00` = medium. Stored verbatim in `RaInterface.prio`
/// (`option.c`'s `LOPT_RA_PARAM` handler assigns exactly these byte values),
/// so `calc_prio()` is a pure passthrough — see radv.c:1031-1037/292.
#[cfg(feature = "dhcp6")]
const RA_FLAG_PRIO_MASK: u8 = 0x18;

// Prefix Information option flags
#[cfg(feature = "dhcp6")]
const PREFIX_FLAG_ONLINK:     u8 = 0x80;
#[cfg(feature = "dhcp6")]
const PREFIX_FLAG_AUTONOMOUS: u8 = 0x40;
/// "Router Address" bit (RFC 3775 §7.2), set when the prefix option actually
/// carries a router's on-link address rather than an advertised prefix.
#[cfg(feature = "dhcp6")]
const PREFIX_FLAG_ROUTER: u8 = 0x20;

/// One prefix advertised in a Router Advertisement.
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaPrefix {
    pub prefix:       Ipv6Addr,
    pub prefix_len:   u8,
    pub on_link:      bool,
    pub autonomous:   bool,
    /// RFC 3775 §7.2 "Router Address" bit — set when `context->flags &
    /// CONTEXT_RA_ROUTER` (radv.c:649-654).
    pub router:       bool,
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
    /// Raw preference bits (`0x00`/`0x08`/`0x18`) from `calc_prio()`.
    pub prio:        u8,
    /// Router lifetime in seconds (0 = not a default router).
    pub router_lt:   u16,
    pub prefixes:    Vec<RaPrefix>,
    /// RDNSS addresses; empty means no RDNSS option is emitted.
    pub dns_servers: Vec<Ipv6Addr>,
    pub rdnss_lifetime: u32,
    /// Advertisement Interval option value in milliseconds, emitted only
    /// when `Some` (radv.c:416-423 — only sent when advertising a router
    /// address rather than a prefix).
    pub adv_interval_ms: Option<u32>,
    /// MTU option value; `Some(0)` and `None` both omit the option upstream
    /// (`if (mtu > 0)`, radv.c:444), so callers should only set `Some(m)`
    /// for `m > 0`.
    pub mtu: Option<u32>,
    /// Source Link-Layer Address option payload (raw MAC bytes), if known.
    pub source_lla: Option<Vec<u8>>,
}

#[cfg(feature = "dhcp6")]
impl Default for RouterAdvertisement {
    fn default() -> Self {
        Self {
            hop_limit: 64,
            managed: false,
            other: false,
            prio: 0,
            router_lt: 0,
            prefixes: Vec::new(),
            dns_servers: Vec::new(),
            rdnss_lifetime: 0,
            adv_interval_ms: None,
            mtu: None,
            source_lla: None,
        }
    }
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
/// The checksum is left zero: for `IPPROTO_ICMPV6` raw sockets, the Linux
/// kernel always computes and fills in the ICMPv6 checksum on send
/// (RFC 3542 §3.1), so userspace never needs to compute the pseudo-header
/// checksum itself — this is why upstream's `send_ra_alias` never touches
/// `ra->checksum` either.
#[cfg(feature = "dhcp6")]
pub fn build_ra(ra: &RouterAdvertisement) -> Vec<u8> {
    let mut buf = Vec::new();

    // Fixed header (16 bytes)
    buf.push(ICMPV6_RA);               // type
    buf.push(0u8);                     // code
    buf.extend_from_slice(&0u16.to_be_bytes()); // checksum (kernel fills in)
    buf.push(ra.hop_limit);
    let mut flags = ra.prio & RA_FLAG_PRIO_MASK;
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
        if pfx.router     { pflags |= PREFIX_FLAG_ROUTER; }
        buf.push(pflags);
        buf.extend_from_slice(&pfx.valid_lt.to_be_bytes());
        buf.extend_from_slice(&pfx.preferred_lt.to_be_bytes());
        buf.extend_from_slice(&0u32.to_be_bytes()); // reserved
        buf.extend_from_slice(&pfx.prefix.octets());
    }

    // Advertisement Interval option (type 7) — radv.c:416-423
    if let Some(ms) = ra.adv_interval_ms {
        buf.push(ICMP6_OPT_ADV_INTERVAL);
        buf.push(1u8);
        buf.extend_from_slice(&0u16.to_be_bytes()); // reserved
        buf.extend_from_slice(&ms.to_be_bytes());
    }

    // MTU option (type 5) — radv.c:444-450
    if let Some(mtu) = ra.mtu {
        if mtu > 0 {
            buf.push(ICMP6_OPT_MTU);
            buf.push(1u8);
            buf.extend_from_slice(&0u16.to_be_bytes()); // reserved
            buf.extend_from_slice(&mtu.to_be_bytes());
        }
    }

    // Source Link-Layer Address option (type 1) — radv.c:452, 766-787
    if let Some(mac) = &ra.source_lla {
        add_lla(&mut buf, mac);
    }

    // RDNSS option (type 25) — only emitted when there are DNS servers
    if !ra.dns_servers.is_empty() {
        // length = 1 (header) + 1 (reserved/lifetime) + N*2 units of 8 bytes
        let opt_len = 1u8 + 2 * ra.dns_servers.len() as u8;
        buf.push(ICMP6_OPT_RDNSS);
        buf.push(opt_len);
        buf.extend_from_slice(&0u16.to_be_bytes()); // reserved
        buf.extend_from_slice(&ra.rdnss_lifetime.to_be_bytes());
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
    let prio      = flags & RA_FLAG_PRIO_MASK;
    let router_lt = u16::from_be_bytes([data[6], data[7]]);
    // bytes 8..11 = reachable time, 12..15 = retrans time — not stored

    let mut prefixes       = Vec::new();
    let mut dns_servers    = Vec::new();
    let mut rdnss_lifetime = 0u32;
    let mut adv_interval_ms = None;
    let mut mtu             = None;
    let mut source_lla      = None;

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
                    on_link:      (pflags & PREFIX_FLAG_ONLINK)     != 0,
                    autonomous:   (pflags & PREFIX_FLAG_AUTONOMOUS) != 0,
                    router:       (pflags & PREFIX_FLAG_ROUTER)     != 0,
                    valid_lt,
                    preferred_lt,
                });
            }
            t if t == ICMP6_OPT_RDNSS => {
                // RDNSS: reserved(2) lifetime(4) addresses(16*N)
                if opt_data.len() < 6 {
                    return Err(RadvError::TooShort);
                }
                rdnss_lifetime = u32::from_be_bytes([opt_data[2], opt_data[3], opt_data[4], opt_data[5]]);
                let mut i = 6usize; // skip reserved(2) + lifetime(4)
                while i + 16 <= opt_data.len() {
                    let addr_bytes: [u8; 16] = opt_data[i..i + 16].try_into().unwrap();
                    dns_servers.push(Ipv6Addr::from(addr_bytes));
                    i += 16;
                }
            }
            t if t == ICMP6_OPT_ADV_INTERVAL => {
                if opt_data.len() >= 6 {
                    adv_interval_ms = Some(u32::from_be_bytes([opt_data[2], opt_data[3], opt_data[4], opt_data[5]]));
                }
            }
            t if t == ICMP6_OPT_MTU => {
                if opt_data.len() >= 6 {
                    mtu = Some(u32::from_be_bytes([opt_data[2], opt_data[3], opt_data[4], opt_data[5]]));
                }
            }
            t if t == crate::radv_protocol::ICMP6_OPT_SOURCE_MAC => {
                source_lla = Some(opt_data.to_vec());
            }
            _ => {} // ignore unknown options
        }

        pos += opt_len;
    }

    Ok(RouterAdvertisement {
        hop_limit, managed, other, prio, router_lt, prefixes, dns_servers,
        rdnss_lifetime, adv_interval_ms, mtu, source_lla,
    })
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
pub fn calc_interval(ra: Option<&RaInterface>) -> u32 {
    match ra.map(|p| p.interval).filter(|&i| i != 0) {
        Some(i) => i.clamp(4, 1800) as u32,
        None => 600,
    }
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
pub fn calc_lifetime(ra: Option<&RaInterface>) -> u32 {
    let interval = calc_interval(ra) as i32;

    let lifetime = match ra {
        Some(p) if p.lifetime != -1 => {
            let mut lifetime = p.lifetime;
            if lifetime < interval && lifetime != 0 {
                lifetime = interval;
            } else if lifetime > 9000 {
                lifetime = 9000;
            }
            lifetime
        }
        _ => 3 * interval,
    };

    lifetime as u32
}

/// Extract the raw preference byte from RA interface config (`0x00`/`0x08`/
/// `0x18`), a pure passthrough since `--ra-param`'s `high`/`low` parsing
/// already stores the final flag value in `RaInterface.prio`.
///
/// Port of `calc_prio()` from radv.c:1031-1037.
#[cfg(feature = "dhcp6")]
pub fn calc_prio(ra: Option<&RaInterface>) -> u32 {
    match ra {
        Some(p) => p.prio as u32,
        None => 0, // medium
    }
}

/// Find RA interface config matching an interface name (with wildcard support).
///
/// Port of `find_iface_param()` from radv.c:986-995.
#[cfg(feature = "dhcp6")]
pub fn find_iface_param<'a>(
    ra_interfaces: &'a [RaInterface],
    iface: &str,
) -> Option<&'a RaInterface> {
    ra_interfaces.iter().find(|p| wildcard_match(&p.name, iface))
}

/// Calculate the next RA transmission timeout with jitter.
///
/// During the "short period" (first 60 seconds), uses 5-20 second range.
/// After that, uses 3/4 to 1× `adv_interval`.
/// `rand_val` provides randomness (0-65535) for jitter.
/// Port of `new_timeout()` from radv.c:973-984.
#[cfg(feature = "dhcp6")]
pub fn new_timeout(
    elapsed_since_start: std::time::Duration,
    adv_interval: u32,
    rand_val: u16,
) -> std::time::Duration {
    use std::time::Duration;
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

/// Reschedule `context->ra_time` per `new_timeout()` (radv.c:973-984),
/// operating directly on the context's own `ra_time`/`ra_short_period_start`
/// fields rather than returning a bare `Duration`.
#[cfg(feature = "dhcp6")]
pub fn new_timeout_context(context: &mut DhcpContext, adv_interval: u32, now: u64, rand_val: u16) {
    let elapsed = std::time::Duration::from_secs(now.saturating_sub(context.ra_short_period_start));
    context.ra_time = now + new_timeout(elapsed, adv_interval, rand_val).as_secs();
}

// ─────────────────────────────────────────────────────────────────────────────
// Unsolicited RA start-up scheduling (radv.c:118-139)
// ─────────────────────────────────────────────────────────────────────────────

/// Seed `ra_time` on every non-template DHCPv6 context so `periodic_ra` sends
/// an unsolicited RA for each of them soon after startup (or after a
/// netlink route-change re-triggers this).
///
/// `rand16` supplies one `0..65535` value per context, matching upstream's
/// per-context `rand16()` call — range 0-5s (radv.c:135).
///
/// Port of `ra_start_unsolicited(now, NULL)` from radv.c:131-138.
#[cfg(feature = "dhcp6")]
pub fn ra_start_unsolicited_all(contexts: &mut [DhcpContext], now: u64, mut rand16: impl FnMut() -> u16) {
    for context in contexts.iter_mut() {
        if context.flags & CONTEXT_TEMPLATE != 0 {
            continue;
        }
        context.ra_time = now + (rand16() as u64) / 13000; // range 0 - 5
        context.ra_short_period_start = now;
    }
}

/// Seed `ra_time` on one specific (newly-added) context, one second out so
/// startup logging order stays sane.
///
/// Port of `ra_start_unsolicited(now, context)` from radv.c:125-130.
#[cfg(feature = "dhcp6")]
pub fn ra_start_unsolicited_one(context: &mut DhcpContext, now: u64) {
    context.ra_short_period_start = now;
    context.ra_time = now + 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Prefix construction from live interface addresses (radv.c:586-764)
// ─────────────────────────────────────────────────────────────────────────────

/// Per-transmission accumulator mirroring C's `struct ra_param` (radv.c:29-37).
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone)]
pub struct RaParam {
    pub managed: bool,
    pub other: bool,
    pub first: bool,
    pub adv_router: bool,
    pub found_context: bool,
    pub link_local:  Ipv6Addr,
    pub link_global: Ipv6Addr,
    pub ula:         Ipv6Addr,
    pub glob_pref_time: u32,
    pub link_pref_time: u32,
    pub ula_pref_time:  u32,
    pub adv_interval: u32,
    pub prio: u32,
}

#[cfg(feature = "dhcp6")]
impl Default for RaParam {
    fn default() -> Self {
        Self {
            managed: false,
            other: false,
            first: true,
            adv_router: false,
            found_context: false,
            link_local:  Ipv6Addr::UNSPECIFIED,
            link_global: Ipv6Addr::UNSPECIFIED,
            ula:         Ipv6Addr::UNSPECIFIED,
            glob_pref_time: 0,
            link_pref_time: 0,
            ula_pref_time:  0,
            adv_interval: 600,
            prio: 0,
        }
    }
}

/// Zero the host part of `addr` below `prefix_len` bits, matching upstream's
/// `setaddr6part(local, addr6part(local) & ~mask)` (radv.c:357,739). Only
/// meaningful for `prefix_len` in `64..=128`, same as upstream.
#[cfg(feature = "dhcp6")]
fn zero_host_part(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    let part = addr6part(&addr);
    let mask: u64 = if prefix_len >= 128 {
        0
    } else if prefix_len <= 64 {
        u64::MAX
    } else {
        (1u64 << (128 - prefix_len as u32)) - 1
    };
    setaddr6part(&addr, part & !mask)
}

/// Process one live address against every DHCPv6 context for `add_prefixes`
/// (radv.c:586-764): updates `param`'s best-link-local/ULA/global selection,
/// marks matching contexts (`saved_valid`, `CONTEXT_RA_DONE`, `ra_time`
/// resets for repeats), and returns the prefix option to advertise for this
/// address, if any.
///
/// `target_if_index` is the interface the RA is being built for; addresses
/// on other interfaces are ignored, same as upstream's `if_index ==
/// param->ind` guard.
#[cfg(feature = "dhcp6")]
pub fn add_prefix_for_addr(
    addr: &LiveAddr6,
    target_if_index: u32,
    param: &mut RaParam,
    contexts: &mut [DhcpContext],
    opt_ra: bool,
) -> Option<RaPrefix> {
    if addr.if_index != target_if_index {
        return None;
    }

    if crate::network::is_link_local_v6(addr.addr) {
        if addr.preferred > param.link_pref_time {
            param.link_pref_time = addr.preferred;
            param.link_local = addr.addr;
        }
        return None;
    }

    if addr.addr.is_loopback() || addr.addr.is_multicast() {
        return None;
    }

    let mut real_prefix: u8 = 0;
    let mut do_slaac = false;
    let mut deprecate = false;
    let mut constructed = false;
    let mut adv_router = false;
    let mut off_link = false;
    let mut time: u32 = u32::MAX;

    for context in contexts.iter_mut() {
        if context.flags & (CONTEXT_TEMPLATE | CONTEXT_OLD) != 0 {
            continue;
        }
        if addr.prefix > context.prefix {
            continue;
        }
        if !is_same_net6(&addr.addr, &context.start6, context.prefix)
            || !is_same_net6(&addr.addr, &context.end6, context.prefix)
        {
            continue;
        }

        context.saved_valid = addr.valid;

        if context.flags & CONTEXT_RA != 0 {
            do_slaac = true;
            if context.flags & CONTEXT_DHCP != 0 {
                param.other = true;
                if context.flags & CONTEXT_RA_STATELESS == 0 {
                    param.managed = true;
                }
            }
        } else {
            if !opt_ra {
                continue;
            }
            param.managed = true;
            param.other = true;
        }

        if context.flags & CONTEXT_RA_ROUTER != 0 {
            adv_router = true;
            param.adv_router = true;
            real_prefix = context.prefix as u8;
        }

        if context.flags & CONTEXT_SETLEASE != 0 && time > context.lease_time {
            time = context.lease_time;
            let floor = 3 * param.adv_interval;
            if time < floor {
                time = floor;
            }
        }

        if context.flags & CONTEXT_DEPRECATE != 0 {
            deprecate = true;
        }
        if context.flags & CONTEXT_CONSTRUCTED != 0 {
            constructed = true;
        }

        if context.flags & CONTEXT_RA_DONE == 0 {
            if !param.first {
                context.ra_time = 0;
            }
            context.flags |= CONTEXT_RA_DONE;
            real_prefix = context.prefix as u8;
            off_link = context.flags & CONTEXT_RA_OFF_LINK != 0;
        }

        param.first = false;
        param.found_context = true;
    }

    let mut valid = addr.valid;
    if !constructed || valid > time {
        valid = time;
    }

    let mut preferred = if addr.deprecated { 0 } else { addr.preferred };
    if deprecate {
        time = 0;
    }
    if !constructed || preferred > time {
        preferred = time;
    }

    if crate::network::is_ula_v6(addr.addr) {
        if preferred > param.ula_pref_time {
            param.ula_pref_time = preferred;
            param.ula = addr.addr;
        }
    } else if preferred > param.glob_pref_time {
        param.glob_pref_time = preferred;
        param.link_global = addr.addr;
    }

    if real_prefix == 0 {
        return None;
    }

    let prefix_addr = if adv_router {
        addr.addr
    } else {
        zero_host_part(addr.addr, real_prefix)
    };

    Some(RaPrefix {
        prefix: prefix_addr,
        prefix_len: real_prefix,
        on_link: !off_link,
        autonomous: do_slaac,
        router: adv_router,
        valid_lt: valid,
        preferred_lt: preferred,
    })
}

/// Parameters describing which interface an RA is being built for and the
/// pieces of state that need a real socket/kernel lookup to resolve — kept
/// separate from the pure prefix/context logic in [`build_ra_for_interface`].
#[cfg(feature = "dhcp6")]
pub struct RaBuildParams<'a> {
    pub now: u64,
    pub if_index: u32,
    pub iface_name: &'a str,
    pub opt_ra: bool,
    pub is_dns_server: bool,
    pub hop_limit: u8,
    /// Resolved MTU to advertise, already applying the `--ra-param`
    /// `mtu:<value>|off` override and any `/proc` fallback lookup (both are
    /// I/O, so they happen in the transport layer, not here).
    pub mtu: Option<u32>,
    pub mac: Option<Vec<u8>>,
}

/// Build the Router Advertisement content for one interface: selects the
/// link-local/ULA/global source addresses, advertises live prefixes plus any
/// still-draining `CONTEXT_OLD` ones, and fills in the RDNSS/Advertisement
/// Interval/MTU/Source-LLA options.
///
/// Returns `None` when there is nothing to advertise (radv.c:311-312's "no
/// link-local address" bail-out, or 411-412's "no prefixes at all").
///
/// Port of `send_ra_alias()`'s content-building half (radv.c:257-536) minus
/// the actual `sendto` and `--dhcp-option6`-driven RDNSS/DNSSL substitution
/// (tracked as a gap in `tasks.md`).
#[cfg(feature = "dhcp6")]
pub fn build_ra_for_interface(
    params: &RaBuildParams,
    live_addrs: &[LiveAddr6],
    contexts: &mut Vec<DhcpContext>,
    ra_interfaces: &[RaInterface],
) -> Option<RouterAdvertisement> {
    let iface_cfg = find_iface_param(ra_interfaces, params.iface_name);
    let mut param = RaParam {
        adv_interval: calc_interval(iface_cfg),
        prio: calc_prio(iface_cfg),
        ..Default::default()
    };

    for c in contexts.iter_mut() {
        c.flags &= !CONTEXT_RA_DONE;
    }

    let mut prefixes = Vec::new();
    for addr in live_addrs {
        if let Some(p) = add_prefix_for_addr(addr, params.if_index, &mut param, contexts, params.opt_ra) {
            prefixes.push(p);
        }
    }

    if param.link_pref_time == 0 {
        // RFC 4861 §6.1.2: the RA's source address must be link-local.
        return None;
    }

    let mut min_pref_time = u32::MAX;
    if param.glob_pref_time != 0 && param.glob_pref_time < min_pref_time {
        min_pref_time = param.glob_pref_time;
    }
    if param.ula_pref_time != 0 && param.ula_pref_time < min_pref_time {
        min_pref_time = param.ula_pref_time;
    }
    if param.link_pref_time != 0 && param.link_pref_time < min_pref_time {
        min_pref_time = param.link_pref_time;
    }

    // Old (removed) addresses whose context is still draining its valid
    // lifetime (radv.c:326-404): keep advertising them, deprecated, until
    // they age out past `saved_valid`.
    let mut old_prefix = false;
    let mut kept = Vec::with_capacity(contexts.len());
    for context in contexts.drain(..) {
        if context.if_index as u32 == params.if_index && context.flags & CONTEXT_OLD != 0 {
            let old = (params.now.saturating_sub(context.address_lost_time)) as u32;
            if old > context.saved_valid {
                // Advertised enough; drop it.
                continue;
            }
            old_prefix = true;
            let do_slaac = context.flags & CONTEXT_RA != 0;
            if do_slaac {
                if context.flags & CONTEXT_DHCP != 0 {
                    param.other = true;
                    if context.flags & CONTEXT_RA_STATELESS == 0 {
                        param.managed = true;
                    }
                }
            } else if params.opt_ra {
                param.managed = true;
                param.other = true;
            }
            let off_link = context.flags & CONTEXT_RA_OFF_LINK != 0;
            let local = zero_host_part(context.start6, context.prefix as u8);
            prefixes.push(RaPrefix {
                prefix: local,
                prefix_len: context.prefix as u8,
                on_link: !off_link,
                autonomous: do_slaac,
                router: false,
                valid_lt: context.saved_valid.saturating_sub(old),
                preferred_lt: 0,
            });
            kept.push(context);
        } else {
            kept.push(context);
        }
    }
    *contexts = kept;

    if !old_prefix && !param.found_context {
        return None;
    }
    let router_lt = if old_prefix && !param.found_context {
        0
    } else {
        calc_lifetime(iface_cfg) as u16
    };

    let adv_interval_ms = if param.adv_router {
        Some(1000 * calc_interval(find_iface_param(ra_interfaces, params.iface_name)))
    } else {
        None
    };

    // Default RDNSS fallback: advertise ourselves when we're the DNS server
    // and no `--dhcp-option6=option6:dns-server` substitution applies
    // (radv.c:527-535). Tag-filtered dhcp_opts6 RDNSS/DNSSL substitution
    // (radv.c:454-525) is not yet ported — see tasks.md.
    let mut dns_servers = Vec::new();
    let mut rdnss_lifetime = 0;
    if params.is_dns_server && param.link_pref_time != 0 {
        dns_servers.push(param.link_local);
        rdnss_lifetime = min_pref_time;
    }

    Some(RouterAdvertisement {
        hop_limit: params.hop_limit,
        managed: param.managed,
        other: param.other,
        prio: param.prio as u8,
        router_lt,
        prefixes,
        dns_servers,
        rdnss_lifetime,
        adv_interval_ms,
        mtu: params.mtu,
        source_lla: params.mac.clone(),
    })
}

// ─────────────────────────────────────────────────────────────────────────────
// Router Solicitation parsing (radv.c:141-255)
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the Source Link-Layer Address option from a Router Solicitation
/// payload, if present, for logging (radv.c:210-223). `data` is the ICMPv6
/// payload starting at the RS's type byte; the fixed RS header is 8 bytes
/// (type, code, checksum, 4 reserved), so options start at offset 8.
///
/// Returns `Err(MalformedRsOption)` on a malformed option
/// (`opt_sz == 0 || opt_sz > rem`), matching upstream's "bad packet" early
/// return.
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedRsOption;

#[cfg(feature = "dhcp6")]
pub fn parse_rs_source_mac(data: &[u8]) -> Result<Option<Vec<u8>>, MalformedRsOption> {
    if data.len() < 8 {
        return Ok(None);
    }
    let mut mac = None;
    let mut rem = data.len() - 8;
    let mut pos = 8;
    while rem >= 2 {
        let opt_sz = (data[pos + 1] as usize) * 8;
        if opt_sz == 0 || opt_sz > rem {
            return Err(MalformedRsOption);
        }
        if data[pos] == crate::radv_protocol::ICMP6_OPT_SOURCE_MAC {
            mac = Some(data[pos + 2..pos + opt_sz].to_vec());
        }
        pos += opt_sz;
        rem -= opt_sz;
    }
    Ok(mac)
}

/// `ND_ROUTER_SOLICIT` = 133, the ICMPv6 type `icmp6_packet` dispatches to
/// [`parse_rs_source_mac`]/`send_ra`.
#[cfg(feature = "dhcp6")]
pub const ND_ROUTER_SOLICIT: u8 = 133;

/// `ICMP6_ECHO_REPLY` = 129, dispatched to `lease_ping_reply` upstream
/// (radv.c:196-197) for SLAAC address-guessing probes.
#[cfg(feature = "dhcp6")]
pub const ICMP6_ECHO_REPLY: u8 = 129;

// ─────────────────────────────────────────────────────────────────────────────
// Bridge-interface aliasing (radv.c:228-247, 899-919)
// ─────────────────────────────────────────────────────────────────────────────

/// Whether `dhcp_except` (`--no-dhcp-interface`) blocks RA on `iface_name`.
///
/// Port of the `INAME_6`-flagged loop shared by `icmp6_packet` (radv.c:188-191)
/// and `iface_search` (radv.c:938-941).
#[cfg(feature = "dhcp6")]
pub fn blocked_by_dhcp_except(iface_name: &str, dhcp_except: &[Iname]) -> bool {
    dhcp_except.iter().any(|e| {
        e.flags.contains(IfaceNameFlags::V6)
            && e.name.as_deref().is_some_and(|n| wildcard_match(n, iface_name))
    })
}

/// Find the `--bridge-interface` whose alias list matches the RS's arrival
/// interface, so the RA gets built from the bridge's own interface context
/// instead (radv.c:231-247).
#[cfg(feature = "dhcp6")]
pub fn find_bridge_for_alias<'a>(bridges: &'a [DhcpBridge], arrival_iface: &str) -> Option<&'a DhcpBridge> {
    bridges.iter().find(|b| {
        b.aliases.iter().any(|a| wildcard_matchn(a, arrival_iface, libc_if_namesize()))
    })
}

/// Live interfaces (name + index) whose name matches one of `bridge`'s alias
/// patterns — the set `periodic_ra` also sends an RA on for every unsolicited
/// advertisement of `bridge`'s own interface (radv.c:846-892's
/// `send_ra_to_aliases`).
#[cfg(feature = "dhcp6")]
pub fn bridge_alias_targets<'a>(bridge: &DhcpBridge, live_ifaces: &'a [(String, u32)]) -> Vec<&'a (String, u32)> {
    live_ifaces
        .iter()
        .filter(|(name, _)| bridge.aliases.iter().any(|a| wildcard_matchn(a, name, libc_if_namesize())))
        .collect()
}

/// `IFNAMSIZ` — matches upstream's `wildcard_matchn(alias->iface, interface,
/// IF_NAMESIZE)` / `IFNAMSIZ` truncation length.
#[cfg(feature = "dhcp6")]
fn libc_if_namesize() -> usize {
    #[cfg(unix)]
    { libc::IF_NAMESIZE }
    #[cfg(not(unix))]
    { 16 }
}

// ─────────────────────────────────────────────────────────────────────────────
// Periodic RA timer scan (radv.c:789-971)
// ─────────────────────────────────────────────────────────────────────────────

/// A live interface, as `periodic_ra`'s `iface_enumerate(AF_INET6, ...,
/// iface_search)` callback would see it.
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone)]
pub struct LiveIface6 {
    pub if_index: u32,
    pub name: String,
    pub addr: Ipv6Addr,
    pub prefix: i32,
    /// `IFACE_TENTATIVE` — address still doing DAD (radv.c:954).
    pub tentative: bool,
}

/// An interface `periodic_ra` decided to actually send an RA on.
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RaSendTarget {
    pub if_index: u32,
    pub name: String,
}

/// Scan every DHCPv6 context for an overdue `ra_time`, resolve which live
/// interface should carry the RA, reschedule via [`new_timeout_context`], and
/// return the interfaces to actually send on plus the next wakeup time.
///
/// `resolve_stale_name` stands in for `indextoname(daemon->icmp6fd, ...)` —
/// the one part of the `CONTEXT_OLD` branch (radv.c:816-825) that needs a
/// live kernel lookup rather than the `live_ifaces` snapshot, since a
/// `CONTEXT_OLD` context's address has already vanished from that snapshot.
///
/// `iface_allowed` is the `--interface`/`--except-interface`/`--listen-address`
/// gate, ported as `crate::network::iface_check_name` and applied here exactly
/// where upstream applies it: once inside the `iface_search` candidate scan
/// (radv.c:934-935, so a disallowed interface is skipped in favour of another
/// live candidate on the same subnet) and again, uniformly, on whichever
/// interface name was found — including the `CONTEXT_OLD` branch, which has
/// no candidate scan of its own — right before upstream's `send_ra`
/// (radv.c:833-834). `dhcp_except` (`--no-dhcp-interface`, `INAME_6`) is
/// applied at the same two points, mirroring radv.c:938-941 and :836-839.
///
/// Port of `periodic_ra()`/`iface_search()`/`new_timeout()` (radv.c:789-984).
///
/// Mirrors upstream's parameter list (per-context state, live interfaces,
/// the `--ra-param`/`--no-dhcp-interface` config, and the RNG/name-resolver
/// hooks tests substitute) rather than collapsing it into a config struct.
#[cfg(feature = "dhcp6")]
#[allow(clippy::too_many_arguments)]
pub fn periodic_ra(
    now: u64,
    contexts: &mut [DhcpContext],
    live_ifaces: &[LiveIface6],
    ra_interfaces: &[RaInterface],
    dhcp_except: &[Iname],
    mut rand16: impl FnMut() -> u16,
    resolve_stale_name: impl Fn(u32) -> Option<String>,
    iface_allowed: impl Fn(&str) -> bool,
) -> (Vec<RaSendTarget>, Option<u64>) {
    let mut targets = Vec::new();

    loop {
        let mut overdue_idx = None;
        let mut next_event: Option<u64> = None;
        for (i, ctx) in contexts.iter().enumerate() {
            if ctx.ra_time == 0 {
                continue;
            }
            if ctx.ra_time <= now {
                overdue_idx = Some(i);
                break;
            }
            next_event = Some(match next_event {
                Some(n) if n <= ctx.ra_time => n,
                _ => ctx.ra_time,
            });
        }

        let Some(idx) = overdue_idx else {
            return (targets, next_event);
        };

        let mut target: Option<RaSendTarget> = None;

        if contexts[idx].flags & CONTEXT_OLD != 0 && contexts[idx].if_index != 0 {
            let if_index = contexts[idx].if_index as u32;
            if let Some(name) = resolve_stale_name(if_index) {
                let adv_interval = calc_interval(find_iface_param(ra_interfaces, &name));
                new_timeout_context(&mut contexts[idx], adv_interval, now, rand16());
                target = Some(RaSendTarget { if_index, name });
            } else {
                // Can't resolve the interface at all; give up on this timer.
                contexts[idx].ra_time = 0;
            }
        } else {
            let prefix = contexts[idx].prefix;
            let (s6, e6) = (contexts[idx].start6, contexts[idx].end6);
            let mut found = false;

            for iface in live_ifaces {
                if !iface_allowed(&iface.name) || blocked_by_dhcp_except(&iface.name, dhcp_except) {
                    continue;
                }
                if iface.prefix > prefix
                    || !is_same_net6(&iface.addr, &s6, prefix)
                    || !is_same_net6(&iface.addr, &e6, prefix)
                {
                    continue;
                }

                if !iface.tentative {
                    target = Some(RaSendTarget { if_index: iface.if_index, name: iface.name.clone() });
                }

                let adv_interval = calc_interval(find_iface_param(ra_interfaces, &iface.name));
                new_timeout_context(&mut contexts[idx], adv_interval, now, rand16());

                for (j, other) in contexts.iter_mut().enumerate() {
                    if j == idx {
                        continue;
                    }
                    if iface.prefix <= other.prefix
                        && is_same_net6(&iface.addr, &other.start6, other.prefix)
                        && is_same_net6(&iface.addr, &other.end6, other.prefix)
                    {
                        other.ra_time = 0;
                    }
                }

                found = true;
                break;
            }

            if !found {
                contexts[idx].ra_time = 0;
            }
        }

        // radv.c:833-834's `iface_check`/`dhcp_except` re-check, applied
        // uniformly to whichever branch found `target` — the only gate the
        // `CONTEXT_OLD` branch gets, since it has no candidate scan of its own.
        if let Some(t) = target {
            if iface_allowed(&t.name) && !blocked_by_dhcp_except(&t.name, dhcp_except) {
                targets.push(t);
            }
        }
    }
}

#[cfg(all(test, feature = "dhcp6"))]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use crate::types::dhcp::{DhcpNetid, CONTEXT_DHCP, CONTEXT_RA};

    fn sample_ra() -> RouterAdvertisement {
        RouterAdvertisement {
            hop_limit: 64,
            managed:   false,
            other:     true,
            prio: 0,
            router_lt: 1800,
            prefixes:  vec![RaPrefix {
                prefix:       Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0),
                prefix_len:   64,
                on_link:      true,
                autonomous:   true,
                router:       false,
                valid_lt:     86400,
                preferred_lt: 14400,
            }],
            dns_servers: vec![Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)],
            rdnss_lifetime: 3600,
            adv_interval_ms: None,
            mtu: None,
            source_lla: None,
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
            router:       false,
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
    fn router_flag_bit_roundtrips() {
        let mut ra = sample_ra();
        ra.prefixes[0].router = true;
        let buf = build_ra(&ra);
        let parsed = parse_ra(&buf).unwrap();
        assert!(parsed.prefixes[0].router);
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

    #[test]
    fn prio_bits_roundtrip() {
        let mut ra = sample_ra();
        ra.prio = 0x18; // low
        let buf = build_ra(&ra);
        assert_eq!(buf[5] & 0x18, 0x18);
        let parsed = parse_ra(&buf).unwrap();
        assert_eq!(parsed.prio, 0x18);
    }

    #[test]
    fn adv_interval_option_roundtrips() {
        let mut ra = sample_ra();
        ra.adv_interval_ms = Some(60_000);
        let buf = build_ra(&ra);
        let parsed = parse_ra(&buf).unwrap();
        assert_eq!(parsed.adv_interval_ms, Some(60_000));
    }

    #[test]
    fn mtu_option_roundtrips() {
        let mut ra = sample_ra();
        ra.mtu = Some(1500);
        let buf = build_ra(&ra);
        let parsed = parse_ra(&buf).unwrap();
        assert_eq!(parsed.mtu, Some(1500));
    }

    #[test]
    fn mtu_zero_is_omitted() {
        let mut ra = sample_ra();
        ra.mtu = Some(0);
        let buf = build_ra(&ra);
        let parsed = parse_ra(&buf).unwrap();
        assert_eq!(parsed.mtu, None);
    }

    #[test]
    fn source_lla_option_roundtrips() {
        let mut ra = sample_ra();
        ra.source_lla = Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let buf = build_ra(&ra);
        let parsed = parse_ra(&buf).unwrap();
        assert_eq!(parsed.source_lla.as_deref(), Some(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff][..]));
    }

    // --- calc_interval tests (radv.c:997-1011) ---

    fn ra_with(interval: i32, lifetime: i32) -> RaInterface {
        RaInterface { name: "eth0".to_string(), mtu_name: None, interval, lifetime, prio: 0, mtu: 0 }
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

    // ── calc_prio ────────────────────────────────────────────────────────────

    fn make_ra_param(name: &str, prio: i32) -> RaInterface {
        RaInterface { name: name.to_string(), mtu_name: None, interval: 0, lifetime: -1, prio, mtu: 0 }
    }

    #[test]
    fn calc_prio_none_returns_zero() {
        assert_eq!(calc_prio(None), 0);
    }

    #[test]
    fn calc_prio_medium() {
        let p = make_ra_param("eth0", 0x00);
        assert_eq!(calc_prio(Some(&p)), 0x00);
    }

    #[test]
    fn calc_prio_high() {
        let p = make_ra_param("eth0", 0x08);
        assert_eq!(calc_prio(Some(&p)), 0x08);
    }

    #[test]
    fn calc_prio_low() {
        let p = make_ra_param("eth0", 0x18);
        assert_eq!(calc_prio(Some(&p)), 0x18);
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
        let d = new_timeout(std::time::Duration::from_secs(0), 600, 0);
        assert_eq!(d.as_secs(), 5);
    }

    #[test]
    fn new_timeout_short_period_max() {
        let d = new_timeout(std::time::Duration::from_secs(0), 600, 65535);
        assert!(d.as_secs() >= 19 && d.as_secs() <= 20);
    }

    #[test]
    fn new_timeout_short_period_mid() {
        let d = new_timeout(std::time::Duration::from_secs(30), 600, 32768);
        assert!(d.as_secs() >= 12 && d.as_secs() <= 13);
    }

    #[test]
    fn new_timeout_long_period_min() {
        let d = new_timeout(std::time::Duration::from_secs(120), 600, 0);
        assert_eq!(d.as_secs(), 450); // 3/4 * 600
    }

    #[test]
    fn new_timeout_long_period_max() {
        let d = new_timeout(std::time::Duration::from_secs(120), 600, 65535);
        assert!(d.as_secs() >= 599 && d.as_secs() <= 600);
    }

    #[test]
    fn new_timeout_default_interval() {
        // interval=0 should use default 600
        let d = new_timeout(std::time::Duration::from_secs(120), 0, 0);
        assert_eq!(d.as_secs(), 450);
    }

    #[test]
    fn new_timeout_boundary_at_60s() {
        // At exactly 59s → short period
        let d59 = new_timeout(std::time::Duration::from_secs(59), 600, 0);
        assert_eq!(d59.as_secs(), 5);
        // At 60s → long period
        let d60 = new_timeout(std::time::Duration::from_secs(60), 600, 0);
        assert_eq!(d60.as_secs(), 450);
    }

    #[test]
    fn new_timeout_context_sets_ra_time_in_short_period() {
        let mut ctx = base_ctx();
        ctx.ra_short_period_start = 1000;
        new_timeout_context(&mut ctx, 600, 1005, 0); // 5s into short period
        assert_eq!(ctx.ra_time, 1005 + 5);
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

    // ── test fixtures for DhcpContext-based logic ────────────────────────────

    fn base_ctx() -> DhcpContext {
        DhcpContext {
            lease_time: 3600,
            addr_epoch: 0,
            netmask: Ipv4Addr::UNSPECIFIED,
            broadcast: Ipv4Addr::UNSPECIFIED,
            local: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            // CONTEXT_CONSTRUCTED matches the realistic "dhcp-range=
            // ...,constructor:eth0" case this issue is about: the prefix is
            // tied to a live interface address, so its valid/preferred
            // lifetimes should reflect that address's real kernel-reported
            // values rather than the "no ceiling configured" infinite
            // default a plain static range gets (see the
            // `add_prefix_for_addr_no_matching_context_returns_none` test
            // below for that other case).
            flags: CONTEXT_DHCP | CONTEXT_RA | CONTEXT_CONSTRUCTED,
            netid: DhcpNetid { net: String::new() },
            filter: vec![],
            start6: "2001:db8::".parse().unwrap(),
            end6: "2001:db8::ffff:ffff:ffff:ffff".parse().unwrap(),
            local6: Ipv6Addr::UNSPECIFIED,
            prefix: 64,
            if_index: 5,
            valid: 0,
            preferred: 0,
            ra_time: 0,
            ra_short_period_start: 0,
            saved_valid: 0,
            address_lost_time: 0,
        }
    }

    fn live_addr(if_index: u32, addr: &str, prefix: i32, preferred: u32, valid: u32) -> LiveAddr6 {
        LiveAddr6 { addr: addr.parse().unwrap(), prefix, if_index, preferred, valid, deprecated: false }
    }

    // ── ra_start_unsolicited_all / _one ──────────────────────────────────────

    #[test]
    fn ra_start_unsolicited_all_skips_template_contexts() {
        let mut ctx = base_ctx();
        ctx.flags |= CONTEXT_TEMPLATE;
        let mut ctxs = vec![ctx];
        ra_start_unsolicited_all(&mut ctxs, 1000, || 0);
        assert_eq!(ctxs[0].ra_time, 0);
    }

    #[test]
    fn ra_start_unsolicited_all_sets_ra_time_within_5s() {
        let mut ctxs = vec![base_ctx()];
        ra_start_unsolicited_all(&mut ctxs, 1000, || 65535);
        assert!(ctxs[0].ra_time >= 1000 && ctxs[0].ra_time <= 1005);
        assert_eq!(ctxs[0].ra_short_period_start, 1000);
    }

    #[test]
    fn ra_start_unsolicited_one_sets_one_second_out() {
        let mut ctx = base_ctx();
        ra_start_unsolicited_one(&mut ctx, 2000);
        assert_eq!(ctx.ra_time, 2001);
        assert_eq!(ctx.ra_short_period_start, 2000);
    }

    // ── add_prefix_for_addr ───────────────────────────────────────────────────

    #[test]
    fn add_prefix_for_addr_ignores_other_interface() {
        let mut param = RaParam::default();
        let mut ctxs = vec![base_ctx()];
        let addr = live_addr(99, "2001:db8::1", 64, 1000, 2000);
        assert!(add_prefix_for_addr(&addr, 5, &mut param, &mut ctxs, false).is_none());
        assert_eq!(param.link_pref_time, 0);
    }

    #[test]
    fn add_prefix_for_addr_selects_best_link_local() {
        let mut param = RaParam::default();
        let mut ctxs = vec![base_ctx()];
        let a1 = live_addr(5, "fe80::1", 64, 100, 200);
        let a2 = live_addr(5, "fe80::2", 64, 500, 200);
        assert!(add_prefix_for_addr(&a1, 5, &mut param, &mut ctxs, false).is_none());
        assert!(add_prefix_for_addr(&a2, 5, &mut param, &mut ctxs, false).is_none());
        assert_eq!(param.link_pref_time, 500);
        assert_eq!(param.link_local, "fe80::2".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn add_prefix_for_addr_matches_context_and_returns_prefix() {
        let mut param = RaParam::default();
        let mut ctxs = vec![base_ctx()];
        let addr = live_addr(5, "2001:db8::1234", 64, 1000, 2000);
        let p = add_prefix_for_addr(&addr, 5, &mut param, &mut ctxs, false).expect("should advertise");
        assert_eq!(p.prefix_len, 64);
        assert_eq!(p.valid_lt, 2000);
        assert_eq!(p.preferred_lt, 1000);
        assert!(p.autonomous); // CONTEXT_RA set
        assert!(p.on_link);
        assert!(!p.router);
        // zeroed host part
        assert_eq!(p.prefix, "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert!(ctxs[0].flags & CONTEXT_RA_DONE != 0);
        assert_eq!(ctxs[0].saved_valid, 2000);
        assert!(param.found_context);
    }

    #[test]
    fn add_prefix_for_addr_no_matching_context_returns_none() {
        let mut param = RaParam::default();
        let mut ctxs = vec![base_ctx()];
        // Different subnet entirely.
        let addr = live_addr(5, "fd00::1234", 64, 1000, 2000);
        assert!(add_prefix_for_addr(&addr, 5, &mut param, &mut ctxs, false).is_none());
        assert!(!param.found_context);
        // Still counts towards the ULA selection, but since no *constructed*
        // context claimed it, the "configured time is ceiling" logic
        // (radv.c:700-712) falls back to its unset-ceiling sentinel
        // (0xffffffff) rather than the address's real preferred time —
        // matching upstream's `!constructed || preferred > time` check.
        assert_eq!(param.ula_pref_time, u32::MAX);
    }

    #[test]
    fn add_prefix_for_addr_loopback_and_multicast_ignored() {
        let mut param = RaParam::default();
        let mut ctxs = vec![base_ctx()];
        assert!(add_prefix_for_addr(&live_addr(5, "::1", 128, 1, 1), 5, &mut param, &mut ctxs, false).is_none());
        assert!(add_prefix_for_addr(&live_addr(5, "ff02::1", 128, 1, 1), 5, &mut param, &mut ctxs, false).is_none());
        assert_eq!(param.glob_pref_time, 0);
    }

    #[test]
    fn add_prefix_for_addr_non_ra_context_needs_opt_ra() {
        let mut ctx = base_ctx();
        ctx.flags = CONTEXT_DHCP; // no CONTEXT_RA
        let mut ctxs = vec![ctx];
        let addr = live_addr(5, "2001:db8::1234", 64, 1000, 2000);

        let mut param = RaParam::default();
        assert!(add_prefix_for_addr(&addr, 5, &mut param, &mut ctxs, false).is_none(), "without --enable-ra, non-RA context is skipped");

        let mut param2 = RaParam::default();
        let p = add_prefix_for_addr(&addr, 5, &mut param2, &mut ctxs, true).expect("with --enable-ra it's advertised");
        assert!(param2.managed);
        assert!(param2.other);
        assert!(!p.autonomous);
    }

    // ── build_ra_for_interface ────────────────────────────────────────────────

    fn build_params(if_index: u32) -> RaBuildParams<'static> {
        RaBuildParams {
            now: 1000,
            if_index,
            iface_name: "eth0",
            opt_ra: false,
            is_dns_server: true,
            hop_limit: 64,
            mtu: None,
            mac: None,
        }
    }

    #[test]
    fn build_ra_for_interface_none_without_link_local() {
        let mut ctxs = vec![base_ctx()];
        let addrs = vec![live_addr(5, "2001:db8::1234", 64, 1000, 2000)];
        let params = build_params(5);
        assert!(build_ra_for_interface(&params, &addrs, &mut ctxs, &[]).is_none());
    }

    #[test]
    fn build_ra_for_interface_produces_prefix_and_default_rdnss() {
        let mut ctxs = vec![base_ctx()];
        let addrs = vec![
            live_addr(5, "fe80::1", 64, 100, 200),
            live_addr(5, "2001:db8::1234", 64, 1000, 2000),
        ];
        let params = build_params(5);
        let ra = build_ra_for_interface(&params, &addrs, &mut ctxs, &[]).expect("should advertise");
        assert_eq!(ra.prefixes.len(), 1);
        assert_eq!(ra.prefixes[0].prefix, "2001:db8::".parse::<Ipv6Addr>().unwrap());
        assert_eq!(ra.dns_servers, vec!["fe80::1".parse::<Ipv6Addr>().unwrap()]);
        assert_eq!(ra.router_lt, calc_lifetime(None) as u16);
    }

    #[test]
    fn build_ra_for_interface_no_dns_server_omits_rdnss() {
        let mut ctxs = vec![base_ctx()];
        let addrs = vec![
            live_addr(5, "fe80::1", 64, 100, 200),
            live_addr(5, "2001:db8::1234", 64, 1000, 2000),
        ];
        let mut params = build_params(5);
        params.is_dns_server = false;
        let ra = build_ra_for_interface(&params, &addrs, &mut ctxs, &[]).expect("should advertise");
        assert!(ra.dns_servers.is_empty());
    }

    #[test]
    fn build_ra_for_interface_wrong_interface_addr_not_advertised() {
        let mut ctxs = vec![base_ctx()];
        let addrs = vec![
            live_addr(5, "fe80::1", 64, 100, 200),
            live_addr(99, "2001:db8::1234", 64, 1000, 2000), // different if_index
        ];
        let params = build_params(5);
        assert!(build_ra_for_interface(&params, &addrs, &mut ctxs, &[]).is_none());
    }

    #[test]
    fn build_ra_for_interface_old_context_advertised_deprecated() {
        let mut ctx = base_ctx();
        ctx.flags |= CONTEXT_OLD;
        ctx.if_index = 5;
        ctx.saved_valid = 500;
        ctx.address_lost_time = 900; // 100s ago at now=1000
        let mut ctxs = vec![ctx];
        let addrs = vec![live_addr(5, "fe80::1", 64, 100, 200)];
        let params = build_params(5);
        let ra = build_ra_for_interface(&params, &addrs, &mut ctxs, &[]).expect("old prefix still advertised");
        assert_eq!(ra.prefixes.len(), 1);
        assert_eq!(ra.prefixes[0].preferred_lt, 0);
        assert_eq!(ra.prefixes[0].valid_lt, 400); // 500 - 100
        assert_eq!(ra.router_lt, 0, "only old prefixes ⇒ router lifetime zeroed");
        assert_eq!(ctxs.len(), 1, "context kept while still within saved_valid");
    }

    #[test]
    fn build_ra_for_interface_old_context_expires_and_is_removed() {
        let mut ctx = base_ctx();
        ctx.flags |= CONTEXT_OLD;
        ctx.if_index = 5;
        ctx.saved_valid = 50;
        ctx.address_lost_time = 900; // 100s ago at now=1000, past saved_valid
        let mut ctxs = vec![ctx];
        let addrs = vec![live_addr(5, "fe80::1", 64, 100, 200)];
        let params = build_params(5);
        assert!(build_ra_for_interface(&params, &addrs, &mut ctxs, &[]).is_none());
        assert!(ctxs.is_empty(), "expired old context should be dropped");
    }

    // ── parse_rs_source_mac ───────────────────────────────────────────────────

    #[test]
    fn parse_rs_source_mac_absent_returns_none() {
        let mut rs = vec![133u8, 0, 0, 0, 0, 0, 0, 0]; // fixed header only
        rs.truncate(8);
        assert_eq!(parse_rs_source_mac(&rs).unwrap(), None);
    }

    #[test]
    fn parse_rs_source_mac_present() {
        let mut rs = vec![133u8, 0, 0, 0, 0, 0, 0, 0];
        add_lla(&mut rs, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let mac = parse_rs_source_mac(&rs).unwrap().expect("mac present");
        assert_eq!(&mac[..6], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn parse_rs_source_mac_malformed_option_errors() {
        let mut rs = vec![133u8, 0, 0, 0, 0, 0, 0, 0];
        rs.extend_from_slice(&[1, 0]); // len=0 is invalid
        assert!(parse_rs_source_mac(&rs).is_err());
    }

    #[test]
    fn parse_rs_source_mac_too_short_header_returns_none() {
        assert_eq!(parse_rs_source_mac(&[133, 0]).unwrap(), None);
    }

    // ── blocked_by_dhcp_except / bridge helpers ───────────────────────────────

    #[test]
    fn blocked_by_dhcp_except_matches_v6_flagged_name() {
        let except = vec![Iname { name: Some("eth0".to_string()), addr: None, flags: IfaceNameFlags::V6 }];
        assert!(blocked_by_dhcp_except("eth0", &except));
        assert!(!blocked_by_dhcp_except("eth1", &except));
    }

    #[test]
    fn blocked_by_dhcp_except_ignores_v4_only_flag() {
        let except = vec![Iname { name: Some("eth0".to_string()), addr: None, flags: crate::types::network::IfaceNameFlags::V4 }];
        assert!(!blocked_by_dhcp_except("eth0", &except));
    }

    #[test]
    fn find_bridge_for_alias_matches_wildcard() {
        let bridges = vec![DhcpBridge { iface: "br0".to_string(), aliases: vec!["eth*".to_string()] }];
        assert!(find_bridge_for_alias(&bridges, "eth0").is_some());
        assert!(find_bridge_for_alias(&bridges, "wlan0").is_none());
    }

    #[test]
    fn bridge_alias_targets_filters_matching_only() {
        let bridge = DhcpBridge { iface: "br0".to_string(), aliases: vec!["eth*".to_string()] };
        let live = vec![("eth0".to_string(), 2u32), ("wlan0".to_string(), 3u32)];
        let targets = bridge_alias_targets(&bridge, &live);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, "eth0");
    }

    // ── periodic_ra ───────────────────────────────────────────────────────────

    fn live_iface(if_index: u32, name: &str, addr: &str, prefix: i32) -> LiveIface6 {
        LiveIface6 { if_index, name: name.to_string(), addr: addr.parse().unwrap(), prefix, tentative: false }
    }

    #[test]
    fn periodic_ra_no_overdue_contexts_returns_next_event() {
        let mut ctx = base_ctx();
        ctx.ra_time = 2000;
        let mut ctxs = vec![ctx];
        let (targets, next) = periodic_ra(1000, &mut ctxs, &[], &[], &[], || 0, |_| None, |_| true);
        assert!(targets.is_empty());
        assert_eq!(next, Some(2000));
    }

    #[test]
    fn periodic_ra_finds_matching_interface_and_sends() {
        let mut ctx = base_ctx();
        ctx.ra_time = 900; // overdue at now=1000
        let mut ctxs = vec![ctx];
        let ifaces = vec![live_iface(5, "eth0", "2001:db8::1", 64)];
        let (targets, _next) = periodic_ra(1000, &mut ctxs, &ifaces, &[], &[], || 0, |_| None, |_| true);
        assert_eq!(targets, vec![RaSendTarget { if_index: 5, name: "eth0".to_string() }]);
        assert!(ctxs[0].ra_time > 1000, "should be rescheduled, not left overdue");
    }

    #[test]
    fn periodic_ra_no_matching_interface_zeroes_timer() {
        let mut ctx = base_ctx();
        ctx.ra_time = 900;
        let mut ctxs = vec![ctx];
        // No live interfaces on this subnet at all.
        let (targets, next) = periodic_ra(1000, &mut ctxs, &[], &[], &[], || 0, |_| None, |_| true);
        assert!(targets.is_empty());
        assert_eq!(next, None);
        assert_eq!(ctxs[0].ra_time, 0, "gives up rather than spinning forever");
    }

    #[test]
    fn periodic_ra_dhcp_except_blocks_interface() {
        let mut ctx = base_ctx();
        ctx.ra_time = 900;
        let mut ctxs = vec![ctx];
        let ifaces = vec![live_iface(5, "eth0", "2001:db8::1", 64)];
        let except = vec![Iname { name: Some("eth0".to_string()), addr: None, flags: IfaceNameFlags::V6 }];
        let (targets, _next) = periodic_ra(1000, &mut ctxs, &ifaces, &[], &except, || 0, |_| None, |_| true);
        assert!(targets.is_empty());
        assert_eq!(ctxs[0].ra_time, 0);
    }

    #[test]
    fn periodic_ra_iface_check_blocks_interface() {
        let mut ctx = base_ctx();
        ctx.ra_time = 900;
        let mut ctxs = vec![ctx];
        let ifaces = vec![live_iface(5, "eth0", "2001:db8::1", 64)];
        let (targets, _next) =
            periodic_ra(1000, &mut ctxs, &ifaces, &[], &[], || 0, |_| None, |name| name != "eth0");
        assert!(targets.is_empty(), "--except-interface=eth0 should suppress the RA");
        assert_eq!(ctxs[0].ra_time, 0);
    }

    #[test]
    fn periodic_ra_iface_check_blocks_old_context() {
        let mut ctx = base_ctx();
        ctx.flags |= CONTEXT_OLD;
        ctx.if_index = 7;
        ctx.ra_time = 900;
        let mut ctxs = vec![ctx];
        let (targets, _next) = periodic_ra(
            1000, &mut ctxs, &[], &[], &[], || 0,
            |idx| if idx == 7 { Some("eth7".to_string()) } else { None },
            |name| name != "eth7",
        );
        assert!(
            targets.is_empty(),
            "a CONTEXT_OLD context has no candidate scan of its own, so it must still be \
             gated by --except-interface at the final check"
        );
    }

    #[test]
    fn periodic_ra_tentative_interface_reschedules_but_does_not_send() {
        let mut ctx = base_ctx();
        ctx.ra_time = 900;
        let mut ctxs = vec![ctx];
        let mut iface = live_iface(5, "eth0", "2001:db8::1", 64);
        iface.tentative = true;
        let (targets, _next) = periodic_ra(1000, &mut ctxs, &[iface], &[], &[], || 0, |_| None, |_| true);
        assert!(targets.is_empty());
        assert!(ctxs[0].ra_time > 1000, "still rescheduled even though nothing sent");
    }

    #[test]
    fn periodic_ra_old_context_uses_stale_resolver() {
        let mut ctx = base_ctx();
        ctx.flags |= CONTEXT_OLD;
        ctx.if_index = 7;
        ctx.ra_time = 900;
        let mut ctxs = vec![ctx];
        let (targets, _next) = periodic_ra(1000, &mut ctxs, &[], &[], &[], || 0, |idx| {
            if idx == 7 { Some("eth7".to_string()) } else { None }
        }, |_| true);
        assert_eq!(targets, vec![RaSendTarget { if_index: 7, name: "eth7".to_string() }]);
    }

    #[test]
    fn periodic_ra_old_context_unresolvable_gives_up() {
        let mut ctx = base_ctx();
        ctx.flags |= CONTEXT_OLD;
        ctx.if_index = 7;
        ctx.ra_time = 900;
        let mut ctxs = vec![ctx];
        let (targets, next) = periodic_ra(1000, &mut ctxs, &[], &[], &[], || 0, |_| None, |_| true);
        assert!(targets.is_empty());
        assert_eq!(next, None);
        assert_eq!(ctxs[0].ra_time, 0);
    }

    #[test]
    fn periodic_ra_zeroes_sibling_contexts_on_same_subnet() {
        let mut ctx1 = base_ctx();
        ctx1.ra_time = 900;
        let mut ctx2 = base_ctx(); // same subnet
        ctx2.ra_time = 950;
        let mut ctxs = vec![ctx1, ctx2];
        let ifaces = vec![live_iface(5, "eth0", "2001:db8::1", 64)];
        let (targets, _next) = periodic_ra(1000, &mut ctxs, &ifaces, &[], &[], || 0, |_| None, |_| true);
        assert_eq!(targets.len(), 1, "only one RA sent even though two contexts were overdue");
        assert_eq!(ctxs[1].ra_time, 0, "sibling on the same subnet is zeroed, not independently rescheduled");
    }
}

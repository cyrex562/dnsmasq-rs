//! DHCPv6 server — UDP receive loop and packet dispatch.
//! Ported from `dhcp6.c` (881 lines) in the original dnsmasq source.
//!
//! DHCPv6 uses UDP on port 547 (server) / 546 (client), sending to the
//! all-servers multicast group FF05::1:3 or all-agents FF02::1:2.

#![cfg(feature = "dhcp6")]

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;

use tracing::{debug, warn};

use crate::dhcp6_protocol::{
    Dhcp6MsgType, DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT,
    OPTION6_CLIENT_ID, OPTION6_IA_NA, OPTION6_IAADDR, OPTION6_SERVER_ID, OPTION6_STATUS_CODE,
};
use crate::lease::LeaseDb;
use crate::metrics::{inc_metric, Metric};
use crate::types::daemon::Daemon;
use crate::types::dhcp::{DhcpConfig, DhcpContext, DhcpNetid, LEASE_NA};

// ─────────────────────────────────────────────────────────────────────────────
// DHCPv6 packet representation
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed DHCPv6 message (non-relay).
#[derive(Debug, Clone)]
pub struct Dhcp6Packet {
    /// Message type byte.
    pub msg_type: Dhcp6MsgType,
    /// Transaction ID (3 bytes, stored in the low 24 bits of a u32).
    pub xid: u32,
    /// Raw options bytes (remainder of the packet after the 4-byte header).
    pub options: Vec<u8>,
}

/// A DHCPv6 relay message (RELAY-FORW or RELAY-REPL).
#[derive(Debug, Clone)]
pub struct Dhcp6RelayMsg {
    pub msg_type:  Dhcp6MsgType,
    pub hop_count: u8,
    pub link_addr: Ipv6Addr,
    pub peer_addr: Ipv6Addr,
    pub options:   Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire-format parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a raw UDP payload into a `Dhcp6Packet`.
///
/// Returns `None` if the packet is shorter than 4 bytes or the message type
/// is not recognized.  Relay messages (RELAY-FORW / RELAY-REPL) require at
/// least 34 bytes and are returned as `Err(Dhcp6RelayMsg)`.
pub fn parse_dhcp6_packet(data: &[u8]) -> Result<Dhcp6Packet, Option<Dhcp6RelayMsg>> {
    if data.len() < 4 {
        return Err(None);
    }
    let msg_type = Dhcp6MsgType::from_u8(data[0]).ok_or(None)?;

    // Relay messages have a different header layout.
    if matches!(msg_type, Dhcp6MsgType::RelayForw | Dhcp6MsgType::RelayRepl) {
        if data.len() < 34 {
            return Err(None);
        }
        let hop_count = data[1];
        let link_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[2..18]).unwrap());
        let peer_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[18..34]).unwrap());
        return Err(Some(Dhcp6RelayMsg {
            msg_type,
            hop_count,
            link_addr,
            peer_addr,
            options: data[34..].to_vec(),
        }));
    }

    let xid = u32::from_be_bytes([0, data[1], data[2], data[3]]);
    Ok(Dhcp6Packet {
        msg_type,
        xid,
        options: data[4..].to_vec(),
    })
}

/// Find a DHCPv6 option by code in a raw options buffer.
///
/// Returns a slice of the option *value* (excluding the 4-byte TLV header)
/// or `None` if not present.
pub fn find_option6(options: &[u8], code: u16) -> Option<&[u8]> {
    let mut i = 0;
    while i + 4 <= options.len() {
        let opt_code = u16::from_be_bytes([options[i], options[i + 1]]);
        let opt_len  = u16::from_be_bytes([options[i + 2], options[i + 3]]) as usize;
        i += 4;
        if i + opt_len > options.len() {
            break;
        }
        if opt_code == code {
            return Some(&options[i..i + opt_len]);
        }
        i += opt_len;
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Reply construction
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal DHCPv6 reply.
#[derive(Debug, Clone)]
pub struct Dhcp6Reply {
    pub msg_type: Dhcp6MsgType,
    pub xid:      u32,
    pub options:  Vec<u8>,
}

impl Dhcp6Reply {
    /// Serialize to wire format.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.options.len());
        buf.push(self.msg_type as u8);
        buf.push(((self.xid >> 16) & 0xFF) as u8);
        buf.push(((self.xid >>  8) & 0xFF) as u8);
        buf.push(( self.xid        & 0xFF) as u8);
        buf.extend_from_slice(&self.options);
        buf
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Build a flat (code + length + data) DHCPv6 option.
fn build_option6(code: u16, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&code.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Build an IA_NA reply option: `IAID | T1 | T2 | sub-options`.
///
/// On a successful allocation the sub-option is an IAADDR carrying `addr`;
/// otherwise it is a Status Code sub-option reporting `NoAddrsAvail` (2),
/// mirroring upstream's IA_NA construction when `address6_allocate()`
/// returns no context (rfc3315.c).
fn build_ia_na_reply(
    iaid: [u8; 4],
    addr: Option<Ipv6Addr>,
    preferred: u32,
    valid: u32,
    t1: u32,
    t2: u32,
) -> Vec<u8> {
    let mut data = Vec::new();
    data.extend_from_slice(&iaid);
    data.extend_from_slice(&t1.to_be_bytes());
    data.extend_from_slice(&t2.to_be_bytes());

    match addr {
        Some(addr) => {
            let mut iaaddr = Vec::with_capacity(24);
            iaaddr.extend_from_slice(&addr.octets());
            iaaddr.extend_from_slice(&preferred.to_be_bytes());
            iaaddr.extend_from_slice(&valid.to_be_bytes());
            data.extend(build_option6(OPTION6_IAADDR, &iaaddr));
        }
        None => {
            const STATUS_NO_ADDRS_AVAIL: u16 = 2;
            let status = STATUS_NO_ADDRS_AVAIL.to_be_bytes();
            data.extend(build_option6(OPTION6_STATUS_CODE, &status));
        }
    }

    build_option6(OPTION6_IA_NA, &data)
}

/// Dispatch a parsed DHCPv6 packet using real server state.
///
/// Builds a genuine IA_NA/IAADDR-bearing Advertise/Reply by allocating an
/// address via [`address6_allocate`] over `contexts` (typically the
/// per-interface chain built by [`complete_context6`]), keyed on the
/// client's IAID, and stamps the server's own DUID (from [`make_duid`]) as
/// the SERVERID option. `in_use` reports addresses already committed to a
/// lease or static reservation — see [`address6_allocate`].
///
/// Returns `Some(Dhcp6Reply)` when a reply should be sent, `None` to drop.
///
/// Port of the message-type dispatch driving `dhcp6_reply()`/
/// `handle_solicit()`/`handle_request6()` (rfc3315.c), using this module's
/// own flat option encoding rather than `rfc3315::Dhcp6Packet` — see the
/// module-level gap analysis for why the crate's two DHCPv6 packet
/// representations were not unified in this change.
pub fn dispatch_dhcp6(
    pkt: &Dhcp6Packet,
    duid: &[u8],
    contexts: &[crate::types::dhcp::DhcpContext],
    in_use: &mut dyn FnMut(&Ipv6Addr) -> bool,
) -> Option<Dhcp6Reply> {
    debug!("DHCPv6 {:?} xid={:#x}", pkt.msg_type, pkt.xid);

    match pkt.msg_type {
        Dhcp6MsgType::Solicit | Dhcp6MsgType::Request | Dhcp6MsgType::Renew |
        Dhcp6MsgType::Rebind | Dhcp6MsgType::Confirm => {
            let client_id = find_option6(&pkt.options, OPTION6_CLIENT_ID).unwrap_or(&[]);
            let iaid_bytes = match find_option6(&pkt.options, OPTION6_IA_NA) {
                Some(d) if d.len() >= 4 => [d[0], d[1], d[2], d[3]],
                _ => [0u8; 4],
            };
            let iaid = u32::from_be_bytes(iaid_bytes);

            let addr = address6_allocate(contexts, client_id, iaid, &[], in_use);
            let (preferred, valid, t1, t2) = match addr {
                Some(_) => (3600, 7200, 1800, 2880),
                None => (0, 0, 0, 0),
            };

            let mut options = Vec::new();
            options.extend(build_option6(OPTION6_CLIENT_ID, client_id));
            options.extend(build_option6(OPTION6_SERVER_ID, duid));
            options.extend(build_ia_na_reply(iaid_bytes, addr, preferred, valid, t1, t2));

            let reply_type = if pkt.msg_type == Dhcp6MsgType::Solicit {
                Dhcp6MsgType::Advertise
            } else {
                Dhcp6MsgType::Reply
            };
            Some(Dhcp6Reply { msg_type: reply_type, xid: pkt.xid, options })
        }
        Dhcp6MsgType::Release | Dhcp6MsgType::Decline => {
            // No reply needed in most cases; send empty Reply to confirm receipt.
            Some(Dhcp6Reply {
                msg_type: Dhcp6MsgType::Reply,
                xid:      pkt.xid,
                options:  Vec::new(),
            })
        }
        Dhcp6MsgType::InfoReq => {
            // Information-only request — reply without IA options.
            Some(Dhcp6Reply {
                msg_type: Dhcp6MsgType::Reply,
                xid:      pkt.xid,
                options:  Vec::new(),
            })
        }
        // Relay messages handled separately by relay_dispatch().
        Dhcp6MsgType::RelayForw | Dhcp6MsgType::RelayRepl |
        Dhcp6MsgType::Advertise | Dhcp6MsgType::Reply |
        Dhcp6MsgType::Reconfigure => {
            warn!("Unexpected DHCPv6 message type {:?}", pkt.msg_type);
            None
        }
    }
}

/// Determine where to send a DHCPv6 reply.
///
/// DHCPv6 replies go to the client's link-local address on port 546.
/// If the source address is unspecified, use all-nodes multicast.
///
/// `port_override` substitutes a different reply port, for unprivileged test
/// and harness setups that can't bind the real client port — mirrors
/// [`crate::dhcp::DhcpLoopOptions::reply_port_override`].
pub fn dhcp6_reply_dest(src: SocketAddr, port_override: Option<u16>) -> SocketAddr {
    let port = port_override.unwrap_or(DHCPV6_CLIENT_PORT);
    match src {
        SocketAddr::V6(v6) => {
            SocketAddr::V6(SocketAddrV6::new(*v6.ip(), port, 0, v6.scope_id()))
        }
        _ => {
            // Fallback: all-nodes link-local multicast
            let all_nodes: Ipv6Addr = "ff02::1".parse().unwrap();
            SocketAddr::V6(SocketAddrV6::new(all_nodes, port, 0, 0))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IPv6 address helpers (ported from dhcp6.c:575-615)
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the lower 64 bits of an IPv6 address (the host part).
fn addr6part(addr: &Ipv6Addr) -> u64 {
    let o = addr.octets();
    u64::from_be_bytes(o[8..16].try_into().unwrap())
}

/// Check if two IPv6 addresses share the same prefix of `prefix_len` bits.
pub fn is_same_net6(a: &Ipv6Addr, b: &Ipv6Addr, prefix_len: i32) -> bool {
    let a_oct = a.octets();
    let b_oct = b.octets();
    let mut remaining = prefix_len as usize;
    for i in 0..16 {
        if remaining == 0 {
            break;
        }
        if remaining >= 8 {
            if a_oct[i] != b_oct[i] {
                return false;
            }
            remaining -= 8;
        } else {
            let mask = 0xFF << (8 - remaining);
            if (a_oct[i] & mask) != (b_oct[i] & mask) {
                return false;
            }
            remaining = 0;
        }
    }
    true
}

/// Check if `addr` can be dynamically allocated from one of the DHCPv6 contexts.
///
/// Returns `true` if addr falls within any non-static context range on the same prefix.
/// Port of `address6_available()` from dhcp6.c:575-599.
pub fn address6_available(contexts: &[crate::types::dhcp::DhcpContext], addr: &Ipv6Addr) -> bool {
    let a = addr6part(addr);
    for ctx in contexts {
        #[cfg(feature = "dhcp6")]
        {
            use crate::types::dhcp::{CONTEXT_STATIC, CONTEXT_RA_STATELESS};
            if ctx.flags & (CONTEXT_STATIC | CONTEXT_RA_STATELESS) != 0 {
                continue;
            }
            if !is_same_net6(&ctx.start6, addr, ctx.prefix) {
                continue;
            }
            let start = addr6part(&ctx.start6);
            let end = addr6part(&ctx.end6);
            if a >= start && a <= end {
                return true;
            }
        }
    }
    false
}

/// Check if `addr` is valid for any configured DHCPv6 context (static or dynamic).
///
/// Returns `true` if addr is on the same prefix as any context.
/// Port of `address6_valid()` from dhcp6.c:601-615.
pub fn address6_valid(contexts: &[crate::types::dhcp::DhcpContext], addr: &Ipv6Addr) -> bool {
    for ctx in contexts {
        #[cfg(feature = "dhcp6")]
        {
            if is_same_net6(&ctx.start6, addr, ctx.prefix) {
                return true;
            }
        }
    }
    false
}

/// Find a static DHCPv6 host config matching an address.
///
/// Port of `config_find_by_address6()` from dhcp6.c:474-490.
#[cfg(feature = "dhcp6")]
pub fn config_find_by_address6(
    configs: &[crate::types::dhcp::DhcpConfig],
    addr: &Ipv6Addr,
) -> bool {
    use crate::types::addr::AllAddr;
    use crate::types::dhcp::CONFIG_ADDR6;
    for config in configs {
        if config.flags & CONFIG_ADDR6 == 0 {
            continue;
        }
        for a6 in &config.addr6 {
            if let AllAddr::Addr6(ref v6) = a6.addr {
                if is_same_net6(v6, addr, 128) {
                    return true;
                }
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// DHCPv6 SDBM hash and address allocation (ported from dhcp6.c:492-573)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute 64-bit SDBM hash of a client identifier for DHCPv6 address allocation.
///
/// Seeded with the IAID (Identity Association ID).
/// Port of the hash in dhcp6.c:514-515.
pub fn sdbm_hash64(clid: &[u8], iaid: u32) -> u64 {
    let mut j: u64 = iaid as u64;
    for &b in clid {
        j = (b as u64)
            .wrapping_add(j.wrapping_shl(6))
            .wrapping_add(j.wrapping_shl(16))
            .wrapping_sub(j);
    }
    j
}

/// Calculate the starting IPv6 host-part for allocation using hash-based seeding.
///
/// Maps the hash into the range [start6_low64, end6_low64] using modular arithmetic.
/// Port of the address calculation in dhcp6.c:536-544.
pub fn hash_to_addr6(hash: u64, epoch: u32, start_low: u64, end_low: u64) -> u64 {
    let range = end_low.wrapping_sub(start_low).wrapping_add(1);
    let offset = hash.wrapping_add(epoch as u64);
    if range == 0 {
        // Full 2^64 range — don't divide by zero
        start_low.wrapping_add(offset)
    } else {
        start_low.wrapping_add(offset % range)
    }
}

/// Replace the low 64 bits (host part) of `base` with `host`, keeping its
/// upper (network) bits. Inverse of `addr6part`.
fn addr6_with_host(base: &Ipv6Addr, host: u64) -> Ipv6Addr {
    let mut octets = base.octets();
    octets[8..16].copy_from_slice(&host.to_be_bytes());
    Ipv6Addr::from(octets)
}

/// Allocate a free IPv6 address from a context chain for a client.
///
/// `contexts` should be the "current" chain for the packet's arrival
/// interface (e.g. built by [`complete_context6`]). Contexts flagged
/// `CONTEXT_DEPRECATE`/`CONTEXT_STATIC`/`CONTEXT_RA_STATELESS`/`CONTEXT_USED`
/// are skipped, as is any context whose `filter` doesn't match `netids`
/// (empty `filter` matches everyone). For each remaining context, computes a
/// hash-seeded starting offset ([`sdbm_hash64`]/[`hash_to_addr6`]) and scans
/// the whole range once, wrapping around, for an address that collides with
/// neither another context's own `local6` address, nor `in_use` (leases and
/// static `--dhcp-host` reservations).
///
/// Single-pass only: upstream's two-pass `plain_range` fallback (try
/// netid-matching contexts first, then fall back to any context) is not
/// ported — see `tasks.md`. Upstream's `--consec-addresses` seeding mode is
/// likewise not ported; only the hash-seeded mode is.
///
/// Port of `address6_allocate()` (dhcp6.c:492-573).
pub fn address6_allocate(
    contexts: &[crate::types::dhcp::DhcpContext],
    clid: &[u8],
    iaid: u32,
    netids: &[DhcpNetid],
    in_use: &mut dyn FnMut(&Ipv6Addr) -> bool,
) -> Option<Ipv6Addr> {
    use crate::types::dhcp::{CONTEXT_DEPRECATE, CONTEXT_RA_STATELESS, CONTEXT_STATIC, CONTEXT_USED};

    let hash = sdbm_hash64(clid, iaid);

    for ctx in contexts {
        if ctx.flags & (CONTEXT_DEPRECATE | CONTEXT_STATIC | CONTEXT_RA_STATELESS | CONTEXT_USED) != 0 {
            continue;
        }
        if !ctx.filter.is_empty() && !crate::dhcp_common::match_netid(&ctx.filter, netids) {
            continue;
        }

        let start = addr6part(&ctx.start6);
        let end = addr6part(&ctx.end6);
        let start_addr = hash_to_addr6(hash, ctx.addr_epoch, start, end);

        let mut addr = start_addr;
        loop {
            let candidate = addr6_with_host(&ctx.start6, addr);

            let collides_with_server = contexts.iter().any(|d| addr6part(&d.local6) == addr);
            if !collides_with_server && !in_use(&candidate) {
                return Some(candidate);
            }

            addr = if addr == end { start } else { addr.wrapping_add(1) };
            if addr == start_addr {
                break;
            }
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Live-interface context matching (ported from dhcp6.c:352-420)
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of an address seen on an interface.
///
/// Loopback/link-local/multicast addresses never participate in context
/// matching (dhcp6.c:371-374). ULA is called out separately because upstream
/// records it into a dedicated `param->ula_addr` local (dhcp6.c:370) for
/// later use as a DNS-server-option fallback distinct from a link-local or
/// global address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addr6Class {
    Loopback,
    LinkLocal,
    Ula,
    Multicast,
    Global,
}

/// Classify an address the way `complete_context6()` does (dhcp6.c:367-374).
pub fn classify_addr6(addr: &Ipv6Addr) -> Addr6Class {
    if addr.is_loopback() {
        Addr6Class::Loopback
    } else if crate::network::is_link_local_v6(*addr) {
        Addr6Class::LinkLocal
    } else if addr.is_multicast() {
        Addr6Class::Multicast
    } else if crate::network::is_ula_v6(*addr) {
        Addr6Class::Ula
    } else {
        Addr6Class::Global
    }
}

/// One address discovered on the packet's arrival interface — the subset of
/// upstream's `iface_enumerate(AF_INET6, ..., complete_context6)` callback
/// arguments that plain (non-shared-network) context matching needs.
#[derive(Debug, Clone)]
pub struct LiveAddr6 {
    pub addr:      Ipv6Addr,
    pub prefix:    i32,
    pub if_index:  u32,
    /// Kernel-reported preferred/valid lifetimes for this address.
    pub preferred: u32,
    pub valid:     u32,
    /// Upstream's `IFACE_DEPRECATED` interface flag.
    pub deprecated: bool,
}

/// Build the ordered "current" context chain for one live interface address,
/// filling in `local6`/`preferred`/`valid`/`if_index` on each match.
///
/// Restricted to the plain (non-shared-network) branch of `complete_context6`
/// (dhcp6.c:388-420); shared-network matching and DHCPv6-relay
/// `iface_index`/duplicate-warning bookkeeping (dhcp6.c:421-460) are not
/// ported — see `tasks.md`. Loopback/link-local/multicast addresses never
/// match (dhcp6.c:371-374).
///
/// Returns the chain ordered longest-preferred-time first, matching
/// upstream's linked-list insertion (dhcp6.c:405-412).
///
/// Port of `complete_context6()` (dhcp6.c:352-420).
pub fn complete_context6(
    live: &LiveAddr6,
    contexts: &[crate::types::dhcp::DhcpContext],
) -> Vec<crate::types::dhcp::DhcpContext> {
    use crate::types::dhcp::{CONTEXT_CONSTRUCTED, CONTEXT_DEPRECATE, CONTEXT_DHCP, CONTEXT_OLD, CONTEXT_TEMPLATE};

    if matches!(
        classify_addr6(&live.addr),
        Addr6Class::Loopback | Addr6Class::LinkLocal | Addr6Class::Multicast
    ) {
        return Vec::new();
    }

    let mut current: Vec<crate::types::dhcp::DhcpContext> = Vec::new();
    for ctx in contexts {
        if ctx.flags & CONTEXT_DHCP == 0 {
            continue;
        }
        if ctx.flags & (CONTEXT_TEMPLATE | CONTEXT_OLD) != 0 {
            continue;
        }
        if live.prefix > ctx.prefix {
            continue;
        }
        if !is_same_net6(&live.addr, &ctx.start6, ctx.prefix)
            || !is_same_net6(&live.addr, &ctx.end6, ctx.prefix)
        {
            continue;
        }

        // "use interface values only for constructed contexts"
        let (mut preferred, valid) = if ctx.flags & CONTEXT_CONSTRUCTED == 0 {
            (0xffff_ffffu32, 0xffff_ffffu32)
        } else {
            let p = if live.deprecated { 0 } else { live.preferred };
            (p, live.valid)
        };
        if ctx.flags & CONTEXT_DEPRECATE != 0 {
            preferred = 0;
        }

        let mut matched = ctx.clone();
        matched.local6 = live.addr;
        matched.preferred = preferred;
        matched.valid = valid;
        matched.if_index = live.if_index as i32;

        let pos = current.iter().position(|c| c.preferred <= preferred).unwrap_or(current.len());
        current.insert(pos, matched);
    }
    current
}

/// Fill in `if_index`/`local6` on plain (non-template) DHCPv6 contexts whose
/// prefix matches a live interface address, mutating them in place.
///
/// Port of the non-template branch of `construct_worker()` (dhcp6.c:730-748),
/// called from `dhcp_construct_contexts()` via
/// `iface_enumerate(AF_INET6, ..., construct_worker)`. The other branch —
/// constructing brand-new contexts from a
/// `--dhcp-range=...,constructor:IFACE,...` template — needs a
/// `template_interface` field on `DhcpContext` and `constructor:` config
/// parsing that don't exist yet in this crate (see `tasks.md`); template
/// (`CONTEXT_TEMPLATE`) and already-constructed (`CONTEXT_CONSTRUCTED`)
/// contexts are left untouched here, same as fast-RA kickoff and GC aging of
/// constructed contexts whose interface/prefix has disappeared.
pub fn dhcp_construct_contexts(
    contexts: &mut [crate::types::dhcp::DhcpContext],
    live_addrs: &[LiveAddr6],
) {
    use crate::types::dhcp::{CONTEXT_CONSTRUCTED, CONTEXT_TEMPLATE};

    for live in live_addrs {
        if matches!(
            classify_addr6(&live.addr),
            Addr6Class::Loopback | Addr6Class::LinkLocal | Addr6Class::Multicast
        ) {
            continue;
        }
        for ctx in contexts.iter_mut() {
            if ctx.flags & (CONTEXT_TEMPLATE | CONTEXT_CONSTRUCTED) != 0 {
                continue;
            }
            if live.prefix <= ctx.prefix
                && is_same_net6(&live.addr, &ctx.start6, ctx.prefix)
                && is_same_net6(&live.addr, &ctx.end6, ctx.prefix)
            {
                ctx.if_index = live.if_index as i32;
                ctx.local6 = live.addr;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DUID generation (ported from dhcp6.c:617-689)
// ─────────────────────────────────────────────────────────────────────────────

/// DUID type codes (RFC 3315 §9.1-9.3).
pub const DUID_LLT: u16 = 1;
pub const DUID_EN:  u16 = 2;
pub const DUID_LL:  u16 = 3;

/// The 2000-01-01 epoch offset upstream rebases DUID-LLT timestamps to
/// (`dhcp6.c:635`: `newnow = now - 946684800`).
pub const DUID_EPOCH_OFFSET: u64 = 946_684_800;

/// Build a DUID-EN (type 2): enterprise-assigned identifier.
/// Wire format: `type(2) | enterprise-number(4) | identifier(N)`.
/// Port of the `daemon->duid_config` branch of `make_duid()` (dhcp6.c:621-627).
pub fn build_duid_en(enterprise: u32, id: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(6 + id.len());
    buf.extend_from_slice(&DUID_EN.to_be_bytes());
    buf.extend_from_slice(&enterprise.to_be_bytes());
    buf.extend_from_slice(id);
    buf
}

/// Build a DUID-LLT (type 1): link-layer address plus a 2000-epoch timestamp.
/// Wire format: `type(2) | hw-type(2) | time(4) | link-layer-address(N)`.
/// Port of `make_duid1()`'s `newnow != 0` branch (dhcp6.c:658-666).
pub fn build_duid_llt(hw_type: u16, mac: &[u8], time_secs: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + mac.len());
    buf.extend_from_slice(&DUID_LLT.to_be_bytes());
    buf.extend_from_slice(&hw_type.to_be_bytes());
    buf.extend_from_slice(&time_secs.to_be_bytes());
    buf.extend_from_slice(mac);
    buf
}

/// Build a DUID-LL (type 3): link-layer address only, no timestamp. Used
/// when there's no persistent lease database or the RTC isn't trusted.
/// Wire format: `type(2) | hw-type(2) | link-layer-address(N)`.
/// Port of `make_duid1()`'s `newnow == 0` branch (dhcp6.c:650-656).
pub fn build_duid_ll(hw_type: u16, mac: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + mac.len());
    buf.extend_from_slice(&DUID_LL.to_be_bytes());
    buf.extend_from_slice(&hw_type.to_be_bytes());
    buf.extend_from_slice(mac);
    buf
}

/// A MAC address discovered by enumerating live interfaces, input to
/// [`make_duid`]'s DUID-LL/DUID-LLT fallback. `hw_type` is the kernel's
/// ARPHRD_* hardware type; upstream skips anything `>= 256` (tunnels and
/// other MAC-less link types), which this module's caller is expected to
/// have already filtered before selecting a source (mirrors
/// `make_duid1()`'s own `type >= 256` check, dhcp6.c:653).
#[derive(Debug, Clone)]
pub struct DuidMacSource {
    pub hw_type: u16,
    pub mac:     Vec<u8>,
}

/// Generate and store the server's DHCPv6 DUID into `daemon.duid`.
///
/// If `--dhcp-duid=` configured an enterprise number and id
/// (`daemon.duid_config`), builds a DUID-EN from it. Otherwise builds a
/// DUID-LLT (`use_llt`, upstream's persistent-lease-DB-or-stable-RTC case)
/// or a DUID-LL from `mac_source`, the first eligible interface MAC
/// discovered by the caller (production wiring enumerates live interfaces
/// via netlink `AF_LOCAL`; tests inject a fixed MAC).
///
/// Returns `Err` if no DUID could be built at all — upstream calls
/// `die(EC_MISC)` in this case (dhcp6.c:643).
///
/// Port of `make_duid()`/`make_duid1()` (dhcp6.c:617-689).
pub fn make_duid(
    daemon: &mut Daemon,
    mac_source: Option<DuidMacSource>,
    use_llt: bool,
    now_secs: u64,
) -> Result<(), &'static str> {
    if let Some(id) = &daemon.duid_config {
        daemon.duid = Some(build_duid_en(daemon.duid_enterprise, id));
        return Ok(());
    }

    let Some(src) = mac_source else {
        return Err("Cannot create DHCPv6 server DUID: no interface with a usable MAC address");
    };
    if src.hw_type >= 256 {
        return Err("Cannot create DHCPv6 server DUID: no interface with a usable MAC address");
    }

    daemon.duid = Some(if use_llt {
        let epoch_time = now_secs.saturating_sub(DUID_EPOCH_OFFSET) as u32;
        build_duid_llt(src.hw_type, &src.mac, epoch_time)
    } else {
        build_duid_ll(src.hw_type, &src.mac)
    });
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Socket init (ported from dhcp6.c:35-88)
// ─────────────────────────────────────────────────────────────────────────────

/// Bind the DHCPv6 server UDP socket to `[::]:547`.
///
/// Uses [`crate::network::make_sock`], which already sets `IPV6_V6ONLY`,
/// `SO_REUSEADDR`, and (for UDP IPv6 sockets) `IPV6_RECVPKTINFO` — mirroring
/// upstream's own socket setup. `nowild` is `--bind-interfaces`
/// (`OPT_NOWILD`), same meaning as `make_sock`'s parameter.
///
/// Does not join the `ALL_DHCP_RELAY_AGENTS_AND_SERVERS` (FF02::1:2) /
/// `ALL_DHCP_SERVERS` (FF05::1:3) multicast groups: upstream's
/// `dhcp6_init()` doesn't either (dhcp6.c:35-88) — it relies on a wildcard
/// bind plus per-interface `join_multicast()` in `network.c`, which this
/// crate does not yet port (see `tasks.md`).
///
/// Port of `dhcp6_init()` (dhcp6.c:35-88).
#[cfg(unix)]
pub fn dhcp6_init(nowild: bool) -> std::io::Result<std::os::unix::io::RawFd> {
    use crate::network::{make_sock, SockType};

    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DHCPV6_SERVER_PORT, 0, 0));
    make_sock(addr, SockType::Udp, nowild)
}

// ─────────────────────────────────────────────────────────────────────────────
// Receive/dispatch loop (ported from dhcp6.c:89-306, receive-loop portion)
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the allocated IPv6 address from a reply's IA_NA/IAADDR sub-option,
/// if the allocation succeeded (as opposed to a Status-Code NoAddrsAvail).
fn extract_allocated_addr(reply: &Dhcp6Reply) -> Option<Ipv6Addr> {
    let ia_data = find_option6(&reply.options, OPTION6_IA_NA)?;
    if ia_data.len() <= 12 {
        return None;
    }
    let iaaddr = find_option6(&ia_data[12..], OPTION6_IAADDR)?;
    let bytes: [u8; 16] = iaaddr.get(0..16)?.try_into().ok()?;
    Some(Ipv6Addr::from(bytes))
}

/// Run the DHCPv6 receive/dispatch loop over an already-bound `[::]:547` socket.
///
/// `contexts` is the "current" chain [`complete_context6`] builds from live
/// interface prefixes — production callers build this once at startup via
/// [`dhcp_construct_contexts`]/[`complete_context6`]. This loop does not
/// re-derive that chain per packet against the packet's arrival interface the
/// way upstream's `dhcp6_packet()` does (dhcp6.c:89-306); see `tasks.md`.
///
/// An allocated address is committed into `lease_db` only when the client
/// sent Request/Renew/Rebind — Solicit/Advertise never commits, matching
/// upstream (`address6_allocate()` is a pure candidate search; only
/// `lease6_allocate()` on the Reply path persists it). `lease_db` is kept
/// in-memory only by this loop: it does not load or write a shared
/// `--dhcp-leasefile` — doing that safely needs one writer for the file the
/// IPv4 loop already owns, not two independent in-memory copies of it (see
/// `tasks.md`).
///
/// Port of the receive-loop portion of `dhcp6_packet()` (dhcp6.c:89-306),
/// wired to the real [`dispatch_dhcp6`] pipeline.
pub async fn run_dhcp6_loop(
    socket: Arc<tokio::net::UdpSocket>,
    duid: Vec<u8>,
    contexts: Vec<DhcpContext>,
    configs: Vec<DhcpConfig>,
    mut lease_db: LeaseDb,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    reply_port_override: Option<u16>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 1500];
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow() => return Ok(()),
                    Ok(()) => continue,
                    Err(_) => return Ok(()),
                }
            }
            recv = socket.recv_from(&mut buf) => {
                let (len, src) = recv?;
                let Ok(pkt) = parse_dhcp6_packet(&buf[..len]) else {
                    debug!("ignoring malformed or relay DHCPv6 packet from {src}");
                    continue;
                };

                let reply = {
                    let mut in_use = |addr: &Ipv6Addr| {
                        lease_db.find_v6_by_addr(addr).is_some()
                            || config_find_by_address6(&configs, addr)
                    };
                    dispatch_dhcp6(&pkt, &duid, &contexts, &mut in_use)
                };
                let Some(reply) = reply else { continue };

                if matches!(
                    pkt.msg_type,
                    Dhcp6MsgType::Request | Dhcp6MsgType::Renew | Dhcp6MsgType::Rebind
                ) {
                    if let Some(addr) = extract_allocated_addr(&reply) {
                        if lease_db.find_v6_by_addr(&addr).is_none() {
                            let client_id = find_option6(&pkt.options, OPTION6_CLIENT_ID)
                                .unwrap_or(&[])
                                .to_vec();
                            let iaid = find_option6(&pkt.options, OPTION6_IA_NA)
                                .filter(|d| d.len() >= 4)
                                .map(|d| u32::from_be_bytes([d[0], d[1], d[2], d[3]]))
                                .unwrap_or(0);
                            if let Some(lease) = lease_db.allocate_v6(addr, LEASE_NA) {
                                lease.clid = Some(client_id);
                                lease.iaid = iaid;
                            }
                        }
                    }
                }

                let dest = dhcp6_reply_dest(src, reply_port_override);
                if let Err(e) = socket.send_to(&reply.to_wire(), dest).await {
                    warn!("failed to send DHCPv6 reply to {dest}: {e}");
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn solicit_pkt(xid: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(Dhcp6MsgType::Solicit as u8);
        v.push(((xid >> 16) & 0xFF) as u8);
        v.push(((xid >>  8) & 0xFF) as u8);
        v.push(( xid        & 0xFF) as u8);
        v
    }

    /// A Solicit with a CLIENT_ID and an empty (no sub-options) IA_NA, the
    /// minimum a real client sends to request an address.
    fn solicit_with_ia(xid: u32, iaid: [u8; 4]) -> Vec<u8> {
        let mut v = solicit_pkt(xid);
        v.extend_from_slice(&OPTION6_CLIENT_ID.to_be_bytes());
        v.extend_from_slice(&4u16.to_be_bytes());
        v.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        v.extend_from_slice(&OPTION6_IA_NA.to_be_bytes());
        v.extend_from_slice(&12u16.to_be_bytes());
        v.extend_from_slice(&iaid);
        v.extend_from_slice(&0u32.to_be_bytes()); // T1
        v.extend_from_slice(&0u32.to_be_bytes()); // T2
        v
    }

    #[test]
    fn parse_solicit_ok() {
        let data = solicit_pkt(0xABCD12);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        assert_eq!(pkt.msg_type, Dhcp6MsgType::Solicit);
        assert_eq!(pkt.xid, 0xABCD12);
    }

    #[test]
    fn parse_short_returns_err() {
        assert!(parse_dhcp6_packet(&[1, 2, 3]).is_err());
    }

    #[test]
    fn parse_unknown_type_returns_err() {
        assert!(parse_dhcp6_packet(&[0xFF, 0, 0, 0]).is_err());
    }

    #[test]
    fn solicit_dispatches_to_advertise() {
        let data = solicit_pkt(0x1234);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut in_use = |_: &Ipv6Addr| false;
        let reply = dispatch_dhcp6(&pkt, &duid, &[], &mut in_use);
        assert!(reply.is_some());
        assert_eq!(reply.unwrap().msg_type, Dhcp6MsgType::Advertise);
    }

    #[test]
    fn request_dispatches_to_reply() {
        let mut data = solicit_pkt(0x5678);
        data[0] = Dhcp6MsgType::Request as u8;
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut in_use = |_: &Ipv6Addr| false;
        let reply = dispatch_dhcp6(&pkt, &duid, &[], &mut in_use);
        assert_eq!(reply.unwrap().msg_type, Dhcp6MsgType::Reply);
    }

    #[test]
    fn find_option6_present() {
        // Build an option buffer with option code 1, length 2, value [0xAB, 0xCD]
        let opts = [0, 1, 0, 2, 0xAB, 0xCD, 0, 2, 0, 1, 0xFF];
        let val = find_option6(&opts, 1).unwrap();
        assert_eq!(val, &[0xAB, 0xCD]);
    }

    #[test]
    fn find_option6_missing() {
        let opts = [0, 1, 0, 2, 0xAB, 0xCD];
        assert!(find_option6(&opts, 99).is_none());
    }

    #[test]
    fn reply_to_wire_roundtrip() {
        let reply = Dhcp6Reply {
            msg_type: Dhcp6MsgType::Advertise,
            xid:      0xAABBCC,
            options:  vec![0x00, 0x01, 0x00, 0x00], // empty option 1
        };
        let wire = reply.to_wire();
        assert_eq!(wire[0], Dhcp6MsgType::Advertise as u8);
        assert_eq!(wire[1], 0xAA);
        assert_eq!(wire[2], 0xBB);
        assert_eq!(wire[3], 0xCC);
    }

    #[test]
    fn parse_relay_forw() {
        let mut data = vec![0u8; 34];
        data[0] = Dhcp6MsgType::RelayForw as u8;
        data[1] = 5; // hop count
        // link_addr and peer_addr are all zeros
        let result = parse_dhcp6_packet(&data);
        assert!(result.is_err());
        let relay = result.err().unwrap().unwrap();
        assert_eq!(relay.msg_type, Dhcp6MsgType::RelayForw);
        assert_eq!(relay.hop_count, 5);
    }

    // ── is_same_net6 ─────────────────────────────────────────────────────────

    #[test]
    fn is_same_net6_same_prefix() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::ffff".parse().unwrap();
        assert!(is_same_net6(&a, &b, 64));
    }

    #[test]
    fn is_same_net6_different_prefix() {
        let a: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
        assert!(!is_same_net6(&a, &b, 48));
    }

    #[test]
    fn is_same_net6_exact_match() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(is_same_net6(&a, &b, 128));
    }

    #[test]
    fn is_same_net6_exact_mismatch() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert!(!is_same_net6(&a, &b, 128));
    }

    #[test]
    fn is_same_net6_zero_prefix() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_same_net6(&a, &b, 0));
    }

    // ── addr6part ────────────────────────────────────────────────────────────

    #[test]
    fn addr6part_extracts_low64() {
        let a: Ipv6Addr = "2001:db8::42".parse().unwrap();
        assert_eq!(addr6part(&a), 0x42);
    }

    #[test]
    fn addr6part_max() {
        let a: Ipv6Addr = "::ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(addr6part(&a), u64::MAX);
    }

    // ── address6_available / address6_valid ───────────────────────────────────

    #[cfg(feature = "dhcp6")]
    fn make_v6_ctx(start6: Ipv6Addr, end6: Ipv6Addr, prefix: i32, flags: u32) -> crate::types::dhcp::DhcpContext {
        use std::net::Ipv4Addr;
        crate::types::dhcp::DhcpContext {
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            flags,
            netmask: Ipv4Addr::new(0,0,0,0),
            broadcast: Ipv4Addr::new(0,0,0,0),
            local: Ipv4Addr::new(0,0,0,0),
            lease_time: 3600,
            addr_epoch: 0,
            netid: crate::types::dhcp::DhcpNetid { net: String::new() },
            filter: vec![],
            start6,
            end6,
            local6: Ipv6Addr::UNSPECIFIED,
            prefix,
            if_index: 0,
            valid: 0,
            preferred: 0,
        }
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_available_in_range() {
        let ctx = make_v6_ctx(
            "2001:db8::100".parse().unwrap(),
            "2001:db8::200".parse().unwrap(),
            64, 0,
        );
        assert!(address6_available(&[ctx], &"2001:db8::150".parse().unwrap()));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_available_out_of_range() {
        let ctx = make_v6_ctx(
            "2001:db8::100".parse().unwrap(),
            "2001:db8::200".parse().unwrap(),
            64, 0,
        );
        assert!(!address6_available(&[ctx], &"2001:db8::50".parse().unwrap()));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_available_skips_static() {
        use crate::types::dhcp::CONTEXT_STATIC;
        let ctx = make_v6_ctx(
            "2001:db8::100".parse().unwrap(),
            "2001:db8::200".parse().unwrap(),
            64, CONTEXT_STATIC,
        );
        assert!(!address6_available(&[ctx], &"2001:db8::150".parse().unwrap()));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_valid_on_prefix() {
        let ctx = make_v6_ctx(
            "2001:db8::100".parse().unwrap(),
            "2001:db8::200".parse().unwrap(),
            64, 0,
        );
        assert!(address6_valid(&[ctx], &"2001:db8::999".parse().unwrap()));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_valid_wrong_prefix() {
        let ctx = make_v6_ctx(
            "2001:db8:1::100".parse().unwrap(),
            "2001:db8:1::200".parse().unwrap(),
            48, 0,
        );
        assert!(!address6_valid(&[ctx], &"2001:db8:2::1".parse().unwrap()));
    }

    // ── sdbm_hash64 ─────────────────────────────────────────────────────────

    #[test]
    fn sdbm_hash64_deterministic() {
        let clid = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(sdbm_hash64(&clid, 1), sdbm_hash64(&clid, 1));
    }

    #[test]
    fn sdbm_hash64_different_clids_differ() {
        let h1 = sdbm_hash64(&[0x01, 0x02], 1);
        let h2 = sdbm_hash64(&[0xAA, 0xBB], 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn sdbm_hash64_different_iaids_differ() {
        let clid = [0x01, 0x02, 0x03];
        assert_ne!(sdbm_hash64(&clid, 1), sdbm_hash64(&clid, 2));
    }

    // ── hash_to_addr6 ────────────────────────────────────────────────────────

    #[test]
    fn hash_to_addr6_in_range() {
        let start = 0x100u64;
        let end = 0x200u64;
        let result = hash_to_addr6(42, 0, start, end);
        assert!(result >= start && result <= end);
    }

    #[test]
    fn hash_to_addr6_single_address() {
        let result = hash_to_addr6(999, 0, 0x42, 0x42);
        assert_eq!(result, 0x42);
    }

    #[test]
    fn hash_to_addr6_epoch_shifts() {
        let a1 = hash_to_addr6(42, 0, 0x100, 0x200);
        let a2 = hash_to_addr6(42, 1, 0x100, 0x200);
        assert_ne!(a1, a2);
    }

    #[test]
    fn hash_to_addr6_full_range() {
        // Full 2^64 range should not panic
        let result = hash_to_addr6(42, 0, 0, u64::MAX);
        // Just verify it doesn't panic
        let _ = result;
    }

    // ── address6_allocate ──────────────────────────────────────────────────────

    #[test]
    fn address6_allocate_finds_free_address() {
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
            64, 0,
        );
        let mut in_use = |_: &Ipv6Addr| false;
        let addr = address6_allocate(&[ctx], &[0x01, 0x02], 1, &[], &mut in_use);
        assert!(addr.is_some());
        let a = addr.unwrap();
        assert!(is_same_net6(&a, &"2001:db8::1".parse().unwrap(), 64));
    }

    #[test]
    fn address6_allocate_skips_collision_and_finds_next() {
        let start: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let end: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let ctx = make_v6_ctx(start, end, 64, 0);
        let clid = [0x01, 0x02];
        let iaid = 1u32;

        let hash = sdbm_hash64(&clid, iaid);
        let predicted_host = hash_to_addr6(hash, 0, addr6part(&start), addr6part(&end));
        let predicted = addr6_with_host(&start, predicted_host);

        let mut in_use = |a: &Ipv6Addr| *a == predicted;
        let addr = address6_allocate(&[ctx], &clid, iaid, &[], &mut in_use).unwrap();
        assert_ne!(addr, predicted);
    }

    #[test]
    fn address6_allocate_skips_static_context() {
        use crate::types::dhcp::CONTEXT_STATIC;
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
            64, CONTEXT_STATIC,
        );
        let mut in_use = |_: &Ipv6Addr| false;
        assert!(address6_allocate(&[ctx], &[0x01], 1, &[], &mut in_use).is_none());
    }

    #[test]
    fn address6_allocate_returns_none_when_full() {
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            128, 0,
        );
        let mut in_use = |_: &Ipv6Addr| true;
        assert!(address6_allocate(&[ctx], &[0x01], 1, &[], &mut in_use).is_none());
    }

    #[test]
    fn address6_allocate_skips_server_own_local6() {
        let mut ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            128, 0,
        );
        ctx.local6 = "2001:db8::1".parse().unwrap();
        let mut in_use = |_: &Ipv6Addr| false;
        assert!(address6_allocate(&[ctx], &[0x01], 1, &[], &mut in_use).is_none());
    }

    // ── classify_addr6 ────────────────────────────────────────────────────────

    #[test]
    fn classify_addr6_loopback() {
        assert_eq!(classify_addr6(&"::1".parse().unwrap()), Addr6Class::Loopback);
    }

    #[test]
    fn classify_addr6_link_local() {
        assert_eq!(classify_addr6(&"fe80::1".parse().unwrap()), Addr6Class::LinkLocal);
    }

    #[test]
    fn classify_addr6_ula() {
        assert_eq!(classify_addr6(&"fc00::1".parse().unwrap()), Addr6Class::Ula);
        assert_eq!(classify_addr6(&"fd00::1".parse().unwrap()), Addr6Class::Ula);
    }

    #[test]
    fn classify_addr6_multicast() {
        assert_eq!(classify_addr6(&"ff02::1".parse().unwrap()), Addr6Class::Multicast);
    }

    #[test]
    fn classify_addr6_global() {
        assert_eq!(classify_addr6(&"2001:db8::1".parse().unwrap()), Addr6Class::Global);
    }

    // ── complete_context6 ─────────────────────────────────────────────────────

    #[test]
    fn complete_context6_matches_and_fills_fields() {
        use crate::types::dhcp::CONTEXT_DHCP;
        let ctx = make_v6_ctx(
            "2001:db8:1::".parse().unwrap(),
            "2001:db8:1::ffff".parse().unwrap(),
            64, CONTEXT_DHCP,
        );
        let live = LiveAddr6 {
            addr: "2001:db8:1::1".parse().unwrap(),
            prefix: 64,
            if_index: 3,
            preferred: 500,
            valid: 1000,
            deprecated: false,
        };
        let chain = complete_context6(&live, &[ctx]);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].local6, live.addr);
        assert_eq!(chain[0].if_index, 3);
        // Not CONTEXT_CONSTRUCTED -> infinite lifetimes (dhcp6.c:401-402).
        assert_eq!(chain[0].preferred, 0xffff_ffff);
        assert_eq!(chain[0].valid, 0xffff_ffff);
    }

    #[test]
    fn complete_context6_constructed_uses_interface_lifetimes() {
        use crate::types::dhcp::{CONTEXT_CONSTRUCTED, CONTEXT_DHCP};
        let ctx = make_v6_ctx(
            "2001:db8:1::".parse().unwrap(),
            "2001:db8:1::ffff".parse().unwrap(),
            64, CONTEXT_DHCP | CONTEXT_CONSTRUCTED,
        );
        let live = LiveAddr6 {
            addr: "2001:db8:1::1".parse().unwrap(),
            prefix: 64,
            if_index: 3,
            preferred: 500,
            valid: 1000,
            deprecated: false,
        };
        let chain = complete_context6(&live, &[ctx]);
        assert_eq!(chain[0].preferred, 500);
        assert_eq!(chain[0].valid, 1000);
    }

    #[test]
    fn complete_context6_skips_link_local() {
        use crate::types::dhcp::CONTEXT_DHCP;
        let ctx = make_v6_ctx(
            "fe80::".parse().unwrap(),
            "fe80::ffff".parse().unwrap(),
            64, CONTEXT_DHCP,
        );
        let live = LiveAddr6 {
            addr: "fe80::1".parse().unwrap(),
            prefix: 64, if_index: 1, preferred: 100, valid: 100, deprecated: false,
        };
        assert!(complete_context6(&live, &[ctx]).is_empty());
    }

    #[test]
    fn complete_context6_orders_by_preferred_descending() {
        use crate::types::dhcp::{CONTEXT_CONSTRUCTED, CONTEXT_DHCP};
        let ctx_a = make_v6_ctx(
            "2001:db8:1::".parse().unwrap(), "2001:db8:1::ffff".parse().unwrap(),
            64, CONTEXT_DHCP | CONTEXT_CONSTRUCTED,
        );
        let ctx_b = make_v6_ctx(
            "2001:db8:1::".parse().unwrap(), "2001:db8:1::ffff".parse().unwrap(),
            64, CONTEXT_DHCP | CONTEXT_CONSTRUCTED,
        );
        let live = LiveAddr6 {
            addr: "2001:db8:1::1".parse().unwrap(),
            prefix: 64, if_index: 1, preferred: 100, valid: 200, deprecated: false,
        };
        // Both contexts match identically here; verify the chain is built
        // (ordering degenerates to insertion order on ties, matching upstream).
        let chain = complete_context6(&live, &[ctx_a, ctx_b]);
        assert_eq!(chain.len(), 2);
        assert!(chain[0].preferred >= chain[1].preferred);
    }

    // ── dhcp_construct_contexts ───────────────────────────────────────────────

    #[test]
    fn dhcp_construct_contexts_fills_if_index_and_local6() {
        use crate::types::dhcp::CONTEXT_DHCP;
        let ctx = make_v6_ctx(
            "2001:db8::".parse().unwrap(), "2001:db8::ffff".parse().unwrap(),
            64, CONTEXT_DHCP,
        );
        let mut contexts = vec![ctx];
        let live = LiveAddr6 {
            addr: "2001:db8::42".parse().unwrap(),
            prefix: 64, if_index: 7, preferred: 100, valid: 200, deprecated: false,
        };
        dhcp_construct_contexts(&mut contexts, &[live.clone()]);
        assert_eq!(contexts[0].if_index, 7);
        assert_eq!(contexts[0].local6, live.addr);
    }

    #[test]
    fn dhcp_construct_contexts_skips_template_contexts() {
        use crate::types::dhcp::{CONTEXT_DHCP, CONTEXT_TEMPLATE};
        let ctx = make_v6_ctx(
            "2001:db8::".parse().unwrap(), "2001:db8::ffff".parse().unwrap(),
            64, CONTEXT_DHCP | CONTEXT_TEMPLATE,
        );
        let mut contexts = vec![ctx];
        let live = LiveAddr6 {
            addr: "2001:db8::42".parse().unwrap(),
            prefix: 64, if_index: 7, preferred: 100, valid: 200, deprecated: false,
        };
        dhcp_construct_contexts(&mut contexts, &[live]);
        assert_eq!(contexts[0].if_index, 0);
    }

    #[test]
    fn dhcp_construct_contexts_skips_link_local_live_addr() {
        use crate::types::dhcp::CONTEXT_DHCP;
        let ctx = make_v6_ctx(
            "2001:db8::".parse().unwrap(), "2001:db8::ffff".parse().unwrap(),
            64, CONTEXT_DHCP,
        );
        let mut contexts = vec![ctx];
        let live = LiveAddr6 {
            addr: "fe80::1".parse().unwrap(),
            prefix: 64, if_index: 7, preferred: 100, valid: 200, deprecated: false,
        };
        dhcp_construct_contexts(&mut contexts, &[live]);
        assert_eq!(contexts[0].if_index, 0);
    }

    // ── make_duid ─────────────────────────────────────────────────────────────

    #[test]
    fn make_duid_prefers_configured_en() {
        let mut d = Daemon::default();
        d.duid_config = Some(vec![0xAA, 0xBB]);
        d.duid_enterprise = 9;
        make_duid(&mut d, None, true, 1_000_000_000).unwrap();
        let duid = d.duid.unwrap();
        assert_eq!(u16::from_be_bytes([duid[0], duid[1]]), DUID_EN);
        assert_eq!(u32::from_be_bytes([duid[2], duid[3], duid[4], duid[5]]), 9);
        assert_eq!(&duid[6..], &[0xAA, 0xBB]);
    }

    #[test]
    fn make_duid_builds_llt_from_mac_when_stable() {
        let mut d = Daemon::default();
        let mac = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        make_duid(&mut d, Some(DuidMacSource { hw_type: 1, mac: mac.clone() }), true, 1_000_000_000).unwrap();
        let duid = d.duid.unwrap();
        assert_eq!(u16::from_be_bytes([duid[0], duid[1]]), DUID_LLT);
        assert_eq!(u16::from_be_bytes([duid[2], duid[3]]), 1);
        assert_eq!(&duid[8..], &mac[..]);
    }

    #[test]
    fn make_duid_builds_ll_when_not_stable() {
        let mut d = Daemon::default();
        let mac = vec![0xAA; 6];
        make_duid(&mut d, Some(DuidMacSource { hw_type: 1, mac: mac.clone() }), false, 0).unwrap();
        let duid = d.duid.unwrap();
        assert_eq!(u16::from_be_bytes([duid[0], duid[1]]), DUID_LL);
        assert_eq!(duid.len(), 4 + mac.len());
    }

    #[test]
    fn make_duid_errs_without_config_or_mac() {
        let mut d = Daemon::default();
        assert!(make_duid(&mut d, None, true, 0).is_err());
        assert!(d.duid.is_none());
    }

    #[test]
    fn make_duid_skips_high_hw_type() {
        let mut d = Daemon::default();
        let mac = vec![0x01; 6];
        let err = make_duid(&mut d, Some(DuidMacSource { hw_type: 300, mac }), true, 0);
        assert!(err.is_err());
    }

    #[test]
    fn make_duid_is_stable_across_calls() {
        let mut d = Daemon::default();
        let mac = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        make_duid(&mut d, Some(DuidMacSource { hw_type: 1, mac: mac.clone() }), true, 1_000_000_000).unwrap();
        let first = d.duid.clone();
        make_duid(&mut d, Some(DuidMacSource { hw_type: 1, mac }), true, 1_000_000_000).unwrap();
        assert_eq!(d.duid, first);
    }

    // ── dispatch_dhcp6 (stateful) ─────────────────────────────────────────────

    #[test]
    fn dispatch_dhcp6_solicit_returns_advertise_with_allocated_address() {
        use crate::types::dhcp::CONTEXT_DHCP;
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, CONTEXT_DHCP,
        );
        let data = solicit_with_ia(0x1234, [0, 0, 0, 1]);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03, 0x00, 0x01, 1, 2, 3, 4, 5, 6];
        let mut in_use = |_: &Ipv6Addr| false;

        let reply = dispatch_dhcp6(&pkt, &duid, &[ctx], &mut in_use).unwrap();
        assert_eq!(reply.msg_type, Dhcp6MsgType::Advertise);
        assert_eq!(reply.xid, 0x1234);

        assert_eq!(find_option6(&reply.options, OPTION6_SERVER_ID), Some(duid.as_slice()));

        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        assert!(ia_data.len() > 12);
        let suboptions = &ia_data[12..];
        let iaaddr = find_option6(suboptions, OPTION6_IAADDR).expect("IAADDR sub-option present");
        assert_eq!(iaaddr.len(), 24);
        let addr = Ipv6Addr::from(<[u8; 16]>::try_from(&iaaddr[0..16]).unwrap());
        assert!(is_same_net6(&addr, &"2001:db8::1".parse().unwrap(), 64));
    }

    #[test]
    fn dispatch_dhcp6_solicit_no_context_reports_no_addrs_available() {
        let data = solicit_with_ia(0x1, [0, 0, 0, 1]);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03];
        let mut in_use = |_: &Ipv6Addr| false;

        let reply = dispatch_dhcp6(&pkt, &duid, &[], &mut in_use).unwrap();
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        let suboptions = &ia_data[12..];
        assert!(find_option6(suboptions, OPTION6_STATUS_CODE).is_some());
        assert!(find_option6(suboptions, OPTION6_IAADDR).is_none());
    }

    #[test]
    fn dispatch_dhcp6_request_returns_reply_with_allocated_address() {
        use crate::types::dhcp::CONTEXT_DHCP;
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, CONTEXT_DHCP,
        );
        let mut data = solicit_with_ia(0x99, [0, 0, 0, 2]);
        data[0] = Dhcp6MsgType::Request as u8;
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03, 0x00, 0x01, 1, 2, 3, 4, 5, 6];
        let mut in_use = |_: &Ipv6Addr| false;

        let reply = dispatch_dhcp6(&pkt, &duid, &[ctx], &mut in_use).unwrap();
        assert_eq!(reply.msg_type, Dhcp6MsgType::Reply);
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        assert!(find_option6(&ia_data[12..], OPTION6_IAADDR).is_some());
    }

    // ── dhcp6_init ────────────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn dhcp6_init_binds_port_547_or_skips_without_privilege() {
        match dhcp6_init(false) {
            Ok(fd) => unsafe { libc::close(fd); },
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(err) => panic!("dhcp6_init failed unexpectedly: {err}"),
        }
    }

    // ── run_dhcp6_loop ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn run_dhcp6_loop_solicit_gets_advertise_with_allocated_address() {
        let server = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        client.connect(server.local_addr().unwrap()).await.unwrap();

        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, crate::types::dhcp::CONTEXT_DHCP,
        );
        let duid = vec![0x00, 0x03, 0x00, 0x01, 1, 2, 3, 4, 5, 6];
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = std::sync::Arc::new(server);
        let loop_task = tokio::spawn(run_dhcp6_loop(
            server.clone(), duid, vec![ctx], vec![],
            crate::lease::LeaseDb::new(), shutdown_rx,
            Some(client.local_addr().unwrap().port()),
        ));

        client.send(&solicit_with_ia(0xABCD, [0, 0, 0, 7])).await.unwrap();

        let mut buf = [0u8; 512];
        let len = tokio::time::timeout(std::time::Duration::from_millis(500), client.recv(&mut buf))
            .await
            .expect("timed out waiting for DHCPv6 loop reply")
            .unwrap();
        let reply = parse_dhcp6_packet(&buf[..len]).unwrap();
        assert_eq!(reply.msg_type, Dhcp6MsgType::Advertise);
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        assert!(find_option6(&ia_data[12..], OPTION6_IAADDR).is_some());

        shutdown_tx.send(true).unwrap();
        loop_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_dhcp6_loop_request_commits_lease_so_second_client_is_refused() {
        let server = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        client.connect(server.local_addr().unwrap()).await.unwrap();

        // Single-address pool: only one address to ever hand out.
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::1".parse().unwrap(),
            128, crate::types::dhcp::CONTEXT_DHCP,
        );
        let duid = vec![0x00, 0x03, 0x00, 0x01, 1, 2, 3, 4, 5, 6];
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = std::sync::Arc::new(server);
        let loop_task = tokio::spawn(run_dhcp6_loop(
            server.clone(), duid, vec![ctx], vec![],
            crate::lease::LeaseDb::new(), shutdown_rx,
            Some(client.local_addr().unwrap().port()),
        ));

        let mut req1 = solicit_with_ia(1, [0, 0, 0, 1]);
        req1[0] = Dhcp6MsgType::Request as u8;
        client.send(&req1).await.unwrap();
        let mut buf = [0u8; 512];
        let len1 = tokio::time::timeout(std::time::Duration::from_millis(500), client.recv(&mut buf))
            .await
            .expect("timed out on first reply")
            .unwrap();
        let reply1 = parse_dhcp6_packet(&buf[..len1]).unwrap();
        let ia1 = find_option6(&reply1.options, OPTION6_IA_NA).unwrap();
        assert!(
            find_option6(&ia1[12..], OPTION6_IAADDR).is_some(),
            "first client should get the only address in the pool"
        );

        let mut req2 = solicit_with_ia(2, [0, 0, 0, 2]);
        req2[0] = Dhcp6MsgType::Request as u8;
        client.send(&req2).await.unwrap();
        let len2 = tokio::time::timeout(std::time::Duration::from_millis(500), client.recv(&mut buf))
            .await
            .expect("timed out on second reply")
            .unwrap();
        let reply2 = parse_dhcp6_packet(&buf[..len2]).unwrap();
        let ia2 = find_option6(&reply2.options, OPTION6_IA_NA).unwrap();
        assert!(
            find_option6(&ia2[12..], OPTION6_IAADDR).is_none(),
            "second client must be refused: the loop should have committed the first lease"
        );
        assert!(find_option6(&ia2[12..], OPTION6_STATUS_CODE).is_some());

        shutdown_tx.send(true).unwrap();
        loop_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_dhcp6_loop_stops_on_shutdown_signal() {
        let server = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = std::sync::Arc::new(server);
        let loop_task = tokio::spawn(run_dhcp6_loop(
            server, vec![], vec![], vec![],
            crate::lease::LeaseDb::new(), shutdown_rx, None,
        ));

        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_millis(500), loop_task)
            .await
            .expect("loop did not stop after shutdown signal")
            .unwrap()
            .unwrap();
    }
}

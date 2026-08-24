//! SLAAC (Stateless Address Auto-Configuration) address synthesis, lease
//! tracking, and ICMPv6 DAD (liveness) probing.
//! Ported from `slaac.c`.

#[cfg(feature = "dhcp6")]
use std::net::Ipv6Addr;

/// Derive an EUI-64 interface identifier from a 48-bit MAC address.
///
/// Per RFC 4291 Appendix A: insert `0xFF 0xFE` in the middle and flip bit 6
/// (the "universal/local" bit) of the first byte.
#[cfg(feature = "dhcp6")]
pub fn eui64_from_mac(mac: &[u8; 6]) -> [u8; 8] {
    [
        mac[0] ^ 0x02, // flip U/L bit
        mac[1],
        mac[2],
        0xFF,
        0xFE,
        mac[3],
        mac[4],
        mac[5],
    ]
}

/// Build a SLAAC address from a prefix and a MAC address (EUI-64 method).
///
/// The host portion (low 128 − `prefix_len` bits) is derived from the MAC
/// via [`eui64_from_mac`]; the prefix portion is taken from `prefix`.
/// Only prefix lengths that are multiples of 8 and ≤ 64 are fully supported.
#[cfg(feature = "dhcp6")]
pub fn slaac_address(prefix: Ipv6Addr, prefix_len: u8, mac: &[u8; 6]) -> Ipv6Addr {
    let eui = eui64_from_mac(mac);
    let pfx = prefix.octets();

    // Number of complete prefix bytes
    let pfx_bytes = (prefix_len / 8) as usize;
    // Remaining prefix bits in the boundary byte (if any)
    let pfx_bits  = (prefix_len % 8) as u32;

    let mut octets = [0u8; 16];

    // Copy prefix bytes
    for i in 0..pfx_bytes.min(16) {
        octets[i] = pfx[i];
    }

    // Handle the boundary byte (mix prefix bits and EUI-64 bits)
    if pfx_bytes < 16 && pfx_bits > 0 {
        let mask        = 0xFFu8.wrapping_shl(8 - pfx_bits);
        let eui_byte    = if pfx_bytes >= 8 { 0u8 } else { eui[pfx_bytes.max(8) - 8] };
        let eui_idx     = pfx_bytes; // index into the 16-byte result
        let eui_src_idx = if pfx_bytes >= 8 { pfx_bytes - 8 } else { pfx_bytes };
        let src_eui     = if pfx_bytes < 8 { eui[eui_src_idx] } else { eui_byte };
        octets[eui_idx] = (pfx[pfx_bytes] & mask) | (src_eui & !mask);
    }

    // Fill the host portion from EUI-64 (right-aligned into the last 8 bytes)
    // For the standard /64 case this is straightforward.
    let host_start = pfx_bytes + if pfx_bits > 0 { 1 } else { 0 };
    for i in host_start..16 {
        // offset into eui: the last 8 bytes of the address are the EUI-64
        let eui_offset = i.saturating_sub(8);
        if i >= 8 {
            octets[i] = eui[eui_offset];
        }
    }

    Ipv6Addr::from(octets)
}

// ─────────────────────────────────────────────────────────────────────────────
// slaac_add_addrs (slaac.c:25-116)
// ─────────────────────────────────────────────────────────────────────────────

use crate::types::dhcp::{
    ContextFlags, LEASE_HAVE_HWADDR, LEASE_TA, LEASE_NA,
    DhcpContext, DhcpLease, SlaacAddress,
};

#[cfg(feature = "dhcp6")]
const ARPHRD_ETHER: i32 = 1;
#[cfg(feature = "dhcp6")]
const ARPHRD_IEEE802: i32 = 6;
#[cfg(feature = "dhcp6")]
const ARPHRD_IEEE1394: i32 = 24;
#[cfg(feature = "dhcp6")]
const ARPHRD_EUI64: i32 = 27;

/// Derive the 8-byte SLAAC host identifier for a lease's hardware address,
/// mirroring the three branches of `slaac_add_addrs()` (slaac.c:45-70):
/// a 6-byte Ethernet MAC (EUI-64 synthesis), a raw 8-byte EUI-64 hardware
/// address, or (FireWire) an EUI-64 carried in the client-id. In every case
/// the universal/local bit of the first byte is flipped (`^= 0x02`,
/// slaac.c:70), applied once here rather than per-branch to match upstream's
/// single post-`else` XOR.
#[cfg(feature = "dhcp6")]
fn derive_slaac_host_id(lease: &DhcpLease) -> Option<[u8; 8]> {
    if lease.hwaddr_len == 6
        && (lease.hwaddr_type == ARPHRD_ETHER || lease.hwaddr_type == ARPHRD_IEEE802)
    {
        let mac = &lease.hwaddr[..6];
        let mut id = [mac[0], mac[1], mac[2], 0xff, 0xfe, mac[3], mac[4], mac[5]];
        id[0] ^= 0x02;
        return Some(id);
    }

    if lease.hwaddr_len == 8 && lease.hwaddr_type == ARPHRD_EUI64 {
        let mut id = [0u8; 8];
        id.copy_from_slice(&lease.hwaddr[..8]);
        id[0] ^= 0x02;
        return Some(id);
    }

    if let Some(clid) = &lease.clid {
        if clid.len() == 9
            && clid[0] == ARPHRD_EUI64 as u8
            && lease.hwaddr_type == ARPHRD_IEEE1394
        {
            let mut id = [0u8; 8];
            id.copy_from_slice(&clid[1..9]);
            id[0] ^= 0x02;
            return Some(id);
        }
    }

    None
}

/// Recompute the SLAAC addresses for `lease` against `contexts` (the current
/// `daemon->dhcp6` RA-name chain), mutating `lease.slaac_address` in place.
///
/// Port of `slaac_add_addrs()` (slaac.c:25-116). For every context with
/// `CONTEXT_RA_NAME` set (and not `CONTEXT_OLD`) on the lease's interface,
/// derives a candidate address and either reuses the matching existing entry
/// (resetting its probe state when `force` is set, matching the "recheck
/// when DHCPv4 goes through init-reboot" comment at slaac.c:78) or creates a
/// new one and invokes `ra_start_unsolicited` to prod an RA out — the
/// production callback for that is still a no-op (see `tasks.md`: RA
/// scheduling itself has no main-loop caller yet either). Entries that no
/// longer match any context are dropped. Returns whether anything changed
/// (the `lease_update_dns(1)` trigger upstream fires from `old || dns_dirty`).
#[cfg(feature = "dhcp6")]
pub fn slaac_add_addrs(
    lease: &mut DhcpLease,
    now: std::time::SystemTime,
    force: bool,
    contexts: &[DhcpContext],
    mut ra_start_unsolicited: impl FnMut(&DhcpContext),
) -> bool {
    if lease.flags & LEASE_HAVE_HWADDR == 0
        || lease.flags & (LEASE_TA | LEASE_NA) != 0
        || lease.last_interface == 0
        || lease.hostname.is_none()
    {
        return false;
    }

    let mut old = std::mem::take(&mut lease.slaac_address);
    let mut dns_dirty = false;

    for ctx in contexts {
        if !ctx.flags.contains(ContextFlags::RA_NAME) || ctx.flags.contains(ContextFlags::OLD) {
            continue;
        }
        if lease.last_interface != ctx.if_index {
            continue;
        }

        let Some(host_id) = derive_slaac_host_id(lease) else {
            continue;
        };

        let prefix = ctx.start6.octets();
        let mut octets = [0u8; 16];
        octets[..8].copy_from_slice(&prefix[..8]);
        octets[8..].copy_from_slice(&host_id);
        let addr = Ipv6Addr::from(octets);

        let entry = match old.iter().position(|s| s.addr == addr) {
            Some(idx) => {
                let mut existing = old.remove(idx);
                if force {
                    existing.ping_time = Some(now);
                    existing.backoff = 1;
                    dns_dirty = true;
                }
                existing
            }
            None => {
                ra_start_unsolicited(ctx);
                SlaacAddress {
                    addr,
                    ping_time: Some(now),
                    backoff: 1,
                }
            }
        };

        lease.slaac_address.push(entry);
    }

    dns_dirty || !old.is_empty()
}

// ─────────────────────────────────────────────────────────────────────────────
// periodic_slaac / slaac_ping_reply (slaac.c:119-213)
// ─────────────────────────────────────────────────────────────────────────────

/// ICMPv6 echo request type (RFC 4443 §4.1).
#[cfg(feature = "dhcp6")]
pub const ICMP6_ECHO_REQUEST: u8 = 128;
/// ICMPv6 echo reply type (RFC 4443 §4.2).
#[cfg(feature = "dhcp6")]
pub const ICMP6_ECHO_REPLY: u8 = 129;

/// Build the 8-byte `struct ping_packet` wire format (ping.h): type, code,
/// checksum (left zero — Linux raw ICMPv6 sockets fill it in on send),
/// identifier, sequence number.
#[cfg(feature = "dhcp6")]
pub fn build_ping_packet(ping_id: u16, seq: u16) -> [u8; 8] {
    let id = ping_id.to_be_bytes();
    let sq = seq.to_be_bytes();
    [ICMP6_ECHO_REQUEST, 0, 0, 0, id[0], id[1], sq[0], sq[1]]
}

/// Parse a `struct ping_packet`, returning `(type, code, identifier, seq)`.
#[cfg(feature = "dhcp6")]
pub fn parse_ping_packet(data: &[u8]) -> Option<(u8, u8, u16, u16)> {
    if data.len() < 8 {
        return None;
    }
    let identifier = u16::from_be_bytes([data[4], data[5]]);
    let seq = u16::from_be_bytes([data[6], data[7]]);
    Some((data[0], data[1], identifier, seq))
}

/// Run one tick of SLAAC DAD probing across `leases` (`periodic_slaac`,
/// slaac.c:119-190).
///
/// Returns `None` immediately if no context has `CONTEXT_RA_NAME` set
/// (slaac.c:126-132: "nothing configured"). Otherwise, for every
/// [`SlaacAddress`] whose `ping_time` is due, calls `send` with an ICMPv6
/// echo-request packet; on an `EHOSTUNREACH` error at the maximum backoff
/// (12), the entry is marked given-up (`ping_time = None`) exactly as
/// upstream sets `ping_time = 0`, matching slaac.c:169-171. Otherwise the
/// next probe time is rescheduled with the same exponential-backoff +
/// jitter formula as slaac.c:174-178. Returns the earliest still-pending
/// `ping_time` across all leases, or `None` if nothing is outstanding.
#[cfg(feature = "dhcp6")]
pub fn periodic_slaac<'a>(
    now: std::time::SystemTime,
    contexts: &[DhcpContext],
    leases: impl Iterator<Item = &'a mut DhcpLease>,
    ping_id: u16,
    mut send: impl FnMut(Ipv6Addr, &[u8]) -> std::io::Result<()>,
) -> Option<std::time::SystemTime> {
    let configured = contexts
        .iter()
        .any(|c| c.flags.contains(ContextFlags::RA_NAME) && !c.flags.contains(ContextFlags::OLD));
    if !configured {
        return None;
    }

    let mut next_event: Option<std::time::SystemTime> = None;

    for lease in leases {
        for slaac in lease.slaac_address.iter_mut() {
            if slaac.backoff == 0 {
                continue;
            }
            let Some(ping_time) = slaac.ping_time else {
                continue;
            };

            if ping_time <= now {
                let packet = build_ping_packet(ping_id, slaac.backoff as u16);
                let result = send(slaac.addr, &packet);

                let host_unreachable_at_max = matches!(
                    &result,
                    Err(e) if e.raw_os_error() == Some(libc::EHOSTUNREACH)
                ) && slaac.backoff == 12;

                if host_unreachable_at_max {
                    slaac.ping_time = None; // give up
                } else {
                    let mut delay_secs = (1u64 << (slaac.backoff - 1))
                        + (crate::util::rand16() / 21785) as u64;
                    if slaac.backoff > 4 {
                        delay_secs += (crate::util::rand16() / 4000) as u64;
                    }
                    slaac.ping_time = Some(ping_time + std::time::Duration::from_secs(delay_secs));
                    if slaac.backoff < 12 {
                        slaac.backoff += 1;
                    }
                }
            }

            if let Some(pt) = slaac.ping_time {
                if next_event.is_none() || next_event.is_some_and(|ne| ne >= pt) {
                    next_event = Some(pt);
                }
            }
        }
    }

    next_event
}

/// Handle an inbound ICMPv6 echo reply for SLAAC DAD confirmation
/// (`slaac_ping_reply`, slaac.c:191-213).
///
/// If `packet`'s identifier matches `ping_id`, finds every outstanding
/// (`backoff != 0`) [`SlaacAddress`] across `leases` whose address equals
/// `sender`, marks it confirmed (`backoff = 0`), and logs `SLAAC-CONFIRM`
/// (unless `quiet`). Returns whether anything was confirmed — callers should
/// treat that the same way upstream's `lease_update_dns(gotone)` does (i.e.
/// mark DNS records dirty).
#[cfg(feature = "dhcp6")]
pub fn slaac_ping_reply<'a>(
    sender: Ipv6Addr,
    packet: &[u8],
    ping_id: u16,
    interface: &str,
    quiet: bool,
    leases: impl Iterator<Item = &'a mut DhcpLease>,
) -> bool {
    let Some((_type, _code, identifier, _seq)) = parse_ping_packet(packet) else {
        return false;
    };
    if identifier != ping_id {
        return false;
    }

    let mut gotone = false;
    for lease in leases {
        for slaac in lease.slaac_address.iter_mut() {
            if slaac.backoff != 0 && slaac.addr == sender {
                slaac.backoff = 0;
                gotone = true;
                if !quiet {
                    tracing::info!(
                        "SLAAC-CONFIRM({}) {} {}",
                        interface,
                        sender,
                        lease.hostname.as_deref().unwrap_or("")
                    );
                }
            }
        }
    }
    gotone
}

// ─────────────────────────────────────────────────────────────────────────────
// Real ICMPv6 raw socket (send/receive side of the DAD probe loop)
// ─────────────────────────────────────────────────────────────────────────────

/// A raw ICMPv6 socket used to send/receive SLAAC DAD probes.
///
/// Opening this requires `CAP_NET_RAW` (or root); [`Icmp6Socket::create`]
/// returns `Err` rather than panicking when the process lacks it, so callers
/// can disable DAD probing gracefully instead of failing DHCPv6 startup —
/// "DAD probing works where permissions allow" per the acceptance criteria,
/// not "DAD probing is mandatory".
#[cfg(all(feature = "dhcp6", unix))]
pub struct Icmp6Socket {
    inner: tokio::io::unix::AsyncFd<socket2::Socket>,
}

#[cfg(all(feature = "dhcp6", unix))]
impl Icmp6Socket {
    pub fn create() -> std::io::Result<Self> {
        use socket2::{Domain, Protocol, Socket, Type};
        let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: tokio::io::unix::AsyncFd::new(socket)?,
        })
    }

    /// Synchronous send, matching upstream's plain (non-blocking-aware)
    /// `sendto()` call at slaac.c:167 — a single small ICMPv6 datagram never
    /// blocks in practice, and any error (including `EWOULDBLOCK`) is simply
    /// surfaced to [`periodic_slaac`]'s backoff/give-up logic, same as
    /// upstream tolerating any `sendto` failure other than the
    /// `EHOSTUNREACH`-at-max-backoff give-up case.
    pub fn send_echo_sync(&self, dest: Ipv6Addr, packet: &[u8]) -> std::io::Result<()> {
        let addr = std::net::SocketAddr::new(std::net::IpAddr::V6(dest), 0);
        let sock_addr: socket2::SockAddr = addr.into();
        self.inner.get_ref().send_to(packet, &sock_addr).map(|_| ())
    }

    /// Receive one ICMPv6 datagram, returning its payload length and sender.
    pub async fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, Ipv6Addr)> {
        loop {
            let mut guard = self.inner.readable().await?;
            // Safe: `MaybeUninit<u8>` has the same layout as `u8`, and `buf`
            // is already fully initialized, so relaxing its init guarantee
            // for this call is sound.
            let buf_uninit: &mut [std::mem::MaybeUninit<u8>] =
                unsafe { &mut *(buf as *mut [u8] as *mut [std::mem::MaybeUninit<u8>]) };
            match guard.try_io(|inner| inner.get_ref().recv_from(buf_uninit)) {
                Ok(Ok((n, addr))) => {
                    let ip = addr
                        .as_socket_ipv6()
                        .map(|s| *s.ip())
                        .unwrap_or(Ipv6Addr::UNSPECIFIED);
                    return Ok((n, ip));
                }
                Ok(Err(e)) => return Err(e),
                Err(_would_block) => continue,
            }
        }
    }
}

#[cfg(all(test, feature = "dhcp6"))]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;
    use std::time::{Duration, SystemTime};

    // Sample MAC and its expected EUI-64 (RFC 4291 example)
    const MAC: [u8; 6] = [0x00, 0x60, 0x97, 0x00, 0x28, 0x4C]; // from RFC 4291 App.A

    #[test]
    fn eui64_flips_bit6() {
        // Bit 6 of byte 0: 0x00 → 0x02 (U/L bit flipped)
        let eui = eui64_from_mac(&[0x00, 0x1A, 0x2B, 0x3C, 0x4D, 0x5E]);
        assert_eq!(eui[0], 0x02, "U/L bit should be flipped for universally administered MAC");
        assert_eq!(eui[3], 0xFF);
        assert_eq!(eui[4], 0xFE);
        assert_eq!(eui[5], 0x3C);
        assert_eq!(eui[6], 0x4D);
        assert_eq!(eui[7], 0x5E);
    }

    #[test]
    fn eui64_locally_administered_bit() {
        // For a locally-administered MAC (bit 6 = 1) the bit is flipped to 0
        let eui = eui64_from_mac(&[0x02, 0x00, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(eui[0], 0x00, "U/L bit should be cleared for locally administered MAC");
    }

    #[test]
    fn eui64_rfc4291_example() {
        // RFC 4291 Appendix A: MAC 00-60-97-00-28-4C → EUI-64 02-60-97-FF-FE-00-28-4C
        let eui = eui64_from_mac(&MAC);
        assert_eq!(eui, [0x02, 0x60, 0x97, 0xFF, 0xFE, 0x00, 0x28, 0x4C]);
    }

    #[test]
    fn slaac_address_uses_correct_prefix() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let addr = slaac_address(prefix, 64, &MAC);
        let octets = addr.octets();
        // First 8 bytes must match prefix
        assert_eq!(&octets[0..8], &prefix.octets()[0..8]);
        // Last 8 bytes must be the EUI-64
        let eui = eui64_from_mac(&MAC);
        assert_eq!(&octets[8..16], &eui);
    }

    // ── slaac_add_addrs ─────────────────────────────────────────────────────

    fn make_ra_ctx(start6: Ipv6Addr, if_index: i32) -> DhcpContext {
        use std::net::Ipv4Addr;
        DhcpContext {
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            flags: ContextFlags::RA_NAME,
            netmask: Ipv4Addr::UNSPECIFIED,
            broadcast: Ipv4Addr::UNSPECIFIED,
            local: Ipv4Addr::UNSPECIFIED,
            lease_time: 0,
            addr_epoch: 0,
            netid: crate::types::dhcp::DhcpNetid { net: String::new() },
            filter: vec![],
            start6,
            end6: Ipv6Addr::UNSPECIFIED,
            local6: Ipv6Addr::UNSPECIFIED,
            prefix: 64,
            if_index,
            valid: 0,
            preferred: 0,
            ra_time: 0,
            ra_short_period_start: 0,
            saved_valid: 0,
            address_lost_time: 0,
        }
    }

    fn make_lease(hwaddr: [u8; 6], if_index: i32, hostname: Option<&str>) -> DhcpLease {
        let mut hw = [0u8; crate::dhcp_protocol::DHCP_CHADDR_MAX];
        hw[..6].copy_from_slice(&hwaddr);
        DhcpLease {
            clid: None,
            hostname: hostname.map(|s| s.to_string()),
            fqdn: None,
            old_hostname: None,
            flags: LEASE_HAVE_HWADDR,
            expires: None,
            hwaddr: hw,
            hwaddr_len: 6,
            hwaddr_type: ARPHRD_ETHER,
            addr: std::net::Ipv4Addr::UNSPECIFIED,
            giaddr: std::net::Ipv4Addr::UNSPECIFIED,
            extradata: Vec::new(),
            last_interface: if_index,
            new_interface: 0,
            new_prefixlen: 0,
            agent_id: None,
            vendorclass: None,
            addr6: Ipv6Addr::UNSPECIFIED,
            iaid: 0,
            slaac_address: Vec::new(),
            vendorclass_count: 0,
        }
    }

    #[test]
    fn slaac_add_addrs_generates_from_context() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        let now = SystemTime::now();
        let dirty = slaac_add_addrs(&mut lease, now, false, std::slice::from_ref(&ctx), |_| {});
        // Upstream's own `old || dns_dirty` check is false on the very first
        // population (there was nothing to remove, and `force` is false) —
        // slaac.c:107 only fires `lease_update_dns(1)` for removals or a
        // forced reset, not for brand-new entries.
        assert!(!dirty);
        assert_eq!(lease.slaac_address.len(), 1);
        assert_eq!(lease.slaac_address[0].addr, slaac_address("2001:db8::".parse().unwrap(), 64, &MAC));
        assert_eq!(lease.slaac_address[0].backoff, 1);
        assert_eq!(lease.slaac_address[0].ping_time, Some(now));
    }

    #[test]
    fn slaac_add_addrs_calls_ra_trigger_only_for_new_addrs() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        let now = SystemTime::now();

        let mut triggered = 0;
        slaac_add_addrs(&mut lease, now, false, std::slice::from_ref(&ctx), |_| triggered += 1);
        assert_eq!(triggered, 1);

        // Second call with the same context/hwaddr: address already exists,
        // no new RA trigger, and not dirty (force=false).
        let mut triggered2 = 0;
        let dirty = slaac_add_addrs(&mut lease, now, false, std::slice::from_ref(&ctx), |_| triggered2 += 1);
        assert_eq!(triggered2, 0);
        assert!(!dirty);
        assert_eq!(lease.slaac_address.len(), 1);
    }

    #[test]
    fn slaac_add_addrs_force_resets_existing_entry() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        let t0 = SystemTime::now();
        slaac_add_addrs(&mut lease, t0, false, std::slice::from_ref(&ctx), |_| {});
        lease.slaac_address[0].backoff = 7; // simulate some probing having happened

        let t1 = t0 + Duration::from_secs(60);
        let dirty = slaac_add_addrs(&mut lease, t1, true, std::slice::from_ref(&ctx), |_| {});
        assert!(dirty);
        assert_eq!(lease.slaac_address.len(), 1);
        assert_eq!(lease.slaac_address[0].backoff, 1);
        assert_eq!(lease.slaac_address[0].ping_time, Some(t1));
    }

    #[test]
    fn slaac_add_addrs_drops_stale_entries() {
        let ctx1 = make_ra_ctx("2001:db8:1::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        let now = SystemTime::now();
        slaac_add_addrs(&mut lease, now, false, std::slice::from_ref(&ctx1), |_| {});
        assert_eq!(lease.slaac_address.len(), 1);

        // Context list no longer contains ctx1 (e.g. prefix renumbered away).
        let ctx2 = make_ra_ctx("2001:db8:2::".parse().unwrap(), 1);
        let dirty = slaac_add_addrs(&mut lease, now, false, std::slice::from_ref(&ctx2), |_| {});
        assert!(dirty);
        assert_eq!(lease.slaac_address.len(), 1);
        assert_eq!(lease.slaac_address[0].addr, slaac_address("2001:db8:2::".parse().unwrap(), 64, &MAC));
    }

    #[test]
    fn slaac_add_addrs_skips_wrong_interface() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 2);
        let mut lease = make_lease(MAC, 1, Some("host"));
        let dirty = slaac_add_addrs(&mut lease, SystemTime::now(), false, std::slice::from_ref(&ctx), |_| {});
        assert!(!dirty);
        assert!(lease.slaac_address.is_empty());
    }

    #[test]
    fn slaac_add_addrs_skips_no_hwaddr_flag() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        lease.flags = 0; // no LEASE_HAVE_HWADDR
        let dirty = slaac_add_addrs(&mut lease, SystemTime::now(), false, std::slice::from_ref(&ctx), |_| {});
        assert!(!dirty);
        assert!(lease.slaac_address.is_empty());
    }

    #[test]
    fn slaac_add_addrs_skips_ta_na() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        lease.flags |= LEASE_NA;
        let dirty = slaac_add_addrs(&mut lease, SystemTime::now(), false, std::slice::from_ref(&ctx), |_| {});
        assert!(!dirty);
        assert!(lease.slaac_address.is_empty());
    }

    #[test]
    fn slaac_add_addrs_skips_old_context() {
        let mut ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        ctx.flags.insert(ContextFlags::OLD);
        let mut lease = make_lease(MAC, 1, Some("host"));
        let dirty = slaac_add_addrs(&mut lease, SystemTime::now(), false, std::slice::from_ref(&ctx), |_| {});
        assert!(!dirty);
        assert!(lease.slaac_address.is_empty());
    }

    #[test]
    fn slaac_add_addrs_skips_no_hostname() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, None);
        let dirty = slaac_add_addrs(&mut lease, SystemTime::now(), false, std::slice::from_ref(&ctx), |_| {});
        assert!(!dirty);
        assert!(lease.slaac_address.is_empty());
    }

    #[test]
    fn slaac_add_addrs_skips_zero_interface() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 0);
        let mut lease = make_lease(MAC, 0, Some("host"));
        let dirty = slaac_add_addrs(&mut lease, SystemTime::now(), false, std::slice::from_ref(&ctx), |_| {});
        assert!(!dirty);
        assert!(lease.slaac_address.is_empty());
    }

    #[test]
    fn slaac_add_addrs_multiple_contexts() {
        let ctx1 = make_ra_ctx("2001:db8:1::".parse().unwrap(), 1);
        let ctx2 = make_ra_ctx("2001:db8:2::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        slaac_add_addrs(&mut lease, SystemTime::now(), false, &[ctx1, ctx2], |_| {});
        assert_eq!(lease.slaac_address.len(), 2);
    }

    #[test]
    fn slaac_add_addrs_eui64_hwaddr_type() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        // Switch to a raw 8-byte EUI-64 hardware address.
        let raw_eui = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        lease.hwaddr[..8].copy_from_slice(&raw_eui);
        lease.hwaddr_len = 8;
        lease.hwaddr_type = ARPHRD_EUI64;

        slaac_add_addrs(&mut lease, SystemTime::now(), false, std::slice::from_ref(&ctx), |_| {});
        assert_eq!(lease.slaac_address.len(), 1);
        let octets = lease.slaac_address[0].addr.octets();
        let mut expect = raw_eui;
        expect[0] ^= 0x02;
        assert_eq!(&octets[8..16], &expect);
    }

    #[test]
    fn slaac_add_addrs_ieee1394_clid() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        lease.hwaddr_len = 0;
        lease.hwaddr_type = ARPHRD_IEEE1394;
        let mut clid = vec![ARPHRD_EUI64 as u8];
        clid.extend_from_slice(&[0x02, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77]);
        lease.clid = Some(clid);

        slaac_add_addrs(&mut lease, SystemTime::now(), false, std::slice::from_ref(&ctx), |_| {});
        assert_eq!(lease.slaac_address.len(), 1);
        let octets = lease.slaac_address[0].addr.octets();
        let mut expect = [0x02u8, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
        expect[0] ^= 0x02;
        assert_eq!(&octets[8..16], &expect);
    }

    #[test]
    fn slaac_add_addrs_unsupported_hwaddr_skipped() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        lease.hwaddr_len = 4; // neither 6 nor 8 bytes, and no clid fallback
        let dirty = slaac_add_addrs(&mut lease, SystemTime::now(), false, std::slice::from_ref(&ctx), |_| {});
        assert!(!dirty);
        assert!(lease.slaac_address.is_empty());
    }

    // ── ping packet wire format ──────────────────────────────────────────────

    #[test]
    fn ping_packet_roundtrip() {
        let packet = build_ping_packet(0xABCD, 7);
        let (ty, code, id, seq) = parse_ping_packet(&packet).unwrap();
        assert_eq!(ty, ICMP6_ECHO_REQUEST);
        assert_eq!(code, 0);
        assert_eq!(id, 0xABCD);
        assert_eq!(seq, 7);
    }

    #[test]
    fn parse_ping_packet_too_short() {
        assert!(parse_ping_packet(&[1, 2, 3]).is_none());
    }

    // ── periodic_slaac ───────────────────────────────────────────────────────

    #[test]
    fn periodic_slaac_nothing_configured_returns_none() {
        let mut lease = make_lease(MAC, 1, Some("host"));
        lease.slaac_address.push(SlaacAddress {
            addr: "2001:db8::1".parse().unwrap(),
            ping_time: Some(SystemTime::now()),
            backoff: 1,
        });
        let next = periodic_slaac(SystemTime::now(), &[], std::iter::once(&mut lease), 1234, |_, _| Ok(()));
        assert!(next.is_none());
    }

    #[test]
    fn periodic_slaac_sends_due_probe_and_advances_backoff() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        let now = SystemTime::now();
        lease.slaac_address.push(SlaacAddress {
            addr: "2001:db8::1".parse().unwrap(),
            ping_time: Some(now),
            backoff: 1,
        });

        let mut sent = Vec::new();
        let next = periodic_slaac(now, std::slice::from_ref(&ctx), std::iter::once(&mut lease), 42, |addr, pkt| {
            sent.push((addr, pkt.to_vec()));
            Ok(())
        });

        assert_eq!(sent.len(), 1);
        let (_ty, _code, id, seq) = parse_ping_packet(&sent[0].1).unwrap();
        assert_eq!(id, 42);
        assert_eq!(seq, 1); // old backoff value used as sequence_no
        assert_eq!(lease.slaac_address[0].backoff, 2);
        assert!(next.is_some());
        assert!(next.unwrap() > now);
        assert_eq!(next, lease.slaac_address[0].ping_time);
    }

    #[test]
    fn periodic_slaac_skips_confirmed_entries() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        let now = SystemTime::now();
        lease.slaac_address.push(SlaacAddress {
            addr: "2001:db8::1".parse().unwrap(),
            ping_time: Some(now),
            backoff: 0, // confirmed
        });

        let mut sent = 0;
        let next = periodic_slaac(now, std::slice::from_ref(&ctx), std::iter::once(&mut lease), 42, |_, _| {
            sent += 1;
            Ok(())
        });
        assert_eq!(sent, 0);
        assert!(next.is_none());
    }

    #[test]
    fn periodic_slaac_skips_not_yet_due() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        let now = SystemTime::now();
        let future = now + Duration::from_secs(300);
        lease.slaac_address.push(SlaacAddress {
            addr: "2001:db8::1".parse().unwrap(),
            ping_time: Some(future),
            backoff: 1,
        });

        let mut sent = 0;
        let next = periodic_slaac(now, std::slice::from_ref(&ctx), std::iter::once(&mut lease), 42, |_, _| {
            sent += 1;
            Ok(())
        });
        assert_eq!(sent, 0);
        assert_eq!(next, Some(future));
    }

    #[test]
    fn periodic_slaac_gives_up_on_host_unreachable_at_max_backoff() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        let now = SystemTime::now();
        lease.slaac_address.push(SlaacAddress {
            addr: "2001:db8::1".parse().unwrap(),
            ping_time: Some(now),
            backoff: 12, // max backoff
        });

        let next = periodic_slaac(now, std::slice::from_ref(&ctx), std::iter::once(&mut lease), 42, |_, _| {
            Err(std::io::Error::from_raw_os_error(libc::EHOSTUNREACH))
        });

        assert_eq!(lease.slaac_address[0].ping_time, None);
        assert_eq!(lease.slaac_address[0].backoff, 12);
        assert!(next.is_none());
    }

    #[test]
    fn periodic_slaac_host_unreachable_below_max_backoff_still_reschedules() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        let now = SystemTime::now();
        lease.slaac_address.push(SlaacAddress {
            addr: "2001:db8::1".parse().unwrap(),
            ping_time: Some(now),
            backoff: 3,
        });

        let next = periodic_slaac(now, std::slice::from_ref(&ctx), std::iter::once(&mut lease), 42, |_, _| {
            Err(std::io::Error::from_raw_os_error(libc::EHOSTUNREACH))
        });

        assert_eq!(lease.slaac_address[0].backoff, 4);
        assert!(lease.slaac_address[0].ping_time.is_some());
        assert!(next.is_some());
    }

    #[test]
    fn periodic_slaac_backoff_never_exceeds_twelve() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let mut lease = make_lease(MAC, 1, Some("host"));
        let mut now = SystemTime::now();
        lease.slaac_address.push(SlaacAddress {
            addr: "2001:db8::1".parse().unwrap(),
            ping_time: Some(now),
            backoff: 1,
        });

        for _ in 0..20 {
            periodic_slaac(now, std::slice::from_ref(&ctx), std::iter::once(&mut lease), 42, |_, _| Ok(()));
            assert!(lease.slaac_address[0].backoff <= 12);
            if let Some(pt) = lease.slaac_address[0].ping_time {
                now = pt;
            } else {
                break;
            }
        }
    }

    // ── slaac_ping_reply ─────────────────────────────────────────────────────

    #[test]
    fn slaac_ping_reply_confirms_matching_entry() {
        let mut lease = make_lease(MAC, 1, Some("host"));
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        lease.slaac_address.push(SlaacAddress {
            addr,
            ping_time: Some(SystemTime::now()),
            backoff: 3,
        });

        let packet = build_ping_packet(42, 3);
        let gotone = slaac_ping_reply(addr, &packet, 42, "eth0", true, std::iter::once(&mut lease));
        assert!(gotone);
        assert_eq!(lease.slaac_address[0].backoff, 0);
    }

    #[test]
    fn slaac_ping_reply_wrong_ping_id_ignored() {
        let mut lease = make_lease(MAC, 1, Some("host"));
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        lease.slaac_address.push(SlaacAddress {
            addr,
            ping_time: Some(SystemTime::now()),
            backoff: 3,
        });

        let packet = build_ping_packet(99, 3); // wrong id
        let gotone = slaac_ping_reply(addr, &packet, 42, "eth0", true, std::iter::once(&mut lease));
        assert!(!gotone);
        assert_eq!(lease.slaac_address[0].backoff, 3);
    }

    #[test]
    fn slaac_ping_reply_wrong_sender_ignored() {
        let mut lease = make_lease(MAC, 1, Some("host"));
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        lease.slaac_address.push(SlaacAddress {
            addr,
            ping_time: Some(SystemTime::now()),
            backoff: 3,
        });

        let packet = build_ping_packet(42, 3);
        let other: Ipv6Addr = "2001:db8::2".parse().unwrap();
        let gotone = slaac_ping_reply(other, &packet, 42, "eth0", true, std::iter::once(&mut lease));
        assert!(!gotone);
        assert_eq!(lease.slaac_address[0].backoff, 3);
    }

    #[test]
    fn slaac_ping_reply_already_confirmed_not_regotten() {
        let mut lease = make_lease(MAC, 1, Some("host"));
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        lease.slaac_address.push(SlaacAddress {
            addr,
            ping_time: None,
            backoff: 0, // already confirmed
        });

        let packet = build_ping_packet(42, 0);
        let gotone = slaac_ping_reply(addr, &packet, 42, "eth0", true, std::iter::once(&mut lease));
        assert!(!gotone);
    }

    #[test]
    fn slaac_ping_reply_malformed_packet_ignored() {
        let mut lease = make_lease(MAC, 1, Some("host"));
        let gotone = slaac_ping_reply(
            "2001:db8::1".parse().unwrap(),
            &[1, 2, 3],
            42,
            "eth0",
            true,
            std::iter::once(&mut lease),
        );
        assert!(!gotone);
    }

    // ── Icmp6Socket (capability-gated) ───────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn icmp6_socket_create_fails_gracefully_without_capability() {
        // In restricted (non-root, no CAP_NET_RAW) environments this must
        // return an Err rather than panicking; where the capability is
        // present (e.g. a privileged CI runner) it should succeed. Either
        // outcome is acceptable — we only assert it doesn't panic.
        match Icmp6Socket::create() {
            Ok(_) => {}
            Err(e) => {
                assert!(
                    e.kind() == std::io::ErrorKind::PermissionDenied || e.raw_os_error().is_some()
                );
            }
        }
    }
}

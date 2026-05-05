//! SLAAC (Stateless Address Auto-Configuration) address synthesis.
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

/// Return `true` if `addr` was likely synthesized from the given prefix + MAC
/// using the EUI-64 SLAAC method.
#[cfg(feature = "dhcp6")]
pub fn is_slaac_for(
    addr: Ipv6Addr,
    prefix: Ipv6Addr,
    prefix_len: u8,
    mac: &[u8; 6],
) -> bool {
    slaac_address(prefix, prefix_len, mac) == addr
}

// ─────────────────────────────────────────────────────────────────────────────
// SLAAC address generation from lease+contexts (ported from slaac.c:25-116)
// ─────────────────────────────────────────────────────────────────────────────

use crate::types::dhcp::{CONTEXT_RA_NAME, CONTEXT_OLD, LEASE_HAVE_HWADDR, LEASE_TA, LEASE_NA};

/// Generate SLAAC addresses for a lease from a set of DHCPv6 RA-name contexts.
///
/// For each context with CONTEXT_RA_NAME on the lease's interface, derives
/// a SLAAC address from the lease's MAC using EUI-64. Returns the list of
/// generated addresses.
/// Port of the core loop from `slaac_add_addrs()` in slaac.c:25-116.
#[cfg(feature = "dhcp6")]
pub fn synthesize_slaac_addrs(
    hwaddr: &[u8],
    hwaddr_len: usize,
    hwaddr_type: i32,
    lease_flags: u32,
    interface_index: i32,
    contexts: &[crate::types::dhcp::DhcpContext],
) -> Vec<Ipv6Addr> {
    // Only process if lease has hardware address and is not TA/NA
    if lease_flags & LEASE_HAVE_HWADDR == 0 {
        return vec![];
    }
    if lease_flags & (LEASE_TA | LEASE_NA) != 0 {
        return vec![];
    }
    if interface_index == 0 {
        return vec![];
    }

    let mut addrs = Vec::new();

    for ctx in contexts {
        if ctx.flags & CONTEXT_RA_NAME == 0 || ctx.flags & CONTEXT_OLD != 0 {
            continue;
        }
        if interface_index != ctx.if_index {
            continue;
        }

        // Only support 6-byte Ethernet MAC (ARPHRD_ETHER=1, ARPHRD_IEEE802=6)
        if hwaddr_len != 6 || (hwaddr_type != 1 && hwaddr_type != 6) {
            continue;
        }

        let mac: [u8; 6] = [hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5]];
        let addr = slaac_address(ctx.start6, 64, &mac);
        addrs.push(addr);
    }

    addrs
}

/// State for SLAAC address confirmation via ICMPv6 echo probes.
///
/// Models the exponential backoff probe scheduling from `periodic_slaac()`.
#[cfg(feature = "dhcp6")]
#[derive(Debug, Clone)]
pub struct SlaacProbeState {
    pub addr: Ipv6Addr,
    /// Current backoff level (1-12). 0 means confirmed, never probes again.
    pub backoff: u32,
    /// Whether the probe has been confirmed (echo reply received).
    pub confirmed: bool,
}

#[cfg(feature = "dhcp6")]
impl SlaacProbeState {
    /// Create a new probe state for an address.
    pub fn new(addr: Ipv6Addr) -> Self {
        Self { addr, backoff: 1, confirmed: false }
    }

    /// Record that an echo reply was received — mark as confirmed.
    pub fn confirm(&mut self) {
        self.backoff = 0;
        self.confirmed = true;
    }

    /// Advance the backoff after a probe was sent.
    /// Returns the delay in seconds until the next probe.
    pub fn advance_backoff(&mut self) -> u64 {
        if self.backoff == 0 || self.backoff >= 12 {
            return 0; // confirmed or given up
        }
        let delay = 1u64 << (self.backoff - 1); // exponential: 1, 2, 4, 8, ...
        self.backoff += 1;
        delay
    }

    /// Return true if we've given up probing (backoff reached max).
    pub fn given_up(&self) -> bool {
        self.backoff >= 12 && !self.confirmed
    }
}

#[cfg(all(test, feature = "dhcp6"))]
mod tests {
    use super::*;
    use std::net::Ipv6Addr;

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

    #[test]
    fn is_slaac_for_match() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let addr = slaac_address(prefix, 64, &MAC);
        assert!(is_slaac_for(addr, prefix, 64, &MAC));
    }

    #[test]
    fn is_slaac_for_no_match_wrong_mac() {
        let prefix = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let addr = slaac_address(prefix, 64, &MAC);
        let other_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert!(!is_slaac_for(addr, prefix, 64, &other_mac));
    }

    #[test]
    fn is_slaac_for_no_match_wrong_prefix() {
        let prefix1 = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0);
        let prefix2 = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 0);
        let addr = slaac_address(prefix1, 64, &MAC);
        assert!(!is_slaac_for(addr, prefix2, 64, &MAC));
    }

    // ── synthesize_slaac_addrs ───────────────────────────────────────────────

    fn make_ra_ctx(start6: Ipv6Addr, if_index: i32) -> crate::types::dhcp::DhcpContext {
        use std::net::Ipv4Addr;
        crate::types::dhcp::DhcpContext {
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            flags: CONTEXT_RA_NAME,
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
        }
    }

    #[test]
    fn synthesize_slaac_addrs_generates_from_context() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let addrs = synthesize_slaac_addrs(
            &MAC, 6, 1, // ARPHRD_ETHER
            LEASE_HAVE_HWADDR,
            1, // interface matches
            &[ctx],
        );
        assert_eq!(addrs.len(), 1);
        assert!(is_slaac_for(addrs[0], "2001:db8::".parse().unwrap(), 64, &MAC));
    }

    #[test]
    fn synthesize_slaac_addrs_skips_wrong_interface() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 2);
        let addrs = synthesize_slaac_addrs(&MAC, 6, 1, LEASE_HAVE_HWADDR, 1, &[ctx]);
        assert!(addrs.is_empty());
    }

    #[test]
    fn synthesize_slaac_addrs_skips_no_hwaddr_flag() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let addrs = synthesize_slaac_addrs(&MAC, 6, 1, 0, 1, &[ctx]);
        assert!(addrs.is_empty());
    }

    #[test]
    fn synthesize_slaac_addrs_skips_ta_na() {
        let ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        let addrs = synthesize_slaac_addrs(&MAC, 6, 1, LEASE_HAVE_HWADDR | LEASE_NA, 1, &[ctx]);
        assert!(addrs.is_empty());
    }

    #[test]
    fn synthesize_slaac_addrs_skips_old_context() {
        let mut ctx = make_ra_ctx("2001:db8::".parse().unwrap(), 1);
        ctx.flags |= CONTEXT_OLD;
        let addrs = synthesize_slaac_addrs(&MAC, 6, 1, LEASE_HAVE_HWADDR, 1, &[ctx]);
        assert!(addrs.is_empty());
    }

    #[test]
    fn synthesize_slaac_addrs_multiple_contexts() {
        let ctx1 = make_ra_ctx("2001:db8:1::".parse().unwrap(), 1);
        let ctx2 = make_ra_ctx("2001:db8:2::".parse().unwrap(), 1);
        let addrs = synthesize_slaac_addrs(&MAC, 6, 1, LEASE_HAVE_HWADDR, 1, &[ctx1, ctx2]);
        assert_eq!(addrs.len(), 2);
    }

    // ── SlaacProbeState ──────────────────────────────────────────────────────

    #[test]
    fn probe_state_new() {
        let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let state = SlaacProbeState::new(addr);
        assert_eq!(state.backoff, 1);
        assert!(!state.confirmed);
        assert!(!state.given_up());
    }

    #[test]
    fn probe_state_confirm() {
        let mut state = SlaacProbeState::new("2001:db8::1".parse().unwrap());
        state.confirm();
        assert!(state.confirmed);
        assert_eq!(state.backoff, 0);
        assert!(!state.given_up());
    }

    #[test]
    fn probe_state_advance_backoff_exponential() {
        let mut state = SlaacProbeState::new("2001:db8::1".parse().unwrap());
        let d1 = state.advance_backoff(); // backoff 1 → 2, delay = 2^0 = 1
        assert_eq!(d1, 1);
        let d2 = state.advance_backoff(); // backoff 2 → 3, delay = 2^1 = 2
        assert_eq!(d2, 2);
        let d3 = state.advance_backoff(); // backoff 3 → 4, delay = 2^2 = 4
        assert_eq!(d3, 4);
    }

    #[test]
    fn probe_state_gives_up() {
        let mut state = SlaacProbeState::new("2001:db8::1".parse().unwrap());
        for _ in 0..11 {
            state.advance_backoff();
        }
        assert!(state.given_up());
    }
}

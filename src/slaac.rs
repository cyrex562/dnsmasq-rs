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
}

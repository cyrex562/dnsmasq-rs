use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};

/// Information about a network interface.
#[derive(Debug, Clone)]
pub struct IfaceInfo {
    pub name:    String,
    pub index:   u32,
    pub addr:    IpAddr,
    pub netmask: Option<IpAddr>,
    pub flags:   u32,
}

/// Check if `addr` is on the same subnet as `iface_addr` with given `netmask`.
pub fn is_same_subnet(addr: Ipv4Addr, iface_addr: Ipv4Addr, netmask: Ipv4Addr) -> bool {
    let mask = u32::from(netmask);
    (u32::from(addr) & mask) == (u32::from(iface_addr) & mask)
}

/// Check if an interface name matches a pattern (supports wildcards via '*').
pub fn iface_name_matches(name: &str, pattern: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        name == pattern
    }
}

/// Returns true if the address is a link-local IPv4 address (169.254.x.x).
pub fn is_link_local_v4(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 169 && octets[1] == 254
}

/// Returns true if the address is a link-local IPv6 address (fe80::/10).
pub fn is_link_local_v6(addr: Ipv6Addr) -> bool {
    let segs = addr.segments();
    (segs[0] & 0xffc0) == 0xfe80
}

/// Returns true if the address is an IPv6 ULA (fc00::/7).
pub fn is_ula_v6(addr: Ipv6Addr) -> bool {
    let segs = addr.segments();
    (segs[0] & 0xfe00) == 0xfc00
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_same_subnet_24() {
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        let iface = Ipv4Addr::new(192, 168, 1, 1);
        assert!(is_same_subnet(Ipv4Addr::new(192, 168, 1, 100), iface, mask));
        assert!(!is_same_subnet(Ipv4Addr::new(192, 168, 2, 1), iface, mask));
    }

    #[test]
    fn test_is_same_subnet_16() {
        let mask = Ipv4Addr::new(255, 255, 0, 0);
        let iface = Ipv4Addr::new(10, 0, 1, 1);
        assert!(is_same_subnet(Ipv4Addr::new(10, 0, 200, 5), iface, mask));
        assert!(!is_same_subnet(Ipv4Addr::new(10, 1, 0, 1), iface, mask));
    }

    #[test]
    fn test_iface_name_matches_exact() {
        assert!(iface_name_matches("eth0", "eth0"));
        assert!(!iface_name_matches("eth0", "eth1"));
    }

    #[test]
    fn test_iface_name_matches_wildcard() {
        assert!(iface_name_matches("eth0", "eth*"));
        assert!(iface_name_matches("eth1", "eth*"));
        assert!(!iface_name_matches("wlan0", "eth*"));
    }

    #[test]
    fn test_is_link_local_v4() {
        assert!(is_link_local_v4(Ipv4Addr::new(169, 254, 0, 1)));
        assert!(is_link_local_v4(Ipv4Addr::new(169, 254, 255, 255)));
        assert!(!is_link_local_v4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_link_local_v4(Ipv4Addr::new(169, 255, 0, 1)));
    }

    #[test]
    fn test_is_link_local_v6() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let not_ll: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(is_link_local_v6(ll));
        assert!(!is_link_local_v6(not_ll));
        // fe80::/10 boundary: febf:: is still link-local
        let boundary: Ipv6Addr = "febf::1".parse().unwrap();
        assert!(is_link_local_v6(boundary));
        // fec0:: is NOT link-local (it's site-local, old)
        let fec0: Ipv6Addr = "fec0::1".parse().unwrap();
        assert!(!is_link_local_v6(fec0));
    }

    #[test]
    fn test_is_ula_v6() {
        let ula: Ipv6Addr = "fd00::1".parse().unwrap();
        let not_ula: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(is_ula_v6(ula));
        assert!(!is_ula_v6(not_ula));
        // fc00::/7 covers fc00:: and fd00::
        let fc: Ipv6Addr = "fc00::1".parse().unwrap();
        assert!(is_ula_v6(fc));
    }
}

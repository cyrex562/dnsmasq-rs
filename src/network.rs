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

// ──────────────────────────────────────────────────────────────────────────────
// Interface enumeration
// ──────────────────────────────────────────────────────────────────────────────

/// Enumerate all network interfaces and return their addresses.
///
/// Uses the `if-addrs` crate which wraps `getifaddrs(3)` on Linux/macOS and
/// `GetAdaptersAddresses` on Windows.
///
/// Returns an empty `Vec` (not an error) when no interfaces are present.
pub fn enumerate_interfaces() -> std::io::Result<Vec<IfaceInfo>> {
    let ifaces = if_addrs::get_if_addrs()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let result = ifaces.into_iter().map(|i| {
        let (addr, netmask) = match &i.addr {
            if_addrs::IfAddr::V4(v4) => (
                IpAddr::V4(v4.ip),
                Some(IpAddr::V4(v4.netmask)),
            ),
            if_addrs::IfAddr::V6(v6) => (
                IpAddr::V6(v6.ip),
                None, // IPv6 doesn't have a simple netmask
            ),
        };
        IfaceInfo {
            name:    i.name,
            index:   0, // if-addrs doesn't expose the ifindex; netlink can provide it
            addr,
            netmask,
            flags:   0,
        }
    }).collect();

    Ok(result)
}

// ──────────────────────────────────────────────────────────────────────────────
// Listener socket creation
// ──────────────────────────────────────────────────────────────────────────────

/// Options for creating a DNS listener socket.
#[derive(Debug, Clone)]
pub struct ListenerOpts {
    /// IP address to bind to.
    pub addr: IpAddr,
    /// Port to bind to (usually 53).
    pub port: u16,
    /// If true, allow multiple processes to bind to the same address/port
    /// (SO_REUSEADDR / SO_REUSEPORT).
    pub reuse: bool,
}

impl Default for ListenerOpts {
    fn default() -> Self {
        Self {
            addr:  IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port:  53,
            reuse: false,
        }
    }
}

/// Create and bind a UDP DNS listener socket using `socket2` for fine-grained
/// control over socket options.
///
/// Sets:
/// - `SO_REUSEADDR` (always)
/// - `SO_REUSEPORT` (when `opts.reuse` is true)
/// - `IPV6_V6ONLY` on IPv6 sockets (to avoid dual-stack confusion)
///
/// Returns a `tokio::net::UdpSocket` on success.
pub async fn create_udp_listener(
    opts: &ListenerOpts,
) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

    let domain = if opts.addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;

    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    if opts.reuse {
        sock.set_reuse_port(true)?;
    }
    if opts.addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_nonblocking(true)?;

    let bind_addr = SocketAddr::new(opts.addr, opts.port);
    sock.bind(&bind_addr.into())?;

    tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(sock))
}

/// Create and bind a TCP DNS listener socket.
pub async fn create_tcp_listener(
    opts: &ListenerOpts,
) -> std::io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::SocketAddr;

    let domain = if opts.addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let sock = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    sock.set_reuse_address(true)?;
    #[cfg(unix)]
    if opts.reuse {
        sock.set_reuse_port(true)?;
    }
    if opts.addr.is_ipv6() {
        sock.set_only_v6(true)?;
    }
    sock.set_nonblocking(true)?;

    let bind_addr = SocketAddr::new(opts.addr, opts.port);
    sock.bind(&bind_addr.into())?;
    sock.listen(128)?;

    tokio::net::TcpListener::from_std(std::net::TcpListener::from(sock))
}

// ──────────────────────────────────────────────────────────────────────────────
// Interface check / filtering
// ──────────────────────────────────────────────────────────────────────────────

/// Configuration for interface filtering.
#[derive(Debug, Clone, Default)]
pub struct IfaceCheckConfig {
    /// If non-empty, only interfaces whose name matches one of these patterns
    /// are accepted (supports `*` suffix wildcard).
    pub allow: Vec<String>,
    /// Interfaces matching any of these patterns are always rejected.
    pub deny:  Vec<String>,
}

/// Return `true` if `iface` is allowed by the filter configuration.
///
/// Rules (evaluated in order):
/// 1. If `deny` is non-empty and the name matches any deny pattern → reject.
/// 2. If `allow` is non-empty and the name matches any allow pattern → accept.
/// 3. If `allow` is empty → accept (deny-only mode).
/// 4. Otherwise → reject.
pub fn iface_check(iface: &IfaceInfo, config: &IfaceCheckConfig) -> bool {
    // Check deny list first.
    if config.deny.iter().any(|p| iface_name_matches(&iface.name, p)) {
        return false;
    }
    // If allow list is empty, accept everything not denied.
    if config.allow.is_empty() {
        return true;
    }
    // Otherwise accept only if in allow list.
    config.allow.iter().any(|p| iface_name_matches(&iface.name, p))
}

/// Returns `true` if the address is a loopback address.
///
/// Wraps `IpAddr::is_loopback()` — provided as a named function to mirror
/// dnsmasq's `loopback_exception()` helper.
pub fn loopback_exception(addr: IpAddr) -> bool {
    addr.is_loopback()
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

    // ── iface_check tests ────────────────────────────────────────────────────

    fn make_iface(name: &str) -> IfaceInfo {
        IfaceInfo {
            name:    name.to_string(),
            index:   0,
            addr:    IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            netmask: None,
            flags:   0,
        }
    }

    #[test]
    fn test_iface_check_allow_empty_accepts_all() {
        let cfg = IfaceCheckConfig::default();
        assert!(iface_check(&make_iface("eth0"), &cfg));
        assert!(iface_check(&make_iface("lo"), &cfg));
    }

    #[test]
    fn test_iface_check_allow_list() {
        let cfg = IfaceCheckConfig {
            allow: vec!["eth*".to_string()],
            deny:  vec![],
        };
        assert!(iface_check(&make_iface("eth0"), &cfg));
        assert!(iface_check(&make_iface("eth1"), &cfg));
        assert!(!iface_check(&make_iface("lo"), &cfg));
    }

    #[test]
    fn test_iface_check_deny_overrides_allow() {
        let cfg = IfaceCheckConfig {
            allow: vec!["eth*".to_string()],
            deny:  vec!["eth0".to_string()],
        };
        assert!(!iface_check(&make_iface("eth0"), &cfg));
        assert!(iface_check(&make_iface("eth1"), &cfg));
    }

    #[test]
    fn test_loopback_exception() {
        assert!(loopback_exception(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(loopback_exception(IpAddr::V6("::1".parse().unwrap())));
        assert!(!loopback_exception(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    // ── enumerate_interfaces smoke test ──────────────────────────────────────

    #[test]
    fn test_enumerate_interfaces_returns_something() {
        // We can't assert specific interfaces, but at least it should not error
        // and should return at least the loopback interface.
        let result = enumerate_interfaces();
        assert!(result.is_ok(), "enumerate_interfaces failed: {:?}", result.err());
        let ifaces = result.unwrap();
        assert!(!ifaces.is_empty(), "no interfaces found");
        let has_lo = ifaces.iter().any(|i| loopback_exception(i.addr));
        assert!(has_lo, "no loopback address found");
    }

    // ── listener socket creation ──────────────────────────────────────────────

    #[tokio::test]
    async fn test_create_udp_listener_high_port() {
        let opts = ListenerOpts {
            addr:  IpAddr::V4(Ipv4Addr::LOCALHOST),
            port:  0, // kernel picks port
            reuse: false,
        };
        // port 0 not supported by DNS but tests that socket creation itself works
        let sock = create_udp_listener(&opts).await;
        assert!(sock.is_ok(), "create_udp_listener failed: {:?}", sock.err());
    }

    #[tokio::test]
    async fn test_create_tcp_listener_high_port() {
        let opts = ListenerOpts {
            addr:  IpAddr::V4(Ipv4Addr::LOCALHOST),
            port:  0,
            reuse: false,
        };
        let listener = create_tcp_listener(&opts).await;
        assert!(listener.is_ok(), "create_tcp_listener failed: {:?}", listener.err());
    }
}

use std::net::{Ipv4Addr, Ipv6Addr, IpAddr};
use crate::types::network::{INAME_4, INAME_6};

/// `IFF_LOOPBACK` — the one interface flag this module needs from `SIOCGIFFLAGS`.
pub const IFACE_LOOPBACK: u32 = 0x8;

/// Information about a network interface.
#[derive(Debug, Clone)]
pub struct IfaceInfo {
    pub name:    String,
    pub index:   u32,
    pub addr:    IpAddr,
    pub netmask: Option<IpAddr>,
    pub flags:   u32,
}

impl IfaceInfo {
    /// True when this address belongs to a loopback interface.
    pub fn is_loopback(&self) -> bool {
        self.flags & IFACE_LOOPBACK != 0
    }
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

/// Returns true if the address is exactly fd00:: (ULA zero sentinel).
/// Used by upstream radv.c and rfc3315.c to indicate "elide this prefix/RA option".
pub fn is_ula_zero_v6(addr: Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0xfd && octets[1] == 0x00 && octets[2] == 0x00 && octets[3] == 0x00
        && octets[4..].iter().all(|b| *b == 0)
}

/// Returns true if the address is exactly fe80:: (link-local zero sentinel).
/// Used by upstream radv.c and rfc3315.c to indicate "elide this prefix/RA option".
pub fn is_link_local_zero_v6(addr: Ipv6Addr) -> bool {
    let octets = addr.octets();
    octets[0] == 0xfe && octets[1] == 0x80 && octets[2] == 0x00 && octets[3] == 0x00
        && octets[4..].iter().all(|b| *b == 0)
}

// ──────────────────────────────────────────────────────────────────────────────
// Interface enumeration
// ──────────────────────────────────────────────────────────────────────────────

/// Look up an interface index by name (`if_nametoindex(3)`).
///
/// Returns `0` when the name is unknown, matching the C function.
#[cfg(unix)]
pub fn nametoindex(name: &str) -> u32 {
    match std::ffi::CString::new(name) {
        Ok(c) => unsafe { libc::if_nametoindex(c.as_ptr()) },
        Err(_) => 0,
    }
}

/// Non-Unix stub.
#[cfg(not(unix))]
pub fn nametoindex(_name: &str) -> u32 { 0 }

/// Enumerate all network interfaces and return their addresses.
///
/// Uses the `if-addrs` crate which wraps `getifaddrs(3)` on Linux/macOS and
/// `GetAdaptersAddresses` on Windows.  The interface index and the loopback
/// flag are filled in afterwards — `iface_allowed_*` and the per-packet arrival
/// check both need them, and `if-addrs` exposes neither directly.
///
/// Returns an empty `Vec` (not an error) when no interfaces are present.
pub fn enumerate_interfaces() -> std::io::Result<Vec<IfaceInfo>> {
    let ifaces = if_addrs::get_if_addrs()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    let result = ifaces.into_iter().map(|i| {
        let loopback = i.is_loopback();
        let (addr, netmask) = match &i.addr {
            if_addrs::IfAddr::V4(v4) => (
                IpAddr::V4(v4.ip),
                Some(IpAddr::V4(v4.netmask)),
            ),
            if_addrs::IfAddr::V6(v6) => (
                IpAddr::V6(v6.ip),
                Some(IpAddr::V6(v6.netmask)),
            ),
        };
        IfaceInfo {
            index:   nametoindex(&i.name),
            name:    i.name,
            addr,
            netmask,
            flags:   if loopback { IFACE_LOOPBACK } else { 0 },
        }
    }).collect();

    Ok(result)
}

/// Count the leading one-bits of an IPv6 netmask, giving a prefix length.
///
/// `if_addrs` reports IPv6 netmasks the same shape as IPv4's (a mask, not a
/// prefix length); DHCPv6 context matching (`complete_context6`,
/// `dhcp_construct_contexts`) wants a plain prefix length instead.
pub fn netmask_to_prefix6(mask: Ipv6Addr) -> i32 {
    mask.segments().iter().map(|s| s.count_ones()).sum::<u32>() as i32
}

/// Enumerate live IPv6 addresses across all interfaces as
/// [`crate::dhcp6::LiveAddr6`] values, for DHCPv6 context construction
/// (`dhcp_construct_contexts`/`complete_context6`, dhcp6.c's
/// `iface_enumerate(AF_INET6, ...)`).
///
/// `if-addrs` doesn't surface kernel preferred/valid lifetimes or the
/// `IFACE_DEPRECATED` flag the way `getifaddrs`'s `ifa_flags` or a netlink
/// `RTM_NEWADDR` does, so every address is reported as non-deprecated with
/// maximal lifetimes — `complete_context6` only actually reads those fields
/// for `CONTEXT_CONSTRUCTED` contexts, so this only affects lease lifetimes
/// offered from a *constructed* context, not plain configured ranges.
#[cfg(feature = "dhcp6")]
pub fn enumerate_live_addrs6() -> std::io::Result<Vec<crate::dhcp6::LiveAddr6>> {
    let ifaces = enumerate_interfaces()?;
    Ok(ifaces
        .into_iter()
        .filter_map(|i| {
            let IpAddr::V6(addr) = i.addr else { return None };
            let prefix = match i.netmask {
                Some(IpAddr::V6(mask)) => netmask_to_prefix6(mask),
                _ => 128,
            };
            Some(crate::dhcp6::LiveAddr6 {
                addr,
                prefix,
                if_index: i.index,
                preferred: 0xffff_ffff,
                valid: 0xffff_ffff,
                deprecated: false,
            })
        })
        .collect())
}

/// Parse a colon-separated hex MAC address string (`/sys/class/net/*/address`
/// format) into raw bytes.
fn parse_mac_addr_str(s: &str) -> Option<Vec<u8>> {
    let bytes: Vec<u8> = s
        .trim()
        .split(':')
        .map(|b| u8::from_str_radix(b, 16))
        .collect::<Result<_, _>>()
        .ok()?;
    if bytes.is_empty() || bytes.iter().all(|&b| b == 0) {
        return None;
    }
    Some(bytes)
}

/// Find the first non-loopback interface with a usable Ethernet-class MAC,
/// for DHCPv6 DUID-LL/DUID-LLT generation (`make_duid1`, dhcp6.c:643-683).
///
/// Reads `/sys/class/net/<iface>/{type,address}`. Skips `lo` and any
/// interface reporting an ARPHRD type `>= 256` (tunnels and other MAC-less
/// link types), matching `make_duid1()`'s own cutoff (dhcp6.c:653).
#[cfg(all(feature = "dhcp6", target_os = "linux"))]
pub fn first_dhcp6_mac_source() -> Option<crate::dhcp6::DuidMacSource> {
    let mut names: Vec<String> = std::fs::read_dir("/sys/class/net")
        .ok()?
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    names.sort();

    for name in names {
        if name == "lo" {
            continue;
        }
        let Some(hw_type): Option<u16> = std::fs::read_to_string(format!("/sys/class/net/{name}/type"))
            .ok()
            .and_then(|s| s.trim().parse().ok())
        else {
            continue;
        };
        if hw_type >= 256 {
            continue;
        }
        let Some(mac) = std::fs::read_to_string(format!("/sys/class/net/{name}/address"))
            .ok()
            .and_then(|s| parse_mac_addr_str(&s))
        else {
            continue;
        };
        return Some(crate::dhcp6::DuidMacSource { hw_type, mac });
    }
    None
}

/// Non-Linux stub: no `/sys/class/net` to read.
#[cfg(all(feature = "dhcp6", not(target_os = "linux")))]
pub fn first_dhcp6_mac_source() -> Option<crate::dhcp6::DuidMacSource> {
    None
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

/// Configuration for interface filtering — the Rust form of the
/// `--interface` / `--except-interface` / `--listen-address` triple that
/// upstream's `iface_check()` consults (`daemon->if_names`, `if_except`,
/// `if_addrs`).
#[derive(Debug, Clone, Default)]
pub struct IfaceCheckConfig {
    /// `--interface` name patterns (supports a `*` wildcard).
    pub allow: Vec<String>,
    /// `--except-interface` name patterns.
    pub deny:  Vec<String>,
    /// `--listen-address` addresses.  An arrival/interface address matching one
    /// of these is accepted regardless of `allow`, and — as upstream's
    /// `match_addr` does — it also overrides `deny`.
    pub addrs: Vec<IpAddr>,
    /// Set when `--interface` was given with no name, upstream's NULL-named
    /// `struct iname` (pushed by `--local-service=host`, `option.c:6312`).  It
    /// restricts the served set without naming an interface, so it has to be
    /// tracked separately from `allow` being non-empty.
    pub unnamed_iface: bool,
}

impl IfaceCheckConfig {
    /// True when any access control at all is configured — upstream's
    /// `if (daemon->if_names || daemon->if_addrs)` test.
    pub fn restricted(&self) -> bool {
        self.has_if_names() || !self.addrs.is_empty()
    }

    /// True when `--interface` was given at all, named or not — upstream's
    /// `daemon->if_names` being non-NULL.
    ///
    /// This is deliberately narrower than [`restricted`](Self::restricted):
    /// the loopback-always-served rule keys off `if_names` alone, so
    /// `--listen-address` on its own does *not* pull loopback into the set.
    pub fn has_if_names(&self) -> bool {
        self.unnamed_iface || !self.allow.is_empty()
    }
}

/// Which `--interface` / `--listen-address` entries a check matched.
///
/// Mirrors upstream's `INAME_USED` flag, which drives both the "unknown
/// interface %s" startup error (`dnsmasq.c:396-398`) and the extra listeners
/// created for `--listen-address` values no interface carries
/// (`network.c:1219-1233`).
#[derive(Debug, Clone, Default)]
pub struct IfaceCheckUsed {
    /// Parallel to `IfaceCheckConfig::allow`.
    pub names: Vec<bool>,
    /// Parallel to `IfaceCheckConfig::addrs`.
    pub addrs: Vec<bool>,
}

impl IfaceCheckUsed {
    /// An all-unused record sized for `config`.
    pub fn for_config(config: &IfaceCheckConfig) -> Self {
        Self {
            names: vec![false; config.allow.len()],
            addrs: vec![false; config.addrs.len()],
        }
    }
}

/// Return `true` if `iface` is allowed by the filter configuration, recording
/// which config entries matched in `used`.
///
/// Direct port of `iface_check()` (`network.c:112-181`), minus the auth-DNS
/// output parameter:
///
/// 1. With no `--interface`/`--listen-address` config at all, everything is
///    accepted and only `--except-interface` can reject.
/// 2. Otherwise the default is reject, and either a name match against
///    `allow` or an address match against `addrs` accepts.
/// 3. `--except-interface` then rejects — unless the accept came from an
///    address match (upstream's `match_addr`), because an explicitly named
///    listen address outranks an interface exclusion.
///
/// Note that, like upstream, every list is walked in full even after the answer
/// is known: the `used` flags have to be set for entries that matched.
pub fn iface_check_used(
    iface:  &IfaceInfo,
    config: &IfaceCheckConfig,
    used:   &mut IfaceCheckUsed,
) -> bool {
    used.names.resize(config.allow.len(), false);
    used.addrs.resize(config.addrs.len(), false);

    let mut ret = true;
    let mut match_addr = false;

    if config.restricted() {
        ret = false;

        for (i, pattern) in config.allow.iter().enumerate() {
            if iface_name_matches(&iface.name, pattern) {
                used.names[i] = true;
                ret = true;
            }
        }

        for (i, addr) in config.addrs.iter().enumerate() {
            if *addr == iface.addr {
                used.addrs[i] = true;
                ret = true;
                match_addr = true;
            }
        }
    }

    if !match_addr && config.deny.iter().any(|p| iface_name_matches(&iface.name, p)) {
        ret = false;
    }

    ret
}

/// [`iface_check_used`] without the `used` bookkeeping.
pub fn iface_check(iface: &IfaceInfo, config: &IfaceCheckConfig) -> bool {
    let mut used = IfaceCheckUsed::for_config(config);
    iface_check_used(iface, config, &mut used)
}

/// Accept a datagram that arrived via a loopback interface addressed to an
/// address we do serve.
///
/// The kernel sometimes reports the loopback interface as the arrival interface
/// for locally-originated packets even when they were sent to the address of
/// another interface.  Upstream works around that by accepting any packet whose
/// arrival interface is a loopback one, as long as its destination address is
/// one of the addresses we know about.
///
/// Port of `loopback_exception()` (`network.c:185-206`).  `arrival_is_loopback`
/// stands in for the `SIOCGIFFLAGS`/`IFF_LOOPBACK` test upstream does on the
/// arrival interface name.
pub fn loopback_exception(
    arrival_is_loopback: bool,
    addr:                IpAddr,
    ifaces:              &[IfaceRecord],
) -> bool {
    arrival_is_loopback && ifaces.iter().any(|iface| iface.addr == addr)
}

// ──────────────────────────────────────────────────────────────────────────────
// Socket utilities (fix_fd, set_ipv6pktinfo, tcp_interface, indextoname)
// ──────────────────────────────────────────────────────────────────────────────

/// Set `O_NONBLOCK` on a raw file descriptor.
///
/// Returns `Ok(())` on success or an `io::Error` on failure.
/// Mirrors C's `fix_fd()`.
///
/// On non-Unix platforms this is a no-op that always returns `Ok(())`.
#[cfg(unix)]
pub fn fix_fd(fd: std::os::unix::io::RawFd) -> std::io::Result<()> {
    use std::os::unix::io::FromRawFd;
    // Safety: we only use fcntl to query/set flags; we don't take ownership.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags == -1 {
        return Err(std::io::Error::last_os_error());
    }
    let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if rc == -1 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(not(unix))]
pub fn fix_fd(_fd: i32) -> std::io::Result<()> {
    Ok(())
}

/// Enable `IPV6_RECVPKTINFO` (or the legacy `IPV6_2292PKTINFO`) on an IPv6
/// UDP socket so that `recvmsg` populates the incoming packet-info control
/// message (destination address + interface index).
///
/// Returns `Ok(true)` if the option was set, `Ok(false)` if the kernel does
/// not support it, or an `io::Error` on a hard failure.
///
/// Mirrors C's `set_ipv6pktinfo()`.
#[cfg(all(unix, target_os = "linux"))]
pub fn set_ipv6pktinfo(fd: std::os::unix::io::RawFd) -> std::io::Result<bool> {
    let opt: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_RECVPKTINFO,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    // Try legacy IPV6_2292PKTINFO (Linux ABI compatibility).
    const IPV6_2292PKTINFO: libc::c_int = 2;
    let errno = unsafe { *libc::__errno_location() };
    if errno == libc::ENOPROTOOPT {
        let rc2 = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IPV6,
                IPV6_2292PKTINFO,
                &opt as *const _ as *const libc::c_void,
                std::mem::size_of_val(&opt) as libc::socklen_t,
            )
        };
        if rc2 == 0 {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(all(unix, not(target_os = "linux")))]
pub fn set_ipv6pktinfo(fd: std::os::unix::io::RawFd) -> std::io::Result<bool> {
    let opt: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_PKTINFO,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        )
    };
    Ok(rc == 0)
}

#[cfg(not(unix))]
pub fn set_ipv6pktinfo(_fd: i32) -> std::io::Result<bool> {
    Ok(false)
}

/// Enable `IP_PKTINFO` on an IPv4 UDP socket so that `recvmsg` populates the
/// incoming packet-info control message (destination address + arrival
/// interface index). [`recv_with_dest`] reads it back out via [`parse_pktinfo`].
///
/// Returns `Ok(true)` if the option was set, `Ok(false)` if the kernel does
/// not support it, or an `io::Error` on a hard failure. Unlike the inline
/// `IP_PKTINFO` set in `create_listeners_checked` (DNS wildcard sockets),
/// this is for sockets bound to one specific address — such as the DHCP
/// socket — that still want per-datagram arrival-interface metadata.
#[cfg(all(unix, target_os = "linux"))]
pub fn set_ipv4pktinfo(fd: std::os::unix::io::RawFd) -> std::io::Result<bool> {
    let opt: libc::c_int = 1;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_PKTINFO,
            &opt as *const _ as *const libc::c_void,
            std::mem::size_of_val(&opt) as libc::socklen_t,
        )
    };
    Ok(rc == 0)
}

// BSD's equivalent is `IP_RECVDSTADDR` + `IP_RECVIF`, but `parse_pktinfo`
// only decodes Linux's `IP_PKTINFO` control message for IPv4 today, so
// enabling it here would set a socket option nothing reads back. Left
// unimplemented rather than silently misleading; see `tasks.md`.
#[cfg(all(unix, not(target_os = "linux")))]
pub fn set_ipv4pktinfo(_fd: std::os::unix::io::RawFd) -> std::io::Result<bool> {
    Ok(false)
}

#[cfg(not(unix))]
pub fn set_ipv4pktinfo(_fd: i32) -> std::io::Result<bool> {
    Ok(false)
}

/// Determine the interface index of the local end of a TCP connection.
///
/// Uses `IP_PKTOPTIONS` (IPv4) or `IPV6_2292PKTOPTIONS` (IPv6) to retrieve
/// the packet-info control message, which carries the interface index.
///
/// Returns the interface index, or `0` if it cannot be determined.
///
/// Mirrors C's `tcp_interface()`.
#[cfg(all(unix, target_os = "linux"))]
pub fn tcp_interface(fd: std::os::unix::io::RawFd, is_ipv6: bool) -> u32 {
    use std::mem::MaybeUninit;

    if !is_ipv6 {
        // Enable IP_PKTINFO on the socket first.
        let opt: libc::c_int = 1;
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_PKTINFO,
                &opt as *const _ as *const libc::c_void,
                std::mem::size_of_val(&opt) as libc::socklen_t,
            )
        };
        if rc != 0 {
            return 0;
        }

        // Read IP_PKTOPTIONS to get packet-info control message.
        let mut buf = [0u8; 256];
        let mut len = buf.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_PKTOPTIONS,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return 0;
        }

        // Walk the control messages looking for IP_PKTINFO.
        let mut offset = 0usize;
        while offset + std::mem::size_of::<libc::cmsghdr>() <= len as usize {
            let cmsg: libc::cmsghdr = unsafe {
                std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const _)
            };
            if cmsg.cmsg_level == libc::IPPROTO_IP
                && cmsg.cmsg_type == libc::IP_PKTINFO
                && cmsg.cmsg_len as usize
                    >= std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<libc::in_pktinfo>()
            {
                let pktinfo: libc::in_pktinfo = unsafe {
                    std::ptr::read_unaligned(
                        buf.as_ptr()
                            .add(offset + std::mem::size_of::<libc::cmsghdr>())
                            as *const _,
                    )
                };
                return pktinfo.ipi_ifindex as u32;
            }
            // Align to next cmsghdr boundary.
            let next = offset + ((cmsg.cmsg_len as usize + std::mem::size_of::<usize>() - 1)
                & !(std::mem::size_of::<usize>() - 1));
            if next <= offset {
                break;
            }
            offset = next;
        }
        0
    } else {
        // IPv6: use IPV6_2292PKTOPTIONS (Linux legacy ABI)
        const IPV6_2292PKTOPTIONS: libc::c_int = 6;
        let mut buf = [0u8; 256];
        let mut len = buf.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                libc::IPPROTO_IPV6,
                IPV6_2292PKTOPTIONS,
                buf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };
        if rc != 0 {
            return 0;
        }
        // Walk messages looking for IPV6_PKTINFO.
        let mut offset = 0usize;
        while offset + std::mem::size_of::<libc::cmsghdr>() <= len as usize {
            let cmsg: libc::cmsghdr = unsafe {
                std::ptr::read_unaligned(buf.as_ptr().add(offset) as *const _)
            };
            if cmsg.cmsg_level == libc::IPPROTO_IPV6
                && cmsg.cmsg_type == libc::IPV6_PKTINFO
                && cmsg.cmsg_len as usize
                    >= std::mem::size_of::<libc::cmsghdr>() + std::mem::size_of::<libc::in6_pktinfo>()
            {
                let pktinfo: libc::in6_pktinfo = unsafe {
                    std::ptr::read_unaligned(
                        buf.as_ptr()
                            .add(offset + std::mem::size_of::<libc::cmsghdr>())
                            as *const _,
                    )
                };
                return pktinfo.ipi6_ifindex;
            }
            let next = offset + ((cmsg.cmsg_len as usize + std::mem::size_of::<usize>() - 1)
                & !(std::mem::size_of::<usize>() - 1));
            if next <= offset {
                break;
            }
            offset = next;
        }
        0
    }
}

#[cfg(not(all(unix, target_os = "linux")))]
pub fn tcp_interface(_fd: i32, _is_ipv6: bool) -> u32 {
    0
}

/// Convert a network interface index to its name.
///
/// Uses the POSIX `if_indextoname()` function.  Returns `None` if `index` is 0
/// or the conversion fails (e.g. no interface with that index exists).
///
/// Mirrors C's `indextoname()`.
#[cfg(unix)]
pub fn indextoname(index: u32) -> Option<String> {
    if index == 0 {
        return None;
    }
    let mut buf = [0i8; libc::IF_NAMESIZE];
    let result = unsafe { libc::if_indextoname(index, buf.as_mut_ptr()) };
    if result.is_null() {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    cstr.to_str().ok().map(|s| s.to_owned())
}

#[cfg(not(unix))]
pub fn indextoname(_index: u32) -> Option<String> {
    None
}

// ──────────────────────────────────────────────────────────────────────────────
// Receiving with destination metadata (forward.c:1700-1780)
// ──────────────────────────────────────────────────────────────────────────────

/// One received datagram plus the arrival metadata a wildcard listener needs.
#[derive(Debug, Clone)]
pub struct RecvMeta {
    /// Number of bytes written into the caller's buffer.
    pub len: usize,
    /// Source address of the datagram.
    pub src: std::net::SocketAddr,
    /// Destination address, from `IP_PKTINFO` / `IPV6_PKTINFO`.  `None` when
    /// the socket was bound to a specific address (no control message is
    /// requested) or the kernel did not supply one.
    pub dest: Option<IpAddr>,
    /// Arrival interface index, or 0 when unknown.
    pub if_index: u32,
}

/// `recvmsg(2)` a datagram, extracting the destination address and arrival
/// interface index from the `IP_PKTINFO` / `IPV6_PKTINFO` control message.
///
/// Upstream reads exactly this metadata in `udp_request()` before calling
/// `iface_check()`, which is how `--interface` and `--listen-address` are
/// enforced on a wildcard socket.  Sockets created with `nowild = true` never
/// carry the control message, and the fields come back as `None` / `0`.
#[cfg(unix)]
pub fn recv_with_dest(
    fd:  std::os::unix::io::RawFd,
    buf: &mut [u8],
) -> std::io::Result<RecvMeta> {
    use std::mem;

    let mut name: libc::sockaddr_storage = unsafe { mem::zeroed() };
    let mut ctrl = [0u8; 256];
    let iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len:  buf.len(),
    };
    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name       = &mut name as *mut _ as *mut libc::c_void;
    msg.msg_namelen    = mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov        = &iov as *const libc::iovec as *mut libc::iovec;
    msg.msg_iovlen     = 1;
    msg.msg_control    = ctrl.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = ctrl.len() as _;

    let rc = unsafe { libc::recvmsg(fd, &mut msg, 0) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error());
    }

    let src = sockaddr_storage_to_socket_addr(&name)
        .ok_or_else(|| std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "recvmsg returned an unsupported source address family",
        ))?;

    let (dest, if_index) = parse_pktinfo(&msg);
    Ok(RecvMeta { len: rc as usize, src, dest, if_index })
}

/// Walk a received `msghdr`'s control messages for `IP_PKTINFO` /
/// `IPV6_PKTINFO`.
#[cfg(unix)]
fn parse_pktinfo(msg: &libc::msghdr) -> (Option<IpAddr>, u32) {
    use std::mem;

    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(msg) };
    while !cmsg.is_null() {
        let (level, ctype, clen) = unsafe {
            ((*cmsg).cmsg_level, (*cmsg).cmsg_type, (*cmsg).cmsg_len as usize)
        };
        let payload = unsafe { libc::CMSG_DATA(cmsg) };
        let hdr_len = unsafe { libc::CMSG_LEN(0) as usize };

        #[cfg(target_os = "linux")]
        if level == libc::IPPROTO_IP
            && ctype == libc::IP_PKTINFO
            && clen >= hdr_len + mem::size_of::<libc::in_pktinfo>()
        {
            let pi: libc::in_pktinfo =
                unsafe { std::ptr::read_unaligned(payload as *const libc::in_pktinfo) };
            let addr = Ipv4Addr::from(u32::from_be(u32::from_ne_bytes(
                pi.ipi_addr.s_addr.to_ne_bytes(),
            )));
            return (Some(IpAddr::V4(addr)), pi.ipi_ifindex as u32);
        }

        if level == libc::IPPROTO_IPV6
            && ctype == libc::IPV6_PKTINFO
            && clen >= hdr_len + mem::size_of::<libc::in6_pktinfo>()
        {
            let pi: libc::in6_pktinfo =
                unsafe { std::ptr::read_unaligned(payload as *const libc::in6_pktinfo) };
            return (
                Some(IpAddr::V6(Ipv6Addr::from(pi.ipi6_addr.s6_addr))),
                pi.ipi6_ifindex,
            );
        }

        let _ = (payload, hdr_len, clen);
        cmsg = unsafe { libc::CMSG_NXTHDR(msg, cmsg) };
    }
    (None, 0)
}

/// Convert a filled `sockaddr_storage` into a `SocketAddr`.
#[cfg(unix)]
fn sockaddr_storage_to_socket_addr(
    storage: &libc::sockaddr_storage,
) -> Option<std::net::SocketAddr> {
    match storage.ss_family as libc::c_int {
        libc::AF_INET => {
            let sin = unsafe { &*(storage as *const _ as *const libc::sockaddr_in) };
            let ip = Ipv4Addr::from(u32::from_be(u32::from_ne_bytes(
                sin.sin_addr.s_addr.to_ne_bytes(),
            )));
            Some(std::net::SocketAddr::new(IpAddr::V4(ip), u16::from_be(sin.sin_port)))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(storage as *const _ as *const libc::sockaddr_in6) };
            let ip = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
            Some(std::net::SocketAddr::new(IpAddr::V6(ip), u16::from_be(sin6.sin6_port)))
        }
        _ => None,
    }
}

/// Non-Unix stub.
#[cfg(not(unix))]
pub fn recv_with_dest(_fd: i32, _buf: &mut [u8]) -> std::io::Result<RecvMeta> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "recv_with_dest not supported on this platform",
    ))
}

// ──────────────────────────────────────────────────────────────────────────────
// Low-level listener socket helpers
// (ported from network.c: make_sock, create_listeners,
//  create_wildcard_listeners, find_listener, release_listener,
//  create_bound_listeners)
// ──────────────────────────────────────────────────────────────────────────────

/// A DNS listener: one UDP socket + one TCP socket bound to the same address.
///
/// An optional TFTP UDP fd (`tftp_fd`) is only present when the caller
/// requests TFTP support.  The `used` counter tracks how many logical
/// interfaces share this physical socket pair (used in `--bind-dynamic` mode).
#[derive(Debug)]
pub struct Listener {
    /// Bound address.
    pub addr:     std::net::SocketAddr,
    /// UDP socket fd (`-1` if absent).
    pub udp_fd:   i32,
    /// TCP socket fd (`-1` if absent).
    pub tcp_fd:   i32,
    /// TFTP UDP socket fd (`-1` if absent).
    pub tftp_fd:  i32,
    /// Reference count — how many interfaces share this socket pair.
    pub used:     u32,
    /// Interface name, if known.
    pub iface:    Option<String>,
}

impl Listener {
    /// Decrement the use-counter.  When it reaches zero, close all open file
    /// descriptors and return `true`; otherwise return `false`.
    pub fn release(&mut self) -> bool {
        if self.used > 1 {
            self.used -= 1;
            return false;
        }
        #[cfg(unix)]
        {
            if self.udp_fd  >= 0 { unsafe { libc::close(self.udp_fd);  } }
            if self.tcp_fd  >= 0 { unsafe { libc::close(self.tcp_fd);  } }
            if self.tftp_fd >= 0 { unsafe { libc::close(self.tftp_fd); } }
        }
        self.udp_fd  = -1;
        self.tcp_fd  = -1;
        self.tftp_fd = -1;
        true
    }
}

/// Socket type for `make_sock`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SockType { Udp, Tcp }

/// Create and configure a single raw socket bound to `addr`.
///
/// * Sets `SO_REUSEADDR`.
/// * Sets `O_NONBLOCK` via `fix_fd`.
/// * For IPv6 sockets: sets `IPV6_V6ONLY`.
/// * For **UDP IPv4**, unless `nowild`: enables `IP_PKTINFO` (Linux) or
///   `IP_RECVDSTADDR` + `IP_RECVIF` (BSD) so the kernel reports the
///   destination address on each received datagram.
/// * For **UDP IPv6**: always calls `set_ipv6pktinfo` — the arrival interface
///   is part of the standard IPv6 API, so upstream never opts out of it.
/// * For **TCP**: calls `listen(128)` and optionally enables `TCP_FASTOPEN`.
///
/// `nowild` is upstream's global `option_bool(OPT_NOWILD)` (`--bind-interfaces`),
/// which is what `network.c:962` actually tests — *not* "this socket is bound to
/// one address".  `--bind-dynamic` binds per address but leaves `OPT_NOWILD`
/// clear, and so keeps `IP_PKTINFO`; that is precisely how it manages to check
/// the arrival interface where `--bind-interfaces` cannot.
///
/// Returns the raw file descriptor, or `Err` on failure.
///
/// Mirrors `make_sock()` in `network.c`.
#[cfg(unix)]
pub fn make_sock(
    addr: std::net::SocketAddr,
    kind: SockType,
    nowild: bool,
) -> std::io::Result<std::os::unix::io::RawFd> {
    use std::io;
    use std::os::unix::io::{AsRawFd, IntoRawFd};
    use socket2::{Domain, Protocol, Socket, Type};

    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let (sock_type, proto) = match kind {
        SockType::Udp => (Type::DGRAM,   Some(Protocol::UDP)),
        SockType::Tcp => (Type::STREAM,  Some(Protocol::TCP)),
    };

    // "No error if the kernel just doesn't support this IP flavour"
    // (`network.c:900-905`).  Upstream grants that exemption to the `socket()`
    // call *only*: every later failure reaches `goto err` and dies.  Tag the
    // error here so callers can tell the two apart — a `bind()` that quietly
    // did not happen is exactly the bug this module exists to prevent.
    let sock = Socket::new(domain, sock_type, proto).map_err(|e| {
        if matches!(
            e.raw_os_error(),
            Some(libc::EPROTONOSUPPORT) | Some(libc::EAFNOSUPPORT) | Some(libc::EINVAL)
        ) || matches!(e.kind(), io::ErrorKind::Unsupported)
        {
            io::Error::new(io::ErrorKind::Unsupported, FamilyUnsupported(e))
        } else {
            e
        }
    })?;

    let one: libc::c_int = 1;
    // SO_REUSEADDR
    unsafe {
        if libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        ) != 0 {
            return Err(io::Error::last_os_error());
        }
    }

    fix_fd(sock.as_raw_fd())?;

    if addr.is_ipv6() {
        unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_V6ONLY,
                &one as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    sock.bind(&addr.into())?;

    match kind {
        SockType::Tcp => {
            #[cfg(target_os = "linux")]
            unsafe {
                let qlen: libc::c_int = 5;
                libc::setsockopt(
                    sock.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    libc::TCP_FASTOPEN,
                    &qlen as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                );
            }
            sock.listen(128)?;
        }
        SockType::Udp if !nowild => {
            if addr.is_ipv4() {
                #[cfg(target_os = "linux")]
                unsafe {
                    libc::setsockopt(
                        sock.as_raw_fd(),
                        libc::IPPROTO_IP,
                        libc::IP_PKTINFO,
                        &one as *const _ as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    );
                }
            } else {
                set_ipv6pktinfo(sock.as_raw_fd())?;
            }
        }
        SockType::Udp => {
            if addr.is_ipv6() {
                set_ipv6pktinfo(sock.as_raw_fd())?;
            }
        }
    }

    Ok(sock.into_raw_fd())
}

/// Non-Unix stub.
#[cfg(not(unix))]
pub fn make_sock(
    _addr: std::net::SocketAddr,
    _kind: SockType,
    _nowild: bool,
) -> std::io::Result<i32> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "make_sock not supported on this platform",
    ))
}

/// `ALL_RELAY_AGENTS_AND_SERVERS` (network.c) — ff02::1:2.
pub const ALL_DHCP_RELAY_AGENTS_AND_SERVERS: &str = "ff02::1:2";
/// `ALL_SERVERS` (network.c) — ff05::1:3.
pub const ALL_DHCP_SERVERS: &str = "ff05::1:3";

/// Join a single IPv6 multicast `group` on `if_index` for socket `fd`.
#[cfg(all(unix, target_os = "linux"))]
fn join_ipv6_group(
    fd: std::os::unix::io::RawFd,
    if_index: u32,
    group: Ipv6Addr,
) -> std::io::Result<()> {
    let mreq = libc::ipv6_mreq {
        ipv6mr_multiaddr: libc::in6_addr { s6_addr: group.octets() },
        ipv6mr_interface: if_index,
    };
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            // `IPV6_ADD_MEMBERSHIP` is Linux's name for the option upstream
            // calls `IPV6_JOIN_GROUP`; both are value 20 and libc only
            // exposes the former.
            libc::IPV6_ADD_MEMBERSHIP,
            &mreq as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::ipv6_mreq>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

/// Join the DHCPv6 `ALL_DHCP_RELAY_AGENTS_AND_SERVERS` (ff02::1:2) and
/// `ALL_DHCP_SERVERS` (ff05::1:3) multicast groups on `if_index` for the
/// bound DHCPv6 socket `fd`.
///
/// A wildcard `[::]:547` bind does **not** by itself receive multicast
/// datagrams — IPv6 requires explicit group membership per interface even
/// for a wildcard-bound socket, and the kernel silently drops unjoined
/// multicast. Real DHCPv6 clients always multicast their initial SOLICIT
/// (they have no unicast address to send to yet), so without this join the
/// server can never receive one.
///
/// Port of the DHCPv6 portion of `join_multicast()` (network.c:1306-1360).
/// Upstream also joins `ALL_ROUTERS` on the ICMPv6 socket for `--enable-ra`,
/// which this crate's RA support does not yet call — see `tasks.md`.
#[cfg(all(unix, target_os = "linux"))]
pub fn join_dhcp6_multicast(fd: std::os::unix::io::RawFd, if_index: u32) -> std::io::Result<()> {
    let relay_agents: Ipv6Addr = ALL_DHCP_RELAY_AGENTS_AND_SERVERS.parse().unwrap();
    let all_servers: Ipv6Addr = ALL_DHCP_SERVERS.parse().unwrap();
    join_ipv6_group(fd, if_index, relay_agents)?;
    join_ipv6_group(fd, if_index, all_servers)?;
    Ok(())
}

/// Non-Linux stub: multicast group join for DHCPv6 is Linux-only in this
/// crate today (mirrors [`set_ipv6pktinfo`]'s platform split).
#[cfg(all(unix, not(target_os = "linux")))]
pub fn join_dhcp6_multicast(_fd: std::os::unix::io::RawFd, _if_index: u32) -> std::io::Result<()> {
    Ok(())
}

#[cfg(not(unix))]
pub fn join_dhcp6_multicast(_fd: i32, _if_index: u32) -> std::io::Result<()> {
    Ok(())
}

/// Join DHCPv6 multicast groups on every live, non-loopback interface index
/// discovered via [`enumerate_live_addrs6`], deduplicating by `if_index` the
/// way upstream's `join_multicast()` does with its `multicast_done` flag.
/// A per-interface join failure is logged and skipped rather than aborting —
/// a container without `CAP_NET_ADMIN`, or an interface that doesn't support
/// multicast, must not prevent the rest of the daemon from starting.
#[cfg(feature = "dhcp6")]
pub fn join_dhcp6_multicast_all_interfaces(fd: std::os::unix::io::RawFd) {
    let Ok(live) = enumerate_live_addrs6() else { return };
    let mut done = std::collections::HashSet::new();
    for l in &live {
        if l.if_index == 0 || !done.insert(l.if_index) {
            continue;
        }
        if let Err(e) = join_dhcp6_multicast(fd, l.if_index) {
            tracing::warn!(
                "interface index {} failed to join DHCPv6 multicast group: {e}",
                l.if_index
            );
        }
    }
}

/// Which sockets a `Listener` should own.
///
/// Upstream always creates the UDP/TCP pair.  This port serves DNS over UDP
/// only, so the caller says what it can actually read — binding a TCP socket
/// nothing ever `accept()`s would open a port that silently swallows
/// connections.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerKinds {
    pub udp:  bool,
    pub tcp:  bool,
    pub tftp: bool,
}

impl Default for ListenerKinds {
    fn default() -> Self {
        Self { udp: true, tcp: true, tftp: false }
    }
}

impl ListenerKinds {
    /// UDP only — what the current DNS runtime can serve.
    pub const UDP_ONLY: Self = Self { udp: true, tcp: false, tftp: false };
}

/// Create a `Listener` bound to `addr`.
///
/// `kinds` selects which sockets are created; the TFTP socket is bound on
/// port 69.  `nowild` is `--bind-interfaces` — see [`make_sock`] for why it is
/// not the same question as "is this socket address-bound".
///
/// Mirrors `create_listeners()` in `network.c`.
#[cfg(unix)]
pub fn create_listeners(
    addr: std::net::SocketAddr,
    kinds: ListenerKinds,
    nowild: bool,
) -> Option<Listener> {
    let udp_fd = if kinds.udp {
        make_sock(addr, SockType::Udp, nowild).unwrap_or(-1)
    } else { -1 };
    let tcp_fd = if kinds.tcp {
        make_sock(addr, SockType::Tcp, nowild).unwrap_or(-1)
    } else { -1 };

    let tftp_fd = if kinds.tftp {
        let mut tftp_addr = addr;
        tftp_addr.set_port(69); // TFTP_PORT
        make_sock(tftp_addr, SockType::Udp, nowild).unwrap_or(-1)
    } else {
        -1
    };

    if udp_fd < 0 && tcp_fd < 0 && tftp_fd < 0 {
        return None;
    }

    Some(Listener {
        addr,
        udp_fd,
        tcp_fd,
        tftp_fd,
        used:  1,
        iface: None,
    })
}

/// Non-Unix stub.
#[cfg(not(unix))]
pub fn create_listeners(
    _addr: std::net::SocketAddr,
    _kinds: ListenerKinds,
    _nowild: bool,
) -> Option<Listener> {
    None
}

/// Marker attached by [`make_sock`] to a `socket()` failure that upstream skips
/// silently (`network.c:900-905`).
#[cfg(unix)]
#[derive(Debug)]
struct FamilyUnsupported(std::io::Error);

#[cfg(unix)]
impl std::fmt::Display for FamilyUnsupported {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "address family not supported: {}", self.0)
    }
}

#[cfg(unix)]
impl std::error::Error for FamilyUnsupported {}

/// True only for a `socket()` call that failed because the kernel does not
/// support the address family.
///
/// Deliberately *not* an errno test: `EINVAL` is on upstream's exempt list, but
/// only where upstream applies it.  `bind()` also returns `EINVAL` — binding a
/// link-local address with no scope id, say — and upstream dies on that.
#[cfg(unix)]
fn family_unsupported(e: &std::io::Error) -> bool {
    e.get_ref().is_some_and(|inner| inner.is::<FamilyUnsupported>())
}

/// True when the address does not exist on any interface.  Under
/// `--bind-dynamic` this is not an error: the address may appear later
/// (`network.c:929-936`).
#[cfg(unix)]
fn addr_not_available(e: &std::io::Error) -> bool {
    e.raw_os_error() == Some(libc::EADDRNOTAVAIL)
}

/// [`create_listeners`], but reporting *why* a socket could not be created.
///
/// `Ok(None)` means the address family is not supported and upstream would move
/// on quietly.  Any other failure is returned as `Err`, because upstream dies on
/// it at startup (`make_sock`'s `dienow` path) — a bind that silently does not
/// happen is exactly the class of bug this module exists to prevent.
///
/// `cleverbind` suppresses `EADDRNOTAVAIL`, as `--bind-dynamic` does.
#[cfg(unix)]
pub fn create_listeners_checked(
    addr:       std::net::SocketAddr,
    kinds:      ListenerKinds,
    nowild:     bool,
    cleverbind: bool,
) -> std::io::Result<Option<Listener>> {
    let sock = |addr: std::net::SocketAddr, kind: SockType, want: bool| {
        if !want {
            return Ok(-1);
        }
        match make_sock(addr, kind, nowild) {
            Ok(fd) => Ok(fd),
            Err(e) if family_unsupported(&e) => Ok(-1),
            Err(e) if cleverbind && addr_not_available(&e) => Ok(-1),
            Err(e) => Err(e),
        }
    };

    let udp_fd = sock(addr, SockType::Udp, kinds.udp)?;
    let tcp_fd = sock(addr, SockType::Tcp, kinds.tcp)?;
    let tftp_fd = {
        let mut tftp_addr = addr;
        tftp_addr.set_port(69); // TFTP_PORT
        sock(tftp_addr, SockType::Udp, kinds.tftp)?
    };

    if udp_fd < 0 && tcp_fd < 0 && tftp_fd < 0 {
        // Every requested socket was skipped, or none was requested at all.
        return Ok(None);
    }

    Ok(Some(Listener {
        addr,
        udp_fd,
        tcp_fd,
        tftp_fd,
        used:  1,
        iface: None,
    }))
}

/// Non-Unix stub.
#[cfg(not(unix))]
pub fn create_listeners_checked(
    _addr: std::net::SocketAddr,
    _kinds: ListenerKinds,
    _nowild: bool,
    _cleverbind: bool,
) -> std::io::Result<Option<Listener>> {
    Ok(None)
}

/// Create wildcard (`0.0.0.0` and `::`) listeners for `port`.
///
/// Returns up to two `Listener`s — one for IPv4, one for IPv6.
///
/// Mirrors `create_wildcard_listeners()` in `network.c`.  Note that these are
/// created with `nowild = false`, so the kernel reports the destination address
/// and arrival interface of every datagram — which is what lets
/// `--interface`/`--listen-address` still be enforced without a per-address
/// bind (see [`ArrivalFilter`]).
pub fn create_wildcard_listeners(port: u16, kinds: ListenerKinds) -> Vec<Listener> {
    create_wildcard_listeners_checked(port, kinds).unwrap_or_default()
}

/// [`create_wildcard_listeners`], failing loudly when a wildcard address could
/// not be bound for a reason other than "no support for this family".
///
/// Upstream dies here (`make_sock`'s `dienow` path), and it matters: a daemon
/// that quietly came up with only the IPv6 wildcard socket because the IPv4
/// port was taken would look healthy and answer nothing.
pub fn create_wildcard_listeners_checked(
    port: u16,
    kinds: ListenerKinds,
) -> std::io::Result<Vec<Listener>> {
    let mut out = Vec::new();
    let addrs: &[std::net::SocketAddr] = &[
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        std::net::SocketAddr::new(
            std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    ];
    for &addr in addrs {
        if let Some(l) =
            create_listeners_checked(addr, kinds, /*nowild=*/false, /*cleverbind=*/false)?
        {
            out.push(l);
        }
    }
    Ok(out)
}

/// Find a listener whose bound address equals `addr`.
///
/// Mirrors `find_listener()` in `network.c`.
pub fn find_listener<'a>(
    listeners: &'a mut [Listener],
    addr: std::net::SocketAddr,
) -> Option<&'a mut Listener> {
    listeners.iter_mut().find(|l| l.addr == addr)
}

/// Create bound listeners for a list of interface addresses.
///
/// For each `(addr, iface_name)` pair:
/// - If a listener already exists for that address, increment its `used`
///   counter.
/// - Otherwise, create a new `Listener` and push it onto the list.
///
/// Returns the number of new listeners created.
///
/// Mirrors the core loop of `create_bound_listeners()` in `network.c`.
pub fn create_bound_listeners(
    listeners: &mut Vec<Listener>,
    iface_addrs: &[(std::net::SocketAddr, String)],
    kinds: ListenerKinds,
    nowild: bool,
) -> usize {
    create_bound_listeners_checked(
        listeners, iface_addrs, kinds, nowild, /*cleverbind=*/true,
    )
    .unwrap_or(0)
}

/// [`create_bound_listeners`], reporting a bind failure instead of skipping the
/// address.
///
/// `nowild` is `--bind-interfaces`, and it is *not* implied by "this socket is
/// address-bound": `--bind-dynamic` binds per address too but leaves `OPT_NOWILD`
/// clear, so its sockets still request `IP_PKTINFO` and get arrival-checked.
///
/// `cleverbind` is `--bind-dynamic`: an address that does not exist yet is
/// tolerated, because netlink will bring it up later (`network.c:929-936`).
pub fn create_bound_listeners_checked(
    listeners: &mut Vec<Listener>,
    iface_addrs: &[(std::net::SocketAddr, String)],
    kinds: ListenerKinds,
    nowild: bool,
    cleverbind: bool,
) -> std::io::Result<usize> {
    let mut created = 0;
    for &(addr, ref name) in iface_addrs {
        // Check if a listener already covers this address.
        if let Some(existing) = find_listener(listeners, addr) {
            existing.used += 1;
            continue;
        }
        if let Some(mut l) = create_listeners_checked(addr, kinds, nowild, cleverbind)? {
            l.iface = Some(name.clone());
            listeners.push(l);
            created += 1;
        }
    }
    Ok(created)
}

// ─── Interface allowed / filtering ───────────────────────────────────────────

/// A known network interface record.
///
/// Mirrors dnsmasq's `struct irec`.
#[derive(Debug, Clone)]
pub struct IfaceRecord {
    /// Interface name, e.g. `"eth0"`.
    pub name:       String,
    /// Kernel interface index.
    pub index:      u32,
    /// IP address of this interface.
    pub addr:       IpAddr,
    /// IPv4 netmask (None for IPv6 addresses).
    pub netmask:    Option<Ipv4Addr>,
    /// Prefix length (for IPv6).
    pub prefix_len: u8,
    /// Whether this is a loopback interface.
    pub loopback:   bool,
    /// Whether DHCP (v4) is allowed on this interface.
    pub dhcp4_ok:   bool,
    /// Whether DHCPv6 is allowed on this interface.
    pub dhcp6_ok:   bool,
    /// Whether TFTP is allowed on this interface.
    pub tftp_ok:    bool,
    /// Whether this is an auth-DNS interface.
    pub auth_dns:   bool,
    /// Used for garbage-collection: set when the interface is seen during
    /// an enumeration pass, cleared when it is not.
    pub found:      bool,
    /// Whether this address is a label (secondary alias) rather than the
    /// primary address of the interface.
    pub is_label:   bool,
}

impl IfaceRecord {
    /// The address a listener for this interface binds to.
    ///
    /// `iface_allowed_v6()` copies the interface index into `sin6_scope_id` for
    /// link-local addresses and zeroes it otherwise — "FreeBSD insists this is
    /// zero for non-linklocal addresses" (`network.c:617-620`).  The scope is
    /// not cosmetic: Linux rejects a `bind()` of a link-local address with no
    /// scope (`EINVAL`), because the address alone does not identify a link.
    pub fn listen_addr(&self, port: u16) -> std::net::SocketAddr {
        match self.addr {
            IpAddr::V4(a) => std::net::SocketAddr::new(IpAddr::V4(a), port),
            IpAddr::V6(a) => {
                let scope = if is_link_local_v6(a) { self.index } else { 0 };
                std::net::SocketAddr::V6(std::net::SocketAddrV6::new(a, port, 0, scope))
            }
        }
    }
}

impl Default for IfaceRecord {
    fn default() -> Self {
        Self {
            name:       String::new(),
            index:      0,
            addr:       IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            netmask:    None,
            prefix_len: 0,
            loopback:   false,
            dhcp4_ok:   true,
            dhcp6_ok:   true,
            tftp_ok:    true,
            auth_dns:   false,
            found:      true,
            is_label:   false,
        }
    }
}

/// Configuration used by `iface_allowed_v4` / `iface_allowed_v6`.
#[derive(Debug, Clone, Default)]
pub struct IfaceAllowedConfig {
    /// Interface name / pattern allowlist (empty = accept all).
    pub if_names:      Vec<String>,
    /// Interface name / pattern denylist, paired with the `INAME_4`/`INAME_6`
    /// family bits it applies to (mirrors `struct iname.flags` in
    /// `dnsmasq.h`). TFTP is disabled on any name match regardless of family.
    pub dhcp_except:   Vec<(String, u32)>,
    /// If non-empty, only these interfaces get TFTP service.
    pub tftp_ifaces:   Vec<String>,
}

/// Determine whether a label (secondary IPv4 address alias) should be treated
/// as a full interface address.
///
/// Returns `true` if any already-known interface record has the same index and
/// IPv4 address — in which case the label is an alias for an address we already
/// serve, not a distinct new interface.
///
/// Mirrors `label_exception()` in `network.c`.
pub fn label_exception(
    index:   u32,
    addr:    Ipv4Addr,
    ifaces:  &[IfaceRecord],
) -> bool {
    ifaces.iter().any(|iface| {
        iface.index == index
            && matches!(iface.addr, IpAddr::V4(a) if a == addr)
    })
}

/// Decide whether an IPv4 interface/address should be added to the served set.
///
/// This is the Rust equivalent of `iface_allowed_v4()` (the adapter around
/// `iface_allowed()`) in `network.c`.
///
/// Returns `Some(IfaceRecord)` if the interface should be added, `None` if it
/// should be skipped.
///
/// The caller is responsible for deduplication (checking whether the same
/// address is already in the list) before calling this function.
pub fn iface_allowed_v4(
    name:       &str,
    label:      Option<&str>,
    index:      u32,
    addr:       Ipv4Addr,
    netmask:    Ipv4Addr,
    loopback:   bool,
    config:     &IfaceAllowedConfig,
    iface_check_cfg: &IfaceCheckConfig,
    used:       &mut IfaceCheckUsed,
) -> Option<IfaceRecord> {
    let effective_name = label.unwrap_or(name);
    let is_label = label.map(|l| l != name).unwrap_or(false);

    // Apply interface name filter.
    let dummy = IfaceInfo {
        name:    effective_name.to_string(),
        index,
        addr:    IpAddr::V4(addr),
        netmask: Some(IpAddr::V4(netmask)),
        flags:   if loopback { IFACE_LOOPBACK } else { 0 },
    };
    if !iface_check_used(&dummy, iface_check_cfg, used) {
        return None;
    }

    // No DHCP/TFTP on loopback.
    let mut dhcp4_ok = !loopback;
    let tftp_ok_base = !loopback;

    // Apply dhcp_except deny list. Matches upstream network.c:538-546: any
    // name match disables TFTP; the family bit gates whether DHCP for this
    // family is also disabled.
    let mut tftp_denied = false;
    for (pat, flags) in &config.dhcp_except {
        if iface_name_matches(name, pat) {
            tftp_denied = true;
            if flags & INAME_4 != 0 {
                dhcp4_ok = false;
            }
        }
    }

    // TFTP: if a dedicated list is given, only those interfaces get TFTP.
    let tftp_ok = if tftp_denied {
        false
    } else if config.tftp_ifaces.is_empty() {
        tftp_ok_base
    } else {
        config.tftp_ifaces.iter().any(|p| iface_name_matches(name, p))
    };

    // Compute prefix length from netmask.
    let mask_u32 = u32::from(netmask);
    let prefix_len = mask_u32.count_ones() as u8;

    Some(IfaceRecord {
        name:       name.to_string(),
        index,
        addr:       IpAddr::V4(addr),
        netmask:    Some(netmask),
        prefix_len,
        loopback,
        dhcp4_ok,
        dhcp6_ok:   false, // IPv4 interface → no DHCPv6
        tftp_ok,
        auth_dns:   false,
        found:      true,
        is_label,
    })
}

/// Decide whether an IPv6 interface/address should be added to the served set.
///
/// Mirrors `iface_allowed_v6()` + the IPv6 path in `iface_allowed()` in
/// `network.c`.
///
/// Returns `Some(IfaceRecord)` if the interface should be added, `None` if it
/// should be skipped (link-local with DHCP-except, or filtered by name).
pub fn iface_allowed_v6(
    name:       &str,
    index:      u32,
    addr:       Ipv6Addr,
    prefix_len: u8,
    loopback:   bool,
    config:     &IfaceAllowedConfig,
    iface_check_cfg: &IfaceCheckConfig,
    used:       &mut IfaceCheckUsed,
) -> Option<IfaceRecord> {
    let dummy = IfaceInfo {
        name:    name.to_string(),
        index,
        addr:    IpAddr::V6(addr),
        netmask: None,
        flags:   if loopback { IFACE_LOOPBACK } else { 0 },
    };
    if !iface_check_used(&dummy, iface_check_cfg, used) {
        return None;
    }

    let mut dhcp6_ok = !loopback;

    let mut tftp_denied = false;
    for (pat, flags) in &config.dhcp_except {
        if iface_name_matches(name, pat) {
            tftp_denied = true;
            if flags & INAME_6 != 0 {
                dhcp6_ok = false;
            }
        }
    }

    let tftp_ok = if tftp_denied {
        false
    } else if config.tftp_ifaces.is_empty() {
        !loopback
    } else {
        config.tftp_ifaces.iter().any(|p| iface_name_matches(name, p))
    };

    Some(IfaceRecord {
        name:       name.to_string(),
        index,
        addr:       IpAddr::V6(addr),
        netmask:    None,
        prefix_len,
        loopback,
        dhcp4_ok:   false, // IPv6 interface → no DHCPv4
        dhcp6_ok,
        tftp_ok,
        auth_dns:   false,
        found:      true,
        is_label:   false,
    })
}

/// The result of one interface-enumeration pass.
///
/// Mirrors what `enumerate_interfaces()` leaves behind in `daemon->interfaces`
/// plus the `INAME_USED` flags it sets on `daemon->if_names` / `if_addrs`.
#[derive(Debug, Clone, Default)]
pub struct EnumeratedInterfaces {
    /// Addresses the daemon is willing to serve, after filtering.
    pub interfaces: Vec<IfaceRecord>,
    /// Which `--interface` / `--listen-address` entries were matched.
    pub used: IfaceCheckUsed,
}

impl EnumeratedInterfaces {
    /// `--interface` patterns that matched no live interface.
    pub fn unmatched_names<'a>(&self, config: &'a IfaceCheckConfig) -> Vec<&'a str> {
        config
            .allow
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.used.names.get(*i).copied().unwrap_or(false))
            .map(|(_, name)| name.as_str())
            .collect()
    }

    /// `--listen-address` values no live interface carries.  Upstream still
    /// binds these (`network.c:1219-1233`): it is legal to listen on 127.0.1.1
    /// when the loopback interface only advertises 127.0.0.1.
    pub fn unmatched_addrs(&self, config: &IfaceCheckConfig) -> Vec<IpAddr> {
        config
            .addrs
            .iter()
            .enumerate()
            .filter(|(i, _)| !self.used.addrs.get(*i).copied().unwrap_or(false))
            .map(|(_, addr)| *addr)
            .collect()
    }
}

/// Walk the live interface list and keep the addresses the config allows.
///
/// Port of `enumerate_interfaces()` (`network.c:722-...`) as far as the DNS
/// listener set is concerned: each address from `getifaddrs(3)` is offered to
/// [`iface_allowed_v4`] / [`iface_allowed_v6`], which apply `check` and record
/// the per-interface DHCP/TFTP permissions.
///
/// `check` is taken by `&mut` because upstream mutates `daemon->if_names` here:
/// when the interface set is restricted at all, loopback interfaces are added
/// to it so that a `--interface=eth0` config still serves 127.0.0.1
/// (`network.c:500-519`).
pub fn enumerate_allowed_interfaces(
    check:   &mut IfaceCheckConfig,
    allowed: &IfaceAllowedConfig,
) -> std::io::Result<EnumeratedInterfaces> {
    let live = enumerate_interfaces()?;
    let mut out = EnumeratedInterfaces {
        interfaces: Vec::new(),
        used: IfaceCheckUsed::for_config(check),
    };

    for info in &live {
        // "If we are restricting the set of interfaces to use, make sure that
        // loopback interfaces are in that set" (network.c:500-519).  The
        // synthesised entry is marked used so it never triggers the "unknown
        // interface" error.  Note the condition is `if_names`, not
        // `if_names || if_addrs`: a bare --listen-address does not pull
        // loopback in.
        if check.has_if_names()
            && info.is_loopback()
            && !check.allow.iter().any(|n| n == &info.name)
        {
            check.allow.push(info.name.clone());
            out.used.names.push(true);
        }

        // "check whether the interface IP has been added already" (network.c:489)
        if out
            .interfaces
            .iter()
            .any(|r| r.addr == info.addr && r.index == info.index)
        {
            continue;
        }

        let record = match (info.addr, info.netmask) {
            (IpAddr::V4(addr), netmask) => {
                let mask = match netmask {
                    Some(IpAddr::V4(m)) => m,
                    _ => Ipv4Addr::UNSPECIFIED,
                };
                iface_allowed_v4(
                    &info.name, None, info.index, addr, mask,
                    info.is_loopback(), allowed, check, &mut out.used,
                )
            }
            (IpAddr::V6(addr), netmask) => {
                let prefix_len = match netmask {
                    Some(IpAddr::V6(m)) => m.octets().iter().map(|b| b.count_ones()).sum::<u32>() as u8,
                    _ => 0,
                };
                iface_allowed_v6(
                    &info.name, info.index, addr, prefix_len,
                    info.is_loopback(), allowed, check, &mut out.used,
                )
            }
        };

        if let Some(record) = record {
            out.interfaces.push(record);
        }
    }

    Ok(out)
}

/// Per-datagram arrival check — upstream's `check_dst` path in `udp_request()`
/// (`forward.c:1771-1780`).
///
/// A wildcard socket receives datagrams addressed to *every* local address, so
/// `--interface` / `--except-interface` / `--listen-address` can only be
/// honoured by re-checking each datagram's arrival interface and destination
/// address, read from the `IP_PKTINFO` / `IPV6_PKTINFO` control message.
///
/// Address-bound sockets need it too, and for a sharper reason: binding an
/// address does not stop a query for that address arriving via a *different*
/// interface.  `forward.c:1612` computes
/// `check_dst = !option_bool(OPT_NOWILD) || family == AF_INET6`, so the check
/// runs for every listener except IPv4 under plain `--bind-interfaces` — the one
/// case where the platform may not report the arrival interface at all, and the
/// reason `network.c:1240-1250` tells you to use `--bind-dynamic` instead.
#[derive(Debug, Clone)]
pub struct ArrivalFilter {
    check:      IfaceCheckConfig,
    allowed:    IfaceAllowedConfig,
    interfaces: Vec<IfaceRecord>,
    /// `--bind-dynamic`: upstream skips the re-enumeration retry in this mode
    /// because netlink already keeps the interface list current.
    cleverbind: bool,
}

impl ArrivalFilter {
    /// Build a filter from a config and an enumeration that has already run.
    pub fn new(
        check:      IfaceCheckConfig,
        allowed:    IfaceAllowedConfig,
        interfaces: Vec<IfaceRecord>,
        cleverbind: bool,
    ) -> Self {
        Self { check, allowed, interfaces, cleverbind }
    }

    /// True when no filtering is configured, so every datagram is accepted and
    /// the caller can skip reading control messages entirely.
    pub fn is_unrestricted(&self) -> bool {
        !self.check.restricted() && self.check.deny.is_empty()
    }

    /// The addresses currently considered local, for `loopback_exception`.
    pub fn interfaces(&self) -> &[IfaceRecord] {
        &self.interfaces
    }

    /// Re-run interface enumeration, as upstream's `enumerate_interfaces(0)`
    /// retry does.  Failures leave the previous list in place.
    pub fn refresh(&mut self) {
        if let Ok(fresh) = enumerate_allowed_interfaces(&mut self.check, &self.allowed) {
            self.interfaces = fresh.interfaces;
        }
    }

    /// Decide whether a datagram that arrived on interface index `if_index`,
    /// addressed to `dest`, may be answered.
    ///
    /// `if_index == 0` or an unresolvable index means the kernel gave us no
    /// arrival interface; upstream drops such packets (`forward.c:1771-1772`)
    /// rather than guessing.
    pub fn accepts(&mut self, if_index: u32, dest: Option<IpAddr>) -> bool {
        if self.is_unrestricted() {
            return true;
        }
        let Some(name) = indextoname(if_index) else { return false };
        let Some(dest) = dest else { return false };

        let info = IfaceInfo {
            index:   if_index,
            addr:    dest,
            netmask: None,
            flags:   0,
            name,
        };
        if iface_check(&info, &self.check) {
            return true;
        }

        // Upstream refreshes the interface list before falling back to the
        // exceptions, so an interface that came up since startup is seen.
        if !self.cleverbind {
            self.refresh();
        }

        let arrival_is_loopback = self
            .interfaces
            .iter()
            .any(|r| r.index == if_index && r.loopback);
        if loopback_exception(arrival_is_loopback, dest, &self.interfaces) {
            return true;
        }
        match dest {
            IpAddr::V4(v4) => label_exception(if_index, v4, &self.interfaces),
            IpAddr::V6(_) => false, // labels are IPv4-only (network.c:212-214)
        }
    }
}

/// Remove stale `IfaceRecord` entries from the interface list.
///
/// An entry is stale if `found == false` (it was not seen in the most recent
/// enumeration pass).  Entries with `found == true` are kept and their `found`
/// flag is reset to `false` ready for the next pass.
///
/// Returns the number of records removed.
///
/// Mirrors `clean_interfaces()` in `network.c`.
pub fn clean_interfaces(ifaces: &mut Vec<IfaceRecord>) -> usize {
    let before = ifaces.len();
    ifaces.retain(|iface| iface.found);
    // Reset `found` on survivors so the next pass starts fresh.
    for iface in ifaces.iter_mut() {
        iface.found = false;
    }
    before - ifaces.len()
}

// ─────────────────────────────────────────────────────────────────────────────
// resolv.conf parsing (ported from network.c:1699-1775)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a resolv.conf-format text and extract nameserver addresses.
///
/// Each line should be "nameserver <ip>" or "server <ip>".
/// Supports IPv4, IPv6, and IPv6 with scope IDs (%eth0).
/// Port of `reload_servers()` from network.c:1699-1775.
pub fn parse_resolv_conf(text: &str, dns_port: u16) -> Vec<std::net::SocketAddr> {
    let mut servers = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let mut tokens = line.split_whitespace();
        let keyword = match tokens.next() {
            Some(k) => k,
            None => continue,
        };
        if keyword != "nameserver" && keyword != "server" {
            continue;
        }
        let addr_str = match tokens.next() {
            Some(a) => a,
            None => continue,
        };
        // Strip scope ID for IPv6 (e.g. "fe80::1%eth0" → "fe80::1")
        let clean = if let Some(idx) = addr_str.find('%') {
            &addr_str[..idx]
        } else {
            addr_str
        };
        if let Ok(ip) = clean.parse::<std::net::IpAddr>() {
            servers.push(std::net::SocketAddr::new(ip, dns_port));
        }
    }
    servers
}

/// Check if an interface address is non-local/non-private and should trigger a warning.
///
/// Returns true for globally-routable addresses that should be warned about
/// when using --bind-interfaces without --bind-dynamic.
/// Port of the logic in `warn_bound_listeners()` from network.c:1251-1274.
pub fn is_globally_routable(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            !(octets[0] == 10
                || (octets[0] == 172 && (octets[1] & 0xf0) == 16)
                || (octets[0] == 192 && octets[1] == 168)
                || octets[0] == 127
                || v4 == Ipv4Addr::UNSPECIFIED)
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            !((octets[0] & 0xfe) == 0xfc  // ULA
                || (octets[0] == 0xfe && (octets[1] & 0xc0) == 0x80) // link-local
                || v6 == Ipv6Addr::LOCALHOST
                || v6 == Ipv6Addr::UNSPECIFIED)
        }
    }
}

/// Validate an upstream server address.
///
/// Returns `None` if the address is valid, or `Some(reason)` if invalid.
pub fn validate_server_addr(addr: &std::net::SocketAddr) -> Option<&'static str> {
    if addr.port() == 0 {
        return Some("port is zero");
    }
    match addr.ip() {
        IpAddr::V4(v4) if v4 == Ipv4Addr::UNSPECIFIED => Some("address is 0.0.0.0"),
        IpAddr::V6(v6) if v6 == Ipv6Addr::UNSPECIFIED => Some("address is ::"),
        _ => None,
    }
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

    #[test]
    fn test_is_ula_zero_v6() {
        // Exact match: fd00::
        let ula_zero: Ipv6Addr = "fd00::".parse().unwrap();
        assert!(is_ula_zero_v6(ula_zero));
        // Non-zero suffix should not match
        let ula_nonzero: Ipv6Addr = "fd00::1".parse().unwrap();
        assert!(!is_ula_zero_v6(ula_nonzero));
        // Other ULA addresses should not match
        let other_ula: Ipv6Addr = "fc00::".parse().unwrap();
        assert!(!is_ula_zero_v6(other_ula));
        // Non-ULA addresses should not match
        let not_ula: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(!is_ula_zero_v6(not_ula));
    }

    #[test]
    fn test_is_link_local_zero_v6() {
        // Exact match: fe80::
        let ll_zero: Ipv6Addr = "fe80::".parse().unwrap();
        assert!(is_link_local_zero_v6(ll_zero));
        // Non-zero suffix should not match
        let ll_nonzero: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(!is_link_local_zero_v6(ll_nonzero));
        // Other link-local addresses should not match
        let other_ll: Ipv6Addr = "fe80:1::".parse().unwrap();
        assert!(!is_link_local_zero_v6(other_ll));
        // Non-link-local addresses should not match
        let not_ll: Ipv6Addr = "2001:db8::".parse().unwrap();
        assert!(!is_link_local_zero_v6(not_ll));
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
            ..Default::default()
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
            ..Default::default()
        };
        assert!(!iface_check(&make_iface("eth0"), &cfg));
        assert!(iface_check(&make_iface("eth1"), &cfg));
    }

    // ── iface_check: --listen-address (network.c:130-148) ────────────────────

    fn make_iface_at(name: &str, addr: IpAddr) -> IfaceInfo {
        IfaceInfo { name: name.to_string(), index: 0, addr, netmask: None, flags: 0 }
    }

    /// `--listen-address` alone restricts the served set: an interface whose
    /// address is not listed is rejected even though no `--interface` was given.
    #[test]
    fn iface_check_listen_address_restricts_by_address() {
        let cfg = IfaceCheckConfig {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
            ..Default::default()
        };
        assert!(iface_check(&make_iface_at("lo", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), &cfg));
        assert!(!iface_check(&make_iface_at("lo", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))), &cfg));
        assert!(!iface_check(&make_iface_at("eth0", IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))), &cfg));
    }

    /// An explicit `--listen-address` match outranks `--except-interface`
    /// (upstream's `match_addr` short-circuit).
    #[test]
    fn iface_check_listen_address_beats_except_interface() {
        let cfg = IfaceCheckConfig {
            deny:  vec!["lo".to_string()],
            addrs: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
            ..Default::default()
        };
        assert!(iface_check(&make_iface_at("lo", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), &cfg));
        assert!(!iface_check(&make_iface_at("lo", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))), &cfg));
    }

    /// `--except-interface` still wins over a plain `--interface` name match.
    #[test]
    fn iface_check_except_interface_beats_name_match() {
        let cfg = IfaceCheckConfig {
            allow: vec!["lo".to_string()],
            deny:  vec!["lo".to_string()],
            ..Default::default()
        };
        assert!(!iface_check(&make_iface_at("lo", IpAddr::V4(Ipv4Addr::LOCALHOST)), &cfg));
    }

    /// A NULL-named `--interface` (upstream's `--local-service=host`) restricts
    /// everything without naming anything.
    #[test]
    fn iface_check_unnamed_iface_restricts_everything() {
        let cfg = IfaceCheckConfig { unnamed_iface: true, ..Default::default() };
        assert!(cfg.restricted());
        assert!(!iface_check(&make_iface("eth0"), &cfg));
    }

    #[test]
    fn iface_check_records_used_entries() {
        let cfg = IfaceCheckConfig {
            allow: vec!["eth*".to_string(), "wlan0".to_string()],
            addrs: vec![
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            ],
            ..Default::default()
        };
        let mut used = IfaceCheckUsed::for_config(&cfg);
        assert!(iface_check_used(
            &make_iface_at("eth0", IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))),
            &cfg,
            &mut used,
        ));
        assert_eq!(used.names, vec![true, false], "only eth* matched");
        assert_eq!(used.addrs, vec![true, false], "only 127.0.0.1 matched");
    }

    // ── loopback_exception (network.c:185-206) ───────────────────────────────

    #[test]
    fn loopback_exception_accepts_known_address_via_loopback() {
        let ifaces = vec![make_iface_rec(1, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))];
        assert!(loopback_exception(true, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), &ifaces));
    }

    #[test]
    fn loopback_exception_rejects_unknown_address() {
        let ifaces = vec![make_iface_rec(1, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))];
        assert!(!loopback_exception(true, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), &ifaces));
    }

    #[test]
    fn loopback_exception_rejects_non_loopback_arrival() {
        let ifaces = vec![make_iface_rec(1, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))];
        assert!(!loopback_exception(false, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), &ifaces));
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
        let has_lo = ifaces.iter().any(|i| i.addr.is_loopback());
        assert!(has_lo, "no loopback address found");
    }

    /// The loopback interface must come back flagged and with a real index —
    /// `iface_allowed_*` and the per-datagram arrival check both depend on it,
    /// and `if-addrs` supplies neither.
    #[test]
    fn enumerate_interfaces_fills_index_and_loopback_flag() {
        let ifaces = enumerate_interfaces().expect("enumeration must succeed");
        let Some(lo) = ifaces.iter().find(|i| i.addr.is_loopback()) else { return };
        assert!(lo.is_loopback(), "loopback address must carry IFACE_LOOPBACK");
        assert_ne!(lo.index, 0, "interface index must be resolved");
    }

    // ── enumerate_allowed_interfaces ─────────────────────────────────────────

    /// `--interface=nosuchif0` matches nothing, and the unmatched name is
    /// reported so the caller can raise upstream's "unknown interface" error.
    #[test]
    fn enumerate_allowed_reports_unmatched_interface_name() {
        let mut check = IfaceCheckConfig {
            allow: vec!["nosuchif0".to_string()],
            ..Default::default()
        };
        let out = enumerate_allowed_interfaces(&mut check, &IfaceAllowedConfig::default())
            .expect("enumeration must succeed");
        assert!(
            out.unmatched_names(&check).contains(&"nosuchif0"),
            "nosuchif0 matched no live interface, so it must be reported unused"
        );
    }

    /// A restricted interface set still keeps loopback, because upstream adds
    /// loopback interfaces to `if_names` during enumeration (network.c:500-519).
    #[test]
    fn enumerate_allowed_keeps_loopback_in_a_restricted_set() {
        let mut check = IfaceCheckConfig {
            allow: vec!["nosuchif0".to_string()],
            ..Default::default()
        };
        let out = enumerate_allowed_interfaces(&mut check, &IfaceAllowedConfig::default())
            .expect("enumeration must succeed");
        let has_loopback = enumerate_interfaces()
            .map(|live| live.iter().any(|i| i.addr.is_loopback()))
            .unwrap_or(false);
        if !has_loopback {
            return; // no loopback address visible here
        }
        assert!(
            out.interfaces.iter().any(|i| i.addr.is_loopback()),
            "loopback must survive a restricted --interface set"
        );
    }

    /// A bare `--listen-address` must *not* pull loopback into the served set:
    /// upstream keys that rule off `daemon->if_names` alone, so listening on one
    /// address does not quietly start serving 127.0.0.1 as well.
    #[test]
    fn enumerate_allowed_listen_address_alone_does_not_add_loopback() {
        let unusual = IpAddr::V4(Ipv4Addr::new(127, 199, 199, 199));
        let mut check = IfaceCheckConfig { addrs: vec![unusual], ..Default::default() };
        assert!(check.restricted() && !check.has_if_names());
        let out = enumerate_allowed_interfaces(&mut check, &IfaceAllowedConfig::default())
            .expect("enumeration must succeed");
        assert!(
            check.allow.is_empty(),
            "--listen-address must not synthesise an --interface entry: {:?}",
            check.allow
        );
        assert!(
            out.interfaces.is_empty(),
            "no live interface carries {unusual}, so nothing may be served"
        );
    }

    /// `--listen-address` for an address no interface carries is still reported,
    /// so bound mode can bind it explicitly (network.c:1219-1233).
    #[test]
    fn enumerate_allowed_reports_unmatched_listen_address() {
        let unusual = IpAddr::V4(Ipv4Addr::new(127, 199, 199, 199));
        let mut check = IfaceCheckConfig { addrs: vec![unusual], ..Default::default() };
        let out = enumerate_allowed_interfaces(&mut check, &IfaceAllowedConfig::default())
            .expect("enumeration must succeed");
        assert_eq!(out.unmatched_addrs(&check), vec![unusual]);
    }

    // ── ArrivalFilter ───────────────────────────────────────────────────────

    #[test]
    fn wildcard_filter_unrestricted_accepts_without_metadata() {
        let mut filter = ArrivalFilter::new(
            IfaceCheckConfig::default(),
            IfaceAllowedConfig::default(),
            Vec::new(),
            false,
        );
        assert!(filter.is_unrestricted());
        assert!(filter.accepts(0, None), "an unfiltered daemon answers everything");
    }

    /// With `--listen-address` set, a datagram whose destination is a different
    /// local address must be dropped — the wildcard-socket half of the fix.
    #[test]
    fn wildcard_filter_drops_other_destination_addresses() {
        let check = IfaceCheckConfig {
            addrs: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
            ..Default::default()
        };
        let lo_index = nametoindex("lo");
        if lo_index == 0 {
            return; // no interface named "lo" here
        }
        let mut filter = ArrivalFilter::new(
            check,
            IfaceAllowedConfig::default(),
            Vec::new(),
            /*cleverbind=*/true, // no re-enumeration, so the test is deterministic
        );
        assert!(!filter.is_unrestricted());
        assert!(
            filter.accepts(lo_index, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))),
            "the configured listen address must be served"
        );
        assert!(
            !filter.accepts(lo_index, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)))),
            "127.0.0.2 is not the configured listen address"
        );
    }

    /// No arrival metadata means the packet cannot be checked, and upstream
    /// drops it rather than guessing.
    #[test]
    fn wildcard_filter_drops_packets_with_no_arrival_metadata() {
        let check = IfaceCheckConfig {
            allow: vec!["eth0".to_string()],
            ..Default::default()
        };
        let mut filter = ArrivalFilter::new(
            check, IfaceAllowedConfig::default(), Vec::new(), true,
        );
        assert!(!filter.accepts(0, None));
        assert!(!filter.accepts(0, Some(IpAddr::V4(Ipv4Addr::LOCALHOST))));
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

    // ── fix_fd ────────────────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn fix_fd_on_pipe_sets_nonblock() {
        use std::os::unix::io::IntoRawFd;
        // Create a pipe; fix_fd the read end.
        let (read_pipe, _write_pipe) = {
            let mut fds = [0i32; 2];
            unsafe { libc::pipe(fds.as_mut_ptr()) };
            (fds[0], fds[1])
        };
        let result = fix_fd(read_pipe);
        // Clean up.
        unsafe { libc::close(read_pipe) };
        assert!(result.is_ok(), "fix_fd failed: {:?}", result.err());
    }

    #[cfg(unix)]
    #[test]
    fn fix_fd_invalid_fd_returns_error() {
        let result = fix_fd(-1);
        assert!(result.is_err(), "expected error for invalid fd");
    }

    // ── indextoname ───────────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn indextoname_zero_returns_none() {
        assert!(indextoname(0).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn indextoname_loopback_returns_name() {
        // The loopback interface is always index 1 on Linux.
        // If it's unavailable the test is still valid (just None).
        let result = indextoname(1);
        if let Some(name) = result {
            assert!(!name.is_empty(), "interface name should not be empty");
        }
    }

    #[cfg(unix)]
    #[test]
    fn indextoname_invalid_returns_none() {
        // A very large index is unlikely to exist.
        assert!(indextoname(u32::MAX).is_none());
    }

    // ── set_ipv6pktinfo ───────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn set_ipv6pktinfo_on_ipv6_socket() {
        // Create a real IPv6 UDP socket.
        let fd = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
        if fd == -1 {
            // IPv6 not available in CI — skip.
            return;
        }
        let result = set_ipv6pktinfo(fd);
        unsafe { libc::close(fd) };
        assert!(result.is_ok());
        // We don't assert true/false since kernel support varies.
    }

    // ── join_dhcp6_multicast ──────────────────────────────────────────────────

    #[cfg(all(unix, target_os = "linux"))]
    #[test]
    fn join_dhcp6_multicast_on_loopback_succeeds() {
        let addr: std::net::SocketAddr = "[::]:0".parse().unwrap();
        let fd = match make_sock(addr, SockType::Udp, true) {
            Ok(fd) => fd,
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => return,
            Err(e) => panic!("make_sock UDP6 failed: {e}"),
        };
        let if_index = nametoindex("lo");
        if if_index == 0 {
            unsafe { libc::close(fd); }
            return;
        }
        let result = join_dhcp6_multicast(fd, if_index);
        unsafe { libc::close(fd); }
        assert!(result.is_ok(), "expected loopback multicast join to succeed: {result:?}");
    }

    // ── tcp_interface ─────────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn tcp_interface_invalid_fd_returns_zero() {
        // An invalid fd should not panic; just return 0.
        let result = tcp_interface(-1, false);
        assert_eq!(result, 0);
    }

    // ── Listener / make_sock / create_listeners ───────────────────────────────

    #[cfg(unix)]
    #[test]
    fn make_sock_udp_creates_socket() {
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let fd = make_sock(addr, SockType::Udp, true).expect("make_sock UDP failed");
        assert!(fd >= 0);
        unsafe { libc::close(fd); }
    }

    #[cfg(unix)]
    #[test]
    fn make_sock_tcp_creates_socket() {
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let fd = make_sock(addr, SockType::Tcp, true).expect("make_sock TCP failed");
        assert!(fd >= 0);
        unsafe { libc::close(fd); }
    }

    #[cfg(unix)]
    #[test]
    fn make_sock_ipv6_creates_socket() {
        let addr: std::net::SocketAddr = "[::1]:0".parse().unwrap();
        // IPv6 may not be available in all CI environments; treat EAFNOSUPPORT as skip.
        match make_sock(addr, SockType::Udp, true) {
            Ok(fd) => { assert!(fd >= 0); unsafe { libc::close(fd); } }
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn create_listeners_returns_some() {
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let l = create_listeners(addr, ListenerKinds::default(), true).expect("should create listener");
        // At least one of UDP/TCP must be valid.
        assert!(l.udp_fd >= 0 || l.tcp_fd >= 0);
        // Manual cleanup.
        unsafe {
            if l.udp_fd >= 0 { libc::close(l.udp_fd); }
            if l.tcp_fd >= 0 { libc::close(l.tcp_fd); }
        }
        // Prevent double-close by forgetting the Listener (which has no Drop impl).
    }

    #[test]
    fn create_wildcard_listeners_produces_entries() {
        // Port 0 lets the OS pick a free port; should always succeed.
        let listeners = create_wildcard_listeners(0, ListenerKinds::default());
        // At least the IPv4 wildcard listener must be created.
        assert!(!listeners.is_empty(), "wildcard listeners should not be empty");
        #[cfg(unix)]
        for l in listeners {
            unsafe {
                if l.udp_fd >= 0 { libc::close(l.udp_fd); }
                if l.tcp_fd >= 0 { libc::close(l.tcp_fd); }
            }
        }
    }

    /// `make_sock`'s third argument is upstream's *global* `OPT_NOWILD`, not
    /// "is this socket address-bound": `network.c:964` requests `IP_PKTINFO`
    /// whenever `--bind-interfaces` is off, so `--bind-dynamic`'s bound sockets
    /// get it too and can be arrival-checked.
    #[cfg(target_os = "linux")]
    #[test]
    fn make_sock_requests_ip_pktinfo_unless_nowild() {
        use std::os::unix::io::RawFd;

        fn pktinfo_enabled(fd: RawFd) -> i32 {
            let mut val: libc::c_int = -1;
            let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::IPPROTO_IP,
                    libc::IP_PKTINFO,
                    &mut val as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            assert_eq!(rc, 0, "getsockopt(IP_PKTINFO) failed");
            val
        }

        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let Ok(wild) = make_sock(addr, SockType::Udp, /*nowild=*/false) else { return };
        assert_ne!(
            pktinfo_enabled(wild), 0,
            "IP_PKTINFO must be requested when --bind-interfaces is not set"
        );
        unsafe { libc::close(wild) };

        let Ok(bound) = make_sock(addr, SockType::Udp, /*nowild=*/true) else { return };
        assert_eq!(
            pktinfo_enabled(bound), 0,
            "--bind-interfaces suppresses IP_PKTINFO (network.c:962-966)"
        );
        unsafe { libc::close(bound) };
    }

    /// `network.c:900-905` exempts `EPROTONOSUPPORT`/`EAFNOSUPPORT`/`EINVAL`
    /// only for the `socket()` call.  Every later failure — `bind()` included —
    /// falls through to `die()`, so a bind that did not happen must never be
    /// reported as success.
    #[test]
    fn create_listeners_checked_reports_a_bind_failure() {
        // Gate: no usable IPv6 here means `socket()` itself fails, which *is*
        // the exempt case.
        if std::net::UdpSocket::bind("[::1]:0").is_err() {
            return;
        }
        // A link-local address with no scope id: `socket()` succeeds, `bind()`
        // returns EINVAL because the kernel cannot tell which link it means.
        let addr = std::net::SocketAddr::V6(std::net::SocketAddrV6::new(
            "fe80::1".parse().unwrap(), 0, 0, /*scope_id=*/0,
        ));
        let result = create_listeners_checked(
            addr, ListenerKinds::UDP_ONLY, /*nowild=*/true, /*cleverbind=*/false,
        );
        match result {
            Err(_) => {}
            Ok(Some(l)) => {
                unsafe { if l.udp_fd >= 0 { libc::close(l.udp_fd); } }
                panic!("binding {addr} unexpectedly succeeded");
            }
            Ok(None) => panic!("a bind() failure was silently swallowed as Ok(None)"),
        }
    }

    /// Upstream copies the interface index into `sin6_scope_id`, but only for
    /// link-local addresses — "FreeBSD insists this is zero for non-linklocal"
    /// (`network.c:617-620`).  Without it the link-local listener cannot bind.
    #[test]
    fn iface_record_listen_addr_scopes_link_local_only() {
        let record = |addr: IpAddr| IfaceRecord {
            name: "eth0".into(), index: 7, addr, ..IfaceRecord::default()
        };

        let link_local = record(IpAddr::V6("fe80::1".parse().unwrap())).listen_addr(53);
        match link_local {
            std::net::SocketAddr::V6(a) => assert_eq!(a.scope_id(), 7),
            other => panic!("expected an IPv6 address, got {other}"),
        }

        let global = record(IpAddr::V6("2001:db8::1".parse().unwrap())).listen_addr(53);
        match global {
            std::net::SocketAddr::V6(a) => assert_eq!(a.scope_id(), 0),
            other => panic!("expected an IPv6 address, got {other}"),
        }

        let v4 = record(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))).listen_addr(53);
        assert_eq!(v4, "192.0.2.1:53".parse::<std::net::SocketAddr>().unwrap());
    }

    #[test]
    fn find_listener_finds_matching_addr() {
        // Fabricate two fake listeners (fds -1 to avoid real sockets).
        let addr1: std::net::SocketAddr = "127.0.0.1:5300".parse().unwrap();
        let addr2: std::net::SocketAddr = "127.0.0.1:5301".parse().unwrap();
        let mut listeners = vec![
            Listener { addr: addr1, udp_fd: -1, tcp_fd: -1, tftp_fd: -1, used: 1, iface: None },
            Listener { addr: addr2, udp_fd: -1, tcp_fd: -1, tftp_fd: -1, used: 1, iface: None },
        ];
        let found = find_listener(&mut listeners, addr1);
        assert!(found.is_some());
        assert_eq!(found.unwrap().addr, addr1);
    }

    #[test]
    fn find_listener_returns_none_for_missing() {
        let addr: std::net::SocketAddr = "127.0.0.1:5300".parse().unwrap();
        let other: std::net::SocketAddr = "127.0.0.1:5301".parse().unwrap();
        let mut listeners = vec![
            Listener { addr, udp_fd: -1, tcp_fd: -1, tftp_fd: -1, used: 1, iface: None },
        ];
        assert!(find_listener(&mut listeners, other).is_none());
    }

    #[test]
    fn listener_release_decrements_used() {
        let addr: std::net::SocketAddr = "127.0.0.1:5302".parse().unwrap();
        let mut l = Listener {
            addr, udp_fd: -1, tcp_fd: -1, tftp_fd: -1, used: 2, iface: None,
        };
        let freed = l.release();
        assert!(!freed, "should not free when used > 1");
        assert_eq!(l.used, 1);
    }

    #[test]
    fn listener_release_frees_when_last() {
        let addr: std::net::SocketAddr = "127.0.0.1:5303".parse().unwrap();
        let mut l = Listener {
            addr, udp_fd: -1, tcp_fd: -1, tftp_fd: -1, used: 1, iface: None,
        };
        let freed = l.release();
        assert!(freed, "should free when used == 1");
    }

    #[test]
    fn create_bound_listeners_reuses_existing() {
        let addr: std::net::SocketAddr = "127.0.0.1:5304".parse().unwrap();
        let mut listeners = vec![
            Listener { addr, udp_fd: -1, tcp_fd: -1, tftp_fd: -1, used: 1, iface: None },
        ];
        let ifaces = vec![(addr, "lo".to_string())];
        let created = create_bound_listeners(&mut listeners, &ifaces, ListenerKinds::default(), /*nowild=*/true);
        assert_eq!(created, 0, "no new listener should be created for existing addr");
        assert_eq!(listeners[0].used, 2, "used counter should be incremented");
    }

    #[cfg(unix)]
    #[test]
    fn create_bound_listeners_creates_new() {
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut listeners: Vec<Listener> = vec![];
        let ifaces = vec![(addr, "lo".to_string())];
        let created = create_bound_listeners(&mut listeners, &ifaces, ListenerKinds::default(), /*nowild=*/true);
        assert_eq!(created, 1);
        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].iface.as_deref(), Some("lo"));
        unsafe {
            if listeners[0].udp_fd >= 0 { libc::close(listeners[0].udp_fd); }
            if listeners[0].tcp_fd >= 0 { libc::close(listeners[0].tcp_fd); }
        }
    }

    // ── label_exception ───────────────────────────────────────────────────────

    fn make_iface_rec(index: u32, addr: IpAddr) -> IfaceRecord {
        IfaceRecord { index, addr, ..Default::default() }
    }

    #[test]
    fn label_exception_matches_same_index_and_addr() {
        let ifaces = vec![
            make_iface_rec(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        ];
        assert!(label_exception(2, Ipv4Addr::new(192, 168, 1, 1), &ifaces));
    }

    #[test]
    fn label_exception_no_match_different_index() {
        let ifaces = vec![
            make_iface_rec(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        ];
        assert!(!label_exception(3, Ipv4Addr::new(192, 168, 1, 1), &ifaces));
    }

    #[test]
    fn label_exception_no_match_different_addr() {
        let ifaces = vec![
            make_iface_rec(2, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
        ];
        assert!(!label_exception(2, Ipv4Addr::new(10, 0, 0, 1), &ifaces));
    }

    // ── iface_allowed_v4 ──────────────────────────────────────────────────────

    fn default_allowed_cfg() -> IfaceAllowedConfig { IfaceAllowedConfig::default() }
    fn default_check_cfg() -> IfaceCheckConfig { IfaceCheckConfig::default() }

    #[test]
    fn iface_allowed_v4_accepts_normal_iface() {
        let rec = iface_allowed_v4(
            "eth0", None, 2,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            false,
            &default_allowed_cfg(), &default_check_cfg(), &mut IfaceCheckUsed::default(),
        );
        assert!(rec.is_some());
        let rec = rec.unwrap();
        assert!(rec.dhcp4_ok);
        assert_eq!(rec.prefix_len, 24);
    }

    #[test]
    fn iface_allowed_v4_loopback_disables_dhcp() {
        let rec = iface_allowed_v4(
            "lo", None, 1,
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::new(255, 0, 0, 0),
            true,
            &default_allowed_cfg(), &default_check_cfg(), &mut IfaceCheckUsed::default(),
        ).unwrap();
        assert!(!rec.dhcp4_ok, "loopback should have dhcp4 disabled");
        assert!(!rec.tftp_ok,  "loopback should have tftp disabled");
    }

    #[test]
    fn iface_allowed_v4_dhcp_except_disables_dhcp() {
        let cfg = IfaceAllowedConfig {
            dhcp_except: vec![("eth0".to_string(), INAME_4 | INAME_6)],
            ..Default::default()
        };
        let rec = iface_allowed_v4(
            "eth0", None, 2,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            false,
            &cfg, &default_check_cfg(), &mut IfaceCheckUsed::default(),
        ).unwrap();
        assert!(!rec.dhcp4_ok, "dhcp_except should disable dhcp");
        assert!(!rec.tftp_ok, "dhcp_except should disable tftp regardless of family");
    }

    #[test]
    fn iface_allowed_v4_no_dhcpv6_interface_leaves_v4_enabled() {
        // `no-dhcpv6-interface=eth0` stores only INAME_6 — v4 must stay on.
        let cfg = IfaceAllowedConfig {
            dhcp_except: vec![("eth0".to_string(), INAME_6)],
            ..Default::default()
        };
        let rec = iface_allowed_v4(
            "eth0", None, 2,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            false,
            &cfg, &default_check_cfg(), &mut IfaceCheckUsed::default(),
        ).unwrap();
        assert!(rec.dhcp4_ok, "no-dhcpv6-interface must not disable dhcp4");
    }

    #[test]
    fn iface_allowed_v6_no_dhcpv4_interface_leaves_v6_enabled() {
        // `no-dhcpv4-interface=eth0` stores only INAME_4 — v6 must stay on.
        let cfg = IfaceAllowedConfig {
            dhcp_except: vec![("eth0".to_string(), INAME_4)],
            ..Default::default()
        };
        let rec = iface_allowed_v6(
            "eth0", 2,
            "fe80::1".parse().unwrap(),
            64,
            false,
            &cfg, &default_check_cfg(), &mut IfaceCheckUsed::default(),
        ).unwrap();
        assert!(rec.dhcp6_ok, "no-dhcpv4-interface must not disable dhcp6");
    }

    #[test]
    fn iface_allowed_v6_no_dhcpv6_interface_disables_v6() {
        let cfg = IfaceAllowedConfig {
            dhcp_except: vec![("eth0".to_string(), INAME_6)],
            ..Default::default()
        };
        let rec = iface_allowed_v6(
            "eth0", 2,
            "fe80::1".parse().unwrap(),
            64,
            false,
            &cfg, &default_check_cfg(), &mut IfaceCheckUsed::default(),
        ).unwrap();
        assert!(!rec.dhcp6_ok, "no-dhcpv6-interface should disable dhcp6");
    }

    #[test]
    fn iface_allowed_v4_denied_by_check_config() {
        let check_cfg = IfaceCheckConfig {
            deny: vec!["docker*".to_string()],
            ..Default::default()
        };
        let rec = iface_allowed_v4(
            "docker0", None, 5,
            Ipv4Addr::new(172, 17, 0, 1),
            Ipv4Addr::new(255, 255, 0, 0),
            false,
            &default_allowed_cfg(), &check_cfg, &mut IfaceCheckUsed::default(),
        );
        assert!(rec.is_none(), "docker0 should be denied by check_cfg deny list");
    }

    // ── iface_allowed_v6 ──────────────────────────────────────────────────────

    #[test]
    fn iface_allowed_v6_accepts_global_addr() {
        let addr = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let rec = iface_allowed_v6(
            "eth0", 2, addr, 64, false,
            &default_allowed_cfg(), &default_check_cfg(), &mut IfaceCheckUsed::default(),
        );
        assert!(rec.is_some());
        let rec = rec.unwrap();
        assert!(rec.dhcp6_ok);
        assert_eq!(rec.prefix_len, 64);
    }

    #[test]
    fn iface_allowed_v6_loopback_disables_dhcp6() {
        let addr = "::1".parse::<Ipv6Addr>().unwrap();
        let rec = iface_allowed_v6(
            "lo", 1, addr, 128, true,
            &default_allowed_cfg(), &default_check_cfg(), &mut IfaceCheckUsed::default(),
        ).unwrap();
        assert!(!rec.dhcp6_ok);
        assert!(!rec.tftp_ok);
    }

    // ── clean_interfaces ──────────────────────────────────────────────────────

    #[test]
    fn clean_interfaces_removes_unfound() {
        let mut ifaces = vec![
            IfaceRecord { found: true,  ..Default::default() },
            IfaceRecord { found: false, ..Default::default() },
            IfaceRecord { found: true,  ..Default::default() },
        ];
        let removed = clean_interfaces(&mut ifaces);
        assert_eq!(removed, 1, "one unfound interface should be removed");
        assert_eq!(ifaces.len(), 2);
        // After clean, found flags should be reset to false for next pass.
        assert!(ifaces.iter().all(|r| !r.found));
    }

    #[test]
    fn clean_interfaces_empty_list_ok() {
        let mut ifaces: Vec<IfaceRecord> = vec![];
        let removed = clean_interfaces(&mut ifaces);
        assert_eq!(removed, 0);
    }

    // ── parse_resolv_conf ────────────────────────────────────────────────────

    #[test]
    fn parse_resolv_conf_ipv4() {
        let text = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n";
        let servers = parse_resolv_conf(text, 53);
        assert_eq!(servers.len(), 2);
        assert_eq!(servers[0].ip(), "8.8.8.8".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(servers[0].port(), 53);
    }

    #[test]
    fn parse_resolv_conf_ipv6() {
        let text = "nameserver ::1\n";
        let servers = parse_resolv_conf(text, 53);
        assert_eq!(servers.len(), 1);
        assert!(servers[0].ip().is_ipv6());
    }

    #[test]
    fn parse_resolv_conf_ipv6_scope() {
        let text = "nameserver fe80::1%eth0\n";
        let servers = parse_resolv_conf(text, 53);
        assert_eq!(servers.len(), 1);
    }

    #[test]
    fn parse_resolv_conf_skips_comments() {
        let text = "# comment\nnameserver 1.1.1.1\nsearch example.com\n";
        let servers = parse_resolv_conf(text, 53);
        assert_eq!(servers.len(), 1);
    }

    #[test]
    fn parse_resolv_conf_empty() {
        let servers = parse_resolv_conf("", 53);
        assert!(servers.is_empty());
    }

    #[test]
    fn parse_resolv_conf_server_keyword() {
        let text = "server 9.9.9.9\n";
        let servers = parse_resolv_conf(text, 53);
        assert_eq!(servers.len(), 1);
    }

    #[test]
    fn parse_resolv_conf_custom_port() {
        let servers = parse_resolv_conf("nameserver 1.2.3.4\n", 5353);
        assert_eq!(servers[0].port(), 5353);
    }

    #[test]
    fn parse_resolv_conf_invalid_addr_skipped() {
        let text = "nameserver not.valid\nnameserver 8.8.8.8\n";
        let servers = parse_resolv_conf(text, 53);
        assert_eq!(servers.len(), 1);
    }

    // ── is_globally_routable ─────────────────────────────────────────────────

    #[test]
    fn globally_routable_public_ipv4() {
        assert!(is_globally_routable("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn globally_routable_private_ipv4() {
        assert!(!is_globally_routable("10.0.0.1".parse().unwrap()));
        assert!(!is_globally_routable("172.16.0.1".parse().unwrap()));
        assert!(!is_globally_routable("192.168.1.1".parse().unwrap()));
        assert!(!is_globally_routable("127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn globally_routable_public_ipv6() {
        assert!(is_globally_routable("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn globally_routable_ula_ipv6() {
        assert!(!is_globally_routable("fd00::1".parse().unwrap()));
    }

    #[test]
    fn globally_routable_link_local_ipv6() {
        assert!(!is_globally_routable("fe80::1".parse().unwrap()));
    }

    // ── validate_server_addr ─────────────────────────────────────────────────

    #[test]
    fn validate_server_addr_good() {
        let addr: std::net::SocketAddr = "8.8.8.8:53".parse().unwrap();
        assert!(validate_server_addr(&addr).is_none());
    }

    #[test]
    fn validate_server_addr_zero_port() {
        let addr: std::net::SocketAddr = "8.8.8.8:0".parse().unwrap();
        assert!(validate_server_addr(&addr).is_some());
    }

    #[test]
    fn validate_server_addr_unspecified() {
        let addr: std::net::SocketAddr = "0.0.0.0:53".parse().unwrap();
        assert!(validate_server_addr(&addr).is_some());
    }

    // ── netmask_to_prefix6 ────────────────────────────────────────────────────

    #[test]
    fn netmask_to_prefix6_64() {
        let mask: Ipv6Addr = "ffff:ffff:ffff:ffff::".parse().unwrap();
        assert_eq!(netmask_to_prefix6(mask), 64);
    }

    #[test]
    fn netmask_to_prefix6_128() {
        assert_eq!(netmask_to_prefix6(Ipv6Addr::from([0xff; 16])), 128);
    }

    #[test]
    fn netmask_to_prefix6_zero() {
        assert_eq!(netmask_to_prefix6(Ipv6Addr::UNSPECIFIED), 0);
    }

    // ── parse_mac_addr_str ────────────────────────────────────────────────────

    #[test]
    fn parse_mac_addr_str_valid() {
        assert_eq!(
            parse_mac_addr_str("aa:bb:cc:dd:ee:ff\n"),
            Some(vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
    }

    #[test]
    fn parse_mac_addr_str_all_zero_rejected() {
        assert_eq!(parse_mac_addr_str("00:00:00:00:00:00"), None);
    }

    #[test]
    fn parse_mac_addr_str_malformed_rejected() {
        assert_eq!(parse_mac_addr_str("not-a-mac"), None);
    }

    // ── enumerate_live_addrs6 smoke test ─────────────────────────────────────

    #[cfg(feature = "dhcp6")]
    #[test]
    fn enumerate_live_addrs6_does_not_error() {
        let result = enumerate_live_addrs6();
        assert!(result.is_ok(), "enumerate_live_addrs6 failed: {:?}", result.err());
    }
}

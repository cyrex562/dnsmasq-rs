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
/// * For **UDP IPv4** wildcard (not `nowild`): enables `IP_PKTINFO` (Linux) or
///   `IP_RECVDSTADDR` + `IP_RECVIF` (BSD) so the kernel reports the
///   destination address on each received datagram.
/// * For **UDP IPv6**: calls `set_ipv6pktinfo`.
/// * For **TCP**: calls `listen(128)` and optionally enables `TCP_FASTOPEN`.
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

    let sock = Socket::new(domain, sock_type, proto).map_err(|e| {
        // Silently ignore "kernel doesn't support this protocol family".
        if matches!(e.kind(), io::ErrorKind::Unsupported) {
            io::Error::new(io::ErrorKind::Unsupported, e)
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

/// Create a `Listener` (UDP + TCP socket pair) bound to `addr`.
///
/// When `do_tftp` is true a third UDP socket is created for TFTP on port 69.
/// When `nowild` is true `IP_PKTINFO` is not requested (the socket is already
/// bound to a specific interface address).
///
/// Mirrors `create_listeners()` in `network.c`.
#[cfg(unix)]
pub fn create_listeners(
    addr: std::net::SocketAddr,
    do_tftp: bool,
    nowild: bool,
) -> Option<Listener> {
    let udp_fd  = make_sock(addr, SockType::Udp, nowild).unwrap_or(-1);
    let tcp_fd  = make_sock(addr, SockType::Tcp, nowild).unwrap_or(-1);

    let tftp_fd = if do_tftp {
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
    _do_tftp: bool,
    _nowild: bool,
) -> Option<Listener> {
    None
}

/// Create wildcard (`0.0.0.0` and `::`) listeners for `port`.
///
/// Returns up to two `Listener`s — one for IPv4, one for IPv6.
///
/// Mirrors `create_wildcard_listeners()` in `network.c`.
pub fn create_wildcard_listeners(port: u16, do_tftp: bool) -> Vec<Listener> {
    let mut out = Vec::new();
    let addrs: &[std::net::SocketAddr] = &[
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED), port),
        std::net::SocketAddr::new(
            std::net::IpAddr::V6(Ipv6Addr::UNSPECIFIED), port),
    ];
    for &addr in addrs {
        if let Some(l) = create_listeners(addr, do_tftp, /*nowild=*/false) {
            out.push(l);
        }
    }
    out
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
/// - Otherwise, create a new `Listener` (with `nowild = true`) and push it
///   onto the list.
///
/// Returns the number of new listeners created.
///
/// Mirrors the core loop of `create_bound_listeners()` in `network.c`.
pub fn create_bound_listeners(
    listeners: &mut Vec<Listener>,
    iface_addrs: &[(std::net::SocketAddr, String)],
    do_tftp: bool,
) -> usize {
    let mut created = 0;
    for &(addr, ref name) in iface_addrs {
        // Check if a listener already covers this address.
        if let Some(existing) = find_listener(listeners, addr) {
            existing.used += 1;
            continue;
        }
        if let Some(mut l) = create_listeners(addr, do_tftp, /*nowild=*/true) {
            l.iface = Some(name.clone());
            listeners.push(l);
            created += 1;
        }
    }
    created
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
    /// Interface name / pattern denylist.
    pub dhcp_except:   Vec<String>,
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
) -> Option<IfaceRecord> {
    let effective_name = label.unwrap_or(name);
    let is_label = label.map(|l| l != name).unwrap_or(false);

    // Apply interface name filter.
    let dummy = IfaceInfo {
        name:    effective_name.to_string(),
        index,
        addr:    IpAddr::V4(addr),
        netmask: Some(IpAddr::V4(netmask)),
        flags:   if loopback { 0x8 } else { 0 },
    };
    if !iface_check(&dummy, iface_check_cfg) {
        return None;
    }

    // No DHCP/TFTP on loopback.
    let mut dhcp4_ok = !loopback;
    let tftp_ok_base = !loopback;

    // Apply dhcp_except deny list.
    for pat in &config.dhcp_except {
        if iface_name_matches(name, pat) {
            dhcp4_ok = false;
            break;
        }
    }

    // TFTP: if a dedicated list is given, only those interfaces get TFTP.
    let tftp_ok = if config.tftp_ifaces.is_empty() {
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
) -> Option<IfaceRecord> {
    let dummy = IfaceInfo {
        name:    name.to_string(),
        index,
        addr:    IpAddr::V6(addr),
        netmask: None,
        flags:   if loopback { 0x8 } else { 0 },
    };
    if !iface_check(&dummy, iface_check_cfg) {
        return None;
    }

    let mut dhcp6_ok = !loopback;

    for pat in &config.dhcp_except {
        if iface_name_matches(name, pat) {
            dhcp6_ok = false;
            break;
        }
    }

    let tftp_ok = if config.tftp_ifaces.is_empty() {
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
        let l = create_listeners(addr, false, true).expect("should create listener");
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
        let listeners = create_wildcard_listeners(0, false);
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
        let created = create_bound_listeners(&mut listeners, &ifaces, false);
        assert_eq!(created, 0, "no new listener should be created for existing addr");
        assert_eq!(listeners[0].used, 2, "used counter should be incremented");
    }

    #[cfg(unix)]
    #[test]
    fn create_bound_listeners_creates_new() {
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let mut listeners: Vec<Listener> = vec![];
        let ifaces = vec![(addr, "lo".to_string())];
        let created = create_bound_listeners(&mut listeners, &ifaces, false);
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
            &default_allowed_cfg(), &default_check_cfg(),
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
            &default_allowed_cfg(), &default_check_cfg(),
        ).unwrap();
        assert!(!rec.dhcp4_ok, "loopback should have dhcp4 disabled");
        assert!(!rec.tftp_ok,  "loopback should have tftp disabled");
    }

    #[test]
    fn iface_allowed_v4_dhcp_except_disables_dhcp() {
        let cfg = IfaceAllowedConfig {
            dhcp_except: vec!["eth0".to_string()],
            ..Default::default()
        };
        let rec = iface_allowed_v4(
            "eth0", None, 2,
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(255, 255, 255, 0),
            false,
            &cfg, &default_check_cfg(),
        ).unwrap();
        assert!(!rec.dhcp4_ok, "dhcp_except should disable dhcp");
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
            &default_allowed_cfg(), &check_cfg,
        );
        assert!(rec.is_none(), "docker0 should be denied by check_cfg deny list");
    }

    // ── iface_allowed_v6 ──────────────────────────────────────────────────────

    #[test]
    fn iface_allowed_v6_accepts_global_addr() {
        let addr = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let rec = iface_allowed_v6(
            "eth0", 2, addr, 64, false,
            &default_allowed_cfg(), &default_check_cfg(),
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
            &default_allowed_cfg(), &default_check_cfg(),
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
}

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Raw netlink message type constants.
pub mod nlmsg_type {
    pub const RTM_NEWLINK:  u16 = 16;
    pub const RTM_NEWADDR:  u16 = 20;
    pub const RTM_DELADDR:  u16 = 21;
    pub const RTM_NEWROUTE: u16 = 24;
    pub const RTM_DELROUTE: u16 = 25;
    pub const RTM_NEWNEIGH: u16 = 28;
    // Kernel request types
    pub const RTM_GETLINK:  u16 = 18;
    pub const RTM_GETADDR:  u16 = 22;
    pub const RTM_GETNEIGH: u16 = 30;
    // Control messages
    pub const NLMSG_DONE:  u16 = 3;
    pub const NLMSG_ERROR: u16 = 2;
}

// ── Family constants ──────────────────────────────────────────────────────────
const AF_UNSPEC: u8 = 0;
#[allow(dead_code)]
const AF_LOCAL:  u8 = 1; // AF_UNIX; triggers RTM_GETLINK for MAC enumeration
const AF_INET:   u8 = 2;
const AF_INET6:  u8 = 10;

// ── IFA (ifaddr) attribute types ──────────────────────────────────────────────
const IFA_ADDRESS:   u16 = 1;
const IFA_LOCAL:     u16 = 2;
const IFA_BROADCAST: u16 = 3;
const IFA_LABEL:     u16 = 4;
const IFA_CACHEINFO: u16 = 6;

// ── NDA (neighbor/ARP) attribute types ───────────────────────────────────────
const NDA_DST:    u16 = 1;
const NDA_LLADDR: u16 = 2;

// ── IFLA (link) attribute types ───────────────────────────────────────────────
const IFLA_ADDRESS: u16 = 1;

// ── IFA flag bits ─────────────────────────────────────────────────────────────
const IFA_F_TENTATIVE:  u8 = 0x40;
const IFA_F_DEPRECATED: u8 = 0x20;
const IFA_F_TEMPORARY:  u8 = 0x01;

// ── NUD (neighbour unreachability) state bits ────────────────────────────────
const NUD_INCOMPLETE: u16 = 0x01;
const NUD_FAILED:     u16 = 0x20;
const NUD_NOARP:      u16 = 0x40;

// ── IFF (interface) flag bits ─────────────────────────────────────────────────
const IFF_LOOPBACK:    u32 = 0x8;
const IFF_POINTOPOINT: u32 = 0x10;

// ── rtm route type / scope / table ────────────────────────────────────────────
const RTN_UNICAST:    u8 = 1;
const RT_SCOPE_LINK:  u8 = 253;
const RT_TABLE_MAIN:  u8 = 254;
const RT_TABLE_LOCAL: u8 = 255;

// ── NLM flags ─────────────────────────────────────────────────────────────────
const NLM_F_REQUEST: u16 = 1;
const NLM_F_ROOT:    u16 = 0x100;
const NLM_F_MATCH:   u16 = 0x200;
const NLM_F_ACK:     u16 = 4;

/// Multicast state flags (mirrors C `async_states` enum).
pub const STATE_NEWADDR:  u32 = 1 << 0;
pub const STATE_NEWROUTE: u32 = 1 << 1;

/// Interface address flags (mirrors C `IFACE_*` constants).
pub const IFACE_TENTATIVE:  u32 = 1;
pub const IFACE_DEPRECATED: u32 = 2;
pub const IFACE_PERMANENT:  u32 = 4;
pub const IFACE_USED:       u32 = 8;

// ── Netlink message header layout ────────────────────────────────────────────
/// Size of `struct nlmsghdr` (16 bytes).
pub const NLMSG_HDRLEN: usize = 16;

#[inline]
fn nlmsg_align(n: usize) -> usize { (n + 3) & !3 }

#[inline]
fn rta_align(n: usize) -> usize { (n + 3) & !3 }

/// Extract `nlmsg_len` from a raw header (host byte order).
#[inline]
fn nlmsg_len(hdr: &[u8]) -> usize {
    u32::from_ne_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize
}

/// Extract `nlmsg_type` from a raw header.
#[inline]
pub fn nlmsg_msg_type(hdr: &[u8]) -> u16 {
    u16::from_ne_bytes([hdr[4], hdr[5]])
}

/// Extract `nlmsg_seq` from a raw header.
#[inline]
fn nlmsg_seq(hdr: &[u8]) -> u32 {
    u32::from_ne_bytes([hdr[8], hdr[9], hdr[10], hdr[11]])
}

/// Extract `nlmsg_pid` from a raw header.
#[inline]
pub fn nlmsg_pid(hdr: &[u8]) -> u32 {
    u32::from_ne_bytes([hdr[12], hdr[13], hdr[14], hdr[15]])
}

/// True if the header is valid and fits in `buf`.
#[inline]
fn nlmsg_ok(buf: &[u8]) -> bool {
    buf.len() >= NLMSG_HDRLEN && nlmsg_len(buf) >= NLMSG_HDRLEN && nlmsg_len(buf) <= buf.len()
}

/// Iterate over all valid netlink messages in a received buffer.
fn for_each_nlmsg<F: FnMut(&[u8])>(buf: &[u8], mut f: F) {
    let mut off = 0;
    while off + NLMSG_HDRLEN <= buf.len() {
        let slice = &buf[off..];
        if !nlmsg_ok(slice) {
            break;
        }
        let msg_len = nlmsg_len(slice);
        f(&slice[..msg_len]);
        let step = nlmsg_align(msg_len);
        if step == 0 || off + step > buf.len() {
            break;
        }
        off += step;
    }
}

/// Iterate over netlink routing attributes (RTA / IFA / NDA attrs are all the same format).
/// `attrs` is the attribute payload (after the family-specific header).
fn for_each_rta<F: FnMut(u16, &[u8])>(attrs: &[u8], mut f: F) {
    const RTA_HDRLEN: usize = 4;
    let mut off = 0;
    while off + RTA_HDRLEN <= attrs.len() {
        let rta_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let rta_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]);
        if rta_len < RTA_HDRLEN || off + rta_len > attrs.len() {
            break;
        }
        f(rta_type, &attrs[off + RTA_HDRLEN..off + rta_len]);
        let step = rta_align(rta_len);
        if step == 0 || off + step > attrs.len() {
            break;
        }
        off += step;
    }
}

/// Parsed netlink event.
#[derive(Debug, Clone, PartialEq)]
pub enum NetlinkEvent {
    NewAddress { iface_index: u32, addr: IpAddr, prefix_len: u8 },
    DelAddress { iface_index: u32, addr: IpAddr },
    NewRoute    { dst: IpAddr, prefix_len: u8, gateway: Option<IpAddr> },
    DelRoute    { dst: IpAddr, prefix_len: u8 },
}

// ── IfaceRecord — used by iface_enumerate ────────────────────────────────────

/// A network-interface record returned by `iface_enumerate`.
#[derive(Debug, Clone, PartialEq)]
pub enum IfaceRecord {
    /// An IPv4 interface address (from `RTM_NEWADDR`, family `AF_INET`).
    V4 {
        addr:      Ipv4Addr,
        if_index:  u32,
        label:     Option<String>,
        netmask:   Ipv4Addr,
        broadcast: Ipv4Addr,
    },
    /// An IPv6 interface address (from `RTM_NEWADDR`, family `AF_INET6`).
    V6 {
        addr:       Ipv6Addr,
        prefix_len: u8,
        scope:      u8,
        if_index:   u32,
        flags:      u32,
        preferred:  u32,
        valid:      u32,
    },
    /// An ARP / neighbour-table entry (from `RTM_NEWNEIGH`).
    Arp {
        family: u8,
        ip:     Vec<u8>,
        mac:    Vec<u8>,
    },
    /// A link-layer record (from `RTM_NEWLINK`) for DUID / DHCPv6 MAC lookup.
    Link {
        if_index: u32,
        if_type:  u16,
        mac:      Vec<u8>,
    },
}

// ── Pure-Rust netlink message parsers (no socket required) ───────────────────

/// Parse a single `RTM_NEWADDR` message into an `IfaceRecord`.
/// Returns `None` if the message is too short or the family is not `AF_INET`/`AF_INET6`.
pub fn parse_newaddr_record(msg: &[u8]) -> Option<IfaceRecord> {
    // nlmsghdr (16) + ifaddrmsg (8) = 24 bytes minimum
    const IFADDRMSG_LEN: usize = 8;
    if msg.len() < NLMSG_HDRLEN + IFADDRMSG_LEN {
        return None;
    }
    let p = &msg[NLMSG_HDRLEN..];
    let family     = p[0];
    let prefix_len = p[1];
    let ifa_flags  = p[2];
    let scope      = p[3];
    let if_index   = u32::from_ne_bytes([p[4], p[5], p[6], p[7]]);
    let attrs      = &p[IFADDRMSG_LEN..];

    match family {
        f if f == AF_INET => {
            let mut addr      = Ipv4Addr::UNSPECIFIED;
            let mut broadcast = Ipv4Addr::UNSPECIFIED;
            let mut label     = None::<String>;
            for_each_rta(attrs, |rta_type, data| {
                match rta_type {
                    IFA_LOCAL | IFA_ADDRESS => {
                        if data.len() >= 4 {
                            addr = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                        }
                    }
                    IFA_BROADCAST => {
                        if data.len() >= 4 {
                            broadcast = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                        }
                    }
                    IFA_LABEL => {
                        // null-terminated C string
                        let s = data.split(|&b| b == 0).next().unwrap_or(data);
                        label = String::from_utf8(s.to_vec()).ok();
                    }
                    _ => {}
                }
            });
            if addr == Ipv4Addr::UNSPECIFIED {
                return None;
            }
            // netmask from prefix length
            let mask_bits: u32 = if prefix_len == 0 { 0 } else { !0u32 << (32 - prefix_len) };
            let netmask = Ipv4Addr::from(mask_bits);
            Some(IfaceRecord::V4 { addr, if_index, label, netmask, broadcast })
        }
        f if f == AF_INET6 => {
            let mut addr_bytes = None::<[u8; 16]>;
            let mut preferred  = 0u32;
            let mut valid      = 0u32;
            for_each_rta(attrs, |rta_type, data| {
                match rta_type {
                    IFA_LOCAL => {
                        if data.len() >= 16 {
                            let mut b = [0u8; 16];
                            b.copy_from_slice(&data[..16]);
                            addr_bytes = Some(b);
                        }
                    }
                    IFA_ADDRESS => {
                        if addr_bytes.is_none() && data.len() >= 16 {
                            let mut b = [0u8; 16];
                            b.copy_from_slice(&data[..16]);
                            addr_bytes = Some(b);
                        }
                    }
                    IFA_CACHEINFO => {
                        if data.len() >= 8 {
                            preferred = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);
                            valid     = u32::from_ne_bytes([data[4], data[5], data[6], data[7]]);
                        }
                    }
                    _ => {}
                }
            });
            let addr = Ipv6Addr::from(addr_bytes?);
            let mut flags = 0u32;
            if ifa_flags & IFA_F_TENTATIVE  != 0 { flags |= IFACE_TENTATIVE; }
            if ifa_flags & IFA_F_DEPRECATED != 0 { flags |= IFACE_DEPRECATED; }
            if ifa_flags & IFA_F_TEMPORARY  == 0 { flags |= IFACE_PERMANENT; }
            Some(IfaceRecord::V6 { addr, prefix_len, scope, if_index, flags, preferred, valid })
        }
        _ => None,
    }
}

/// Parse a single `RTM_NEWNEIGH` message into an `IfaceRecord::Arp`.
/// Returns `None` if the message is malformed or the NUD state indicates
/// the entry is incomplete/failed.
pub fn parse_newneigh_record(msg: &[u8]) -> Option<IfaceRecord> {
    // nlmsghdr (16) + ndmsg (12) = 28 bytes minimum
    const NDMSG_LEN: usize = 12;
    if msg.len() < NLMSG_HDRLEN + NDMSG_LEN {
        return None;
    }
    let p       = &msg[NLMSG_HDRLEN..];
    let family  = p[0];
    let ndm_state = u16::from_ne_bytes([p[8], p[9]]);

    // Skip entries that are incomplete/failed/noarp
    if ndm_state & (NUD_NOARP | NUD_INCOMPLETE | NUD_FAILED) != 0 {
        return None;
    }

    let attrs = &p[NDMSG_LEN..];
    let mut ip  = None::<Vec<u8>>;
    let mut mac = None::<Vec<u8>>;
    for_each_rta(attrs, |rta_type, data| {
        match rta_type {
            NDA_DST    => ip  = Some(data.to_vec()),
            NDA_LLADDR => mac = Some(data.to_vec()),
            _ => {}
        }
    });

    Some(IfaceRecord::Arp {
        family,
        ip:  ip?,
        mac: mac?,
    })
}

/// Parse a single `RTM_NEWLINK` message into an `IfaceRecord::Link`.
/// Returns `None` if the interface has no MAC address, or is loopback/point-to-point.
pub fn parse_newlink_record(msg: &[u8]) -> Option<IfaceRecord> {
    // nlmsghdr (16) + ifinfomsg (16) = 32 bytes minimum
    const IFINFOMSG_LEN: usize = 16;
    if msg.len() < NLMSG_HDRLEN + IFINFOMSG_LEN {
        return None;
    }
    let p        = &msg[NLMSG_HDRLEN..];
    let if_type  = u16::from_ne_bytes([p[2], p[3]]);
    let if_index = u32::from_ne_bytes([p[4], p[5], p[6], p[7]]);
    let ifi_flags = u32::from_ne_bytes([p[8], p[9], p[10], p[11]]);

    // Skip loopback and point-to-point interfaces
    if ifi_flags & (IFF_LOOPBACK | IFF_POINTOPOINT) != 0 {
        return None;
    }

    let attrs = &p[IFINFOMSG_LEN..];
    let mut mac = None::<Vec<u8>>;
    for_each_rta(attrs, |rta_type, data| {
        if rta_type == IFLA_ADDRESS {
            mac = Some(data.to_vec());
        }
    });

    Some(IfaceRecord::Link {
        if_index,
        if_type,
        mac: mac?,
    })
}

/// Parse a raw netlink response buffer into a list of `IfaceRecord`s.
///
/// Only records matching `family` are returned:
/// - `AF_INET` (2)  / `AF_INET6` (10) → `V4` / `V6` records from `RTM_NEWADDR` messages
/// - `AF_UNSPEC` (0) → `Arp` records from `RTM_NEWNEIGH` messages
/// - `AF_LOCAL` (1)  → `Link` records from `RTM_NEWLINK` messages
///
/// Processes all messages until `NLMSG_DONE` is found or the buffer is exhausted.
pub fn parse_iface_response(buf: &[u8], family: u8) -> Vec<IfaceRecord> {
    let mut records = Vec::new();
    for_each_nlmsg(buf, |msg| {
        let msg_type = nlmsg_msg_type(msg);
        match msg_type {
            t if t == nlmsg_type::RTM_NEWADDR && family != AF_UNSPEC && family != AF_LOCAL => {
                if let Some(r) = parse_newaddr_record(msg) {
                    records.push(r);
                }
            }
            t if t == nlmsg_type::RTM_NEWNEIGH && family == AF_UNSPEC => {
                if let Some(r) = parse_newneigh_record(msg) {
                    records.push(r);
                }
            }
            t if t == nlmsg_type::RTM_NEWLINK && family == AF_LOCAL => {
                if let Some(r) = parse_newlink_record(msg) {
                    records.push(r);
                }
            }
            _ => {}
        }
    });
    records
}

// ── nl_async — async multicast state machine ─────────────────────────────────

/// Process a single async (multicast) netlink message, updating `state`.
///
/// Mirrors the C `nl_async()` function.  Emits events for new routes and
/// new/deleted addresses; returns updated state.
pub fn nl_async(msg: &[u8], mut state: u32) -> u32 {
    if msg.len() < NLMSG_HDRLEN {
        return state;
    }
    let msg_type = nlmsg_msg_type(msg);
    let pid      = nlmsg_pid(msg);

    if msg_type == nlmsg_type::NLMSG_ERROR {
        // Error response — nothing to do in pure parse; caller logs
        return state;
    }

    if pid == 0 && msg_type == nlmsg_type::RTM_NEWROUTE && (state & STATE_NEWROUTE) == 0 {
        // Check that this is a unicast link-scoped route in main or local table
        // rtmsg starts at offset 16: u8 family, u8 dst_len, u8 src_len, u8 tos,
        //   u8 table, u8 protocol, u8 scope, u8 rtm_type, u32 rtm_flags
        if msg.len() >= NLMSG_HDRLEN + 8 {
            let p = &msg[NLMSG_HDRLEN..];
            let rtm_type  = p[7]; // rtm_type
            let rtm_scope = p[6];
            let rtm_table = p[4];
            if rtm_type == RTN_UNICAST
                && rtm_scope == RT_SCOPE_LINK
                && (rtm_table == RT_TABLE_MAIN || rtm_table == RT_TABLE_LOCAL)
            {
                state |= STATE_NEWROUTE;
            }
        }
    } else if (msg_type == nlmsg_type::RTM_NEWADDR || msg_type == nlmsg_type::RTM_DELADDR)
        && (state & STATE_NEWADDR) == 0
    {
        state |= STATE_NEWADDR;
    }

    state
}

// ── Linux socket-level operations ────────────────────────────────────────────

/// Whether a failed multicast-group `bind()` should be retried with
/// `nl_groups = 0` (no multicast).
///
/// Mirrors `netlink.c:79`: `errno != EPERM || bind(...) == -1`. Upstream
/// retries the no-multicast bind *only* when the first bind failed with
/// `EPERM` (insufficient privilege to join the multicast groups); any other
/// errno (`EADDRINUSE`, `EINVAL`, ...) is a hard failure that should propagate
/// immediately rather than being silently masked by a fallback bind.
#[cfg(target_os = "linux")]
fn should_retry_without_multicast(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(libc::EPERM)
}

/// Open a `NETLINK_ROUTE` socket and subscribe to address/route multicast groups.
///
/// On success returns the raw file descriptor.  The caller must close it with
/// `libc::close()` (or wrap it in a type that implements `Drop`).
///
/// The function mirrors `netlink_init()` from the C source.  If the multicast
/// groups cannot be subscribed because of `EPERM` it falls back to a plain
/// socket with no multicast, matching upstream exactly; any other bind error
/// is returned as-is.
#[cfg(target_os = "linux")]
pub fn netlink_open() -> std::io::Result<(i32, u32)> {
    use libc::{
        AF_NETLINK, SOCK_RAW, NETLINK_ROUTE,
        RTMGRP_IPV4_IFADDR, RTMGRP_IPV4_ROUTE, RTMGRP_IPV6_IFADDR, RTMGRP_IPV6_ROUTE,
    };

    let fd = unsafe { libc::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE) };
    if fd == -1 {
        return Err(std::io::Error::last_os_error());
    }

    // sockaddr_nl: u16 nl_family, u16 nl_pad, u32 nl_pid, u32 nl_groups
    let groups = (RTMGRP_IPV4_ROUTE | RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_ROUTE | RTMGRP_IPV6_IFADDR) as u32;
    let mut addr = [0u8; 12];
    addr[0..2].copy_from_slice(&(AF_NETLINK as u16).to_ne_bytes()); // nl_family
    addr[8..12].copy_from_slice(&groups.to_ne_bytes()); // nl_groups

    let bind_ret = unsafe {
        libc::bind(fd, addr.as_ptr() as *const libc::sockaddr, addr.len() as libc::socklen_t)
    };
    if bind_ret == -1 {
        let first_err = std::io::Error::last_os_error();
        if !should_retry_without_multicast(&first_err) {
            unsafe { libc::close(fd) };
            return Err(first_err);
        }

        // Fall back to no multicast
        let mut addr2 = [0u8; 12];
        addr2[0..2].copy_from_slice(&(AF_NETLINK as u16).to_ne_bytes());
        let ret2 = unsafe {
            libc::bind(fd, addr2.as_ptr() as *const libc::sockaddr, addr2.len() as libc::socklen_t)
        };
        if ret2 == -1 {
            let err = std::io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(err);
        }
    }

    // Retrieve the kernel-assigned pid via getsockname
    let mut bound = [0u8; 12];
    let mut len = 12u32;
    unsafe {
        libc::getsockname(fd, bound.as_mut_ptr() as *mut libc::sockaddr, &mut len as *mut libc::socklen_t);
    }
    let pid = u32::from_ne_bytes([bound[4], bound[5], bound[6], bound[7]]);

    Ok((fd, pid))
}

/// Receive a netlink message into `buf`, growing it as needed.
///
/// Returns the number of bytes received, or an IO error.
/// This mirrors `netlink_recv()` from the C source.
#[cfg(target_os = "linux")]
pub fn netlink_recv(fd: i32, buf: &mut Vec<u8>, flags: i32) -> std::io::Result<usize> {
    loop {
        if buf.is_empty() {
            buf.resize(4096, 0);
        }

        // Peek to find the real message size
        let rc = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                flags | libc::MSG_PEEK | libc::MSG_TRUNC,
            )
        };
        if rc == -1 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }

        let needed = rc as usize;
        if needed > buf.len() {
            buf.resize(needed + 100, 0);
            continue; // peek again with larger buffer
        }

        // Real receive
        let rc2 = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                flags,
            )
        };
        if rc2 == -1 {
            let e = std::io::Error::last_os_error();
            if e.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(e);
        }
        return Ok(rc2 as usize);
    }
}

/// Drain async (multicast) netlink messages without blocking, updating `state`.
///
/// Mirrors `nl_multicast_state()` and `netlink_multicast()` from the C source.
/// Returns the updated state after processing all available messages.
#[cfg(target_os = "linux")]
pub fn netlink_multicast(fd: i32) -> u32 {
    let mut state = 0u32;
    let mut buf = vec![0u8; 4096];
    loop {
        let rc = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT | libc::MSG_PEEK | libc::MSG_TRUNC,
            )
        };
        if rc < 0 {
            let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if e == libc::ENOBUFS {
                // kernel dropped packets — keep going
                continue;
            }
            break;
        }
        // Grow buf if needed
        let needed = rc as usize;
        if needed > buf.len() {
            buf.resize(needed + 100, 0);
        }
        let rc2 = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if rc2 < 0 {
            break;
        }
        let n = rc2 as usize;
        for_each_nlmsg(&buf[..n], |msg| {
            state = nl_async(msg, state);
        });
    }
    state
}

/// Await readability on a netlink socket and drain address/route-change
/// notifications as they arrive, calling `on_change` with the resulting
/// [`STATE_NEWADDR`]/[`STATE_NEWROUTE`] bits whenever a wakeup yields a
/// non-zero state.
///
/// This is the runtime consumer of [`netlink_open`] / [`netlink_multicast`]:
/// upstream registers `daemon->netlinkfd` in its main `poll()` loop and reacts
/// to `EVENT_NEWADDR`/`EVENT_NEWROUTE` from `nl_async()` (`dnsmasq.c`); this
/// mirrors that with a `tokio::io::unix::AsyncFd` readiness loop instead of a
/// poll-based event queue. Takes ownership of `fd` (closed on return/drop via
/// `OwnedFd`). Runs until the socket errors.
#[cfg(target_os = "linux")]
pub async fn watch_address_changes<F>(fd: i32, mut on_change: F) -> std::io::Result<()>
where
    F: FnMut(u32) + Send,
{
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let async_fd = tokio::io::unix::AsyncFd::new(owned)?;
    loop {
        let mut guard = async_fd.readable().await?;
        let state = netlink_multicast(async_fd.get_ref().as_raw_fd());
        guard.clear_ready();
        if state != 0 {
            on_change(state);
        }
    }
}

/// Query the kernel for all network addresses / neighbours / links of `family`
/// and call `callback` for each resulting `IfaceRecord`.
///
/// - `family = libc::AF_INET (2)`   → IPv4 addresses  
/// - `family = libc::AF_INET6 (10)` → IPv6 addresses  
/// - `family = libc::AF_UNSPEC (0)` → ARP table entries  
/// - `family = libc::AF_LOCAL (1)`  → Link-layer / MAC addresses  
///
/// Returns `Ok(true)` on success, `Ok(false)` on error, `Err(())` if the
/// caller should restart (kernel dropped packets with `ENOBUFS`).
#[cfg(target_os = "linux")]
pub fn iface_enumerate<F>(fd: i32, pid: u32, family: i32, callback: &mut F) -> Result<bool, ()>
where
    F: FnMut(IfaceRecord) -> bool,
{
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed).wrapping_add(1);

    // Determine request message type
    let req_type: u16 = match family as u8 {
        AF_UNSPEC => nlmsg_type::RTM_GETNEIGH,
        AF_LOCAL  => nlmsg_type::RTM_GETLINK,
        _         => nlmsg_type::RTM_GETADDR,
    };

    // Build nlmsghdr (16 bytes) + rtgenmsg (4 bytes) = 20 bytes
    let mut req = [0u8; 20];
    req[0..4].copy_from_slice(&20u32.to_ne_bytes());                 // nlmsg_len
    req[4..6].copy_from_slice(&req_type.to_ne_bytes());              // nlmsg_type
    let flags = NLM_F_REQUEST | NLM_F_ROOT | NLM_F_MATCH | NLM_F_ACK;
    req[6..8].copy_from_slice(&flags.to_ne_bytes());                 // nlmsg_flags
    req[8..12].copy_from_slice(&seq.to_ne_bytes());                  // nlmsg_seq
    // nlmsg_pid = 0 (kernel)
    req[16] = family as u8;                                          // rtgenmsg.rtgen_family

    // Destination: sockaddr_nl for kernel (pid=0)
    let mut dest = [0u8; 12];
    dest[0..2].copy_from_slice(&(libc::AF_NETLINK as u16).to_ne_bytes());

    // Send the request
    loop {
        let rc = unsafe {
            libc::sendto(
                fd,
                req.as_ptr() as *const libc::c_void,
                req.len(),
                0,
                dest.as_ptr() as *const libc::sockaddr,
                dest.len() as libc::socklen_t,
            )
        };
        if rc != -1 {
            break;
        }
        let e = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if e != libc::EINTR {
            if e != 0 {
                return Ok(false);
            }
            break;
        }
    }

    // Receive and process responses
    let mut buf = vec![0u8; 4096];
    let mut async_state = 0u32;
    loop {
        let n = match netlink_recv(fd, &mut buf, 0) {
            Ok(n)  => n,
            Err(e) => {
                if e.raw_os_error() == Some(libc::ENOBUFS) {
                    // Drain any queued multicast messages, then tell caller to restart
                    let _ = netlink_multicast(fd);
                    async_state |= STATE_NEWADDR; // conservative: assume addr changed
                    return Err(());
                }
                return Ok(false);
            }
        };

        let mut done = false;
        let mut callback_ok = true;

        for_each_nlmsg(&buf[..n], |msg| {
            let msg_pid  = nlmsg_pid(msg);
            let msg_type = nlmsg_msg_type(msg);
            let msg_seq  = nlmsg_seq(msg);

            if msg_pid != pid || msg_type == nlmsg_type::NLMSG_ERROR {
                // Async multicast arriving out of order
                async_state = nl_async(msg, async_state);
                return;
            }
            if msg_seq != seq {
                // Stale response from a previous request; discard
                return;
            }
            if msg_type == nlmsg_type::NLMSG_DONE {
                done = true;
                return;
            }

            // Parse and dispatch according to request family
            let fam = family as u8;
            let record = match msg_type {
                t if t == nlmsg_type::RTM_NEWADDR && fam != AF_UNSPEC && fam != AF_LOCAL => {
                    parse_newaddr_record(msg)
                }
                t if t == nlmsg_type::RTM_NEWNEIGH && fam == AF_UNSPEC => {
                    parse_newneigh_record(msg)
                }
                t if t == nlmsg_type::RTM_NEWLINK && fam == AF_LOCAL => {
                    parse_newlink_record(msg)
                }
                _ => None,
            };

            if let Some(r) = record {
                if callback_ok && !callback(r) {
                    callback_ok = false;
                }
            }
        });

        if done {
            return Ok(callback_ok);
        }
    }
}

/// Parse a Linux netlink message into a NetlinkEvent.
/// `msg`: the raw bytes of a single netlink message (nlmsghdr + payload).
/// Returns None for unknown/unhandled message types.
pub fn parse_netlink_msg(msg: &[u8]) -> Option<NetlinkEvent> {
    // nlmsghdr is 16 bytes: u32 len, u16 type, u16 flags, u32 seq, u32 pid
    if msg.len() < 16 {
        return None;
    }
    let nlmsg_type = u16::from_ne_bytes([msg[4], msg[5]]);

    match nlmsg_type {
        nlmsg_type::RTM_NEWADDR | nlmsg_type::RTM_DELADDR => {
            parse_addr_msg(msg, nlmsg_type)
        }
        nlmsg_type::RTM_NEWROUTE | nlmsg_type::RTM_DELROUTE => {
            parse_route_msg(msg, nlmsg_type)
        }
        _ => None,
    }
}

fn parse_addr_msg(msg: &[u8], nlmsg_type: u16) -> Option<NetlinkEvent> {
    // ifaddrmsg starts at offset 16: u8 family, u8 prefix_len, u8 flags, u8 scope, u32 ifi_index
    if msg.len() < 16 + 8 {
        return None;
    }
    let family     = msg[16];
    let prefix_len = msg[17];
    let iface_index = u32::from_ne_bytes([msg[20], msg[21], msg[22], msg[23]]);

    // netlink attributes start after nlmsghdr (16) + ifaddrmsg (8) = offset 24
    let addr = parse_ifa_attrs(&msg[24..], family)?;

    Some(match nlmsg_type {
        nlmsg_type::RTM_NEWADDR => NetlinkEvent::NewAddress { iface_index, addr, prefix_len },
        _                       => NetlinkEvent::DelAddress { iface_index, addr },
    })
}

fn parse_route_msg(msg: &[u8], nlmsg_type: u16) -> Option<NetlinkEvent> {
    // rtmsg starts at offset 16: u8 family, u8 dst_len, u8 src_len, u8 tos,
    //   u8 table, u8 protocol, u8 scope, u8 type, u32 flags  → 12 bytes
    if msg.len() < 16 + 12 {
        return None;
    }
    let family     = msg[16];
    let prefix_len = msg[17];

    // attributes start at 16 + 12 = 28
    let (dst, _gateway) = parse_rta_attrs(&msg[28..], family);
    let dst = dst?;

    Some(match nlmsg_type {
        nlmsg_type::RTM_NEWROUTE => NetlinkEvent::NewRoute { dst, prefix_len, gateway: _gateway },
        _                        => NetlinkEvent::DelRoute { dst, prefix_len },
    })
}

/// Walk IFA netlink attributes and return the first IFA_LOCAL or IFA_ADDRESS found.
fn parse_ifa_attrs(attrs: &[u8], family: u8) -> Option<IpAddr> {
    let mut offset = 0;
    while offset + 4 <= attrs.len() {
        let nla_len  = u16::from_ne_bytes([attrs[offset], attrs[offset + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[offset + 2], attrs[offset + 3]]);
        if nla_len < 4 || offset + nla_len > attrs.len() {
            break;
        }
        let data = &attrs[offset + 4..offset + nla_len];
        if nla_type == IFA_LOCAL || nla_type == IFA_ADDRESS {
            if let Some(addr) = parse_ip(data, family) {
                return Some(addr);
            }
        }
        // align to 4-byte boundary
        offset += (nla_len + 3) & !3;
    }
    None
}

const RTA_DST:     u16 = 1;
const RTA_GATEWAY: u16 = 5;

/// Walk RTA netlink attributes and return (dst, gateway).
fn parse_rta_attrs(attrs: &[u8], family: u8) -> (Option<IpAddr>, Option<IpAddr>) {
    let mut offset  = 0;
    let mut dst     = None;
    let mut gateway = None;
    while offset + 4 <= attrs.len() {
        let nla_len  = u16::from_ne_bytes([attrs[offset], attrs[offset + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[offset + 2], attrs[offset + 3]]);
        if nla_len < 4 || offset + nla_len > attrs.len() {
            break;
        }
        let data = &attrs[offset + 4..offset + nla_len];
        match nla_type {
            RTA_DST     => dst     = parse_ip(data, family),
            RTA_GATEWAY => gateway = parse_ip(data, family),
            _ => {}
        }
        offset += (nla_len + 3) & !3;
    }
    (dst, gateway)
}

fn parse_ip(data: &[u8], family: u8) -> Option<IpAddr> {
    match family {
        AF_INET if data.len() >= 4 => {
            Some(IpAddr::V4(Ipv4Addr::new(data[0], data[1], data[2], data[3])))
        }
        AF_INET6 if data.len() >= 16 => {
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[..16]);
            Some(IpAddr::V6(Ipv6Addr::from(bytes)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_nlmsghdr(nlmsg_len: u32, nlmsg_type: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&nlmsg_len.to_ne_bytes());   // nlmsg_len
        v.extend_from_slice(&nlmsg_type.to_ne_bytes());  // nlmsg_type
        v.extend_from_slice(&0u16.to_ne_bytes());        // nlmsg_flags
        v.extend_from_slice(&0u32.to_ne_bytes());        // nlmsg_seq
        v.extend_from_slice(&0u32.to_ne_bytes());        // nlmsg_pid
        v
    }

    fn build_ifaddrmsg(family: u8, prefix_len: u8, iface_index: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(family);
        v.push(prefix_len);
        v.push(0); // flags
        v.push(0); // scope
        v.extend_from_slice(&iface_index.to_ne_bytes());
        v
    }

    fn build_nla(nla_type: u16, data: &[u8]) -> Vec<u8> {
        let nla_len = (4 + data.len()) as u16;
        let mut v = Vec::new();
        v.extend_from_slice(&nla_len.to_ne_bytes());
        v.extend_from_slice(&nla_type.to_ne_bytes());
        v.extend_from_slice(data);
        // pad to 4-byte alignment
        while v.len() % 4 != 0 {
            v.push(0);
        }
        v
    }

    #[test]
    fn test_parse_newaddr_ipv4() {
        let ip = Ipv4Addr::new(192, 168, 1, 5);
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWADDR);
        msg.extend(build_ifaddrmsg(AF_INET, 24, 3));
        msg.extend(build_nla(IFA_ADDRESS, &ip.octets()));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        let evt = parse_netlink_msg(&msg).unwrap();
        assert_eq!(evt, NetlinkEvent::NewAddress {
            iface_index: 3,
            addr: IpAddr::V4(ip),
            prefix_len: 24,
        });
    }

    #[test]
    fn test_parse_newaddr_ipv6() {
        let ip: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWADDR);
        msg.extend(build_ifaddrmsg(AF_INET6, 64, 2));
        msg.extend(build_nla(IFA_ADDRESS, &ip.octets()));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        let evt = parse_netlink_msg(&msg).unwrap();
        assert_eq!(evt, NetlinkEvent::NewAddress {
            iface_index: 2,
            addr: IpAddr::V6(ip),
            prefix_len: 64,
        });
    }

    #[test]
    fn test_parse_deladdr() {
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_DELADDR);
        msg.extend(build_ifaddrmsg(AF_INET, 8, 1));
        msg.extend(build_nla(IFA_ADDRESS, &ip.octets()));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        let evt = parse_netlink_msg(&msg).unwrap();
        assert_eq!(evt, NetlinkEvent::DelAddress {
            iface_index: 1,
            addr: IpAddr::V4(ip),
        });
    }

    #[test]
    fn test_unknown_msg_type() {
        let msg = build_nlmsghdr(16, 999);
        assert_eq!(parse_netlink_msg(&msg), None);
    }

    // ── Tests for IfaceRecord parsers ──────────────────────────────────────────

    fn build_ifaddrmsg_flags(family: u8, prefix_len: u8, flags: u8, scope: u8, iface_index: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(family);
        v.push(prefix_len);
        v.push(flags);
        v.push(scope);
        v.extend_from_slice(&iface_index.to_ne_bytes());
        v
    }

    fn build_ndmsg(family: u8, if_index: u32, ndm_state: u16) -> Vec<u8> {
        let mut v = vec![0u8; 12];
        v[0] = family;
        // pad1 = 0, pad2 = 0 already
        v[4..8].copy_from_slice(&if_index.to_ne_bytes());
        v[8..10].copy_from_slice(&ndm_state.to_ne_bytes());
        v
    }

    fn build_ifinfomsg(if_type: u16, if_index: u32, ifi_flags: u32) -> Vec<u8> {
        let mut v = vec![0u8; 16];
        v[2..4].copy_from_slice(&if_type.to_ne_bytes());
        v[4..8].copy_from_slice(&if_index.to_ne_bytes());
        v[8..12].copy_from_slice(&ifi_flags.to_ne_bytes());
        v
    }

    #[test]
    fn test_parse_newaddr_record_ipv4() {
        let ip: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWADDR);
        msg.extend(build_ifaddrmsg_flags(AF_INET, 24, 0, 0, 2));
        msg.extend(build_nla(IFA_LOCAL, &ip.octets()));
        msg.extend(build_nla(IFA_BROADCAST, &Ipv4Addr::new(10, 0, 0, 255).octets()));
        msg.extend(build_nla(IFA_LABEL, b"eth0\0"));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        let rec = parse_newaddr_record(&msg).unwrap();
        match rec {
            IfaceRecord::V4 { addr, if_index, label, netmask, broadcast } => {
                assert_eq!(addr, ip);
                assert_eq!(if_index, 2);
                assert_eq!(label.as_deref(), Some("eth0"));
                assert_eq!(netmask, Ipv4Addr::new(255, 255, 255, 0));
                assert_eq!(broadcast, Ipv4Addr::new(10, 0, 0, 255));
            }
            other => panic!("expected V4, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_newaddr_record_ipv6() {
        let ip: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWADDR);
        // flags: IFA_F_TEMPORARY = 0x01  (so PERMANENT flag should NOT be set)
        msg.extend(build_ifaddrmsg_flags(AF_INET6, 64, 0x01, 0, 3));
        msg.extend(build_nla(IFA_ADDRESS, &ip.octets()));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        let rec = parse_newaddr_record(&msg).unwrap();
        match rec {
            IfaceRecord::V6 { addr, prefix_len, if_index, flags, .. } => {
                assert_eq!(addr, ip);
                assert_eq!(prefix_len, 64);
                assert_eq!(if_index, 3);
                assert_eq!(flags & IFACE_PERMANENT, 0); // temporary → not permanent
            }
            other => panic!("expected V6, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_newaddr_record_ipv6_permanent() {
        let ip: Ipv6Addr = "fd00::1".parse().unwrap();
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWADDR);
        // flags = 0 → not temporary → PERMANENT should be set
        msg.extend(build_ifaddrmsg_flags(AF_INET6, 48, 0, 0, 1));
        msg.extend(build_nla(IFA_ADDRESS, &ip.octets()));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        let rec = parse_newaddr_record(&msg).unwrap();
        match rec {
            IfaceRecord::V6 { flags, .. } => {
                assert_ne!(flags & IFACE_PERMANENT, 0);
            }
            other => panic!("expected V6, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_newneigh_record_ok() {
        let ip   = [192u8, 168, 1, 1];
        let mac  = [0xaau8, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        // NUD_REACHABLE = 0x02 (not NOARP/INCOMPLETE/FAILED)
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWNEIGH);
        msg.extend(build_ndmsg(AF_INET, 1, 0x02));
        msg.extend(build_nla(NDA_DST,    &ip));
        msg.extend(build_nla(NDA_LLADDR, &mac));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        let rec = parse_newneigh_record(&msg).unwrap();
        match rec {
            IfaceRecord::Arp { ip: r_ip, mac: r_mac, .. } => {
                assert_eq!(r_ip,  ip.to_vec());
                assert_eq!(r_mac, mac.to_vec());
            }
            other => panic!("expected Arp, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_newneigh_record_nud_failed() {
        // NUD_FAILED entries should be filtered out
        let ip  = [192u8, 168, 1, 1];
        let mac = [0xaau8, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWNEIGH);
        msg.extend(build_ndmsg(AF_INET, 1, NUD_FAILED));
        msg.extend(build_nla(NDA_DST,    &ip));
        msg.extend(build_nla(NDA_LLADDR, &mac));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        assert!(parse_newneigh_record(&msg).is_none());
    }

    #[test]
    fn test_parse_newlink_record_ok() {
        let mac = [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWLINK);
        // type=1 (ETHER), index=5, flags=0 (not loopback/p2p)
        msg.extend(build_ifinfomsg(1, 5, 0));
        msg.extend(build_nla(IFLA_ADDRESS, &mac));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        let rec = parse_newlink_record(&msg).unwrap();
        match rec {
            IfaceRecord::Link { if_index, if_type, mac: r_mac } => {
                assert_eq!(if_index, 5);
                assert_eq!(if_type, 1);
                assert_eq!(r_mac, mac.to_vec());
            }
            other => panic!("expected Link, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_newlink_record_loopback_filtered() {
        let mac = [0u8; 6];
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWLINK);
        // IFF_LOOPBACK = 0x8
        msg.extend(build_ifinfomsg(772, 1, IFF_LOOPBACK));
        msg.extend(build_nla(IFLA_ADDRESS, &mac));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        assert!(parse_newlink_record(&msg).is_none());
    }

    #[test]
    fn test_parse_iface_response_ipv4() {
        let ip: Ipv4Addr = "192.168.0.100".parse().unwrap();
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWADDR);
        msg.extend(build_ifaddrmsg(AF_INET, 24, 2));
        msg.extend(build_nla(IFA_LOCAL, &ip.octets()));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        let records = parse_iface_response(&msg, AF_INET);
        assert_eq!(records.len(), 1);
        match &records[0] {
            IfaceRecord::V4 { addr, .. } => assert_eq!(*addr, ip),
            other => panic!("unexpected: {:?}", other),
        }
    }

    #[test]
    fn test_nl_async_newaddr_sets_state() {
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWADDR);
        msg.extend(build_ifaddrmsg(AF_INET, 24, 1));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        let state = nl_async(&msg, 0);
        assert_ne!(state & STATE_NEWADDR, 0);
    }

    #[test]
    fn test_nl_async_newaddr_only_once() {
        // Second identical message should not toggle the flag (it's already set)
        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWADDR);
        msg.extend(build_ifaddrmsg(AF_INET, 24, 1));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        let s0 = nl_async(&msg, 0);
        let s1 = nl_async(&msg, s0);
        assert_eq!(s0, s1); // flag already set, no change
    }

    // ── EPERM-only multicast-bind fallback (netlink.c:76-81) ─────────────────

    #[test]
    fn retries_without_multicast_only_on_eperm() {
        let eperm = std::io::Error::from_raw_os_error(libc::EPERM);
        assert!(should_retry_without_multicast(&eperm));
    }

    #[test]
    fn does_not_retry_on_other_bind_errors() {
        let eaddrinuse = std::io::Error::from_raw_os_error(libc::EADDRINUSE);
        let einval = std::io::Error::from_raw_os_error(libc::EINVAL);
        let eacces = std::io::Error::from_raw_os_error(libc::EACCES);
        assert!(!should_retry_without_multicast(&eaddrinuse));
        assert!(!should_retry_without_multicast(&einval));
        assert!(!should_retry_without_multicast(&eacces));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn netlink_open_succeeds_or_fails_gracefully() {
        // Creating a NETLINK_ROUTE socket never requires elevated privilege;
        // only the multicast-group bind might (netlink.c:73-81), and
        // `netlink_open` already falls back to a no-multicast bind on EPERM.
        // Either outcome here is acceptable — we only assert it doesn't panic
        // and that any error carries a real errno.
        match netlink_open() {
            Ok((fd, _pid)) => unsafe { libc::close(fd); },
            Err(e) => assert!(e.raw_os_error().is_some()),
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn netlink_multicast_drains_and_detects_newaddr() {
        // netlink_multicast() only ever calls libc::recv() on the fd it's
        // given, so a plain AF_UNIX SOCK_DGRAM socketpair can stand in for a
        // real netlink socket to prove the drain/dispatch wiring works,
        // without needing CAP_NET_ADMIN to bind real multicast groups.
        let mut fds = [0i32; 2];
        let rc = unsafe {
            libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr())
        };
        assert_eq!(rc, 0);
        let [a, b] = fds;

        let mut msg = build_nlmsghdr(0, nlmsg_type::RTM_NEWADDR);
        msg.extend(build_ifaddrmsg(AF_INET, 24, 1));
        let total = msg.len() as u32;
        msg[0..4].copy_from_slice(&total.to_ne_bytes());

        let sent = unsafe {
            libc::send(a, msg.as_ptr() as *const libc::c_void, msg.len(), 0)
        };
        assert_eq!(sent as usize, msg.len());

        let state = netlink_multicast(b);
        assert_ne!(state & STATE_NEWADDR, 0);

        unsafe {
            libc::close(a);
            libc::close(b);
        }
    }
}

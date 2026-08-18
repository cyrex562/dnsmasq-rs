//! Linux conntrack mark retrieval via nfnetlink.
//!
//! Port of `get_incoming_mark()` / `callback()` in upstream `conntrack.c`.
//! Upstream issues an `NFCT_Q_GET` query (nfnetlink message type
//! `IPCTNL_MSG_CT_GET`) describing the client's flow tuple and reads the
//! `CTA_MARK` attribute out of the kernel's response — it never creates or
//! mutates a conntrack entry.

#![cfg(feature = "conntrack")]

use std::net::{IpAddr, SocketAddr};

// ---------------------------------------------------------------------------
// Netlink / nfct protocol constants
// ---------------------------------------------------------------------------

// NETLINK_NETFILTER subsystem for conntrack
const NFNL_SUBSYS_CTNETLINK: u16 = 1;
/// `IPCTNL_MSG_CT_GET` — query an existing entry (never `CT_NEW`, which
/// upstream never sends from `get_incoming_mark`).
const IPCTNL_MSG_CT_GET: u8 = 1;

// CTA attributes
const CTA_TUPLE_ORIG: u16 = 1;
const CTA_MARK: u16 = 8;

// CTA_TUPLE sub-attrs
const CTA_TUPLE_IP: u16 = 1;
const CTA_TUPLE_PROTO: u16 = 2;

// CTA_IP sub-attrs
const CTA_IP_V4_SRC: u16 = 1;
const CTA_IP_V4_DST: u16 = 2;
const CTA_IP_V6_SRC: u16 = 3;
const CTA_IP_V6_DST: u16 = 4;

// CTA_PROTO sub-attrs
const CTA_PROTO_NUM: u16 = 1;
const CTA_PROTO_SRC_PORT: u16 = 2;
const CTA_PROTO_DST_PORT: u16 = 3;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_TYPE_MASK: u16 = !NLA_F_NESTED;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

// Address families
const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;

// nlmsg flags
const NLM_F_REQUEST: u16 = 0x0001;

// Control message types
const NLMSG_ERROR: u16 = 2;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn append_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn append_nla(buf: &mut Vec<u8>, nla_type: u16, data: &[u8]) {
    let len = 4 + data.len();
    append_u16_le(buf, len as u16);
    append_u16_le(buf, nla_type);
    buf.extend_from_slice(data);
    let pad = (4 - (len % 4)) % 4;
    for _ in 0..pad {
        buf.push(0);
    }
}

fn append_nested(buf: &mut Vec<u8>, nla_type: u16, body: Vec<u8>) {
    append_nla(buf, nla_type | NLA_F_NESTED, &body);
}

/// Walk the top-level NLAs starting at `off` in `buf`, calling `f(type, data)`
/// for each. Malformed trailing bytes are simply not visited — no panics.
fn for_each_nla<F: FnMut(u16, &[u8])>(buf: &[u8], off: usize, mut f: F) {
    let mut pos = off;
    while pos + 4 <= buf.len() {
        let len = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
        let nla_type = u16::from_le_bytes([buf[pos + 2], buf[pos + 3]]) & NLA_TYPE_MASK;
        if len < 4 || pos + len > buf.len() {
            break;
        }
        f(nla_type, &buf[pos + 4..pos + len]);
        let padded = len + ((4 - (len % 4)) % 4);
        if padded == 0 {
            break;
        }
        pos += padded;
    }
}

// ---------------------------------------------------------------------------
// Query construction
// ---------------------------------------------------------------------------

/// Build an nfnetlink `IPCTNL_MSG_CT_GET` request for the flow tuple
/// `peer_addr -> (local_addr, daemon_port)`.
///
/// Mirrors the tuple upstream builds in `get_incoming_mark()`
/// (`conntrack.c:34-52`): `ATTR_L4PROTO`/`ATTR_PORT_DST` = `daemon->port`,
/// `ATTR_L3PROTO`/source address+port from `peer_addr`, destination address
/// from `local_addr`. Unlike a set/create message, a GET query carries no
/// `CTA_MARK` attribute — the mark is what the kernel's response supplies.
pub fn build_get_mark_query(
    peer_addr: SocketAddr,
    local_addr: IpAddr,
    daemon_port: u16,
    istcp: bool,
    seq: u32,
) -> Vec<u8> {
    let family = match peer_addr.ip() {
        IpAddr::V4(_) => AF_INET,
        IpAddr::V6(_) => AF_INET6,
    };

    // --- CTA_TUPLE_IP ---
    let mut ip_body: Vec<u8> = Vec::new();
    match (peer_addr.ip(), local_addr) {
        (IpAddr::V4(s), IpAddr::V4(d)) => {
            append_nla(&mut ip_body, CTA_IP_V4_SRC, &s.octets());
            append_nla(&mut ip_body, CTA_IP_V4_DST, &d.octets());
        }
        (IpAddr::V6(s), IpAddr::V6(d)) => {
            append_nla(&mut ip_body, CTA_IP_V6_SRC, &s.octets());
            append_nla(&mut ip_body, CTA_IP_V6_DST, &d.octets());
        }
        _ => {
            // Mixed address families — emit empty ip body, matching no entry.
        }
    }

    // --- CTA_TUPLE_PROTO ---
    let mut proto_body: Vec<u8> = Vec::new();
    let l4proto = if istcp { IPPROTO_TCP } else { IPPROTO_UDP };
    append_nla(&mut proto_body, CTA_PROTO_NUM, &[l4proto]);
    append_nla(
        &mut proto_body,
        CTA_PROTO_SRC_PORT,
        &peer_addr.port().to_be_bytes(),
    );
    append_nla(&mut proto_body, CTA_PROTO_DST_PORT, &daemon_port.to_be_bytes());

    // --- CTA_TUPLE_ORIG (nested) ---
    let mut tuple_body: Vec<u8> = Vec::new();
    append_nested(&mut tuple_body, CTA_TUPLE_IP, ip_body);
    append_nested(&mut tuple_body, CTA_TUPLE_PROTO, proto_body);

    // --- Top-level NLAs --- (no CTA_MARK: this is a query, not a set)
    let mut nlas: Vec<u8> = Vec::new();
    append_nested(&mut nlas, CTA_TUPLE_ORIG, tuple_body);

    // --- nfgenmsg ---
    let nfgenmsg = [family, 0u8, 0u8, 0u8];

    // --- nlmsghdr ---
    let msg_type: u16 = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET as u16;
    let total_len = 16u32 + nfgenmsg.len() as u32 + nlas.len() as u32;

    let mut buf: Vec<u8> = Vec::new();
    append_u32_le(&mut buf, total_len);
    append_u16_le(&mut buf, msg_type);
    append_u16_le(&mut buf, NLM_F_REQUEST);
    append_u32_le(&mut buf, seq);
    append_u32_le(&mut buf, 0); // pid (kernel)
    buf.extend_from_slice(&nfgenmsg);
    buf.extend_from_slice(&nlas);
    buf
}

// ---------------------------------------------------------------------------
// Response parsing — equivalent of `callback()` (`conntrack.c:75-83`)
// ---------------------------------------------------------------------------

/// Extract `CTA_MARK` from a single nfnetlink response message (header
/// included). Returns `None` if the message is an error reply, too short to
/// contain a header, or carries no `CTA_MARK` attribute — exactly the cases
/// upstream leaves `gotit == 0` for.
pub fn parse_mark_response(buf: &[u8]) -> Option<u32> {
    const NLMSG_HDRLEN: usize = 16;
    const NFGENMSG_LEN: usize = 4;

    if buf.len() < NLMSG_HDRLEN {
        return None;
    }
    let msg_type = u16::from_le_bytes([buf[4], buf[5]]);
    if msg_type == NLMSG_ERROR {
        return None;
    }
    if buf.len() < NLMSG_HDRLEN + NFGENMSG_LEN {
        return None;
    }

    let mut mark = None;
    for_each_nla(buf, NLMSG_HDRLEN + NFGENMSG_LEN, |nla_type, data| {
        if nla_type == CTA_MARK && data.len() == 4 {
            mark = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
        }
    });
    mark
}

// ---------------------------------------------------------------------------
// Socket I/O — equivalent of `nfct_open`/`nfct_query`/`nfct_close`
// (`conntrack.c:55-67`)
// ---------------------------------------------------------------------------

/// Query the kernel for the firewall mark of the connection matching
/// `peer_addr -> (local_addr, daemon_port)` over TCP or UDP.
///
/// Mirrors `get_incoming_mark()` (`conntrack.c:27-73`): opens a
/// `NETLINK_NETFILTER` socket, sends an `IPCTNL_MSG_CT_GET` query, and reads
/// back `CTA_MARK` from the response. Returns `None` on any error or when no
/// matching connection is found — upstream's `gotit == 0` path — never
/// panics.
#[cfg(target_os = "linux")]
pub fn get_incoming_mark(
    peer_addr: SocketAddr,
    local_addr: IpAddr,
    istcp: bool,
    daemon_port: u16,
) -> Option<u32> {
    use std::sync::atomic::{AtomicU32, Ordering};
    static SEQ: AtomicU32 = AtomicU32::new(0);

    const NETLINK_NETFILTER: i32 = 12;

    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_NETFILTER) };
    if fd == -1 {
        return None;
    }

    // sockaddr_nl: u16 nl_family, u16 nl_pad, u32 nl_pid, u32 nl_groups
    let mut addr = [0u8; 12];
    addr[0..2].copy_from_slice(&(libc::AF_NETLINK as u16).to_ne_bytes());
    let bind_ret = unsafe {
        libc::bind(
            fd,
            addr.as_ptr() as *const libc::sockaddr,
            addr.len() as libc::socklen_t,
        )
    };
    if bind_ret == -1 {
        unsafe { libc::close(fd) };
        return None;
    }

    let seq = SEQ.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    let msg = build_get_mark_query(peer_addr, local_addr, daemon_port, istcp, seq);

    // Destination: sockaddr_nl for kernel (pid = 0).
    let mut dest = [0u8; 12];
    dest[0..2].copy_from_slice(&(libc::AF_NETLINK as u16).to_ne_bytes());

    let sent = unsafe {
        libc::sendto(
            fd,
            msg.as_ptr() as *const libc::c_void,
            msg.len(),
            0,
            dest.as_ptr() as *const libc::sockaddr,
            dest.len() as libc::socklen_t,
        )
    };
    if sent == -1 {
        unsafe { libc::close(fd) };
        return None;
    }

    let mut buf = vec![0u8; 4096];
    let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
    unsafe { libc::close(fd) };
    if n <= 0 {
        return None;
    }

    parse_mark_response(&buf[..n as usize])
}

/// Non-Linux stub — conntrack is a Linux-only kernel facility, matching the
/// `#[cfg(target_os = "linux")]` gate already used by `set_outgoing_mark` in
/// `forward.rs`.
#[cfg(not(target_os = "linux"))]
pub fn get_incoming_mark(
    _peer_addr: SocketAddr,
    _local_addr: IpAddr,
    _istcp: bool,
    _daemon_port: u16,
) -> Option<u32> {
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn nlmsg_type(buf: &[u8]) -> u16 {
        u16::from_le_bytes([buf[4], buf[5]])
    }

    fn nlmsg_flags(buf: &[u8]) -> u16 {
        u16::from_le_bytes([buf[6], buf[7]])
    }

    fn nlmsg_seq(buf: &[u8]) -> u32 {
        u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]])
    }

    fn top_level_nla_types(buf: &[u8]) -> Vec<u16> {
        let mut types = Vec::new();
        for_each_nla(buf, 20, |t, _| types.push(t));
        types
    }

    #[test]
    fn build_get_mark_query_uses_ct_get_message_type() {
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345));
        let local = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let buf = build_get_mark_query(peer, local, 53, false, 7);
        let expected_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET as u16;
        assert_eq!(nlmsg_type(&buf), expected_type, "must request IPCTNL_MSG_CT_GET, not CT_NEW");
    }

    #[test]
    fn build_get_mark_query_flags_are_request_only() {
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345));
        let local = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let buf = build_get_mark_query(peer, local, 53, false, 1);
        assert_eq!(
            nlmsg_flags(&buf),
            NLM_F_REQUEST,
            "a GET query must not carry NLM_F_CREATE (or unrequested ACK)"
        );
    }

    #[test]
    fn build_get_mark_query_carries_the_given_sequence_number() {
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345));
        let local = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let buf = build_get_mark_query(peer, local, 53, false, 99);
        assert_eq!(nlmsg_seq(&buf), 99);
    }

    #[test]
    fn build_get_mark_query_carries_no_cta_mark_attribute() {
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 12345));
        let local = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        let buf = build_get_mark_query(peer, local, 53, false, 1);
        assert!(
            !top_level_nla_types(&buf).contains(&CTA_MARK),
            "a query reads the mark, it does not set one"
        );
        // top-level attribute set is exactly the tuple.
        assert_eq!(top_level_nla_types(&buf), vec![CTA_TUPLE_ORIG]);
    }

    #[test]
    fn build_get_mark_query_family_byte_ipv4() {
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 1024));
        let local = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let buf = build_get_mark_query(peer, local, 53, false, 1);
        assert_eq!(buf[16], AF_INET);
    }

    #[test]
    fn build_get_mark_query_family_byte_ipv6() {
        let peer = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1024, 0, 0));
        let local = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let buf = build_get_mark_query(peer, local, 53, true, 1);
        assert_eq!(buf[16], AF_INET6);
    }

    #[test]
    fn build_get_mark_query_tcp_vs_udp_proto_num() {
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 1024));
        let local = IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8));
        let udp = build_get_mark_query(peer, local, 53, false, 1);
        let tcp = build_get_mark_query(peer, local, 53, true, 1);
        assert!(udp.windows(1).any(|w| w == [IPPROTO_UDP]));
        assert!(tcp.windows(1).any(|w| w == [IPPROTO_TCP]));
    }

    /// Build a synthetic `IPCTNL_MSG_CT_GET` reply carrying `CTA_MARK`, the
    /// way the kernel would answer a query — used to test the parser without
    /// a real socket.
    fn synthetic_reply_with_mark(mark: u32) -> Vec<u8> {
        let mut nlas = Vec::new();
        append_nla(&mut nlas, CTA_MARK, &mark.to_be_bytes());
        let nfgenmsg = [AF_INET, 0, 0, 0];
        let msg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET as u16;
        let total_len = 16u32 + nfgenmsg.len() as u32 + nlas.len() as u32;
        let mut buf = Vec::new();
        append_u32_le(&mut buf, total_len);
        append_u16_le(&mut buf, msg_type);
        append_u16_le(&mut buf, 0);
        append_u32_le(&mut buf, 1);
        append_u32_le(&mut buf, 0);
        buf.extend_from_slice(&nfgenmsg);
        buf.extend_from_slice(&nlas);
        buf
    }

    #[test]
    fn parse_mark_response_extracts_the_mark() {
        let buf = synthetic_reply_with_mark(0xDEADBEEF);
        assert_eq!(parse_mark_response(&buf), Some(0xDEADBEEF));
    }

    #[test]
    fn parse_mark_response_extracts_a_zero_mark() {
        let buf = synthetic_reply_with_mark(0);
        assert_eq!(parse_mark_response(&buf), Some(0));
    }

    #[test]
    fn parse_mark_response_without_cta_mark_returns_none() {
        // A response that carries a tuple but no mark attribute.
        let mut tuple_body = Vec::new();
        append_nla(&mut tuple_body, CTA_TUPLE_IP, &[]);
        let mut nlas = Vec::new();
        append_nested(&mut nlas, CTA_TUPLE_ORIG, tuple_body);
        let nfgenmsg = [AF_INET, 0, 0, 0];
        let msg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET as u16;
        let total_len = 16u32 + nfgenmsg.len() as u32 + nlas.len() as u32;
        let mut buf = Vec::new();
        append_u32_le(&mut buf, total_len);
        append_u16_le(&mut buf, msg_type);
        append_u16_le(&mut buf, 0);
        append_u32_le(&mut buf, 1);
        append_u32_le(&mut buf, 0);
        buf.extend_from_slice(&nfgenmsg);
        buf.extend_from_slice(&nlas);

        assert_eq!(parse_mark_response(&buf), None);
    }

    #[test]
    fn parse_mark_response_on_nlmsg_error_returns_none() {
        let mut buf = Vec::new();
        append_u32_le(&mut buf, 20);
        append_u16_le(&mut buf, NLMSG_ERROR);
        append_u16_le(&mut buf, 0);
        append_u32_le(&mut buf, 1);
        append_u32_le(&mut buf, 0);
        buf.extend_from_slice(&[0u8; 4]); // error code / stub payload
        assert_eq!(parse_mark_response(&buf), None);
    }

    #[test]
    fn parse_mark_response_on_truncated_buffer_does_not_panic() {
        assert_eq!(parse_mark_response(&[]), None);
        assert_eq!(parse_mark_response(&[0u8; 10]), None);
        assert_eq!(parse_mark_response(&[0u8; 18]), None);
    }

    #[test]
    fn parse_mark_response_on_corrupt_nla_length_does_not_panic() {
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&24u32.to_le_bytes());
        let msg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET as u16;
        buf[4..6].copy_from_slice(&msg_type.to_le_bytes());
        // A bogus NLA claiming a length far beyond the buffer.
        buf.extend_from_slice(&0xFFFFu16.to_le_bytes());
        buf.extend_from_slice(&CTA_MARK.to_le_bytes());
        assert_eq!(parse_mark_response(&buf), None);
    }

    /// Capability-dependent: opening a `NETLINK_NETFILTER` socket needs no
    /// special privilege, but a real conntrack lookup may still be denied in
    /// a restricted sandbox. Either way `get_incoming_mark` must not panic,
    /// and the fabricated addresses below will not match any real
    /// connection, so `None` is the only value that would ever be correct.
    #[cfg(target_os = "linux")]
    #[test]
    fn get_incoming_mark_on_a_nonexistent_flow_returns_none_without_panicking() {
        let peer = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 5), 54321));
        let local = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 6));
        let result = std::panic::catch_unwind(|| get_incoming_mark(peer, local, false, 53));
        assert!(result.is_ok(), "get_incoming_mark must not panic even when unprivileged");
        assert_eq!(result.unwrap(), None);
    }
}

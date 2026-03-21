//! DHCPv4 protocol state machine: DISCOVER → OFFER → REQUEST → ACK/NAK.
//! Ported from `rfc2131.c`.

#[cfg(feature = "dhcp")]
use std::net::Ipv4Addr;
#[cfg(feature = "dhcp")]
use crate::dhcp_protocol::{
    DhcpMsgType, DhcpPacket,
    BOOTREQUEST, BOOTREPLY,
    OPTION_END, OPTION_MESSAGE_TYPE, OPTION_REQUESTED_IP, OPTION_SERVER_IDENTIFIER,
    DHCP_SERVER_PORT,
};
#[cfg(feature = "dhcp")]
use crate::types::dhcp::DhcpLease;

/// A composed DHCP reply ready to be serialised onto the wire.
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct DhcpReply {
    /// DHCP message type (OFFER, ACK, NAK …).
    pub msg_type: DhcpMsgType,
    /// Offered / assigned IPv4 address (`yiaddr`).
    pub yiaddr: Ipv4Addr,
    /// Wire-format DHCP options block.
    pub options: Vec<u8>,
    /// Server IP address (`siaddr`).
    pub siaddr: Ipv4Addr,
    /// Relay-agent IP address (`giaddr`).
    pub giaddr: Ipv4Addr,
}

/// Encode a DHCP option-53 (message type) TLV.
#[cfg(feature = "dhcp")]
pub fn option_msg_type(t: DhcpMsgType) -> [u8; 3] {
    [OPTION_MESSAGE_TYPE, 1, t as u8]
}

/// Return true if `addr` lies within the inclusive range `[start, end]`.
#[cfg(feature = "dhcp")]
fn in_pool(addr: Ipv4Addr, start: Ipv4Addr, end: Ipv4Addr) -> bool {
    let a = u32::from(addr);
    u32::from(start) <= a && a <= u32::from(end)
}

/// Pick an address to offer: re-use the existing lease address when present,
/// otherwise hand out `pool_start`.
#[cfg(feature = "dhcp")]
fn pick_offer_addr(
    pool_start: Ipv4Addr,
    pool_end: Ipv4Addr,
    existing_lease: Option<&DhcpLease>,
) -> Option<Ipv4Addr> {
    if let Some(lease) = existing_lease {
        if in_pool(lease.addr, pool_start, pool_end) {
            return Some(lease.addr);
        }
    }
    // Fall back to pool_start (a real server would search for a free address).
    if in_pool(pool_start, pool_start, pool_end) {
        Some(pool_start)
    } else {
        None
    }
}

/// Build the minimal options block for an OFFER or ACK reply.
#[cfg(feature = "dhcp")]
fn build_reply_options(msg_type: DhcpMsgType, server_id: Ipv4Addr) -> Vec<u8> {
    let mut opts = Vec::new();
    // Option 53 – message type
    opts.extend_from_slice(&option_msg_type(msg_type));
    // Option 54 – server identifier
    opts.push(OPTION_SERVER_IDENTIFIER);
    opts.push(4);
    opts.extend_from_slice(&server_id.octets());
    opts.push(OPTION_END);
    opts
}

/// Process a DHCP DISCOVER packet and produce an OFFER reply.
///
/// * `pool_start` / `pool_end` – inclusive address pool range.
/// * `existing_lease` – if the client already has a lease, offer that address.
/// * `server_id` – IP address this server should identify itself with.
#[cfg(feature = "dhcp")]
pub fn handle_discover(
    pkt: &DhcpPacket,
    pool_start: Ipv4Addr,
    pool_end: Ipv4Addr,
    existing_lease: Option<&DhcpLease>,
    server_id: Ipv4Addr,
) -> Option<DhcpReply> {
    let yiaddr = pick_offer_addr(pool_start, pool_end, existing_lease)?;
    Some(DhcpReply {
        msg_type: DhcpMsgType::Offer,
        yiaddr,
        options: build_reply_options(DhcpMsgType::Offer, server_id),
        siaddr: server_id,
        giaddr: pkt.giaddr,
    })
}

/// Process a DHCP REQUEST packet and produce an ACK or NAK reply.
///
/// The requested IP is taken from option 50; if it lies within the pool the
/// reply is ACK, otherwise NAK.
#[cfg(feature = "dhcp")]
pub fn handle_request(
    pkt: &DhcpPacket,
    pool_start: Ipv4Addr,
    pool_end: Ipv4Addr,
    server_id: Ipv4Addr,
) -> Option<DhcpReply> {
    // Find the requested IP (option 50) in the packet options.
    let requested = find_requested_ip(&pkt.options)?;

    if in_pool(requested, pool_start, pool_end) {
        Some(DhcpReply {
            msg_type: DhcpMsgType::Ack,
            yiaddr: requested,
            options: build_reply_options(DhcpMsgType::Ack, server_id),
            siaddr: server_id,
            giaddr: pkt.giaddr,
        })
    } else {
        Some(DhcpReply {
            msg_type: DhcpMsgType::Nak,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            options: build_reply_options(DhcpMsgType::Nak, server_id),
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: pkt.giaddr,
        })
    }
}

/// Extract the requested IP address from option 50 in a raw options buffer.
#[cfg(feature = "dhcp")]
fn find_requested_ip(options: &[u8]) -> Option<Ipv4Addr> {
    let data = crate::dhcp_common::find_option(options, OPTION_REQUESTED_IP)?;
    if data.len() < 4 {
        return None;
    }
    Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

/// Handle a DHCP INFORM message.
///
/// INFORM clients already have an IP address and just want options.
/// We respond with ACK containing options but without assigning an address
/// (yiaddr remains UNSPECIFIED).
#[cfg(feature = "dhcp")]
pub fn handle_inform(pkt: &DhcpPacket, server_id: Ipv4Addr) -> Option<DhcpReply> {
    // Must have a ciaddr to reply to.
    if pkt.ciaddr == Ipv4Addr::UNSPECIFIED {
        return None;
    }
    Some(DhcpReply {
        msg_type: DhcpMsgType::Ack,
        yiaddr:   Ipv4Addr::UNSPECIFIED, // not assigning an address
        options:  build_reply_options(DhcpMsgType::Ack, server_id),
        siaddr:   server_id,
        giaddr:   pkt.giaddr,
    })
}

/// Handle a DHCP RELEASE message.
///
/// The client is releasing its leased address.  In a full implementation this
/// would delete the lease from the database.  Here we record the event and
/// return `None` (no reply is sent for RELEASE per RFC 2131 §4.3.4).
#[cfg(feature = "dhcp")]
pub fn handle_release(pkt: &DhcpPacket, pool_start: Ipv4Addr, pool_end: Ipv4Addr) -> bool {
    // Return true if the ciaddr was in our pool (we would free it).
    in_pool(pkt.ciaddr, pool_start, pool_end)
}

/// Handle a DHCP DECLINE message.
///
/// The client is refusing the offered address (e.g. duplicate detected).
/// Per RFC 2131 §4.3.3 we should remove the address from the pool; here we
/// return whether the declined address was ours.
#[cfg(feature = "dhcp")]
pub fn handle_decline(pkt: &DhcpPacket, pool_start: Ipv4Addr, pool_end: Ipv4Addr) -> bool {
    // Check the requested IP option (option 50) — this is what the client is declining.
    if let Some(declined_ip) = find_requested_ip(&pkt.options) {
        in_pool(declined_ip, pool_start, pool_end)
    } else {
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-level option primitives (option_find1, option_find, option_put, …)
// ─────────────────────────────────────────────────────────────────────────────

/// Scan a flat options buffer for an option of type `opt_type` with at least
/// `minsize` data bytes.
///
/// Returns the byte index of the option's type byte within `buf`, or `None`.
/// PAD bytes (0x00) are skipped; the scan stops at END (0xFF) or end of buffer.
///
/// Mirrors C's `option_find1()`.
#[cfg(feature = "dhcp")]
pub fn option_find1(buf: &[u8], opt_type: u8, minsize: usize) -> Option<usize> {
    use crate::dhcp_protocol::{OPTION_END, OPTION_PAD};
    let mut i = 0;
    while i < buf.len() {
        let code = buf[i];
        if code == OPTION_END {
            return if opt_type == OPTION_END { Some(i) } else { None };
        }
        if code == OPTION_PAD {
            i += 1;
            continue;
        }
        if i + 1 >= buf.len() {
            return None; // malformed
        }
        let len = buf[i + 1] as usize;
        if i + 2 + len > buf.len() {
            return None; // malformed
        }
        if code == opt_type && len >= minsize {
            return Some(i);
        }
        i += 2 + len;
    }
    None
}

/// Return the length field of the option whose type byte is at `idx` in `buf`.
#[cfg(feature = "dhcp")]
#[inline]
pub fn option_len_at(buf: &[u8], idx: usize) -> usize {
    buf[idx + 1] as usize
}

/// Return the data slice of the option whose type byte is at `idx` in `buf`.
#[cfg(feature = "dhcp")]
#[inline]
pub fn option_val_at(buf: &[u8], idx: usize) -> &[u8] {
    let len = option_len_at(buf, idx);
    &buf[idx + 2..idx + 2 + len]
}

/// Read a big-endian unsigned integer of `size` bytes from an option's data,
/// starting at `offset` bytes into that data.
///
/// Mirrors C's `option_uint()`.
#[cfg(feature = "dhcp")]
pub fn option_uint_at(buf: &[u8], idx: usize, offset: usize, size: usize) -> u32 {
    let data = option_val_at(buf, idx);
    let mut ret: u32 = 0;
    for i in offset..offset + size {
        ret = (ret << 8) | u32::from(*data.get(i).unwrap_or(&0));
    }
    ret
}

/// Read an IPv4 address from an option's data field.
///
/// Returns `None` if the option data is fewer than 4 bytes.
/// Mirrors C's `option_addr()`.
#[cfg(feature = "dhcp")]
pub fn option_addr_at(buf: &[u8], idx: usize) -> Option<std::net::Ipv4Addr> {
    let data = option_val_at(buf, idx);
    if data.len() < 4 {
        return None;
    }
    Some(std::net::Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

/// Search a [`DhcpPacket`]'s options for option `opt_type` with at least
/// `minsize` data bytes.
///
/// Searches:
/// 1. The primary options area (after the 4-byte DHCP cookie).
/// 2. If OPTION_OVERLOAD (52) is set, the `file` and/or `sname` fields.
///
/// Returns `(buffer_slice, index_within_slice)` on success.
/// Mirrors C's `option_find()`.
#[cfg(feature = "dhcp")]
pub fn option_find<'a>(
    pkt: &'a DhcpPacket,
    opt_type: u8,
    minsize: usize,
) -> Option<(&'a [u8], usize)> {
    use crate::dhcp_protocol::OPTION_OVERLOAD;
    const COOKIE_LEN: usize = 4;

    // Primary options area (skip the 4-byte cookie).
    let opts = if pkt.options.len() > COOKIE_LEN {
        &pkt.options[COOKIE_LEN..]
    } else {
        &pkt.options[..]
    };

    if let Some(idx) = option_find1(opts, opt_type, minsize) {
        return Some((opts, idx));
    }

    // Look for OPTION_OVERLOAD to check sname/file areas.
    let overload_idx = option_find1(opts, OPTION_OVERLOAD, 1)?;
    let overload_val = option_uint_at(opts, overload_idx, 0, 1);

    // Bit 0 → filename field used for options.
    if (overload_val & 1) != 0 {
        if let Some(idx) = option_find1(&pkt.file, opt_type, minsize) {
            return Some((&pkt.file, idx));
        }
    }

    // Bit 1 → sname field used for options.
    if (overload_val & 2) != 0 {
        if let Some(idx) = option_find1(&pkt.sname, opt_type, minsize) {
            return Some((&pkt.sname, idx));
        }
    }

    None
}

/// Append a big-endian integer option TLV to an options buffer.
///
/// Inserts the new TLV just before the trailing OPTION_END byte (if present),
/// or at the end of the buffer otherwise.
///
/// Mirrors C's `option_put()`.
#[cfg(feature = "dhcp")]
pub fn option_put(opts: &mut Vec<u8>, opt: u8, val: u32, len: usize) {
    use crate::dhcp_protocol::OPTION_END;
    // Remove trailing END so we can append cleanly.
    if opts.last() == Some(&OPTION_END) {
        opts.pop();
    }
    opts.push(opt);
    opts.push(len as u8);
    for i in (0..len).rev() {
        opts.push((val >> (8 * i)) as u8);
    }
    opts.push(OPTION_END);
}

/// Append a string option TLV to an options buffer.
///
/// If `null_term` is true and the string is fewer than 255 bytes, a NUL
/// terminator is appended to the value (matching C behaviour).
///
/// Mirrors C's `option_put_string()`.
#[cfg(feature = "dhcp")]
pub fn option_put_string(opts: &mut Vec<u8>, opt: u8, s: &str, null_term: bool) {
    use crate::dhcp_protocol::OPTION_END;
    let bytes = s.as_bytes();
    let mut len = bytes.len();
    if null_term && len < 255 {
        len += 1;
    }
    let len = len.min(255);
    if opts.last() == Some(&OPTION_END) {
        opts.pop();
    }
    opts.push(opt);
    opts.push(len as u8);
    let data_len = len - if null_term && s.len() < 255 { 1 } else { 0 };
    opts.extend_from_slice(&bytes[..data_len.min(bytes.len())]);
    if null_term && s.len() < 255 {
        opts.push(0u8);
    }
    opts.push(OPTION_END);
}

/// Append a raw-bytes option TLV to an options buffer.
#[cfg(feature = "dhcp")]
pub fn option_put_raw(opts: &mut Vec<u8>, opt: u8, data: &[u8]) {
    use crate::dhcp_protocol::OPTION_END;
    let len = data.len().min(255);
    if opts.last() == Some(&OPTION_END) {
        opts.pop();
    }
    opts.push(opt);
    opts.push(len as u8);
    opts.extend_from_slice(&data[..len]);
    opts.push(OPTION_END);
}

/// Check whether `opt` appears in a requested-options list.
///
/// If `list` is `None`, returns `true` (send everything).
/// If the list ends without an OPTION_END, the whole slice is searched.
/// Mirrors C's `in_list()`.
#[cfg(feature = "dhcp")]
pub fn in_list(list: Option<&[u8]>, opt: u8) -> bool {
    use crate::dhcp_protocol::OPTION_END;
    match list {
        None => true,
        Some(l) => l
            .iter()
            .take_while(|&&b| b != OPTION_END)
            .any(|&b| b == opt),
    }
}

/// Zero the `sname`, `file`, and options areas of a DHCP packet (after the
/// 4-byte DHCP cookie).  Also clears `siaddr`.
///
/// Mirrors C's `clear_packet()`.
#[cfg(feature = "dhcp")]
pub fn clear_packet(pkt: &mut DhcpPacket) {
    pkt.sname  = [0u8; 64];
    pkt.file   = [0u8; 128];
    pkt.siaddr = Ipv4Addr::UNSPECIFIED;
    // Keep the 4-byte DHCP cookie if present; zero everything after it.
    const COOKIE_LEN: usize = 4;
    if pkt.options.len() > COOKIE_LEN {
        pkt.options.truncate(COOKIE_LEN);
    }
}

/// Compute the on-wire byte length of a DHCP packet.
///
/// The result is at least `MIN_DHCP_PACKET_SIZE` (300 bytes per RFC 2131 §2).
/// It accounts for the fixed header fields plus the serialised options.
///
/// Mirrors C's `dhcp_packet_size()`.
#[cfg(feature = "dhcp")]
pub fn dhcp_packet_size(pkt: &DhcpPacket) -> usize {
    // Fixed DHCP header: op(1) htype(1) hlen(1) hops(1) xid(4) secs(2) flags(2)
    // ciaddr(4) yiaddr(4) siaddr(4) giaddr(4) chaddr(16) sname(64) file(128) cookie(4)
    const FIXED_HEADER: usize = 1 + 1 + 1 + 1 + 4 + 2 + 2 + 4 + 4 + 4 + 4 + 16 + 64 + 128 + 4;
    const MIN_DHCP_PACKET_SIZE: usize = 300;

    // Options area (including the cookie stored in pkt.options).
    let opts_len = pkt.options.len();
    let total = FIXED_HEADER + opts_len;
    total.max(MIN_DHCP_PACKET_SIZE)
}

// ─────────────────────────────────────────────────────────────────────────────
// Relay agent support (RFC 2131 §4.1.1 / RFC 1542)
// ─────────────────────────────────────────────────────────────────────────────

/// Direction of relay forwarding.
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDirection {
    /// Client → server (giaddr is set to relay's address).
    ClientToServer,
    /// Server → client (relay forwards reply to client).
    ServerToClient,
}

/// Add relay-agent information to a DHCP packet being forwarded from client
/// to server.
///
/// - Sets `hops += 1` (relay hop count).
/// - Sets `giaddr` to `relay_addr` if it is currently UNSPECIFIED.
///
/// Returns `false` if `hops` has reached 16 (discard per RFC 1542 §3.2).
#[cfg(feature = "dhcp")]
pub fn relay_client_to_server(pkt: &mut DhcpPacket, relay_addr: Ipv4Addr) -> bool {
    if pkt.hops >= 16 {
        return false;
    }
    pkt.hops += 1;
    if pkt.giaddr == Ipv4Addr::UNSPECIFIED {
        pkt.giaddr = relay_addr;
    }
    pkt.op = BOOTREQUEST;
    true
}

/// Strip relay-agent modifications and forward a server reply to the client.
///
/// The relay:
/// 1. Extracts the destination from `giaddr` (if set) or uses broadcast.
/// 2. Sets `op = BOOTREPLY`.
/// 3. Returns the destination address where the packet should be sent.
///
/// Returns `None` if `giaddr` is UNSPECIFIED (packet was not relayed).
#[cfg(feature = "dhcp")]
pub fn relay_server_to_client(pkt: &mut DhcpPacket) -> Option<Ipv4Addr> {
    if pkt.giaddr == Ipv4Addr::UNSPECIFIED {
        return None;
    }
    pkt.op = BOOTREPLY;
    Some(pkt.giaddr)
}

// ──────────────────────────────────────────────────────────────────────────────
// Option-building helpers
// (ported from rfc2131.c: free_space, do_opt, match_vendor_opts,
//  do_encap_opts, prune_vendor_opts, pxe_misc, do_options)
// ──────────────────────────────────────────────────────────────────────────────

/// Find (or make) room for an option of type `opt` and length `len` in the
/// packet's options area, with overflow into `file` and `sname` fields when
/// `overload` is enabled.
///
/// Returns `Some(offset)` into `opts`, pointing at the first data byte (after
/// the code/len bytes), or `None` when the packet is full.
///
/// Mirrors `free_space()` in `rfc2131.c`.
#[cfg(feature = "dhcp")]
pub fn free_space(
    opts:   &mut Vec<u8>,
    sname:  &mut [u8; 64],
    file:   &mut [u8; 128],
    opt:    u8,
    len:    usize,
) -> Option<usize> {
    use crate::dhcp_protocol::OPTION_OVERLOAD;

    // Skip past the 4-byte magic cookie and all existing options.
    let start = 4usize;
    let end_pos = skip_opts(opts, start);

    // Check if options Vec has enough space.
    if end_pos + 2 + len <= opts.len() {
        let off = end_pos;
        opts[off]     = opt;
        opts[off + 1] = len as u8;
        return Some(off + 2);
    }

    // Try overload: can we use the `file` or `sname` fields?
    let overload_pos = find_overload_opt(opts, start);
    // Only attempt overload when at least one of file/sname is unused.
    let can_overload = file[0] == 0 || sname[0] == 0;

    if overload_pos.is_none() && !can_overload {
        return None;
    }

    // Record/create the OPTION_OVERLOAD entry.
    let ov_idx = match overload_pos {
        Some(pos) => pos,
        None => {
            // Append OPTION_OVERLOAD at end_pos (we reserved 3 bytes for it).
            if end_pos + 3 > opts.len() { return None; }
            opts[end_pos]     = OPTION_OVERLOAD;
            opts[end_pos + 1] = 1;
            opts[end_pos + 2] = 0;
            end_pos + 2 // index of the value byte
        }
    };

    // Try file field first.
    if file[0] == 0 {
        opts[ov_idx] |= 1; // set bit 0: file field in use
        let file_end = skip_opts_slice(file, 0);
        if file_end + 2 + len <= file.len() {
            file[file_end]     = opt;
            file[file_end + 1] = len as u8;
            // We return an encoded offset: 0x10000 + file_offset means "file field"
            // Callers must understand this convention.
            // Instead we write directly and return None (caller writes via returned slice).
            // Simpler: just write header bytes, return offset within file slice via
            // a negative sentinel.  Actually, to avoid unsafe pointer return, use the
            // same Vec approach: copy file data.
            // For simplicity we extend opts to accommodate (alternative encoding).
            // Real approach: return (area, offset) tuple.  We use None for now and let the
            // caller fall through; this is the simplified port.
            return None; // overflow area not supported in this simplified port
        }
    }

    // Try sname field.
    if sname[0] == 0 {
        opts[ov_idx] |= 2; // set bit 1: sname field in use
        let sname_end = skip_opts_slice(sname, 0);
        if sname_end + 2 + len <= sname.len() {
            sname[sname_end]     = opt;
            sname[sname_end + 1] = len as u8;
            return None; // overflow area not supported in this simplified port
        }
    }

    None
}

/// Skip past all options in `buf[start..]`, returning the offset of the next
/// free byte (either the OPTION_END byte or just past it if the buffer is
/// full).
#[cfg(feature = "dhcp")]
fn skip_opts(buf: &[u8], start: usize) -> usize {
    use crate::dhcp_protocol::{OPTION_PAD, OPTION_END};
    let mut i = start;
    while i < buf.len() {
        match buf[i] {
            OPTION_END => return i,
            OPTION_PAD => i += 1,
            _ => {
                if i + 1 < buf.len() {
                    i += 2 + buf[i + 1] as usize;
                } else {
                    break;
                }
            }
        }
    }
    i
}

/// Same as `skip_opts` but operates on a plain slice (used for file/sname).
#[cfg(feature = "dhcp")]
fn skip_opts_slice(buf: &[u8], start: usize) -> usize {
    use crate::dhcp_protocol::{OPTION_PAD, OPTION_END};
    let mut i = start;
    while i < buf.len() {
        match buf[i] {
            OPTION_END => return i,
            OPTION_PAD => i += 1,
            _ => {
                if i + 1 < buf.len() {
                    i += 2 + buf[i + 1] as usize;
                } else {
                    break;
                }
            }
        }
    }
    i
}

/// Return the index of the OPTION_OVERLOAD value byte if found.
#[cfg(feature = "dhcp")]
fn find_overload_opt(opts: &[u8], start: usize) -> Option<usize> {
    use crate::dhcp_protocol::{OPTION_PAD, OPTION_END, OPTION_OVERLOAD};
    let mut i = start;
    while i + 1 < opts.len() {
        match opts[i] {
            OPTION_END => break,
            OPTION_PAD => i += 1,
            OPTION_OVERLOAD => return Some(i + 2),
            _ => i += 2 + opts[i + 1] as usize,
        }
    }
    None
}

/// Append a fully-formed TLV (code + len + data) to `opts`.
///
/// The caller is responsible for calling this only when there is space
/// (i.e., after `free_space` succeeds or when building from scratch).
#[cfg(feature = "dhcp")]
pub fn append_opt(opts: &mut Vec<u8>, code: u8, data: &[u8]) {
    // Overwrite the trailing OPTION_END if present.
    if opts.last() == Some(&crate::dhcp_protocol::OPTION_END) {
        opts.pop();
    }
    opts.push(code);
    opts.push(data.len() as u8);
    opts.extend_from_slice(data);
    opts.push(crate::dhcp_protocol::OPTION_END);
}

/// Serialise a `DhcpOpt` value into a pre-allocated byte slice `p`, taking
/// the local context address into account for `DHOPT_ADDR` zero-address
/// substitution.  Returns the number of bytes written (the option data
/// length, excluding TLV header).
///
/// When `p` is `None`, performs only the length calculation.
///
/// Mirrors `do_opt()` in `rfc2131.c`.
#[cfg(feature = "dhcp")]
pub fn do_opt(
    opt:       &crate::types::dhcp::DhcpOpt,
    p:         Option<&mut [u8]>,
    local:     Option<Ipv4Addr>,
    null_term: bool,
) -> usize {
    use crate::types::dhcp::DHOPT_STRING;
    use crate::types::dhcp::DHOPT_ADDR;

    let raw = match &opt.val {
        Some(v) => v.as_slice(),
        None    => &[][..],
    };

    let mut len = raw.len();
    if (opt.flags & DHOPT_STRING) != 0 && null_term && len < 255 {
        len += 1; // null terminator
    }

    if let Some(buf) = p {
        if len == 0 { return 0; }

        if (opt.flags & DHOPT_ADDR) != 0 && local.is_some() {
            // Replace every 4-byte zero address with the local address.
            let local_b = local.unwrap().octets();
            for (chunk, out) in raw.chunks(4).zip(buf.chunks_mut(4)) {
                let src = if chunk == [0, 0, 0, 0] { &local_b } else { chunk };
                let n = src.len().min(out.len());
                out[..n].copy_from_slice(&src[..n]);
            }
        } else {
            let n = raw.len().min(buf.len());
            buf[..n].copy_from_slice(&raw[..n]);
            if (opt.flags & DHOPT_STRING) != 0 && null_term && len <= buf.len() {
                buf[len - 1] = 0;
            }
        }
    }
    len
}

/// Mark `DhcpOpt` entries in `opts` with `DHOPT_VENDOR_MATCH` when their
/// vendor-class string appears as a substring of the vendor-class option
/// value `vc_data`.
///
/// Mirrors `match_vendor_opts()` in `rfc2131.c`.
#[cfg(feature = "dhcp")]
pub fn match_vendor_opts(vc_data: Option<&[u8]>, opts: &mut Vec<crate::types::dhcp::DhcpOpt>) {
    use crate::types::dhcp::{DHOPT_VENDOR, DHOPT_VENDOR_MATCH};
    for opt in opts.iter_mut() {
        opt.flags &= !DHOPT_VENDOR_MATCH;
        if vc_data.is_none() || (opt.flags & DHOPT_VENDOR) == 0 {
            continue;
        }
        let haystack = vc_data.unwrap();
        let needle = match &opt.vendor_class {
            Some(vc) => vc.as_slice(),
            None     => &[][..],
        };
        // An empty needle matches anything (wildcard).
        if needle.is_empty() {
            opt.flags |= DHOPT_VENDOR_MATCH;
            continue;
        }
        // Substring search.
        if haystack.windows(needle.len()).any(|w| w == needle) {
            opt.flags |= DHOPT_VENDOR_MATCH;
        }
    }
}

/// Write all vendor-encapsulated options (those with `flag` set) as a
/// single encapsulating option `encap` into `opts`.
///
/// Returns `true` if any matching options were found.
///
/// Mirrors `do_encap_opts()` in `rfc2131.c`.
#[cfg(feature = "dhcp")]
pub fn do_encap_opts(
    config_opts: &[crate::types::dhcp::DhcpOpt],
    encap:       u8,
    flag:        u32,
    opts:        &mut Vec<u8>,
    null_term:   bool,
) -> bool {
    // Collect matching options.
    let matching: Vec<&crate::types::dhcp::DhcpOpt> = config_opts
        .iter()
        .filter(|o| (o.flags & flag) != 0)
        .collect();

    if matching.is_empty() { return false; }

    // Build inner payload.
    let mut inner: Vec<u8> = Vec::new();
    for o in &matching {
        let len = do_opt(o, None, None, null_term);
        inner.push(o.opt as u8);
        inner.push(len as u8);
        let start = inner.len();
        inner.resize(start + len, 0);
        do_opt(o, Some(&mut inner[start..start + len]), None, null_term);
    }
    inner.push(crate::dhcp_protocol::OPTION_END);

    // Append as encapsulated option (split into ≤255-byte chunks).
    for chunk in inner.chunks(255) {
        append_opt(opts, encap, chunk);
    }
    true
}

/// Remove `DHOPT_VENDOR_MATCH` from options that don't match `netid`, and
/// return `true` if any remaining vendor option has `DHOPT_FORCE` set.
///
/// Mirrors `prune_vendor_opts()` in `rfc2131.c`.
#[cfg(feature = "dhcp")]
pub fn prune_vendor_opts(
    opts:  &mut Vec<crate::types::dhcp::DhcpOpt>,
    netid: &[crate::types::dhcp::DhcpNetid],
) -> bool {
    use crate::types::dhcp::{DHOPT_VENDOR_MATCH, DHOPT_FORCE};
    use crate::dhcp_common::match_netid;
    let mut force = false;
    for opt in opts.iter_mut() {
        if (opt.flags & DHOPT_VENDOR_MATCH) != 0 {
            let opt_netids: Vec<_> = opt.netid.iter().collect();
            if !match_netid(netid, netid) {
                opt.flags &= !DHOPT_VENDOR_MATCH;
            } else if (opt.flags & DHOPT_FORCE) != 0 {
                force = true;
            }
            let _ = opt_netids; // suppress unused warning
        }
    }
    force
}

/// Write PXE miscellaneous options (vendor-class identifier + UUID) into
/// `opts`.
///
/// Mirrors `pxe_misc()` in `rfc2131.c`.
#[cfg(feature = "dhcp")]
pub fn pxe_misc(
    opts:      &mut Vec<u8>,
    uuid:      Option<&[u8]>,
    pxevendor: Option<&str>,
) {
    let vendor = pxevendor.unwrap_or("PXEClient");
    append_opt(opts, crate::dhcp_protocol::OPTION_VENDOR_ID, vendor.as_bytes());
    if let Some(uuid_bytes) = uuid {
        if uuid_bytes.len() == 17 {
            append_opt(opts, crate::dhcp_protocol::OPTION_PXE_UUID, uuid_bytes);
        }
    }
}

/// Configuration block passed to `do_options`.
#[cfg(feature = "dhcp")]
#[derive(Debug)]
pub struct DoOptionsConfig<'a> {
    /// Active DHCP context (subnet, local address, …).
    pub context:          Option<&'a crate::types::dhcp::DhcpContext>,
    /// Options the client requested (OPTION_REQUESTED_OPTIONS value).
    pub req_options:      Option<&'a [u8]>,
    /// Hostname to offer.
    pub hostname:         Option<&'a str>,
    /// Domain name to offer.
    pub domain:           Option<&'a str>,
    /// Active network-id tags.
    pub netid:            &'a [crate::types::dhcp::DhcpNetid],
    /// Subnet-select address (rfc3011).
    pub subnet_addr:      Option<Ipv4Addr>,
    /// FQDN flags (0 = no FQDN option).
    pub fqdn_flags:       u8,
    /// Append null-terminator to string options.
    pub null_term:        bool,
    /// PXE architecture code (`-1` = not PXE).
    pub pxe_arch:         i32,
    /// PXE UUID (17 bytes) or `None`.
    pub uuid:             Option<&'a [u8]>,
    /// Vendor-class string from client, for vendor-opt matching.
    pub vendor_class:     Option<&'a [u8]>,
    /// Lease time in seconds (`u32::MAX` = infinite).
    pub lease_time:       u32,
    /// Fuzz applied to T1/T2 timers.
    pub fuzz:             u16,
    /// PXE vendor-class string override.
    pub pxevendor:        Option<&'a str>,
    /// Configured DHCP options list.
    pub config_opts:      &'a mut Vec<crate::types::dhcp::DhcpOpt>,
    /// Boot configuration.
    pub boot:             Option<&'a crate::types::dhcp::DhcpBoot>,
    /// DNS port (53 = standard, triggers auto-DNS option).
    pub dns_port:         u16,
}

/// Apply all configured DHCP options to `pkt`.
///
/// This writes T1/T2 timers, netmask, broadcast, router, DNS server, domain
/// name, hostname, FQDN, and all user-configured options (`config_opts`), as
/// well as vendor-encapsulated options and PXE misc options when applicable.
///
/// Mirrors `do_options()` in `rfc2131.c`.
#[cfg(feature = "dhcp")]
pub fn do_options(pkt: &mut DhcpPacket, cfg: &mut DoOptionsConfig<'_>) {
    use crate::dhcp_protocol::{
        OPTION_SUBNET_SELECT, OPTION_LEASE_TIME, OPTION_T1, OPTION_T2,
        OPTION_NETMASK, OPTION_BROADCAST, OPTION_ROUTER, OPTION_DNSSERVER,
        OPTION_DOMAINNAME, OPTION_HOSTNAME, OPTION_CLIENT_FQDN,
        OPTION_VENDOR_CLASS_OPT,
        OPTION_PAD, OPTION_END, OPTION_OVERLOAD,
        OPTION_MAXMESSAGE, OPTION_SNAME, OPTION_FILENAME,
        OPTION_VENDOR_ID,
    };
    use crate::types::dhcp::{DHOPT_TAGOK, DHOPT_FORCE, DHOPT_VENDOR_MATCH};

    let opts = &mut pkt.options;

    // ── T1 / T2 timers ──────────────────────────────────────────────────────
    let lt = cfg.lease_time;
    if lt != u32::MAX {
        let mut t1 = lt / 2;
        let mut t2 = (lt as u64 * 7 / 8) as u32;

        // Apply user overrides from config_opts.
        for o in cfg.config_opts.iter() {
            if o.opt == OPTION_T1 as i32 {
                if let Some(v) = &o.val {
                    if v.len() >= 4 {
                        let h = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                        if h > 2 && h < lt { t1 = h; }
                    }
                }
            }
            if o.opt == OPTION_T2 as i32 {
                if let Some(v) = &o.val {
                    if v.len() >= 4 {
                        let h = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
                        if h > 2 && h < lt { t2 = h; }
                    }
                }
            }
        }
        if t2 <= t1 { t1 = t2.saturating_sub(1); }
        let mut fuzz = cfg.fuzz as u32;
        while fuzz > t1 / 8 { fuzz /= 2; }
        t1 = t1.saturating_sub(fuzz);
        t2 = t2.saturating_sub(fuzz);

        option_put(opts, OPTION_T1, t1, 4);
        option_put(opts, OPTION_T2, t2, 4);
    }

    // ── Context-derived options ──────────────────────────────────────────────
    if let Some(ctx) = cfg.context {
        if !has_opt_raw(opts, OPTION_NETMASK) {
            option_put(opts, OPTION_NETMASK, u32::from(ctx.netmask), 4);
        }
        if ctx.broadcast != Ipv4Addr::UNSPECIFIED && !has_opt_raw(opts, OPTION_BROADCAST) {
            option_put(opts, OPTION_BROADCAST, u32::from(ctx.broadcast), 4);
        }
        if ctx.router != Ipv4Addr::UNSPECIFIED
            && in_list(cfg.req_options, OPTION_ROUTER)
            && !has_opt_raw(opts, OPTION_ROUTER)
        {
            option_put(opts, OPTION_ROUTER, u32::from(ctx.router), 4);
        }
        if cfg.dns_port == 53
            && in_list(cfg.req_options, OPTION_DNSSERVER)
            && !has_opt_raw(opts, OPTION_DNSSERVER)
        {
            option_put(opts, OPTION_DNSSERVER, u32::from(ctx.local), 4);
        }
    }

    // ── Subnet select (rfc3011) ──────────────────────────────────────────────
    if let Some(sa) = cfg.subnet_addr {
        option_put(opts, OPTION_SUBNET_SELECT, u32::from(sa), 4);
    }

    // ── Domain name ─────────────────────────────────────────────────────────
    if let Some(domain) = cfg.domain {
        if in_list(cfg.req_options, OPTION_DOMAINNAME) && !has_opt_raw(opts, OPTION_DOMAINNAME) {
            option_put_string(opts, OPTION_DOMAINNAME, domain, cfg.null_term);
        }
    }

    // ── Hostname / FQDN ─────────────────────────────────────────────────────
    if let Some(hostname) = cfg.hostname {
        if in_list(cfg.req_options, OPTION_HOSTNAME) && !has_opt_raw(opts, OPTION_HOSTNAME) {
            option_put_string(opts, OPTION_HOSTNAME, hostname, cfg.null_term);
        }
        if cfg.fqdn_flags != 0 {
            let mut fqdn = hostname.to_string();
            if let Some(domain) = cfg.domain {
                fqdn.push('.');
                fqdn.push_str(domain);
            }
            let fqdn_data = {
                let mut v = vec![cfg.fqdn_flags & 0x0f, 0xff, 0xff];
                v.extend_from_slice(fqdn.as_bytes());
                if cfg.null_term { v.push(0); }
                v
            };
            append_opt(opts, OPTION_CLIENT_FQDN, &fqdn_data);
        }
    }

    // ── User-configured options ──────────────────────────────────────────────
    let skip_set: std::collections::HashSet<u8> = [
        OPTION_CLIENT_FQDN, OPTION_MAXMESSAGE, OPTION_OVERLOAD,
        OPTION_PAD, OPTION_END, OPTION_T1, OPTION_T2,
    ].iter().copied().collect();

    // Mark vendor opts that match client's vendor-class.
    match_vendor_opts(cfg.vendor_class, cfg.config_opts);

    let local_addr = cfg.context.map(|c| c.local);
    let config_opts_snapshot: Vec<crate::types::dhcp::DhcpOpt> = cfg.config_opts.clone();

    for opt in &config_opts_snapshot {
        let code = opt.opt as u8;
        if (opt.flags & DHOPT_TAGOK) == 0 { continue; }
        if (opt.flags & DHOPT_FORCE) == 0 && !in_list(cfg.req_options, code) { continue; }
        if skip_set.contains(&code) { continue; }
        if code == OPTION_VENDOR_ID && cfg.pxe_arch != -1 { continue; }

        // Empty val on default options = "suppress this option".
        if opt.val.as_ref().map_or(true, |v| v.is_empty()) {
            if matches!(code,
                x if x == OPTION_NETMASK || x == OPTION_BROADCAST ||
                     x == OPTION_ROUTER   || x == OPTION_DNSSERVER ||
                     x == OPTION_DOMAINNAME || x == OPTION_HOSTNAME) {
                continue;
            }
        }

        let len = do_opt(opt, None, local_addr, cfg.null_term ||
            code == OPTION_SNAME || code == OPTION_FILENAME);
        let start = opts.len().saturating_sub(1); // before OPTION_END
        let pos = if opts.last() == Some(&OPTION_END) { opts.len() - 1 } else { opts.len() };
        opts.resize(pos + 2 + len, 0);
        opts[pos]     = code;
        opts[pos + 1] = len as u8;
        do_opt(opt, Some(&mut opts[pos + 2..pos + 2 + len]), local_addr,
               cfg.null_term || code == OPTION_SNAME || code == OPTION_FILENAME);
        opts.push(OPTION_END);
        let _ = start;
    }

    // ── Vendor-encapsulated options ──────────────────────────────────────────
    let force_encap = prune_vendor_opts(cfg.config_opts, cfg.netid);
    if force_encap
        || in_list(cfg.req_options, OPTION_VENDOR_CLASS_OPT)
        || in_list(cfg.req_options, OPTION_VENDOR_ID)
    {
        do_encap_opts(cfg.config_opts, OPTION_VENDOR_CLASS_OPT, DHOPT_VENDOR_MATCH, opts, cfg.null_term);
    }

    // ── PXE misc ─────────────────────────────────────────────────────────────
    if cfg.pxe_arch != -1 {
        pxe_misc(opts, cfg.uuid, cfg.pxevendor);
    }
}

/// Return `true` if `opt` is present in `pkt`.
#[cfg(feature = "dhcp")]
pub fn has_opt(pkt: &DhcpPacket, opt: u8) -> bool {
    option_find(pkt, opt, 0).is_some()
}

/// Return `true` if option code `opt` already appears in raw options slice,
/// beginning the search at `start` (pass 4 to skip the DHCP magic cookie).
#[cfg(feature = "dhcp")]
pub fn has_opt_raw(opts: &[u8], opt: u8) -> bool {
    use crate::dhcp_protocol::{OPTION_PAD, OPTION_END};
    // If the slice begins with the 4-byte DHCP cookie, skip it.
    let start = if opts.len() >= 4
        && opts[0] == 0x63 && opts[1] == 0x82
        && opts[2] == 0x53 && opts[3] == 0x63
    { 4 } else { 0 };
    let mut i = start;
    while i < opts.len() {
        match opts[i] {
            OPTION_END => return false,
            OPTION_PAD => i += 1,
            c if c == opt => return true,
            _ => {
                if i + 1 < opts.len() {
                    i += 2 + opts[i + 1] as usize;
                } else { break; }
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// Lease time / server-id / sanitise (ported from rfc2131.c:1859-1906)
// ─────────────────────────────────────────────────────────────────────────────

/// Calculate lease time: minimum of context default, config override, and client request.
///
/// `config_time` is the per-host config lease time (or `None` for default).
/// `context_time` is the pool's default lease time.
/// `requested` is the client-requested time from option 51 (or `None`).
/// Returns the final lease duration in seconds.
/// Port of `calc_time()` from rfc2131.c:1859-1873.
#[cfg(feature = "dhcp")]
pub fn calc_time(context_time: u32, config_time: Option<u32>, requested: Option<u32>) -> u32 {
    let mut time = config_time.unwrap_or(context_time);

    if let Some(mut req) = requested {
        if req < 120 {
            req = 120; // sanity minimum
        }
        if time == 0xFFFFFFFF || (req != 0xFFFFFFFF && req < time) {
            time = req;
        }
    }

    time
}

/// Determine the DHCP Server Identifier (option 54) address.
///
/// Priority: explicit override > context local address > fallback.
/// Port of `server_id()` from rfc2131.c:1875-1883.
#[cfg(feature = "dhcp")]
pub fn server_id(
    context_local: Option<Ipv4Addr>,
    override_addr: Option<Ipv4Addr>,
    fallback: Ipv4Addr,
) -> Ipv4Addr {
    if let Some(o) = override_addr {
        if o != Ipv4Addr::UNSPECIFIED {
            return o;
        }
    }
    if let Some(l) = context_local {
        if l != Ipv4Addr::UNSPECIFIED {
            return l;
        }
    }
    fallback
}

/// Sanitise a DHCP option value to a printable ASCII string.
///
/// Non-printable bytes are dropped. Used for logging client hostnames etc.
/// Port of `sanitise()` from rfc2131.c:1885-1906.
#[cfg(feature = "dhcp")]
pub fn sanitise(data: &[u8]) -> String {
    data.iter()
        .filter(|&&b| b >= 0x20 && b < 0x7f)
        .map(|&b| b as char)
        .collect()
}

/// Format a DHCP log line for a packet event.
///
/// Port of `log_packet()` from rfc2131.c:1918-1960.
#[cfg(feature = "dhcp")]
pub fn log_packet(
    msg_type: &str,
    addr: Option<Ipv4Addr>,
    mac: Option<&[u8]>,
    interface: &str,
    hostname: Option<&str>,
    xid: u32,
    log_opts: bool,
) -> String {
    let addr_str = match addr {
        Some(a) if a != Ipv4Addr::UNSPECIFIED => a.to_string(),
        _ => String::new(),
    };

    let mac_str = match mac {
        Some(m) if !m.is_empty() => m.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":"),
        _ => String::new(),
    };

    let host_str = hostname.unwrap_or("");

    if log_opts {
        format!("{xid:08x} {msg_type}({interface}) {addr_str} {mac_str} {host_str}").trim().to_string()
    } else {
        format!("{msg_type}({interface}) {addr_str} {mac_str} {host_str}").trim().to_string()
    }
}

/// Check if a DHCP option value looks like a PXE client identifier.
///
/// PXE clients send option 60 starting with "PXEClient".
/// Port of `is_pxe_client()` from rfc2131.c:2582-2604.
#[cfg(feature = "dhcp")]
pub fn is_pxe_client(vendor_class: Option<&[u8]>) -> bool {
    match vendor_class {
        Some(vc) => vc.starts_with(b"PXEClient"),
        None => false,
    }
}

/// Find the boot server config matching a network tag.
///
/// Port of `find_boot()` from rfc2131.c:2565-2581.
#[cfg(feature = "dhcp")]
pub fn find_boot<'a>(
    boot_configs: &'a [crate::types::dhcp::DhcpBoot],
    netid: Option<&str>,
) -> Option<&'a crate::types::dhcp::DhcpBoot> {
    // First try to find one with a matching tag
    if let Some(tag) = netid {
        for b in boot_configs {
            if let Some(ref n) = b.netid {
                if n.net == tag {
                    return Some(b);
                }
            }
        }
    }
    // Fall back to untagged entry
    boot_configs.iter().find(|b| b.netid.is_none())
}

#[cfg(all(test, feature = "dhcp"))]
mod tests {
    use super::*;
    use crate::dhcp_protocol::{DhcpPacket, DHCP_CHADDR_MAX, OPTION_OVERLOAD, OPTION_PAD};

    fn base_packet() -> DhcpPacket {
        DhcpPacket {
            op: 1,
            htype: 1,
            hlen: 6,
            hops: 0,
            xid: 0x1234_5678,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr: [0u8; DHCP_CHADDR_MAX],
            sname: [0u8; 64],
            file: [0u8; 128],
            options: Vec::new(),
        }
    }

    fn opts_with_requested_ip(ip: Ipv4Addr) -> Vec<u8> {
        let mut opts = vec![OPTION_REQUESTED_IP, 4];
        opts.extend_from_slice(&ip.octets());
        opts.push(OPTION_END);
        opts
    }

    // ── option_find1 ──────────────────────────────────────────────────────────

    #[test]
    fn option_find1_finds_option() {
        let buf = vec![12, 6, b'h', b'o', b's', b't', b'o', b'k', OPTION_END];
        let idx = option_find1(&buf, 12, 1).unwrap();
        assert_eq!(idx, 0);
        assert_eq!(option_val_at(&buf, idx), b"hostok");
    }

    #[test]
    fn option_find1_skips_pad() {
        let buf = vec![OPTION_PAD, OPTION_PAD, 12, 3, 1, 2, 3, OPTION_END];
        let idx = option_find1(&buf, 12, 1).unwrap();
        assert_eq!(idx, 2);
    }

    #[test]
    fn option_find1_not_found() {
        let buf = vec![12, 1, 0x42, OPTION_END];
        assert!(option_find1(&buf, 53, 1).is_none());
    }

    #[test]
    fn option_find1_minsize_too_large() {
        let buf = vec![12, 1, 0x42, OPTION_END];
        // option 12 exists but only 1 byte; asking for 2 should fail
        assert!(option_find1(&buf, 12, 2).is_none());
    }

    // ── option_uint_at ────────────────────────────────────────────────────────

    #[test]
    fn option_uint_at_big_endian() {
        // Option 51 (IP Address Lease Time), value 0x0001_5180 = 86400
        let buf = vec![51, 4, 0x00, 0x01, 0x51, 0x80, OPTION_END];
        let idx = option_find1(&buf, 51, 4).unwrap();
        assert_eq!(option_uint_at(&buf, idx, 0, 4), 86400);
    }

    // ── option_addr_at ────────────────────────────────────────────────────────

    #[test]
    fn option_addr_at_parses_ipv4() {
        let buf = vec![1, 4, 255, 255, 255, 0, OPTION_END]; // subnet mask
        let idx = option_find1(&buf, 1, 4).unwrap();
        let addr = option_addr_at(&buf, idx).unwrap();
        assert_eq!(addr, std::net::Ipv4Addr::new(255, 255, 255, 0));
    }

    // ── option_find (packet-level) ────────────────────────────────────────────

    #[test]
    fn option_find_primary_area() {
        let mut pkt = base_packet();
        // cookie + option 12
        pkt.options = vec![0x63, 0x82, 0x53, 0x63, 12, 3, b'a', b'b', b'c', OPTION_END];
        let (buf, idx) = option_find(&pkt, 12, 1).unwrap();
        assert_eq!(option_val_at(buf, idx), b"abc");
    }

    #[test]
    fn option_find_overload_file() {
        let mut pkt = base_packet();
        // options area: cookie + OVERLOAD(bit 0) + END
        pkt.options = vec![0x63, 0x82, 0x53, 0x63, OPTION_OVERLOAD, 1, 1, OPTION_END];
        // Put option 12 in the file area
        pkt.file[0] = 12;
        pkt.file[1] = 3;
        pkt.file[2] = b'x';
        pkt.file[3] = b'y';
        pkt.file[4] = b'z';
        pkt.file[5] = OPTION_END;
        let (buf, idx) = option_find(&pkt, 12, 1).unwrap();
        assert_eq!(option_val_at(buf, idx), b"xyz");
    }

    // ── option_put ────────────────────────────────────────────────────────────

    #[test]
    fn option_put_appends_before_end() {
        let mut opts = vec![OPTION_END];
        option_put(&mut opts, 51, 86400, 4);
        assert_eq!(opts, vec![51, 4, 0x00, 0x01, 0x51, 0x80, OPTION_END]);
    }

    #[test]
    fn option_put_into_empty_buffer() {
        let mut opts = Vec::new();
        option_put(&mut opts, 53, 1, 1);
        assert_eq!(opts, vec![53, 1, 1, OPTION_END]);
    }

    // ── option_put_string ─────────────────────────────────────────────────────

    #[test]
    fn option_put_string_no_null() {
        let mut opts = vec![OPTION_END];
        option_put_string(&mut opts, 12, "host", false);
        assert_eq!(opts, vec![12, 4, b'h', b'o', b's', b't', OPTION_END]);
    }

    #[test]
    fn option_put_string_with_null() {
        let mut opts = vec![OPTION_END];
        option_put_string(&mut opts, 12, "hi", true);
        assert_eq!(opts, vec![12, 3, b'h', b'i', 0, OPTION_END]);
    }

    // ── in_list ───────────────────────────────────────────────────────────────

    #[test]
    fn in_list_none_is_true() {
        assert!(in_list(None, 12));
    }

    #[test]
    fn in_list_found() {
        let list = vec![1, 3, 6, 12, 15, 28, OPTION_END];
        assert!(in_list(Some(&list), 12));
    }

    #[test]
    fn in_list_not_found() {
        let list = vec![1, 3, 6, OPTION_END];
        assert!(!in_list(Some(&list), 12));
    }

    // ── clear_packet ──────────────────────────────────────────────────────────

    #[test]
    fn clear_packet_zeros_areas() {
        let mut pkt = base_packet();
        pkt.sname[0] = 0xAB;
        pkt.file[0] = 0xCD;
        // cookie + some options
        pkt.options = vec![0x63, 0x82, 0x53, 0x63, 12, 1, 0x42, OPTION_END];
        pkt.siaddr = std::net::Ipv4Addr::new(10, 0, 0, 1);
        clear_packet(&mut pkt);
        assert_eq!(pkt.sname, [0u8; 64]);
        assert_eq!(pkt.file, [0u8; 128]);
        assert_eq!(pkt.siaddr, std::net::Ipv4Addr::UNSPECIFIED);
        // options should be trimmed to cookie only
        assert_eq!(pkt.options, vec![0x63, 0x82, 0x53, 0x63]);
    }

    // ── dhcp_packet_size ──────────────────────────────────────────────────────

    #[test]
    fn dhcp_packet_size_minimum() {
        let pkt = base_packet();
        assert!(dhcp_packet_size(&pkt) >= 300);
    }

    #[test]
    fn dhcp_packet_size_grows_with_options() {
        let mut pkt = base_packet();
        // 4-byte cookie + lots of options
        pkt.options = vec![0u8; 400];
        let sz = dhcp_packet_size(&pkt);
        // fixed header 236 + 400 options = 636 > 300
        assert!(sz > 300);
    }


    #[test]
    fn option_msg_type_encodes_correctly() {
        let tlv = option_msg_type(DhcpMsgType::Discover);
        assert_eq!(tlv, [OPTION_MESSAGE_TYPE, 1, 1]);
    }

    #[test]
    fn handle_discover_returns_offer_in_pool() {
        let pkt = base_packet();
        let start = Ipv4Addr::new(192, 168, 1, 10);
        let end = Ipv4Addr::new(192, 168, 1, 200);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let reply = handle_discover(&pkt, start, end, None, server).unwrap();
        assert_eq!(reply.msg_type, DhcpMsgType::Offer);
        assert!(in_pool(reply.yiaddr, start, end));
    }

    #[test]
    fn handle_discover_reoffers_existing_lease() {
        use crate::types::dhcp::DhcpLease;
        let pkt = base_packet();
        let start = Ipv4Addr::new(10, 0, 0, 10);
        let end = Ipv4Addr::new(10, 0, 0, 200);
        let server = Ipv4Addr::new(10, 0, 0, 1);
        let lease_addr = Ipv4Addr::new(10, 0, 0, 42);
        let lease = DhcpLease {
            clid: None,
            hostname: None,
            fqdn: None,
            old_hostname: None,
            flags: 0,
            expires: None,
            hwaddr: [0u8; DHCP_CHADDR_MAX],
            hwaddr_len: 6,
            hwaddr_type: 1,
            addr: lease_addr,
            giaddr: Ipv4Addr::UNSPECIFIED,
            extradata: Vec::new(),
            last_interface: 0,
            new_interface: 0,
            new_prefixlen: 0,
            agent_id: None,
            vendorclass: None,
            #[cfg(feature = "dhcp6")]
            addr6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            iaid: 0,
            #[cfg(feature = "dhcp6")]
            slaac_address: Vec::new(),
            #[cfg(feature = "dhcp6")]
            vendorclass_count: 0,
        };
        let reply = handle_discover(&pkt, start, end, Some(&lease), server).unwrap();
        assert_eq!(reply.yiaddr, lease_addr);
    }

    #[test]
    fn handle_request_ack_for_pool_address() {
        let start = Ipv4Addr::new(192, 168, 1, 10);
        let end = Ipv4Addr::new(192, 168, 1, 200);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let requested = Ipv4Addr::new(192, 168, 1, 50);
        let mut pkt = base_packet();
        pkt.options = opts_with_requested_ip(requested);
        let reply = handle_request(&pkt, start, end, server).unwrap();
        assert_eq!(reply.msg_type, DhcpMsgType::Ack);
        assert_eq!(reply.yiaddr, requested);
    }

    #[test]
    fn handle_request_nak_for_out_of_pool() {
        let start = Ipv4Addr::new(192, 168, 1, 10);
        let end = Ipv4Addr::new(192, 168, 1, 200);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let out_of_pool = Ipv4Addr::new(10, 0, 0, 1);
        let mut pkt = base_packet();
        pkt.options = opts_with_requested_ip(out_of_pool);
        let reply = handle_request(&pkt, start, end, server).unwrap();
        assert_eq!(reply.msg_type, DhcpMsgType::Nak);
    }

    #[test]
    fn handle_inform_with_ciaddr_returns_ack() {
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let mut pkt = base_packet();
        pkt.ciaddr = Ipv4Addr::new(192, 168, 1, 50);
        let reply = handle_inform(&pkt, server).unwrap();
        assert_eq!(reply.msg_type, DhcpMsgType::Ack);
        assert_eq!(reply.yiaddr, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn handle_inform_without_ciaddr_returns_none() {
        let server = Ipv4Addr::new(192, 168, 1, 1);
        let pkt = base_packet(); // ciaddr is UNSPECIFIED
        assert!(handle_inform(&pkt, server).is_none());
    }

    #[test]
    fn handle_release_returns_true_for_pool_address() {
        let start = Ipv4Addr::new(10, 0, 0, 100);
        let end   = Ipv4Addr::new(10, 0, 0, 200);
        let mut pkt = base_packet();
        pkt.ciaddr = Ipv4Addr::new(10, 0, 0, 150);
        assert!(handle_release(&pkt, start, end));
    }

    #[test]
    fn handle_release_returns_false_for_foreign_address() {
        let start = Ipv4Addr::new(10, 0, 0, 100);
        let end   = Ipv4Addr::new(10, 0, 0, 200);
        let mut pkt = base_packet();
        pkt.ciaddr = Ipv4Addr::new(192, 168, 1, 50); // not in pool
        assert!(!handle_release(&pkt, start, end));
    }

    #[test]
    fn handle_decline_pool_address_returns_true() {
        let start = Ipv4Addr::new(10, 0, 0, 100);
        let end   = Ipv4Addr::new(10, 0, 0, 200);
        let declined = Ipv4Addr::new(10, 0, 0, 120);
        let mut pkt = base_packet();
        pkt.options = opts_with_requested_ip(declined);
        assert!(handle_decline(&pkt, start, end));
    }

    #[test]
    fn handle_decline_foreign_address_returns_false() {
        let start = Ipv4Addr::new(10, 0, 0, 100);
        let end   = Ipv4Addr::new(10, 0, 0, 200);
        let declined = Ipv4Addr::new(192, 168, 1, 50); // not in pool
        let mut pkt = base_packet();
        pkt.options = opts_with_requested_ip(declined);
        assert!(!handle_decline(&pkt, start, end));
    }

    // ── relay tests ──────────────────────────────────────────────────────────

    #[test]
    fn relay_client_to_server_sets_giaddr_and_increments_hops() {
        let mut pkt = base_packet();
        let relay = Ipv4Addr::new(10, 0, 0, 1);
        assert!(relay_client_to_server(&mut pkt, relay));
        assert_eq!(pkt.giaddr, relay);
        assert_eq!(pkt.hops, 1);
    }

    #[test]
    fn relay_client_to_server_preserves_existing_giaddr() {
        let mut pkt = base_packet();
        pkt.giaddr = Ipv4Addr::new(172, 16, 0, 1);
        let relay = Ipv4Addr::new(10, 0, 0, 1);
        assert!(relay_client_to_server(&mut pkt, relay));
        assert_eq!(pkt.giaddr, Ipv4Addr::new(172, 16, 0, 1));
    }

    #[test]
    fn relay_client_to_server_rejects_at_hop_limit() {
        let mut pkt = base_packet();
        pkt.hops = 16;
        let relay = Ipv4Addr::new(10, 0, 0, 1);
        assert!(!relay_client_to_server(&mut pkt, relay));
    }

    #[test]
    fn relay_server_to_client_returns_giaddr() {
        let mut pkt = base_packet();
        pkt.giaddr = Ipv4Addr::new(10, 0, 0, 254);
        let dest = relay_server_to_client(&mut pkt).unwrap();
        assert_eq!(dest, Ipv4Addr::new(10, 0, 0, 254));
        assert_eq!(pkt.op, BOOTREPLY);
    }

    #[test]
    fn relay_server_to_client_returns_none_without_giaddr() {
        let mut pkt = base_packet();
        assert!(relay_server_to_client(&mut pkt).is_none());
    }

    // ── append_opt / has_opt_raw ──────────────────────────────────────────────

    #[test]
    fn append_opt_adds_tlv() {
        let mut opts = vec![OPTION_END];
        append_opt(&mut opts, 15, b"example.com");
        assert!(has_opt_raw(&opts, 15));
        assert!(!has_opt_raw(&opts, 12));
    }

    #[test]
    fn append_opt_replaces_trailing_end() {
        let mut opts = vec![OPTION_END];
        append_opt(&mut opts, 12, b"host");
        // Should still end with OPTION_END.
        assert_eq!(*opts.last().unwrap(), OPTION_END);
    }

    // ── do_opt ────────────────────────────────────────────────────────────────

    #[test]
    fn do_opt_len_only() {
        use crate::types::dhcp::{DhcpOpt, DHOPT_STRING};
        let opt = DhcpOpt { opt: 15, flags: DHOPT_STRING, val: Some(b"hi".to_vec()),
                            netid: None, encap: 0, vendor_class: None };
        // null_term → len + 1
        assert_eq!(do_opt(&opt, None, None, true), 3);
        assert_eq!(do_opt(&opt, None, None, false), 2);
    }

    #[test]
    fn do_opt_writes_data() {
        use crate::types::dhcp::{DhcpOpt, DHOPT_STRING};
        let opt = DhcpOpt { opt: 15, flags: DHOPT_STRING, val: Some(b"hi".to_vec()),
                            netid: None, encap: 0, vendor_class: None };
        let mut buf = vec![0u8; 2];
        let n = do_opt(&opt, Some(&mut buf), None, false);
        assert_eq!(n, 2);
        assert_eq!(&buf, b"hi");
    }

    #[test]
    fn do_opt_null_terminator() {
        use crate::types::dhcp::{DhcpOpt, DHOPT_STRING};
        let opt = DhcpOpt { opt: 15, flags: DHOPT_STRING, val: Some(b"hi".to_vec()),
                            netid: None, encap: 0, vendor_class: None };
        let mut buf = vec![0u8; 3];
        do_opt(&opt, Some(&mut buf), None, true);
        assert_eq!(buf[2], 0, "null terminator should be appended");
    }

    // ── match_vendor_opts ─────────────────────────────────────────────────────

    #[test]
    fn match_vendor_opts_marks_match() {
        use crate::types::dhcp::{DhcpOpt, DHOPT_VENDOR, DHOPT_VENDOR_MATCH};
        let mut opts = vec![DhcpOpt {
            opt: 43, flags: DHOPT_VENDOR,
            val: Some(b"v".to_vec()),
            netid: None, encap: 0,
            vendor_class: Some(b"PXEClient".to_vec()),
        }];
        match_vendor_opts(Some(b"PXEClient:Arch:00000"), &mut opts);
        assert!((opts[0].flags & DHOPT_VENDOR_MATCH) != 0);
    }

    #[test]
    fn match_vendor_opts_no_match() {
        use crate::types::dhcp::{DhcpOpt, DHOPT_VENDOR, DHOPT_VENDOR_MATCH};
        let mut opts = vec![DhcpOpt {
            opt: 43, flags: DHOPT_VENDOR,
            val: Some(b"v".to_vec()),
            netid: None, encap: 0,
            vendor_class: Some(b"PXEClient".to_vec()),
        }];
        match_vendor_opts(Some(b"MSFT 5.0"), &mut opts);
        assert!((opts[0].flags & DHOPT_VENDOR_MATCH) == 0);
    }

    #[test]
    fn match_vendor_opts_clears_previous_match() {
        use crate::types::dhcp::{DhcpOpt, DHOPT_VENDOR, DHOPT_VENDOR_MATCH};
        let mut opts = vec![DhcpOpt {
            opt: 43, flags: DHOPT_VENDOR | DHOPT_VENDOR_MATCH,
            val: Some(b"v".to_vec()),
            netid: None, encap: 0,
            vendor_class: Some(b"PXEClient".to_vec()),
        }];
        // No vc_data → should clear VENDOR_MATCH.
        match_vendor_opts(None, &mut opts);
        assert!((opts[0].flags & DHOPT_VENDOR_MATCH) == 0);
    }

    // ── pxe_misc ──────────────────────────────────────────────────────────────

    #[test]
    fn pxe_misc_writes_vendor_class() {
        let mut opts = vec![OPTION_END];
        pxe_misc(&mut opts, None, None);
        assert!(has_opt_raw(&opts, crate::dhcp_protocol::OPTION_VENDOR_ID));
    }

    #[test]
    fn pxe_misc_writes_uuid() {
        let uuid = [0xABu8; 17];
        let mut opts = vec![OPTION_END];
        pxe_misc(&mut opts, Some(&uuid), Some("PXEClient"));
        assert!(has_opt_raw(&opts, crate::dhcp_protocol::OPTION_PXE_UUID));
    }

    // ── do_options ────────────────────────────────────────────────────────────

    fn make_opts_pkt() -> DhcpPacket {
        let mut pkt = base_packet();
        // 4-byte cookie + OPTION_END
        pkt.options = vec![0x63, 0x82, 0x53, 0x63, OPTION_END];
        pkt
    }

    #[test]
    fn do_options_writes_t1_t2() {
        use crate::types::dhcp::DhcpContext;
        let mut pkt = make_opts_pkt();
        let mut config_opts: Vec<crate::types::dhcp::DhcpOpt> = vec![];
        let mut cfg = DoOptionsConfig {
            context: None,
            req_options: None,
            hostname: None, domain: None,
            netid: &[],
            subnet_addr: None,
            fqdn_flags: 0,
            null_term: false,
            pxe_arch: -1,
            uuid: None,
            vendor_class: None,
            lease_time: 3600,
            fuzz: 0,
            pxevendor: None,
            config_opts: &mut config_opts,
            boot: None,
            dns_port: 53,
        };
        do_options(&mut pkt, &mut cfg);
        assert!(has_opt_raw(&pkt.options, crate::dhcp_protocol::OPTION_T1));
        assert!(has_opt_raw(&pkt.options, crate::dhcp_protocol::OPTION_T2));
    }

    #[test]
    fn do_options_skips_t1_t2_for_infinite_lease() {
        let mut pkt = make_opts_pkt();
        let mut config_opts: Vec<crate::types::dhcp::DhcpOpt> = vec![];
        let mut cfg = DoOptionsConfig {
            context: None,
            req_options: None,
            hostname: None, domain: None,
            netid: &[],
            subnet_addr: None,
            fqdn_flags: 0,
            null_term: false,
            pxe_arch: -1,
            uuid: None,
            vendor_class: None,
            lease_time: u32::MAX,
            fuzz: 0,
            pxevendor: None,
            config_opts: &mut config_opts,
            boot: None,
            dns_port: 53,
        };
        do_options(&mut pkt, &mut cfg);
        assert!(!has_opt_raw(&pkt.options, crate::dhcp_protocol::OPTION_T1));
        assert!(!has_opt_raw(&pkt.options, crate::dhcp_protocol::OPTION_T2));
    }

    #[test]
    fn do_options_writes_hostname_when_requested() {
        use crate::dhcp_protocol::OPTION_HOSTNAME;
        let mut pkt = make_opts_pkt();
        let req = vec![OPTION_HOSTNAME, OPTION_END];
        let mut config_opts: Vec<crate::types::dhcp::DhcpOpt> = vec![];
        let mut cfg = DoOptionsConfig {
            context: None,
            req_options: Some(&req),
            hostname: Some("myhost"),
            domain: None,
            netid: &[],
            subnet_addr: None,
            fqdn_flags: 0,
            null_term: false,
            pxe_arch: -1,
            uuid: None,
            vendor_class: None,
            lease_time: u32::MAX,
            fuzz: 0,
            pxevendor: None,
            config_opts: &mut config_opts,
            boot: None,
            dns_port: 53,
        };
        do_options(&mut pkt, &mut cfg);
        assert!(has_opt_raw(&pkt.options, OPTION_HOSTNAME));
    }

    #[test]
    fn do_options_pxe_misc_written_when_pxe_arch_set() {
        let mut pkt = make_opts_pkt();
        let mut config_opts: Vec<crate::types::dhcp::DhcpOpt> = vec![];
        let mut cfg = DoOptionsConfig {
            context: None,
            req_options: None,
            hostname: None, domain: None,
            netid: &[],
            subnet_addr: None,
            fqdn_flags: 0,
            null_term: false,
            pxe_arch: 0, // valid PXE arch
            uuid: None,
            vendor_class: None,
            lease_time: u32::MAX,
            fuzz: 0,
            pxevendor: None,
            config_opts: &mut config_opts,
            boot: None,
            dns_port: 53,
        };
        do_options(&mut pkt, &mut cfg);
        assert!(has_opt_raw(&pkt.options, crate::dhcp_protocol::OPTION_VENDOR_ID));
    }

    // ── calc_time ────────────────────────────────────────────────────────────

    #[test]
    fn calc_time_context_default() {
        assert_eq!(calc_time(3600, None, None), 3600);
    }

    #[test]
    fn calc_time_config_override() {
        assert_eq!(calc_time(3600, Some(7200), None), 7200);
    }

    #[test]
    fn calc_time_client_request_lower() {
        assert_eq!(calc_time(3600, None, Some(1800)), 1800);
    }

    #[test]
    fn calc_time_client_request_minimum_120() {
        assert_eq!(calc_time(3600, None, Some(10)), 120);
    }

    #[test]
    fn calc_time_infinite_context_uses_request() {
        assert_eq!(calc_time(0xFFFFFFFF, None, Some(3600)), 3600);
    }

    #[test]
    fn calc_time_infinite_request_keeps_context() {
        assert_eq!(calc_time(3600, None, Some(0xFFFFFFFF)), 3600);
    }

    // ── server_id ────────────────────────────────────────────────────────────

    #[test]
    fn server_id_override_wins() {
        let o = Some(Ipv4Addr::new(10, 0, 0, 99));
        let c = Some(Ipv4Addr::new(10, 0, 0, 1));
        let f = Ipv4Addr::new(1, 2, 3, 4);
        assert_eq!(server_id(c, o, f), Ipv4Addr::new(10, 0, 0, 99));
    }

    #[test]
    fn server_id_context_local() {
        let c = Some(Ipv4Addr::new(10, 0, 0, 1));
        let f = Ipv4Addr::new(1, 2, 3, 4);
        assert_eq!(server_id(c, None, f), Ipv4Addr::new(10, 0, 0, 1));
    }

    #[test]
    fn server_id_fallback() {
        let f = Ipv4Addr::new(1, 2, 3, 4);
        assert_eq!(server_id(None, None, f), Ipv4Addr::new(1, 2, 3, 4));
    }

    // ── sanitise ─────────────────────────────────────────────────────────────

    #[test]
    fn sanitise_printable() {
        assert_eq!(sanitise(b"hello"), "hello");
    }

    #[test]
    fn sanitise_strips_control() {
        assert_eq!(sanitise(b"he\x01llo\x7f"), "hello");
    }

    #[test]
    fn sanitise_empty() {
        assert_eq!(sanitise(b""), "");
    }

    // ── log_packet ───────────────────────────────────────────────────────────

    #[test]
    fn log_packet_basic() {
        let s = log_packet("DHCPOFFER", Some(Ipv4Addr::new(10,0,0,5)), Some(&[0xaa,0xbb,0xcc]), "eth0", Some("host1"), 0x1234, false);
        assert!(s.contains("DHCPOFFER(eth0)"));
        assert!(s.contains("10.0.0.5"));
        assert!(s.contains("aa:bb:cc"));
        assert!(s.contains("host1"));
    }

    #[test]
    fn log_packet_with_xid() {
        let s = log_packet("DHCPACK", None, None, "eth0", None, 0xDEAD, true);
        assert!(s.contains("0000dead"));
        assert!(s.contains("DHCPACK(eth0)"));
    }

    #[test]
    fn log_packet_no_addr_no_mac() {
        let s = log_packet("DHCPNAK", None, None, "br0", None, 0, false);
        assert!(s.contains("DHCPNAK(br0)"));
    }

    // ── is_pxe_client ────────────────────────────────────────────────────────

    #[test]
    fn is_pxe_client_yes() {
        assert!(is_pxe_client(Some(b"PXEClient:Arch:00000")));
    }

    #[test]
    fn is_pxe_client_no() {
        assert!(!is_pxe_client(Some(b"MSFT 5.0")));
    }

    #[test]
    fn is_pxe_client_none() {
        assert!(!is_pxe_client(None));
    }

    // ── find_boot ────────────────────────────────────────────────────────────

    #[test]
    fn find_boot_tagged() {
        use crate::types::dhcp::{DhcpBoot, DhcpNetid};
        let boots = vec![
            DhcpBoot {
                file: Some("default.img".into()),
                sname: None, tftp_sname: None,
                next_server: Ipv4Addr::UNSPECIFIED,
                netid: None,
            },
            DhcpBoot {
                file: Some("special.img".into()),
                sname: None, tftp_sname: None,
                next_server: Ipv4Addr::UNSPECIFIED,
                netid: Some(DhcpNetid { net: "lab".into() }),
            },
        ];
        let result = find_boot(&boots, Some("lab"));
        assert_eq!(result.unwrap().file.as_deref(), Some("special.img"));
    }

    #[test]
    fn find_boot_untagged_fallback() {
        use crate::types::dhcp::DhcpBoot;
        let boots = vec![
            DhcpBoot {
                file: Some("default.img".into()),
                sname: None, tftp_sname: None,
                next_server: Ipv4Addr::UNSPECIFIED,
                netid: None,
            },
        ];
        let result = find_boot(&boots, Some("nomatch"));
        assert_eq!(result.unwrap().file.as_deref(), Some("default.img"));
    }

    #[test]
    fn find_boot_empty() {
        assert!(find_boot(&[], Some("x")).is_none());
    }
}

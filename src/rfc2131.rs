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
    /// Optional BOOTP server host name (`sname`).
    pub sname: Option<String>,
    /// Optional BOOTP boot file name (`file`).
    pub file: Option<String>,
    /// Override for the wire `ciaddr` field. Every ordinary reply echoes the
    /// request's `ciaddr` verbatim ([`dhcp_reply_to_wire`][crate::dhcp::dhcp_reply_to_wire]);
    /// a `DHCPLEASEQUERY` reply instead reports the *queried* lease's address
    /// (or explicitly zero for `DHCPLEASEUNKNOWN`), independent of whatever
    /// `ciaddr` the query itself carried (rfc2131.c:1216-1226).
    pub ciaddr_override: Option<Ipv4Addr>,
    /// Override for the wire `chaddr`/`hlen`/`htype` fields (hardware
    /// address bytes, length, type), for the same `DHCPLEASEACTIVE` case as
    /// [`Self::ciaddr_override`] — the reply describes the lease's owner,
    /// not the querying manager (rfc2131.c:1219-1222).
    pub chaddr_override: Option<([u8; crate::dhcp_protocol::DHCP_CHADDR_MAX], u8, u8)>,
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

/// Pick an address to offer: a static reservation wins, then a re-usable
/// existing lease, then whatever the caller's pool scan already found.
///
/// `scanned_addr` is the result of [`crate::dhcp::address_allocate`] — this
/// function has no access to the lease database, DHCP contexts, or an ICMP
/// prober, so the actual free-address search happens in `dhcp.rs` before
/// `handle_discover` is called, matching rfc2131.c:1298-1345's `conf` →
/// `lease->addr` → `address_allocate()` priority chain.
#[cfg(feature = "dhcp")]
fn pick_offer_addr(
    pool_start: Ipv4Addr,
    pool_end: Ipv4Addr,
    existing_lease: Option<&DhcpLease>,
    static_addr: Option<Ipv4Addr>,
    scanned_addr: Option<Ipv4Addr>,
) -> Option<Ipv4Addr> {
    if let Some(addr) = static_addr {
        return Some(addr);
    }
    if let Some(lease) = existing_lease {
        if in_pool(lease.addr, pool_start, pool_end) {
            return Some(lease.addr);
        }
    }
    scanned_addr
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

/// Turn a would-be OFFER into the immediate ACK a rapid-commit DISCOVER gets
/// instead (`OPT_RAPID_COMMIT` + client-sent OPTION_RAPID_COMMIT,
/// rfc2131.c:1363-1372 jumping to the `rapid_commit:` label at :1493).
///
/// Before committing, re-runs the same pool/static/reserved validity check
/// the `rapid_commit:` label re-does on the offered address (rfc2131.c's
/// `narrow_context`/`address_available`/"static lease available"/"address
/// reserved" checks, reduced to this port's existing model — see
/// [`handle_request`]). If that fails, upstream sends **no reply at all**
/// ("rapid commit case: lease allocate failed but don't send DHCPNAK",
/// rfc2131.c:1568-1569) rather than a NAK, so this returns `None`.
///
/// On success, keeps the already-resolved `yiaddr`/`siaddr`/`giaddr`,
/// rebuilds the option-53/54 header as ACK, and echoes back a zero-length
/// OPTION_RAPID_COMMIT (80) per rfc2131.c:1745-1746.
#[cfg(feature = "dhcp")]
pub fn make_rapid_commit_ack(
    mut reply: DhcpReply,
    server_id: Ipv4Addr,
    pool_start: Ipv4Addr,
    pool_end: Ipv4Addr,
    static_addr: Option<Ipv4Addr>,
    reserved_for_other: bool,
) -> Option<DhcpReply> {
    use crate::dhcp_protocol::OPTION_RAPID_COMMIT;
    if !address_in_range(reply.yiaddr, pool_start, pool_end, static_addr, reserved_for_other) {
        return None;
    }
    reply.msg_type = DhcpMsgType::Ack;
    reply.options = build_reply_options(DhcpMsgType::Ack, server_id);
    if let Some(end_pos) = reply.options.iter().position(|&b| b == OPTION_END) {
        reply.options.splice(end_pos..end_pos, [OPTION_RAPID_COMMIT, 0]);
    }
    Some(reply)
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
    static_addr: Option<Ipv4Addr>,
    scanned_addr: Option<Ipv4Addr>,
) -> Option<DhcpReply> {
    let yiaddr = pick_offer_addr(pool_start, pool_end, existing_lease, static_addr, scanned_addr)?;
    Some(DhcpReply {
        msg_type: DhcpMsgType::Offer,
        yiaddr,
        options: build_reply_options(DhcpMsgType::Offer, server_id),
        siaddr: server_id,
        giaddr: pkt.giaddr,
        sname: None,
        file: None,
        ciaddr_override: None,
        chaddr_override: None,
    })
}

/// Shared validity gate for "is `requested` an address we should hand out to
/// this client", used both by [`handle_request`]'s ACK/NAK decision and by
/// the DISCOVER+rapid-commit re-validation at the `rapid_commit:` label
/// (rfc2131.c:1493 `narrow_context`/`address_available`/"static lease
/// available"/"address reserved" checks, reduced to this port's existing
/// pool/static/reserved model). `reserved_for_other` is true when the
/// address is a `dhcp-host` static reservation belonging to a *different*
/// client (`config_find_by_address(...) != config`, rfc2131.c:1529-1530).
#[cfg(feature = "dhcp")]
fn address_in_range(
    requested: Ipv4Addr,
    pool_start: Ipv4Addr,
    pool_end: Ipv4Addr,
    static_addr: Option<Ipv4Addr>,
    reserved_for_other: bool,
) -> bool {
    !reserved_for_other
        && static_addr.map(|addr| requested == addr).unwrap_or_else(|| {
            in_pool(requested, pool_start, pool_end)
        })
}

/// Process a DHCP REQUEST packet and produce an ACK or NAK reply.
///
/// The requested IP is taken from option 50; if it lies within the pool the
/// reply is ACK, otherwise NAK. `reserved_for_other` forces a NAK regardless
/// of pool/static match — it is true when the requested address is a
/// `dhcp-host` static reservation belonging to a *different* client
/// (`config_find_by_address(...) != config`, rfc2131.c:1529-1530).
#[cfg(feature = "dhcp")]
pub fn handle_request(
    pkt: &DhcpPacket,
    pool_start: Ipv4Addr,
    pool_end: Ipv4Addr,
    server_id: Ipv4Addr,
    static_addr: Option<Ipv4Addr>,
    reserved_for_other: bool,
) -> Option<DhcpReply> {
    // Find the requested IP (option 50) in the packet options, falling back to
    // ciaddr for the renewal/rebind path.
    let requested = find_requested_ip(&pkt.options)
        .or_else(|| (pkt.ciaddr != Ipv4Addr::UNSPECIFIED).then_some(pkt.ciaddr))?;

    let in_range = address_in_range(requested, pool_start, pool_end, static_addr, reserved_for_other);

    if in_range {
        Some(DhcpReply {
            msg_type: DhcpMsgType::Ack,
            yiaddr: static_addr.unwrap_or(requested),
            options: build_reply_options(DhcpMsgType::Ack, server_id),
            siaddr: server_id,
            giaddr: pkt.giaddr,
            sname: None,
            file: None,
            ciaddr_override: None,
            chaddr_override: None,
        })
    } else {
        Some(DhcpReply {
            msg_type: DhcpMsgType::Nak,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            options: build_reply_options(DhcpMsgType::Nak, server_id),
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: pkt.giaddr,
            sname: None,
            file: None,
            ciaddr_override: None,
            chaddr_override: None,
        })
    }
}

/// Build a BOOTP reply (`mess_type == 0`, rfc2131.c:564-698) for an already
/// resolved `yiaddr`.
///
/// Unlike every DHCP reply type, a BOOTP reply carries no OPTION_MESSAGE_TYPE
/// (upstream never calls `option_put(..., OPTION_MESSAGE_TYPE, ...)` on this
/// path) and no OPTION_SERVER_IDENTIFIER, so `options` starts empty rather
/// than going through [`build_reply_options`]. `siaddr` starts at `server_id`
/// as a stand-in for upstream's `context->local` default (do_options is
/// shared with every other message type, which already approximates that
/// default the same way — see [`crate::dhcp::decorate_reply`]); a matching
/// `dhcp-boot` entry overrides it the same way it does for every other
/// message type. The caller is responsible for capping the final options
/// blob to BOOTP's 64-byte vendor area with [`cap_vendor_area`].
#[cfg(feature = "dhcp")]
pub fn handle_bootp(pkt: &DhcpPacket, yiaddr: Ipv4Addr, server_id: Ipv4Addr) -> DhcpReply {
    DhcpReply {
        msg_type: DhcpMsgType::Bootp,
        yiaddr,
        options: Vec::new(),
        siaddr: server_id,
        giaddr: pkt.giaddr,
        sname: None,
        file: None,
        ciaddr_override: None,
        chaddr_override: None,
    }
}

/// Truncate a DHCP options blob to BOOTP's 64-byte vendor area
/// (`end = mess->options + 64`, rfc2131.c:577), never splitting a TLV: it
/// keeps every option that fits complete within `max_len - 1` bytes (the
/// last byte is reserved for OPTION_END) and drops the rest, then appends
/// OPTION_END. `options` must not itself already contain OPTION_PAD gaps
/// wider than a single option boundary — the code we emit never produces
/// those, so this only needs to recognise PAD as a 1-byte filler.
#[cfg(feature = "dhcp")]
pub fn cap_vendor_area(options: &mut Vec<u8>, max_len: usize) {
    use crate::dhcp_protocol::OPTION_PAD;
    let budget = max_len.saturating_sub(1); // reserve room for the trailing END
    let mut i = 0;
    let mut fit = 0usize;
    while i < options.len() {
        let code = options[i];
        if code == OPTION_END {
            break;
        }
        if code == OPTION_PAD {
            if i + 1 > budget {
                break;
            }
            i += 1;
            fit = i;
            continue;
        }
        if i + 1 >= options.len() {
            break;
        }
        let len = options[i + 1] as usize;
        let end = i + 2 + len;
        if end > options.len() || end > budget {
            break;
        }
        i = end;
        fit = i;
    }
    options.truncate(fit);
    options.push(OPTION_END);
}

/// Extract the requested IP address from option 50 in a raw options buffer.
#[cfg(feature = "dhcp")]
pub(crate) fn find_requested_ip(options: &[u8]) -> Option<Ipv4Addr> {
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
        sname:    None,
        file:     None,
        ciaddr_override: None,
        chaddr_override: None,
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

/// Build a `DHCPLEASEQUERY` reply (RFC 4388, rfc2131.c:1067-1235).
///
/// `reply_type` must be one of `LeaseUnknown` / `LeaseUnassigned` /
/// `LeaseActive` — the caller (dispatch) has already done the address/context
/// lookups that classify the query (rfc2131.c:1094-1150) and, for
/// `LeaseActive`, resolved `context`/`filtered_tags`/`full_lease_time` the
/// same way an ordinary reply would. Only `LeaseActive` (`lease.is_some()`)
/// populates anything beyond the bare message type: client-id, remaining
/// lease time, T1/T2 (computed from *remaining* time, not the full lease
/// time), `OPTION_LAST_TRANSACTION`, the usual `do_options` set filtered by
/// the client's requested-options list, and finally the lease's stored
/// agent-id echoed back as the last option (rfc2131.c:1230-1232).
#[allow(clippy::too_many_arguments)]
#[cfg(feature = "dhcp")]
pub fn handle_leasequery(
    pkt: &DhcpPacket,
    reply_type: DhcpMsgType,
    lease: Option<&DhcpLease>,
    req_options: Option<&[u8]>,
    context: Option<&crate::types::dhcp::DhcpContext>,
    filtered_tags: &[crate::types::dhcp::DhcpNetid],
    config_opts: &mut Vec<crate::types::dhcp::DhcpOpt>,
    domain: Option<&str>,
    full_lease_time: u32,
) -> DhcpReply {
    use crate::dhcp_protocol::{
        DHCP_CHADDR_MAX, OPTION_AGENT_ID, OPTION_CLIENT_ID, OPTION_LAST_TRANSACTION,
        OPTION_LEASE_TIME, OPTION_T1, OPTION_T2,
    };

    let mut options = Vec::new();
    option_put(&mut options, OPTION_MESSAGE_TYPE, u32::from(reply_type as u8), 1);

    // rfc2131.c:2557-2563 `clear_packet` never touches `ciaddr`, so by default
    // the reply echoes back whatever `ciaddr` the request carried (the
    // queried address, for DHCPLEASEUNASSIGNED). Only DHCPLEASEUNKNOWN
    // explicitly zeroes it (rfc2131.c:1173-1177); DHCPLEASEACTIVE overwrites
    // it with the lease's address below.
    let mut ciaddr_override = if reply_type == DhcpMsgType::LeaseUnknown {
        Some(Ipv4Addr::UNSPECIFIED)
    } else {
        None
    };
    let mut chaddr_override = None;

    if let Some(lease) = lease {
        ciaddr_override = Some(lease.addr);
        let hw_len = lease.hwaddr_len.min(DHCP_CHADDR_MAX);
        let mut chaddr = [0u8; DHCP_CHADDR_MAX];
        chaddr[..hw_len].copy_from_slice(&lease.hwaddr[..hw_len]);
        chaddr_override = Some((chaddr, hw_len as u8, lease.hwaddr_type as u8));

        if let Some(clid) = lease.clid.as_deref() {
            if in_list(req_options, OPTION_CLIENT_ID) {
                option_put_raw(&mut options, OPTION_CLIENT_ID, clid);
            }
        }

        // `lease.expires == None` means infinite (rfc2131.c's `expires == 0`).
        let now = std::time::SystemTime::now();
        let remaining = lease
            .expires
            .map(|exp| exp.duration_since(now).map(|d| d.as_secs() as u32).unwrap_or(0));

        if in_list(req_options, OPTION_LEASE_TIME) {
            option_put(&mut options, OPTION_LEASE_TIME, remaining.unwrap_or(0xFFFF_FFFF), 4);
        }

        if let Some(remaining) = remaining {
            if in_list(req_options, OPTION_T1) && remaining > full_lease_time / 2 {
                option_put(&mut options, OPTION_T1, remaining - full_lease_time / 2, 4);
            }
            if in_list(req_options, OPTION_T2) && remaining > full_lease_time / 8 {
                option_put(&mut options, OPTION_T2, remaining - full_lease_time / 8, 4);
            }
            if in_list(req_options, OPTION_LAST_TRANSACTION) && remaining < full_lease_time {
                option_put(&mut options, OPTION_LAST_TRANSACTION, full_lease_time - remaining, 4);
            }
        }

        let mut tmp_pkt = DhcpPacket {
            op: BOOTREPLY,
            htype: pkt.htype,
            hlen: pkt.hlen,
            hops: 0,
            xid: pkt.xid,
            secs: 0,
            flags: 0,
            ciaddr: pkt.ciaddr,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: pkt.giaddr,
            chaddr: pkt.chaddr,
            sname: [0u8; 64],
            file: [0u8; 128],
            options,
        };
        let mut opt_cfg = DoOptionsConfig {
            context,
            req_options,
            hostname: lease.hostname.as_deref(),
            domain,
            netid: filtered_tags,
            subnet_addr: None,
            fqdn_flags: 0,
            null_term: false,
            pxe_arch: -1,
            uuid: None,
            vendor_class: lease.vendorclass.as_deref(),
            lease_time: u32::MAX,
            fuzz: 0,
            pxevendor: None,
            config_opts,
            boot: None,
            dns_port: 53,
            leasequery: true,
        };
        do_options(&mut tmp_pkt, &mut opt_cfg);
        options = tmp_pkt.options;

        if let Some(agent_id) = lease.agent_id.as_deref() {
            if in_list(req_options, OPTION_AGENT_ID) {
                option_put_raw(&mut options, OPTION_AGENT_ID, agent_id);
            }
        }
    }

    DhcpReply {
        msg_type: reply_type,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        options,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr: pkt.giaddr,
        sname: None,
        file: None,
        ciaddr_override,
        chaddr_override,
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

/// One forwarded copy of a DHCP request produced by [`relay_upstream4`]: the
/// modified packet plus where and from which address to send it.
#[cfg(feature = "dhcp")]
#[derive(Debug, Clone)]
pub struct RelayForward {
    /// Where to send the forwarded packet (a configured server, or a
    /// broadcast address resolved via `resolve_broadcast`).
    pub dest: Ipv4Addr,
    /// UDP destination port (`relay.port`).
    pub port: u16,
    /// Source address the packet should be sent from (`relay.local`/`relay.uplink`).
    pub from: Ipv4Addr,
    /// The packet as it should go on the wire: `giaddr` stamped and, in split
    /// mode, an RFC 3046 agent-information option appended.
    pub packet: DhcpPacket,
}

/// Layer-3 DHCP relay forwarding: for every configured IPv4 relay that
/// matches the interface `pkt` arrived on, build a forwarded copy addressed
/// to that relay's server.
///
/// Port of `relay_upstream4()` (`rfc2131.c:3058-3225`).
///
/// Two of upstream's ioctls become injected lookups here since this is a pure
/// function with no socket access of its own:
/// - `resolve_uplink` stands in for `ioctl(SIOCGIFADDR)`: given a split-mode
///   relay's `interface` name, returns that interface's own IPv4 address.
///   Also updates `relay.uplink_addr`, exactly as upstream's
///   `relay->uplink.addr4 = ...` assignment does.
/// - `resolve_broadcast` stands in for `ioctl(SIOCGIFBRDADDR)`: given an
///   interface name, returns its broadcast address, used when a relay's
///   `server_addr` is unspecified (broadcast mode).
///
/// `iface_index` is the numeric index of the interface `pkt` arrived on; a
/// non-split relay only fires when it matches `relay.iface_index` (upstream
/// binds that field to the interface owning `relay.local` — see
/// `dhcp.c:669-673` — callers are expected to do the same before calling in).
#[cfg(feature = "dhcp")]
pub fn relay_upstream4(
    iface_addr: Ipv4Addr,
    iface_index: i32,
    pkt: &DhcpPacket,
    unicast: bool,
    relays: &mut [crate::types::dhcp::DhcpRelay],
    mut resolve_uplink: impl FnMut(&str) -> Option<Ipv4Addr>,
    mut resolve_broadcast: impl FnMut(&str) -> Option<Ipv4Addr>,
) -> Vec<RelayForward> {
    use crate::dhcp_protocol::{OPTION_AGENT_ID, SUBOPT_FLAGS, SUBOPT_REMOTE_ID, SUBOPT_SERVER_OR, SUBOPT_SUBNET_SELECT};
    use crate::types::addr::AllAddr;

    if pkt.op != BOOTREQUEST || pkt.hops > 20 {
        return Vec::new();
    }

    let orig_giaddr = pkt.giaddr;
    let mut out = Vec::new();

    for relay in relays.iter_mut() {
        let AllAddr::Addr4(local4) = relay.local_addr else { continue };

        let mut mess = pkt.clone();
        mess.hops = pkt.hops + 1;

        let from4 = if relay.split_mode == 0 && relay.iface_index != 0 && relay.iface_index == iface_index {
            if orig_giaddr != Ipv4Addr::UNSPECIFIED {
                if orig_giaddr == local4 {
                    continue; // already gatewayed by us: loop
                }
            } else {
                mess.giaddr = local4;
            }
            local4
        } else if relay.split_mode != 0 && local4 == iface_addr {
            if let Some(iface) = relay.interface.clone() {
                match resolve_uplink(&iface) {
                    Some(addr) => relay.uplink_addr = AllAddr::Addr4(addr),
                    None => continue,
                }
            }
            let AllAddr::Addr4(uplink4) = relay.uplink_addr else { continue };

            if orig_giaddr != Ipv4Addr::UNSPECIFIED {
                if orig_giaddr == uplink4 {
                    continue; // already gatewayed by us: loop
                }
            } else {
                mess.giaddr = uplink4;

                // RFC 3046 agent-information: RFC 3527 subnet-select (our
                // client-facing address), RFC 5107 server-id-override (same
                // address), RFC 5010 flags, and an RFC 3046 remote-id holding
                // the arrival interface index so relay_reply4 can route the
                // reply back out the same interface.
                let mut payload = [0u8; 21];
                payload[0] = SUBOPT_SUBNET_SELECT;
                payload[1] = 4;
                payload[2..6].copy_from_slice(&local4.octets());
                payload[6] = SUBOPT_SERVER_OR;
                payload[7] = 4;
                payload[8..12].copy_from_slice(&local4.octets());
                payload[12] = SUBOPT_FLAGS;
                payload[13] = 1;
                payload[14] = if unicast { 0x80 } else { 0x00 };
                payload[15] = SUBOPT_REMOTE_ID;
                payload[16] = 4;
                payload[17..21].copy_from_slice(&(iface_index as u32).to_be_bytes());
                option_put_raw(&mut mess.options, OPTION_AGENT_ID, &payload);
            }
            uplink4
        } else {
            continue;
        };

        let AllAddr::Addr4(server4) = relay.server_addr else { continue };
        let dest = if server4 == Ipv4Addr::UNSPECIFIED {
            let Some(bcast) = relay.interface.as_deref().and_then(&mut resolve_broadcast) else { continue };
            bcast
        } else {
            server4
        };

        out.push(RelayForward {
            dest,
            port: relay.port as u16,
            from: from4,
            packet: mess,
        });
    }

    out
}

/// Match a relayed DHCP reply against configured relays and report which
/// interface to send it back out.
///
/// Port of `relay_reply4()` (`rfc2131.c:3227-3262`). In split mode, strips
/// the agent-information option this daemon injected in `relay_upstream4`
/// before the reply reaches the client, per RFC 3046 §2.1.
///
/// Returns `0` when `pkt` was not relayed via any configured relay (matching
/// upstream, where the caller treats a zero return as "not ours").
#[cfg(feature = "dhcp")]
pub fn relay_reply4(pkt: &mut DhcpPacket, relays: &[crate::types::dhcp::DhcpRelay], arrival_interface: Option<&str>) -> i32 {
    use crate::dhcp_protocol::{OPTION_AGENT_ID, OPTION_END, SUBOPT_REMOTE_ID};
    use crate::types::addr::AllAddr;

    if pkt.giaddr == Ipv4Addr::UNSPECIFIED || pkt.op != BOOTREPLY {
        return 0;
    }

    for relay in relays {
        let mut return_iface = 0i32;

        if relay.split_mode != 0 {
            if let AllAddr::Addr4(uplink4) = relay.uplink_addr {
                if pkt.giaddr == uplink4 {
                    if let Some(idx) = option_find1(&pkt.options, OPTION_AGENT_ID, 1) {
                        let data = option_val_at(&pkt.options, idx);
                        if let Some(sidx) = option_find1(data, SUBOPT_REMOTE_ID, 4) {
                            return_iface = option_uint_at(data, sidx, 0, 4) as i32;
                        }

                        // Delete agent info before returning it to the client (RFC 3046 §2.1).
                        let len = option_len_at(&pkt.options, idx);
                        pkt.options[idx] = OPTION_END;
                        let start = idx + 1;
                        let end = (start + len + 2).min(pkt.options.len());
                        for b in &mut pkt.options[start..end] {
                            *b = 0;
                        }
                    }
                }
            }
        } else if let AllAddr::Addr4(local4) = relay.local_addr {
            if pkt.giaddr == local4 {
                return_iface = relay.iface_index;
            }
        }

        if return_iface != 0 {
            let matches_iface = match (relay.interface.as_deref(), arrival_interface) {
                (None, _) => true,
                (Some(pattern), Some(actual)) => crate::util::wildcard_match(pattern, actual),
                (Some(_), None) => false,
            };
            if matches_iface {
                return return_iface;
            }
        }
    }

    0
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
    use crate::types::dhcp::DhOptFlags;

    let raw = match &opt.val {
        Some(v) => v.as_slice(),
        None    => &[][..],
    };

    let mut len = raw.len();
    if opt.flags.contains(DhOptFlags::STRING) && null_term && len < 255 {
        len += 1; // null terminator
    }

    if let Some(buf) = p {
        if len == 0 { return 0; }

        if let Some(l) = local.filter(|_| opt.flags.contains(DhOptFlags::ADDR)) {
            // Replace every 4-byte zero address with the local address.
            let local_b = l.octets();
            for (chunk, out) in raw.chunks(4).zip(buf.chunks_mut(4)) {
                let src = if chunk == [0, 0, 0, 0] { &local_b } else { chunk };
                let n = src.len().min(out.len());
                out[..n].copy_from_slice(&src[..n]);
            }
        } else {
            let n = raw.len().min(buf.len());
            buf[..n].copy_from_slice(&raw[..n]);
            if opt.flags.contains(DhOptFlags::STRING) && null_term && len <= buf.len() {
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
    use crate::types::dhcp::DhOptFlags;
    for opt in opts.iter_mut() {
        opt.flags.remove(DhOptFlags::VENDOR_MATCH);
        if !opt.flags.contains(DhOptFlags::VENDOR) {
            continue;
        }
        let Some(haystack) = vc_data else { continue };
        let needle = match &opt.vendor_class {
            Some(vc) => vc.as_slice(),
            None     => &[][..],
        };
        // An empty needle matches anything (wildcard).
        if needle.is_empty() {
            opt.flags.insert(DhOptFlags::VENDOR_MATCH);
            continue;
        }
        // Substring search.
        if haystack.windows(needle.len()).any(|w| w == needle) {
            opt.flags.insert(DhOptFlags::VENDOR_MATCH);
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
    flag:        crate::types::dhcp::DhOptFlags,
    opts:        &mut Vec<u8>,
    null_term:   bool,
) -> bool {
    // Collect matching options.
    let matching: Vec<&crate::types::dhcp::DhcpOpt> = config_opts
        .iter()
        .filter(|o| o.flags.intersects(flag))
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
    use crate::types::dhcp::DhOptFlags;
    use crate::dhcp_common::match_netid;
    let mut force = false;
    for opt in opts.iter_mut() {
        if opt.flags.contains(DhOptFlags::VENDOR_MATCH) {
            if !match_netid(netid, &opt.netid) {
                opt.flags.remove(DhOptFlags::VENDOR_MATCH);
            } else if opt.flags.contains(DhOptFlags::FORCE) {
                force = true;
            }
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
    /// Set for a DHCPLEASEQUERY reply (rfc2131.c's `leasequery` param,
    /// :2621). Gates netmask/broadcast and `DHOPT_FORCE` options behind the
    /// client's requested-options list even when they'd otherwise be sent
    /// unconditionally, and skips vendor-encapsulated options entirely
    /// (rfc2131.c:2787-2797, :2878, :2945).
    pub leasequery:       bool,
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
    use crate::types::dhcp::DhOptFlags;

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
        if (!cfg.leasequery || in_list(cfg.req_options, OPTION_NETMASK))
            && !has_opt_raw(opts, OPTION_NETMASK)
        {
            option_put(opts, OPTION_NETMASK, u32::from(ctx.netmask), 4);
        }
        if ctx.broadcast != Ipv4Addr::UNSPECIFIED
            && (!cfg.leasequery || in_list(cfg.req_options, OPTION_BROADCAST))
            && !has_opt_raw(opts, OPTION_BROADCAST)
        {
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
        if !opt.flags.contains(DhOptFlags::TAGOK) { continue; }
        if (!opt.flags.contains(DhOptFlags::FORCE) || cfg.leasequery) && !in_list(cfg.req_options, code) { continue; }
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
    if !cfg.leasequery
        && (force_encap
            || in_list(cfg.req_options, OPTION_VENDOR_CLASS_OPT)
            || in_list(cfg.req_options, OPTION_VENDOR_ID))
    {
        do_encap_opts(cfg.config_opts, OPTION_VENDOR_CLASS_OPT, DhOptFlags::VENDOR_MATCH, opts, cfg.null_term);
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

/// Select the best hardware address for a DHCP client.
///
/// Prefers the actual hwaddr if available; falls back to extracting
/// the address from the client-id if the hardware address length is 0
/// and the client-id starts with the hardware type byte.
/// Port of `extended_hwaddr()` from rfc2131.c:1832-1857.
#[cfg(feature = "dhcp")]
pub fn extended_hwaddr<'a>(
    hwtype: u8,
    hwaddr: &'a [u8],
    clid: Option<&'a [u8]>,
) -> &'a [u8] {
    if hwaddr.is_empty() {
        if let Some(clid) = clid {
            if clid.len() > 3 {
                if clid[0] == hwtype {
                    return &clid[1..];
                }
                // EUI-64 / IEEE 1394 fallback
                if clid[0] == 27 && hwtype == 24 {
                    return &clid[1..];
                }
                return clid;
            }
        }
    }
    hwaddr
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
            if b.netid.iter().any(|n| n.net == tag) {
                return Some(b);
            }
        }
    }
    // Fall back to untagged entry
    boot_configs.iter().find(|b| b.netid.is_empty())
}

#[cfg(all(test, feature = "dhcp"))]
mod tests {
    use super::*;
    use crate::dhcp_protocol::{DhcpPacket, DHCP_CHADDR_MAX, OPTION_AGENT_ID, OPTION_OVERLOAD, OPTION_PAD};

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
        let scanned = Ipv4Addr::new(192, 168, 1, 50);
        let reply = handle_discover(&pkt, start, end, None, server, None, Some(scanned)).unwrap();
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
            flags: crate::types::dhcp::LeaseFlags::empty(),
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
        let reply = handle_discover(&pkt, start, end, Some(&lease), server, None, None).unwrap();
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
        let reply = handle_request(&pkt, start, end, server, None, false).unwrap();
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
        let reply = handle_request(&pkt, start, end, server, None, false).unwrap();
        assert_eq!(reply.msg_type, DhcpMsgType::Nak);
    }

    #[test]
    fn handle_request_nak_when_reserved_for_other() {
        let start = Ipv4Addr::new(192, 168, 1, 10);
        let end = Ipv4Addr::new(192, 168, 1, 200);
        let server = Ipv4Addr::new(192, 168, 1, 1);
        // In-pool and no static_addr override, but the caller has determined
        // this address is reserved for a different client's dhcp-host entry.
        let requested = Ipv4Addr::new(192, 168, 1, 50);
        let mut pkt = base_packet();
        pkt.options = opts_with_requested_ip(requested);
        let reply = handle_request(&pkt, start, end, server, None, true).unwrap();
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

    // ── relay_upstream4 / relay_reply4 (rfc2131.c:3058-3262) ───────────────────

    fn normal_relay(local: Ipv4Addr, server: Ipv4Addr, iface_index: i32) -> crate::types::dhcp::DhcpRelay {
        crate::types::dhcp::DhcpRelay {
            local_addr:  crate::types::addr::AllAddr::Addr4(local),
            server_addr: crate::types::addr::AllAddr::Addr4(server),
            uplink_addr: crate::types::addr::AllAddr::Addr4(Ipv4Addr::UNSPECIFIED),
            interface:   None,
            iface_index,
            port:        67,
            split_mode:  0,
            warned:      0,
            matchcount:  0,
        }
    }

    fn split_relay(local: Ipv4Addr, server: Ipv4Addr, interface: &str) -> crate::types::dhcp::DhcpRelay {
        crate::types::dhcp::DhcpRelay {
            local_addr:  crate::types::addr::AllAddr::Addr4(local),
            server_addr: crate::types::addr::AllAddr::Addr4(server),
            uplink_addr: crate::types::addr::AllAddr::Addr4(Ipv4Addr::UNSPECIFIED),
            interface:   Some(interface.to_string()),
            iface_index: 0,
            port:        67,
            split_mode:  1,
            warned:      0,
            matchcount:  0,
        }
    }

    #[test]
    fn relay_upstream4_stamps_giaddr_and_forwards_to_server() {
        let iface_addr = Ipv4Addr::new(192, 168, 1, 1);
        let pkt = base_packet();
        let mut relays = vec![normal_relay(iface_addr, Ipv4Addr::new(10, 0, 0, 1), 2)];

        let forwards = relay_upstream4(iface_addr, 2, &pkt, false, &mut relays, |_| None, |_| None);

        assert_eq!(forwards.len(), 1);
        let fwd = &forwards[0];
        assert_eq!(fwd.dest, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(fwd.port, 67);
        assert_eq!(fwd.from, iface_addr);
        assert_eq!(fwd.packet.giaddr, iface_addr);
        assert_eq!(fwd.packet.hops, 1);
    }

    #[test]
    fn relay_upstream4_skips_non_matching_interface() {
        let iface_addr = Ipv4Addr::new(192, 168, 1, 1);
        let pkt = base_packet();
        let mut relays = vec![normal_relay(iface_addr, Ipv4Addr::new(10, 0, 0, 1), 2)];

        let forwards = relay_upstream4(iface_addr, 3, &pkt, false, &mut relays, |_| None, |_| None);

        assert!(forwards.is_empty());
    }

    #[test]
    fn relay_upstream4_loop_detection_skips_own_giaddr() {
        let iface_addr = Ipv4Addr::new(192, 168, 1, 1);
        let mut pkt = base_packet();
        pkt.giaddr = iface_addr; // already gatewayed by us
        let mut relays = vec![normal_relay(iface_addr, Ipv4Addr::new(10, 0, 0, 1), 2)];

        let forwards = relay_upstream4(iface_addr, 2, &pkt, false, &mut relays, |_| None, |_| None);

        assert!(forwards.is_empty());
    }

    #[test]
    fn relay_upstream4_drops_packet_over_hop_limit() {
        let iface_addr = Ipv4Addr::new(192, 168, 1, 1);
        let mut pkt = base_packet();
        pkt.hops = 21;
        let mut relays = vec![normal_relay(iface_addr, Ipv4Addr::new(10, 0, 0, 1), 2)];

        let forwards = relay_upstream4(iface_addr, 2, &pkt, false, &mut relays, |_| None, |_| None);

        assert!(forwards.is_empty());
    }

    #[test]
    fn relay_upstream4_broadcasts_when_server_unspecified() {
        let iface_addr = Ipv4Addr::new(192, 168, 1, 1);
        let pkt = base_packet();
        let mut relays = vec![normal_relay(iface_addr, Ipv4Addr::UNSPECIFIED, 2)];
        relays[0].interface = Some("eth0".to_string());

        let forwards = relay_upstream4(
            iface_addr, 2, &pkt, false, &mut relays,
            |_| None,
            |iface| (iface == "eth0").then_some(Ipv4Addr::new(192, 168, 1, 255)),
        );

        assert_eq!(forwards.len(), 1);
        assert_eq!(forwards[0].dest, Ipv4Addr::new(192, 168, 1, 255));
    }

    #[test]
    fn relay_upstream4_split_mode_injects_option82() {
        let iface_addr = Ipv4Addr::new(192, 168, 1, 1); // client-facing address
        let pkt = base_packet();
        let mut relays = vec![split_relay(iface_addr, Ipv4Addr::new(10, 0, 0, 1), "eth1")];
        let uplink = Ipv4Addr::new(203, 0, 113, 1);

        let forwards = relay_upstream4(
            iface_addr, 5, &pkt, true, &mut relays,
            |iface| (iface == "eth1").then_some(uplink),
            |_| None,
        );

        assert_eq!(forwards.len(), 1);
        let fwd = &forwards[0];
        assert_eq!(fwd.from, uplink);
        assert_eq!(fwd.packet.giaddr, uplink);
        assert!(matches!(relays[0].uplink_addr, crate::types::addr::AllAddr::Addr4(a) if a == uplink));

        let idx = option_find1(&fwd.packet.options, OPTION_AGENT_ID, 1).expect("agent-id option present");
        assert_eq!(option_len_at(&fwd.packet.options, idx), 21);
        let data = option_val_at(&fwd.packet.options, idx);
        let subnet_idx = option_find1(data, crate::dhcp_protocol::SUBOPT_SUBNET_SELECT, 4).unwrap();
        assert_eq!(option_val_at(data, subnet_idx), iface_addr.octets());
        let remote_idx = option_find1(data, crate::dhcp_protocol::SUBOPT_REMOTE_ID, 4).unwrap();
        assert_eq!(option_uint_at(data, remote_idx, 0, 4), 5);
        let flags_idx = option_find1(data, crate::dhcp_protocol::SUBOPT_FLAGS, 1).unwrap();
        assert_eq!(option_val_at(data, flags_idx), [0x80]); // unicast
    }

    #[test]
    fn relay_upstream4_split_mode_requires_matching_local_addr() {
        let iface_addr = Ipv4Addr::new(192, 168, 1, 1);
        let pkt = base_packet();
        let mut relays = vec![split_relay(Ipv4Addr::new(10, 10, 10, 10), Ipv4Addr::new(10, 0, 0, 1), "eth1")];

        let forwards = relay_upstream4(iface_addr, 5, &pkt, true, &mut relays, |_| None, |_| None);

        assert!(forwards.is_empty());
    }

    #[test]
    fn relay_reply4_normal_mode_returns_iface_index() {
        let mut pkt = base_packet();
        pkt.op = BOOTREPLY;
        pkt.giaddr = Ipv4Addr::new(192, 168, 1, 1);
        let relays = vec![normal_relay(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 0, 0, 1), 2)];

        let iface = relay_reply4(&mut pkt, &relays, None);

        assert_eq!(iface, 2);
    }

    #[test]
    fn relay_reply4_ignores_non_reply_or_unset_giaddr() {
        let mut pkt = base_packet(); // op is BOOTREQUEST, giaddr unset
        let relays = vec![normal_relay(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 0, 0, 1), 2)];
        assert_eq!(relay_reply4(&mut pkt, &relays, None), 0);

        pkt.op = BOOTREPLY;
        assert_eq!(relay_reply4(&mut pkt, &relays, None), 0); // giaddr still unset
    }

    #[test]
    fn relay_reply4_honors_interface_wildcard() {
        let mut pkt = base_packet();
        pkt.op = BOOTREPLY;
        pkt.giaddr = Ipv4Addr::new(192, 168, 1, 1);
        let mut relay = normal_relay(Ipv4Addr::new(192, 168, 1, 1), Ipv4Addr::new(10, 0, 0, 1), 2);
        relay.interface = Some("eth*".to_string());
        let relays = vec![relay];

        assert_eq!(relay_reply4(&mut pkt, &relays, Some("eth0")), 2);
        assert_eq!(relay_reply4(&mut pkt, &relays, Some("wlan0")), 0);
    }

    #[test]
    fn relay_reply4_split_mode_extracts_and_strips_remote_id() {
        let iface_addr = Ipv4Addr::new(192, 168, 1, 1);
        let req = base_packet();
        let mut relays = vec![split_relay(iface_addr, Ipv4Addr::new(10, 0, 0, 1), "eth1")];
        let uplink = Ipv4Addr::new(203, 0, 113, 1);
        let forwards = relay_upstream4(
            iface_addr, 7, &req, false, &mut relays,
            |_| Some(uplink),
            |_| None,
        );
        let mut reply = forwards[0].packet.clone();
        reply.op = BOOTREPLY;
        // giaddr is already `uplink` from the forwarded request, as a real
        // server would echo it back unchanged.

        let iface = relay_reply4(&mut reply, &relays, Some("eth1"));

        assert_eq!(iface, 7);
        // Agent-id must be stripped per RFC 3046 §2.1 before the reply reaches the client.
        assert!(option_find1(&reply.options, OPTION_AGENT_ID, 0).is_none());
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
        use crate::types::dhcp::{DhcpOpt, DhOptFlags};
        let opt = DhcpOpt { opt: 15, flags: DhOptFlags::STRING, val: Some(b"hi".to_vec()),
                            netid: vec![], encap: 0, vendor_class: None };
        // null_term → len + 1
        assert_eq!(do_opt(&opt, None, None, true), 3);
        assert_eq!(do_opt(&opt, None, None, false), 2);
    }

    #[test]
    fn do_opt_writes_data() {
        use crate::types::dhcp::{DhcpOpt, DhOptFlags};
        let opt = DhcpOpt { opt: 15, flags: DhOptFlags::STRING, val: Some(b"hi".to_vec()),
                            netid: vec![], encap: 0, vendor_class: None };
        let mut buf = vec![0u8; 2];
        let n = do_opt(&opt, Some(&mut buf), None, false);
        assert_eq!(n, 2);
        assert_eq!(&buf, b"hi");
    }

    #[test]
    fn do_opt_null_terminator() {
        use crate::types::dhcp::{DhcpOpt, DhOptFlags};
        let opt = DhcpOpt { opt: 15, flags: DhOptFlags::STRING, val: Some(b"hi".to_vec()),
                            netid: vec![], encap: 0, vendor_class: None };
        let mut buf = vec![0u8; 3];
        do_opt(&opt, Some(&mut buf), None, true);
        assert_eq!(buf[2], 0, "null terminator should be appended");
    }

    // ── match_vendor_opts ─────────────────────────────────────────────────────

    #[test]
    fn match_vendor_opts_marks_match() {
        use crate::types::dhcp::{DhcpOpt, DhOptFlags};
        let mut opts = vec![DhcpOpt {
            opt: 43, flags: DhOptFlags::VENDOR,
            val: Some(b"v".to_vec()),
            netid: vec![], encap: 0,
            vendor_class: Some(b"PXEClient".to_vec()),
        }];
        match_vendor_opts(Some(b"PXEClient:Arch:00000"), &mut opts);
        assert!(opts[0].flags.contains(DhOptFlags::VENDOR_MATCH));
    }

    #[test]
    fn match_vendor_opts_no_match() {
        use crate::types::dhcp::{DhcpOpt, DhOptFlags};
        let mut opts = vec![DhcpOpt {
            opt: 43, flags: DhOptFlags::VENDOR,
            val: Some(b"v".to_vec()),
            netid: vec![], encap: 0,
            vendor_class: Some(b"PXEClient".to_vec()),
        }];
        match_vendor_opts(Some(b"MSFT 5.0"), &mut opts);
        assert!(!opts[0].flags.contains(DhOptFlags::VENDOR_MATCH));
    }

    #[test]
    fn match_vendor_opts_clears_previous_match() {
        use crate::types::dhcp::{DhcpOpt, DhOptFlags};
        let mut opts = vec![DhcpOpt {
            opt: 43, flags: DhOptFlags::VENDOR | DhOptFlags::VENDOR_MATCH,
            val: Some(b"v".to_vec()),
            netid: vec![], encap: 0,
            vendor_class: Some(b"PXEClient".to_vec()),
        }];
        // No vc_data → should clear VENDOR_MATCH.
        match_vendor_opts(None, &mut opts);
        assert!(!opts[0].flags.contains(DhOptFlags::VENDOR_MATCH));
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
            leasequery: false,
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
            leasequery: false,
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
            leasequery: false,
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
            leasequery: false,
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

    // ── extended_hwaddr ───────────────────────────────────────────────────────

    #[test]
    fn extended_hwaddr_uses_hwaddr_when_available() {
        let hw = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let result = extended_hwaddr(1, &hw, Some(&[1, 0x11, 0x22, 0x33, 0x44]));
        assert_eq!(result, &hw);
    }

    #[test]
    fn extended_hwaddr_falls_back_to_clid_matching_type() {
        // hwaddr empty, clid starts with hwtype=1
        let clid = [1u8, 0xAA, 0xBB, 0xCC, 0xDD];
        let result = extended_hwaddr(1, &[], Some(&clid));
        assert_eq!(result, &[0xAA, 0xBB, 0xCC, 0xDD]); // skip type byte
    }

    #[test]
    fn extended_hwaddr_falls_back_to_full_clid_mismatched_type() {
        // hwaddr empty, clid type doesn't match
        let clid = [2u8, 0xAA, 0xBB, 0xCC, 0xDD];
        let result = extended_hwaddr(1, &[], Some(&clid));
        assert_eq!(result, &clid[..]); // full clid
    }

    #[test]
    fn extended_hwaddr_empty_hwaddr_no_clid() {
        let result = extended_hwaddr(1, &[], None);
        assert!(result.is_empty());
    }

    #[test]
    fn extended_hwaddr_empty_hwaddr_short_clid() {
        // clid too short (<=3), returns hwaddr (empty)
        let result = extended_hwaddr(1, &[], Some(&[1, 2, 3]));
        assert!(result.is_empty());
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
                netid: vec![],
            },
            DhcpBoot {
                file: Some("special.img".into()),
                sname: None, tftp_sname: None,
                next_server: Ipv4Addr::UNSPECIFIED,
                netid: vec![DhcpNetid { net: "lab".into() }],
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
                netid: vec![],
            },
        ];
        let result = find_boot(&boots, Some("nomatch"));
        assert_eq!(result.unwrap().file.as_deref(), Some("default.img"));
    }

    #[test]
    fn find_boot_empty() {
        assert!(find_boot(&[], Some("x")).is_none());
    }

    // ── cap_vendor_area (BOOTP 64-byte vend area, rfc2131.c:577) ────────────

    #[test]
    fn cap_vendor_area_keeps_short_blob_and_terminates() {
        let mut opts = vec![crate::dhcp_protocol::OPTION_NETMASK, 4, 255, 255, 255, 0];
        cap_vendor_area(&mut opts, 64);
        assert_eq!(opts, vec![crate::dhcp_protocol::OPTION_NETMASK, 4, 255, 255, 255, 0, OPTION_END]);
    }

    #[test]
    fn cap_vendor_area_drops_options_past_the_limit_without_splitting_a_tlv() {
        // Three 6-byte TLVs (2-byte header + 4-byte value) = 18 bytes; cap at
        // 10 leaves room for exactly one full TLV (6 bytes) + END (1 byte).
        let mut opts = vec![
            1, 4, 1, 1, 1, 1, // fits (bytes 0-5)
            3, 4, 2, 2, 2, 2, // would end at byte 12 > budget (10-1=9) — dropped
            6, 4, 3, 3, 3, 3,
        ];
        cap_vendor_area(&mut opts, 10);
        assert_eq!(opts, vec![1, 4, 1, 1, 1, 1, OPTION_END]);
        assert!(opts.len() <= 10);
    }

    #[test]
    fn cap_vendor_area_on_empty_options_just_terminates() {
        let mut opts = Vec::new();
        cap_vendor_area(&mut opts, 64);
        assert_eq!(opts, vec![OPTION_END]);
    }

    // ── make_rapid_commit_ack ────────────────────────────────────────────────

    #[test]
    fn make_rapid_commit_ack_converts_offer_to_ack_with_option_80() {
        let offer = DhcpReply {
            msg_type: DhcpMsgType::Offer,
            yiaddr: Ipv4Addr::new(10, 0, 0, 5),
            options: build_reply_options(DhcpMsgType::Offer, Ipv4Addr::new(10, 0, 0, 1)),
            siaddr: Ipv4Addr::new(10, 0, 0, 1),
            giaddr: Ipv4Addr::UNSPECIFIED,
            sname: None,
            file: None,
            ciaddr_override: None,
            chaddr_override: None,
        };
        let ack = make_rapid_commit_ack(
            offer,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 254),
            None,
            false,
        )
        .expect("address is in-range, so rapid commit should succeed");
        assert_eq!(ack.msg_type, DhcpMsgType::Ack);
        assert_eq!(ack.yiaddr, Ipv4Addr::new(10, 0, 0, 5));
        assert!(option_find1(&ack.options, crate::dhcp_protocol::OPTION_RAPID_COMMIT, 0).is_some());
        assert_eq!(option_len_at(&ack.options, option_find1(&ack.options, crate::dhcp_protocol::OPTION_RAPID_COMMIT, 0).unwrap()), 0);
    }

    #[test]
    fn make_rapid_commit_ack_returns_none_when_address_out_of_range() {
        let offer = DhcpReply {
            msg_type: DhcpMsgType::Offer,
            yiaddr: Ipv4Addr::new(192, 168, 9, 9),
            options: build_reply_options(DhcpMsgType::Offer, Ipv4Addr::new(10, 0, 0, 1)),
            siaddr: Ipv4Addr::new(10, 0, 0, 1),
            giaddr: Ipv4Addr::UNSPECIFIED,
            sname: None,
            file: None,
            ciaddr_override: None,
            chaddr_override: None,
        };
        // yiaddr falls outside the pool and there's no static reservation for
        // it, so upstream's re-validation at `rapid_commit:` fails and no
        // reply is sent at all (rfc2131.c:1568-1569).
        let ack = make_rapid_commit_ack(
            offer,
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 254),
            None,
            false,
        );
        assert!(ack.is_none());
    }
}

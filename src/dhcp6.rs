//! DHCPv6 server — UDP receive loop and packet dispatch.
//! Ported from `dhcp6.c` (881 lines) in the original dnsmasq source.
//!
//! DHCPv6 uses UDP on port 547 (server) / 546 (client), sending to the
//! all-servers multicast group FF05::1:3 or all-agents FF02::1:2.

#![cfg(feature = "dhcp6")]

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;

use tracing::{debug, warn};

use crate::dhcp6_protocol::{
    Dhcp6MsgType, DHCPV6_CLIENT_PORT, DHCPV6_SERVER_PORT,
    OPTION6_CLIENT_ID, OPTION6_IA_NA, OPTION6_IAADDR, OPTION6_PREFERENCE,
    OPTION6_RAPID_COMMIT, OPTION6_SERVER_ID, OPTION6_STATUS_CODE,
};
use crate::lease::LeaseDb;
use crate::metrics::{inc_metric, Metric};
use crate::types::daemon::Daemon;
use crate::types::dhcp::{DhcpConfig, DhcpContext, DhcpNetid, LEASE_NA};

// ─────────────────────────────────────────────────────────────────────────────
// DHCPv6 packet representation
// ─────────────────────────────────────────────────────────────────────────────

/// A parsed DHCPv6 message (non-relay).
#[derive(Debug, Clone)]
pub struct Dhcp6Packet {
    /// Message type byte.
    pub msg_type: Dhcp6MsgType,
    /// Transaction ID (3 bytes, stored in the low 24 bits of a u32).
    pub xid: u32,
    /// Raw options bytes (remainder of the packet after the 4-byte header).
    pub options: Vec<u8>,
}

/// A DHCPv6 relay message (RELAY-FORW or RELAY-REPL).
#[derive(Debug, Clone)]
pub struct Dhcp6RelayMsg {
    pub msg_type:  Dhcp6MsgType,
    pub hop_count: u8,
    pub link_addr: Ipv6Addr,
    pub peer_addr: Ipv6Addr,
    pub options:   Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire-format parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a raw UDP payload into a `Dhcp6Packet`.
///
/// Returns `None` if the packet is shorter than 4 bytes or the message type
/// is not recognized.  Relay messages (RELAY-FORW / RELAY-REPL) require at
/// least 34 bytes and are returned as `Err(Dhcp6RelayMsg)`.
pub fn parse_dhcp6_packet(data: &[u8]) -> Result<Dhcp6Packet, Option<Dhcp6RelayMsg>> {
    if data.len() < 4 {
        return Err(None);
    }
    let msg_type = Dhcp6MsgType::from_u8(data[0]).ok_or(None)?;

    // Relay messages have a different header layout.
    if matches!(msg_type, Dhcp6MsgType::RelayForw | Dhcp6MsgType::RelayRepl) {
        if data.len() < 34 {
            return Err(None);
        }
        let hop_count = data[1];
        let link_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[2..18]).unwrap());
        let peer_addr = Ipv6Addr::from(<[u8; 16]>::try_from(&data[18..34]).unwrap());
        return Err(Some(Dhcp6RelayMsg {
            msg_type,
            hop_count,
            link_addr,
            peer_addr,
            options: data[34..].to_vec(),
        }));
    }

    let xid = u32::from_be_bytes([0, data[1], data[2], data[3]]);
    Ok(Dhcp6Packet {
        msg_type,
        xid,
        options: data[4..].to_vec(),
    })
}

/// Find a DHCPv6 option by code in a raw options buffer.
///
/// Returns a slice of the option *value* (excluding the 4-byte TLV header)
/// or `None` if not present.
pub fn find_option6(options: &[u8], code: u16) -> Option<&[u8]> {
    let mut i = 0;
    while i + 4 <= options.len() {
        let opt_code = u16::from_be_bytes([options[i], options[i + 1]]);
        let opt_len  = u16::from_be_bytes([options[i + 2], options[i + 3]]) as usize;
        i += 4;
        if i + opt_len > options.len() {
            break;
        }
        if opt_code == code {
            return Some(&options[i..i + opt_len]);
        }
        i += opt_len;
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Reply construction
// ─────────────────────────────────────────────────────────────────────────────

/// A minimal DHCPv6 reply.
#[derive(Debug, Clone)]
pub struct Dhcp6Reply {
    pub msg_type: Dhcp6MsgType,
    pub xid:      u32,
    pub options:  Vec<u8>,
}

impl Dhcp6Reply {
    /// Serialize to wire format.
    pub fn to_wire(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(4 + self.options.len());
        buf.push(self.msg_type as u8);
        buf.push(((self.xid >> 16) & 0xFF) as u8);
        buf.push(((self.xid >>  8) & 0xFF) as u8);
        buf.push(( self.xid        & 0xFF) as u8);
        buf.extend_from_slice(&self.options);
        buf
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Build a flat (code + length + data) DHCPv6 option.
fn build_option6(code: u16, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&code.to_be_bytes());
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Build a raw IAADDR sub-option (24 bytes: addr | preferred-lt | valid-lt).
fn iaaddr_suboption(addr: Ipv6Addr, preferred: u32, valid: u32) -> Vec<u8> {
    let mut iaaddr = Vec::with_capacity(24);
    iaaddr.extend_from_slice(&addr.octets());
    iaaddr.extend_from_slice(&preferred.to_be_bytes());
    iaaddr.extend_from_slice(&valid.to_be_bytes());
    build_option6(OPTION6_IAADDR, &iaaddr)
}

/// Build a raw Status Code sub/top-level option (both share the same wire shape).
fn status_option(code: u16, message: &str) -> Vec<u8> {
    build_option6(OPTION6_STATUS_CODE, &crate::rfc3315::build_status_code(code, message))
}

/// Build an IA_NA reply option: `IAID | T1 | T2 | suboption_bytes`.
fn build_ia_na_option(iaid: [u8; 4], t1: u32, t2: u32, suboption: Vec<u8>) -> Vec<u8> {
    let mut data = Vec::with_capacity(12 + suboption.len());
    data.extend_from_slice(&iaid);
    data.extend_from_slice(&t1.to_be_bytes());
    data.extend_from_slice(&t2.to_be_bytes());
    data.extend(suboption);
    build_option6(OPTION6_IA_NA, &data)
}

/// Extract the client-id option's raw bytes (empty slice if absent).
fn extract_client_id(pkt: &Dhcp6Packet) -> &[u8] {
    find_option6(&pkt.options, OPTION6_CLIENT_ID).unwrap_or(&[])
}

/// Extract the packet's (single, first) IA_NA option value and IAID.
///
/// This module handles one IA_NA per packet — matching its existing
/// simplification (see tasks.md); upstream walks every IA in the message.
fn extract_ia(pkt: &Dhcp6Packet) -> Option<(&[u8], u32)> {
    let ia_data = find_option6(&pkt.options, OPTION6_IA_NA)?;
    if ia_data.len() < 4 {
        return None;
    }
    let iaid = u32::from_be_bytes([ia_data[0], ia_data[1], ia_data[2], ia_data[3]]);
    Some((ia_data, iaid))
}

/// Extract the first client-requested address from an IA_NA option's value
/// (the bytes after the 4-byte option header: IAID(4) | T1(4) | T2(4) |
/// sub-options…). Only the first IAADDR sub-option is read — this module
/// handles a single address per IA (see tasks.md); upstream walks every
/// IAADDR in the IA.
fn ia_na_first_addr(ia_data: &[u8]) -> Option<Ipv6Addr> {
    if ia_data.len() <= 12 {
        return None;
    }
    let iaaddr = find_option6(&ia_data[12..], OPTION6_IAADDR)?;
    let bytes: [u8; 16] = iaaddr.get(0..16)?.try_into().ok()?;
    Some(Ipv6Addr::from(bytes))
}

/// `true` if `addr` is already committed to a lease or a static
/// `--dhcp-host` reservation — the same test [`address6_allocate`]'s `in_use`
/// callback performs, factored out so the per-message-type handlers below
/// can build it from `lease_db`/`configs` directly.
fn addr_in_use(lease_db: &LeaseDb, configs: &[DhcpConfig], addr: &Ipv6Addr) -> bool {
    lease_db.find_v6_by_addr(addr).is_some() || config_find_by_address6(configs, addr)
}

/// Make sure `addr` isn't leased to a *different* client/IAID.
///
/// Port of `check_address()` (rfc3315.c:1719-1732).
fn check_address(lease_db: &LeaseDb, clid: &[u8], iaid: u32, addr: &Ipv6Addr) -> bool {
    match lease_db.find_v6_by_addr(addr) {
        None => true,
        Some(l) => l.clid.as_deref() == Some(clid) && l.iaid == iaid,
    }
}

/// Find the context whose prefix `addr` belongs to, for reading its
/// configured `lease_time`.
fn context_for_addr<'a>(contexts: &'a [DhcpContext], addr: &Ipv6Addr) -> Option<&'a DhcpContext> {
    contexts.iter().find(|c| is_same_net6(&c.start6, addr, c.prefix))
}

/// Compute `(preferred, valid, t1, t2)` for `addr` from its owning context's
/// `lease_time` (falling back to 3600s if `addr` matches no context, e.g. a
/// REBIND-created lease for an address a live context no longer covers).
///
/// Port of the `calculate_times()` call sites in rfc3315.c that read
/// `context->lease_time` (or `config->lease_time` when `have_config(...,
/// CONFIG_TIME)` — not ported, see tasks.md for the static-host-config gap).
fn compute_times_for_addr(contexts: &[DhcpContext], addr: &Ipv6Addr) -> (u32, u32, u32, u32) {
    let lease_time = context_for_addr(contexts, addr).map(|c| c.lease_time).unwrap_or(3600);
    crate::rfc3315::calculate_times(lease_time)
}

/// Bind (allocate-or-renew) a lease for `addr` and return the lifetimes used
/// to compute its expiry — the `update_leases()` equivalent every success
/// path below calls (rfc3315.c:1870-1986).
fn persist_lease(
    lease_db: &mut LeaseDb,
    clid: &[u8],
    iaid: u32,
    addr: Ipv6Addr,
    contexts: &[DhcpContext],
    now_secs: u64,
) -> (u32, u32, u32, u32) {
    let (preferred, valid, t1, t2) = compute_times_for_addr(contexts, &addr);
    let expires = if valid == 0xFFFF_FFFF {
        None
    } else {
        Some(std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(now_secs.saturating_add(valid as u64)))
    };
    lease_db.bind_v6(addr, clid, iaid, LEASE_NA, expires);
    (preferred, valid, t1, t2)
}

/// Select an address to offer/assign for a Solicit (or a Request whose IA
/// carried no address, which upstream redirects into this same selection —
/// rfc3315.c:833-839 `goto request_no_address`).
///
/// Tries, in order: (1) the client's requested address if it's valid,
/// available, and not leased to someone else; (2) an existing lease already
/// bound to this client/IAID; (3) a fresh [`address6_allocate`]. Does not
/// persist anything — callers decide whether/when to call [`persist_lease`].
///
/// Scope note: unlike upstream's `DHCP6SOLICIT` case, this does not offer a
/// statically-`--dhcp-host`-configured address ahead of a dynamic one
/// (`config_valid()`, rfc3315.c:695-701) — that needs the fuller
/// `config_valid`/`config_implies` static-host-address port tracked in
/// tasks.md; a static reservation still blocks allocation via
/// [`addr_in_use`], it's just never *preferred*.
fn select_address_for_ia(
    contexts: &[DhcpContext],
    configs: &[DhcpConfig],
    lease_db: &LeaseDb,
    client_id: &[u8],
    iaid: u32,
    requested: Option<Ipv6Addr>,
) -> Option<Ipv6Addr> {
    if let Some(r) = requested {
        if address6_valid(contexts, &r)
            && address6_available(contexts, &r)
            && check_address(lease_db, client_id, iaid, &r)
        {
            return Some(r);
        }
    }
    if let Some(existing) = lease_db.find_v6_by_client_iaid(client_id, iaid).map(|l| l.addr6) {
        if address6_available(contexts, &existing) {
            return Some(existing);
        }
    }
    address6_allocate(contexts, client_id, iaid, &[], &mut |a| addr_in_use(lease_db, configs, a))
}

/// Build a Solicit-shaped (Advertise or, with rapid-commit, Reply) result.
///
/// Shared by [`dispatch_solicit`] and the Request-with-no-address redirect
/// in [`dispatch_request`] (rfc3315.c:833-839).
#[allow(clippy::too_many_arguments)]
fn build_solicit_style_reply(
    xid: u32,
    duid: &[u8],
    client_id: &[u8],
    iaid_bytes: [u8; 4],
    contexts: &[DhcpContext],
    lease_db: &mut LeaseDb,
    addr: Option<Ipv6Addr>,
    persist: bool,
    reply_type: Dhcp6MsgType,
    include_rapid_commit_opt: bool,
    authoritative: bool,
    now_secs: u64,
) -> Dhcp6Reply {
    let iaid = u32::from_be_bytes(iaid_bytes);
    let (preferred, valid, t1, t2) = match addr {
        Some(a) if persist => persist_lease(lease_db, client_id, iaid, a, contexts, now_secs),
        Some(a) => compute_times_for_addr(contexts, &a),
        None => (0, 0, 0, 0),
    };

    let mut options = Vec::new();
    options.extend(build_option6(OPTION6_CLIENT_ID, client_id));
    options.extend(build_option6(OPTION6_SERVER_ID, duid));
    if include_rapid_commit_opt {
        options.extend(build_option6(OPTION6_RAPID_COMMIT, &[]));
    }
    let ia_sub = match addr {
        Some(a) => iaaddr_suboption(a, preferred, valid),
        None => status_option(crate::rfc3315::STATUS_NO_ADDRS_AVAIL, "address unavailable"),
    };
    options.extend(build_ia_na_option(iaid_bytes, t1, t2, ia_sub));
    if addr.is_some() {
        options.extend(status_option(crate::rfc3315::STATUS_SUCCESS, "success"));
        options.extend(build_option6(OPTION6_PREFERENCE, &[if authoritative { 255 } else { 0 }]));
    } else {
        options.extend(status_option(crate::rfc3315::STATUS_NO_ADDRS_AVAIL, "no addresses available"));
    }

    Dhcp6Reply { msg_type: reply_type, xid, options }
}

/// `DHCP6SOLICIT` (rfc3315.c:627-808).
fn dispatch_solicit(
    pkt: &Dhcp6Packet,
    duid: &[u8],
    contexts: &[DhcpContext],
    configs: &[DhcpConfig],
    lease_db: &mut LeaseDb,
    authoritative: bool,
    now_secs: u64,
) -> Option<Dhcp6Reply> {
    let client_id = extract_client_id(pkt).to_vec();
    let rapid_commit = find_option6(&pkt.options, OPTION6_RAPID_COMMIT).is_some();
    let reply_type = if rapid_commit { Dhcp6MsgType::Reply } else { Dhcp6MsgType::Advertise };

    // No IA in the packet at all: upstream's per-IA loop simply never runs,
    // leaving `address_assigned == 0` -> a reply with no IA_NA option and a
    // top-level NoAddrsAvail (rfc3315.c:660-807's loop body vs. :774-804).
    let Some((ia_data, iaid)) = extract_ia(pkt) else {
        let mut options = Vec::new();
        options.extend(build_option6(OPTION6_CLIENT_ID, &client_id));
        options.extend(build_option6(OPTION6_SERVER_ID, duid));
        options.extend(status_option(crate::rfc3315::STATUS_NO_ADDRS_AVAIL, "no addresses available"));
        return Some(Dhcp6Reply { msg_type: reply_type, xid: pkt.xid, options });
    };
    let iaid_bytes = iaid.to_be_bytes();
    let requested = ia_na_first_addr(ia_data);

    let addr = select_address_for_ia(contexts, configs, lease_db, &client_id, iaid, requested);

    Some(build_solicit_style_reply(
        pkt.xid, duid, &client_id, iaid_bytes, contexts, lease_db,
        addr, rapid_commit, reply_type, rapid_commit, authoritative, now_secs,
    ))
}

/// `DHCP6REQUEST` (rfc3315.c:810-922), including the "IA with no address"
/// redirect into Solicit-with-rapid-commit-equivalent behavior
/// (rfc3315.c:833-839).
fn dispatch_request(
    pkt: &Dhcp6Packet,
    duid: &[u8],
    contexts: &[DhcpContext],
    configs: &[DhcpConfig],
    lease_db: &mut LeaseDb,
    authoritative: bool,
    now_secs: u64,
) -> Option<Dhcp6Reply> {
    let client_id = extract_client_id(pkt).to_vec();
    // No IA in the packet at all (distinct from an IA present but empty,
    // handled by the redirect below): same "loop never runs" fall-through as
    // Solicit (rfc3315.c:824-901 vs. :903-918).
    let Some((ia_data, iaid)) = extract_ia(pkt) else {
        let mut options = Vec::new();
        options.extend(build_option6(OPTION6_CLIENT_ID, &client_id));
        options.extend(build_option6(OPTION6_SERVER_ID, duid));
        options.extend(status_option(crate::rfc3315::STATUS_NO_ADDRS_AVAIL, "no addresses available"));
        return Some(Dhcp6Reply { msg_type: Dhcp6MsgType::Reply, xid: pkt.xid, options });
    };
    let iaid_bytes = iaid.to_be_bytes();
    let requested = ia_na_first_addr(ia_data);

    let Some(req_addr) = requested else {
        let addr = select_address_for_ia(contexts, configs, lease_db, &client_id, iaid, None);
        return Some(build_solicit_style_reply(
            pkt.xid, duid, &client_id, iaid_bytes, contexts, lease_db,
            addr, true, Dhcp6MsgType::Reply, false, authoritative, now_secs,
        ));
    };

    let on_link = address6_valid(contexts, &req_addr);
    let dynamic = address6_available(contexts, &req_addr);
    let config_ok = config_find_by_address6(configs, &req_addr);

    let (status, addr) = if dynamic || on_link {
        if !dynamic && !config_ok {
            (Some((crate::rfc3315::STATUS_NO_ADDRS_AVAIL, "address unavailable")), None)
        } else if !check_address(lease_db, &client_id, iaid, &req_addr) {
            (Some((crate::rfc3315::STATUS_UNSPEC_FAIL, "address in use")), None)
        } else {
            (None, Some(req_addr))
        }
    } else {
        (Some((crate::rfc3315::STATUS_NOT_ON_LINK, "not on link")), None)
    };

    let (preferred, valid, t1, t2) = match addr {
        Some(a) => persist_lease(lease_db, &client_id, iaid, a, contexts, now_secs),
        None => (0, 0, 0, 0),
    };

    let mut options = Vec::new();
    options.extend(build_option6(OPTION6_CLIENT_ID, &client_id));
    options.extend(build_option6(OPTION6_SERVER_ID, duid));
    let ia_sub = match addr {
        Some(a) => iaaddr_suboption(a, preferred, valid),
        None => {
            let (code, msg) = status.unwrap();
            status_option(code, msg)
        }
    };
    options.extend(build_ia_na_option(iaid_bytes, t1, t2, ia_sub));
    if addr.is_some() {
        options.extend(status_option(crate::rfc3315::STATUS_SUCCESS, "success"));
    } else {
        options.extend(status_option(crate::rfc3315::STATUS_NO_ADDRS_AVAIL, "no addresses available"));
    }

    Some(Dhcp6Reply { msg_type: Dhcp6MsgType::Reply, xid: pkt.xid, options })
}

/// `DHCP6RENEW`/`DHCP6REBIND` (rfc3315.c:925-1059).
///
/// Scope note: only the single client-echoed address this module tracks per
/// IA is renewed/rebound; upstream walks every IAADDR in the IA
/// independently (see tasks.md).
fn dispatch_renew_rebind(
    pkt: &Dhcp6Packet,
    duid: &[u8],
    contexts: &[DhcpContext],
    lease_db: &mut LeaseDb,
    is_rebind: bool,
    authoritative: bool,
    now_secs: u64,
) -> Option<Dhcp6Reply> {
    let client_id = extract_client_id(pkt).to_vec();
    let (ia_data, iaid) = extract_ia(pkt)?;
    let iaid_bytes = iaid.to_be_bytes();
    let addr = ia_na_first_addr(ia_data)?;

    let mut options = Vec::new();
    options.extend(build_option6(OPTION6_CLIENT_ID, &client_id));
    options.extend(build_option6(OPTION6_SERVER_ID, duid));

    let has_lease = lease_db.find_v6_by_clid_iaid(&client_id, iaid, &addr).is_some();

    if !has_lease {
        // Authoritative REBIND may create a lease the server doesn't
        // remember, as long as the address is still plausible for some
        // context (rfc3315.c:962-972).
        if is_rebind
            && authoritative
            && (address6_available(contexts, &addr) || address6_valid(contexts, &addr))
        {
            let (preferred, valid, t1, t2) = persist_lease(lease_db, &client_id, iaid, addr, contexts, now_secs);
            options.extend(build_ia_na_option(iaid_bytes, t1, t2, iaaddr_suboption(addr, preferred, valid)));
            options.extend(status_option(crate::rfc3315::STATUS_SUCCESS, "success"));
            return Some(Dhcp6Reply { msg_type: Dhcp6MsgType::Reply, xid: pkt.xid, options });
        }

        options.extend(build_ia_na_option(
            iaid_bytes, 0, 0,
            status_option(crate::rfc3315::STATUS_NO_BINDING, "no binding found"),
        ));
        // RENEW never sets a top-level error, only Rebind does when nothing
        // could be (re)bound at all (rfc3315.c:1048-1055).
        if is_rebind {
            options.extend(status_option(crate::rfc3315::STATUS_NO_ADDRS_AVAIL, "no addresses available"));
        }
        return Some(Dhcp6Reply { msg_type: Dhcp6MsgType::Reply, xid: pkt.xid, options });
    }

    if !(address6_available(contexts, &addr) || address6_valid(contexts, &addr)) {
        // Address no longer valid for any live context: deprecate it
        // (preferred=valid=0) without touching the lease (rfc3315.c:1026-1030).
        options.extend(build_ia_na_option(iaid_bytes, 0, 0, iaaddr_suboption(addr, 0, 0)));
        options.extend(status_option(crate::rfc3315::STATUS_SUCCESS, "success"));
        return Some(Dhcp6Reply { msg_type: Dhcp6MsgType::Reply, xid: pkt.xid, options });
    }

    let (preferred, valid, t1, t2) = persist_lease(lease_db, &client_id, iaid, addr, contexts, now_secs);
    options.extend(build_ia_na_option(iaid_bytes, t1, t2, iaaddr_suboption(addr, preferred, valid)));
    options.extend(status_option(crate::rfc3315::STATUS_SUCCESS, "success"));
    Some(Dhcp6Reply { msg_type: Dhcp6MsgType::Reply, xid: pkt.xid, options })
}

/// `DHCP6CONFIRM` (rfc3315.c:1061-1105).
///
/// No allocation ever happens here — only a validity check against
/// [`address6_valid`]. Returns `None` (no reply at all) when the packet
/// carried no address to confirm, per RFC 3315 §18.2.2.
fn dispatch_confirm(pkt: &Dhcp6Packet, duid: &[u8], contexts: &[DhcpContext]) -> Option<Dhcp6Reply> {
    let client_id = extract_client_id(pkt).to_vec();
    let (ia_data, _iaid) = extract_ia(pkt)?;
    let addr = ia_na_first_addr(ia_data)?;

    let bad = !address6_valid(contexts, &addr);

    let mut options = Vec::new();
    options.extend(build_option6(OPTION6_CLIENT_ID, &client_id));
    options.extend(build_option6(OPTION6_SERVER_ID, duid));
    if bad {
        options.extend(status_option(crate::rfc3315::STATUS_NOT_ON_LINK, "confirm failed"));
    } else {
        options.extend(status_option(crate::rfc3315::STATUS_SUCCESS, "all addresses still on link"));
    }
    Some(Dhcp6Reply { msg_type: Dhcp6MsgType::Reply, xid: pkt.xid, options })
}

/// `DHCP6RELEASE`/`DHCP6DECLINE` (rfc3315.c:1139-1284).
///
/// Both prune the matching lease (freeing the address) and both always
/// return top-level Success regardless of whether a binding was found — only
/// the differ in status message text and (upstream) the static-host
/// decline-backoff/`addr_epoch` bump this module doesn't port (tasks.md).
fn dispatch_release_or_decline(
    pkt: &Dhcp6Packet,
    duid: &[u8],
    lease_db: &mut LeaseDb,
    is_decline: bool,
) -> Option<Dhcp6Reply> {
    let client_id = extract_client_id(pkt).to_vec();

    let mut options = Vec::new();
    options.extend(build_option6(OPTION6_CLIENT_ID, &client_id));
    options.extend(build_option6(OPTION6_SERVER_ID, duid));

    if let Some((ia_data, iaid)) = extract_ia(pkt) {
        let iaid_bytes = iaid.to_be_bytes();
        if let Some(addr) = ia_na_first_addr(ia_data) {
            if !lease_db.remove_v6_by_clid_iaid_addr(&client_id, iaid, &addr) {
                options.extend(build_ia_na_option(
                    iaid_bytes, 0, 0,
                    status_option(crate::rfc3315::STATUS_NO_BINDING, "no binding found"),
                ));
            }
        }
    }

    let msg = if is_decline { "success" } else { "release received" };
    options.extend(status_option(crate::rfc3315::STATUS_SUCCESS, msg));
    Some(Dhcp6Reply { msg_type: Dhcp6MsgType::Reply, xid: pkt.xid, options })
}

/// `DHCP6IREQ` (rfc3315.c:1107-1136).
///
/// Rejects (drops) a request that carries an IA_NA/IA_TA per RFC 3315 §15.12
/// / rfc3315.c:1110-1112 — Information-Request is for stateless option
/// delivery only. Non-IA option delivery itself (`add_options()`: DNS
/// servers, domain search, SNTP, ULA/link-local auto-prefix) is not ported —
/// see tasks.md — so a valid Information-Request currently gets an
/// options-less Reply rather than a silent drop.
fn dispatch_inforeq(pkt: &Dhcp6Packet, duid: &[u8]) -> Option<Dhcp6Reply> {
    use crate::dhcp6_protocol::OPTION6_IA_TA;
    if find_option6(&pkt.options, OPTION6_IA_NA).is_some()
        || find_option6(&pkt.options, OPTION6_IA_TA).is_some()
    {
        return None;
    }
    let client_id = extract_client_id(pkt).to_vec();
    let mut options = Vec::new();
    options.extend(build_option6(OPTION6_CLIENT_ID, &client_id));
    options.extend(build_option6(OPTION6_SERVER_ID, duid));
    Some(Dhcp6Reply { msg_type: Dhcp6MsgType::Reply, xid: pkt.xid, options })
}

/// Dispatch a parsed DHCPv6 packet using real server state.
///
/// Each RFC 8415 message type is handled by its own function per the
/// module-level gap analysis in the originating issue: Solicit/Request build
/// and (Request only, or rapid-commit Solicit) persist a fresh allocation;
/// Renew/Rebind extend an existing lease found by (`clid`, `iaid`, `addr`) in
/// `lease_db`, only Rebind may create one when `authoritative` is set;
/// Confirm never allocates; Release/Decline free the matching lease.
/// `authoritative` mirrors `--dhcp-authoritative` (`OPT_AUTHORITATIVE`, only
/// consulted for Solicit's Preference option and Rebind's no-lease
/// fallback); `now_secs` is UNIX-epoch seconds used to compute lease expiry.
///
/// Returns `Some(Dhcp6Reply)` when a reply should be sent, `None` to drop.
///
/// Port of the message-type dispatch driving `dhcp6_reply()` (rfc3315.c).
pub fn dispatch_dhcp6(
    pkt: &Dhcp6Packet,
    duid: &[u8],
    contexts: &[DhcpContext],
    configs: &[DhcpConfig],
    lease_db: &mut LeaseDb,
    authoritative: bool,
    now_secs: u64,
) -> Option<Dhcp6Reply> {
    debug!("DHCPv6 {:?} xid={:#x}", pkt.msg_type, pkt.xid);

    match pkt.msg_type {
        Dhcp6MsgType::Solicit => dispatch_solicit(pkt, duid, contexts, configs, lease_db, authoritative, now_secs),
        Dhcp6MsgType::Request => dispatch_request(pkt, duid, contexts, configs, lease_db, authoritative, now_secs),
        Dhcp6MsgType::Renew => dispatch_renew_rebind(pkt, duid, contexts, lease_db, false, authoritative, now_secs),
        Dhcp6MsgType::Rebind => dispatch_renew_rebind(pkt, duid, contexts, lease_db, true, authoritative, now_secs),
        Dhcp6MsgType::Confirm => dispatch_confirm(pkt, duid, contexts),
        Dhcp6MsgType::Release => dispatch_release_or_decline(pkt, duid, lease_db, false),
        Dhcp6MsgType::Decline => dispatch_release_or_decline(pkt, duid, lease_db, true),
        Dhcp6MsgType::InfoReq => dispatch_inforeq(pkt, duid),
        // Relay messages handled separately by relay_dispatch().
        Dhcp6MsgType::RelayForw | Dhcp6MsgType::RelayRepl |
        Dhcp6MsgType::Advertise | Dhcp6MsgType::Reply |
        Dhcp6MsgType::Reconfigure => {
            warn!("Unexpected DHCPv6 message type {:?}", pkt.msg_type);
            None
        }
    }
}

/// Determine where to send a DHCPv6 reply.
///
/// DHCPv6 replies go to the client's link-local address on port 546.
/// If the source address is unspecified, use all-nodes multicast.
///
/// `port_override` substitutes a different reply port, for unprivileged test
/// and harness setups that can't bind the real client port — mirrors
/// [`crate::dhcp::DhcpLoopOptions::reply_port_override`].
pub fn dhcp6_reply_dest(src: SocketAddr, port_override: Option<u16>) -> SocketAddr {
    let port = port_override.unwrap_or(DHCPV6_CLIENT_PORT);
    match src {
        SocketAddr::V6(v6) => {
            SocketAddr::V6(SocketAddrV6::new(*v6.ip(), port, 0, v6.scope_id()))
        }
        _ => {
            // Fallback: all-nodes link-local multicast
            let all_nodes: Ipv6Addr = "ff02::1".parse().unwrap();
            SocketAddr::V6(SocketAddrV6::new(all_nodes, port, 0, 0))
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IPv6 address helpers (ported from dhcp6.c:575-615)
// ─────────────────────────────────────────────────────────────────────────────

/// Extract the lower 64 bits of an IPv6 address (the host part).
fn addr6part(addr: &Ipv6Addr) -> u64 {
    let o = addr.octets();
    u64::from_be_bytes(o[8..16].try_into().unwrap())
}

/// Check if two IPv6 addresses share the same prefix of `prefix_len` bits.
pub fn is_same_net6(a: &Ipv6Addr, b: &Ipv6Addr, prefix_len: i32) -> bool {
    let a_oct = a.octets();
    let b_oct = b.octets();
    let mut remaining = prefix_len as usize;
    for i in 0..16 {
        if remaining == 0 {
            break;
        }
        if remaining >= 8 {
            if a_oct[i] != b_oct[i] {
                return false;
            }
            remaining -= 8;
        } else {
            let mask = 0xFF << (8 - remaining);
            if (a_oct[i] & mask) != (b_oct[i] & mask) {
                return false;
            }
            remaining = 0;
        }
    }
    true
}

/// Check if `addr` can be dynamically allocated from one of the DHCPv6 contexts.
///
/// Returns `true` if addr falls within any non-static context range on the same prefix.
/// Port of `address6_available()` from dhcp6.c:575-599.
pub fn address6_available(contexts: &[crate::types::dhcp::DhcpContext], addr: &Ipv6Addr) -> bool {
    let a = addr6part(addr);
    for ctx in contexts {
        #[cfg(feature = "dhcp6")]
        {
            use crate::types::dhcp::ContextFlags;
            if ctx.flags.intersects(ContextFlags::STATIC | ContextFlags::RA_STATELESS) {
                continue;
            }
            if !is_same_net6(&ctx.start6, addr, ctx.prefix) {
                continue;
            }
            let start = addr6part(&ctx.start6);
            let end = addr6part(&ctx.end6);
            if a >= start && a <= end {
                return true;
            }
        }
    }
    false
}

/// Check if `addr` is valid for any configured DHCPv6 context (static or dynamic).
///
/// Returns `true` if addr is on the same prefix as any context.
/// Port of `address6_valid()` from dhcp6.c:601-615.
pub fn address6_valid(contexts: &[crate::types::dhcp::DhcpContext], addr: &Ipv6Addr) -> bool {
    for ctx in contexts {
        #[cfg(feature = "dhcp6")]
        {
            if is_same_net6(&ctx.start6, addr, ctx.prefix) {
                return true;
            }
        }
    }
    false
}

/// Find a static DHCPv6 host config matching an address.
///
/// Port of `config_find_by_address6()` from dhcp6.c:474-490.
#[cfg(feature = "dhcp6")]
pub fn config_find_by_address6(
    configs: &[crate::types::dhcp::DhcpConfig],
    addr: &Ipv6Addr,
) -> bool {
    use crate::types::addr::AllAddr;
    use crate::types::dhcp::ConfigFlags;
    for config in configs {
        if !config.flags.contains(ConfigFlags::ADDR6) {
            continue;
        }
        for a6 in &config.addr6 {
            if let AllAddr::Addr6(ref v6) = a6.addr {
                if is_same_net6(v6, addr, 128) {
                    return true;
                }
            }
        }
    }
    false
}

// ─────────────────────────────────────────────────────────────────────────────
// DHCPv6 SDBM hash and address allocation (ported from dhcp6.c:492-573)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute 64-bit SDBM hash of a client identifier for DHCPv6 address allocation.
///
/// Seeded with the IAID (Identity Association ID).
/// Port of the hash in dhcp6.c:514-515.
pub fn sdbm_hash64(clid: &[u8], iaid: u32) -> u64 {
    let mut j: u64 = iaid as u64;
    for &b in clid {
        j = (b as u64)
            .wrapping_add(j.wrapping_shl(6))
            .wrapping_add(j.wrapping_shl(16))
            .wrapping_sub(j);
    }
    j
}

/// Calculate the starting IPv6 host-part for allocation using hash-based seeding.
///
/// Maps the hash into the range [start6_low64, end6_low64] using modular arithmetic.
/// Port of the address calculation in dhcp6.c:536-544.
pub fn hash_to_addr6(hash: u64, epoch: u32, start_low: u64, end_low: u64) -> u64 {
    let range = end_low.wrapping_sub(start_low).wrapping_add(1);
    let offset = hash.wrapping_add(epoch as u64);
    if range == 0 {
        // Full 2^64 range — don't divide by zero
        start_low.wrapping_add(offset)
    } else {
        start_low.wrapping_add(offset % range)
    }
}

/// Replace the low 64 bits (host part) of `base` with `host`, keeping its
/// upper (network) bits. Inverse of `addr6part`.
fn addr6_with_host(base: &Ipv6Addr, host: u64) -> Ipv6Addr {
    let mut octets = base.octets();
    octets[8..16].copy_from_slice(&host.to_be_bytes());
    Ipv6Addr::from(octets)
}

/// Allocate a free IPv6 address from a context chain for a client.
///
/// `contexts` should be the "current" chain for the packet's arrival
/// interface (e.g. built by [`complete_context6`]). Contexts flagged
/// `CONTEXT_DEPRECATE`/`CONTEXT_STATIC`/`CONTEXT_RA_STATELESS`/`CONTEXT_USED`
/// are skipped, as is any context whose `filter` doesn't match `netids`
/// (empty `filter` matches everyone). For each remaining context, computes a
/// hash-seeded starting offset ([`sdbm_hash64`]/[`hash_to_addr6`]) and scans
/// the whole range once, wrapping around, for an address that collides with
/// neither another context's own `local6` address, nor `in_use` (leases and
/// static `--dhcp-host` reservations).
///
/// Single-pass only: upstream's two-pass `plain_range` fallback (try
/// netid-matching contexts first, then fall back to any context) is not
/// ported — see `tasks.md`. Upstream's `--consec-addresses` seeding mode is
/// likewise not ported; only the hash-seeded mode is.
///
/// Port of `address6_allocate()` (dhcp6.c:492-573).
pub fn address6_allocate(
    contexts: &[crate::types::dhcp::DhcpContext],
    clid: &[u8],
    iaid: u32,
    netids: &[DhcpNetid],
    in_use: &mut dyn FnMut(&Ipv6Addr) -> bool,
) -> Option<Ipv6Addr> {
    use crate::types::dhcp::ContextFlags;

    let hash = sdbm_hash64(clid, iaid);

    for ctx in contexts {
        if ctx.flags.intersects(ContextFlags::DEPRECATE | ContextFlags::STATIC | ContextFlags::RA_STATELESS | ContextFlags::USED) {
            continue;
        }
        if !ctx.filter.is_empty() && !crate::dhcp_common::match_netid(&ctx.filter, netids) {
            continue;
        }

        let start = addr6part(&ctx.start6);
        let end = addr6part(&ctx.end6);
        let start_addr = hash_to_addr6(hash, ctx.addr_epoch, start, end);

        let mut addr = start_addr;
        loop {
            let candidate = addr6_with_host(&ctx.start6, addr);

            let collides_with_server = contexts.iter().any(|d| addr6part(&d.local6) == addr);
            if !collides_with_server && !in_use(&candidate) {
                return Some(candidate);
            }

            addr = if addr == end { start } else { addr.wrapping_add(1) };
            if addr == start_addr {
                break;
            }
        }
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Live-interface context matching (ported from dhcp6.c:352-420)
// ─────────────────────────────────────────────────────────────────────────────

/// Classification of an address seen on an interface.
///
/// Loopback/link-local/multicast addresses never participate in context
/// matching (dhcp6.c:371-374). ULA is called out separately because upstream
/// records it into a dedicated `param->ula_addr` local (dhcp6.c:370) for
/// later use as a DNS-server-option fallback distinct from a link-local or
/// global address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Addr6Class {
    Loopback,
    LinkLocal,
    Ula,
    Multicast,
    Global,
}

/// Classify an address the way `complete_context6()` does (dhcp6.c:367-374).
pub fn classify_addr6(addr: &Ipv6Addr) -> Addr6Class {
    if addr.is_loopback() {
        Addr6Class::Loopback
    } else if crate::network::is_link_local_v6(*addr) {
        Addr6Class::LinkLocal
    } else if addr.is_multicast() {
        Addr6Class::Multicast
    } else if crate::network::is_ula_v6(*addr) {
        Addr6Class::Ula
    } else {
        Addr6Class::Global
    }
}

/// One address discovered on the packet's arrival interface — the subset of
/// upstream's `iface_enumerate(AF_INET6, ..., complete_context6)` callback
/// arguments that plain (non-shared-network) context matching needs.
#[derive(Debug, Clone)]
pub struct LiveAddr6 {
    pub addr:      Ipv6Addr,
    pub prefix:    i32,
    pub if_index:  u32,
    /// Kernel-reported preferred/valid lifetimes for this address.
    pub preferred: u32,
    pub valid:     u32,
    /// Upstream's `IFACE_DEPRECATED` interface flag.
    pub deprecated: bool,
}

/// Build the ordered "current" context chain for one live interface address,
/// filling in `local6`/`preferred`/`valid`/`if_index` on each match.
///
/// Restricted to the plain (non-shared-network) branch of `complete_context6`
/// (dhcp6.c:388-420); shared-network matching and DHCPv6-relay
/// `iface_index`/duplicate-warning bookkeeping (dhcp6.c:421-460) are not
/// ported — see `tasks.md`. Loopback/link-local/multicast addresses never
/// match (dhcp6.c:371-374).
///
/// Returns the chain ordered longest-preferred-time first, matching
/// upstream's linked-list insertion (dhcp6.c:405-412).
///
/// Port of `complete_context6()` (dhcp6.c:352-420).
pub fn complete_context6(
    live: &LiveAddr6,
    contexts: &[crate::types::dhcp::DhcpContext],
) -> Vec<crate::types::dhcp::DhcpContext> {
    use crate::types::dhcp::ContextFlags;

    if matches!(
        classify_addr6(&live.addr),
        Addr6Class::Loopback | Addr6Class::LinkLocal | Addr6Class::Multicast
    ) {
        return Vec::new();
    }

    let mut current: Vec<crate::types::dhcp::DhcpContext> = Vec::new();
    for ctx in contexts {
        if !ctx.flags.contains(ContextFlags::DHCP) {
            continue;
        }
        if ctx.flags.intersects(ContextFlags::TEMPLATE | ContextFlags::OLD) {
            continue;
        }
        if live.prefix > ctx.prefix {
            continue;
        }
        if !is_same_net6(&live.addr, &ctx.start6, ctx.prefix)
            || !is_same_net6(&live.addr, &ctx.end6, ctx.prefix)
        {
            continue;
        }

        // "use interface values only for constructed contexts"
        let (mut preferred, valid) = if !ctx.flags.contains(ContextFlags::CONSTRUCTED) {
            (0xffff_ffffu32, 0xffff_ffffu32)
        } else {
            let p = if live.deprecated { 0 } else { live.preferred };
            (p, live.valid)
        };
        if ctx.flags.contains(ContextFlags::DEPRECATE) {
            preferred = 0;
        }

        let mut matched = ctx.clone();
        matched.local6 = live.addr;
        matched.preferred = preferred;
        matched.valid = valid;
        matched.if_index = live.if_index as i32;

        let pos = current.iter().position(|c| c.preferred <= preferred).unwrap_or(current.len());
        current.insert(pos, matched);
    }
    current
}

/// Fill in `if_index`/`local6` on plain (non-template) DHCPv6 contexts whose
/// prefix matches a live interface address, mutating them in place.
///
/// Port of the non-template branch of `construct_worker()` (dhcp6.c:730-748),
/// called from `dhcp_construct_contexts()` via
/// `iface_enumerate(AF_INET6, ..., construct_worker)`. The other branch —
/// constructing brand-new contexts from a
/// `--dhcp-range=...,constructor:IFACE,...` template — needs a
/// `template_interface` field on `DhcpContext` and `constructor:` config
/// parsing that don't exist yet in this crate (see `tasks.md`); template
/// (`CONTEXT_TEMPLATE`) and already-constructed (`CONTEXT_CONSTRUCTED`)
/// contexts are left untouched here, same as fast-RA kickoff and GC aging of
/// constructed contexts whose interface/prefix has disappeared.
pub fn dhcp_construct_contexts(
    contexts: &mut [crate::types::dhcp::DhcpContext],
    live_addrs: &[LiveAddr6],
) {
    use crate::types::dhcp::ContextFlags;

    for live in live_addrs {
        if matches!(
            classify_addr6(&live.addr),
            Addr6Class::Loopback | Addr6Class::LinkLocal | Addr6Class::Multicast
        ) {
            continue;
        }
        for ctx in contexts.iter_mut() {
            if ctx.flags.intersects(ContextFlags::TEMPLATE | ContextFlags::CONSTRUCTED) {
                continue;
            }
            if live.prefix <= ctx.prefix
                && is_same_net6(&live.addr, &ctx.start6, ctx.prefix)
                && is_same_net6(&live.addr, &ctx.end6, ctx.prefix)
            {
                ctx.if_index = live.if_index as i32;
                ctx.local6 = live.addr;
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DUID generation (ported from dhcp6.c:617-689)
// ─────────────────────────────────────────────────────────────────────────────

/// DUID type codes (RFC 3315 §9.1-9.3).
pub const DUID_LLT: u16 = 1;
pub const DUID_EN:  u16 = 2;
pub const DUID_LL:  u16 = 3;

/// The 2000-01-01 epoch offset upstream rebases DUID-LLT timestamps to
/// (`dhcp6.c:635`: `newnow = now - 946684800`).
pub const DUID_EPOCH_OFFSET: u64 = 946_684_800;

/// Build a DUID-EN (type 2): enterprise-assigned identifier.
/// Wire format: `type(2) | enterprise-number(4) | identifier(N)`.
/// Port of the `daemon->duid_config` branch of `make_duid()` (dhcp6.c:621-627).
pub fn build_duid_en(enterprise: u32, id: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(6 + id.len());
    buf.extend_from_slice(&DUID_EN.to_be_bytes());
    buf.extend_from_slice(&enterprise.to_be_bytes());
    buf.extend_from_slice(id);
    buf
}

/// Build a DUID-LLT (type 1): link-layer address plus a 2000-epoch timestamp.
/// Wire format: `type(2) | hw-type(2) | time(4) | link-layer-address(N)`.
/// Port of `make_duid1()`'s `newnow != 0` branch (dhcp6.c:658-666).
pub fn build_duid_llt(hw_type: u16, mac: &[u8], time_secs: u32) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + mac.len());
    buf.extend_from_slice(&DUID_LLT.to_be_bytes());
    buf.extend_from_slice(&hw_type.to_be_bytes());
    buf.extend_from_slice(&time_secs.to_be_bytes());
    buf.extend_from_slice(mac);
    buf
}

/// Build a DUID-LL (type 3): link-layer address only, no timestamp. Used
/// when there's no persistent lease database or the RTC isn't trusted.
/// Wire format: `type(2) | hw-type(2) | link-layer-address(N)`.
/// Port of `make_duid1()`'s `newnow == 0` branch (dhcp6.c:650-656).
pub fn build_duid_ll(hw_type: u16, mac: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + mac.len());
    buf.extend_from_slice(&DUID_LL.to_be_bytes());
    buf.extend_from_slice(&hw_type.to_be_bytes());
    buf.extend_from_slice(mac);
    buf
}

/// A MAC address discovered by enumerating live interfaces, input to
/// [`make_duid`]'s DUID-LL/DUID-LLT fallback. `hw_type` is the kernel's
/// ARPHRD_* hardware type; upstream skips anything `>= 256` (tunnels and
/// other MAC-less link types), which this module's caller is expected to
/// have already filtered before selecting a source (mirrors
/// `make_duid1()`'s own `type >= 256` check, dhcp6.c:653).
#[derive(Debug, Clone)]
pub struct DuidMacSource {
    pub hw_type: u16,
    pub mac:     Vec<u8>,
}

/// Generate and store the server's DHCPv6 DUID into `daemon.duid`.
///
/// If `--dhcp-duid=` configured an enterprise number and id
/// (`daemon.duid_config`), builds a DUID-EN from it. Otherwise builds a
/// DUID-LLT (`use_llt`, upstream's persistent-lease-DB-or-stable-RTC case)
/// or a DUID-LL from `mac_source`, the first eligible interface MAC
/// discovered by the caller (production wiring enumerates live interfaces
/// via netlink `AF_LOCAL`; tests inject a fixed MAC).
///
/// Returns `Err` if no DUID could be built at all — upstream calls
/// `die(EC_MISC)` in this case (dhcp6.c:643).
///
/// Port of `make_duid()`/`make_duid1()` (dhcp6.c:617-689).
pub fn make_duid(
    daemon: &mut Daemon,
    mac_source: Option<DuidMacSource>,
    use_llt: bool,
    now_secs: u64,
) -> Result<(), &'static str> {
    if let Some(id) = &daemon.duid_config {
        daemon.duid = Some(build_duid_en(daemon.duid_enterprise, id));
        return Ok(());
    }

    let Some(src) = mac_source else {
        return Err("Cannot create DHCPv6 server DUID: no interface with a usable MAC address");
    };
    if src.hw_type >= 256 {
        return Err("Cannot create DHCPv6 server DUID: no interface with a usable MAC address");
    }

    daemon.duid = Some(if use_llt {
        let epoch_time = now_secs.saturating_sub(DUID_EPOCH_OFFSET) as u32;
        build_duid_llt(src.hw_type, &src.mac, epoch_time)
    } else {
        build_duid_ll(src.hw_type, &src.mac)
    });
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Socket init (ported from dhcp6.c:35-88)
// ─────────────────────────────────────────────────────────────────────────────

/// Bind the DHCPv6 server UDP socket to `[::]:547`.
///
/// Uses [`crate::network::make_sock`], which already sets `IPV6_V6ONLY`,
/// `SO_REUSEADDR`, and (for UDP IPv6 sockets) `IPV6_RECVPKTINFO` — mirroring
/// upstream's own socket setup. `nowild` is `--bind-interfaces`
/// (`OPT_NOWILD`), same meaning as `make_sock`'s parameter.
///
/// Does not join the `ALL_DHCP_RELAY_AGENTS_AND_SERVERS` (FF02::1:2) /
/// `ALL_DHCP_SERVERS` (FF05::1:3) multicast groups: upstream's
/// `dhcp6_init()` doesn't either (dhcp6.c:35-88) — it relies on a wildcard
/// bind plus per-interface `join_multicast()` in `network.c`, which this
/// crate does not yet port (see `tasks.md`).
///
/// Port of `dhcp6_init()` (dhcp6.c:35-88).
#[cfg(unix)]
pub fn dhcp6_init(nowild: bool) -> std::io::Result<std::os::unix::io::RawFd> {
    use crate::network::{make_sock, SockType};

    let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, DHCPV6_SERVER_PORT, 0, 0));
    make_sock(addr, SockType::Udp, nowild)
}

// ─────────────────────────────────────────────────────────────────────────────
// Receive/dispatch loop (ported from dhcp6.c:89-306, receive-loop portion)
// ─────────────────────────────────────────────────────────────────────────────

/// Run the DHCPv6 receive/dispatch loop over an already-bound `[::]:547` socket.
///
/// `contexts` is the "current" chain [`complete_context6`] builds from live
/// interface prefixes — production callers build this once at startup via
/// [`dhcp_construct_contexts`]/[`complete_context6`]. This loop does not
/// re-derive that chain per packet against the packet's arrival interface the
/// way upstream's `dhcp6_packet()` does (dhcp6.c:89-306); see `tasks.md`.
///
/// Lease persistence now happens inside [`dispatch_dhcp6`] itself (each
/// message-type handler calls `persist_lease`/`LeaseDb::remove_v6_*`
/// directly), not as a post-processing step here — matching upstream, where
/// `update_leases()` is called from inside the per-message-type branches of
/// `dhcp6_reply()`, not after it returns. `lease_db` is kept in-memory only
/// by this loop: it does not load or write a shared `--dhcp-leasefile` —
/// doing that safely needs one writer for the file the IPv4 loop already
/// owns, not two independent in-memory copies of it (see `tasks.md`).
///
/// `authoritative` mirrors `--dhcp-authoritative` (`OPT_AUTHORITATIVE`).
///
/// Port of the receive-loop portion of `dhcp6_packet()` (dhcp6.c:89-306),
/// wired to the real [`dispatch_dhcp6`] pipeline.
pub async fn run_dhcp6_loop(
    socket: Arc<tokio::net::UdpSocket>,
    duid: Vec<u8>,
    contexts: Vec<DhcpContext>,
    configs: Vec<DhcpConfig>,
    mut lease_db: LeaseDb,
    authoritative: bool,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    reply_port_override: Option<u16>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; 1500];

    // SLAAC DAD probing (slaac.c:119-213) needs a nonzero, process-lifetime
    // `ping_id` (matching the `while (ping_id == 0) ping_id = rand16();` at
    // slaac.c:134-135) and a raw ICMPv6 socket, which requires `CAP_NET_RAW`.
    // Probing is disabled — not a hard failure — when the process lacks it;
    // "DAD probing works where permissions allow" is the acceptance bar, not
    // "DHCPv6 startup requires it".
    let mut ping_id: u16 = crate::util::rand16();
    while ping_id == 0 {
        ping_id = crate::util::rand16();
    }
    let icmp6 = match crate::slaac::Icmp6Socket::create() {
        Ok(s) => Some(s),
        Err(e) => {
            debug!("SLAAC DAD probing disabled (no ICMPv6 raw socket: {e})");
            None
        }
    };
    let mut slaac_probe_tick = tokio::time::interval(std::time::Duration::from_secs(1));
    let mut icmp6_buf = [0u8; 1500];

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow() => return Ok(()),
                    Ok(()) => continue,
                    Err(_) => return Ok(()),
                }
            }
            recv = socket.recv_from(&mut buf) => {
                let (len, src) = recv?;
                let Ok(pkt) = parse_dhcp6_packet(&buf[..len]) else {
                    debug!("ignoring malformed or relay DHCPv6 packet from {src}");
                    continue;
                };

                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let reply = dispatch_dhcp6(&pkt, &duid, &contexts, &configs, &mut lease_db, authoritative, now_secs);

                // Port of the `lease_set_hwaddr()` -> `slaac_add_addrs()` call
                // chain (lease.c:992-993), applied across the whole lease set
                // rather than the single lease `lease_set_hwaddr` targets —
                // this port's DHCPv4 commit path does not yet thread
                // `daemon->dhcp6` contexts down to `LeaseDb::set_hwaddr`
                // itself (see `tasks.md`), so this is the nearest production
                // call site that actually has both a fresh lease commit and
                // the live RA-name context chain in scope. The RA-trigger
                // callback is a documented no-op: production RA scheduling
                // has no main-loop caller yet either (`tasks.md`, `radv.rs`).
                lease_db.refresh_slaac(std::time::SystemTime::now(), &contexts, false, |_ctx| {});

                let Some(reply) = reply else { continue };

                let dest = dhcp6_reply_dest(src, reply_port_override);
                if let Err(e) = socket.send_to(&reply.to_wire(), dest).await {
                    warn!("failed to send DHCPv6 reply to {dest}: {e}");
                }
            }
            _ = slaac_probe_tick.tick(), if icmp6.is_some() => {
                let sock = icmp6.as_ref().unwrap();
                lease_db.tick_slaac(std::time::SystemTime::now(), &contexts, ping_id, |dest, packet| {
                    sock.send_echo_sync(dest, packet)
                });
            }
            recv6 = icmp6_recv(&icmp6, &mut icmp6_buf), if icmp6.is_some() => {
                match recv6 {
                    Ok((n, sender)) => {
                        lease_db.confirm_slaac_ping(sender, &icmp6_buf[..n], ping_id, "", false);
                    }
                    Err(e) => debug!("SLAAC DAD probe ICMPv6 recv error: {e}"),
                }
            }
        }
    }
}

/// Await a receive on `icmp6` when present. Only ever polled from the
/// `tokio::select!` arm guarded by `icmp6.is_some()`, so the `unwrap()` here
/// never fires in practice.
async fn icmp6_recv(
    icmp6: &Option<crate::slaac::Icmp6Socket>,
    buf: &mut [u8],
) -> std::io::Result<(usize, Ipv6Addr)> {
    icmp6.as_ref().unwrap().recv(buf).await
}

// ─────────────────────────────────────────────────────────────────────────────
// Client MAC resolution (ported from dhcp6.c:307-348)
// ─────────────────────────────────────────────────────────────────────────────

/// Resolve and log the DHCPv6 client's link-layer (MAC) address for `client`.
///
/// Port of `get_client_mac()` (`dhcp6.c:307-348`), minus the active
/// neighbour-discovery probe: C retries up to 5 times, sending an ICMPv6
/// Neighbour Solicitation to `client` and sleeping 100ms between attempts,
/// to populate the kernel's neighbour cache for a host that hasn't sent
/// traffic recently (`daemon->icmp6fd`). This port has no ICMPv6 socket
/// wired up, so it only consults whatever [`crate::arp::find_mac`] can
/// resolve from the kernel's *existing* neighbour table — tracked as a
/// deliberate deviation in `tasks.md`.
///
/// Called from `rfc3315.c:132,2166` upstream to populate `state->mac`; this
/// port's DHCPv6 request-handling path (`handle_solicit`/`handle_request6`
/// in `rfc3315.rs`) has no client-MAC field to populate yet either, so this
/// function currently has no live caller — it's ready to be wired in once
/// that state-carrying integration lands.
#[cfg(target_os = "linux")]
pub fn get_client_mac(
    daemon: &crate::types::daemon::Daemon,
    client: Ipv6Addr,
    now: u64,
) -> Option<Vec<u8>> {
    let mac = crate::arp::find_mac_for_daemon(daemon, std::net::IpAddr::V6(client), false, now);
    if let Some(ref m) = mac {
        debug!("DHCPv6 client {client} resolved to MAC {}", crate::util::print_mac(m));
    }
    mac
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::dhcp::ContextFlags;

    fn solicit_pkt(xid: u32) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(Dhcp6MsgType::Solicit as u8);
        v.push(((xid >> 16) & 0xFF) as u8);
        v.push(((xid >>  8) & 0xFF) as u8);
        v.push(( xid        & 0xFF) as u8);
        v
    }

    /// A Solicit with a CLIENT_ID and an empty (no sub-options) IA_NA, the
    /// minimum a real client sends to request an address.
    fn solicit_with_ia(xid: u32, iaid: [u8; 4]) -> Vec<u8> {
        let mut v = solicit_pkt(xid);
        v.extend_from_slice(&OPTION6_CLIENT_ID.to_be_bytes());
        v.extend_from_slice(&4u16.to_be_bytes());
        v.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        v.extend_from_slice(&OPTION6_IA_NA.to_be_bytes());
        v.extend_from_slice(&12u16.to_be_bytes());
        v.extend_from_slice(&iaid);
        v.extend_from_slice(&0u32.to_be_bytes()); // T1
        v.extend_from_slice(&0u32.to_be_bytes()); // T2
        v
    }

    #[test]
    fn parse_solicit_ok() {
        let data = solicit_pkt(0xABCD12);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        assert_eq!(pkt.msg_type, Dhcp6MsgType::Solicit);
        assert_eq!(pkt.xid, 0xABCD12);
    }

    #[test]
    fn parse_short_returns_err() {
        assert!(parse_dhcp6_packet(&[1, 2, 3]).is_err());
    }

    #[test]
    fn parse_unknown_type_returns_err() {
        assert!(parse_dhcp6_packet(&[0xFF, 0, 0, 0]).is_err());
    }

    #[test]
    fn solicit_dispatches_to_advertise() {
        let data = solicit_pkt(0x1234);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut db = LeaseDb::new();
        let reply = dispatch_dhcp6(&pkt, &duid, &[], &[], &mut db, false, 0);
        assert!(reply.is_some());
        assert_eq!(reply.unwrap().msg_type, Dhcp6MsgType::Advertise);
    }

    #[test]
    fn request_dispatches_to_reply() {
        let mut data = solicit_pkt(0x5678);
        data[0] = Dhcp6MsgType::Request as u8;
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03, 0x00, 0x01, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let mut db = LeaseDb::new();
        let reply = dispatch_dhcp6(&pkt, &duid, &[], &[], &mut db, false, 0);
        assert_eq!(reply.unwrap().msg_type, Dhcp6MsgType::Reply);
    }

    #[test]
    fn find_option6_present() {
        // Build an option buffer with option code 1, length 2, value [0xAB, 0xCD]
        let opts = [0, 1, 0, 2, 0xAB, 0xCD, 0, 2, 0, 1, 0xFF];
        let val = find_option6(&opts, 1).unwrap();
        assert_eq!(val, &[0xAB, 0xCD]);
    }

    #[test]
    fn find_option6_missing() {
        let opts = [0, 1, 0, 2, 0xAB, 0xCD];
        assert!(find_option6(&opts, 99).is_none());
    }

    #[test]
    fn reply_to_wire_roundtrip() {
        let reply = Dhcp6Reply {
            msg_type: Dhcp6MsgType::Advertise,
            xid:      0xAABBCC,
            options:  vec![0x00, 0x01, 0x00, 0x00], // empty option 1
        };
        let wire = reply.to_wire();
        assert_eq!(wire[0], Dhcp6MsgType::Advertise as u8);
        assert_eq!(wire[1], 0xAA);
        assert_eq!(wire[2], 0xBB);
        assert_eq!(wire[3], 0xCC);
    }

    #[test]
    fn parse_relay_forw() {
        let mut data = vec![0u8; 34];
        data[0] = Dhcp6MsgType::RelayForw as u8;
        data[1] = 5; // hop count
        // link_addr and peer_addr are all zeros
        let result = parse_dhcp6_packet(&data);
        assert!(result.is_err());
        let relay = result.err().unwrap().unwrap();
        assert_eq!(relay.msg_type, Dhcp6MsgType::RelayForw);
        assert_eq!(relay.hop_count, 5);
    }

    // ── is_same_net6 ─────────────────────────────────────────────────────────

    #[test]
    fn is_same_net6_same_prefix() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::ffff".parse().unwrap();
        assert!(is_same_net6(&a, &b, 64));
    }

    #[test]
    fn is_same_net6_different_prefix() {
        let a: Ipv6Addr = "2001:db8:1::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8:2::1".parse().unwrap();
        assert!(!is_same_net6(&a, &b, 48));
    }

    #[test]
    fn is_same_net6_exact_match() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(is_same_net6(&a, &b, 128));
    }

    #[test]
    fn is_same_net6_exact_mismatch() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "2001:db8::2".parse().unwrap();
        assert!(!is_same_net6(&a, &b, 128));
    }

    #[test]
    fn is_same_net6_zero_prefix() {
        let a: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let b: Ipv6Addr = "fe80::1".parse().unwrap();
        assert!(is_same_net6(&a, &b, 0));
    }

    // ── addr6part ────────────────────────────────────────────────────────────

    #[test]
    fn addr6part_extracts_low64() {
        let a: Ipv6Addr = "2001:db8::42".parse().unwrap();
        assert_eq!(addr6part(&a), 0x42);
    }

    #[test]
    fn addr6part_max() {
        let a: Ipv6Addr = "::ffff:ffff:ffff:ffff".parse().unwrap();
        assert_eq!(addr6part(&a), u64::MAX);
    }

    // ── address6_available / address6_valid ───────────────────────────────────

    #[cfg(feature = "dhcp6")]
    fn make_v6_ctx(start6: Ipv6Addr, end6: Ipv6Addr, prefix: i32, flags: crate::types::dhcp::ContextFlags) -> crate::types::dhcp::DhcpContext {
        use std::net::Ipv4Addr;
        crate::types::dhcp::DhcpContext {
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            flags,
            netmask: Ipv4Addr::new(0,0,0,0),
            broadcast: Ipv4Addr::new(0,0,0,0),
            local: Ipv4Addr::new(0,0,0,0),
            lease_time: 3600,
            addr_epoch: 0,
            netid: crate::types::dhcp::DhcpNetid { net: String::new() },
            filter: vec![],
            start6,
            end6,
            local6: Ipv6Addr::UNSPECIFIED,
            prefix,
            if_index: 0,
            valid: 0,
            preferred: 0,
            ra_time: 0,
            ra_short_period_start: 0,
            saved_valid: 0,
            address_lost_time: 0,
        }
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_available_in_range() {
        let ctx = make_v6_ctx(
            "2001:db8::100".parse().unwrap(),
            "2001:db8::200".parse().unwrap(),
            64, ContextFlags::empty(),
        );
        assert!(address6_available(&[ctx], &"2001:db8::150".parse().unwrap()));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_available_out_of_range() {
        let ctx = make_v6_ctx(
            "2001:db8::100".parse().unwrap(),
            "2001:db8::200".parse().unwrap(),
            64, ContextFlags::empty(),
        );
        assert!(!address6_available(&[ctx], &"2001:db8::50".parse().unwrap()));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_available_skips_static() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8::100".parse().unwrap(),
            "2001:db8::200".parse().unwrap(),
            64, ContextFlags::STATIC,
        );
        assert!(!address6_available(&[ctx], &"2001:db8::150".parse().unwrap()));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_valid_on_prefix() {
        let ctx = make_v6_ctx(
            "2001:db8::100".parse().unwrap(),
            "2001:db8::200".parse().unwrap(),
            64, ContextFlags::empty(),
        );
        assert!(address6_valid(&[ctx], &"2001:db8::999".parse().unwrap()));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn address6_valid_wrong_prefix() {
        let ctx = make_v6_ctx(
            "2001:db8:1::100".parse().unwrap(),
            "2001:db8:1::200".parse().unwrap(),
            48, ContextFlags::empty(),
        );
        assert!(!address6_valid(&[ctx], &"2001:db8:2::1".parse().unwrap()));
    }

    // ── sdbm_hash64 ─────────────────────────────────────────────────────────

    #[test]
    fn sdbm_hash64_deterministic() {
        let clid = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(sdbm_hash64(&clid, 1), sdbm_hash64(&clid, 1));
    }

    #[test]
    fn sdbm_hash64_different_clids_differ() {
        let h1 = sdbm_hash64(&[0x01, 0x02], 1);
        let h2 = sdbm_hash64(&[0xAA, 0xBB], 1);
        assert_ne!(h1, h2);
    }

    #[test]
    fn sdbm_hash64_different_iaids_differ() {
        let clid = [0x01, 0x02, 0x03];
        assert_ne!(sdbm_hash64(&clid, 1), sdbm_hash64(&clid, 2));
    }

    // ── hash_to_addr6 ────────────────────────────────────────────────────────

    #[test]
    fn hash_to_addr6_in_range() {
        let start = 0x100u64;
        let end = 0x200u64;
        let result = hash_to_addr6(42, 0, start, end);
        assert!(result >= start && result <= end);
    }

    #[test]
    fn hash_to_addr6_single_address() {
        let result = hash_to_addr6(999, 0, 0x42, 0x42);
        assert_eq!(result, 0x42);
    }

    #[test]
    fn hash_to_addr6_epoch_shifts() {
        let a1 = hash_to_addr6(42, 0, 0x100, 0x200);
        let a2 = hash_to_addr6(42, 1, 0x100, 0x200);
        assert_ne!(a1, a2);
    }

    #[test]
    fn hash_to_addr6_full_range() {
        // Full 2^64 range should not panic
        let result = hash_to_addr6(42, 0, 0, u64::MAX);
        // Just verify it doesn't panic
        let _ = result;
    }

    // ── address6_allocate ──────────────────────────────────────────────────────

    #[test]
    fn address6_allocate_finds_free_address() {
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
            64, ContextFlags::empty(),
        );
        let mut in_use = |_: &Ipv6Addr| false;
        let addr = address6_allocate(&[ctx], &[0x01, 0x02], 1, &[], &mut in_use);
        assert!(addr.is_some());
        let a = addr.unwrap();
        assert!(is_same_net6(&a, &"2001:db8::1".parse().unwrap(), 64));
    }

    #[test]
    fn address6_allocate_skips_collision_and_finds_next() {
        let start: Ipv6Addr = "2001:db8::1".parse().unwrap();
        let end: Ipv6Addr = "2001:db8::10".parse().unwrap();
        let ctx = make_v6_ctx(start, end, 64, ContextFlags::empty());
        let clid = [0x01, 0x02];
        let iaid = 1u32;

        let hash = sdbm_hash64(&clid, iaid);
        let predicted_host = hash_to_addr6(hash, 0, addr6part(&start), addr6part(&end));
        let predicted = addr6_with_host(&start, predicted_host);

        let mut in_use = |a: &Ipv6Addr| *a == predicted;
        let addr = address6_allocate(&[ctx], &clid, iaid, &[], &mut in_use).unwrap();
        assert_ne!(addr, predicted);
    }

    #[test]
    fn address6_allocate_skips_static_context() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::10".parse().unwrap(),
            64, ContextFlags::STATIC,
        );
        let mut in_use = |_: &Ipv6Addr| false;
        assert!(address6_allocate(&[ctx], &[0x01], 1, &[], &mut in_use).is_none());
    }

    #[test]
    fn address6_allocate_returns_none_when_full() {
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            128, ContextFlags::empty(),
        );
        let mut in_use = |_: &Ipv6Addr| true;
        assert!(address6_allocate(&[ctx], &[0x01], 1, &[], &mut in_use).is_none());
    }

    #[test]
    fn address6_allocate_skips_server_own_local6() {
        let mut ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            128, ContextFlags::empty(),
        );
        ctx.local6 = "2001:db8::1".parse().unwrap();
        let mut in_use = |_: &Ipv6Addr| false;
        assert!(address6_allocate(&[ctx], &[0x01], 1, &[], &mut in_use).is_none());
    }

    // ── classify_addr6 ────────────────────────────────────────────────────────

    #[test]
    fn classify_addr6_loopback() {
        assert_eq!(classify_addr6(&"::1".parse().unwrap()), Addr6Class::Loopback);
    }

    #[test]
    fn classify_addr6_link_local() {
        assert_eq!(classify_addr6(&"fe80::1".parse().unwrap()), Addr6Class::LinkLocal);
    }

    #[test]
    fn classify_addr6_ula() {
        assert_eq!(classify_addr6(&"fc00::1".parse().unwrap()), Addr6Class::Ula);
        assert_eq!(classify_addr6(&"fd00::1".parse().unwrap()), Addr6Class::Ula);
    }

    #[test]
    fn classify_addr6_multicast() {
        assert_eq!(classify_addr6(&"ff02::1".parse().unwrap()), Addr6Class::Multicast);
    }

    #[test]
    fn classify_addr6_global() {
        assert_eq!(classify_addr6(&"2001:db8::1".parse().unwrap()), Addr6Class::Global);
    }

    // ── complete_context6 ─────────────────────────────────────────────────────

    #[test]
    fn complete_context6_matches_and_fills_fields() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8:1::".parse().unwrap(),
            "2001:db8:1::ffff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        let live = LiveAddr6 {
            addr: "2001:db8:1::1".parse().unwrap(),
            prefix: 64,
            if_index: 3,
            preferred: 500,
            valid: 1000,
            deprecated: false,
        };
        let chain = complete_context6(&live, &[ctx]);
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].local6, live.addr);
        assert_eq!(chain[0].if_index, 3);
        // Not CONTEXT_CONSTRUCTED -> infinite lifetimes (dhcp6.c:401-402).
        assert_eq!(chain[0].preferred, 0xffff_ffff);
        assert_eq!(chain[0].valid, 0xffff_ffff);
    }

    #[test]
    fn complete_context6_constructed_uses_interface_lifetimes() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8:1::".parse().unwrap(),
            "2001:db8:1::ffff".parse().unwrap(),
            64, ContextFlags::DHCP | ContextFlags::CONSTRUCTED,
        );
        let live = LiveAddr6 {
            addr: "2001:db8:1::1".parse().unwrap(),
            prefix: 64,
            if_index: 3,
            preferred: 500,
            valid: 1000,
            deprecated: false,
        };
        let chain = complete_context6(&live, &[ctx]);
        assert_eq!(chain[0].preferred, 500);
        assert_eq!(chain[0].valid, 1000);
    }

    #[test]
    fn complete_context6_skips_link_local() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "fe80::".parse().unwrap(),
            "fe80::ffff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        let live = LiveAddr6 {
            addr: "fe80::1".parse().unwrap(),
            prefix: 64, if_index: 1, preferred: 100, valid: 100, deprecated: false,
        };
        assert!(complete_context6(&live, &[ctx]).is_empty());
    }

    #[test]
    fn complete_context6_orders_by_preferred_descending() {
        use crate::types::dhcp::ContextFlags;
        let ctx_a = make_v6_ctx(
            "2001:db8:1::".parse().unwrap(), "2001:db8:1::ffff".parse().unwrap(),
            64, ContextFlags::DHCP | ContextFlags::CONSTRUCTED,
        );
        let ctx_b = make_v6_ctx(
            "2001:db8:1::".parse().unwrap(), "2001:db8:1::ffff".parse().unwrap(),
            64, ContextFlags::DHCP | ContextFlags::CONSTRUCTED,
        );
        let live = LiveAddr6 {
            addr: "2001:db8:1::1".parse().unwrap(),
            prefix: 64, if_index: 1, preferred: 100, valid: 200, deprecated: false,
        };
        // Both contexts match identically here; verify the chain is built
        // (ordering degenerates to insertion order on ties, matching upstream).
        let chain = complete_context6(&live, &[ctx_a, ctx_b]);
        assert_eq!(chain.len(), 2);
        assert!(chain[0].preferred >= chain[1].preferred);
    }

    // ── dhcp_construct_contexts ───────────────────────────────────────────────

    #[test]
    fn dhcp_construct_contexts_fills_if_index_and_local6() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8::".parse().unwrap(), "2001:db8::ffff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        let mut contexts = vec![ctx];
        let live = LiveAddr6 {
            addr: "2001:db8::42".parse().unwrap(),
            prefix: 64, if_index: 7, preferred: 100, valid: 200, deprecated: false,
        };
        dhcp_construct_contexts(&mut contexts, &[live.clone()]);
        assert_eq!(contexts[0].if_index, 7);
        assert_eq!(contexts[0].local6, live.addr);
    }

    #[test]
    fn dhcp_construct_contexts_skips_template_contexts() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8::".parse().unwrap(), "2001:db8::ffff".parse().unwrap(),
            64, ContextFlags::DHCP | ContextFlags::TEMPLATE,
        );
        let mut contexts = vec![ctx];
        let live = LiveAddr6 {
            addr: "2001:db8::42".parse().unwrap(),
            prefix: 64, if_index: 7, preferred: 100, valid: 200, deprecated: false,
        };
        dhcp_construct_contexts(&mut contexts, &[live]);
        assert_eq!(contexts[0].if_index, 0);
    }

    #[test]
    fn dhcp_construct_contexts_skips_link_local_live_addr() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8::".parse().unwrap(), "2001:db8::ffff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        let mut contexts = vec![ctx];
        let live = LiveAddr6 {
            addr: "fe80::1".parse().unwrap(),
            prefix: 64, if_index: 7, preferred: 100, valid: 200, deprecated: false,
        };
        dhcp_construct_contexts(&mut contexts, &[live]);
        assert_eq!(contexts[0].if_index, 0);
    }

    // ── make_duid ─────────────────────────────────────────────────────────────

    #[test]
    fn make_duid_prefers_configured_en() {
        let mut d = Daemon::default();
        d.duid_config = Some(vec![0xAA, 0xBB]);
        d.duid_enterprise = 9;
        make_duid(&mut d, None, true, 1_000_000_000).unwrap();
        let duid = d.duid.unwrap();
        assert_eq!(u16::from_be_bytes([duid[0], duid[1]]), DUID_EN);
        assert_eq!(u32::from_be_bytes([duid[2], duid[3], duid[4], duid[5]]), 9);
        assert_eq!(&duid[6..], &[0xAA, 0xBB]);
    }

    #[test]
    fn make_duid_builds_llt_from_mac_when_stable() {
        let mut d = Daemon::default();
        let mac = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        make_duid(&mut d, Some(DuidMacSource { hw_type: 1, mac: mac.clone() }), true, 1_000_000_000).unwrap();
        let duid = d.duid.unwrap();
        assert_eq!(u16::from_be_bytes([duid[0], duid[1]]), DUID_LLT);
        assert_eq!(u16::from_be_bytes([duid[2], duid[3]]), 1);
        assert_eq!(&duid[8..], &mac[..]);
    }

    #[test]
    fn make_duid_builds_ll_when_not_stable() {
        let mut d = Daemon::default();
        let mac = vec![0xAA; 6];
        make_duid(&mut d, Some(DuidMacSource { hw_type: 1, mac: mac.clone() }), false, 0).unwrap();
        let duid = d.duid.unwrap();
        assert_eq!(u16::from_be_bytes([duid[0], duid[1]]), DUID_LL);
        assert_eq!(duid.len(), 4 + mac.len());
    }

    #[test]
    fn make_duid_errs_without_config_or_mac() {
        let mut d = Daemon::default();
        assert!(make_duid(&mut d, None, true, 0).is_err());
        assert!(d.duid.is_none());
    }

    #[test]
    fn make_duid_skips_high_hw_type() {
        let mut d = Daemon::default();
        let mac = vec![0x01; 6];
        let err = make_duid(&mut d, Some(DuidMacSource { hw_type: 300, mac }), true, 0);
        assert!(err.is_err());
    }

    #[test]
    fn make_duid_is_stable_across_calls() {
        let mut d = Daemon::default();
        let mac = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06];
        make_duid(&mut d, Some(DuidMacSource { hw_type: 1, mac: mac.clone() }), true, 1_000_000_000).unwrap();
        let first = d.duid.clone();
        make_duid(&mut d, Some(DuidMacSource { hw_type: 1, mac }), true, 1_000_000_000).unwrap();
        assert_eq!(d.duid, first);
    }

    // ── dispatch_dhcp6 (stateful) ─────────────────────────────────────────────

    fn dispatch(
        pkt: &Dhcp6Packet,
        duid: &[u8],
        contexts: &[crate::types::dhcp::DhcpContext],
        lease_db: &mut LeaseDb,
    ) -> Option<Dhcp6Reply> {
        dispatch_dhcp6(pkt, duid, contexts, &[], lease_db, false, 0)
    }

    #[test]
    fn dispatch_dhcp6_solicit_returns_advertise_with_allocated_address() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        let data = solicit_with_ia(0x1234, [0, 0, 0, 1]);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03, 0x00, 0x01, 1, 2, 3, 4, 5, 6];
        let mut db = LeaseDb::new();

        let reply = dispatch(&pkt, &duid, &[ctx], &mut db).unwrap();
        assert_eq!(reply.msg_type, Dhcp6MsgType::Advertise);
        assert_eq!(reply.xid, 0x1234);

        assert_eq!(find_option6(&reply.options, OPTION6_SERVER_ID), Some(duid.as_slice()));

        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        assert!(ia_data.len() > 12);
        let suboptions = &ia_data[12..];
        let iaaddr = find_option6(suboptions, OPTION6_IAADDR).expect("IAADDR sub-option present");
        assert_eq!(iaaddr.len(), 24);
        let addr = Ipv6Addr::from(<[u8; 16]>::try_from(&iaaddr[0..16]).unwrap());
        assert!(is_same_net6(&addr, &"2001:db8::1".parse().unwrap(), 64));

        // Solicit (no rapid-commit) is a pure candidate search: nothing persisted.
        assert_eq!(db.iter().count(), 0);
    }

    #[test]
    fn dispatch_dhcp6_solicit_lifetimes_come_from_context_lease_time_not_hardcoded() {
        use crate::types::dhcp::ContextFlags;
        let mut ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        ctx.lease_time = 100;
        let data = solicit_with_ia(0x1234, [0, 0, 0, 1]);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03];
        let mut db = LeaseDb::new();

        let reply = dispatch(&pkt, &duid, &[ctx], &mut db).unwrap();
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        let iaaddr = find_option6(&ia_data[12..], OPTION6_IAADDR).unwrap();
        let preferred = u32::from_be_bytes(iaaddr[16..20].try_into().unwrap());
        let valid = u32::from_be_bytes(iaaddr[20..24].try_into().unwrap());
        // calculate_times(100) => preferred=100, valid=100 -- not the old
        // hardcoded 3600/7200 regardless of context configuration.
        assert_eq!(preferred, 100);
        assert_eq!(valid, 100);
    }

    #[test]
    fn dispatch_dhcp6_solicit_rapid_commit_persists_and_replies() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        let mut data = solicit_with_ia(0x42, [0, 0, 0, 9]);
        data.extend_from_slice(&OPTION6_RAPID_COMMIT.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03];
        let mut db = LeaseDb::new();

        let reply = dispatch(&pkt, &duid, &[ctx], &mut db).unwrap();
        assert_eq!(reply.msg_type, Dhcp6MsgType::Reply);
        assert!(find_option6(&reply.options, OPTION6_RAPID_COMMIT).is_some());
        assert_eq!(db.iter().count(), 1, "rapid-commit must persist the lease");
    }

    #[test]
    fn dispatch_dhcp6_solicit_no_context_reports_no_addrs_available() {
        let data = solicit_with_ia(0x1, [0, 0, 0, 1]);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03];
        let mut db = LeaseDb::new();

        let reply = dispatch(&pkt, &duid, &[], &mut db).unwrap();
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        let suboptions = &ia_data[12..];
        assert!(find_option6(suboptions, OPTION6_STATUS_CODE).is_some());
        assert!(find_option6(suboptions, OPTION6_IAADDR).is_none());
    }

    #[test]
    fn dispatch_dhcp6_request_returns_reply_with_allocated_address_and_persists() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        let mut data = solicit_with_ia(0x99, [0, 0, 0, 2]);
        data[0] = Dhcp6MsgType::Request as u8;
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03, 0x00, 0x01, 1, 2, 3, 4, 5, 6];
        let mut db = LeaseDb::new();

        let reply = dispatch(&pkt, &duid, &[ctx], &mut db).unwrap();
        assert_eq!(reply.msg_type, Dhcp6MsgType::Reply);
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        assert!(find_option6(&ia_data[12..], OPTION6_IAADDR).is_some());
        assert_eq!(db.iter().count(), 1, "Request always persists on success");
    }

    #[test]
    fn dispatch_dhcp6_request_empty_ia_redirects_like_rapid_commit_solicit() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        // Request whose IA_NA has IAID+T1+T2 but no IAADDR sub-option.
        let mut data = vec![Dhcp6MsgType::Request as u8, 0, 0, 1];
        data.extend_from_slice(&OPTION6_CLIENT_ID.to_be_bytes());
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        data.extend_from_slice(&OPTION6_IA_NA.to_be_bytes());
        data.extend_from_slice(&12u16.to_be_bytes());
        data.extend_from_slice(&[0, 0, 0, 3]);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let duid = vec![0x00, 0x03];
        let mut db = LeaseDb::new();

        let reply = dispatch(&pkt, &duid, &[ctx], &mut db).unwrap();
        assert_eq!(reply.msg_type, Dhcp6MsgType::Reply);
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        assert!(find_option6(&ia_data[12..], OPTION6_IAADDR).is_some());
        assert_eq!(db.iter().count(), 1);
    }

    #[test]
    fn dispatch_dhcp6_request_address_leased_to_other_client_is_unspec_fail() {
        use crate::types::dhcp::{ContextFlags, LEASE_NA};
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        let taken: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let mut db = LeaseDb::new();
        db.bind_v6(taken, &[0xFF, 0xFF], 999, LEASE_NA, None);

        let mut data = solicit_pkt(1);
        data[0] = Dhcp6MsgType::Request as u8;
        data.extend_from_slice(&OPTION6_CLIENT_ID.to_be_bytes());
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        data.extend_from_slice(&OPTION6_IA_NA.to_be_bytes());
        data.extend_from_slice(&40u16.to_be_bytes());
        data.extend_from_slice(&[0, 0, 0, 1]);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&OPTION6_IAADDR.to_be_bytes());
        data.extend_from_slice(&24u16.to_be_bytes());
        data.extend_from_slice(&taken.octets());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        let pkt = parse_dhcp6_packet(&data).unwrap();

        let reply = dispatch(&pkt, &[0x00, 0x03], &[ctx], &mut db).unwrap();
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        let status = find_option6(&ia_data[12..], OPTION6_STATUS_CODE).unwrap();
        let code = u16::from_be_bytes([status[0], status[1]]);
        assert_eq!(code, crate::rfc3315::STATUS_UNSPEC_FAIL);
    }

    #[test]
    fn dispatch_dhcp6_request_address_off_link_is_not_on_link() {
        let mut data = solicit_pkt(1);
        data[0] = Dhcp6MsgType::Request as u8;
        data.extend_from_slice(&OPTION6_CLIENT_ID.to_be_bytes());
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        data.extend_from_slice(&OPTION6_IA_NA.to_be_bytes());
        data.extend_from_slice(&40u16.to_be_bytes());
        data.extend_from_slice(&[0, 0, 0, 1]);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&OPTION6_IAADDR.to_be_bytes());
        data.extend_from_slice(&24u16.to_be_bytes());
        data.extend_from_slice(&"2001:db8:9999::1".parse::<Ipv6Addr>().unwrap().octets());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let mut db = LeaseDb::new();

        let reply = dispatch(&pkt, &[0x00, 0x03], &[], &mut db).unwrap();
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        let status = find_option6(&ia_data[12..], OPTION6_STATUS_CODE).unwrap();
        let code = u16::from_be_bytes([status[0], status[1]]);
        assert_eq!(code, crate::rfc3315::STATUS_NOT_ON_LINK);
    }

    // ── RENEW / REBIND ────────────────────────────────────────────────────────

    fn renew_pkt(msg_type: Dhcp6MsgType, iaid: [u8; 4], addr: Ipv6Addr) -> Vec<u8> {
        let mut data = vec![msg_type as u8, 0, 0, 2];
        data.extend_from_slice(&OPTION6_CLIENT_ID.to_be_bytes());
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        data.extend_from_slice(&OPTION6_IA_NA.to_be_bytes());
        data.extend_from_slice(&40u16.to_be_bytes());
        data.extend_from_slice(&iaid);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&OPTION6_IAADDR.to_be_bytes());
        data.extend_from_slice(&24u16.to_be_bytes());
        data.extend_from_slice(&addr.octets());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data
    }

    #[test]
    fn dispatch_dhcp6_renew_extends_existing_lease() {
        use crate::types::dhcp::{ContextFlags, LEASE_NA};
        let mut ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        ctx.lease_time = 200;
        let addr: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let clid = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let mut db = LeaseDb::new();
        db.bind_v6(addr, &clid, 2, LEASE_NA, None);

        let data = renew_pkt(Dhcp6MsgType::Renew, [0, 0, 0, 2], addr);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let reply = dispatch(&pkt, &[0x00, 0x03], &[ctx], &mut db).unwrap();

        assert_eq!(reply.msg_type, Dhcp6MsgType::Reply);
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        let iaaddr = find_option6(&ia_data[12..], OPTION6_IAADDR).unwrap();
        let preferred = u32::from_be_bytes(iaaddr[16..20].try_into().unwrap());
        assert_eq!(preferred, 200);
        assert!(db.find_v6_by_clid_iaid(&clid, 2, &addr).unwrap().expires.is_some());
    }

    #[test]
    fn dispatch_dhcp6_renew_no_lease_is_no_binding_and_not_top_level_error() {
        let addr: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let data = renew_pkt(Dhcp6MsgType::Renew, [0, 0, 0, 2], addr);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let mut db = LeaseDb::new();

        let reply = dispatch(&pkt, &[0x00, 0x03], &[], &mut db).unwrap();
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        let status = find_option6(&ia_data[12..], OPTION6_STATUS_CODE).unwrap();
        let code = u16::from_be_bytes([status[0], status[1]]);
        assert_eq!(code, crate::rfc3315::STATUS_NO_BINDING);
        // RENEW never sets a top-level error status, only the per-IA one.
        assert!(find_option6(&reply.options, OPTION6_STATUS_CODE).is_none());
    }

    #[test]
    fn dispatch_dhcp6_rebind_no_lease_not_authoritative_reports_no_addrs() {
        let addr: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let data = renew_pkt(Dhcp6MsgType::Rebind, [0, 0, 0, 2], addr);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let mut db = LeaseDb::new();

        let reply = dispatch_dhcp6(&pkt, &[0x00, 0x03], &[], &[], &mut db, false, 0).unwrap();
        let top_status = find_option6(&reply.options, OPTION6_STATUS_CODE).unwrap();
        let code = u16::from_be_bytes([top_status[0], top_status[1]]);
        assert_eq!(code, crate::rfc3315::STATUS_NO_ADDRS_AVAIL);
    }

    #[test]
    fn dispatch_dhcp6_rebind_no_lease_authoritative_creates_lease() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        let addr: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let data = renew_pkt(Dhcp6MsgType::Rebind, [0, 0, 0, 2], addr);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let mut db = LeaseDb::new();

        let reply = dispatch_dhcp6(&pkt, &[0x00, 0x03], &[ctx], &[], &mut db, true, 0).unwrap();
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        assert!(find_option6(&ia_data[12..], OPTION6_IAADDR).is_some());
        assert_eq!(db.iter().count(), 1);
    }

    // ── CONFIRM ──────────────────────────────────────────────────────────────

    #[test]
    fn dispatch_dhcp6_confirm_no_addresses_returns_none() {
        let data = solicit_pkt(1); // Solicit-shaped but retyped below, no IA at all
        let mut data = data;
        data[0] = Dhcp6MsgType::Confirm as u8;
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let mut db = LeaseDb::new();
        assert!(dispatch(&pkt, &[0x00, 0x03], &[], &mut db).is_none());
    }

    #[test]
    fn dispatch_dhcp6_confirm_valid_address_is_success() {
        use crate::types::dhcp::ContextFlags;
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        let addr: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let mut data = renew_pkt(Dhcp6MsgType::Confirm, [0, 0, 0, 2], addr);
        data[0] = Dhcp6MsgType::Confirm as u8;
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let mut db = LeaseDb::new();

        let reply = dispatch(&pkt, &[0x00, 0x03], &[ctx], &mut db).unwrap();
        let status = find_option6(&reply.options, OPTION6_STATUS_CODE).unwrap();
        let code = u16::from_be_bytes([status[0], status[1]]);
        assert_eq!(code, crate::rfc3315::STATUS_SUCCESS);
    }

    #[test]
    fn dispatch_dhcp6_confirm_invalid_address_is_not_on_link() {
        let addr: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let mut data = renew_pkt(Dhcp6MsgType::Confirm, [0, 0, 0, 2], addr);
        data[0] = Dhcp6MsgType::Confirm as u8;
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let mut db = LeaseDb::new();

        let reply = dispatch(&pkt, &[0x00, 0x03], &[], &mut db).unwrap();
        let status = find_option6(&reply.options, OPTION6_STATUS_CODE).unwrap();
        let code = u16::from_be_bytes([status[0], status[1]]);
        assert_eq!(code, crate::rfc3315::STATUS_NOT_ON_LINK);
    }

    // ── RELEASE / DECLINE ────────────────────────────────────────────────────

    #[test]
    fn dispatch_dhcp6_release_removes_lease_and_frees_address() {
        use crate::types::dhcp::LEASE_NA;
        let addr: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let clid = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let mut db = LeaseDb::new();
        db.bind_v6(addr, &clid, 2, LEASE_NA, None);

        let mut data = renew_pkt(Dhcp6MsgType::Release, [0, 0, 0, 2], addr);
        data[0] = Dhcp6MsgType::Release as u8;
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let reply = dispatch(&pkt, &[0x00, 0x03], &[], &mut db).unwrap();

        assert_eq!(reply.msg_type, Dhcp6MsgType::Reply);
        let status = find_option6(&reply.options, OPTION6_STATUS_CODE).unwrap();
        assert_eq!(u16::from_be_bytes([status[0], status[1]]), crate::rfc3315::STATUS_SUCCESS);
        assert!(db.find_v6_by_addr(&addr).is_none(), "released lease must be freed");
    }

    #[test]
    fn dispatch_dhcp6_release_unknown_lease_reports_no_binding_but_top_level_success() {
        let addr: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let mut data = renew_pkt(Dhcp6MsgType::Release, [0, 0, 0, 2], addr);
        data[0] = Dhcp6MsgType::Release as u8;
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let mut db = LeaseDb::new();

        let reply = dispatch(&pkt, &[0x00, 0x03], &[], &mut db).unwrap();
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        let ia_status = find_option6(&ia_data[12..], OPTION6_STATUS_CODE).unwrap();
        assert_eq!(u16::from_be_bytes([ia_status[0], ia_status[1]]), crate::rfc3315::STATUS_NO_BINDING);
        let top_status = find_option6(&reply.options, OPTION6_STATUS_CODE).unwrap();
        assert_eq!(u16::from_be_bytes([top_status[0], top_status[1]]), crate::rfc3315::STATUS_SUCCESS);
    }

    #[test]
    fn dispatch_dhcp6_decline_removes_lease() {
        use crate::types::dhcp::LEASE_NA;
        let addr: Ipv6Addr = "2001:db8::5".parse().unwrap();
        let clid = vec![0xAA, 0xBB, 0xCC, 0xDD];
        let mut db = LeaseDb::new();
        db.bind_v6(addr, &clid, 2, LEASE_NA, None);

        let mut data = renew_pkt(Dhcp6MsgType::Decline, [0, 0, 0, 2], addr);
        data[0] = Dhcp6MsgType::Decline as u8;
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let reply = dispatch(&pkt, &[0x00, 0x03], &[], &mut db).unwrap();

        assert_eq!(reply.msg_type, Dhcp6MsgType::Reply);
        assert!(db.find_v6_by_addr(&addr).is_none(), "declined lease must be freed");
    }

    // ── INFOREQ ──────────────────────────────────────────────────────────────

    #[test]
    fn dispatch_dhcp6_inforeq_without_ia_gets_reply() {
        let mut data = solicit_pkt(1);
        data[0] = Dhcp6MsgType::InfoReq as u8;
        data.extend_from_slice(&OPTION6_CLIENT_ID.to_be_bytes());
        data.extend_from_slice(&4u16.to_be_bytes());
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let mut db = LeaseDb::new();
        let reply = dispatch(&pkt, &[0x00, 0x03], &[], &mut db).unwrap();
        assert_eq!(reply.msg_type, Dhcp6MsgType::Reply);
    }

    #[test]
    fn dispatch_dhcp6_inforeq_with_ia_is_dropped() {
        let mut data = solicit_with_ia(1, [0, 0, 0, 1]);
        data[0] = Dhcp6MsgType::InfoReq as u8;
        let pkt = parse_dhcp6_packet(&data).unwrap();
        let mut db = LeaseDb::new();
        assert!(dispatch(&pkt, &[0x00, 0x03], &[], &mut db).is_none());
    }

    // ── dhcp6_init ────────────────────────────────────────────────────────────

    #[cfg(unix)]
    #[test]
    fn dhcp6_init_binds_port_547_or_skips_without_privilege() {
        match dhcp6_init(false) {
            Ok(fd) => unsafe { libc::close(fd); },
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(err) if err.kind() == std::io::ErrorKind::AddrInUse => {}
            Err(err) => panic!("dhcp6_init failed unexpectedly: {err}"),
        }
    }

    // ── run_dhcp6_loop ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn run_dhcp6_loop_solicit_gets_advertise_with_allocated_address() {
        let server = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        client.connect(server.local_addr().unwrap()).await.unwrap();

        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::ff".parse().unwrap(),
            64, ContextFlags::DHCP,
        );
        let duid = vec![0x00, 0x03, 0x00, 0x01, 1, 2, 3, 4, 5, 6];
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = std::sync::Arc::new(server);
        let loop_task = tokio::spawn(run_dhcp6_loop(
            server.clone(), duid, vec![ctx], vec![],
            crate::lease::LeaseDb::new(), false, shutdown_rx,
            Some(client.local_addr().unwrap().port()),
        ));

        client.send(&solicit_with_ia(0xABCD, [0, 0, 0, 7])).await.unwrap();

        let mut buf = [0u8; 512];
        let len = tokio::time::timeout(std::time::Duration::from_millis(500), client.recv(&mut buf))
            .await
            .expect("timed out waiting for DHCPv6 loop reply")
            .unwrap();
        let reply = parse_dhcp6_packet(&buf[..len]).unwrap();
        assert_eq!(reply.msg_type, Dhcp6MsgType::Advertise);
        let ia_data = find_option6(&reply.options, OPTION6_IA_NA).unwrap();
        assert!(find_option6(&ia_data[12..], OPTION6_IAADDR).is_some());

        shutdown_tx.send(true).unwrap();
        loop_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_dhcp6_loop_request_commits_lease_so_second_client_is_refused() {
        let server = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let client = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        client.connect(server.local_addr().unwrap()).await.unwrap();

        // Single-address pool: only one address to ever hand out.
        let ctx = make_v6_ctx(
            "2001:db8::1".parse().unwrap(), "2001:db8::1".parse().unwrap(),
            128, ContextFlags::DHCP,
        );
        let duid = vec![0x00, 0x03, 0x00, 0x01, 1, 2, 3, 4, 5, 6];
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = std::sync::Arc::new(server);
        let loop_task = tokio::spawn(run_dhcp6_loop(
            server.clone(), duid, vec![ctx], vec![],
            crate::lease::LeaseDb::new(), true, shutdown_rx,
            Some(client.local_addr().unwrap().port()),
        ));

        let mut req1 = solicit_with_ia(1, [0, 0, 0, 1]);
        req1[0] = Dhcp6MsgType::Request as u8;
        client.send(&req1).await.unwrap();
        let mut buf = [0u8; 512];
        let len1 = tokio::time::timeout(std::time::Duration::from_millis(500), client.recv(&mut buf))
            .await
            .expect("timed out on first reply")
            .unwrap();
        let reply1 = parse_dhcp6_packet(&buf[..len1]).unwrap();
        let ia1 = find_option6(&reply1.options, OPTION6_IA_NA).unwrap();
        assert!(
            find_option6(&ia1[12..], OPTION6_IAADDR).is_some(),
            "first client should get the only address in the pool"
        );

        let mut req2 = solicit_with_ia(2, [0, 0, 0, 2]);
        req2[0] = Dhcp6MsgType::Request as u8;
        client.send(&req2).await.unwrap();
        let len2 = tokio::time::timeout(std::time::Duration::from_millis(500), client.recv(&mut buf))
            .await
            .expect("timed out on second reply")
            .unwrap();
        let reply2 = parse_dhcp6_packet(&buf[..len2]).unwrap();
        let ia2 = find_option6(&reply2.options, OPTION6_IA_NA).unwrap();
        assert!(
            find_option6(&ia2[12..], OPTION6_IAADDR).is_none(),
            "second client must be refused: the loop should have committed the first lease"
        );
        assert!(find_option6(&ia2[12..], OPTION6_STATUS_CODE).is_some());

        shutdown_tx.send(true).unwrap();
        loop_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_dhcp6_loop_stops_on_shutdown_signal() {
        let server = tokio::net::UdpSocket::bind("[::1]:0").await.unwrap();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let server = std::sync::Arc::new(server);
        let loop_task = tokio::spawn(run_dhcp6_loop(
            server, vec![], vec![], vec![],
            crate::lease::LeaseDb::new(), false, shutdown_rx, None,
        ));

        shutdown_tx.send(true).unwrap();
        tokio::time::timeout(std::time::Duration::from_millis(500), loop_task)
            .await
            .expect("loop did not stop after shutdown signal")
            .unwrap()
            .unwrap();
    }

    // ── get_client_mac ────────────────────────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn get_client_mac_resolves_from_arp_cache() {
        let daemon = crate::types::daemon::Daemon::default();
        let client: Ipv6Addr = "fe80::1".parse().unwrap();
        let mac_bytes = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

        // Pre-seed the ARP cache directly so this test is deterministic and
        // independent of the real kernel neighbour table: a fresh
        // (not-yet-stale) cache entry is returned without ever touching the
        // netlink socket.
        {
            let mut state = daemon.arp_state.lock().unwrap();
            state.cache.begin_refresh(0);
            state.cache.filter_mac(std::net::IpAddr::V6(client), &mac_bytes);
            state.cache.finish_refresh();
        }

        let mac = get_client_mac(&daemon, client, 0);
        assert_eq!(mac, Some(mac_bytes.to_vec()));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn get_client_mac_none_when_unresolvable() {
        let daemon = crate::types::daemon::Daemon::default();
        // Documentation-only prefix (RFC 3849): never a real neighbour.
        let client: Ipv6Addr = "2001:db8::dead:beef".parse().unwrap();
        assert_eq!(get_client_mac(&daemon, client, 0), None);
    }
}

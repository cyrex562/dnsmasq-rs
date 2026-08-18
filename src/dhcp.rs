//! DHCPv4 server — UDP receive loop and packet dispatch.
//! Ported from `dhcp.c` (1124 lines) in the original dnsmasq source.
//!
//! Responsibilities:
//! - Bind a UDP socket on port 67.
//! - Receive DHCP packets, parse them, demultiplex by message type.
//! - Dispatch to the state machine in `rfc2131`.
//! - Send replies (unicast to known clients, broadcast to unknown).

#![cfg(feature = "dhcp")]

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tracing::{debug, warn};

use crate::dhcp_common::{find_option, get_message_type, match_netid_wild};
use crate::dhcp_protocol::{
    DhcpMsgType, DhcpPacket, BOOTREPLY, DHCP_CHADDR_MAX, DHCP_CLIENT_PORT, DHCP_COOKIE,
    DHCP_SERVER_PORT, OPTION_AGENT_ID, OPTION_ARCH, OPTION_CLIENT_ID, OPTION_END,
    OPTION_HOSTNAME, OPTION_LEASE_TIME, OPTION_REQUESTED_OPTIONS, OPTION_USER_CLASS,
    OPTION_VENDOR_ID,
};
use crate::lease::LeaseDb;
use crate::metrics::{inc_metric, Metric};
use crate::rfc2131::{
    do_options, find_boot, find_requested_ip, handle_decline, handle_discover, handle_inform,
    handle_release, handle_request, is_pxe_client, option_put, DhcpReply, DoOptionsConfig,
};
use crate::dhcp_common::find_config;

// ─────────────────────────────────────────────────────────────────────────────
// DHCP server configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the DHCPv4 server.
#[derive(Debug, Clone)]
pub struct DhcpServerConfig {
    /// First address in the DHCP pool.
    pub pool_start: Ipv4Addr,
    /// Last address in the DHCP pool (inclusive).
    pub pool_end: Ipv4Addr,
    /// The server's own IP address (used as `siaddr` and option 54).
    pub server_ip: Ipv4Addr,
    /// Maximum packet size to accept.
    pub max_packet: usize,
    /// Static/selector DHCP config entries from parsed `dhcp-host`/`dhcp-ignore`.
    pub configs: Vec<crate::types::dhcp::DhcpConfig>,
    /// Vendor-class tag rules from parsed `dhcp-vendorclass`.
    pub vendor_rules: Vec<crate::types::dhcp::DhcpVendorRule>,
    /// User-class tag rules from parsed `dhcp-userclass`.
    pub user_class_rules: Vec<crate::types::dhcp::DhcpUserClassRule>,
    /// MAC-address tag rules from parsed `dhcp-mac`.
    pub mac_rules: Vec<crate::types::dhcp::DhcpMacRule>,
    /// Relay-agent option-82 tag rules from parsed relay-id directives.
    pub relay_id_rules: Vec<crate::types::dhcp::DhcpRelayIdRule>,
    /// Delayed-reply rules from parsed `dhcp-reply-delay`.
    pub reply_delays: Vec<crate::types::dhcp::DhcpReplyDelay>,
    /// Parsed `dhcp-range` contexts for option generation.
    pub contexts: Vec<crate::types::dhcp::DhcpContext>,
    /// Parsed `dhcp-option` directives.
    pub dhcp_opts: Vec<crate::types::dhcp::DhcpOpt>,
    /// Parsed `dhcp-boot` directives.
    pub boot_configs: Vec<crate::types::dhcp::DhcpBoot>,
    /// Optional default domain suffix for DHCP replies.
    pub domain_suffix: Option<String>,
    /// Path to persist the lease database to (`--dhcp-leasefile`).
    pub lease_file: Option<String>,
}

impl Default for DhcpServerConfig {
    fn default() -> Self {
        Self {
            pool_start: Ipv4Addr::new(192, 168, 1, 100),
            pool_end:   Ipv4Addr::new(192, 168, 1, 200),
            server_ip:  Ipv4Addr::new(192, 168, 1, 1),
            max_packet: 1500,
            configs:    Vec::new(),
            vendor_rules: Vec::new(),
            user_class_rules: Vec::new(),
            mac_rules: Vec::new(),
            relay_id_rules: Vec::new(),
            reply_delays: Vec::new(),
            contexts: Vec::new(),
            dhcp_opts: Vec::new(),
            boot_configs: Vec::new(),
            domain_suffix: None,
            lease_file: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DispatchedDhcpReply {
    pub reply: DhcpReply,
    pub delay_secs: u32,
}

#[derive(Debug, Clone, Default)]
pub struct DhcpLoopOptions {
    /// Optional reply-port override for unprivileged test and harness setups.
    /// When set, replies are sent to this port instead of the RFC2131 default.
    pub reply_port_override: Option<u16>,
}

fn rfc3004_user_classes(raw: &[u8]) -> Option<Vec<&[u8]>> {
    let mut classes = Vec::new();
    let mut i = 0;
    while i < raw.len() {
        let len = usize::from(raw[i]);
        i += 1;
        if i + len > raw.len() {
            return None;
        }
        classes.push(&raw[i..i + len]);
        i += len;
    }
    Some(classes)
}

fn derived_tags(pkt: &DhcpPacket, cfg: &DhcpServerConfig) -> Vec<crate::types::dhcp::DhcpNetid> {
    let vendor = find_option(&pkt.options, OPTION_VENDOR_ID);
    let mut tags: Vec<_> = cfg
        .vendor_rules
        .iter()
        .filter(|rule| match vendor {
            Some(data) if rule.vendor_class.is_empty() => true,
            Some(data) => data.windows(rule.vendor_class.len()).any(|w| w == rule.vendor_class),
            None => false,
        })
        .map(|rule| rule.netid.clone())
        .collect();

    if let Some(raw) = find_option(&pkt.options, OPTION_USER_CLASS) {
        for rule in &cfg.user_class_rules {
            let matched = if rule.user_class.is_empty() {
                true
            } else if let Some(classes) = rfc3004_user_classes(raw) {
                classes.iter().any(|class| {
                    class
                        .windows(rule.user_class.len())
                        .any(|w| w == rule.user_class)
                })
            } else {
                raw.windows(rule.user_class.len()).any(|w| w == rule.user_class)
            };
            if matched {
                tags.push(rule.netid.clone());
            }
        }
    }

    let hw_len = usize::from(pkt.hlen).min(DHCP_CHADDR_MAX);
    for rule in &cfg.mac_rules {
        if rule.hwaddr_len as usize == hw_len
            && (rule.hwaddr_type == i32::from(pkt.htype) || rule.hwaddr_type == 0)
            && crate::util::memcmp_masked(
                &rule.hwaddr[..hw_len],
                &pkt.chaddr[..hw_len],
                rule.wildcard_mask,
            ) != 0
        {
            tags.push(rule.netid.clone());
        }
    }

    if let Some(agent_info) = find_option(&pkt.options, OPTION_AGENT_ID) {
        for rule in &cfg.relay_id_rules {
            if let Some(idx) = crate::rfc2131::option_find1(agent_info, rule.subopt, 1) {
                if crate::rfc2131::option_val_at(agent_info, idx) == rule.data.as_slice() {
                    tags.push(rule.netid.clone());
                }
            }
        }
    }

    tags
}

fn select_reply_delay(
    tags: &[crate::types::dhcp::DhcpNetid],
    cfg: &DhcpServerConfig,
) -> u32 {
    if let Some(rule) = cfg
        .reply_delays
        .iter()
        .find(|rule| !rule.filter.is_empty() && match_netid_wild(&rule.filter, tags))
    {
        return rule.delay_secs;
    }

    cfg.reply_delays
        .iter()
        .find(|rule| rule.filter.is_empty())
        .map_or(0, |rule| rule.delay_secs)
}

fn context_for_reply<'a>(
    cfg: &'a DhcpServerConfig,
    reply: &DhcpReply,
) -> Option<&'a crate::types::dhcp::DhcpContext> {
    cfg.contexts
        .iter()
        .find(|ctx| {
            (ctx.flags & crate::types::dhcp::CONTEXT_STATIC) == 0
                && reply.yiaddr != Ipv4Addr::UNSPECIFIED
                && reply.yiaddr >= ctx.start
                && reply.yiaddr <= ctx.end
        })
        .or_else(|| cfg.contexts.first())
}

fn requested_arch(pkt: &DhcpPacket) -> i32 {
    let Some(raw) = find_option(&pkt.options, OPTION_ARCH) else {
        return -1;
    };
    if raw.len() < 2 {
        return -1;
    }
    i32::from(u16::from_be_bytes([raw[0], raw[1]]))
}

fn decorate_reply(
    reply: &mut DhcpReply,
    pkt: &DhcpPacket,
    cfg: &DhcpServerConfig,
    tags: &[crate::types::dhcp::DhcpNetid],
    config: Option<&crate::types::dhcp::DhcpConfig>,
) {
    let context = context_for_reply(cfg, reply);
    let mut config_opts = cfg.dhcp_opts.clone();
    let context_tags = context
        .and_then(|ctx| (!ctx.netid.net.is_empty()).then(|| vec![ctx.netid.clone()]));
    let mut effective_tags = tags.to_vec();
    if let Some(config) = config {
        effective_tags.extend(config.netid.iter().cloned());
    }
    let filtered_tags = crate::dhcp_common::option_filter(
        effective_tags,
        context_tags,
        &mut config_opts,
        if is_pxe_client(find_option(&pkt.options, OPTION_VENDOR_ID)) {
            1
        } else {
            0
        },
        &[],
    );

    let boot = filtered_tags
        .iter()
        .find(|tag| !tag.net.is_empty())
        .and_then(|tag| find_boot(&cfg.boot_configs, Some(tag.net.as_str())))
        .or_else(|| find_boot(&cfg.boot_configs, None));

    if let Some(boot) = boot {
        if boot.next_server != Ipv4Addr::UNSPECIFIED {
            reply.siaddr = boot.next_server;
        }
        reply.sname = boot.sname.clone();
        reply.file = boot.file.clone();
    }

    let mut reply_pkt = DhcpPacket {
        op: BOOTREPLY,
        htype: pkt.htype,
        hlen: pkt.hlen,
        hops: 0,
        xid: pkt.xid,
        secs: 0,
        flags: 0,
        ciaddr: pkt.ciaddr,
        yiaddr: reply.yiaddr,
        siaddr: reply.siaddr,
        giaddr: reply.giaddr,
        chaddr: pkt.chaddr,
        sname: [0u8; 64],
        file: [0u8; 128],
        options: reply.options.clone(),
    };
    let lease_time = context.map_or(3600, |ctx| ctx.lease_time);
    let is_inform = get_message_type(&pkt.options) == Some(DhcpMsgType::Inform);
    // do_options() only emits T1/T2 when the lease time isn't "infinite"; C
    // calls do_options() for DHCPINFORM with time == 0xffffffff precisely so
    // it never sends T1/T2 there (rfc2131.c:1817).
    let do_options_lease_time = if is_inform { u32::MAX } else { lease_time };
    let mut opt_cfg = DoOptionsConfig {
        context,
        req_options: find_option(&pkt.options, OPTION_REQUESTED_OPTIONS),
        hostname: config.and_then(|c| c.hostname.as_deref()),
        domain: config
            .and_then(|c| c.domain.as_deref())
            .or(cfg.domain_suffix.as_deref()),
        netid: &filtered_tags,
        subnet_addr: None,
        fqdn_flags: 0,
        null_term: false,
        pxe_arch: requested_arch(pkt),
        uuid: None,
        vendor_class: find_option(&pkt.options, OPTION_VENDOR_ID),
        lease_time: do_options_lease_time,
        fuzz: 0,
        pxevendor: None,
        config_opts: &mut config_opts,
        boot,
        dns_port: 53,
    };

    // OPTION_LEASE_TIME (51) is written unconditionally for OFFER and for the
    // ACK that answers a REQUEST (rfc2131.c:1384, :1744). It is deliberately
    // *not* written for the ACK that answers an INFORM (rfc2131.c:1797-1810
    // only includes it there if the client asked for it via the parameter
    // request list, which ordinary clients don't).
    let write_lease_time = match reply.msg_type {
        DhcpMsgType::Offer => true,
        DhcpMsgType::Ack => !is_inform,
        _ => false,
    };
    if write_lease_time {
        option_put(&mut reply_pkt.options, OPTION_LEASE_TIME, lease_time, 4);
    }

    do_options(&mut reply_pkt, &mut opt_cfg);
    reply.options = reply_pkt.options;
}

// ─────────────────────────────────────────────────────────────────────────────
// Wire-format parsing
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a raw UDP payload into a `DhcpPacket`.
///
/// Returns `None` if the packet is shorter than the minimum BOOTP header (236
/// bytes) or the magic cookie is wrong.
pub fn parse_dhcp_packet(data: &[u8]) -> Option<DhcpPacket> {
    if data.len() < 240 {
        return None;
    }
    // Magic cookie at fixed offset 236 (after 236-byte BOOTP fixed fields)
    let cookie = u32::from_be_bytes([data[236], data[237], data[238], data[239]]);
    if cookie != DHCP_COOKIE {
        return None;
    }

    let mut chaddr = [0u8; DHCP_CHADDR_MAX];
    chaddr.copy_from_slice(&data[28..44]);
    let mut sname = [0u8; 64];
    sname.copy_from_slice(&data[44..108]);
    let mut file = [0u8; 128];
    file.copy_from_slice(&data[108..236]);

    Some(DhcpPacket {
        op:      data[0],
        htype:   data[1],
        hlen:    data[2],
        hops:    data[3],
        xid:     u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
        secs:    u16::from_be_bytes([data[8], data[9]]),
        flags:   u16::from_be_bytes([data[10], data[11]]),
        ciaddr:  Ipv4Addr::new(data[12], data[13], data[14], data[15]),
        yiaddr:  Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        siaddr:  Ipv4Addr::new(data[20], data[21], data[22], data[23]),
        giaddr:  Ipv4Addr::new(data[24], data[25], data[26], data[27]),
        chaddr,
        sname,
        file,
        options: data[240..].to_vec(),
    })
}

/// Serialize a DHCP reply into a wire-format byte buffer.
///
/// The output is a complete BOOTP packet (fixed header + magic cookie +
/// options) suitable for sending over UDP.
pub fn dhcp_reply_to_wire(reply: &DhcpReply, request: &DhcpPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(300);

    // Fixed BOOTP header (236 bytes)
    buf.push(BOOTREPLY);                    // op
    buf.push(request.htype);               // htype
    buf.push(request.hlen);                // hlen
    buf.push(0);                            // hops
    buf.extend_from_slice(&request.xid.to_be_bytes()); // xid
    buf.extend_from_slice(&[0, 0]);        // secs
    buf.extend_from_slice(&[0, 0]);        // flags (unicast)
    buf.extend_from_slice(&request.ciaddr.octets()); // ciaddr
    buf.extend_from_slice(&reply.yiaddr.octets());   // yiaddr
    buf.extend_from_slice(&reply.siaddr.octets());   // siaddr
    buf.extend_from_slice(&reply.giaddr.octets());   // giaddr
    buf.extend_from_slice(&request.chaddr);          // chaddr (16 bytes)
    let mut sname = [0u8; 64];
    if let Some(name) = reply.sname.as_deref() {
        let bytes = name.as_bytes();
        let len = bytes.len().min(sname.len());
        sname[..len].copy_from_slice(&bytes[..len]);
    }
    buf.extend_from_slice(&sname);
    let mut file = [0u8; 128];
    if let Some(name) = reply.file.as_deref() {
        let bytes = name.as_bytes();
        let len = bytes.len().min(file.len());
        file[..len].copy_from_slice(&bytes[..len]);
    }
    buf.extend_from_slice(&file);

    // Magic cookie
    buf.extend_from_slice(&DHCP_COOKIE.to_be_bytes());

    // Options
    buf.extend_from_slice(&reply.options);
    if reply.options.last() != Some(&OPTION_END) {
        buf.push(OPTION_END);
    }

    // Pad to minimum DHCP size
    while buf.len() < 300 {
        buf.push(0);
    }

    buf
}

// ─────────────────────────────────────────────────────────────────────────────
// Relay-agent detection
// ─────────────────────────────────────────────────────────────────────────────

/// Return true if the packet was forwarded by a relay agent (`giaddr` != 0).
pub fn is_relayed(pkt: &DhcpPacket) -> bool {
    pkt.giaddr != Ipv4Addr::UNSPECIFIED
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet dispatch
// ─────────────────────────────────────────────────────────────────────────────

/// Create-or-renew the lease for a successful REQUEST/ACK, mirroring the
/// `lease_set_*` calls in `rfc2131.c:1683-1730`. No-ops if the lease store is
/// already at `max_leases`.
fn record_lease(
    lease_db: &mut LeaseDb,
    addr: Ipv4Addr,
    pkt: &DhcpPacket,
    hw_len: usize,
    clid: Option<&[u8]>,
    hostname: Option<&str>,
    lease_time: u32,
) {
    if lease_db.find_by_addr(addr).is_none() && lease_db.allocate_v4(addr).is_none() {
        return;
    }
    lease_db.set_hwaddr(addr, &pkt.chaddr[..hw_len], i32::from(pkt.htype), clid);
    lease_db.set_hostname(addr, hostname, false);
    lease_db.set_expires(addr, lease_time);
}

/// Dispatch a received DHCP packet to the appropriate handler.
///
/// Returns `Some(DhcpReply)` when a reply should be sent, `None` when the
/// packet should be silently dropped (e.g. RELEASE, DECLINE, unknown type).
///
/// `lease_db` is mutated in place: a REQUEST that is ACK'd creates or renews
/// a lease, RELEASE frees it, and DECLINE removes it so the address is not
/// handed out as an active lease again (rfc2131.c:1237-1285, :1683-1730).
pub fn dispatch_dhcp_with_meta(
    pkt: &DhcpPacket,
    cfg: &DhcpServerConfig,
    lease_db: &mut LeaseDb,
) -> Option<DispatchedDhcpReply> {
    let msg_type = get_message_type(&pkt.options)?;
    let clid = find_option(&pkt.options, OPTION_CLIENT_ID);
    let hostname = find_option(&pkt.options, OPTION_HOSTNAME)
        .and_then(|raw| std::str::from_utf8(raw).ok());
    let hw_len = usize::from(pkt.hlen).min(DHCP_CHADDR_MAX);
    let tags = derived_tags(pkt, cfg);
    let tag_disable = cfg.configs.iter().any(|c| {
        (c.flags & crate::types::dhcp::CONFIG_DISABLE) != 0
            && !c.filter.is_empty()
            && match_netid_wild(&c.filter, &tags)
    });
    if tag_disable {
        return None;
    }
    let config = find_config(
        &cfg.configs,
        clid,
        Some(&pkt.chaddr[..hw_len]),
        i32::from(pkt.htype),
        hostname,
        &tags,
    );
    if config.is_some_and(|c| (c.flags & crate::types::dhcp::CONFIG_DISABLE) != 0) {
        return None;
    }
    let static_addr = config
        .filter(|c| (c.flags & crate::types::dhcp::CONFIG_ADDR) != 0)
        .map(|c| c.addr);
    debug!("DHCP {msg_type:?}");

    let mut reply = match msg_type {
        DhcpMsgType::Discover => {
            inc_metric(Metric::Dhcpdiscover);
            handle_discover(pkt, cfg.pool_start, cfg.pool_end, None, cfg.server_ip, static_addr)
        }
        DhcpMsgType::Request => {
            inc_metric(Metric::Dhcprequest);
            let requested = find_requested_ip(&pkt.options)
                .or_else(|| (pkt.ciaddr != Ipv4Addr::UNSPECIFIED).then_some(pkt.ciaddr));
            // Address reserved as a static dhcp-host for a *different* client
            // (rfc2131.c:1529-1530). `config` and the lookup below both point
            // into `cfg.configs`, so pointer identity tells them apart.
            let reserved_for_other = requested
                .and_then(|addr| config_find_by_address(&cfg.configs, addr))
                .is_some_and(|addr_cfg| !config.is_some_and(|c| std::ptr::eq(c, addr_cfg)));
            handle_request(
                pkt, cfg.pool_start, cfg.pool_end, cfg.server_ip, static_addr, reserved_for_other,
            )
        }
        DhcpMsgType::Release => {
            inc_metric(Metric::Dhcprelease);
            if handle_release(pkt, cfg.pool_start, cfg.pool_end) {
                lease_db.remove_by_addr(pkt.ciaddr);
            }
            None
        }
        DhcpMsgType::Inform => {
            inc_metric(Metric::Dhcpinform);
            handle_inform(pkt, cfg.server_ip)
        }
        DhcpMsgType::Decline => {
            inc_metric(Metric::Dhcpdecline);
            if handle_decline(pkt, cfg.pool_start, cfg.pool_end) {
                if let Some(declined) = find_requested_ip(&pkt.options) {
                    lease_db.remove_by_addr(declined);
                }
            }
            None
        }
        _ => {
            warn!("Unexpected DHCP message type {:?}", msg_type);
            None
        }
    }?;

    decorate_reply(&mut reply, pkt, cfg, &tags, config);

    // Only a REQUEST's ACK allocates a lease; INFORM's ACK never assigns an
    // address (rfc2131.c:1683-1730 vs. the DHCPINFORM case at :1753-1818).
    if reply.msg_type == DhcpMsgType::Ack
        && reply.yiaddr != Ipv4Addr::UNSPECIFIED
        && get_message_type(&pkt.options) != Some(DhcpMsgType::Inform)
    {
        let lease_time = context_for_reply(cfg, &reply).map_or(3600, |ctx| ctx.lease_time);
        record_lease(lease_db, reply.yiaddr, pkt, hw_len, clid, hostname, lease_time);
    }

    let delay_secs = if reply.msg_type == DhcpMsgType::Offer {
        select_reply_delay(&tags, cfg)
    } else {
        0
    };

    Some(DispatchedDhcpReply { reply, delay_secs })
}

/// Dispatch a received DHCP packet to the appropriate handler.
///
/// Returns `Some(DhcpReply)` when a reply should be sent, `None` when the
/// packet should be silently dropped (e.g. RELEASE, DECLINE, unknown type).
pub fn dispatch_dhcp(
    pkt: &DhcpPacket,
    cfg: &DhcpServerConfig,
    lease_db: &mut LeaseDb,
) -> Option<DhcpReply> {
    dispatch_dhcp_with_meta(pkt, cfg, lease_db).map(|out| out.reply)
}

// ─────────────────────────────────────────────────────────────────────────────
// Reply addressing
// ─────────────────────────────────────────────────────────────────────────────

/// Determine the destination address for a DHCP reply.
///
/// Rules (RFC 2131 §4.1):
/// 1. If `giaddr` (relay agent) is set → unicast to relay agent on port 67.
/// 2. If `ciaddr` is set (client knows its IP) → unicast to client on port 68.
/// 3. Otherwise → broadcast 255.255.255.255:68.
pub fn reply_dest(pkt: &DhcpPacket) -> SocketAddr {
    if pkt.giaddr != Ipv4Addr::UNSPECIFIED {
        SocketAddr::V4(SocketAddrV4::new(pkt.giaddr, DHCP_SERVER_PORT))
    } else if pkt.ciaddr != Ipv4Addr::UNSPECIFIED {
        SocketAddr::V4(SocketAddrV4::new(pkt.ciaddr, DHCP_CLIENT_PORT))
    } else {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT))
    }
}

fn loop_reply_dest(pkt: &DhcpPacket, src: SocketAddr, opts: &DhcpLoopOptions) -> SocketAddr {
    if let Some(port) = opts.reply_port_override {
        if pkt.giaddr != Ipv4Addr::UNSPECIFIED {
            return SocketAddr::V4(SocketAddrV4::new(pkt.giaddr, port));
        }
        if pkt.ciaddr != Ipv4Addr::UNSPECIFIED {
            return SocketAddr::V4(SocketAddrV4::new(pkt.ciaddr, port));
        }
        if let IpAddr::V4(ip) = src.ip() {
            return SocketAddr::V4(SocketAddrV4::new(ip, port));
        }
    }

    reply_dest(pkt)
}

/// Send a DHCP reply to an explicit destination, applying any configured delay.
pub async fn send_dhcp_reply_to(
    socket: &tokio::net::UdpSocket,
    request: &DhcpPacket,
    dispatched: &DispatchedDhcpReply,
    dest: SocketAddr,
) -> std::io::Result<usize> {
    if dispatched.delay_secs != 0 {
        tokio::time::sleep(Duration::from_secs(u64::from(dispatched.delay_secs))).await;
    }

    let wire = dhcp_reply_to_wire(&dispatched.reply, request);
    socket.send_to(&wire, dest).await
}

/// Send a DHCP reply using the standard RFC2131 destination logic.
pub async fn send_dhcp_reply(
    socket: &tokio::net::UdpSocket,
    request: &DhcpPacket,
    dispatched: &DispatchedDhcpReply,
) -> std::io::Result<usize> {
    send_dhcp_reply_to(socket, request, dispatched, reply_dest(request)).await
}

/// Receive DHCP packets on `socket`, dispatch them, and send replies until
/// `shutdown` is set to `true`.
///
/// `lease_db` should be pre-loaded from `cfg.lease_file` (if any) by the
/// caller; it is written back to that file whenever a dispatch marks it dirty.
pub async fn run_dhcp_loop(
    socket: std::sync::Arc<tokio::net::UdpSocket>,
    cfg: DhcpServerConfig,
    opts: DhcpLoopOptions,
    mut lease_db: LeaseDb,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; cfg.max_packet.max(300)];

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
                let Some(pkt) = parse_dhcp_packet(&buf[..len]) else {
                    debug!("ignoring malformed DHCP packet from {src}");
                    continue;
                };
                let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db);

                if lease_db.file_dirty {
                    if let Some(path) = cfg.lease_file.as_deref() {
                        if let Err(err) = lease_db.write_to_file(path) {
                            warn!("failed to write DHCP lease file {path}: {err}");
                        }
                    }
                    lease_db.file_dirty = false;
                }

                let Some(dispatched) = dispatched else {
                    continue;
                };

                let dest = loop_reply_dest(&pkt, src, &opts);
                if let Err(err) = send_dhcp_reply_to(&socket, &pkt, &dispatched, dest).await {
                    warn!("failed to send DHCP reply to {dest}: {err}");
                }
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Network utilities (ported from dhcp.c)
// ─────────────────────────────────────────────────────────────────────────────

/// Check if two IPv4 addresses are on the same network given a netmask.
///
/// Port of `is_same_net()` used throughout dhcp.c.
pub fn is_same_net(a: Ipv4Addr, b: Ipv4Addr, netmask: Ipv4Addr) -> bool {
    let mask = u32::from(netmask);
    (u32::from(a) & mask) == (u32::from(b) & mask)
}

/// Compute the Internet checksum (RFC 1071) used for ICMP echo requests.
///
/// Ones-complement sum of 16-bit words, with carry folded back in.
pub fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

// ─────────────────────────────────────────────────────────────────────────────
// Address pool helpers (ported from dhcp.c:687-763)
// ─────────────────────────────────────────────────────────────────────────────

use crate::types::dhcp::{DhcpContext, DhcpConfig, CONTEXT_STATIC, CONTEXT_PROXY, CONFIG_ADDR};

/// Check if `addr` is available in one of the DHCP contexts.
///
/// Returns `true` if `addr` falls within any non-static, non-proxy context
/// range and is not the router address of any context.
/// Port of `address_available()` from dhcp.c:687-715.
pub fn address_available(contexts: &[DhcpContext], addr: Ipv4Addr) -> bool {
    let a = u32::from(addr);

    // Reject if addr is any context's router (server) address.
    for ctx in contexts {
        if addr == ctx.router {
            return false;
        }
    }

    for ctx in contexts {
        if ctx.flags & (CONTEXT_STATIC | CONTEXT_PROXY) != 0 {
            continue;
        }
        let start = u32::from(ctx.start);
        let end = u32::from(ctx.end);
        if a >= start && a <= end {
            return true;
        }
    }
    false
}

/// Find the DHCP context that best matches `addr`.
///
/// Prefers a pool range match (via [`address_available`]), then a static
/// context on the same subnet, then any context on the same subnet.
/// Port of `narrow_context()` from dhcp.c:717-752.
pub fn narrow_context<'a>(contexts: &'a [DhcpContext], addr: Ipv4Addr) -> Option<&'a DhcpContext> {
    // Try pool range first.
    if address_available(contexts, addr) {
        for ctx in contexts {
            if ctx.flags & (CONTEXT_STATIC | CONTEXT_PROXY) != 0 {
                continue;
            }
            let a = u32::from(addr);
            if a >= u32::from(ctx.start) && a <= u32::from(ctx.end) {
                return Some(ctx);
            }
        }
    }

    // Try static context on same subnet.
    for ctx in contexts {
        if ctx.flags & CONTEXT_STATIC != 0
            && ctx.netmask != Ipv4Addr::UNSPECIFIED
            && is_same_net(addr, ctx.start, ctx.netmask)
        {
            return Some(ctx);
        }
    }

    // Any context on same subnet (non-proxy).
    for ctx in contexts {
        if ctx.flags & CONTEXT_PROXY != 0 {
            continue;
        }
        if ctx.netmask != Ipv4Addr::UNSPECIFIED && is_same_net(addr, ctx.start, ctx.netmask) {
            return Some(ctx);
        }
    }

    None
}

/// Find a static DHCP host config entry by IPv4 address.
///
/// Port of `config_find_by_address()` from dhcp.c:754-763.
pub fn config_find_by_address(configs: &[DhcpConfig], addr: Ipv4Addr) -> Option<&DhcpConfig> {
    configs
        .iter()
        .find(|c| c.flags & CONFIG_ADDR != 0 && c.addr == addr)
}

// ─────────────────────────────────────────────────────────────────────────────
// Packet validation (ported from dhcp.c:130-176)
// ─────────────────────────────────────────────────────────────────────────────

/// Validate a raw DHCP packet without fully parsing it.
///
/// Checks minimum size, op=1 (BOOTREQUEST), hlen<=16, and magic cookie.
pub fn dhcp_packet_validate(data: &[u8]) -> Result<(), &'static str> {
    if data.len() < 240 {
        return Err("packet too short");
    }
    if data[0] != 1 {
        return Err("not a BOOTREQUEST");
    }
    if data[2] > DHCP_CHADDR_MAX as u8 {
        return Err("hlen exceeds maximum");
    }
    let cookie = u32::from_be_bytes([data[236], data[237], data[238], data[239]]);
    if cookie != DHCP_COOKIE {
        return Err("bad magic cookie");
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// SDBM hash for address allocation (ported from dhcp.c:838-845)
// ─────────────────────────────────────────────────────────────────────────────

/// Compute SDBM hash of a hardware address for DHCP address allocation.
///
/// Used as seed for distributing clients across the address pool.
/// Port of the SDBM hash in dhcp.c:840-845.
pub fn sdbm_hash(hwaddr: &[u8]) -> u32 {
    let mut j: u32 = 0;
    for &b in hwaddr {
        j = (b as u32).wrapping_add(j.wrapping_shl(6)).wrapping_add(j.wrapping_shl(16)).wrapping_sub(j);
    }
    if j == 0 { 1 } else { j } // 0 is a sentinel marker
}

/// Calculate the starting address for DHCP allocation using hash-based seeding.
///
/// Maps the hash into the range [start, end] using modular arithmetic.
/// Port of the address calculation in dhcp.c:860-861.
pub fn hash_to_addr(hash: u32, epoch: u32, start: Ipv4Addr, end: Ipv4Addr) -> Ipv4Addr {
    let s = u32::from(start);
    let e = u32::from(end);
    let range = e.wrapping_sub(s).wrapping_add(1);
    if range == 0 {
        return start; // full u32 range
    }
    let offset = hash.wrapping_add(epoch) % range;
    Ipv4Addr::from(s.wrapping_add(offset))
}

/// Check if an IPv4 address is safe to allocate (avoids Windows .0 and .255 issues).
///
/// In class-C ranges, addresses ending in .0 or .255 cause Windows problems.
/// Port of the Windows workaround check in dhcp.c:877-881.
pub fn is_allocatable_addr(addr: Ipv4Addr) -> bool {
    let a = u32::from(addr);
    // Class C check: first octet 192-223
    let first_octet = (a >> 24) & 0xff;
    if first_octet >= 192 && first_octet <= 223 {
        let last_octet = a & 0xff;
        if last_octet == 0 || last_octet == 0xff {
            return false;
        }
    }
    true
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::ErrorKind;
    use crate::dhcp_protocol::{DHCP_CHADDR_MAX, OPTION_MESSAGE_TYPE, OPTION_END};

    async fn bind_udp_or_skip(addr: &str) -> Option<tokio::net::UdpSocket> {
        match tokio::net::UdpSocket::bind(addr).await {
            Ok(sock) => Some(sock),
            Err(err) if err.kind() == ErrorKind::PermissionDenied => None,
            Err(err) => panic!("failed to bind {addr}: {err}"),
        }
    }

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
            sname:  [0u8; 64],
            file:   [0u8; 128],
            options: vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8, OPTION_END],
        }
    }

    fn packet_to_wire(pkt: &DhcpPacket) -> Vec<u8> {
        let mut buf = Vec::with_capacity(300);
        buf.push(pkt.op);
        buf.push(pkt.htype);
        buf.push(pkt.hlen);
        buf.push(pkt.hops);
        buf.extend_from_slice(&pkt.xid.to_be_bytes());
        buf.extend_from_slice(&pkt.secs.to_be_bytes());
        buf.extend_from_slice(&pkt.flags.to_be_bytes());
        buf.extend_from_slice(&pkt.ciaddr.octets());
        buf.extend_from_slice(&pkt.yiaddr.octets());
        buf.extend_from_slice(&pkt.siaddr.octets());
        buf.extend_from_slice(&pkt.giaddr.octets());
        buf.extend_from_slice(&pkt.chaddr);
        buf.extend_from_slice(&pkt.sname);
        buf.extend_from_slice(&pkt.file);
        buf.extend_from_slice(&DHCP_COOKIE.to_be_bytes());
        buf.extend_from_slice(&pkt.options);
        if pkt.options.last() != Some(&OPTION_END) {
            buf.push(OPTION_END);
        }
        while buf.len() < 300 {
            buf.push(0);
        }
        buf
    }

    fn count_option(buf: &[u8], code: u8) -> usize {
        let mut count = 0;
        let mut i = 0;
        while i < buf.len() {
            match buf[i] {
                OPTION_END => break,
                0 => i += 1,
                opt => {
                    if i + 1 >= buf.len() {
                        break;
                    }
                    let len = usize::from(buf[i + 1]);
                    if i + 2 + len > buf.len() {
                        break;
                    }
                    if opt == code {
                        count += 1;
                    }
                    i += 2 + len;
                }
            }
        }
        count
    }

    fn default_cfg() -> DhcpServerConfig {
        DhcpServerConfig {
            pool_start: Ipv4Addr::new(10, 0, 0, 100),
            pool_end:   Ipv4Addr::new(10, 0, 0, 200),
            server_ip:  Ipv4Addr::new(10, 0, 0, 1),
            max_packet: 1500,
            configs:    vec![],
            vendor_rules: vec![],
            user_class_rules: vec![],
            mac_rules: vec![],
            relay_id_rules: vec![],
            reply_delays: vec![],
            contexts: vec![],
            dhcp_opts: vec![],
            boot_configs: vec![],
            domain_suffix: None,
            lease_file: None,
        }
    }

    #[test]
    fn discover_produces_offer() {
        let pkt = base_packet();
        let cfg = default_cfg();
        let reply = dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new());
        assert!(reply.is_some());
        assert_eq!(reply.unwrap().msg_type, DhcpMsgType::Offer);
    }

    #[test]
    fn release_produces_no_reply() {
        let mut pkt = base_packet();
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Release as u8, OPTION_END];
        let cfg = default_cfg();
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn decline_produces_no_reply() {
        let mut pkt = base_packet();
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Decline as u8, OPTION_END];
        let cfg = default_cfg();
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn discover_matching_dhcp_ignore_produces_no_reply() {
        use crate::types::dhcp::{DhcpConfig, HwaddrConfig, CONFIG_DISABLE};

        let mut hw = [0u8; DHCP_CHADDR_MAX];
        hw[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let ignore = DhcpConfig {
            flags: CONFIG_DISABLE,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![],
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![HwaddrConfig {
                hwaddr: hw,
                hwaddr_len: 6,
                hwaddr_type: 1,
                wildcard_mask: 0,
            }],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };

        let mut pkt = base_packet();
        pkt.chaddr[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut cfg = default_cfg();
        cfg.configs.push(ignore);
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn discover_matching_static_config_offers_static_address() {
        use crate::types::dhcp::{DhcpConfig, HwaddrConfig, CONFIG_ADDR};

        let mut hw = [0u8; DHCP_CHADDR_MAX];
        hw[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let static_cfg = DhcpConfig {
            flags: CONFIG_ADDR,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![],
            addr: Ipv4Addr::new(10, 0, 0, 42),
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![HwaddrConfig {
                hwaddr: hw,
                hwaddr_len: 6,
                hwaddr_type: 1,
                wildcard_mask: 0,
            }],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };

        let mut pkt = base_packet();
        pkt.chaddr[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let mut cfg = default_cfg();
        cfg.configs.push(static_cfg);
        let reply = dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).expect("static config should offer");
        assert_eq!(reply.msg_type, DhcpMsgType::Offer);
        assert_eq!(reply.yiaddr, Ipv4Addr::new(10, 0, 0, 42));
    }

    #[test]
    fn discover_matching_vendor_tag_ignore_produces_no_reply() {
        use crate::types::dhcp::{DhcpConfig, DhcpNetid, DhcpVendorRule, CONFIG_DISABLE};

        let ignore = DhcpConfig {
            flags: CONFIG_DISABLE,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![DhcpNetid { net: "pxe".into() }],
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };

        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
            OPTION_VENDOR_ID, 9, b'P', b'X', b'E', b'C', b'l', b'i', b'e', b'n', b't',
            OPTION_END,
        ];
        let mut cfg = default_cfg();
        cfg.configs.push(ignore);
        cfg.vendor_rules.push(DhcpVendorRule {
            netid: DhcpNetid { net: "pxe".into() },
            vendor_class: b"PXEClient".to_vec(),
        });
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn discover_matching_userclass_tag_ignore_produces_no_reply() {
        use crate::types::dhcp::{DhcpConfig, DhcpNetid, DhcpUserClassRule, CONFIG_DISABLE};

        let ignore = DhcpConfig {
            flags: CONFIG_DISABLE,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![DhcpNetid { net: "accounts".into() }],
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };

        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
            OPTION_USER_CLASS, 9, 8, b'a', b'c', b'c', b'o', b'u', b'n', b't', b's',
            OPTION_END,
        ];
        let mut cfg = default_cfg();
        cfg.configs.push(ignore);
        cfg.user_class_rules.push(DhcpUserClassRule {
            netid: DhcpNetid { net: "accounts".into() },
            user_class: b"accounts".to_vec(),
        });
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn discover_matching_broken_userclass_tag_ignore_produces_no_reply() {
        use crate::types::dhcp::{DhcpConfig, DhcpNetid, DhcpUserClassRule, CONFIG_DISABLE};

        let ignore = DhcpConfig {
            flags: CONFIG_DISABLE,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![DhcpNetid { net: "legacy".into() }],
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };

        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
            OPTION_USER_CLASS, 6, b'l', b'e', b'g', b'a', b'c', b'y',
            OPTION_END,
        ];
        let mut cfg = default_cfg();
        cfg.configs.push(ignore);
        cfg.user_class_rules.push(DhcpUserClassRule {
            netid: DhcpNetid { net: "legacy".into() },
            user_class: b"legacy".to_vec(),
        });
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn discover_matching_mac_tag_ignore_produces_no_reply() {
        use crate::types::dhcp::{DhcpConfig, DhcpMacRule, DhcpNetid, CONFIG_DISABLE};

        let ignore = DhcpConfig {
            flags: CONFIG_DISABLE,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![DhcpNetid { net: "printer".into() }],
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };

        let mut pkt = base_packet();
        pkt.chaddr[..6].copy_from_slice(&[0x00, 0x60, 0x8c, 0x12, 0x34, 0x56]);
        let mut cfg = default_cfg();
        cfg.configs.push(ignore);
        cfg.mac_rules.push(DhcpMacRule {
            netid: DhcpNetid { net: "printer".into() },
            hwaddr: [0x00, 0x60, 0x8c, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            hwaddr_len: 6,
            hwaddr_type: 1,
            wildcard_mask: 0b000111,
        });
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn discover_matching_circuitid_tag_ignore_produces_no_reply() {
        use crate::types::dhcp::{DhcpConfig, DhcpNetid, DhcpRelayIdRule, CONFIG_DISABLE};

        let ignore = DhcpConfig {
            flags: CONFIG_DISABLE,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![DhcpNetid { net: "uplink-a".into() }],
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };

        let mut pkt = base_packet();
        pkt.giaddr = Ipv4Addr::new(10, 0, 0, 254);
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
            OPTION_AGENT_ID, 8, 1, 6, b'u', b'p', b'l', b'i', b'n', b'k',
            OPTION_END,
        ];
        let mut cfg = default_cfg();
        cfg.configs.push(ignore);
        cfg.relay_id_rules.push(DhcpRelayIdRule {
            netid: DhcpNetid { net: "uplink-a".into() },
            subopt: crate::dhcp_protocol::SUBOPT_CIRCUIT_ID,
            data: b"uplink".to_vec(),
        });
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn discover_matching_hex_circuitid_tag_ignore_produces_no_reply() {
        use crate::types::dhcp::{DhcpConfig, DhcpNetid, DhcpRelayIdRule, CONFIG_DISABLE};

        let ignore = DhcpConfig {
            flags: CONFIG_DISABLE,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![DhcpNetid { net: "relayhex".into() }],
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };

        let mut pkt = base_packet();
        pkt.giaddr = Ipv4Addr::new(10, 0, 0, 254);
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
            OPTION_AGENT_ID, 6, 1, 4, 0x01, 0x02, 0x03, 0x04,
            OPTION_END,
        ];
        let mut cfg = default_cfg();
        cfg.configs.push(ignore);
        cfg.relay_id_rules.push(DhcpRelayIdRule {
            netid: DhcpNetid { net: "relayhex".into() },
            subopt: crate::dhcp_protocol::SUBOPT_CIRCUIT_ID,
            data: vec![0x01, 0x02, 0x03, 0x04],
        });
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn discover_matching_remoteid_tag_ignore_produces_no_reply() {
        use crate::types::dhcp::{DhcpConfig, DhcpNetid, DhcpRelayIdRule, CONFIG_DISABLE};

        let ignore = DhcpConfig {
            flags: CONFIG_DISABLE,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![DhcpNetid { net: "relay-remote".into() }],
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };

        let mut pkt = base_packet();
        pkt.giaddr = Ipv4Addr::new(10, 0, 0, 254);
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
            OPTION_AGENT_ID, 12, 2, 10, b'r', b'e', b'm', b'o', b't', b'e', b'-', b'i', b'd', b'1',
            OPTION_END,
        ];
        let mut cfg = default_cfg();
        cfg.configs.push(ignore);
        cfg.relay_id_rules.push(DhcpRelayIdRule {
            netid: DhcpNetid { net: "relay-remote".into() },
            subopt: crate::dhcp_protocol::SUBOPT_REMOTE_ID,
            data: b"remote-id1".to_vec(),
        });
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn discover_matching_subscrid_tag_ignore_produces_no_reply() {
        use crate::types::dhcp::{DhcpConfig, DhcpNetid, DhcpRelayIdRule, CONFIG_DISABLE};

        let ignore = DhcpConfig {
            flags: CONFIG_DISABLE,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![DhcpNetid { net: "subscriber-a".into() }],
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };

        let mut pkt = base_packet();
        pkt.giaddr = Ipv4Addr::new(10, 0, 0, 254);
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
            OPTION_AGENT_ID, 15, 6, 13, b's', b'u', b'b', b's', b'c', b'r', b'i', b'b', b'e', b'r', b'-', b'1', b'a',
            OPTION_END,
        ];
        let mut cfg = default_cfg();
        cfg.configs.push(ignore);
        cfg.relay_id_rules.push(DhcpRelayIdRule {
            netid: DhcpNetid { net: "subscriber-a".into() },
            subopt: crate::dhcp_protocol::SUBOPT_SUBSCR_ID,
            data: b"subscriber-1a".to_vec(),
        });
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn discover_default_reply_delay_is_applied_to_offer() {
        use crate::types::dhcp::DhcpReplyDelay;

        let pkt = base_packet();
        let mut cfg = default_cfg();
        cfg.reply_delays.push(DhcpReplyDelay {
            delay_secs: 5,
            filter: vec![],
        });

        let reply = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new()).expect("discover should produce an offer");
        assert_eq!(reply.reply.msg_type, DhcpMsgType::Offer);
        assert_eq!(reply.delay_secs, 5);
    }

    #[test]
    fn discover_tagged_reply_delay_overrides_default() {
        use crate::types::dhcp::{DhcpNetid, DhcpReplyDelay, DhcpVendorRule};

        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
            OPTION_VENDOR_ID, 9, b'P', b'X', b'E', b'C', b'l', b'i', b'e', b'n', b't',
            OPTION_END,
        ];

        let mut cfg = default_cfg();
        cfg.vendor_rules.push(DhcpVendorRule {
            netid: DhcpNetid { net: "pxe".into() },
            vendor_class: b"PXEClient".to_vec(),
        });
        cfg.reply_delays.push(DhcpReplyDelay {
            delay_secs: 2,
            filter: vec![DhcpNetid { net: "pxe".into() }],
        });
        cfg.reply_delays.push(DhcpReplyDelay {
            delay_secs: 7,
            filter: vec![],
        });

        let reply = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new()).expect("discover should produce an offer");
        assert_eq!(reply.reply.msg_type, DhcpMsgType::Offer);
        assert_eq!(reply.delay_secs, 2);
    }

    #[test]
    fn discover_default_reply_delay_is_used_when_no_tag_matches() {
        use crate::types::dhcp::{DhcpNetid, DhcpReplyDelay};

        let pkt = base_packet();
        let mut cfg = default_cfg();
        cfg.reply_delays.push(DhcpReplyDelay {
            delay_secs: 2,
            filter: vec![DhcpNetid { net: "pxe".into() }],
        });
        cfg.reply_delays.push(DhcpReplyDelay {
            delay_secs: 7,
            filter: vec![],
        });

        let reply = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new()).expect("discover should produce an offer");
        assert_eq!(reply.reply.msg_type, DhcpMsgType::Offer);
        assert_eq!(reply.delay_secs, 7);
    }

    #[test]
    fn request_reply_does_not_apply_reply_delay() {
        use crate::types::dhcp::DhcpReplyDelay;

        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Request as u8,
            crate::dhcp_protocol::OPTION_REQUESTED_IP, 4, 10, 0, 0, 123,
            OPTION_END,
        ];

        let mut cfg = default_cfg();
        cfg.reply_delays.push(DhcpReplyDelay {
            delay_secs: 5,
            filter: vec![],
        });

        let reply = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new()).expect("request should produce an ack");
        assert_eq!(reply.reply.msg_type, DhcpMsgType::Ack);
        assert_eq!(reply.delay_secs, 0);
    }

    // ── lease store integration ─────────────────────────────────────────────

    #[test]
    fn request_ack_creates_persisted_lease() {
        let mut pkt = base_packet();
        pkt.chaddr[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Request as u8,
            crate::dhcp_protocol::OPTION_REQUESTED_IP, 4, 10, 0, 0, 123,
            OPTION_END,
        ];
        let cfg = default_cfg();
        let mut lease_db = LeaseDb::new();

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db).expect("request should ack");
        assert_eq!(dispatched.reply.msg_type, DhcpMsgType::Ack);

        let lease = lease_db
            .find_by_addr(Ipv4Addr::new(10, 0, 0, 123))
            .expect("lease should be recorded");
        assert_eq!(&lease.hwaddr[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert!(lease.expires.is_some());
    }

    #[test]
    fn release_frees_lease() {
        let addr = Ipv4Addr::new(10, 0, 0, 150);
        let mut lease_db = LeaseDb::new();
        lease_db.allocate_v4(addr);
        assert!(lease_db.find_by_addr(addr).is_some());

        let mut pkt = base_packet();
        pkt.ciaddr = addr;
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Release as u8, OPTION_END];
        let cfg = default_cfg();

        assert!(dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db).is_none());
        assert!(lease_db.find_by_addr(addr).is_none());
    }

    #[test]
    fn release_for_out_of_pool_ciaddr_leaves_lease_store_untouched() {
        let addr = Ipv4Addr::new(10, 0, 0, 150);
        let mut lease_db = LeaseDb::new();
        lease_db.allocate_v4(addr);

        let mut pkt = base_packet();
        pkt.ciaddr = Ipv4Addr::new(192, 168, 1, 50); // not in cfg's pool
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Release as u8, OPTION_END];
        let cfg = default_cfg();

        assert!(dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db).is_none());
        // Unrelated lease must survive an out-of-pool RELEASE.
        assert!(lease_db.find_by_addr(addr).is_some());
    }

    #[test]
    fn decline_removes_lease() {
        let addr = Ipv4Addr::new(10, 0, 0, 160);
        let mut lease_db = LeaseDb::new();
        lease_db.allocate_v4(addr);

        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Decline as u8,
            crate::dhcp_protocol::OPTION_REQUESTED_IP, 4, 10, 0, 0, 160,
            OPTION_END,
        ];
        let cfg = default_cfg();

        assert!(dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db).is_none());
        assert!(lease_db.find_by_addr(addr).is_none());
    }

    #[test]
    fn inform_returns_ack_without_allocating_address() {
        let mut pkt = base_packet();
        pkt.ciaddr = Ipv4Addr::new(10, 0, 0, 55);
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Inform as u8, OPTION_END];
        let cfg = default_cfg();
        let mut lease_db = LeaseDb::new();

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db).expect("inform should ack");
        assert_eq!(dispatched.reply.msg_type, DhcpMsgType::Ack);
        assert_eq!(dispatched.reply.yiaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(lease_db.count(), 0);
    }

    #[test]
    fn request_for_address_reserved_to_another_client_is_nak_d() {
        use crate::types::dhcp::{DhcpConfig, HwaddrConfig, CONFIG_ADDR};

        let mut reserved_hw = [0u8; DHCP_CHADDR_MAX];
        reserved_hw[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let reserved_cfg = DhcpConfig {
            flags: CONFIG_ADDR,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![],
            addr: Ipv4Addr::new(10, 0, 0, 150),
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![HwaddrConfig {
                hwaddr: reserved_hw,
                hwaddr_len: 6,
                hwaddr_type: 1,
                wildcard_mask: 0,
            }],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };

        let mut cfg = default_cfg();
        cfg.configs.push(reserved_cfg);

        // A different client (no matching config) requests the reserved address.
        let mut pkt = base_packet();
        pkt.chaddr[..6].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Request as u8,
            crate::dhcp_protocol::OPTION_REQUESTED_IP, 4, 10, 0, 0, 150,
            OPTION_END,
        ];

        let reply = dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).expect("request should reply");
        assert_eq!(reply.msg_type, DhcpMsgType::Nak);
    }

    #[test]
    fn request_for_own_reserved_address_is_acked() {
        use crate::types::dhcp::{DhcpConfig, HwaddrConfig, CONFIG_ADDR};

        let mut hw = [0u8; DHCP_CHADDR_MAX];
        hw[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let owner_cfg = DhcpConfig {
            flags: CONFIG_ADDR,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![],
            addr: Ipv4Addr::new(10, 0, 0, 150),
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![HwaddrConfig {
                hwaddr: hw,
                hwaddr_len: 6,
                hwaddr_type: 1,
                wildcard_mask: 0,
            }],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };

        let mut cfg = default_cfg();
        cfg.configs.push(owner_cfg);

        // The client that actually owns the reservation requests it.
        let mut pkt = base_packet();
        pkt.chaddr[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Request as u8,
            crate::dhcp_protocol::OPTION_REQUESTED_IP, 4, 10, 0, 0, 150,
            OPTION_END,
        ];

        let reply = dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).expect("request should reply");
        assert_eq!(reply.msg_type, DhcpMsgType::Ack);
    }

    #[test]
    fn offer_and_ack_carry_lease_time_option() {
        let pkt = base_packet(); // discover
        let cfg = default_cfg();
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new()).expect("discover should offer");
        assert!(find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_LEASE_TIME).is_some());

        let mut req_pkt = base_packet();
        req_pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Request as u8,
            crate::dhcp_protocol::OPTION_REQUESTED_IP, 4, 10, 0, 0, 123,
            OPTION_END,
        ];
        let dispatched = dispatch_dhcp_with_meta(&req_pkt, &cfg, &mut LeaseDb::new()).expect("request should ack");
        assert!(find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_LEASE_TIME).is_some());
    }

    #[test]
    fn inform_ack_does_not_carry_lease_time_option() {
        let mut pkt = base_packet();
        pkt.ciaddr = Ipv4Addr::new(10, 0, 0, 55);
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Inform as u8, OPTION_END];
        let cfg = default_cfg();
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new()).expect("inform should ack");
        assert!(find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_LEASE_TIME).is_none());
    }

    #[test]
    fn inform_ack_does_not_carry_t1_t2_options() {
        // RFC 2131 says DHCPINFORM shouldn't carry lease-time parameters at
        // all; do_options() is only given a finite lease time for OFFER/ACK
        // answering a REQUEST (rfc2131.c:1817 passes 0xffffffff for INFORM).
        let mut pkt = base_packet();
        pkt.ciaddr = Ipv4Addr::new(10, 0, 0, 55);
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Inform as u8, OPTION_END];
        let cfg = default_cfg();
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new()).expect("inform should ack");
        assert!(find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_T1).is_none());
        assert!(find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_T2).is_none());
    }

    #[tokio::test]
    async fn run_dhcp_loop_persists_lease_to_configured_file() {
        let Some(server) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(client) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(receiver) = bind_udp_or_skip("127.0.0.1:0").await else { return; };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loop_leases.dat");
        let path_str = path.to_str().unwrap().to_string();

        let receiver_addr = receiver.local_addr().unwrap();
        let server = std::sync::Arc::new(server);
        let mut cfg = default_cfg();
        cfg.lease_file = Some(path_str.clone());
        let opts = DhcpLoopOptions {
            reply_port_override: Some(receiver_addr.port()),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let loop_task = tokio::spawn(run_dhcp_loop(server.clone(), cfg, opts, LeaseDb::new(), shutdown_rx));

        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Request as u8,
            crate::dhcp_protocol::OPTION_REQUESTED_IP, 4, 10, 0, 0, 123,
            OPTION_END,
        ];
        let wire = packet_to_wire(&pkt);
        client.send_to(&wire, server.local_addr().unwrap()).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_millis(250), receiver.recv_from(&mut buf))
            .await
            .expect("timed out waiting for DHCP loop reply")
            .unwrap();
        let reply = parse_dhcp_packet(&buf[..len]).expect("loop reply should parse");
        assert_eq!(get_message_type(&reply.options), Some(DhcpMsgType::Ack));

        shutdown_tx.send(true).unwrap();
        loop_task.await.unwrap().unwrap();

        let persisted = LeaseDb::load_from_file(&path_str).expect("lease file should have been written");
        assert!(persisted.find_by_addr(Ipv4Addr::new(10, 0, 0, 123)).is_some());
    }

    #[test]
    fn discover_injects_requested_configured_options() {
        use crate::types::dhcp::{DhcpContext, DhcpNetid, DhcpOpt, CONTEXT_DHCP};

        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
            OPTION_REQUESTED_OPTIONS, 2, crate::dhcp_protocol::OPTION_DOMAINNAME, crate::dhcp_protocol::OPTION_ROUTER,
            OPTION_END,
        ];

        let mut cfg = default_cfg();
        cfg.contexts.push(DhcpContext {
            lease_time: 3600,
            addr_epoch: 0,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(10, 0, 0, 255),
            local: Ipv4Addr::new(10, 0, 0, 1),
            router: Ipv4Addr::new(10, 0, 0, 1),
            start: Ipv4Addr::new(10, 0, 0, 100),
            end: Ipv4Addr::new(10, 0, 0, 200),
            flags: CONTEXT_DHCP,
            netid: DhcpNetid { net: String::new() },
            filter: vec![],
            #[cfg(feature = "dhcp6")]
            start6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            end6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 0,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
        });
        cfg.dhcp_opts.push(DhcpOpt {
            opt: crate::dhcp_protocol::OPTION_DOMAINNAME as i32,
            flags: crate::types::dhcp::DHOPT_STRING,
            val: Some(b"lab.example".to_vec()),
            netid: vec![],
            encap: 0,
            vendor_class: None,
        });

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new()).expect("discover should produce an offer");
        assert!(find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_DOMAINNAME).is_some());
        assert!(find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_ROUTER).is_some());
    }

    #[test]
    fn discover_host_set_tag_selects_tagged_option() {
        use crate::types::dhcp::{DhcpConfig, DhcpContext, DhcpNetid, DhcpOpt, HwaddrConfig, CONTEXT_DHCP, CONFIG_NAME};

        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
            OPTION_HOSTNAME, 5, b'h', b'o', b's', b't', b'1',
            OPTION_REQUESTED_OPTIONS, 1, crate::dhcp_protocol::OPTION_DOMAINNAME,
            OPTION_END,
        ];

        let mut hw = [0u8; DHCP_CHADDR_MAX];
        hw[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);

        let mut cfg = default_cfg();
        cfg.contexts.push(DhcpContext {
            lease_time: 3600,
            addr_epoch: 0,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(10, 0, 0, 255),
            local: Ipv4Addr::new(10, 0, 0, 1),
            router: Ipv4Addr::new(10, 0, 0, 1),
            start: Ipv4Addr::new(10, 0, 0, 100),
            end: Ipv4Addr::new(10, 0, 0, 200),
            flags: CONTEXT_DHCP,
            netid: DhcpNetid { net: String::new() },
            filter: vec![],
            #[cfg(feature = "dhcp6")]
            start6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            end6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 0,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
        });
        cfg.configs.push(DhcpConfig {
            flags: CONFIG_NAME,
            clid: None,
            hostname: Some("host1".into()),
            domain: None,
            netid: vec![DhcpNetid { net: "lab".into() }],
            filter: vec![],
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![HwaddrConfig {
                hwaddr: hw,
                hwaddr_len: 6,
                hwaddr_type: 1,
                wildcard_mask: 0,
            }],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        });
        cfg.dhcp_opts.push(DhcpOpt {
            opt: crate::dhcp_protocol::OPTION_DOMAINNAME as i32,
            flags: crate::types::dhcp::DHOPT_STRING,
            val: Some(b"default.example".to_vec()),
            netid: vec![],
            encap: 0,
            vendor_class: None,
        });
        cfg.dhcp_opts.push(DhcpOpt {
            opt: crate::dhcp_protocol::OPTION_DOMAINNAME as i32,
            flags: crate::types::dhcp::DHOPT_STRING,
            val: Some(b"lab.example".to_vec()),
            netid: vec![DhcpNetid { net: "lab".into() }],
            encap: 0,
            vendor_class: None,
        });

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new()).expect("discover should produce an offer");
        assert_eq!(
            find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_DOMAINNAME),
            Some(&b"lab.example"[..])
        );
    }

    #[test]
    fn discover_boot_config_sets_wire_fields_without_duplicate_message_type() {
        use crate::types::dhcp::DhcpBoot;

        let pkt = base_packet();
        let mut cfg = default_cfg();
        cfg.boot_configs.push(DhcpBoot {
            file: Some("pxelinux.0".into()),
            sname: Some("boot.example".into()),
            tftp_sname: None,
            next_server: Ipv4Addr::new(10, 0, 0, 2),
            netid: vec![],
        });

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new()).expect("discover should produce an offer");
        assert_eq!(dispatched.reply.siaddr, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(dispatched.reply.file.as_deref(), Some("pxelinux.0"));
        assert_eq!(dispatched.reply.sname.as_deref(), Some("boot.example"));

        let wire = dhcp_reply_to_wire(&dispatched.reply, &pkt);
        assert_eq!(&wire[44..56], b"boot.example");
        assert_eq!(&wire[108..117], b"pxelinux.");
        assert_eq!(count_option(&wire[240..], OPTION_MESSAGE_TYPE), 1);
    }

    #[test]
    fn is_relayed_detects_giaddr() {
        let mut pkt = base_packet();
        assert!(!is_relayed(&pkt));
        pkt.giaddr = Ipv4Addr::new(192, 168, 1, 1);
        assert!(is_relayed(&pkt));
    }

    #[test]
    fn reply_dest_relay_goes_to_port_67() {
        let mut pkt = base_packet();
        pkt.giaddr = Ipv4Addr::new(10, 0, 0, 254);
        let dest = reply_dest(&pkt);
        match dest {
            SocketAddr::V4(a) => {
                assert_eq!(a.ip(), &Ipv4Addr::new(10, 0, 0, 254));
                assert_eq!(a.port(), DHCP_SERVER_PORT);
            }
            _ => panic!("expected V4"),
        }
    }

    #[test]
    fn reply_dest_known_client_unicast() {
        let mut pkt = base_packet();
        pkt.ciaddr = Ipv4Addr::new(10, 0, 0, 100);
        let dest = reply_dest(&pkt);
        match dest {
            SocketAddr::V4(a) => {
                assert_eq!(a.ip(), &Ipv4Addr::new(10, 0, 0, 100));
                assert_eq!(a.port(), DHCP_CLIENT_PORT);
            }
            _ => panic!("expected V4"),
        }
    }

    #[test]
    fn reply_dest_unknown_client_broadcast() {
        let pkt = base_packet();
        let dest = reply_dest(&pkt);
        match dest {
            SocketAddr::V4(a) => {
                assert_eq!(a.ip(), &Ipv4Addr::BROADCAST);
                assert_eq!(a.port(), DHCP_CLIENT_PORT);
            }
            _ => panic!("expected V4"),
        }
    }

    #[tokio::test]
    async fn send_dhcp_reply_to_sends_wire_reply() {
        let Some(receiver) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(sender) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let dest = receiver.local_addr().unwrap();

        let pkt = base_packet();
        let cfg = default_cfg();
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new()).expect("discover should produce an offer");

        let sent = match send_dhcp_reply_to(&sender, &pkt, &dispatched, dest).await {
            Ok(sent) => sent,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => return,
            Err(err) => panic!("send_dhcp_reply_to failed: {err}"),
        };
        assert!(sent >= 300);

        let mut buf = [0u8; 512];
        let (len, from) = tokio::time::timeout(Duration::from_millis(250), receiver.recv_from(&mut buf))
            .await
            .expect("timed out waiting for DHCP reply")
            .unwrap();
        assert_eq!(from, sender.local_addr().unwrap());

        let reply = parse_dhcp_packet(&buf[..len]).expect("wire reply should parse");
        assert_eq!(get_message_type(&reply.options), Some(DhcpMsgType::Offer));
        assert_eq!(reply.yiaddr, Ipv4Addr::new(10, 0, 0, 100));
    }

    #[tokio::test]
    async fn send_dhcp_reply_to_honors_delay() {
        use crate::types::dhcp::DhcpReplyDelay;

        let Some(receiver) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(sender) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let dest = receiver.local_addr().unwrap();

        let pkt = base_packet();
        let mut cfg = default_cfg();
        cfg.reply_delays.push(DhcpReplyDelay {
            delay_secs: 1,
            filter: vec![],
        });
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new()).expect("discover should produce an offer");
        assert_eq!(dispatched.delay_secs, 1);

        let started = tokio::time::Instant::now();
        let send_task = tokio::spawn(async move {
            send_dhcp_reply_to(&sender, &pkt, &dispatched, dest).await
        });

        let early = tokio::time::timeout(Duration::from_millis(200), async {
            let mut buf = [0u8; 512];
            receiver.recv_from(&mut buf).await
        }).await;
        assert!(early.is_err(), "reply arrived before configured delay elapsed");

        let sent = match send_task.await.unwrap() {
            Ok(sent) => sent,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => return,
            Err(err) => panic!("send_dhcp_reply_to failed: {err}"),
        };

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_millis(250), receiver.recv_from(&mut buf))
            .await
            .expect("timed out waiting for delayed DHCP reply")
            .unwrap();
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(900), "delay elapsed too quickly: {elapsed:?}");

        assert_eq!(sent, len);
        let reply = parse_dhcp_packet(&buf[..len]).expect("wire reply should parse");
        assert_eq!(get_message_type(&reply.options), Some(DhcpMsgType::Offer));
    }

    #[tokio::test]
    async fn run_dhcp_loop_receives_and_replies() {
        let Some(server) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(client) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(receiver) = bind_udp_or_skip("127.0.0.1:0").await else { return; };

        let receiver_addr = receiver.local_addr().unwrap();
        let server = std::sync::Arc::new(server);
        let cfg = default_cfg();
        let opts = DhcpLoopOptions {
            reply_port_override: Some(receiver_addr.port()),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let loop_task = tokio::spawn(run_dhcp_loop(server.clone(), cfg, opts, LeaseDb::new(), shutdown_rx));

        let pkt = base_packet();
        let wire = packet_to_wire(&pkt);
        client.send_to(&wire, server.local_addr().unwrap()).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_millis(250), receiver.recv_from(&mut buf))
            .await
            .expect("timed out waiting for DHCP loop reply")
            .unwrap();
        let reply = parse_dhcp_packet(&buf[..len]).expect("loop reply should parse");
        assert_eq!(get_message_type(&reply.options), Some(DhcpMsgType::Offer));
        assert_eq!(reply.yiaddr, Ipv4Addr::new(10, 0, 0, 100));

        shutdown_tx.send(true).unwrap();
        loop_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_dhcp_loop_honors_reply_delay() {
        use crate::types::dhcp::DhcpReplyDelay;

        let Some(server) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(client) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(receiver) = bind_udp_or_skip("127.0.0.1:0").await else { return; };

        let receiver_addr = receiver.local_addr().unwrap();
        let server = std::sync::Arc::new(server);
        let mut cfg = default_cfg();
        cfg.reply_delays.push(DhcpReplyDelay {
            delay_secs: 1,
            filter: vec![],
        });
        let opts = DhcpLoopOptions {
            reply_port_override: Some(receiver_addr.port()),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let loop_task = tokio::spawn(run_dhcp_loop(server.clone(), cfg, opts, LeaseDb::new(), shutdown_rx));

        let pkt = base_packet();
        let wire = packet_to_wire(&pkt);
        let started = tokio::time::Instant::now();
        client.send_to(&wire, server.local_addr().unwrap()).await.unwrap();

        let early = tokio::time::timeout(Duration::from_millis(200), async {
            let mut buf = [0u8; 512];
            receiver.recv_from(&mut buf).await
        }).await;
        assert!(early.is_err(), "loop reply arrived before configured delay elapsed");

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_millis(1200), receiver.recv_from(&mut buf))
            .await
            .expect("timed out waiting for delayed loop reply")
            .unwrap();
        let elapsed = started.elapsed();
        assert!(elapsed >= Duration::from_millis(900), "delay elapsed too quickly: {elapsed:?}");

        let reply = parse_dhcp_packet(&buf[..len]).expect("loop reply should parse");
        assert_eq!(get_message_type(&reply.options), Some(DhcpMsgType::Offer));

        shutdown_tx.send(true).unwrap();
        loop_task.await.unwrap().unwrap();
    }

    #[test]
    fn parse_short_packet_returns_none() {
        assert!(parse_dhcp_packet(&[0u8; 100]).is_none());
    }

    #[test]
    fn parse_wrong_cookie_returns_none() {
        let mut data = vec![0u8; 300];
        // Set bad cookie at offset 236
        data[236] = 0xDE;
        data[237] = 0xAD;
        data[238] = 0xBE;
        data[239] = 0xEF;
        assert!(parse_dhcp_packet(&data).is_none());
    }

    // ── is_same_net ──────────────────────────────────────────────────────────

    #[test]
    fn is_same_net_same_subnet() {
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        assert!(is_same_net("10.0.0.5".parse().unwrap(), "10.0.0.200".parse().unwrap(), mask));
    }

    #[test]
    fn is_same_net_different_subnet() {
        let mask = Ipv4Addr::new(255, 255, 255, 0);
        assert!(!is_same_net("10.0.0.5".parse().unwrap(), "10.0.1.5".parse().unwrap(), mask));
    }

    #[test]
    fn is_same_net_slash32() {
        let mask = Ipv4Addr::new(255, 255, 255, 255);
        assert!(is_same_net("10.0.0.1".parse().unwrap(), "10.0.0.1".parse().unwrap(), mask));
        assert!(!is_same_net("10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap(), mask));
    }

    #[test]
    fn is_same_net_slash0() {
        let mask = Ipv4Addr::UNSPECIFIED;
        assert!(is_same_net("1.2.3.4".parse().unwrap(), "5.6.7.8".parse().unwrap(), mask));
    }

    #[test]
    fn is_same_net_slash16() {
        let mask = Ipv4Addr::new(255, 255, 0, 0);
        assert!(is_same_net("172.16.5.1".parse().unwrap(), "172.16.200.1".parse().unwrap(), mask));
        assert!(!is_same_net("172.16.5.1".parse().unwrap(), "172.17.5.1".parse().unwrap(), mask));
    }

    // ── icmp_checksum ────────────────────────────────────────────────────────

    #[test]
    fn icmp_checksum_empty() {
        assert_eq!(icmp_checksum(&[]), 0xffff);
    }

    #[test]
    fn icmp_checksum_known_value() {
        // ICMP echo request: type=8, code=0, cksum=0, id=1, seq=1
        let mut pkt = vec![0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        let cksum = icmp_checksum(&pkt);
        // Place checksum and verify it zeros out
        pkt[2] = (cksum >> 8) as u8;
        pkt[3] = (cksum & 0xff) as u8;
        assert_eq!(icmp_checksum(&pkt), 0);
    }

    #[test]
    fn icmp_checksum_odd_length() {
        let data = vec![0x01, 0x02, 0x03];
        let cksum = icmp_checksum(&data);
        assert_ne!(cksum, 0); // just check it doesn't panic
    }

    // ── address_available ────────────────────────────────────────────────────

    fn make_ctx(start: Ipv4Addr, end: Ipv4Addr, router: Ipv4Addr, flags: u32) -> DhcpContext {
        DhcpContext {
            start,
            end,
            router,
            flags,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::BROADCAST,
            local: Ipv4Addr::UNSPECIFIED,
            lease_time: 3600,
            addr_epoch: 0,
            netid: crate::types::dhcp::DhcpNetid { net: String::new() },
            filter: vec![],
            #[cfg(feature = "dhcp6")]
            start6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            end6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            local6: std::net::Ipv6Addr::UNSPECIFIED,
            #[cfg(feature = "dhcp6")]
            prefix: 0,
            #[cfg(feature = "dhcp6")]
            if_index: 0,
            #[cfg(feature = "dhcp6")]
            valid: 0,
            #[cfg(feature = "dhcp6")]
            preferred: 0,
        }
    }

    #[test]
    fn address_available_in_range() {
        let ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            0,
        );
        assert!(address_available(&[ctx], "10.0.0.150".parse().unwrap()));
    }

    #[test]
    fn address_available_out_of_range() {
        let ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            0,
        );
        assert!(!address_available(&[ctx], "10.0.0.50".parse().unwrap()));
    }

    #[test]
    fn address_available_rejects_router() {
        let ctx = make_ctx(
            "10.0.0.1".parse().unwrap(),
            "10.0.0.254".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            0,
        );
        assert!(!address_available(&[ctx], "10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn address_available_skips_static() {
        let ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            CONTEXT_STATIC,
        );
        assert!(!address_available(&[ctx], "10.0.0.150".parse().unwrap()));
    }

    #[test]
    fn address_available_empty_contexts() {
        assert!(!address_available(&[], "10.0.0.1".parse().unwrap()));
    }

    // ── narrow_context ───────────────────────────────────────────────────────

    #[test]
    fn narrow_context_pool_match() {
        let contexts = [make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            0,
        )];
        let result = narrow_context(&contexts, "10.0.0.150".parse().unwrap());
        assert!(result.is_some());
    }

    #[test]
    fn narrow_context_static_fallback() {
        let contexts = [make_ctx(
            "10.0.0.0".parse().unwrap(),
            "10.0.0.0".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            CONTEXT_STATIC,
        )];
        // addr on same subnet but not in pool (static context)
        let result = narrow_context(&contexts, "10.0.0.50".parse().unwrap());
        assert!(result.is_some());
    }

    #[test]
    fn narrow_context_no_match() {
        let contexts = [make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            "10.0.0.1".parse().unwrap(),
            0,
        )];
        let result = narrow_context(&contexts, "192.168.1.1".parse().unwrap());
        assert!(result.is_none());
    }

    // ── config_find_by_address ───────────────────────────────────────────────

    #[test]
    fn config_find_by_address_found() {
        let cfg = DhcpConfig {
            flags: CONFIG_ADDR,
            addr: "10.0.0.50".parse().unwrap(),
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![],
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };
        assert!(config_find_by_address(&[cfg], "10.0.0.50".parse().unwrap()).is_some());
    }

    #[test]
    fn config_find_by_address_not_found() {
        let cfg = DhcpConfig {
            flags: CONFIG_ADDR,
            addr: "10.0.0.50".parse().unwrap(),
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![],
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };
        assert!(config_find_by_address(&[cfg], "10.0.0.99".parse().unwrap()).is_none());
    }

    #[test]
    fn config_find_by_address_empty() {
        assert!(config_find_by_address(&[], "10.0.0.1".parse().unwrap()).is_none());
    }

    // ── dhcp_packet_validate ─────────────────────────────────────────────────

    #[test]
    fn validate_too_short() {
        assert!(dhcp_packet_validate(&[0u8; 100]).is_err());
    }

    #[test]
    fn validate_bad_op() {
        let mut data = vec![0u8; 300];
        data[0] = 2; // BOOTREPLY, not BOOTREQUEST
        let cookie = DHCP_COOKIE.to_be_bytes();
        data[236..240].copy_from_slice(&cookie);
        assert_eq!(dhcp_packet_validate(&data), Err("not a BOOTREQUEST"));
    }

    #[test]
    fn validate_bad_hlen() {
        let mut data = vec![0u8; 300];
        data[0] = 1;
        data[2] = 255; // hlen too big
        let cookie = DHCP_COOKIE.to_be_bytes();
        data[236..240].copy_from_slice(&cookie);
        assert_eq!(dhcp_packet_validate(&data), Err("hlen exceeds maximum"));
    }

    #[test]
    fn validate_bad_cookie() {
        let mut data = vec![0u8; 300];
        data[0] = 1;
        data[2] = 6;
        assert_eq!(dhcp_packet_validate(&data), Err("bad magic cookie"));
    }

    #[test]
    fn validate_good_packet() {
        let mut data = vec![0u8; 300];
        data[0] = 1;
        data[2] = 6;
        let cookie = DHCP_COOKIE.to_be_bytes();
        data[236..240].copy_from_slice(&cookie);
        assert!(dhcp_packet_validate(&data).is_ok());
    }

    // ── sdbm_hash ────────────────────────────────────────────────────────────

    #[test]
    fn sdbm_hash_deterministic() {
        let mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        assert_eq!(sdbm_hash(&mac), sdbm_hash(&mac));
    }

    #[test]
    fn sdbm_hash_different_macs_differ() {
        let h1 = sdbm_hash(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let h2 = sdbm_hash(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn sdbm_hash_never_zero() {
        // All-zero MAC would normally hash to 0, but we return 1 instead
        assert_eq!(sdbm_hash(&[0; 6]), 1);
    }

    #[test]
    fn sdbm_hash_empty() {
        assert_eq!(sdbm_hash(&[]), 1); // 0 → 1
    }

    // ── hash_to_addr ─────────────────────────────────────────────────────────

    #[test]
    fn hash_to_addr_in_range() {
        let start = "10.0.0.100".parse().unwrap();
        let end = "10.0.0.200".parse().unwrap();
        let addr = hash_to_addr(42, 0, start, end);
        let a = u32::from(addr);
        let s = u32::from(start);
        let e = u32::from(end);
        assert!(a >= s && a <= e);
    }

    #[test]
    fn hash_to_addr_single_address() {
        let start: Ipv4Addr = "10.0.0.1".parse().unwrap();
        let addr = hash_to_addr(999, 0, start, start);
        assert_eq!(addr, start);
    }

    #[test]
    fn hash_to_addr_epoch_shifts() {
        let start = "10.0.0.0".parse().unwrap();
        let end = "10.0.0.255".parse().unwrap();
        let a1 = hash_to_addr(42, 0, start, end);
        let a2 = hash_to_addr(42, 1, start, end);
        assert_ne!(a1, a2);
    }

    // ── is_allocatable_addr ──────────────────────────────────────────────────

    #[test]
    fn is_allocatable_normal() {
        assert!(is_allocatable_addr("192.168.1.100".parse().unwrap()));
    }

    #[test]
    fn is_allocatable_rejects_class_c_255() {
        assert!(!is_allocatable_addr("192.168.1.255".parse().unwrap()));
    }

    #[test]
    fn is_allocatable_rejects_class_c_0() {
        assert!(!is_allocatable_addr("192.168.1.0".parse().unwrap()));
    }

    #[test]
    fn is_allocatable_allows_10_net_255() {
        // 10.x.x.255 is NOT class C, so it's fine
        assert!(is_allocatable_addr("10.0.0.255".parse().unwrap()));
    }
}

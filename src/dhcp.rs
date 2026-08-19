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
    OPTION_HOSTNAME, OPTION_LEASE_TIME, OPTION_MESSAGE_TYPE, OPTION_RAPID_COMMIT,
    OPTION_REQUESTED_OPTIONS, OPTION_USER_CLASS, OPTION_VENDOR_ID,
};
use crate::lease::LeaseDb;
use crate::metrics::{inc_metric, Metric};
use crate::rfc2131::{
    calc_time, cap_vendor_area, do_options, find_boot, find_requested_ip, handle_bootp,
    handle_decline, handle_discover, handle_inform, handle_leasequery, handle_release,
    handle_request, is_pxe_client, option_put, relay_reply4, relay_upstream4, DhcpReply,
    DoOptionsConfig,
};
use crate::dhcp_common::find_config;
use crate::types::dhcp::DhcpLease;

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
    /// The dhcp-script hook command (`--dhcp-script`), run on lease
    /// add/old/del via [`crate::lease::LeaseDb::run_lease_scripts`].
    pub lease_change_command: Option<String>,
    /// Option-substring classifier rules from parsed `dhcp-match`.
    pub match_rules: Vec<crate::types::dhcp::DhcpOpt>,
    /// Client-hostname classifier rules from parsed `dhcp-name-match`.
    pub name_match_rules: Vec<crate::types::dhcp::DhcpMatchName>,
    /// Conditional tag-setting rules from parsed `tag-if`.
    pub tag_rules: Vec<crate::dhcp_common::TagIf>,
    /// IPv4 relay entries from parsed `dhcp-relay`/`dhcp-split-relay`.
    pub relay4: Vec<crate::types::dhcp::DhcpRelay>,
    /// `--no-ping` (`OPT_NO_PING`): skip the ICMP conflict probe entirely and
    /// treat every scanned address as free, matching dhcp.c:793-798.
    pub no_ping: bool,
    /// `--dhcp-sequential-ip` (`OPT_CONSEC_ADDR`): seed allocation from the
    /// highest leased address in the range instead of a hwaddr hash,
    /// matching dhcp.c:860-864.
    pub consec_addr: bool,
    /// `--dhcp-ignore=<tag>[,<tag>...]` (`daemon->dhcp_ignore`,
    /// `dnsmasq.h:1239`): a global tag-list gate, checked against a client's
    /// derived tags independently of any matched `DhcpConfig` (rfc2131.c:614,
    /// 851). Distinct from a per-host `dhcp-host=...,ignore` entry, which
    /// `configs`' own `CONFIG_DISABLE` flag (checked above) already covers.
    pub dhcp_ignore: Vec<crate::types::dhcp::DhcpNetidList>,
    /// `--bootp-dynamic` gate rules (`daemon->bootp_dynamic`); see
    /// [`crate::types::daemon::Daemon::bootp_dynamic`].
    pub bootp_dynamic: Vec<Vec<crate::types::dhcp::DhcpNetid>>,
    /// `--dhcp-rapid-commit` (`OPT_RAPID_COMMIT`): answer a DISCOVER
    /// carrying OPTION_RAPID_COMMIT (80) with an immediate ACK instead of an
    /// OFFER (rfc2131.c:1361-1372).
    pub rapid_commit: bool,
    /// `--leasequery` allowed source prefixes (`daemon->leasequery_addr`).
    /// Empty means "no restriction beyond `OPT_LEASEQUERY`" (rfc2131.c:1078-1091).
    pub leasequery_addr: Vec<crate::types::dns_records::BogusAddr>,
    /// `OPT_LEASEQUERY` (`--leasequery`): enables `DHCPLEASEQUERY` (RFC 4388).
    pub leasequery_enabled: bool,
    /// Source address of the packet currently being dispatched. Leasequery
    /// requires a unicast source (rfc2131.c:1073) — the caller (normally
    /// [`run_dhcp_loop`]) sets this per-datagram; it defaults to
    /// [`Ipv4Addr::UNSPECIFIED`], which always rejects leasequery, matching
    /// dispatch helpers that have no real socket source to report.
    pub leasequery_source: Ipv4Addr,
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
            lease_change_command: None,
            match_rules: Vec::new(),
            name_match_rules: Vec::new(),
            tag_rules: Vec::new(),
            relay4: Vec::new(),
            no_ping: false,
            consec_addr: false,
            dhcp_ignore: Vec::new(),
            bootp_dynamic: Vec::new(),
            rapid_commit: false,
            leasequery_addr: Vec::new(),
            leasequery_enabled: false,
            leasequery_source: Ipv4Addr::UNSPECIFIED,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DispatchedDhcpReply {
    pub reply: DhcpReply,
    pub delay_secs: u32,
}

#[derive(Debug, Clone)]
pub struct DhcpLoopOptions {
    /// Optional reply-port override for unprivileged test and harness setups.
    /// When set, replies are sent to this port instead of the RFC2131 default.
    pub reply_port_override: Option<u16>,
    /// The IPv4 address of the interface this loop's socket is bound to.
    /// Used to match non-split `dhcp-relay` entries against arriving requests
    /// (`relay_upstream4`'s `iface_addr`; see `dhcp.c:669-673`).
    pub relay_iface_addr: Ipv4Addr,
    /// Numeric index of the bound interface, resolved via `if_nametoindex`.
    /// Fed to `relay_upstream4`/`relay_reply4` as `iface_index`.
    pub relay_iface_index: i32,
    /// Name of the bound interface, used for `relay_reply4`'s wildcard
    /// interface match against a relay's configured `interface`.
    pub relay_iface_name: Option<String>,
    /// The `daemon->dhcp6` "current" RA-name context chain, needed to
    /// recompute SLAAC addresses (`slaac_add_addrs`, slaac.c:25-116) against
    /// leases this (DHCPv4) loop commits. Upstream shares a single lease
    /// list between the DHCPv4 and DHCPv6 servers and relies on
    /// `slaac_add_addrs`'s own `LEASE_TA|LEASE_NA` guard (slaac.c:32) to
    /// skip DHCPv6-stateful leases; this port keeps separate `LeaseDb`
    /// instances per protocol, so this loop — not the DHCPv6 one, whose
    /// leases are always `LEASE_NA`-flagged and so can never pass that
    /// guard — is where SLAAC tracking for real (DHCPv4-committed) leases
    /// actually happens. Empty when DHCPv6/RA-names aren't configured.
    #[cfg(feature = "dhcp6")]
    pub slaac_contexts: Vec<crate::types::dhcp::DhcpContext>,
}

impl Default for DhcpLoopOptions {
    fn default() -> Self {
        Self {
            reply_port_override: None,
            relay_iface_addr: Ipv4Addr::UNSPECIFIED,
            relay_iface_index: 0,
            relay_iface_name: None,
            #[cfg(feature = "dhcp6")]
            slaac_contexts: Vec::new(),
        }
    }
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

fn derived_tags(
    pkt: &DhcpPacket,
    cfg: &DhcpServerConfig,
    hostname: Option<&str>,
) -> Vec<crate::types::dhcp::DhcpNetid> {
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

    // dhcp-match: substring/array match against a raw DHCP option
    // (rfc2131.c:437-477). The RFC3925 vendor-identifying-class (option 124/125)
    // special case is not implemented — see tasks.md.
    for rule in &cfg.match_rules {
        if let Ok(opt_code) = u8::try_from(rule.opt) {
            if let Some(data) = find_option(&pkt.options, opt_code) {
                if crate::dhcp_common::match_bytes(rule, data) {
                    tags.extend(rule.netid.iter().cloned());
                }
            }
        }
    }

    // dhcp-name-match: exact or prefix match against the client hostname
    // (rfc2131.c:766-793).
    if let Some(name) = hostname {
        for rule in &cfg.name_match_rules {
            let matched = match name.len().cmp(&rule.name.len()) {
                std::cmp::Ordering::Less => false,
                std::cmp::Ordering::Equal => crate::util::hostname_isequal(name, &rule.name),
                std::cmp::Ordering::Greater => {
                    rule.wildcard && crate::util::hostname_isequal(&name[..rule.name.len()], &rule.name)
                }
            };
            if matched {
                tags.push(rule.netid.clone());
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

/// Select the context that best describes `reply.yiaddr`, for filling in
/// lease-time/router/netmask reply options.
///
/// Delegates to [`narrow_context`] — a pool-range match (excluding
/// `CONTEXT_STATIC`/`CONTEXT_PROXY`) first, then a static context on the same
/// subnet, then any context on the same subnet — instead of the previous
/// "first pool match or else the first context regardless of subnet"
/// heuristic. This is `narrow_context()`'s upstream role (dhcp.c:717-752).
/// `cfg.contexts` is `narrow_context`'s whole search domain here; when the
/// caller is [`dispatch_dhcp_with_arrival`], that list has already been
/// restricted to the arriving interface's linked chain
/// (`complete_context()`'s `->current` list, dhcp.c:589-660) — see
/// [`link_contexts_for_interface`].
fn context_for_reply<'a>(
    cfg: &'a DhcpServerConfig,
    reply: &DhcpReply,
) -> Option<&'a crate::types::dhcp::DhcpContext> {
    if reply.yiaddr == Ipv4Addr::UNSPECIFIED {
        return cfg.contexts.first();
    }
    narrow_context(&cfg.contexts, reply.yiaddr).or_else(|| cfg.contexts.first())
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
        &cfg.tag_rules,
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
    // it never sends T1/T2 there (rfc2131.c:1817). The BOOTP call site
    // (rfc2131.c:684-685) unconditionally passes 0xffffffff too, regardless
    // of the actual lease time recorded — that's how upstream suppresses
    // T1/T2 for BOOTP.
    let do_options_lease_time = if is_inform || reply.msg_type == DhcpMsgType::Bootp {
        u32::MAX
    } else {
        lease_time
    };
    // Upstream's BOOTP call site passes NULL for req_options and -1 for
    // pxearch unconditionally (rfc2131.c:684-685) — a BOOTP request that
    // happens to carry option 55 (parameter request list) or option 93
    // (client arch, legal without option 53) is answered as plain BOOTP,
    // never treated as a DHCP/PXE options request.
    let is_bootp = reply.msg_type == DhcpMsgType::Bootp;
    let mut opt_cfg = DoOptionsConfig {
        context,
        req_options: if is_bootp { None } else { find_option(&pkt.options, OPTION_REQUESTED_OPTIONS) },
        hostname: config.and_then(|c| c.hostname.as_deref()),
        domain: config
            .and_then(|c| c.domain.as_deref())
            .or(cfg.domain_suffix.as_deref()),
        netid: &filtered_tags,
        subnet_addr: None,
        fqdn_flags: 0,
        null_term: false,
        pxe_arch: if is_bootp { -1 } else { requested_arch(pkt) },
        uuid: None,
        vendor_class: find_option(&pkt.options, OPTION_VENDOR_ID),
        lease_time: do_options_lease_time,
        fuzz: 0,
        pxevendor: None,
        config_opts: &mut config_opts,
        boot,
        dns_port: 53,
        leasequery: false,
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

    // Echo option 82 (agent information) back verbatim as the last option in
    // the reply, per RFC 3046 §2.1 (rfc2131.c:189-205, :2075-2079). This
    // fires whenever the request carried one, independent of whether this
    // daemon has any `dhcp-relay` of its own configured — an upstream relay
    // agent may have added it before the request reached us.
    if let Some(agent_info) = find_option(&pkt.options, OPTION_AGENT_ID) {
        crate::rfc2131::option_put_raw(&mut reply_pkt.options, OPTION_AGENT_ID, agent_info);
    }

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

/// Serialize a [`DhcpPacket`] as-is into a wire-format byte buffer.
///
/// Unlike [`dhcp_reply_to_wire`], which composes a fresh BOOTREPLY from a
/// [`DhcpReply`] and the originating request, this serializes `pkt` verbatim
/// (op, hops, giaddr, options and all) — used when forwarding a relayed
/// request or reply unchanged onto the wire.
pub fn dhcp_packet_to_wire(pkt: &DhcpPacket) -> Vec<u8> {
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

/// Serialize a DHCP reply into a wire-format byte buffer.
///
/// The output is a complete BOOTP packet (fixed header + magic cookie +
/// options) suitable for sending over UDP.
pub fn dhcp_reply_to_wire(reply: &DhcpReply, request: &DhcpPacket) -> Vec<u8> {
    let mut buf = Vec::with_capacity(300);

    // Fixed BOOTP header (236 bytes)
    let (chaddr, hlen, htype) = reply
        .chaddr_override
        .as_ref()
        .map_or((&request.chaddr, request.hlen, request.htype), |(c, hlen, htype)| {
            (c, *hlen, *htype)
        });
    buf.push(BOOTREPLY);                    // op
    buf.push(htype);                        // htype
    buf.push(hlen);                         // hlen
    buf.push(0);                            // hops
    buf.extend_from_slice(&request.xid.to_be_bytes()); // xid
    buf.extend_from_slice(&[0, 0]);        // secs
    buf.extend_from_slice(&[0, 0]);        // flags (unicast)
    buf.extend_from_slice(&reply.ciaddr_override.unwrap_or(request.ciaddr).octets()); // ciaddr
    buf.extend_from_slice(&reply.yiaddr.octets());   // yiaddr
    buf.extend_from_slice(&reply.siaddr.octets());   // siaddr
    buf.extend_from_slice(&reply.giaddr.octets());   // giaddr
    buf.extend_from_slice(chaddr);                   // chaddr (16 bytes)
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

/// Destination for a reply that [`crate::rfc2131::relay_reply4`] identified as
/// bound for a client behind us, rather than a fresh local reply.
///
/// Unlike [`reply_dest`], this does *not* unicast to `giaddr` — `giaddr` here
/// is our own relay address (that's how `relay_reply4` matched the packet in
/// the first place), not an onward relay to hop through. Mirrors upstream's
/// `is_relay_reply` branch (`dhcp.c:402-425`), minus its interface-targeted
/// `IP_PKTINFO` unicast-to-chaddr case, which needs raw socket options this
/// runtime doesn't use elsewhere.
pub fn relay_reply_client_dest(pkt: &DhcpPacket) -> SocketAddr {
    if pkt.ciaddr != Ipv4Addr::UNSPECIFIED {
        SocketAddr::V4(SocketAddrV4::new(pkt.ciaddr, DHCP_CLIENT_PORT))
    } else {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::BROADCAST, DHCP_CLIENT_PORT))
    }
}

/// Resolve an interface's own IPv4 address (upstream's `ioctl(SIOCGIFADDR)`).
///
/// Used as `relay_upstream4`'s `resolve_uplink` callback for split-mode
/// relays that name an `interface` rather than a literal uplink address.
fn resolve_iface_addr(name: &str) -> Option<Ipv4Addr> {
    crate::network::enumerate_interfaces().ok()?.into_iter().find_map(|iface| {
        (iface.name == name)
            .then_some(iface.addr)
            .and_then(|addr| match addr {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
    })
}

/// Resolve an interface's IPv4 broadcast address (upstream's
/// `ioctl(SIOCGIFBRDADDR)`), used for `dhcp-relay` broadcast mode
/// (`relay.server_addr` unspecified).
fn resolve_iface_broadcast(name: &str) -> Option<Ipv4Addr> {
    crate::network::enumerate_interfaces().ok()?.into_iter().find_map(|iface| {
        if iface.name != name {
            return None;
        }
        match (iface.addr, iface.netmask) {
            (IpAddr::V4(addr), Some(IpAddr::V4(mask))) => {
                Some(Ipv4Addr::from(u32::from(addr) | !u32::from(mask)))
            }
            _ => None,
        }
    })
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
    lease_db.set_hwaddr(addr, &pkt.chaddr[..hw_len], i32::from(pkt.htype), clid, false);
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
    ping_cache: &mut PingCache,
    probe: &dyn AddressProbe,
) -> Option<DispatchedDhcpReply> {
    // `mess_type` stays `None` when option 53 is absent — that's how upstream
    // recognises a BOOTP request (`mess_type == 0`, rfc2131.c:125-133,:564),
    // not a reason to drop the packet, so this can't be an early-return `?`
    // the way it used to be.
    let msg_type = get_message_type(&pkt.options);
    let clid = find_option(&pkt.options, OPTION_CLIENT_ID);
    let hostname = find_option(&pkt.options, OPTION_HOSTNAME)
        .and_then(|raw| std::str::from_utf8(raw).ok());
    let hw_len = usize::from(pkt.hlen).min(DHCP_CHADDR_MAX);
    let tags = derived_tags(pkt, cfg, hostname);
    let tag_disable = cfg.configs.iter().any(|c| {
        (c.flags & crate::types::dhcp::CONFIG_DISABLE) != 0
            && !c.filter.is_empty()
            && match_netid_wild(&c.filter, &tags)
    });
    if tag_disable {
        return None;
    }
    // `--dhcp-ignore=<tag>` (`daemon->dhcp_ignore`, rfc2131.c:614,851): a
    // global tag-list gate checked against the client's derived tags,
    // independent of any `DhcpConfig` match above.
    if cfg.dhcp_ignore.iter().any(|entry| context_filter_matches(&entry.list, &tags, false)) {
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
    // "Have maybe already found the lease by MAC or clid" (rfc2131.c:255) —
    // shared by the BOOTP and DHCPLEASEQUERY paths below. `lease_key()`
    // (lease.rs) derives its lookup key the same way: clid if present and
    // non-empty, else the hardware address.
    let client_key: &[u8] = clid.filter(|c| !c.is_empty()).unwrap_or(&pkt.chaddr[..hw_len]);
    // Owned, not borrowed: BOOTP dispatch needs `lease_db` mutably while this
    // lookup is still in scope, which a borrow from `lease_db` itself would
    // forbid.
    let lease_by_client: Option<DhcpLease> = lease_db.find_by_client_id(client_key).cloned();
    debug!("DHCP {msg_type:?}");

    let Some(msg_type) = msg_type else {
        // Only a genuinely absent option 53 is BOOTP (`mess_type == 0`,
        // rfc2131.c:564). A present-but-unrecognized option-53 byte falls
        // through C's `switch` with no matching `case` and is silently
        // dropped (rfc2131.c:1237-1239) — it must not be answered as BOOTP.
        if find_option(&pkt.options, OPTION_MESSAGE_TYPE).is_some() {
            return None;
        }
        return dispatch_bootp(pkt, cfg, lease_db, ping_cache, probe, &tags, config, static_addr, lease_by_client.as_ref(), hw_len, clid, hostname);
    };

    if msg_type == DhcpMsgType::LeaseQuery {
        return dispatch_leasequery(pkt, cfg, lease_db, &tags, lease_by_client.as_ref());
    }

    let mut reply = match msg_type {
        DhcpMsgType::Discover => {
            inc_metric(Metric::Dhcpdiscover);
            // Only run the pool scan when a static reservation won't already
            // decide the offer — mirrors rfc2131.c's `conf.s_addr` short
            // circuit, and avoids pinging candidates whose result is unused.
            let scanned_addr = if static_addr.is_none() {
                // rfc2131.c:841-848 folds `config->netid` into `tagif_netid`
                // before the DHCPDISCOVER case, so a tag-restricted
                // `dhcp-range` can be selected by a client's own `dhcp-host`
                // netid, not just runtime-derived tags.
                let mut alloc_tags = tags.clone();
                if let Some(c) = config {
                    alloc_tags.extend(c.netid.iter().cloned());
                }
                let contexts = allocation_contexts(cfg);
                address_allocate(
                    &contexts,
                    lease_db,
                    &cfg.configs,
                    &pkt.chaddr[..hw_len],
                    &alloc_tags,
                    std::time::SystemTime::now(),
                    false, // interface-arrival loopback detection is not ported yet
                    cfg.consec_addr,
                    cfg.no_ping,
                    ping_cache,
                    probe,
                )
            } else {
                None
            };
            let offer = handle_discover(pkt, cfg.pool_start, cfg.pool_end, None, cfg.server_ip, static_addr, scanned_addr);
            // `dhcp-rapid-commit` (OPT_RAPID_COMMIT): a DISCOVER carrying
            // OPTION_RAPID_COMMIT (80) gets an immediate ACK instead of an
            // OFFER (rfc2131.c:1363-1372's jump to the `rapid_commit:`
            // label). `apply_delay`'s single DISCOVER-path call site
            // (rfc2131.c:1361, before that jump) covers this ACK the same
            // way it covers the OFFER — see the `delay_secs` computation
            // below, gated on `msg_type == Discover` rather than on the
            // resulting reply type.
            if cfg.rapid_commit && find_option(&pkt.options, OPTION_RAPID_COMMIT).is_some() {
                offer.and_then(|r| {
                    // rfc2131.c:1529-1530: reserved-for-another-client check,
                    // re-run here the same way the `rapid_commit:` label
                    // re-validates the offered address before committing to
                    // an ACK — see `make_rapid_commit_ack`.
                    let reserved_for_other = config_find_by_address(&cfg.configs, r.yiaddr)
                        .is_some_and(|addr_cfg| !config.is_some_and(|c| std::ptr::eq(c, addr_cfg)));
                    crate::rfc2131::make_rapid_commit_ack(
                        r,
                        cfg.server_ip,
                        cfg.pool_start,
                        cfg.pool_end,
                        static_addr,
                        reserved_for_other,
                    )
                })
            } else {
                offer
            }
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

    // apply_delay's only DISCOVER-path call site (rfc2131.c:1361) runs before
    // the rapid-commit jump, so it covers both the ordinary OFFER and a
    // rapid-commit-triggered ACK — but no other ACK (a plain REQUEST->ACK is
    // never delayed upstream).
    let delay_secs = if reply.msg_type == DhcpMsgType::Offer
        || (msg_type == DhcpMsgType::Discover && reply.msg_type == DhcpMsgType::Ack)
    {
        select_reply_delay(&tags, cfg)
    } else {
        0
    };

    Some(DispatchedDhcpReply { reply, delay_secs })
}

/// Match the incoming BOOTP `file` field as a netid, mirroring
/// rfc2131.c:594-600 (`if (mess->file[0]) { ... id.net = daemon->dhcp_buff2; }`).
fn bootp_file_tag(pkt: &DhcpPacket) -> Option<crate::types::dhcp::DhcpNetid> {
    if pkt.file[0] == 0 {
        return None;
    }
    let end = pkt.file.iter().position(|&b| b == 0).unwrap_or(pkt.file.len());
    let s = std::str::from_utf8(&pkt.file[..end]).ok()?;
    Some(crate::types::dhcp::DhcpNetid { net: s.to_string() })
}

/// `--bootp-dynamic` gate: a non-nailed BOOTP client may only be given a
/// dynamically allocated address when at least one configured rule (a bare
/// directive, or one whose tags all match) applies (rfc2131.c:661-668).
fn bootp_dynamic_allowed(rules: &[Vec<crate::types::dhcp::DhcpNetid>], tags: &[crate::types::dhcp::DhcpNetid]) -> bool {
    !rules.is_empty() && rules.iter().any(|filter| match_netid_wild(filter, tags))
}

/// Handle a BOOTP request (`mess_type == 0`, rfc2131.c:564-698) — a client
/// that sent no option 53 at all. Requires a real hardware address; resolves
/// the offered address from a nailed `dhcp-host` entry (checking for a
/// hwaddr conflict on that lease), else an existing lease for this client
/// still valid in a known context, else — gated by `--bootp-dynamic` — a
/// fresh dynamic allocation. Grants an effectively infinite lease
/// (`0xFFFFFFFF`) unless `dhcp-host` set an explicit lease time
/// (`CONFIG_TIME`). The reply has no `OPTION_MESSAGE_TYPE` at all and its
/// vendor area is capped at 64 bytes (rfc2131.c:577).
///
/// Not modelled: upstream's proxy-context exclusion on this same path
/// (`context->flags & CONTEXT_PROXY`) and the `known`/`known-othernet`
/// netid tagging applied earlier in `dhcp_reply` — this codebase has no
/// proxyDHCP context concept yet and does not derive those tags for any
/// message type (tracked in tasks.md).
#[allow(clippy::too_many_arguments)]
fn dispatch_bootp(
    pkt: &DhcpPacket,
    cfg: &DhcpServerConfig,
    lease_db: &mut LeaseDb,
    ping_cache: &mut PingCache,
    probe: &dyn AddressProbe,
    tags: &[crate::types::dhcp::DhcpNetid],
    config: Option<&crate::types::dhcp::DhcpConfig>,
    static_addr: Option<Ipv4Addr>,
    lease_by_client: Option<&DhcpLease>,
    hw_len: usize,
    clid: Option<&[u8]>,
    hostname: Option<&str>,
) -> Option<DispatchedDhcpReply> {
    use crate::types::dhcp::{DhcpNetid, CONFIG_DISABLE, CONFIG_TIME};

    // "must have a MAC addr for bootp" (rfc2131.c:571-572).
    if pkt.htype == 0 || pkt.hlen == 0 {
        return None;
    }

    let mut bootp_tags: Vec<DhcpNetid> = tags.to_vec();
    if let Some(c) = config {
        bootp_tags.extend(c.netid.iter().cloned());
    }
    if let Some(tag) = bootp_file_tag(pkt) {
        bootp_tags.push(tag);
    }
    bootp_tags.push(DhcpNetid { net: "bootp".to_string() });

    // dhcp-ignore, re-checked with the "bootp" tag folded in (rfc2131.c:607-609).
    if cfg.configs.iter().any(|c| {
        (c.flags & CONFIG_DISABLE) != 0 && !c.filter.is_empty() && match_netid_wild(&c.filter, &bootp_tags)
    }) {
        return None;
    }

    let contexts = allocation_contexts(cfg);
    let nailed = static_addr.is_some();

    let yiaddr = if let Some(addr) = static_addr {
        if let Some(existing) = lease_db.find_by_addr(addr) {
            if existing.hwaddr_len != hw_len
                || existing.hwaddr_type != i32::from(pkt.htype)
                || existing.hwaddr[..hw_len] != pkt.chaddr[..hw_len]
            {
                return None; // "address in use"
            }
        }
        addr
    } else if let Some(existing) =
        lease_by_client.filter(|l| address_available(contexts.as_ref(), l.addr))
    {
        existing.addr
    } else {
        address_allocate(
            contexts.as_ref(),
            lease_db,
            &cfg.configs,
            &pkt.chaddr[..hw_len],
            &bootp_tags,
            std::time::SystemTime::now(),
            false,
            cfg.consec_addr,
            cfg.no_ping,
            ping_cache,
            probe,
        )?
    };

    narrow_context(contexts.as_ref(), yiaddr)?; // "wrong network"

    // `bootp_dynamic` gates any non-nailed resolution — reused lease or
    // fresh allocation alike (rfc2131.c:659-666) — not just fresh
    // allocation. Checked here, after the address is known, so a rule
    // change takes effect on the very next renewal of an existing lease
    // instead of only on the next fresh allocation.
    if !nailed && !bootp_dynamic_allowed(&cfg.bootp_dynamic, &bootp_tags) {
        return None; // "no address configured"
    }

    let mut reply = handle_bootp(pkt, yiaddr, cfg.server_ip);
    decorate_reply(&mut reply, pkt, cfg, &bootp_tags, config);
    cap_vendor_area(&mut reply.options, 64);

    let lease_time = if nailed {
        config
            .filter(|c| c.flags & CONFIG_TIME != 0)
            .map_or(0xFFFF_FFFF, |c| c.lease_time)
    } else {
        0xFFFF_FFFF
    };
    record_lease(lease_db, yiaddr, pkt, hw_len, clid, hostname, lease_time);
    inc_metric(Metric::Bootp);

    Some(DispatchedDhcpReply { reply, delay_secs: 0 })
}

/// Handle `DHCPLEASEQUERY` (RFC 4388, rfc2131.c:1067-1235). Requires a
/// unicast source (`cfg.leasequery_source`) and `OPT_LEASEQUERY`; optionally
/// restricted to prefixes in `cfg.leasequery_addr`. Classifies the query by
/// looking up the lease by `ciaddr` (if given) or by MAC/client-id, then
/// building the RFC 4388 reply through [`handle_leasequery`].
fn dispatch_leasequery(
    pkt: &DhcpPacket,
    cfg: &DhcpServerConfig,
    lease_db: &LeaseDb,
    tags: &[crate::types::dhcp::DhcpNetid],
    lease_by_client: Option<&DhcpLease>,
) -> Option<DispatchedDhcpReply> {
    // rfc2131.c:1054-1057: leasequery bypasses the proxy-only short circuit
    // that every other message type hits — not modelled here since this
    // codebase has no proxyDHCP context concept yet.
    if !cfg.leasequery_enabled || cfg.leasequery_source == Ipv4Addr::UNSPECIFIED {
        return None;
    }
    if !cfg.leasequery_addr.is_empty()
        && !cfg.leasequery_addr.iter().any(|b| {
            !b.is6
                && b.addr.as_ipv4().is_some_and(|a| {
                    crate::util::is_same_net_prefix(cfg.leasequery_source, a, b.prefix.clamp(0, 32) as u8)
                })
        })
    {
        warn!("leasequery from {} not permitted", cfg.leasequery_source);
        return None;
    }

    inc_metric(Metric::Dhcpleasequery);

    let contexts = allocation_contexts(cfg);
    let queried = if pkt.ciaddr != Ipv4Addr::UNSPECIFIED {
        lease_db.find_by_addr(pkt.ciaddr)
    } else {
        lease_by_client
    };

    let (reply_type, lease) = match queried {
        Some(l) if narrow_context(contexts.as_ref(), l.addr).is_some() => {
            inc_metric(Metric::Dhcpleaseactive);
            (DhcpMsgType::LeaseActive, Some(l))
        }
        None if pkt.ciaddr != Ipv4Addr::UNSPECIFIED && address_available(contexts.as_ref(), pkt.ciaddr) => {
            inc_metric(Metric::Dhcpleaseunassigned);
            (DhcpMsgType::LeaseUnassigned, None)
        }
        _ => {
            inc_metric(Metric::Dhcpleaseunknown);
            (DhcpMsgType::LeaseUnknown, None)
        }
    };

    let req_options = find_option(&pkt.options, OPTION_REQUESTED_OPTIONS);

    let reply = if let Some(lease) = lease {
        let lease_hw_len = lease.hwaddr_len.min(DHCP_CHADDR_MAX);
        let lease_config = find_config(
            &cfg.configs,
            lease.clid.as_deref(),
            Some(&lease.hwaddr[..lease_hw_len]),
            lease.hwaddr_type,
            lease.hostname.as_deref(),
            tags,
        );
        let context = narrow_context(contexts.as_ref(), lease.addr);
        let mut config_opts = cfg.dhcp_opts.clone();
        let context_tags = context.and_then(|c| (!c.netid.net.is_empty()).then(|| vec![c.netid.clone()]));
        let mut effective_tags = tags.to_vec();
        if let Some(c) = lease_config {
            effective_tags.extend(c.netid.iter().cloned());
        }
        let filtered_tags = crate::dhcp_common::option_filter(
            effective_tags, context_tags, &mut config_opts, 0, &cfg.tag_rules,
        );
        let full_lease_time = calc_time(
            context.map_or(3600, |c| c.lease_time),
            lease_config
                .filter(|c| c.flags & crate::types::dhcp::CONFIG_TIME != 0)
                .map(|c| c.lease_time),
            None,
        );
        handle_leasequery(
            pkt, reply_type, Some(lease), req_options, context, &filtered_tags,
            &mut config_opts, cfg.domain_suffix.as_deref(), full_lease_time,
        )
    } else {
        handle_leasequery(pkt, reply_type, None, req_options, None, &[], &mut Vec::new(), None, 0)
    };

    Some(DispatchedDhcpReply { reply, delay_secs: 0 })
}

/// An [`AddressProbe`] that never reports a conflict, used where a caller
/// has no real ICMP prober available (e.g. [`dispatch_dhcp`]'s no-frills
/// wrapper). Equivalent to always running with `--no-ping`.
struct NullProbe;

impl AddressProbe for NullProbe {
    fn in_use(&self, _addr: Ipv4Addr) -> bool {
        false
    }
}

/// Dispatch a received DHCP packet to the appropriate handler.
///
/// Returns `Some(DhcpReply)` when a reply should be sent, `None` when the
/// packet should be silently dropped (e.g. RELEASE, DECLINE, unknown type).
///
/// Convenience wrapper around [`dispatch_dhcp_with_meta`] for callers that
/// don't need lease-file/delay metadata or real conflict detection: it
/// allocates a fresh [`PingCache`] and a [`NullProbe`] per call, so repeated
/// calls never build up ping history and never treat any address as in use.
pub fn dispatch_dhcp(
    pkt: &DhcpPacket,
    cfg: &DhcpServerConfig,
    lease_db: &mut LeaseDb,
) -> Option<DhcpReply> {
    let mut ping_cache = PingCache::new();
    dispatch_dhcp_with_meta(pkt, cfg, lease_db, &mut ping_cache, &NullProbe).map(|out| out.reply)
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

/// Like [`loop_reply_dest`] but for a reply [`crate::rfc2131::relay_reply4`]
/// identified as needing to go back out to a client, not [`reply_dest`]'s
/// giaddr-first logic (see [`relay_reply_client_dest`]).
fn loop_relay_reply_dest(pkt: &DhcpPacket, opts: &DhcpLoopOptions) -> SocketAddr {
    if let Some(port) = opts.reply_port_override {
        let addr = if pkt.ciaddr != Ipv4Addr::UNSPECIFIED { pkt.ciaddr } else { Ipv4Addr::BROADCAST };
        return SocketAddr::V4(SocketAddrV4::new(addr, port));
    }

    relay_reply_client_dest(pkt)
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
    mut cfg: DhcpServerConfig,
    opts: DhcpLoopOptions,
    mut lease_db: LeaseDb,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
    probe: Box<dyn AddressProbe + Send + Sync>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; cfg.max_packet.max(300)];
    // Persists across packets so `do_icmp_ping`'s cache/load-limiter
    // (dhcp.c:769-823, ported as `PingCache::check`) actually avoids
    // re-pinging addresses within `PING_CACHE_TIME` of each other.
    let mut ping_cache = PingCache::new();

    // SLAAC DAD probing (slaac.c:119-213). `SlaacDad` is always constructed
    // (its `Inactive` variant is a permanently-pending no-op) so the extra
    // `tokio::select!` branch below can be written unconditionally —
    // `tokio::select!` branches can't themselves be `#[cfg]`-gated, unlike a
    // plain `match` arm, which is why the dhcp6/non-dhcp6 split lives inside
    // `SlaacDad` rather than around the branch.
    let mut slaac_dad = SlaacDad::new(opts_slaac_enabled(&opts));
    #[cfg(feature = "dhcp6")]
    let slaac_contexts: &[crate::types::dhcp::DhcpContext] = &opts.slaac_contexts;
    #[cfg(not(feature = "dhcp6"))]
    let slaac_contexts: &[crate::types::dhcp::DhcpContext] = &[];

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                match changed {
                    Ok(()) if *shutdown.borrow() => return Ok(()),
                    Ok(()) => continue,
                    Err(_) => return Ok(()),
                }
            }
            recv = recv_dhcp_datagram(&socket, &mut buf) => {
                let meta = recv?;
                let (len, src) = (meta.len, meta.src);
                let Some(mut pkt) = parse_dhcp_packet(&buf[..len]) else {
                    debug!("ignoring malformed DHCP packet from {src}");
                    continue;
                };

                // Non-standard extension: giaddr == 255.255.255.255 means "reply
                // to the source address of this packet" — lets stand-alone
                // leasequery clients skip source-address determination
                // themselves. Cleared here, before anything else looks at
                // giaddr, to avoid the relay-dispatch and is_relayed() logic
                // below mistaking this for a relayed packet (dhcp.c:255-260).
                let is_relay_use_source = pkt.giaddr == Ipv4Addr::new(255, 255, 255, 255);
                if is_relay_use_source {
                    pkt.giaddr = Ipv4Addr::UNSPECIFIED;
                }

                // Relay dispatch (rfc2131.c relay_reply4/relay_upstream4, called
                // from dhcp.c:305/:366). A reply matching one of our relays is
                // forwarded straight to the client and never reaches local
                // dispatch; a request is forwarded upstream through every
                // matching relay in addition to (not instead of) local dispatch,
                // matching upstream's "may have configured relay, but not DHCP
                // server" comment (dhcp.c:368-370).
                if !cfg.relay4.is_empty() {
                    let return_iface = relay_reply4(&mut pkt, &cfg.relay4, opts.relay_iface_name.as_deref());
                    if return_iface != 0 {
                        let dest = loop_relay_reply_dest(&pkt, &opts);
                        let wire = dhcp_packet_to_wire(&pkt);
                        if let Err(err) = socket.send_to(&wire, dest).await {
                            warn!("failed to relay DHCP reply to {dest}: {err}");
                        }
                        continue;
                    }

                    if pkt.op == crate::dhcp_protocol::BOOTREQUEST {
                        let mut relays = cfg.relay4.clone();
                        let forwards = relay_upstream4(
                            opts.relay_iface_addr,
                            opts.relay_iface_index,
                            &pkt,
                            false,
                            &mut relays,
                            resolve_iface_addr,
                            resolve_iface_broadcast,
                        );
                        for fwd in &forwards {
                            let dest = SocketAddr::V4(SocketAddrV4::new(fwd.dest, fwd.port));
                            let wire = dhcp_packet_to_wire(&fwd.packet);
                            if let Err(err) = socket.send_to(&wire, dest).await {
                                warn!("failed to forward DHCP request to relay {dest}: {err}");
                            }
                        }
                    }
                }

                // `leasequery_source = is_relay_use_source ? <UDP source> :
                // giaddr` (dhcp.c:373-375). Standard RFC 4388 leasequery
                // clients set giaddr to identify themselves; only the
                // stand-alone-client extension above falls back to the raw
                // UDP source.
                cfg.leasequery_source = if is_relay_use_source {
                    match src.ip() {
                        IpAddr::V4(v4) => v4,
                        IpAddr::V6(_) => Ipv4Addr::UNSPECIFIED,
                    }
                } else {
                    pkt.giaddr
                };

                let arrival = arrival_interface(meta.if_index);
                let dispatched = dispatch_dhcp_with_arrival(
                    &pkt, &mut cfg, &mut lease_db, &mut ping_cache, probe.as_ref(), arrival.as_ref(),
                );

                // Port of the slaac_add_addrs() call chain that upstream
                // triggers from lease_set_hwaddr()/lease_set_interface()
                // (lease.c:992-993,1157-1158) every time a commit could have
                // changed a lease's hwaddr, hostname, or interface — applied
                // here across the whole db, once per packet, rather than
                // per-setter.
                #[cfg(feature = "dhcp6")]
                if !opts.slaac_contexts.is_empty() {
                    lease_db.refresh_slaac(
                        std::time::SystemTime::now(), &opts.slaac_contexts, false, |_ctx| {},
                    );
                }

                if lease_db.file_dirty {
                    let write_ok = match cfg.lease_file.as_deref() {
                        Some(path) => match lease_db.write_to_file(path) {
                            Ok(()) => true,
                            Err(err) => {
                                warn!("failed to write DHCP lease file {path}: {err}");
                                false
                            }
                        },
                        None => true,
                    };
                    // Only clear the dirty flag once the write actually
                    // succeeded (or there was nothing to write); otherwise
                    // the next dispatch would silently skip retrying it.
                    if write_ok {
                        lease_db.file_dirty = false;
                    }
                }

                // Fire dhcp-script hooks (ADD/OLD/DEL) for whatever changed
                // in this dispatch. Port of `do_script_run()`'s call site in
                // the upstream main loop (dnsmasq.c), invoked here once per
                // dispatch rather than looped on a "more work" return value
                // — see `LeaseDb::run_lease_scripts` for why.
                if let Some(command) = cfg.lease_change_command.as_deref() {
                    if !command.is_empty() {
                        lease_db.run_lease_scripts(command);
                    }
                }

                let Some(dispatched) = dispatched else {
                    continue;
                };

                let dest = loop_reply_dest(&pkt, src, &opts);
                if let Err(err) = send_dhcp_reply_to(&socket, &pkt, &dispatched, dest).await {
                    warn!("failed to send DHCP reply to {dest}: {err}");
                }
            }
            _ = slaac_dad.poll_tick_or_recv(&mut lease_db, slaac_contexts), if slaac_dad.active() => {}
        }
    }
}

/// Whether `run_dhcp_loop` should stand up SLAAC DAD probing at all: only
/// when `dhcp6` is compiled in and at least one RA-name context was handed
/// down (no point opening a raw ICMPv6 socket otherwise).
fn opts_slaac_enabled(opts: &DhcpLoopOptions) -> bool {
    #[cfg(feature = "dhcp6")]
    {
        !opts.slaac_contexts.is_empty()
    }
    #[cfg(not(feature = "dhcp6"))]
    {
        let _ = opts;
        false
    }
}

/// SLAAC DAD probe/reply state for [`run_dhcp_loop`] (slaac.c:119-213).
///
/// Always constructed, even when `dhcp6` isn't compiled in or no RA-name
/// context was configured, so the loop's extra `tokio::select!` branch can
/// be written once, unconditionally — `tokio::select!` branches don't
/// support `#[cfg(...)]` the way ordinary `match` arms do, so the
/// dhcp6/non-dhcp6 (and enabled/disabled) split has to live inside this
/// type instead of around the branch. `Inactive` polls as permanently
/// pending, matching the `, if slaac_dad.active()` guard that keeps it from
/// ever being selected.
enum SlaacDad {
    Inactive,
    #[cfg(feature = "dhcp6")]
    Active {
        ping_id: u16,
        icmp6: crate::slaac::Icmp6Socket,
        probe_tick: tokio::time::Interval,
        buf: [u8; 1500],
    },
}

impl SlaacDad {
    #[cfg(feature = "dhcp6")]
    fn new(enabled: bool) -> Self {
        if !enabled {
            return Self::Inactive;
        }
        // Nonzero, process-lifetime ping identifier (`while (ping_id == 0)
        // ping_id = rand16();`, slaac.c:134-135).
        let mut ping_id: u16 = crate::util::rand16();
        while ping_id == 0 {
            ping_id = crate::util::rand16();
        }
        // Opening a raw ICMPv6 socket needs CAP_NET_RAW; probing is
        // disabled rather than treated as a startup failure when the
        // process lacks it — "DAD probing works where permissions allow"
        // is the acceptance bar, not "the DHCP server requires it".
        match crate::slaac::Icmp6Socket::create() {
            Ok(icmp6) => Self::Active {
                ping_id,
                icmp6,
                probe_tick: tokio::time::interval(std::time::Duration::from_secs(1)),
                buf: [0u8; 1500],
            },
            Err(e) => {
                debug!("SLAAC DAD probing disabled (no ICMPv6 raw socket: {e})");
                Self::Inactive
            }
        }
    }

    #[cfg(not(feature = "dhcp6"))]
    fn new(_enabled: bool) -> Self {
        Self::Inactive
    }

    fn active(&self) -> bool {
        match self {
            Self::Inactive => false,
            #[cfg(feature = "dhcp6")]
            Self::Active { .. } => true,
        }
    }

    /// Send a due DAD probe or handle an inbound ICMPv6 echo reply,
    /// mutating `lease_db` in place (`periodic_slaac`/`slaac_ping_reply`,
    /// slaac.c:119-213). Never resolves when `Inactive` — callers must gate
    /// on [`Self::active`], matching how this is used in `run_dhcp_loop`.
    #[cfg_attr(not(feature = "dhcp6"), allow(unused_variables))]
    async fn poll_tick_or_recv(
        &mut self,
        lease_db: &mut LeaseDb,
        contexts: &[crate::types::dhcp::DhcpContext],
    ) {
        match self {
            Self::Inactive => std::future::pending::<()>().await,
            #[cfg(feature = "dhcp6")]
            Self::Active { ping_id, icmp6, probe_tick, buf } => {
                tokio::select! {
                    _ = probe_tick.tick() => {
                        let id = *ping_id;
                        lease_db.tick_slaac(std::time::SystemTime::now(), contexts, id, |dest, packet| {
                            icmp6.send_echo_sync(dest, packet)
                        });
                    }
                    r = icmp6.recv(buf) => {
                        match r {
                            Ok((n, sender)) => {
                                lease_db.confirm_slaac_ping(sender, &buf[..n], *ping_id, "", false);
                            }
                            Err(e) => debug!("SLAAC DAD probe ICMPv6 recv error: {e}"),
                        }
                    }
                }
            }
        }
    }
}

/// Receive one DHCP datagram, with the `IP_PKTINFO` arrival-interface
/// metadata [`bind_listeners`] enables on the socket via
/// [`crate::network::set_ipv4pktinfo`].
///
/// Mirrors `recv_datagram` in `forward.rs`: `try_io` after the socket
/// reports readable, retrying on `WouldBlock` since readiness can be a false
/// positive under `tokio`'s edge-triggered polling.
#[cfg(unix)]
async fn recv_dhcp_datagram(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<crate::network::RecvMeta> {
    use std::os::unix::io::AsRawFd;
    loop {
        socket.readable().await?;
        let fd = socket.as_raw_fd();
        match socket.try_io(tokio::io::Interest::READABLE, || crate::network::recv_with_dest(fd, buf)) {
            Ok(meta) => return Ok(meta),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
}

/// Non-Unix fallback: no control messages, so no arrival metadata.
#[cfg(not(unix))]
async fn recv_dhcp_datagram(
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
) -> std::io::Result<crate::network::RecvMeta> {
    let (len, src) = socket.recv_from(buf).await?;
    Ok(crate::network::RecvMeta { len, src, dest: None, if_index: 0 })
}

/// Resolve an `IP_PKTINFO` arrival interface index into the
/// local/netmask/broadcast triple [`link_contexts_for_interface`] needs.
///
/// Returns `None` when the index is `0` (no control message — an unbound
/// socket, a platform without `IP_PKTINFO` support, or a permission failure
/// setting it) or when the interface has since disappeared or carries no
/// IPv4 netmask; callers treat that the same as "arrival interface unknown"
/// and fall back to searching every configured context, same as before this
/// existed.
fn arrival_interface(if_index: u32) -> Option<ArrivalInterface> {
    if if_index == 0 {
        return None;
    }
    let interfaces = crate::network::enumerate_interfaces().ok()?;
    let iface = interfaces.into_iter().find(|i| i.index == if_index)?;
    let IpAddr::V4(local) = iface.addr else { return None };
    let Some(IpAddr::V4(netmask)) = iface.netmask else { return None };
    let broadcast = Ipv4Addr::from(u32::from(local) | !u32::from(netmask));
    Some(ArrivalInterface { local, netmask, broadcast, if_index: if_index as i32 })
}

/// [`dispatch_dhcp_with_meta`], restricted to the `dhcp-range` contexts that
/// share a subnet with `arrival` (upstream's `context->current` chain, built
/// by `complete_context()`/`guess_range_netmask()`, dhcp.c:296-365).
///
/// [`link_contexts_for_interface`] both fills in any netmask/broadcast/router
/// the matched contexts are missing *and* mutates `cfg.contexts` in place —
/// matching upstream, which persists the same fill-in across calls — and
/// returns which contexts are valid for a host on `arrival`. When at least
/// one context links, [`dispatch_dhcp_with_meta`] only sees that narrowed
/// set. When `arrival` is `None`, or links to nothing (an unknown interface,
/// or a relayed request from a subnet with no matching local `dhcp-range`),
/// this falls back to the full context list — [`narrow_context`]'s original,
/// permissive behavior — rather than refusing to answer.
pub fn dispatch_dhcp_with_arrival(
    pkt: &DhcpPacket,
    cfg: &mut DhcpServerConfig,
    lease_db: &mut LeaseDb,
    ping_cache: &mut PingCache,
    probe: &dyn AddressProbe,
    arrival: Option<&ArrivalInterface>,
) -> Option<DispatchedDhcpReply> {
    let Some(iface) = arrival else {
        return dispatch_dhcp_with_meta(pkt, cfg, lease_db, ping_cache, probe);
    };
    let linked = link_contexts_for_interface(&mut cfg.contexts, iface);
    let dispatched = if linked.is_empty() {
        dispatch_dhcp_with_meta(pkt, cfg, lease_db, ping_cache, probe)
    } else {
        let mut narrowed = cfg.clone();
        narrowed.contexts = linked.iter().map(|&i| cfg.contexts[i].clone()).collect();
        dispatch_dhcp_with_meta(pkt, &narrowed, lease_db, ping_cache, probe)
    };

    // Port of lease_set_interface() (lease.c:1148-1159), called from
    // rfc2131.c:1717/:1789 right after a REQUEST/INFORM ACK commits a lease.
    // This is the interface-index half of slaac_add_addrs's
    // `lease->last_interface == context->if_index` match (slaac.c:43) — the
    // hwaddr/hostname half is already set inside record_lease via
    // set_hwaddr/set_hostname. Only known here, at the arrival-metadata
    // boundary, since dispatch_dhcp_with_meta has no IP_PKTINFO to work with.
    if let Some(d) = &dispatched {
        if d.reply.msg_type == DhcpMsgType::Ack && d.reply.yiaddr != Ipv4Addr::UNSPECIFIED {
            lease_db.set_interface(d.reply.yiaddr, iface.if_index);
        }
    }

    dispatched
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

use crate::types::dhcp::{DhcpContext, DhcpConfig, CONTEXT_STATIC, CONTEXT_PROXY, CONTEXT_NETMASK, CONTEXT_BRDCAST, CONFIG_ADDR};

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

/// The local address/netmask/broadcast of the interface a DHCP request
/// arrived on, as `IP_PKTINFO` would report it. Mirrors the per-arrival
/// inputs `dhcp_packet()` feeds to `complete_context()` (dhcp.c:296-365).
///
/// Built by [`arrival_interface`] from the `IP_PKTINFO` control message
/// `crate::network::recv_with_dest` reads off the DHCP socket in
/// `run_dhcp_loop` (`bind_listeners` enables it via
/// `crate::network::set_ipv4pktinfo`), then consumed by
/// [`dispatch_dhcp_with_arrival`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArrivalInterface {
    pub local: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub broadcast: Ipv4Addr,
    /// Numeric index of the arrival interface (`if_index` from `IP_PKTINFO`).
    /// Fed to `LeaseDb::set_interface` — the missing half of
    /// `slaac_add_addrs`'s `lease->last_interface == context->if_index`
    /// match (slaac.c:43), which without this was always `0` for every
    /// lease `record_lease` ever committed.
    pub if_index: i32,
}

/// Link every context that shares a subnet with the arriving interface,
/// filling in a guessed netmask/broadcast/router for any that need it.
///
/// Port of `guess_range_netmask()` (dhcp.c:568-587) plus the local-subnet
/// linking half of `complete_context()` (dhcp.c:589-660) — the
/// `shared_networks`/`dhcp-relay` linking in the other half needs
/// daemon-wide state this function doesn't have and isn't ported.
///
/// Returns the indices into `contexts` that are valid for a host directly
/// connected to this interface (upstream's `context->current` chain).
/// [`dispatch_dhcp_with_arrival`] restricts context selection to just those
/// indices for the rest of that packet's dispatch.
pub fn link_contexts_for_interface(contexts: &mut [DhcpContext], iface: &ArrivalInterface) -> Vec<usize> {
    for ctx in contexts.iter_mut() {
        if ctx.flags & CONTEXT_NETMASK == 0
            && (is_same_net(iface.local, ctx.start, iface.netmask)
                || is_same_net(iface.local, ctx.end, iface.netmask))
        {
            ctx.netmask = iface.netmask;
        }
    }

    let mut linked = Vec::new();
    for (i, ctx) in contexts.iter_mut().enumerate() {
        if ctx.netmask == Ipv4Addr::UNSPECIFIED
            || !is_same_net(iface.local, ctx.start, ctx.netmask)
            || !is_same_net(iface.local, ctx.end, ctx.netmask)
        {
            continue;
        }

        ctx.router = iface.local;
        ctx.local = iface.local;
        if ctx.flags & CONTEXT_BRDCAST == 0 {
            ctx.broadcast = if is_same_net(iface.broadcast, ctx.start, ctx.netmask) {
                iface.broadcast
            } else {
                Ipv4Addr::from(u32::from(ctx.start) | !u32::from(ctx.netmask))
            };
        }
        linked.push(i);
    }
    linked
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
// ICMP address-conflict probing (ported from dhcp.c:769-923, dnsmasq.c:2339-2378)
// ─────────────────────────────────────────────────────────────────────────────

/// Something that can tell whether an address is already answering on the
/// network. Implemented by [`crate::dnsmasq::IcmpPinger`] in production and by
/// fakes in tests, so `address_allocate` never needs a real raw socket to be
/// unit-tested.
pub trait AddressProbe {
    /// Returns `true` if `addr` is in use (answered an ICMP echo request).
    fn in_use(&self, addr: Ipv4Addr) -> bool;
}

/// A single cached ping outcome. Port of `struct ping_result` (dnsmasq.h:1106).
#[derive(Debug, Clone)]
struct PingResult {
    addr: Ipv4Addr,
    time: std::time::SystemTime,
    hash: u32,
}

/// Time-bounded, load-limited cache of ICMP conflict checks.
///
/// Port of `do_icmp_ping()` (dhcp.c:769-823): avoids re-pinging an address
/// that was checked in the last `PING_CACHE_TIME` seconds, and stops pinging
/// altogether once more than 60% of the possible checks in that window have
/// already happened (protects against a misbehaving client hammering us with
/// DISCOVERs).
pub struct PingCache {
    results: Vec<PingResult>,
}

/// Port of `config.h`'s `PING_CACHE_TIME` (30s ping-result validity).
const PING_CACHE_TIME_SECS: f64 = 30.0;
/// Port of `config.h`'s `PING_WAIT` (per-ping timeout, 3s).
const PING_WAIT_SECS: f64 = 3.0;

impl PingCache {
    pub fn new() -> Self {
        Self { results: Vec::new() }
    }

    /// Returns `Some(hash)` if `addr` is believed free (a fresh or cached
    /// negative result), `None` if it answered a ping (in use).
    ///
    /// `no_ping` (`--no-ping`/`OPT_NO_PING`) and `loopback` (request arrived
    /// on the loopback interface) both short-circuit to "not in use" without
    /// ever probing, matching dhcp.c:793-798.
    fn check(
        &mut self,
        now: std::time::SystemTime,
        addr: Ipv4Addr,
        hash: u32,
        no_ping: bool,
        loopback: bool,
        probe: &dyn AddressProbe,
    ) -> Option<u32> {
        let max = (0.6 * (PING_CACHE_TIME_SECS / PING_WAIT_SECS)) as usize;

        let mut count = 0usize;
        let mut victim: Option<usize> = None;
        for (i, r) in self.results.iter().enumerate() {
            let age = now
                .duration_since(r.time)
                .unwrap_or(Duration::ZERO)
                .as_secs_f64();
            if age > PING_CACHE_TIME_SECS {
                victim = Some(i);
            } else {
                count += 1;
                if r.addr == addr {
                    return Some(r.hash);
                }
            }
        }

        if count >= max || no_ping || loopback {
            return Some(hash);
        }

        if probe.in_use(addr) {
            return None;
        }

        let record = PingResult { addr, time: now, hash };
        match victim {
            Some(i) => self.results[i] = record,
            None => self.results.push(record),
        }
        Some(hash)
    }
}

impl Default for PingCache {
    fn default() -> Self {
        Self::new()
    }
}

/// Plain (non-wildcard) `match_netid()` port (dhcp-common.c:224-247), used by
/// `address_allocate`'s two-pass context selection: pass 0 requires the
/// context's filter to be non-empty and satisfied by `netids`; pass 1
/// (`tagnotneeded = true`) also accepts contexts with no filter at all.
fn context_filter_matches(filter: &[crate::types::dhcp::DhcpNetid], netids: &[crate::types::dhcp::DhcpNetid], tagnotneeded: bool) -> bool {
    if filter.is_empty() {
        return tagnotneeded;
    }
    for check in filter {
        let negated = check.net.starts_with('!') || check.net.starts_with('#');
        if negated {
            let name = &check.net[1..];
            if netids.iter().any(|n| n.net == name) {
                return false;
            }
        } else if !netids.iter().any(|n| n.net == check.net) {
            return false;
        }
    }
    true
}

fn next_addr_wrapping(addr: Ipv4Addr, start: Ipv4Addr, end: Ipv4Addr) -> Ipv4Addr {
    let next = u32::from(addr).wrapping_add(1);
    if next == u32::from(end).wrapping_add(1) {
        start
    } else {
        Ipv4Addr::from(next)
    }
}

/// Find a free address by scanning DHCP `contexts`, excluding anything
/// leased, statically reserved, a router/server address, or Windows-unsafe
/// (`.0`/`.255`), and confirming freedom with an ICMP ping.
///
/// Port of `address_allocate()` (dhcp.c:825-922). The seed address is either
/// the highest leased address in the context (`--dhcp-authoritative` /
/// `OPT_CONSEC_ADDR`) or a hash of `hwaddr` mixed with the context's
/// `addr_epoch`, so restarts distribute clients across the pool instead of
/// always starting from `start`.
///
/// Deliberately not ported: the `addr_epoch` perturbation upstream applies
/// when a candidate is rejected (dhcp.c:900-921), which nudges future seeds
/// away from recently-contested addresses. Every scan here always starts
/// from the same seed for a given hwaddr/epoch. Tracked in `tasks.md`.
#[allow(clippy::too_many_arguments)]
pub fn address_allocate(
    contexts: &[DhcpContext],
    lease_db: &LeaseDb,
    configs: &[DhcpConfig],
    hwaddr: &[u8],
    netids: &[crate::types::dhcp::DhcpNetid],
    now: std::time::SystemTime,
    loopback: bool,
    consec_addr: bool,
    no_ping: bool,
    ping_cache: &mut PingCache,
    probe: &dyn AddressProbe,
) -> Option<Ipv4Addr> {
    let hash = sdbm_hash(hwaddr);

    for pass in 0..=1 {
        for c in contexts {
            if c.flags & (CONTEXT_STATIC | CONTEXT_PROXY) != 0 {
                continue;
            }
            if !context_filter_matches(&c.filter, netids, pass == 1) {
                continue;
            }

            let start_addr = if consec_addr {
                lease_db.find_max_addr(c.start, c.end)
            } else {
                hash_to_addr(hash, c.addr_epoch, c.start, c.end)
            };

            let mut addr = start_addr;
            loop {
                let router_conflict = contexts.iter().any(|d| addr == d.router);

                if !router_conflict
                    && is_allocatable_addr(addr)
                    && lease_db.find_by_addr(addr).is_none()
                    && config_find_by_address(configs, addr).is_none()
                {
                    if let Some(r_hash) = ping_cache.check(now, addr, hash, no_ping, loopback, probe) {
                        if !consec_addr || r_hash == hash {
                            return Some(addr);
                        }
                    }
                }

                addr = next_addr_wrapping(addr, c.start, c.end);
                if addr == start_addr {
                    break;
                }
            }
        }
    }

    None
}

/// Build a single DHCP context spanning `[start, end]` with no filter and no
/// router, standing in for `cfg.contexts` when a caller only populated the
/// flat `pool_start`/`pool_end` fields (production always populates
/// `cfg.contexts` from `dhcp-range`; this exists so hand-built
/// `DhcpServerConfig` values in tests don't also need to).
fn synthetic_pool_context(start: Ipv4Addr, end: Ipv4Addr) -> DhcpContext {
    DhcpContext {
        lease_time: 3600,
        addr_epoch: 0,
        netmask: Ipv4Addr::UNSPECIFIED,
        broadcast: Ipv4Addr::UNSPECIFIED,
        local: Ipv4Addr::UNSPECIFIED,
        router: Ipv4Addr::UNSPECIFIED,
        start,
        end,
        flags: 0,
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

fn allocation_contexts(cfg: &DhcpServerConfig) -> std::borrow::Cow<'_, [DhcpContext]> {
    if cfg.contexts.is_empty() {
        std::borrow::Cow::Owned(vec![synthetic_pool_context(cfg.pool_start, cfg.pool_end)])
    } else {
        std::borrow::Cow::Borrowed(&cfg.contexts)
    }
}

/// Build an ICMP echo-request packet (type 8, code 0) with the given
/// identifier and sequence 0, matching the zero-initialised `struct icmp`
/// upstream sends in `icmp_ping()` (dnsmasq.c:2339-2378) — only `icmp_type`
/// and `icmp_id` are ever set there, so `icmp_seq` is always 0.
pub(crate) fn build_icmp_echo_request(id: u16) -> [u8; 8] {
    let mut pkt = [0u8; 8];
    pkt[0] = 8; // ICMP_ECHO
    pkt[1] = 0; // code
    pkt[4..6].copy_from_slice(&id.to_be_bytes());
    // seq (pkt[6..8]) stays 0.
    let cksum = icmp_checksum(&pkt);
    pkt[2..4].copy_from_slice(&cksum.to_be_bytes());
    pkt
}

/// Parse a raw-socket read (`IP header + ICMP header [+ data]`) and report
/// whether it's an echo reply matching `expected_id`/seq 0, mirroring the
/// `packet.icmp.icmp_type == ICMP_ECHOREPLY && ... icmp_seq == 0 &&
/// icmp_id == id` check in `delay_dhcp()` (dnsmasq.c:2466-2469).
pub(crate) fn parse_icmp_echo_reply(data: &[u8], expected_id: u16) -> bool {
    if data.is_empty() {
        return false;
    }
    let ihl = usize::from(data[0] & 0x0f) * 4;
    if data.len() < ihl + 8 {
        return false;
    }
    let icmp = &data[ihl..];
    const ICMP_ECHOREPLY: u8 = 0;
    let id = u16::from_be_bytes([icmp[4], icmp[5]]);
    let seq = u16::from_be_bytes([icmp[6], icmp[7]]);
    icmp[0] == ICMP_ECHOREPLY && seq == 0 && id == expected_id
}

// ─────────────────────────────────────────────────────────────────────────────
// --read-ethers (ported from dhcp.c:924-1083)
// ─────────────────────────────────────────────────────────────────────────────

use crate::types::dhcp::{HwaddrConfig, CONFIG_FROM_ETHERS, CONFIG_NAME, CONFIG_NOCLID};

/// Default location of the ethers file (`ETHERSFILE` in config.h).
pub const ETHERS_FILE: &str = "/etc/ethers";

/// `ARPHRD_ETHER` — the only hardware type `/etc/ethers` lines can specify.
const ARPHRD_ETHER: i32 = 1;

#[derive(Debug, Clone, PartialEq)]
enum EthersKey {
    Addr(Ipv4Addr),
    Name(String),
}

#[derive(Debug, Clone)]
struct EthersRecord {
    hwaddr: [u8; 6],
    key: EthersKey,
}

/// Parse `/etc/ethers`-style text (`<hwaddr> <ip-or-hostname>` per line,
/// `#`/`+`-prefixed and blank lines ignored) into records, skipping
/// malformed lines the same way `dhcp_read_ethers()` does (dhcp.c:958-1006):
/// silently continuing past a bad hwaddr, bad address, or bad hostname.
fn parse_ethers_text(text: &str) -> Vec<EthersRecord> {
    let mut records = Vec::new();

    for raw_line in text.lines() {
        let line = raw_line.trim_end();
        if line.is_empty() || line.starts_with('#') || line.starts_with('+') {
            continue;
        }

        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(mac_part) = parts.next().filter(|s| !s.is_empty()) else { continue };
        let rest = parts.next().map(str::trim_start).unwrap_or("");
        if rest.is_empty() {
            continue; // "bad line" — no IP/name field (dhcp.c:970-975)
        }

        let mut hwaddr_vec = Vec::new();
        if crate::util::parse_hex(mac_part, &mut hwaddr_vec, Some(6), None) != 6 {
            continue; // "bad line" (dhcp.c:970-975)
        }
        let mut hwaddr = [0u8; 6];
        hwaddr.copy_from_slice(&hwaddr_vec);

        // dhcp.c:977-979: a "name or dotted-quad" is a dotted-quad only if
        // every character is a digit or '.'.
        let looks_like_addr = rest.chars().all(|c| c == '.' || c.is_ascii_digit());
        let key = if looks_like_addr {
            match rest.parse::<Ipv4Addr>() {
                Ok(addr) => EthersKey::Addr(addr),
                Err(_) => continue, // "bad address" (dhcp.c:984-988)
            }
        } else {
            match crate::util::canonicalise(rest) {
                Some(host) if crate::util::legal_hostname(&host) => EthersKey::Name(host),
                _ => continue, // "bad name" (dhcp.c:1000-1004)
            }
        };

        records.push(EthersRecord { hwaddr, key });
    }

    records
}

/// Merge parsed `/etc/ethers` records into `dhcp_conf`, purging any
/// entries left over from a prior run first (dhcp.c:944-956 — this makes it
/// safe to re-run on SIGHUP). A record whose address/hostname already
/// matches a `CONFIG_FROM_ETHERS` entry created earlier *in this same pass*
/// is a duplicate and is dropped (dhcp.c:1013-1016); one matching a
/// non-ethers entry (e.g. from `dhcp-host`) is merged into it instead of
/// creating a new one, and a record whose hwaddr exactly matches an existing
/// hwaddr-only `dhcp-host` entry attaches to that entry (dhcp.c:1023-1043).
fn apply_ethers_records(dhcp_conf: &mut Vec<DhcpConfig>, records: Vec<EthersRecord>) -> usize {
    dhcp_conf.retain(|c| c.flags & CONFIG_FROM_ETHERS == 0);

    let mut count = 0;
    for rec in records {
        let existing_idx = dhcp_conf.iter().position(|c| match &rec.key {
            EthersKey::Addr(addr) => (c.flags & CONFIG_ADDR) != 0 && c.addr == *addr,
            EthersKey::Name(name) => {
                (c.flags & CONFIG_NAME) != 0
                    && c.hostname.as_deref().is_some_and(|h| crate::util::hostname_isequal(h, name))
            }
        });

        if let Some(idx) = existing_idx {
            if dhcp_conf[idx].flags & CONFIG_FROM_ETHERS != 0 {
                warn!("ignoring duplicate name or IP address in {ETHERS_FILE}");
                continue;
            }
        }

        let target_idx = if let Some(idx) = existing_idx {
            idx
        } else if let Some(idx) = dhcp_conf.iter().position(|c| {
            c.hwaddrs.len() == 1
                && c.hwaddrs[0].hwaddr_len == 6
                && c.hwaddrs[0].hwaddr_type == ARPHRD_ETHER
                && c.hwaddrs[0].wildcard_mask == 0
                && c.hwaddrs[0].hwaddr[..6] == rec.hwaddr
        }) {
            idx
        } else {
            dhcp_conf.push(DhcpConfig {
                flags: CONFIG_FROM_ETHERS,
                clid: None,
                hostname: None,
                domain: None,
                netid: vec![],
                filter: vec![],
                addr: Ipv4Addr::UNSPECIFIED,
                decline_time: None,
                lease_time: 0,
                hwaddrs: vec![],
                #[cfg(feature = "dhcp6")]
                addr6: vec![],
            });
            dhcp_conf.len() - 1
        };

        let config = &mut dhcp_conf[target_idx];
        match &rec.key {
            EthersKey::Addr(addr) => {
                config.flags |= CONFIG_ADDR;
                config.addr = *addr;
            }
            EthersKey::Name(name) => {
                config.flags |= CONFIG_NAME;
                config.hostname = Some(name.clone());
            }
        }
        config.flags |= CONFIG_NOCLID;

        let mut hwaddr_full = [0u8; DHCP_CHADDR_MAX];
        hwaddr_full[..6].copy_from_slice(&rec.hwaddr);
        let mac_entry = HwaddrConfig {
            hwaddr: hwaddr_full,
            hwaddr_len: 6,
            hwaddr_type: ARPHRD_ETHER,
            wildcard_mask: 0,
        };
        if let Some(first) = config.hwaddrs.first_mut() {
            *first = mac_entry;
        } else {
            config.hwaddrs.push(mac_entry);
        }

        count += 1;
    }

    count
}

/// Read and apply `path` (normally [`ETHERS_FILE`]) into `dhcp_conf`.
/// Port of `dhcp_read_ethers()` (dhcp.c:924-1083), split into the pure
/// [`parse_ethers_text`]/[`apply_ethers_records`] helpers above so parsing
/// and merge logic are unit-testable without touching the filesystem.
pub fn dhcp_read_ethers(dhcp_conf: &mut Vec<DhcpConfig>, path: &str) -> std::io::Result<usize> {
    let text = std::fs::read_to_string(path)?;
    let records = parse_ethers_text(&text);
    Ok(apply_ethers_records(dhcp_conf, records))
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
            lease_change_command: None,
            match_rules: vec![],
            name_match_rules: vec![],
            tag_rules: vec![],
            relay4: vec![],
            no_ping: false,
            consec_addr: false,
            dhcp_ignore: vec![],
            ..Default::default()
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

    /// Option 82 (agent information) must be echoed back verbatim per RFC 3046 §2.1,
    /// even when this daemon has no `dhcp-relay` of its own configured — an upstream
    /// relay agent may have added it before the request ever reached us.
    #[test]
    fn reply_echoes_inbound_agent_id_option_82() {
        let mut pkt = base_packet();
        let agent_info = [OPTION_AGENT_ID, 8, 1, 6, b'u', b'p', b'l', b'i', b'n', b'k'];
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
        ];
        pkt.options.extend_from_slice(&agent_info);
        pkt.options.push(OPTION_END);

        let cfg = default_cfg();
        let reply = dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).expect("offer reply");

        let idx = crate::rfc2131::option_find1(&reply.options, OPTION_AGENT_ID, 1)
            .expect("agent-id echoed in reply");
        assert_eq!(crate::rfc2131::option_val_at(&reply.options, idx), &agent_info[2..]);
    }

    #[test]
    fn reply_has_no_agent_id_when_request_has_none() {
        let pkt = base_packet();
        let cfg = default_cfg();
        let reply = dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).expect("offer reply");
        assert!(crate::rfc2131::option_find1(&reply.options, OPTION_AGENT_ID, 0).is_none());
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

    /// `--dhcp-ignore=<tag>` gates on a client's *derived* tags directly
    /// (rfc2131.c:614/851), independent of any matched `DhcpConfig` entry —
    /// unlike `discover_matching_dhcp_ignore_produces_no_reply` above, no
    /// `cfg.configs`/`CONFIG_DISABLE` entry is involved here at all.
    #[test]
    fn discover_matching_global_dhcp_ignore_tag_produces_no_reply() {
        use crate::types::dhcp::{DhcpMacRule, DhcpNetid, DhcpNetidList};

        let mut cfg = default_cfg();
        cfg.mac_rules.push(DhcpMacRule {
            netid: DhcpNetid { net: "blocked".into() },
            hwaddr: [0x00, 0x60, 0x8c, 0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            hwaddr_len: 6,
            hwaddr_type: 1,
            wildcard_mask: 0b000111,
        });
        cfg.dhcp_ignore.push(DhcpNetidList { list: vec![DhcpNetid { net: "blocked".into() }] });

        let mut pkt = base_packet();
        pkt.chaddr[..6].copy_from_slice(&[0x00, 0x60, 0x8c, 0x12, 0x34, 0x56]);
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn discover_not_matching_global_dhcp_ignore_tag_still_offers() {
        use crate::types::dhcp::{DhcpNetid, DhcpNetidList};

        let mut cfg = default_cfg();
        cfg.dhcp_ignore.push(DhcpNetidList { list: vec![DhcpNetid { net: "blocked".into() }] });

        let pkt = base_packet();
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_some());
    }

    #[test]
    fn discover_empty_dhcp_ignore_entry_does_not_match_anyone() {
        // An empty tag list (from a bare `dhcp-ignore` — not actually valid
        // upstream config, since `-J` requires a value, but exercised here
        // for robustness) must not vacuously ignore every client: real
        // `match_netid(check=[], pool, tagnotneeded=0)` returns false.
        use crate::types::dhcp::DhcpNetidList;

        let mut cfg = default_cfg();
        cfg.dhcp_ignore.push(DhcpNetidList { list: vec![] });

        let pkt = base_packet();
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_some());
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

        let reply = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("discover should produce an offer");
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

        let reply = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("discover should produce an offer");
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

        let reply = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("discover should produce an offer");
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

        let reply = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("request should produce an ack");
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

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db, &mut PingCache::new(), &NullProbe).expect("request should ack");
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

        assert!(dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db, &mut PingCache::new(), &NullProbe).is_none());
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

        assert!(dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db, &mut PingCache::new(), &NullProbe).is_none());
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

        assert!(dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db, &mut PingCache::new(), &NullProbe).is_none());
        assert!(lease_db.find_by_addr(addr).is_none());
    }

    #[test]
    fn inform_returns_ack_without_allocating_address() {
        let mut pkt = base_packet();
        pkt.ciaddr = Ipv4Addr::new(10, 0, 0, 55);
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Inform as u8, OPTION_END];
        let cfg = default_cfg();
        let mut lease_db = LeaseDb::new();

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db, &mut PingCache::new(), &NullProbe).expect("inform should ack");
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
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("discover should offer");
        assert!(find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_LEASE_TIME).is_some());

        let mut req_pkt = base_packet();
        req_pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Request as u8,
            crate::dhcp_protocol::OPTION_REQUESTED_IP, 4, 10, 0, 0, 123,
            OPTION_END,
        ];
        let dispatched = dispatch_dhcp_with_meta(&req_pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("request should ack");
        assert!(find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_LEASE_TIME).is_some());
    }

    #[test]
    fn inform_ack_does_not_carry_lease_time_option() {
        let mut pkt = base_packet();
        pkt.ciaddr = Ipv4Addr::new(10, 0, 0, 55);
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Inform as u8, OPTION_END];
        let cfg = default_cfg();
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("inform should ack");
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
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("inform should ack");
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
            ..Default::default()
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let loop_task = tokio::spawn(run_dhcp_loop(server.clone(), cfg, opts, LeaseDb::new(), shutdown_rx, Box::new(NullProbe)));

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

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("discover should produce an offer");
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

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("discover should produce an offer");
        assert_eq!(
            find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_DOMAINNAME),
            Some(&b"lab.example"[..])
        );
    }

    #[test]
    fn discover_dhcp_match_and_tag_if_select_tagged_option() {
        use crate::types::dhcp::{DhcpNetid, DhcpOpt};

        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
            OPTION_VENDOR_ID, 21,
            b'P', b'X', b'E', b'C', b'l', b'i', b'e', b'n', b't', b':',
            b'A', b'r', b'c', b'h', b':', b'0', b'0', b'0', b'0', b'7',
            OPTION_REQUESTED_OPTIONS, 1, crate::dhcp_protocol::OPTION_DOMAINNAME,
            OPTION_END,
        ];

        let mut cfg = default_cfg();
        // dhcp-match=set:pxe,60,PXEClient
        cfg.match_rules.push(DhcpOpt {
            opt: crate::dhcp_protocol::OPTION_VENDOR_ID as i32,
            flags: crate::types::dhcp::DHOPT_STRING | crate::types::dhcp::DHOPT_MATCH,
            val: Some(b"PXEClient".to_vec()),
            netid: vec![DhcpNetid { net: "pxe".into() }],
            encap: 0,
            vendor_class: None,
        });
        // tag-if=tag:pxe,set:pxeboot
        cfg.tag_rules.push(crate::dhcp_common::TagIf {
            tag: vec![DhcpNetid { net: "pxe".into() }],
            set: vec![DhcpNetid { net: "pxeboot".into() }],
        });
        // dhcp-option=tag:pxeboot,15,"boot.example"
        cfg.dhcp_opts.push(DhcpOpt {
            opt: crate::dhcp_protocol::OPTION_DOMAINNAME as i32,
            flags: crate::types::dhcp::DHOPT_STRING,
            val: Some(b"boot.example".to_vec()),
            netid: vec![DhcpNetid { net: "pxeboot".into() }],
            encap: 0,
            vendor_class: None,
        });

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe)
            .expect("discover should produce an offer");
        assert_eq!(
            find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_DOMAINNAME),
            Some(&b"boot.example"[..])
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

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("discover should produce an offer");
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
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("discover should produce an offer");

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
        // Hash-seeded allocation (dhcp.c:860-864) offers pool_start+1 for an
        // all-zero hwaddr, not pool_start itself — see `sdbm_hash_never_zero`.
        assert_eq!(reply.yiaddr, Ipv4Addr::new(10, 0, 0, 101));
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
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe).expect("discover should produce an offer");
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

    /// End-to-end: a real socket, real `IP_PKTINFO`, real `recvmsg` — proving
    /// `run_dhcp_loop` actually resolves the arrival interface off the wire
    /// and restricts context selection to it, not just in the pure
    /// `dispatch_dhcp_with_arrival` unit tests above (which pass a
    /// hand-built `ArrivalInterface` and never touch a socket).
    #[tokio::test]
    async fn run_dhcp_loop_restricts_offer_to_arriving_interfaces_subnet() {
        let Some(server) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(client) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(receiver) = bind_udp_or_skip("127.0.0.1:0").await else { return; };

        {
            use std::os::unix::io::AsRawFd as _;
            if !crate::network::set_ipv4pktinfo(server.as_raw_fd()).unwrap_or(false) {
                eprintln!("skipping: IP_PKTINFO not supported in this sandbox");
                return;
            }
        }
        if crate::network::nametoindex("lo") == 0 {
            eprintln!("skipping: could not resolve 'lo' interface index");
            return;
        }

        let receiver_addr = receiver.local_addr().unwrap();
        let server = std::sync::Arc::new(server);
        // 10.0.0.0/24 comes first: address_allocate would offer from it if
        // arrival restriction weren't wired up. 127.0.0.0/8 is second, but is
        // the only range on the interface (lo) the request actually arrives
        // on, so a correctly-wired loop must offer from it instead.
        let cfg = DhcpServerConfig {
            contexts: vec![
                make_ctx(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200), Ipv4Addr::UNSPECIFIED, 0),
                make_ctx(Ipv4Addr::new(127, 0, 0, 50), Ipv4Addr::new(127, 0, 0, 60), Ipv4Addr::UNSPECIFIED, 0),
            ],
            ..default_cfg()
        };
        let opts = DhcpLoopOptions {
            reply_port_override: Some(receiver_addr.port()),
            ..Default::default()
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let loop_task = tokio::spawn(run_dhcp_loop(server.clone(), cfg, opts, LeaseDb::new(), shutdown_rx, Box::new(NullProbe)));

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
        assert!(
            is_same_net(reply.yiaddr, Ipv4Addr::new(127, 0, 0, 0), Ipv4Addr::new(255, 0, 0, 0)),
            "expected an offer from the arriving (lo) interface's 127.0.0.0/8 range, got {}",
            reply.yiaddr,
        );

        shutdown_tx.send(true).unwrap();
        loop_task.await.unwrap().unwrap();
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
            ..Default::default()
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let loop_task = tokio::spawn(run_dhcp_loop(server.clone(), cfg, opts, LeaseDb::new(), shutdown_rx, Box::new(NullProbe)));

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
        assert_eq!(reply.yiaddr, Ipv4Addr::new(10, 0, 0, 101));

        shutdown_tx.send(true).unwrap();
        loop_task.await.unwrap().unwrap();
    }

    /// `leasequery_source` must come from `giaddr`, not the raw UDP source,
    /// for a standard RFC 4388 leasequery client (dhcp.c:373-375). A packet
    /// arriving from an always-allowed loopback address but carrying a
    /// `giaddr` outside every configured `leasequery-addr` prefix must be
    /// rejected — the old code derived `leasequery_source` from the UDP
    /// source alone and would have wrongly allowed it.
    #[tokio::test]
    async fn run_dhcp_loop_leasequery_source_comes_from_giaddr_not_udp_source() {
        let Some(server) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(client) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(receiver) = bind_udp_or_skip("127.0.0.1:0").await else { return; };

        let receiver_addr = receiver.local_addr().unwrap();
        let server = std::sync::Arc::new(server);
        let mut cfg = default_cfg();
        cfg.leasequery_enabled = true;
        // Only 127.0.0.1/32 is allowed. The UDP source (127.0.0.1) matches
        // this; the packet's giaddr (203.0.113.9) does not.
        cfg.leasequery_addr = vec![crate::types::dns_records::BogusAddr {
            is6: false,
            addr: crate::types::addr::AllAddr::Addr4(Ipv4Addr::new(127, 0, 0, 1)),
            prefix: 32,
        }];
        let opts = DhcpLoopOptions { reply_port_override: Some(receiver_addr.port()), ..Default::default() };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let loop_task = tokio::spawn(run_dhcp_loop(server.clone(), cfg, opts, LeaseDb::new(), shutdown_rx, Box::new(NullProbe)));

        let mut pkt = leasequery_packet(Ipv4Addr::new(10, 0, 0, 150));
        pkt.giaddr = Ipv4Addr::new(203, 0, 113, 9);
        let wire = packet_to_wire(&pkt);
        client.send_to(&wire, server.local_addr().unwrap()).await.unwrap();

        // Confirm no reply arrives: `leasequery_source` was correctly
        // rejected on giaddr, not wrongly accepted on the UDP source.
        let outcome = tokio::time::timeout(Duration::from_millis(200), receiver.recv_from(&mut [0u8; 512])).await;
        assert!(outcome.is_err(), "leasequery with a disallowed giaddr must not get a reply");

        shutdown_tx.send(true).unwrap();
        loop_task.await.unwrap().unwrap();
    }

    /// The non-standard "stand-alone leasequery client" extension: giaddr ==
    /// 255.255.255.255 means "use the UDP source instead" (dhcp.c:255-260).
    /// A client using this extension from an allowed address must still get
    /// a reply.
    #[tokio::test]
    async fn run_dhcp_loop_leasequery_giaddr_broadcast_sentinel_falls_back_to_udp_source() {
        let Some(server) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(client) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(receiver) = bind_udp_or_skip("127.0.0.1:0").await else { return; };

        let receiver_addr = receiver.local_addr().unwrap();
        let server = std::sync::Arc::new(server);
        let mut cfg = default_cfg();
        cfg.leasequery_enabled = true;
        cfg.leasequery_addr = vec![crate::types::dns_records::BogusAddr {
            is6: false,
            addr: crate::types::addr::AllAddr::Addr4(Ipv4Addr::new(127, 0, 0, 1)),
            prefix: 32,
        }];
        let opts = DhcpLoopOptions { reply_port_override: Some(receiver_addr.port()), ..Default::default() };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let loop_task = tokio::spawn(run_dhcp_loop(server.clone(), cfg, opts, LeaseDb::new(), shutdown_rx, Box::new(NullProbe)));

        // ciaddr left UNSPECIFIED: with giaddr also UNSPECIFIED after the
        // sentinel is consumed, `loop_reply_dest` falls back to the packet's
        // real UDP source — this test's `receiver` — rather than routing to
        // whatever address a query happened to name.
        let mut pkt = leasequery_packet(Ipv4Addr::UNSPECIFIED);
        pkt.giaddr = Ipv4Addr::new(255, 255, 255, 255);
        let wire = packet_to_wire(&pkt);
        client.send_to(&wire, server.local_addr().unwrap()).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_millis(250), receiver.recv_from(&mut buf))
            .await
            .expect("stand-alone leasequery client from an allowed source should get a reply")
            .unwrap();
        let reply = parse_dhcp_packet(&buf[..len]).expect("loop reply should parse");
        assert_eq!(get_message_type(&reply.options), Some(DhcpMsgType::LeaseUnknown));

        shutdown_tx.send(true).unwrap();
        loop_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_dhcp_loop_forwards_relayed_request_upstream() {
        let Some(relay_sock) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(client) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(upstream) = bind_udp_or_skip("127.0.0.1:0").await else { return; };

        let relay_addr = Ipv4Addr::new(10, 9, 9, 9);
        let relay_sock = std::sync::Arc::new(relay_sock);

        let mut cfg = default_cfg();
        // Disable the local pool so only the relay path produces traffic.
        cfg.pool_start = Ipv4Addr::new(10, 0, 0, 5);
        cfg.pool_end = Ipv4Addr::new(10, 0, 0, 1);
        cfg.relay4.push(crate::types::dhcp::DhcpRelay {
            local_addr: crate::types::addr::AllAddr::Addr4(relay_addr),
            server_addr: crate::types::addr::AllAddr::Addr4(upstream.local_addr().unwrap().ip().to_string().parse().unwrap()),
            uplink_addr: crate::types::addr::AllAddr::Addr4(Ipv4Addr::UNSPECIFIED),
            interface: None,
            iface_index: 1,
            port: upstream.local_addr().unwrap().port() as i32,
            split_mode: 0,
            warned: 0,
            matchcount: 0,
        });
        let opts = DhcpLoopOptions {
            relay_iface_addr: relay_addr,
            relay_iface_index: 1,
            ..Default::default()
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let loop_task = tokio::spawn(run_dhcp_loop(relay_sock.clone(), cfg, opts, LeaseDb::new(), shutdown_rx, Box::new(NullProbe)));

        let pkt = base_packet();
        let wire = packet_to_wire(&pkt);
        client.send_to(&wire, relay_sock.local_addr().unwrap()).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_millis(250), upstream.recv_from(&mut buf))
            .await
            .expect("timed out waiting for the relay to forward the request upstream")
            .unwrap();
        let forwarded = parse_dhcp_packet(&buf[..len]).expect("forwarded packet should parse");
        assert_eq!(forwarded.op, crate::dhcp_protocol::BOOTREQUEST);
        assert_eq!(forwarded.giaddr, relay_addr);
        assert_eq!(forwarded.hops, 1);
        assert_eq!(get_message_type(&forwarded.options), Some(DhcpMsgType::Discover));

        shutdown_tx.send(true).unwrap();
        loop_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_dhcp_loop_relays_reply_back_to_client() {
        let Some(relay_sock) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(upstream) = bind_udp_or_skip("127.0.0.1:0").await else { return; };
        let Some(client_receiver) = bind_udp_or_skip("127.0.0.1:0").await else { return; };

        let relay_addr = Ipv4Addr::new(10, 9, 9, 9);
        let relay_sock = std::sync::Arc::new(relay_sock);
        let client_addr = client_receiver.local_addr().unwrap();

        let mut cfg = default_cfg();
        cfg.pool_start = Ipv4Addr::new(10, 0, 0, 5);
        cfg.pool_end = Ipv4Addr::new(10, 0, 0, 1);
        cfg.relay4.push(crate::types::dhcp::DhcpRelay {
            local_addr: crate::types::addr::AllAddr::Addr4(relay_addr),
            server_addr: crate::types::addr::AllAddr::Addr4(upstream.local_addr().unwrap().ip().to_string().parse().unwrap()),
            uplink_addr: crate::types::addr::AllAddr::Addr4(Ipv4Addr::UNSPECIFIED),
            interface: None,
            iface_index: 1,
            port: upstream.local_addr().unwrap().port() as i32,
            split_mode: 0,
            warned: 0,
            matchcount: 0,
        });
        let opts = DhcpLoopOptions {
            relay_iface_addr: relay_addr,
            relay_iface_index: 1,
            reply_port_override: Some(client_addr.port()),
            ..Default::default()
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let loop_task = tokio::spawn(run_dhcp_loop(relay_sock.clone(), cfg, opts, LeaseDb::new(), shutdown_rx, Box::new(NullProbe)));

        // The upstream server's OFFER, addressed back to the relay (giaddr set,
        // ciaddr pointed at our test "client" receiver so delivery doesn't need
        // UDP broadcast permissions).
        let mut reply = base_packet();
        reply.op = BOOTREPLY;
        reply.giaddr = relay_addr;
        reply.ciaddr = client_addr.ip().to_string().parse().unwrap();
        reply.yiaddr = Ipv4Addr::new(10, 0, 0, 50);
        reply.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Offer as u8, OPTION_END];
        let wire = packet_to_wire(&reply);
        upstream.send_to(&wire, relay_sock.local_addr().unwrap()).await.unwrap();

        let mut buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(Duration::from_millis(250), client_receiver.recv_from(&mut buf))
            .await
            .expect("timed out waiting for the relay to forward the reply to the client")
            .unwrap();
        let delivered = parse_dhcp_packet(&buf[..len]).expect("delivered reply should parse");
        assert_eq!(delivered.yiaddr, Ipv4Addr::new(10, 0, 0, 50));
        assert_eq!(get_message_type(&delivered.options), Some(DhcpMsgType::Offer));

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
            ..Default::default()
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let loop_task = tokio::spawn(run_dhcp_loop(server.clone(), cfg, opts, LeaseDb::new(), shutdown_rx, Box::new(NullProbe)));

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

    // ── link_contexts_for_interface ──────────────────────────────────────────

    #[test]
    fn link_contexts_for_interface_links_same_subnet_context() {
        // make_ctx defaults netmask to 255.255.255.0.
        let mut contexts = [make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            Ipv4Addr::UNSPECIFIED,
            0,
        )];
        let iface = ArrivalInterface {
            local: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(10, 0, 0, 255),
            if_index: 1,
        };
        let linked = link_contexts_for_interface(&mut contexts, &iface);
        assert_eq!(linked, vec![0]);
        assert_eq!(contexts[0].router, iface.local);
        assert_eq!(contexts[0].local, iface.local);
        assert_eq!(contexts[0].broadcast, iface.broadcast);
    }

    #[test]
    fn link_contexts_for_interface_skips_different_subnet() {
        let mut contexts = [make_ctx(
            "192.168.1.100".parse().unwrap(),
            "192.168.1.200".parse().unwrap(),
            Ipv4Addr::UNSPECIFIED,
            0,
        )];
        let iface = ArrivalInterface {
            local: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(10, 0, 0, 255),
            if_index: 1,
        };
        let linked = link_contexts_for_interface(&mut contexts, &iface);
        assert!(linked.is_empty());
        // Untouched — this context was never on the arriving interface's subnet.
        assert_eq!(contexts[0].router, Ipv4Addr::UNSPECIFIED);
    }

    #[test]
    fn link_contexts_for_interface_fills_in_missing_netmask() {
        let mut ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            Ipv4Addr::UNSPECIFIED,
            0, // no CONTEXT_NETMASK — netmask below is a placeholder to fill in
        );
        ctx.netmask = Ipv4Addr::UNSPECIFIED;
        let mut contexts = [ctx];
        let iface = ArrivalInterface {
            local: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(10, 0, 0, 255),
            if_index: 1,
        };
        let linked = link_contexts_for_interface(&mut contexts, &iface);
        assert_eq!(contexts[0].netmask, iface.netmask);
        assert_eq!(linked, vec![0]);
    }

    #[test]
    fn link_contexts_for_interface_respects_explicit_netmask_flag() {
        // An explicit /16 that still covers the arriving interface's address
        // must not be clobbered by guess_range_netmask's /24 guess.
        let mut ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            Ipv4Addr::UNSPECIFIED,
            CONTEXT_NETMASK,
        );
        ctx.netmask = Ipv4Addr::new(255, 255, 0, 0);
        let mut contexts = [ctx];
        let iface = ArrivalInterface {
            local: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(10, 0, 0, 255),
            if_index: 1,
        };
        link_contexts_for_interface(&mut contexts, &iface);
        assert_eq!(contexts[0].netmask, Ipv4Addr::new(255, 255, 0, 0));
    }

    #[test]
    fn link_contexts_for_interface_respects_explicit_broadcast_flag() {
        let mut ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.200".parse().unwrap(),
            Ipv4Addr::UNSPECIFIED,
            CONTEXT_BRDCAST,
        );
        ctx.broadcast = Ipv4Addr::new(10, 0, 0, 254); // deliberately non-standard
        let mut contexts = [ctx];
        let iface = ArrivalInterface {
            local: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(10, 0, 0, 255),
            if_index: 1,
        };
        link_contexts_for_interface(&mut contexts, &iface);
        assert_eq!(contexts[0].broadcast, Ipv4Addr::new(10, 0, 0, 254));
    }

    // ── arrival_interface ────────────────────────────────────────────────────

    #[test]
    fn arrival_interface_zero_index_is_none() {
        assert!(arrival_interface(0).is_none());
    }

    #[test]
    fn arrival_interface_unknown_index_is_none() {
        // No real interface has this index outside of pathological setups.
        assert!(arrival_interface(u32::MAX).is_none());
    }

    #[test]
    fn arrival_interface_resolves_a_real_interface() {
        // Environment-dependent: skip if `lo` can't be resolved by index
        // (sandboxes without loopback enumeration support) rather than
        // asserting a specific outcome.
        let idx = crate::network::nametoindex("lo");
        if idx == 0 {
            eprintln!("skipping: could not resolve 'lo' interface index");
            return;
        }
        let Some(iface) = arrival_interface(idx) else {
            eprintln!("skipping: 'lo' has no IPv4 address/netmask in this sandbox");
            return;
        };
        assert_eq!(iface.local, Ipv4Addr::LOCALHOST);
        assert_eq!(iface.broadcast, Ipv4Addr::from(u32::from(iface.local) | !u32::from(iface.netmask)));
    }

    // ── dispatch_dhcp_with_arrival ───────────────────────────────────────────

    /// Two `dhcp-range`s on unrelated subnets, as if configured for two
    /// different interfaces on the same box.
    fn two_subnet_cfg() -> DhcpServerConfig {
        let subnet_a = make_ctx(
            Ipv4Addr::new(10, 0, 0, 100),
            Ipv4Addr::new(10, 0, 0, 200),
            Ipv4Addr::UNSPECIFIED,
            0,
        );
        let subnet_b = make_ctx(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(192, 168, 1, 200),
            Ipv4Addr::UNSPECIFIED,
            0,
        );
        DhcpServerConfig {
            contexts: vec![subnet_a, subnet_b],
            ..default_cfg()
        }
    }

    #[test]
    fn dispatch_with_arrival_restricts_offer_to_arriving_subnet() {
        let cfg0 = two_subnet_cfg();
        let mut cfg = cfg0.clone();
        let pkt = base_packet();

        // Arrives on the 192.168.1.0/24 interface: only that subnet's
        // dhcp-range may be used, even though it's second in cfg.contexts
        // and address_allocate would otherwise offer from the first
        // (10.0.0.0/24) context.
        let iface = ArrivalInterface {
            local: Ipv4Addr::new(192, 168, 1, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(192, 168, 1, 255),
            if_index: 1,
        };
        let dispatched = dispatch_dhcp_with_arrival(
            &pkt, &mut cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe, Some(&iface),
        )
        .expect("discover should produce an offer");

        assert!(is_same_net(dispatched.reply.yiaddr, Ipv4Addr::new(192, 168, 1, 0), Ipv4Addr::new(255, 255, 255, 0)));
    }

    #[test]
    fn dispatch_with_arrival_none_falls_back_to_full_context_search() {
        // No arrival interface known (e.g. IP_PKTINFO unavailable): behaves
        // exactly like dispatch_dhcp_with_meta over the whole context list.
        let mut cfg = two_subnet_cfg();
        let mut cfg_baseline = two_subnet_cfg();
        let pkt = base_packet();

        let via_arrival = dispatch_dhcp_with_arrival(
            &pkt, &mut cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe, None,
        )
        .expect("discover should produce an offer");
        let via_meta = dispatch_dhcp_with_meta(
            &pkt, &mut cfg_baseline, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe,
        )
        .expect("discover should produce an offer");

        assert_eq!(via_arrival.reply.yiaddr, via_meta.reply.yiaddr);
    }

    #[test]
    fn dispatch_with_arrival_unmatched_interface_falls_back_to_full_search() {
        // Arrival interface shares no subnet with any configured dhcp-range
        // (e.g. a relayed request from elsewhere): link_contexts_for_interface
        // links nothing, so dispatch must still answer from the full list
        // rather than silently dropping the request.
        let mut cfg = two_subnet_cfg();
        let pkt = base_packet();
        let iface = ArrivalInterface {
            local: Ipv4Addr::new(172, 16, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(172, 16, 0, 255),
            if_index: 1,
        };
        let dispatched = dispatch_dhcp_with_arrival(
            &pkt, &mut cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe, Some(&iface),
        );
        assert!(dispatched.is_some());
    }

    #[test]
    fn dispatch_with_arrival_fills_router_from_interface() {
        // The linked context's router/netmask (unset in two_subnet_cfg) is
        // filled in from the arrival interface, then surfaces in the offer's
        // OPTION_ROUTER (3) reply option — proof link_contexts_for_interface's
        // mutation actually reaches the wire, not just cfg.contexts in place.
        let mut cfg = two_subnet_cfg();
        let pkt = base_packet();
        let iface = ArrivalInterface {
            local: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(10, 0, 0, 255),
            if_index: 1,
        };
        let dispatched = dispatch_dhcp_with_arrival(
            &pkt, &mut cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe, Some(&iface),
        )
        .expect("discover should produce an offer");

        let router_opt = find_option(&dispatched.reply.options, 3).expect("router option present");
        assert_eq!(router_opt, &iface.local.octets());
        // The mutation also persists on cfg.contexts itself (matching
        // upstream's complete_context, which is not undone after the call).
        assert_eq!(cfg.contexts[0].router, iface.local);
    }

    #[test]
    fn dispatch_with_arrival_sets_last_interface_on_committed_lease() {
        // Port of lease_set_interface() (lease.c:1148-1159), called from
        // rfc2131.c:1717 right after a REQUEST is ACK'd. Without this,
        // lease.last_interface stays 0 forever, and slaac_add_addrs's
        // `lease->last_interface == 0` guard (slaac.c:33) means no DHCPv4
        // lease could ever grow a SLAAC address, regardless of what RA-name
        // contexts are configured.
        let mut cfg = default_cfg();
        let mut lease_db = LeaseDb::new();
        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Request as u8,
            crate::dhcp_protocol::OPTION_REQUESTED_IP, 4, 10, 0, 0, 123,
            OPTION_END,
        ];
        let iface = ArrivalInterface {
            local: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(10, 0, 0, 255),
            if_index: 7,
        };

        let dispatched = dispatch_dhcp_with_arrival(
            &pkt, &mut cfg, &mut lease_db, &mut PingCache::new(), &NullProbe, Some(&iface),
        )
        .expect("request should produce an ack");
        assert_eq!(dispatched.reply.msg_type, DhcpMsgType::Ack);

        let lease = lease_db.find_by_addr(Ipv4Addr::new(10, 0, 0, 123)).expect("lease committed");
        assert_eq!(lease.last_interface, 7);
    }

    #[test]
    fn dispatch_with_arrival_leaves_last_interface_unset_without_arrival() {
        // No IP_PKTINFO arrival metadata (arrival == None): there is no
        // interface index to record, so last_interface must stay 0 rather
        // than being set to some stale/default value.
        let mut cfg = default_cfg();
        let mut lease_db = LeaseDb::new();
        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Request as u8,
            crate::dhcp_protocol::OPTION_REQUESTED_IP, 4, 10, 0, 0, 123,
            OPTION_END,
        ];

        dispatch_dhcp_with_arrival(&pkt, &mut cfg, &mut lease_db, &mut PingCache::new(), &NullProbe, None)
            .expect("request should produce an ack");

        let lease = lease_db.find_by_addr(Ipv4Addr::new(10, 0, 0, 123)).expect("lease committed");
        assert_eq!(lease.last_interface, 0);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn dispatch_then_refresh_slaac_populates_address_for_real_v4_lease() {
        // The exact sequence run_dhcp_loop performs after every packet:
        // dispatch_dhcp_with_arrival (commits the lease: hwaddr, hostname,
        // and now last_interface) then LeaseDb::refresh_slaac across the
        // whole db. This is the T3-slaac production-wiring gap: a real
        // DHCPv4-committed lease is never LEASE_NA/LEASE_TA-flagged (only
        // DHCPv6 stateful leases are), so slaac_add_addrs's guards can
        // actually pass for it — unlike leases in the DHCPv6 loop's own
        // LeaseDb, which are always LEASE_NA-flagged and so never qualify.
        use crate::types::dhcp::{DhcpContext, DhcpNetid, CONTEXT_RA_NAME};
        use std::net::Ipv6Addr;

        let mut cfg = default_cfg();
        let mut lease_db = LeaseDb::new();
        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Request as u8,
            crate::dhcp_protocol::OPTION_REQUESTED_IP, 4, 10, 0, 0, 123,
            OPTION_HOSTNAME, 4, b'h', b'o', b's', b't',
            OPTION_END,
        ];
        let iface = ArrivalInterface {
            local: Ipv4Addr::new(10, 0, 0, 1),
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            broadcast: Ipv4Addr::new(10, 0, 0, 255),
            if_index: 7,
        };

        dispatch_dhcp_with_arrival(
            &pkt, &mut cfg, &mut lease_db, &mut PingCache::new(), &NullProbe, Some(&iface),
        )
        .expect("request should produce an ack");

        let ra_ctx = DhcpContext {
            lease_time: 0,
            addr_epoch: 0,
            netmask: Ipv4Addr::UNSPECIFIED,
            broadcast: Ipv4Addr::UNSPECIFIED,
            local: Ipv4Addr::UNSPECIFIED,
            router: Ipv4Addr::UNSPECIFIED,
            start: Ipv4Addr::UNSPECIFIED,
            end: Ipv4Addr::UNSPECIFIED,
            flags: CONTEXT_RA_NAME,
            netid: DhcpNetid { net: String::new() },
            filter: vec![],
            start6: "2001:db8::".parse().unwrap(),
            end6: Ipv6Addr::UNSPECIFIED,
            local6: Ipv6Addr::UNSPECIFIED,
            prefix: 64,
            if_index: 7,
            valid: 0,
            preferred: 0,
        };
        lease_db.refresh_slaac(std::time::SystemTime::now(), &[ra_ctx], false, |_ctx| {});

        let lease = lease_db.find_by_addr(Ipv4Addr::new(10, 0, 0, 123)).expect("lease committed");
        assert_eq!(lease.slaac_address.len(), 1, "SLAAC address should be derived and tracked for this lease");
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

    // ── address_allocate / PingCache / AddressProbe ──────────────────────────

    struct ConflictProbe(std::collections::HashSet<Ipv4Addr>);

    impl AddressProbe for ConflictProbe {
        fn in_use(&self, addr: Ipv4Addr) -> bool {
            self.0.contains(&addr)
        }
    }

    struct CountingProbe {
        calls: std::cell::Cell<u32>,
        in_use: bool,
    }

    impl AddressProbe for CountingProbe {
        fn in_use(&self, _addr: Ipv4Addr) -> bool {
            self.calls.set(self.calls.get() + 1);
            self.in_use
        }
    }

    #[test]
    fn address_allocate_skips_address_that_answers_ping() {
        // All-zero hwaddr hashes to 1 (see sdbm_hash_never_zero), and a
        // 3-address range [100,102] seeds at start + (1 % 3) = .101.
        let ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.102".parse().unwrap(),
            Ipv4Addr::UNSPECIFIED,
            0,
        );
        let lease_db = LeaseDb::new();
        let mut ping_cache = PingCache::new();
        let mut in_use = std::collections::HashSet::new();
        in_use.insert(Ipv4Addr::new(10, 0, 0, 101));
        let probe = ConflictProbe(in_use);

        let addr = address_allocate(
            &[ctx], &lease_db, &[], &[0u8; 6], &[], std::time::SystemTime::now(),
            false, false, false, &mut ping_cache, &probe,
        );
        assert_eq!(addr, Some(Ipv4Addr::new(10, 0, 0, 102)));
    }

    #[test]
    fn address_allocate_returns_none_when_range_fully_in_use() {
        let ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.101".parse().unwrap(),
            Ipv4Addr::UNSPECIFIED,
            0,
        );
        let lease_db = LeaseDb::new();
        let mut ping_cache = PingCache::new();
        let mut in_use = std::collections::HashSet::new();
        in_use.insert(Ipv4Addr::new(10, 0, 0, 100));
        in_use.insert(Ipv4Addr::new(10, 0, 0, 101));
        let probe = ConflictProbe(in_use);

        let addr = address_allocate(
            &[ctx], &lease_db, &[], &[0u8; 6], &[], std::time::SystemTime::now(),
            false, false, false, &mut ping_cache, &probe,
        );
        assert_eq!(addr, None);
    }

    #[test]
    fn address_allocate_skips_leased_and_statically_reserved_addresses() {
        let ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.102".parse().unwrap(),
            Ipv4Addr::UNSPECIFIED,
            0,
        );
        let mut lease_db = LeaseDb::new();
        lease_db.allocate_v4(Ipv4Addr::new(10, 0, 0, 101));
        let reserved = DhcpConfig {
            flags: CONFIG_ADDR,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![],
            addr: Ipv4Addr::new(10, 0, 0, 102),
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };
        let mut ping_cache = PingCache::new();

        // seed .101 is leased, .102 is a static reservation, so the scan
        // wraps around to .100.
        let addr = address_allocate(
            &[ctx], &lease_db, &[reserved], &[0u8; 6], &[], std::time::SystemTime::now(),
            false, false, false, &mut ping_cache, &NullProbe,
        );
        assert_eq!(addr, Some(Ipv4Addr::new(10, 0, 0, 100)));
    }

    #[test]
    fn address_allocate_skips_router_address() {
        let ctx = make_ctx(
            "10.0.0.100".parse().unwrap(),
            "10.0.0.101".parse().unwrap(),
            Ipv4Addr::new(10, 0, 0, 101),
            0,
        );
        let lease_db = LeaseDb::new();
        let mut ping_cache = PingCache::new();

        let addr = address_allocate(
            &[ctx], &lease_db, &[], &[0u8; 6], &[], std::time::SystemTime::now(),
            false, false, false, &mut ping_cache, &NullProbe,
        );
        assert_eq!(addr, Some(Ipv4Addr::new(10, 0, 0, 100)));
    }

    #[test]
    fn ping_cache_remembers_free_address_without_reprobing() {
        let mut cache = PingCache::new();
        let probe = CountingProbe { calls: std::cell::Cell::new(0), in_use: false };
        let now = std::time::SystemTime::now();
        let addr = Ipv4Addr::new(10, 0, 0, 5);

        assert_eq!(cache.check(now, addr, 42, false, false, &probe), Some(42));
        assert_eq!(probe.calls.get(), 1);
        assert_eq!(cache.check(now, addr, 42, false, false, &probe), Some(42));
        assert_eq!(probe.calls.get(), 1, "second check should hit the cache, not re-ping");
    }

    #[test]
    fn ping_cache_returns_none_when_probe_reports_in_use() {
        let mut cache = PingCache::new();
        let probe = CountingProbe { calls: std::cell::Cell::new(0), in_use: true };
        let now = std::time::SystemTime::now();

        assert_eq!(cache.check(now, Ipv4Addr::new(10, 0, 0, 6), 1, false, false, &probe), None);
    }

    #[test]
    fn ping_cache_no_ping_flag_skips_probe_entirely() {
        let mut cache = PingCache::new();
        let probe = CountingProbe { calls: std::cell::Cell::new(0), in_use: true };
        let now = std::time::SystemTime::now();

        assert_eq!(cache.check(now, Ipv4Addr::new(10, 0, 0, 7), 9, true, false, &probe), Some(9));
        assert_eq!(probe.calls.get(), 0);
    }

    #[test]
    fn ping_cache_loopback_skips_probe_entirely() {
        let mut cache = PingCache::new();
        let probe = CountingProbe { calls: std::cell::Cell::new(0), in_use: true };
        let now = std::time::SystemTime::now();

        assert_eq!(cache.check(now, Ipv4Addr::new(127, 0, 0, 1), 9, false, true, &probe), Some(9));
        assert_eq!(probe.calls.get(), 0);
    }

    // ── ICMP echo packet build/parse ─────────────────────────────────────────

    #[test]
    fn build_icmp_echo_request_checksums_to_zero() {
        let pkt = build_icmp_echo_request(0x1234);
        assert_eq!(icmp_checksum(&pkt), 0);
        assert_eq!(pkt[0], 8); // ICMP_ECHO
        assert_eq!(pkt[1], 0); // code
        assert_eq!(&pkt[6..8], &[0, 0]); // seq always 0, matching icmp_ping()
    }

    fn synthetic_icmp_reply(id: u16, icmp_type: u8, seq: u16) -> Vec<u8> {
        let mut data = vec![0x45u8]; // IPv4, IHL=5 (20-byte header)
        data.extend([0u8; 19]); // rest of the minimal IP header
        data.push(icmp_type);
        data.push(0); // code
        data.extend([0u8, 0]); // checksum (unchecked by the parser)
        data.extend(id.to_be_bytes());
        data.extend(seq.to_be_bytes());
        data
    }

    #[test]
    fn parse_icmp_echo_reply_accepts_matching_reply() {
        let data = synthetic_icmp_reply(0x1234, 0, 0);
        assert!(parse_icmp_echo_reply(&data, 0x1234));
    }

    #[test]
    fn parse_icmp_echo_reply_rejects_wrong_id() {
        let data = synthetic_icmp_reply(0x1234, 0, 0);
        assert!(!parse_icmp_echo_reply(&data, 0x9999));
    }

    #[test]
    fn parse_icmp_echo_reply_rejects_non_reply_type() {
        let data = synthetic_icmp_reply(0x1234, 8, 0); // ICMP_ECHO (request), not a reply
        assert!(!parse_icmp_echo_reply(&data, 0x1234));
    }

    #[test]
    fn parse_icmp_echo_reply_rejects_nonzero_seq() {
        let data = synthetic_icmp_reply(0x1234, 0, 1);
        assert!(!parse_icmp_echo_reply(&data, 0x1234));
    }

    #[test]
    fn parse_icmp_echo_reply_rejects_truncated_data() {
        assert!(!parse_icmp_echo_reply(&[0x45], 0x1234));
        assert!(!parse_icmp_echo_reply(&[], 0x1234));
    }

    // ── dispatch_dhcp_with_meta: in-use address is skipped ───────────────────

    #[test]
    fn dispatch_discover_skips_address_that_answers_icmp_ping() {
        let pkt = base_packet();
        let cfg = default_cfg(); // pool 10.0.0.100-10.0.0.200, all-zero chaddr seeds .101
        let mut lease_db = LeaseDb::new();
        let mut ping_cache = PingCache::new();
        let mut in_use = std::collections::HashSet::new();
        in_use.insert(Ipv4Addr::new(10, 0, 0, 101));
        let probe = ConflictProbe(in_use);

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db, &mut ping_cache, &probe)
            .expect("discover should still offer the next free address");
        assert_ne!(dispatched.reply.yiaddr, Ipv4Addr::new(10, 0, 0, 101));
        assert_eq!(dispatched.reply.yiaddr, Ipv4Addr::new(10, 0, 0, 102));
    }

    // ── --read-ethers ─────────────────────────────────────────────────────────

    #[test]
    fn parse_ethers_text_reads_address_and_name_lines() {
        let text = "aa:bb:cc:dd:ee:ff 10.0.0.5\n00:11:22:33:44:55 myhost\n";
        let records = parse_ethers_text(text);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].hwaddr, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(records[0].key, EthersKey::Addr(Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(records[1].hwaddr, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(records[1].key, EthersKey::Name("myhost".into()));
    }

    #[test]
    fn parse_ethers_text_skips_comments_blank_and_plus_lines() {
        let text = "# a comment\n\n+netgroup\naa:bb:cc:dd:ee:ff 10.0.0.5\n";
        let records = parse_ethers_text(text);
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn parse_ethers_text_skips_bad_hwaddr() {
        let records = parse_ethers_text("not-a-mac 10.0.0.5\n");
        assert!(records.is_empty());
    }

    #[test]
    fn parse_ethers_text_skips_line_with_no_second_field() {
        let records = parse_ethers_text("aa:bb:cc:dd:ee:ff\n");
        assert!(records.is_empty());
    }

    #[test]
    fn parse_ethers_text_skips_illegal_hostname() {
        // A leading "-" is not a legal hostname start character.
        let records = parse_ethers_text("aa:bb:cc:dd:ee:ff -bad\n");
        assert!(records.is_empty());
    }

    #[test]
    fn apply_ethers_records_creates_new_config_from_address_line() {
        let mut dhcp_conf = Vec::new();
        let records = parse_ethers_text("aa:bb:cc:dd:ee:ff 10.0.0.5\n");
        let count = apply_ethers_records(&mut dhcp_conf, records);
        assert_eq!(count, 1);
        assert_eq!(dhcp_conf.len(), 1);
        let cfg = &dhcp_conf[0];
        assert_ne!(cfg.flags & CONFIG_FROM_ETHERS, 0);
        assert_ne!(cfg.flags & crate::types::dhcp::CONFIG_ADDR, 0);
        assert_ne!(cfg.flags & CONFIG_NOCLID, 0);
        assert_eq!(cfg.addr, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(cfg.hwaddrs.len(), 1);
        assert_eq!(&cfg.hwaddrs[0].hwaddr[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        assert_eq!(cfg.hwaddrs[0].hwaddr_len, 6);
    }

    #[test]
    fn apply_ethers_records_creates_new_config_from_name_line() {
        let mut dhcp_conf = Vec::new();
        let records = parse_ethers_text("aa:bb:cc:dd:ee:ff myhost\n");
        apply_ethers_records(&mut dhcp_conf, records);
        assert_eq!(dhcp_conf.len(), 1);
        assert_eq!(dhcp_conf[0].hostname.as_deref(), Some("myhost"));
        assert_ne!(dhcp_conf[0].flags & CONFIG_NAME, 0);
    }

    fn empty_static_config() -> DhcpConfig {
        DhcpConfig {
            flags: 0,
            clid: None,
            hostname: None,
            domain: None,
            netid: vec![],
            filter: vec![],
            addr: Ipv4Addr::UNSPECIFIED,
            decline_time: None,
            lease_time: 0,
            hwaddrs: vec![],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        }
    }

    #[test]
    fn apply_ethers_records_merges_into_existing_dhcp_host_by_address() {
        let mut dhcp_conf = vec![DhcpConfig {
            flags: crate::types::dhcp::CONFIG_ADDR,
            addr: Ipv4Addr::new(10, 0, 0, 5),
            ..empty_static_config()
        }];
        let records = parse_ethers_text("aa:bb:cc:dd:ee:ff 10.0.0.5\n");
        let count = apply_ethers_records(&mut dhcp_conf, records);
        assert_eq!(count, 1);
        // Merged into the existing entry, not appended as a second one.
        assert_eq!(dhcp_conf.len(), 1);
        assert_eq!(dhcp_conf[0].flags & CONFIG_FROM_ETHERS, 0, "reused entry keeps its non-ethers origin");
        assert_eq!(dhcp_conf[0].hwaddrs.len(), 1);
    }

    #[test]
    fn apply_ethers_records_attaches_to_hwaddr_only_dhcp_host() {
        let mac = {
            let mut m = [0u8; DHCP_CHADDR_MAX];
            m[..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
            m
        };
        let mut dhcp_conf = vec![DhcpConfig {
            flags: 0, // no addr/name yet — just a bare hwaddr reservation
            hwaddrs: vec![HwaddrConfig { hwaddr: mac, hwaddr_len: 6, hwaddr_type: 1, wildcard_mask: 0 }],
            ..empty_static_config()
        }];
        let records = parse_ethers_text("aa:bb:cc:dd:ee:ff 10.0.0.5\n");
        apply_ethers_records(&mut dhcp_conf, records);
        assert_eq!(dhcp_conf.len(), 1, "should attach to the existing hwaddr entry, not create a new one");
        assert_eq!(dhcp_conf[0].addr, Ipv4Addr::new(10, 0, 0, 5));
    }

    #[test]
    fn apply_ethers_records_purges_stale_entries_on_rerun() {
        let mut dhcp_conf = Vec::new();
        apply_ethers_records(&mut dhcp_conf, parse_ethers_text("aa:bb:cc:dd:ee:ff 10.0.0.5\n"));
        assert_eq!(dhcp_conf.len(), 1);

        // Simulate a SIGHUP re-read with a file that no longer mentions
        // 10.0.0.5 — the stale entry must be gone, not accumulate.
        apply_ethers_records(&mut dhcp_conf, parse_ethers_text("00:11:22:33:44:55 10.0.0.6\n"));
        assert_eq!(dhcp_conf.len(), 1);
        assert_eq!(dhcp_conf[0].addr, Ipv4Addr::new(10, 0, 0, 6));
    }

    #[test]
    fn apply_ethers_records_drops_duplicate_address_within_same_file() {
        let mut dhcp_conf = Vec::new();
        let records = parse_ethers_text(
            "aa:bb:cc:dd:ee:ff 10.0.0.5\n00:11:22:33:44:55 10.0.0.5\n",
        );
        let count = apply_ethers_records(&mut dhcp_conf, records);
        assert_eq!(count, 1, "the second line duplicates the first line's address");
        assert_eq!(dhcp_conf.len(), 1);
        assert_eq!(&dhcp_conf[0].hwaddrs[0].hwaddr[..6], &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn dhcp_read_ethers_populates_static_host_config_from_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ethers");
        std::fs::write(&path, "aa:bb:cc:dd:ee:ff 10.0.0.5\n00:11:22:33:44:55 myhost\n").unwrap();

        let mut dhcp_conf = Vec::new();
        let count = dhcp_read_ethers(&mut dhcp_conf, path.to_str().unwrap()).expect("file should be read");
        assert_eq!(count, 2);
        assert!(dhcp_conf.iter().any(|c| c.flags & CONFIG_FROM_ETHERS != 0
            && c.flags & crate::types::dhcp::CONFIG_ADDR != 0
            && c.addr == Ipv4Addr::new(10, 0, 0, 5)));
        assert!(dhcp_conf.iter().any(|c| c.flags & CONFIG_FROM_ETHERS != 0
            && c.hostname.as_deref() == Some("myhost")));
    }

    #[test]
    fn dhcp_read_ethers_missing_file_returns_error() {
        let mut dhcp_conf = Vec::new();
        assert!(dhcp_read_ethers(&mut dhcp_conf, "/nonexistent/path/to/ethers").is_err());
    }

    // ── BOOTP (mess_type == 0, rfc2131.c:564-698) ──────────────────────────

    fn bootp_packet() -> DhcpPacket {
        let mut pkt = base_packet();
        pkt.options = vec![OPTION_END]; // no option 53 at all
        pkt
    }

    #[test]
    fn unrecognized_message_type_value_is_dropped_not_answered_as_bootp() {
        // rfc2131.c:564 only takes the BOOTP branch when `mess_type == 0`,
        // i.e. option 53 is genuinely absent. A present-but-garbage option
        // 53 byte falls through C's `switch` with no matching `case` and
        // gets no reply at all — it must not be treated as BOOTP, even when
        // a nailed dhcp-host would otherwise make BOOTP dispatch succeed.
        use crate::types::dhcp::{DhcpConfig, HwaddrConfig, CONFIG_ADDR};

        let mut pkt = bootp_packet(); // htype/hlen/chaddr are valid
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, 99, OPTION_END];
        let nailed_cfg = DhcpConfig {
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
                hwaddr: pkt.chaddr,
                hwaddr_len: 6,
                hwaddr_type: 1,
                wildcard_mask: 0,
            }],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };
        let mut cfg = default_cfg();
        cfg.configs.push(nailed_cfg);
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn bootp_request_without_mac_is_dropped() {
        let mut pkt = bootp_packet();
        pkt.htype = 0;
        pkt.hlen = 0;
        let cfg = default_cfg();
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn bootp_request_without_nailed_host_or_bootp_dynamic_is_dropped() {
        // No dhcp-host reservation and no --bootp-dynamic gate: upstream
        // returns "no address configured" (rfc2131.c:665-668).
        let pkt = bootp_packet();
        let cfg = default_cfg();
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn bootp_request_with_nailed_host_gets_reply_with_no_message_type() {
        use crate::types::dhcp::{DhcpConfig, HwaddrConfig, CONFIG_ADDR};

        let pkt = bootp_packet(); // base_packet()'s chaddr is all-zero, hlen 6
        let nailed_cfg = DhcpConfig {
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
                hwaddr: pkt.chaddr,
                hwaddr_len: 6,
                hwaddr_type: 1,
                wildcard_mask: 0,
            }],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };
        let mut cfg = default_cfg();
        cfg.configs.push(nailed_cfg);

        let mut lease_db = LeaseDb::new();
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db, &mut PingCache::new(), &NullProbe)
            .expect("BOOTP client with a nailed dhcp-host should get a reply");

        assert_eq!(dispatched.reply.msg_type, DhcpMsgType::Bootp);
        assert_eq!(dispatched.reply.yiaddr, Ipv4Addr::new(10, 0, 0, 150));
        assert!(
            find_option(&dispatched.reply.options, OPTION_MESSAGE_TYPE).is_none(),
            "a BOOTP reply must not carry OPTION_MESSAGE_TYPE"
        );
        assert!(dispatched.delay_secs == 0);

        // An effectively infinite lease should have been recorded.
        let lease = lease_db.find_by_addr(Ipv4Addr::new(10, 0, 0, 150)).expect("lease recorded");
        assert!(lease.expires.is_none(), "un-timed dhcp-host BOOTP lease should be infinite");
    }

    #[test]
    fn bootp_reply_has_no_t1_t2_options() {
        // rfc2131.c:684-685 fixes the lease time passed to do_options() at
        // 0xffffffff for BOOTP unless dhcp-host sets an explicit CONFIG_TIME
        // — do_options() only ever emits T1/T2 when the lease time isn't
        // that "infinite" sentinel (rfc2131.c:2745-2746), so a BOOTP reply
        // must never carry them.
        use crate::types::dhcp::{DhcpConfig, HwaddrConfig, CONFIG_ADDR};

        let pkt = bootp_packet();
        let nailed_cfg = DhcpConfig {
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
                hwaddr: pkt.chaddr,
                hwaddr_len: 6,
                hwaddr_type: 1,
                wildcard_mask: 0,
            }],
            #[cfg(feature = "dhcp6")]
            addr6: vec![],
        };
        let mut cfg = default_cfg();
        cfg.configs.push(nailed_cfg);

        let mut lease_db = LeaseDb::new();
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db, &mut PingCache::new(), &NullProbe)
            .expect("BOOTP client with a nailed dhcp-host should get a reply");

        assert!(
            find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_T1).is_none(),
            "a BOOTP reply must not carry OPTION_T1"
        );
        assert!(
            find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_T2).is_none(),
            "a BOOTP reply must not carry OPTION_T2"
        );
    }

    #[test]
    fn bootp_request_gated_by_bootp_dynamic_tag() {
        let pkt = bootp_packet();
        let mut cfg = default_cfg();
        cfg.contexts = vec![make_ctx(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200), Ipv4Addr::UNSPECIFIED, 0)];

        // Without a --bootp-dynamic rule, dynamic BOOTP allocation is refused.
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());

        // A bare `bootp-dynamic` (no tags) opts every client in.
        cfg.bootp_dynamic = vec![vec![]];
        let reply = dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).expect("bootp-dynamic should allow allocation");
        assert_eq!(reply.msg_type, DhcpMsgType::Bootp);
        assert!(is_same_net(reply.yiaddr, Ipv4Addr::new(10, 0, 0, 0), Ipv4Addr::new(255, 255, 255, 0)));
    }

    /// Upstream's `bootp_dynamic` gate applies to *any* non-nailed
    /// resolution (rfc2131.c:659-666) — reusing an already-leased address,
    /// not just a fresh allocation. If an admin narrows/removes a
    /// `bootp-dynamic` rule, an existing non-nailed BOOTP lease must stop
    /// renewing on its very next request, not silently keep renewing until
    /// it expires.
    #[test]
    fn bootp_dynamic_gate_also_applies_when_reusing_an_existing_lease() {
        let pkt = bootp_packet();
        let mut cfg = default_cfg();
        cfg.contexts = vec![make_ctx(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200), Ipv4Addr::UNSPECIFIED, 0)];
        cfg.bootp_dynamic = vec![vec![]]; // matches everyone: allocation is allowed
        let mut lease_db = LeaseDb::new();

        let first = dispatch_dhcp(&pkt, &cfg, &mut lease_db).expect("first request should allocate");
        assert_eq!(first.msg_type, DhcpMsgType::Bootp);

        // Narrow the rule so this client no longer matches. A second request
        // from the same client would take the "reuse existing lease" branch,
        // which must be gated exactly like fresh allocation.
        cfg.bootp_dynamic = vec![vec![crate::types::dhcp::DhcpNetid { net: "not-this-client".to_string() }]];
        assert!(
            dispatch_dhcp(&pkt, &cfg, &mut lease_db).is_none(),
            "reusing an existing non-nailed lease must still be gated by bootp-dynamic"
        );
    }

    // ── DHCPLEASEQUERY (RFC 4388, rfc2131.c:1067-1235) ─────────────────────

    fn leasequery_packet(ciaddr: Ipv4Addr) -> DhcpPacket {
        let mut pkt = base_packet();
        pkt.ciaddr = ciaddr;
        pkt.options = vec![OPTION_MESSAGE_TYPE, 1, DhcpMsgType::LeaseQuery as u8, OPTION_END];
        pkt
    }

    fn leasequery_packet_with_req_options(ciaddr: Ipv4Addr, req: &[u8]) -> DhcpPacket {
        let mut pkt = base_packet();
        pkt.ciaddr = ciaddr;
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::LeaseQuery as u8,
            OPTION_REQUESTED_OPTIONS, req.len() as u8,
        ];
        pkt.options.extend_from_slice(req);
        pkt.options.push(OPTION_END);
        pkt
    }

    #[test]
    fn leasequery_returns_none_when_not_enabled() {
        let pkt = leasequery_packet(Ipv4Addr::UNSPECIFIED);
        let mut cfg = default_cfg();
        cfg.leasequery_source = Ipv4Addr::new(192, 0, 2, 1);
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn leasequery_returns_none_without_unicast_source() {
        let pkt = leasequery_packet(Ipv4Addr::UNSPECIFIED);
        let mut cfg = default_cfg();
        cfg.leasequery_enabled = true;
        // leasequery_source left at UNSPECIFIED (no real socket source).
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    #[test]
    fn leasequery_unknown_when_no_matching_lease() {
        let pkt = leasequery_packet(Ipv4Addr::new(10, 0, 0, 150));
        let mut cfg = default_cfg();
        cfg.leasequery_enabled = true;
        cfg.leasequery_source = Ipv4Addr::new(192, 0, 2, 1);
        cfg.contexts = vec![make_ctx(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200), Ipv4Addr::UNSPECIFIED, 0)];

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe)
            .expect("leasequery should always reply once enabled+unicast");
        assert_eq!(dispatched.reply.msg_type, DhcpMsgType::LeaseUnassigned);
        // rfc2131.c's `clear_packet` never touches `ciaddr` for
        // DHCPLEASEUNASSIGNED (only DHCPLEASEUNKNOWN explicitly zeroes it,
        // rfc2131.c:1173-1177), so the reply must echo back the queried
        // address, not force it to 0.0.0.0.
        assert_eq!(dispatched.reply.ciaddr_override, None);
        assert_eq!(
            dispatched.reply.ciaddr_override.unwrap_or(pkt.ciaddr),
            Ipv4Addr::new(10, 0, 0, 150)
        );
    }

    #[test]
    fn leasequery_unknown_zeroes_ciaddr() {
        // ciaddr == UNSPECIFIED and no lease found by client id: falls to
        // DHCPLEASEUNKNOWN, which rfc2131.c:1173-1177 explicitly zeroes.
        let pkt = leasequery_packet(Ipv4Addr::UNSPECIFIED);
        let mut cfg = default_cfg();
        cfg.leasequery_enabled = true;
        cfg.leasequery_source = Ipv4Addr::new(192, 0, 2, 1);
        cfg.contexts = vec![make_ctx(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200), Ipv4Addr::UNSPECIFIED, 0)];

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe)
            .expect("leasequery should always reply once enabled+unicast");
        assert_eq!(dispatched.reply.msg_type, DhcpMsgType::LeaseUnknown);
        assert_eq!(dispatched.reply.ciaddr_override, Some(Ipv4Addr::UNSPECIFIED));
    }

    #[test]
    fn leasequery_active_lease_reports_ciaddr_and_lease_time() {
        let mut lease_db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 150);
        lease_db.allocate_v4(addr);
        lease_db.set_hwaddr(addr, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 1, None, false);
        lease_db.set_expires(addr, 3600);

        let pkt = leasequery_packet(addr);
        let mut cfg = default_cfg();
        cfg.leasequery_enabled = true;
        cfg.leasequery_source = Ipv4Addr::new(192, 0, 2, 1);
        cfg.contexts = vec![make_ctx(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200), Ipv4Addr::UNSPECIFIED, 0)];

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db, &mut PingCache::new(), &NullProbe)
            .expect("leasequery for an active lease should reply");
        assert_eq!(dispatched.reply.msg_type, DhcpMsgType::LeaseActive);
        assert_eq!(dispatched.reply.ciaddr_override, Some(addr));
        assert!(find_option(&dispatched.reply.options, OPTION_LEASE_TIME).is_some());
    }

    #[test]
    fn leasequery_active_lease_omits_unrequested_netmask_and_broadcast() {
        // Netmask/broadcast are normally sent unconditionally, but
        // rfc2131.c:2787-2797 gates that on the requesting manager actually
        // having asked for them via OPTION_REQUESTED_OPTIONS once
        // `leasequery` is true.
        let mut lease_db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 150);
        lease_db.allocate_v4(addr);
        lease_db.set_hwaddr(addr, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 1, None, false);
        lease_db.set_expires(addr, 3600);

        // Request only OPTION_LEASE_TIME — not netmask or broadcast.
        let pkt = leasequery_packet_with_req_options(addr, &[OPTION_LEASE_TIME]);
        let mut cfg = default_cfg();
        cfg.leasequery_enabled = true;
        cfg.leasequery_source = Ipv4Addr::new(192, 0, 2, 1);
        cfg.contexts = vec![make_ctx(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200), Ipv4Addr::UNSPECIFIED, 0)];

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db, &mut PingCache::new(), &NullProbe)
            .expect("leasequery for an active lease should reply");
        assert_eq!(dispatched.reply.msg_type, DhcpMsgType::LeaseActive);
        assert!(
            find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_NETMASK).is_none(),
            "leasequery reply must not carry netmask unless requested"
        );
        assert!(
            find_option(&dispatched.reply.options, crate::dhcp_protocol::OPTION_BROADCAST).is_none(),
            "leasequery reply must not carry broadcast unless requested"
        );
    }

    #[test]
    fn leasequery_active_lease_omits_unrequested_force_option() {
        // DHOPT_FORCE options are normally sent regardless of the client's
        // requested-options list, but rfc2131.c:2878 additionally gates that
        // on `in_list(req_options, ...)` once `leasequery` is true.
        let mut lease_db = LeaseDb::new();
        let addr = Ipv4Addr::new(10, 0, 0, 150);
        lease_db.allocate_v4(addr);
        lease_db.set_hwaddr(addr, &[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff], 1, None, false);
        lease_db.set_expires(addr, 3600);

        const CUSTOM_OPT: u8 = 200;
        let pkt = leasequery_packet_with_req_options(addr, &[OPTION_LEASE_TIME]);
        let mut cfg = default_cfg();
        cfg.leasequery_enabled = true;
        cfg.leasequery_source = Ipv4Addr::new(192, 0, 2, 1);
        cfg.contexts = vec![make_ctx(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200), Ipv4Addr::UNSPECIFIED, 0)];
        cfg.dhcp_opts = vec![crate::types::dhcp::DhcpOpt {
            opt: i32::from(CUSTOM_OPT),
            flags: crate::types::dhcp::DHOPT_TAGOK | crate::types::dhcp::DHOPT_FORCE,
            val: Some(vec![7]),
            netid: vec![],
            encap: 0,
            vendor_class: None,
        }];

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut lease_db, &mut PingCache::new(), &NullProbe)
            .expect("leasequery for an active lease should reply");
        assert_eq!(dispatched.reply.msg_type, DhcpMsgType::LeaseActive);
        assert!(
            find_option(&dispatched.reply.options, CUSTOM_OPT).is_none(),
            "leasequery reply must not carry a DHOPT_FORCE option unless requested"
        );
    }

    #[test]
    fn leasequery_rejects_source_outside_configured_prefix() {
        let pkt = leasequery_packet(Ipv4Addr::UNSPECIFIED);
        let mut cfg = default_cfg();
        cfg.leasequery_enabled = true;
        cfg.leasequery_source = Ipv4Addr::new(198, 51, 100, 1); // outside 192.0.2.0/24
        cfg.leasequery_addr = vec![crate::types::dns_records::BogusAddr {
            is6: false,
            prefix: 24,
            addr: crate::types::addr::AllAddr::Addr4(Ipv4Addr::new(192, 0, 2, 0)),
        }];
        assert!(dispatch_dhcp(&pkt, &cfg, &mut LeaseDb::new()).is_none());
    }

    // ── dhcp-rapid-commit (OPT_RAPID_COMMIT, rfc2131.c:1363-1372) ──────────

    #[test]
    fn rapid_commit_discover_gets_immediate_ack_with_delay_applied() {
        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Discover as u8,
            OPTION_RAPID_COMMIT, 0,
            OPTION_END,
        ];
        let mut cfg = default_cfg();
        cfg.rapid_commit = true;
        cfg.contexts = vec![make_ctx(Ipv4Addr::new(10, 0, 0, 100), Ipv4Addr::new(10, 0, 0, 200), Ipv4Addr::UNSPECIFIED, 0)];
        cfg.reply_delays = vec![crate::types::dhcp::DhcpReplyDelay { delay_secs: 3, filter: vec![] }];

        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe)
            .expect("rapid-commit discover should ack immediately");
        assert_eq!(dispatched.reply.msg_type, DhcpMsgType::Ack);
        assert!(find_option(&dispatched.reply.options, OPTION_RAPID_COMMIT).is_some());
        assert_eq!(dispatched.delay_secs, 3, "apply_delay's DISCOVER call site must cover the rapid-commit ACK too");
    }

    #[test]
    fn plain_request_ack_is_never_delayed() {
        // Upstream never calls apply_delay for an ordinary REQUEST->ACK
        // (only the DISCOVER path and PXE-proxy replies get one).
        let mut cfg = default_cfg();
        cfg.reply_delays = vec![crate::types::dhcp::DhcpReplyDelay { delay_secs: 3, filter: vec![] }];
        let mut pkt = base_packet();
        pkt.options = vec![
            OPTION_MESSAGE_TYPE, 1, DhcpMsgType::Request as u8,
            crate::dhcp_protocol::OPTION_REQUESTED_IP, 4, 10, 0, 0, 150,
            OPTION_END,
        ];
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe)
            .expect("request should ack");
        assert_eq!(dispatched.reply.msg_type, DhcpMsgType::Ack);
        assert_eq!(dispatched.delay_secs, 0);
    }

    #[test]
    fn rapid_commit_without_client_request_still_offers() {
        // OPT_RAPID_COMMIT enabled server-side, but the client didn't ask
        // for it: ordinary OFFER flow, unaffected.
        let pkt = base_packet(); // plain DISCOVER, no option 80
        let mut cfg = default_cfg();
        cfg.rapid_commit = true;
        let dispatched = dispatch_dhcp_with_meta(&pkt, &cfg, &mut LeaseDb::new(), &mut PingCache::new(), &NullProbe)
            .expect("discover should offer");
        assert_eq!(dispatched.reply.msg_type, DhcpMsgType::Offer);
    }
}

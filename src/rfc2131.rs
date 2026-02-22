//! DHCPv4 protocol state machine: DISCOVER → OFFER → REQUEST → ACK/NAK.
//! Ported from `rfc2131.c`.

#[cfg(feature = "dhcp")]
use std::net::Ipv4Addr;
#[cfg(feature = "dhcp")]
use crate::dhcp_protocol::{
    DhcpMsgType, DhcpPacket,
    OPTION_END, OPTION_MESSAGE_TYPE, OPTION_REQUESTED_IP, OPTION_SERVER_IDENTIFIER,
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

#[cfg(all(test, feature = "dhcp"))]
mod tests {
    use super::*;
    use crate::dhcp_protocol::{DhcpPacket, DHCP_CHADDR_MAX};

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
}

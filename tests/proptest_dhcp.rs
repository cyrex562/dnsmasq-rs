//! Property-based tests for the DHCP parser and state machine.

#[cfg(feature = "dhcp")]
use dnsmasq_rs::dhcp_common::{build_options, find_option, get_message_type};
#[cfg(feature = "dhcp")]
use dnsmasq_rs::dhcp_protocol::{
    DhcpMsgType, DhcpPacket, OPTION_END, OPTION_MESSAGE_TYPE, DHCP_CHADDR_MAX,
};
#[cfg(feature = "dhcp")]
use dnsmasq_rs::rfc2131::{handle_discover, handle_request, option_msg_type};
#[cfg(feature = "dhcp")]
use dnsmasq_rs::types::dhcp::DhcpOpt;
#[cfg(feature = "dhcp")]
use proptest::prelude::*;
#[cfg(feature = "dhcp")]
use std::net::Ipv4Addr;

#[cfg(feature = "dhcp")]
fn options_with_type(msg_type: DhcpMsgType) -> Vec<u8> {
    let [code, len, val] = option_msg_type(msg_type);
    vec![code, len, val, OPTION_END]
}

#[cfg(feature = "dhcp")]
fn minimal_pkt(options: Vec<u8>, giaddr: Ipv4Addr) -> DhcpPacket {
    DhcpPacket {
        op: 1, htype: 1, hlen: 6, hops: 0,
        xid: 0x1234_5678, secs: 0, flags: 0,
        ciaddr: Ipv4Addr::UNSPECIFIED,
        yiaddr: Ipv4Addr::UNSPECIFIED,
        siaddr: Ipv4Addr::UNSPECIFIED,
        giaddr,
        chaddr: [0u8; DHCP_CHADDR_MAX],
        sname:  [0u8; 64],
        file:   [0u8; 128],
        options,
    }
}

#[cfg(feature = "dhcp")]
fn ipv4_strat() -> impl Strategy<Value = Ipv4Addr> {
    (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
        .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
}

#[cfg(feature = "dhcp")]
proptest! {
    /// find_option never panics on arbitrary bytes.
    #[test]
    fn prop_find_option_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..512),
        code in any::<u8>(),
    ) {
        let _ = find_option(&bytes, code);
    }

    /// get_message_type never panics on arbitrary bytes.
    #[test]
    fn prop_get_message_type_never_panics(
        bytes in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let _ = get_message_type(&bytes);
    }

    /// An option encoded with build_options can be found by find_option.
    #[test]
    fn prop_build_then_find_option(
        code in 1u8..=253u8,
        data in prop::collection::vec(any::<u8>(), 0..=64),
    ) {
        let opt = DhcpOpt {
            opt: code as i32,
            flags: 0,
            val: Some(data.clone()),
            netid: vec![],
            encap: 0,
            vendor_class: None,
        };
        let encoded = build_options(&[opt]);
        let found = find_option(&encoded, code);
        prop_assert!(found.is_some(), "option {} should be found", code);
        prop_assert_eq!(found.unwrap(), data.as_slice());
    }

    /// option_msg_type produces a valid 3-byte TLV.
    #[test]
    fn prop_option_msg_type_format(raw in 1u8..=8u8) {
        if let Some(mt) = DhcpMsgType::from_u8(raw) {
            let tlv = option_msg_type(mt);
            prop_assert_eq!(tlv[0], OPTION_MESSAGE_TYPE);
            prop_assert_eq!(tlv[1], 1u8);
            prop_assert_eq!(tlv[2], raw);
        }
    }

    /// get_message_type decodes a correctly encoded options block.
    #[test]
    fn prop_get_message_type_roundtrip(raw in 1u8..=8u8) {
        if let Some(mt) = DhcpMsgType::from_u8(raw) {
            let opts = options_with_type(mt);
            let result = get_message_type(&opts);
            prop_assert!(result.is_some());
            prop_assert_eq!(result.unwrap() as u8, raw);
        }
    }

    /// DISCOVER produces an OFFER with yiaddr in [pool_start, pool_end].
    #[test]
    fn prop_discover_offer_in_pool(
        start_octet in 1u8..=200u8,
        span in 1u8..=55u8,
        server_ip in ipv4_strat(),
    ) {
        let pool_start = Ipv4Addr::new(10, 0, 0, start_octet);
        let pool_end   = Ipv4Addr::new(10, 0, 0, start_octet.saturating_add(span));
        let opts = options_with_type(DhcpMsgType::Discover);
        let pkt  = minimal_pkt(opts, Ipv4Addr::UNSPECIFIED);
        let reply = handle_discover(&pkt, pool_start, pool_end, None, server_ip, None);
        prop_assume!(reply.is_some());
        let offered = u32::from(reply.unwrap().yiaddr);
        prop_assert!(
            offered >= u32::from(pool_start) && offered <= u32::from(pool_end),
            "yiaddr out of pool"
        );
    }

    /// handle_request never panics for any IP combination.
    #[test]
    fn prop_request_never_panics(
        pool_start in ipv4_strat(),
        pool_end   in ipv4_strat(),
        server_ip  in ipv4_strat(),
    ) {
        let mut opts = vec![50u8, 4, 192, 168, 1, 1];
        let [c, l, v] = option_msg_type(DhcpMsgType::Request);
        opts.extend_from_slice(&[c, l, v, OPTION_END]);
        let pkt = minimal_pkt(opts, Ipv4Addr::UNSPECIFIED);
        let _ = handle_request(&pkt, pool_start, pool_end, server_ip, None, false);
    }

    /// REQUEST with in-pool IP → ACK; out-of-pool → NAK.
    #[test]
    fn prop_request_ack_nak(
        start_octet in 1u8..=200u8,
        span in 1u8..=55u8,
        server_ip in ipv4_strat(),
    ) {
        let pool_start = Ipv4Addr::new(10, 0, 0, start_octet);
        let pool_end   = Ipv4Addr::new(10, 0, 0, start_octet.saturating_add(span));
        let [c, l, v] = option_msg_type(DhcpMsgType::Request);

        // In-pool request.
        let [a, b, cc, d] = pool_start.octets();
        let mut in_opts = vec![50u8, 4, a, b, cc, d, c, l, v, OPTION_END];
        let reply_in = handle_request(&minimal_pkt(in_opts, Ipv4Addr::UNSPECIFIED), pool_start, pool_end, server_ip, None, false);
        prop_assert!(reply_in.is_some());
        prop_assert_eq!(reply_in.unwrap().msg_type, DhcpMsgType::Ack);

        // Out-of-pool request (1.2.3.4 is never in a 10.x.x.x pool).
        let out_opts = vec![50u8, 4, 1, 2, 3, 4, c, l, v, OPTION_END];
        let reply_out = handle_request(&minimal_pkt(out_opts, Ipv4Addr::UNSPECIFIED), pool_start, pool_end, server_ip, None, false);
        prop_assert!(reply_out.is_some());
        prop_assert_eq!(reply_out.unwrap().msg_type, DhcpMsgType::Nak);
    }
}

#[test]
fn placeholder_dhcp_proptest() {}

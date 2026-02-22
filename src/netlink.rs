use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Raw netlink message type constants.
pub mod nlmsg_type {
    pub const RTM_NEWADDR:  u16 = 20;
    pub const RTM_DELADDR:  u16 = 21;
    pub const RTM_NEWROUTE: u16 = 24;
    pub const RTM_DELROUTE: u16 = 25;
}

const AF_INET:  u8 = 2;
const AF_INET6: u8 = 10;

const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL:   u16 = 2;

/// Parsed netlink event.
#[derive(Debug, Clone, PartialEq)]
pub enum NetlinkEvent {
    NewAddress { iface_index: u32, addr: IpAddr, prefix_len: u8 },
    DelAddress { iface_index: u32, addr: IpAddr },
    NewRoute    { dst: IpAddr, prefix_len: u8, gateway: Option<IpAddr> },
    DelRoute    { dst: IpAddr, prefix_len: u8 },
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
}

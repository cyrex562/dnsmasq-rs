/// DHCPv4 protocol constants and packet structure.
/// Ported from `dhcp-protocol.h`.

// Port numbers
pub const DHCP_SERVER_PORT:    u16 = 67;
pub const DHCP_CLIENT_PORT:    u16 = 68;
pub const DHCP_SERVER_ALTPORT: u16 = 1067;
pub const DHCP_CLIENT_ALTPORT: u16 = 1068;
pub const PXE_PORT:            u16 = 4011;

pub const DHCP_BUFF_SZ: usize = 256;
pub const DHCP_CHADDR_MAX: usize = 16;
pub const MIN_PACKETSZ: usize = 300;

pub const BOOTREQUEST: u8  = 1;
pub const BOOTREPLY:   u8  = 2;
pub const DHCP_COOKIE: u32 = 0x6382_5363;

// Standard DHCP options
pub const OPTION_PAD:               u8 = 0;
pub const OPTION_NETMASK:           u8 = 1;
pub const OPTION_ROUTER:            u8 = 3;
pub const OPTION_DNSSERVER:         u8 = 6;
pub const OPTION_HOSTNAME:          u8 = 12;
pub const OPTION_DOMAINNAME:        u8 = 15;
pub const OPTION_BROADCAST:         u8 = 28;
pub const OPTION_VENDOR_CLASS_OPT:  u8 = 43;
pub const OPTION_REQUESTED_IP:      u8 = 50;
pub const OPTION_LEASE_TIME:        u8 = 51;
pub const OPTION_OVERLOAD:          u8 = 52;
pub const OPTION_MESSAGE_TYPE:      u8 = 53;
pub const OPTION_SERVER_IDENTIFIER: u8 = 54;
pub const OPTION_REQUESTED_OPTIONS: u8 = 55;
pub const OPTION_MESSAGE:           u8 = 56;
pub const OPTION_MAXMESSAGE:        u8 = 57;
pub const OPTION_T1:                u8 = 58;
pub const OPTION_T2:                u8 = 59;
pub const OPTION_VENDOR_ID:         u8 = 60;
pub const OPTION_CLIENT_ID:         u8 = 61;
pub const OPTION_SNAME:             u8 = 66;
pub const OPTION_FILENAME:          u8 = 67;
pub const OPTION_USER_CLASS:        u8 = 77;
pub const OPTION_RAPID_COMMIT:      u8 = 80;
pub const OPTION_CLIENT_FQDN:       u8 = 81;
pub const OPTION_AGENT_ID:          u8 = 82;
pub const OPTION_LAST_TRANSACTION:  u8 = 91;
pub const OPTION_ASSOCIATED_IP:     u8 = 92;
pub const OPTION_ARCH:              u8 = 93;
pub const OPTION_PXE_UUID:          u8 = 97;
pub const OPTION_SUBNET_SELECT:     u8 = 118;
pub const OPTION_DOMAIN_SEARCH:     u8 = 119;
pub const OPTION_SIP_SERVER:        u8 = 120;
pub const OPTION_VENDOR_IDENT:      u8 = 124;
pub const OPTION_VENDOR_IDENT_OPT:  u8 = 125;
pub const OPTION_MUD_URL_V4:        u8 = 161;
pub const OPTION_END:               u8 = 255;

// Relay agent sub-options (option 82)
pub const SUBOPT_CIRCUIT_ID:    u8 = 1;
pub const SUBOPT_REMOTE_ID:     u8 = 2;
pub const SUBOPT_SUBNET_SELECT: u8 = 5;
pub const SUBOPT_SUBSCR_ID:     u8 = 6;
pub const SUBOPT_FLAGS:         u8 = 10;
pub const SUBOPT_SERVER_OR:     u8 = 11;

// PXE sub-options
pub const SUBOPT_PXE_BOOT_ITEM:  u8 = 71;
pub const SUBOPT_PXE_DISCOVERY:  u8 = 6;
pub const SUBOPT_PXE_SERVERS:    u8 = 8;
pub const SUBOPT_PXE_MENU:       u8 = 9;
pub const SUBOPT_PXE_MENU_PROMPT:u8 = 10;

pub const BRDBAND_FORUM_IANA: u32 = 3561;

/// DHCP message types (option 53 values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpMsgType {
    Discover        = 1,
    Offer           = 2,
    Request         = 3,
    Decline         = 4,
    Ack             = 5,
    Nak             = 6,
    Release         = 7,
    Inform          = 8,
    ForceRenew      = 9,
    LeaseQuery      = 10,
    LeaseUnassigned = 11,
    LeaseUnknown    = 12,
    LeaseActive     = 13,
}

impl DhcpMsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1  => Some(Self::Discover),
            2  => Some(Self::Offer),
            3  => Some(Self::Request),
            4  => Some(Self::Decline),
            5  => Some(Self::Ack),
            6  => Some(Self::Nak),
            7  => Some(Self::Release),
            8  => Some(Self::Inform),
            9  => Some(Self::ForceRenew),
            10 => Some(Self::LeaseQuery),
            11 => Some(Self::LeaseUnassigned),
            12 => Some(Self::LeaseUnknown),
            13 => Some(Self::LeaseActive),
            _  => None,
        }
    }
}

/// On-wire BOOTP/DHCP packet.
#[derive(Debug, Clone)]
pub struct DhcpPacket {
    pub op:      u8,
    pub htype:   u8,
    pub hlen:    u8,
    pub hops:    u8,
    pub xid:     u32,
    pub secs:    u16,
    pub flags:   u16,
    pub ciaddr:  std::net::Ipv4Addr,
    pub yiaddr:  std::net::Ipv4Addr,
    pub siaddr:  std::net::Ipv4Addr,
    pub giaddr:  std::net::Ipv4Addr,
    pub chaddr:  [u8; DHCP_CHADDR_MAX],
    pub sname:   [u8; 64],
    pub file:    [u8; 128],
    pub options: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_msg_type_roundtrip() {
        for v in 1u8..=13 {
            assert!(DhcpMsgType::from_u8(v).is_some(), "missing type {v}");
        }
        assert!(DhcpMsgType::from_u8(0).is_none());
        assert!(DhcpMsgType::from_u8(14).is_none());
    }

    #[test]
    fn cookie_value() {
        assert_eq!(DHCP_COOKIE, 0x63825363);
    }
}

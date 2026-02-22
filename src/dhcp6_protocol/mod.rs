/// DHCPv6 protocol constants.
/// Ported from `dhcp6-protocol.h`.

pub const DHCPV6_SERVER_PORT: u16 = 547;
pub const DHCPV6_CLIENT_PORT: u16 = 546;

pub const ALL_SERVERS:                  &str = "FF05::1:3";
pub const ALL_RELAY_AGENTS_AND_SERVERS: &str = "FF02::1:2";

/// DHCPv6 message types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Dhcp6MsgType {
    Solicit     = 1,
    Advertise   = 2,
    Request     = 3,
    Confirm     = 4,
    Renew       = 5,
    Rebind      = 6,
    Reply       = 7,
    Release     = 8,
    Decline     = 9,
    Reconfigure = 10,
    InfoReq     = 11,
    RelayForw   = 12,
    RelayRepl   = 13,
}

impl Dhcp6MsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1  => Some(Self::Solicit),
            2  => Some(Self::Advertise),
            3  => Some(Self::Request),
            4  => Some(Self::Confirm),
            5  => Some(Self::Renew),
            6  => Some(Self::Rebind),
            7  => Some(Self::Reply),
            8  => Some(Self::Release),
            9  => Some(Self::Decline),
            10 => Some(Self::Reconfigure),
            11 => Some(Self::InfoReq),
            12 => Some(Self::RelayForw),
            13 => Some(Self::RelayRepl),
            _  => None,
        }
    }
}

// DHCPv6 option codes
pub const OPTION6_CLIENT_ID:       u16 = 1;
pub const OPTION6_SERVER_ID:       u16 = 2;
pub const OPTION6_IA_NA:           u16 = 3;
pub const OPTION6_IA_TA:           u16 = 4;
pub const OPTION6_IAADDR:          u16 = 5;
pub const OPTION6_ORO:             u16 = 6;
pub const OPTION6_PREFERENCE:      u16 = 7;
pub const OPTION6_ELAPSED_TIME:    u16 = 8;
pub const OPTION6_RELAY_MSG:       u16 = 9;
pub const OPTION6_AUTH:            u16 = 11;
pub const OPTION6_UNICAST:         u16 = 12;
pub const OPTION6_STATUS_CODE:     u16 = 13;
pub const OPTION6_RAPID_COMMIT:    u16 = 14;
pub const OPTION6_USER_CLASS:      u16 = 15;
pub const OPTION6_VENDOR_CLASS:    u16 = 16;
pub const OPTION6_VENDOR_OPTS:     u16 = 17;
pub const OPTION6_INTERFACE_ID:    u16 = 18;
pub const OPTION6_RECONFIGURE_MSG: u16 = 19;
pub const OPTION6_RECONF_ACCEPT:   u16 = 20;
pub const OPTION6_DNS_SERVER:      u16 = 23;
pub const OPTION6_DOMAIN_SEARCH:   u16 = 24;
pub const OPTION6_IA_PD:           u16 = 25;
pub const OPTION6_IAPREFIX:        u16 = 26;
pub const OPTION6_REFRESH_TIME:    u16 = 32;
pub const OPTION6_REMOTE_ID:       u16 = 37;
pub const OPTION6_SUBSCRIBER_ID:   u16 = 38;
pub const OPTION6_FQDN:            u16 = 39;
pub const OPTION6_NTP_SERVER:      u16 = 56;
pub const OPTION6_CLIENT_MAC:      u16 = 79;
pub const OPTION6_MUD_URL:         u16 = 112;

// NTP sub-options
pub const NTP_SUBOPTION_SRV_ADDR: u16 = 1;
pub const NTP_SUBOPTION_MC_ADDR:  u16 = 2;
pub const NTP_SUBOPTION_SRV_FQDN: u16 = 3;

/// DHCPv6 status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Dhcp6Status {
    Success    = 0,
    Unspec     = 1,
    NoAddrs    = 2,
    NoBinding  = 3,
    NotOnLink  = 4,
    UseMulti   = 5,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msg_type_roundtrip() {
        for v in 1u8..=13 {
            assert!(Dhcp6MsgType::from_u8(v).is_some(), "missing type {v}");
        }
        assert!(Dhcp6MsgType::from_u8(0).is_none());
    }

    #[test]
    fn ports() {
        assert_eq!(DHCPV6_SERVER_PORT, 547);
        assert_eq!(DHCPV6_CLIENT_PORT, 546);
    }
}

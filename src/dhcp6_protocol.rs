
pub const DHCPV6_SERVER_PORT: u16 = 547;
pub const DHCPV6_CLIENT_PORT: u16 = 546;

pub const ALL_SERVERS: &str = "FF05::1:3";
pub const ALL_RELAY_AGENTS_AND_SERVERS: &str = "FF02::1:2";

pub const DHCP6SOLICIT: u8 = 1;
pub const DHCP6ADVERTISE: u8 = 2;
pub const DHCP6REQUEST: u8 = 3;
pub const DHCP6CONFIRM: u8 = 4;
pub const DHCP6RENEW: u8 = 5;
pub const DHCP6REBIND: u8 = 6;
pub const DHCP6REPLY: u8 = 7;
pub const DHCP6RELEASE: u8 = 8;
pub const DHCP6DECLINE: u8 = 9;
pub const DHCP6RECONFIGURE: u8 = 10;
pub const DHCP6IREQ: u8 = 11;
pub const DHCP6RELAYFORW: u8 = 12;
pub const DHCP6RELAYREPL: u8 = 13;

pub const OPTION6_CLIENT_ID: u16 = 1;
pub const OPTION6_SERVER_ID: u16 = 2;
pub const OPTION6_IA_NA: u16 = 3;
pub const OPTION6_IA_TA: u16 = 4;
pub const OPTION6_IAADDR: u16 = 5;
pub const OPTION6_ORO: u16 = 6;
pub const OPTION6_PREFERENCE: u16 = 7;
pub const OPTION6_ELAPSED_TIME: u16 = 8;
pub const OPTION6_RELAY_MSG: u16 = 9;
pub const OPTION6_AUTH: u16 = 11;
pub const OPTION6_UNICAST: u16 = 12;
pub const OPTION6_STATUS_CODE: u16 = 13;
pub const OPTION6_RAPID_COMMIT: u16 = 14;
pub const OPTION6_USER_CLASS: u16 = 15;
pub const OPTION6_VENDOR_CLASS: u16 = 16;
pub const OPTION6_VENDOR_OPTS: u16 = 17;
pub const OPTION6_INTERFACE_ID: u16 = 18;
pub const OPTION6_RECONFIGURE_MSG: u16 = 19;
pub const OPTION6_RECONF_ACCEPT: u16 = 20;
pub const OPTION6_DNS_SERVER: u16 = 23;
pub const OPTION6_DOMAIN_SEARCH: u16 = 24;
pub const OPTION6_IA_PD: u16 = 25;
pub const OPTION6_IAPREFIX: u16 = 26;
pub const OPTION6_REFRESH_TIME: u16 = 32;
pub const OPTION6_REMOTE_ID: u16 = 37;
pub const OPTION6_SUBSCRIBER_ID: u16 = 38;
pub const OPTION6_FQDN: u16 = 39;
pub const OPTION6_NTP_SERVER: u16 = 56;
pub const OPTION6_CLIENT_MAC: u16 = 79;
pub const OPTION6_MUD_URL: u16 = 112;

pub const NTP_SUBOPTION_SRV_ADDR: u8 = 1;
pub const NTP_SUBOPTION_MC_ADDR: u8 = 2;
pub const NTP_SUBOPTION_SRV_FQDN: u8 = 3;

pub const DHCP6SUCCESS: u8 = 0;
pub const DHCP6UNSPEC: u8 = 1;
pub const DHCP6NOADDRS: u8 = 2;
pub const DHCP6NOBINDING: u8 = 3;
pub const DHCP6NOTONLINK: u8 = 4;
pub const DHCP6USEMULTI: u8 = 5;
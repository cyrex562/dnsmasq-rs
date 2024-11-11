
const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_SERVER_ALTPORT: u16 = 1067;
const DHCP_CLIENT_ALTPORT: u16 = 1068;
const PXE_PORT: u16 = 4011;

const DHCP_BUFF_SZ: usize = 256;

const BOOTREQUEST: u8 = 1;
const BOOTREPLY: u8 = 2;
const DHCP_COOKIE: u32 = 0x63825363;

const MIN_PACKETSZ: usize = 300;

const OPTION_PAD: u8 = 0;
const OPTION_NETMASK: u8 = 1;
const OPTION_ROUTER: u8 = 3;
const OPTION_DNSSERVER: u8 = 6;
const OPTION_HOSTNAME: u8 = 12;
const OPTION_DOMAINNAME: u8 = 15;
const OPTION_BROADCAST: u8 = 28;
const OPTION_VENDOR_CLASS_OPT: u8 = 43;
const OPTION_REQUESTED_IP: u8 = 50;
const OPTION_LEASE_TIME: u8 = 51;
const OPTION_OVERLOAD: u8 = 52;
const OPTION_MESSAGE_TYPE: u8 = 53;
const OPTION_SERVER_IDENTIFIER: u8 = 54;
const OPTION_REQUESTED_OPTIONS: u8 = 55;
const OPTION_MESSAGE: u8 = 56;
const OPTION_MAXMESSAGE: u8 = 57;
const OPTION_T1: u8 = 58;
const OPTION_T2: u8 = 59;
const OPTION_VENDOR_ID: u8 = 60;
const OPTION_CLIENT_ID: u8 = 61;
const OPTION_SNAME: u8 = 66;
const OPTION_FILENAME: u8 = 67;
const OPTION_USER_CLASS: u8 = 77;
const OPTION_RAPID_COMMIT: u8 = 80;
const OPTION_CLIENT_FQDN: u8 = 81;
const OPTION_AGENT_ID: u8 = 82;
const OPTION_ARCH: u8 = 93;
const OPTION_PXE_UUID: u8 = 97;
const OPTION_SUBNET_SELECT: u8 = 118;
const OPTION_DOMAIN_SEARCH: u8 = 119;
const OPTION_SIP_SERVER: u8 = 120;
const OPTION_VENDOR_IDENT: u8 = 124;
const OPTION_VENDOR_IDENT_OPT: u8 = 125;
const OPTION_MUD_URL_V4: u8 = 161;
const OPTION_END: u8 = 255;

const SUBOPT_CIRCUIT_ID: u8 = 1;
const SUBOPT_REMOTE_ID: u8 = 2;
const SUBOPT_SUBNET_SELECT: u8 = 5;
const SUBOPT_SUBSCR_ID: u8 = 6;
const SUBOPT_SERVER_OR: u8 = 11;

const SUBOPT_PXE_BOOT_ITEM: u8 = 71;
const SUBOPT_PXE_DISCOVERY: u8 = 6;
const SUBOPT_PXE_SERVERS: u8 = 8;
const SUBOPT_PXE_MENU: u8 = 9;
const SUBOPT_PXE_MENU_PROMPT: u8 = 10;

const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPDECLINE: u8 = 4;
const DHCPACK: u8 = 5;
const DHCPNAK: u8 = 6;
const DHCPRELEASE: u8 = 7;
const DHCPINFORM: u8 = 8;

const BRDBAND_FORUM_IANA: u32 = 3561;

const DHCP_CHADDR_MAX: usize = 16;

#[repr(C, packed)]
struct DhcpPacket {
    op: u8,
    htype: u8,
    hlen: u8,
    hops: u8,
    xid: u32,
    secs: u16,
    flags: u16,
    ciaddr: std::net::Ipv4Addr,
    yiaddr: std::net::Ipv4Addr,
    siaddr: std::net::Ipv4Addr,
    giaddr: std::net::Ipv4Addr,
    chaddr: [u8; DHCP_CHADDR_MAX],
    sname: [u8; 64],
    file: [u8; 128],
    options: [u8; 312],
}
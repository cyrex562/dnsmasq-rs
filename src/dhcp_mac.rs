pub struct DhcpMac {
    mask: u32,
    hwaddr_len: i32,
    hwaddr_type: i32,
    hwaddr: [u8; DHCP_CHADDR_MAX],
    netid: DhcpNetId,
    next: Option<Box<DhcpMac>>,
}
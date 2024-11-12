pub struct DhcpBridge {
    iface: [u8; IF_NAMESIZE],
    alias: Option<Box<DhcpBridge>>,
    next: Option<Box<DhcpBridge>>,
}
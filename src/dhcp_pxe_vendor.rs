pub struct DhcpPxeVendor {
    pub data: String,
    pub next: Option<Box<DhcpPxeVendor>>,
}
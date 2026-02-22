use crate::dhcp_netid::DhcpNetId;

pub struct DhcpVendor {
    pub len: i32,
    pub match_type: i32,
    pub enterprise: u32,
    pub data: String,
    pub netid: DhcpNetId,
    pub next: Option<Box<DhcpVendor>>,
}
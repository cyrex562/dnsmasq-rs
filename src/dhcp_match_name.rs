use crate::dhcp_netid::DhcpNetId;

pub struct DhcpMatchName {
    pub name: String,
    pub wildcard: i32,
    pub netid: Option<Box<DhcpNetId>>,
    pub next: Option<Box<DhcpMatchName>>,
}
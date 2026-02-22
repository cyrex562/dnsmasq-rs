use std::net::Ipv4Addr;

use crate::dhcp_netid::DhcpNetId;

pub struct PxeService {
    pub csa: u16,
    pub service_type: u16,
    pub menu: String,
    pub basename: String,
    pub sname: String,
    pub server: Ipv4Addr,
    pub netid: Option<Box<DhcpNetId>>,
    pub next: Option<Box<PxeService>>,
}
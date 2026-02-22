use std::net::Ipv4Addr;

pub struct DhcpBoot {
    pub file: String,
    pub sname: String,
    pub tftp_sname: String,
    pub next_server: Ipv4Addr,
    pub netid: Option<Box<DhcpNetId>>,
    pub next: Option<Box<DhcpBoot>>,
}
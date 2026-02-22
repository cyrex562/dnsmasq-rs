use std::net::Ipv4Addr;

pub struct Doctor {
    pub in_addr: Ipv4Addr,
    pub end: Ipv4Addr,
    pub out: Ipv4Addr,
    pub mask: Ipv4Addr,
    pub next: *mut Doctor,
}

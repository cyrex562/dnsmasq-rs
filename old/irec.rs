use std::net::Ipv4Addr;

pub struct Irec {
    pub addr: MySockAddr,
    pub netmask: Ipv4Addr, // only valid for IPv4
    pub tftp_ok: i32,
    pub dhcp4_ok: i32,
    pub dhcp6_ok: i32,
    pub mtu: i32,
    pub done: i32,
    pub warned: i32,
    pub dad: i32,
    pub dns_auth: i32,
    pub index: i32,
    pub multicast_done: i32,
    pub found: i32,
    pub label: i32,
    pub name: String,
    pub next: Option<Box<Irec>>,
}
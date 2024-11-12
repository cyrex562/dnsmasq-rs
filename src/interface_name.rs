use std::net::{Ipv4Addr, Ipv6Addr};

use crate::addr_list::AddrList;

pub struct InterfaceName {
    pub name: String, // domain name
    pub intr: String, // interface name
    pub flags: i32,
    pub proto4: Ipv4Addr,
    pub proto6: Ipv6Addr,
    pub addr: Option<Box<AddrList>>,
    pub next: Option<Box<InterfaceName>>,
}

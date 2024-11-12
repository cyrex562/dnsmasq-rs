use std::net::{Ipv4Addr, Ipv6Addr};

use crate::addr_list::AddrList;

struct CondDomain {
    domain: String,
    prefix: String,    // prefix is text-prefix on domain name
    interface: String, // These two set when domain comes from interface
    al: Option<Box<AddrList>>,
    start: Ipv4Addr,
    end: Ipv4Addr,
    start6: Ipv6Addr,
    end6: Ipv6Addr,
    is6: i32,
    indexed: i32,
    prefixlen: i32,
    next: Option<Box<CondDomain>>,
}

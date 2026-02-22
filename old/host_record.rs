use std::net::{Ipv4Addr, Ipv6Addr};

pub struct HostRecord {
    pub ttl: i32,
    pub flags: i32,
    pub names: Option<Box<NameList>>,
    pub addr: Ipv4Addr,
    pub addr6: Ipv6Addr,
    pub next: Option<Box<HostRecord>>,
}

pub struct NameList {
    pub name: String,
    pub next: Option<Box<NameList>>,
}

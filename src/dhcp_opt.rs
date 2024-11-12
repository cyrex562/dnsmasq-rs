use crate::dhcp_netid::DhcpNetId;

pub struct DhcpOpt {
    pub opt: i32,
    pub len: i32,
    pub flags: i32,
    pub u: DhcpOptUnion,
    pub val: Vec<u8>,
    pub netid: Option<Box<DhcpNetId>>,
    pub next: Option<Box<DhcpOpt>>,
}

pub enum DhcpOptUnion {
    Encap(i32),
    WildcardMask(u32),
    VendorClass(Vec<u8>),
}


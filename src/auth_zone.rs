use crate::addr_list::AddrList;

pub struct AuthZone {
    pub domain: String,
    pub interface_names: Option<Box<AuthNameList>>,
    pub subnet: Option<Box<AddrList>>,
    pub exclude: Option<Box<AddrList>>,
    pub next: Option<Box<AuthZone>>,
}

pub struct AuthNameList {
    pub name: String,
    pub flags: i32,
    pub next: Option<Box<AuthNameList>>,
}

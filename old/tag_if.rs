use crate::dhcp_netid::{DhcpNetId, DhcpNetIdList};

pub struct TagIf {
    pub set: Option<Box<DhcpNetIdList>>,
    pub tag: Option<Box<DhcpNetId>>,
    pub next: Option<Box<TagIf>>,
}
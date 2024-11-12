use crate::arp::{AllAddr, DHCP_CHADDR_MAX};

pub struct ArpRecord {
    pub(crate) hwlen: u16,
    pub(crate) status: u16,
    pub(crate) family: i32,
    pub(crate) hwaddr: [u8; DHCP_CHADDR_MAX],
    pub(crate) addr: AllAddr,
    pub(crate) next: *mut ArpRecord,
}
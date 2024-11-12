use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::SystemTime;

pub struct DhcpLease {
    pub clid_len: i32, // length of client identifier
    pub clid: Vec<u8>, // clientid
    pub hostname: String, // name from client-hostname option or config
    pub fqdn: String, // name from client-hostname option or config
    pub old_hostname: String, // hostname before it moved to another lease
    pub flags: i32,
    pub expires: SystemTime, // lease expiry
    #[cfg(feature = "have_broken_rtc")]
    pub length: u32,
    pub hwaddr_len: i32,
    pub hwaddr_type: i32,
    pub hwaddr: [u8; DHCP_CHADDR_MAX],
    pub addr: Ipv4Addr,
    pub override_addr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub extradata: Vec<u8>,
    pub extradata_len: u32,
    pub extradata_size: u32,
    pub last_interface: i32,
    pub new_interface: i32, // save possible originated interface
    pub new_prefixlen: i32, // and its prefix length
    #[cfg(feature = "have_dhcp6")]
    pub addr6: Ipv6Addr,
    #[cfg(feature = "have_dhcp6")]
    pub iaid: u32,
    #[cfg(feature = "have_dhcp6")]
    pub slaac_address: Option<Box<SlaacAddress>>,
    #[cfg(feature = "have_dhcp6")]
    pub vendorclass_count: i32,
    pub next: Option<Box<DhcpLease>>,
}

#[cfg(feature = "have_dhcp6")]
pub struct SlaacAddress {
    pub addr: Ipv6Addr,
    pub ping_time: SystemTime,
    pub backoff: i32, // zero -> confirmed
    pub next: Option<Box<SlaacAddress>>,
}
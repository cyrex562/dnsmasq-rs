use std::net::{Ipv4Addr, Ipv6Addr};

pub union AllAddr {
    pub addr4: Ipv4Addr,
    pub addr6: Ipv6Addr,
    pub cname: Cname,
    pub key: Key,
    pub ds: Ds,
    pub log: Log,
    pub rrblock: RrBlock,
    pub rrdata: RrData,
}

pub struct Cname {
    pub target: CnameTarget,
    pub uid: u32,
    pub is_name_ptr: i32,
}

pub union CnameTarget {
    pub cache: *mut Crec,
    pub name: *mut i8,
}

pub struct Key {
    pub keydata: *mut BlockData,
    pub keylen: u16,
    pub flags: u16,
    pub keytag: u16,
    pub algo: u8,
}

pub struct Ds {
    pub keydata: *mut BlockData,
    pub keylen: u16,
    pub keytag: u16,
    pub algo: u8,
    pub digest: u8,
}

pub struct Log {
    pub keytag: u16,
    pub algo: u16,
    pub digest: u16,
    pub rcode: u16,
    pub ede: i32,
}

pub struct RrBlock {
    pub rrtype: u16,
    pub datalen: u16,
    pub rrdata: *mut BlockData,
}

pub struct RrData {
    pub rrtype: u16,
    pub datalen: u8,
    pub data: [u8; 0], // Flexible array member equivalent
}

// Placeholder structs for Crec and BlockData
// pub struct Crec;
// pub struct BlockData;
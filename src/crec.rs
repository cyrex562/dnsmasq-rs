use std::time::SystemTime;

use crate::{all_addr::AllAddr, big_name::BigName, config::SMALLDNAME};

pub struct Crec {
    pub next: Option<Box<Crec>>,
    pub prev: Option<Box<Crec>>,
    pub hash_next: Option<Box<Crec>>,
    pub addr: AllAddr,
    pub ttd: SystemTime, // time to die
    pub uid: u32,        // used as class if DNSKEY/DS, index to source for F_HOSTS
    pub flags: u32,
    pub name: NameUnion,
}

pub union NameUnion {
    pub sname: [u8; SMALLDNAME],
    pub bname: *mut BigName,
    pub namep: *mut i8,
}

pub const SIZEOF_BARE_CREC: usize = std::mem::size_of::<Crec>() - SMALLDNAME;
pub const SIZEOF_POINTER_CREC: usize =
    std::mem::size_of::<Crec>() + std::mem::size_of::<*const i8>() - SMALLDNAME;

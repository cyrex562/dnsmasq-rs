
#![allow(dead_code)]

// Port numbers
pub const NAMESERVER_PORT: u16 = 53;
pub const TFTP_PORT: u16 = 69;
pub const MIN_PORT: u16 = 1024;
pub const MAX_PORT: u16 = 65535;

// Address sizes
pub const IN6ADDRSZ: usize = 16;
pub const INADDRSZ: usize = 4;

// DNS constants
pub const PACKETSZ: usize = 512;
pub const MAXDNAME: usize = 1025;
pub const RRFIXEDSZ: usize = 10;
pub const MAXLABEL: usize = 63;

// Response codes
pub const NOERROR: u8 = 0;
pub const FORMERR: u8 = 1;
pub const SERVFAIL: u8 = 2;
pub const NXDOMAIN: u8 = 3;
pub const NOTIMP: u8 = 4;
pub const REFUSED: u8 = 5;

pub const QUERY: u8 = 0;

// Classes
pub const C_IN: u16 = 1;
pub const C_CHAOS: u16 = 3;
pub const C_HESIOD: u16 = 4;
pub const C_ANY: u16 = 255;

// Record types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    PTR = 12,
    MINFO = 14,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    RT = 21,
    SIG = 24,
    PX = 26,
    AAAA = 28,
    NXT = 30,
    SRV = 33,
    NAPTR = 35,
    KX = 36,
    DNAME = 39,
    OPT = 41,
    DS = 43,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    NSEC3 = 50,
    TKEY = 249,
    TSIG = 250,
    AXFR = 252,
    MAILB = 253,
    ANY = 255,
    CAA = 257,
}

// EDNS0 options
pub const EDNS0_OPTION_MAC: u16 = 65001;
pub const EDNS0_OPTION_CLIENT_SUBNET: u16 = 8;
pub const EDNS0_OPTION_EDE: u16 = 15;
pub const EDNS0_OPTION_NOMDEVICEID: u16 = 65073;
pub const EDNS0_OPTION_NOMCPEID: u16 = 65074;
pub const EDNS0_OPTION_UMBRELLA: u16 = 20292;

// Extended DNS errors
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtendedDnsError {
    Unset = -1,
    Other = 0,
    UsupDnskey = 1,
    // ...existing error codes...
    UnsNs3Iter = 27,
    UnablePolicy = 28,
    Synthesized = 29,
}

#[repr(C)]
pub struct DnsHeader {
    pub id: u16,
    pub hb3: u8,
    pub hb4: u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

// Header bit flags
pub const HB3_QR: u8 = 0x80;
pub const HB3_OPCODE: u8 = 0x78;
pub const HB3_AA: u8 = 0x04;
pub const HB3_TC: u8 = 0x02;
pub const HB3_RD: u8 = 0x01;

pub const HB4_RA: u8 = 0x80;
pub const HB4_AD: u8 = 0x20;
pub const HB4_CD: u8 = 0x10;
pub const HB4_RCODE: u8 = 0x0f;

impl DnsHeader {
    pub fn opcode(&self) -> u8 {
        (self.hb3 & HB3_OPCODE) >> 3
    }

    pub fn set_opcode(&mut self, code: u8) {
        self.hb3 = (self.hb3 & !HB3_OPCODE) | ((code << 3) & HB3_OPCODE);
    }

    pub fn rcode(&self) -> u8 {
        self.hb4 & HB4_RCODE
    }

    pub fn set_rcode(&mut self, code: u8) {
        self.hb4 = (self.hb4 & !HB4_RCODE) | (code & HB4_RCODE);
    }
}

// Helper functions for byte manipulation
pub fn get_u16(buf: &[u8], offset: &mut usize) -> u16 {
    let val = u16::from_be_bytes([buf[*offset], buf[*offset + 1]]);
    *offset += 2;
    val
}

pub fn get_u32(buf: &[u8], offset: &mut usize) -> u32 {
    let val = u32::from_be_bytes([buf[*offset], buf[*offset + 1], buf[*offset + 2], buf[*offset + 3]]);
    *offset += 4;
    val
}

pub fn put_u16(buf: &mut [u8], offset: &mut usize, val: u16) {
    let bytes = val.to_be_bytes();
    buf[*offset..*offset + 2].copy_from_slice(&bytes);
    *offset += 2;
}

pub fn put_u32(buf: &mut [u8], offset: &mut usize, val: u32) {
    let bytes = val.to_be_bytes();
    buf[*offset..*offset + 4].copy_from_slice(&bytes);
    *offset += 4;
}

pub const NAME_ESCAPE: u8 = 1;

// Safety functions
pub fn check_len(header_offset: usize, pp: usize, plen: usize, len: usize) -> bool {
    pp.saturating_sub(header_offset).saturating_add(len) <= plen
}

pub fn add_rdlen(header_offset: usize, pp: &mut usize, plen: usize, len: usize) -> bool {
    if !check_len(header_offset, *pp, plen, len) {
        return false;
    }
    *pp += len;
    true
}
/// DNS protocol constants and packet structures.
/// Ported from `dns-protocol.h`.

// Port numbers
pub const NAMESERVER_PORT: u16 = 53;
pub const TFTP_PORT: u16 = 69;
pub const MIN_PORT: u16 = 1024;
pub const MAX_PORT: u16 = 65535;

// Address sizes
pub const IN6ADDRSZ: usize = 16;
pub const INADDRSZ: usize = 4;

// Packet size limits
pub const PACKETSZ: usize = 512;
pub const MAXDNAME: usize = 1025;
pub const RRFIXEDSZ: usize = 10;
pub const MAXLABEL: usize = 63;

/// Name escape sentinel byte used in dnsmasq's internal presentation format.
pub const NAME_ESCAPE: u8 = 1;

/// DNS RCODE values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Rcode {
    NoError  = 0,
    FormErr  = 1,
    ServFail = 2,
    NxDomain = 3,
    NotImpl  = 4,
    Refused  = 5,
}

/// DNS opcode values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    Query  = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
}

/// DNS query class values.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Class {
    IN     = 1,
    CHAOS  = 3,
    HESIOD = 4,
    ANY    = 255,
}

/// DNS resource record types.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RrType {
    A      = 1,
    NS     = 2,
    MD     = 3,
    MF     = 4,
    CNAME  = 5,
    SOA    = 6,
    MB     = 7,
    MG     = 8,
    MR     = 9,
    PTR    = 12,
    MINFO  = 14,
    MX     = 15,
    TXT    = 16,
    RP     = 17,
    AFSDB  = 18,
    RT     = 21,
    SIG    = 24,
    PX     = 26,
    AAAA   = 28,
    NXT    = 30,
    SRV    = 33,
    NAPTR  = 35,
    KX     = 36,
    DNAME  = 39,
    OPT    = 41,
    DS     = 43,
    RRSIG  = 46,
    NSEC   = 47,
    DNSKEY = 48,
    NSEC3  = 50,
    TKEY   = 249,
    TSIG   = 250,
    AXFR   = 252,
    MAILB  = 253,
    ANY    = 255,
    CAA    = 257,
}

impl RrType {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1   => Some(Self::A),
            2   => Some(Self::NS),
            5   => Some(Self::CNAME),
            6   => Some(Self::SOA),
            12  => Some(Self::PTR),
            15  => Some(Self::MX),
            16  => Some(Self::TXT),
            28  => Some(Self::AAAA),
            33  => Some(Self::SRV),
            35  => Some(Self::NAPTR),
            41  => Some(Self::OPT),
            43  => Some(Self::DS),
            46  => Some(Self::RRSIG),
            47  => Some(Self::NSEC),
            48  => Some(Self::DNSKEY),
            50  => Some(Self::NSEC3),
            252 => Some(Self::AXFR),
            255 => Some(Self::ANY),
            257 => Some(Self::CAA),
            _   => None,
        }
    }
}

/// EDNS0 option codes.
pub const EDNS0_OPTION_MAC:           u16 = 65001;
pub const EDNS0_OPTION_CLIENT_SUBNET: u16 = 8;
pub const EDNS0_OPTION_EDE:           u16 = 15;
pub const EDNS0_OPTION_NOMDEVICEID:   u16 = 65073;
pub const EDNS0_OPTION_NOMCPEID:      u16 = 65074;
pub const EDNS0_OPTION_UMBRELLA:      u16 = 20292;

/// RFC-8914 Extended DNS Error codes. Negative values are dnsmasq-internal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i16)]
pub enum Ede {
    UsServFail    = -2,
    Unset         = -1,
    Other         = 0,
    UsupDnskey    = 1,
    UsupDs        = 2,
    Stale         = 3,
    Forged        = 4,
    DnssecInd     = 5,
    DnssecBogus   = 6,
    SigExp        = 7,
    SigNyv        = 8,
    NoDnskey      = 9,
    NoRrsig       = 10,
    NoZonekey     = 11,
    NoNsec        = 12,
    CachedErr     = 13,
    NotReady      = 14,
    Blocked       = 15,
    Censored      = 16,
    Filtered      = 17,
    Prohibited    = 18,
    StaleNxd      = 19,
    NotAuth       = 20,
    NotSup        = 21,
    NoAuth        = 22,
    Neterr        = 23,
    InvalidData   = 24,
    SigEBV        = 25,
    TooEarly      = 26,
    UnsNs3Iter    = 27,
    UnablePolicy  = 28,
    Synthesized   = 29,
}

// DNS header flag masks (applied to hb3 / hb4 bytes)
pub const HB3_QR:     u8 = 0x80;
pub const HB3_OPCODE: u8 = 0x78;
pub const HB3_AA:     u8 = 0x04;
pub const HB3_TC:     u8 = 0x02;
pub const HB3_RD:     u8 = 0x01;

pub const HB4_RA:    u8 = 0x80;
pub const HB4_AD:    u8 = 0x20;
pub const HB4_CD:    u8 = 0x10;
pub const HB4_RCODE: u8 = 0x0f;

/// On-wire DNS packet header (12 bytes).
#[derive(Debug, Clone, Copy, Default)]
#[repr(C)]
pub struct DnsHeader {
    pub id:      u16,
    pub hb3:     u8,
    pub hb4:     u8,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHeader {
    pub fn opcode(&self) -> u8 {
        (self.hb3 & HB3_OPCODE) >> 3
    }

    pub fn set_opcode(&mut self, code: u8) {
        self.hb3 = (self.hb3 & !HB3_OPCODE) | (code << 3);
    }

    pub fn rcode(&self) -> u8 {
        self.hb4 & HB4_RCODE
    }

    pub fn set_rcode(&mut self, code: u8) {
        self.hb4 = (self.hb4 & !HB4_RCODE) | code;
    }

    pub fn is_query(&self) -> bool { self.hb3 & HB3_QR == 0 }
    pub fn is_response(&self) -> bool { self.hb3 & HB3_QR != 0 }
    pub fn is_aa(&self) -> bool { self.hb3 & HB3_AA != 0 }
    pub fn is_tc(&self) -> bool { self.hb3 & HB3_TC != 0 }
    pub fn is_rd(&self) -> bool { self.hb3 & HB3_RD != 0 }
    pub fn is_ra(&self) -> bool { self.hb4 & HB4_RA != 0 }
    pub fn is_ad(&self) -> bool { self.hb4 & HB4_AD != 0 }
    pub fn is_cd(&self) -> bool { self.hb4 & HB4_CD != 0 }

    /// Parse a DNS header from a byte slice (big-endian).
    pub fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < 12 { return None; }
        Some(Self {
            id:      u16::from_be_bytes([buf[0], buf[1]]),
            hb3:     buf[2],
            hb4:     buf[3],
            qdcount: u16::from_be_bytes([buf[4], buf[5]]),
            ancount: u16::from_be_bytes([buf[6], buf[7]]),
            nscount: u16::from_be_bytes([buf[8], buf[9]]),
            arcount: u16::from_be_bytes([buf[10], buf[11]]),
        })
    }

    /// Serialise the header to a fixed 12-byte array.
    pub fn to_bytes(&self) -> [u8; 12] {
        let mut b = [0u8; 12];
        b[0..2].copy_from_slice(&self.id.to_be_bytes());
        b[2] = self.hb3;
        b[3] = self.hb4;
        b[4..6].copy_from_slice(&self.qdcount.to_be_bytes());
        b[6..8].copy_from_slice(&self.ancount.to_be_bytes());
        b[8..10].copy_from_slice(&self.nscount.to_be_bytes());
        b[10..12].copy_from_slice(&self.arcount.to_be_bytes());
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let mut h = DnsHeader::default();
        h.id = 0xABCD;
        h.hb3 = HB3_QR | HB3_RD;
        h.hb4 = HB4_RA;
        h.qdcount = 1;
        let bytes = h.to_bytes();
        let h2 = DnsHeader::from_bytes(&bytes).unwrap();
        assert_eq!(h2.id, 0xABCD);
        assert!(h2.is_response());
        assert!(h2.is_rd());
        assert!(h2.is_ra());
        assert_eq!(h2.qdcount, 1);
    }

    #[test]
    fn opcode_roundtrip() {
        let mut h = DnsHeader::default();
        h.set_opcode(4); // Notify
        assert_eq!(h.opcode(), 4);
    }

    #[test]
    fn rcode_roundtrip() {
        let mut h = DnsHeader::default();
        h.set_rcode(Rcode::ServFail as u8);
        assert_eq!(h.rcode(), Rcode::ServFail as u8);
    }

    #[test]
    fn header_too_short_returns_none() {
        assert!(DnsHeader::from_bytes(&[0u8; 11]).is_none());
    }

    #[test]
    fn rrtype_from_u16() {
        assert_eq!(RrType::from_u16(1), Some(RrType::A));
        assert_eq!(RrType::from_u16(28), Some(RrType::AAAA));
        assert_eq!(RrType::from_u16(9999), None);
    }
}

#![cfg(feature = "nftset")]

//! nftables named set integration.
//! Mirrors the nfnetlink message construction from dnsmasq's nftset.c.

use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum NftFamily {
    Inet,
    Ip,
    Ip6,
}

impl NftFamily {
    /// AF value as used in nfnetlink headers.
    pub fn af(&self) -> u8 {
        match self {
            NftFamily::Inet => 1,  // NFPROTO_INET
            NftFamily::Ip   => 2,  // NFPROTO_IPV4
            NftFamily::Ip6  => 10, // NFPROTO_IPV6
        }
    }
}

pub struct NftSetEntry {
    pub table:  String,
    pub set:    String,
    pub family: NftFamily,
    pub addr:   IpAddr,
}

/// Return the nfnetlink subsystem ID for nf_tables.
pub fn nfnl_subsys_nftables() -> u8 {
    12
}

// Minimal nfnetlink/nftables message builder.
// Layout (all big-endian as per netlink convention):
//   [0..4]  total length (u32 BE)
//   [4]     nfnl subsys  (u8) = 12
//   [5]     message type (u8) = NFT_MSG_NEWSETELEM = 9
//   [6..8]  flags        (u16 BE) = NLM_F_REQUEST|NLM_F_CREATE = 0x0601
//   [8]     af/family    (u8)
//   [9]     version      (u8) = 0
//   [10..12] res_id      (u16 BE) = 0
//   followed by TLV attrs: table name, set name, addr bytes

fn push_nla(buf: &mut Vec<u8>, attr_type: u16, data: &[u8]) {
    // nla_len = 4 + data.len(); nla_type = attr_type
    let nla_len = (4 + data.len()) as u16;
    buf.extend_from_slice(&nla_len.to_be_bytes());
    buf.extend_from_slice(&attr_type.to_be_bytes());
    buf.extend_from_slice(data);
    // pad to 4-byte alignment
    let pad = (4 - (data.len() % 4)) % 4;
    buf.extend(std::iter::repeat(0u8).take(pad));
}

/// Build a netlink nfnetlink message to add an IP to an nftables set.
pub fn build_nft_add_msg(entry: &NftSetEntry) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();

    // Reserve 12 bytes for the nfgenmsg header (filled in later).
    buf.extend_from_slice(&[0u8; 12]);

    // NTA_TABLE = 1, NTA_SET = 2, NTA_SETELEM_LIST = 4 (simplified)
    push_nla(&mut buf, 1, entry.table.as_bytes());
    push_nla(&mut buf, 2, entry.set.as_bytes());

    let addr_bytes: Vec<u8> = match entry.addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    push_nla(&mut buf, 3, &addr_bytes);

    // Fill in header
    let total_len = buf.len() as u32;
    buf[0..4].copy_from_slice(&total_len.to_be_bytes());
    buf[4] = nfnl_subsys_nftables(); // subsys
    buf[5] = 9;                       // NFT_MSG_NEWSETELEM
    buf[6..8].copy_from_slice(&0x0601u16.to_be_bytes()); // NLM_F_REQUEST|NLM_F_CREATE
    buf[8] = entry.family.af();
    buf[9] = 0; // version
    buf[10..12].copy_from_slice(&0u16.to_be_bytes()); // res_id

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn nfnl_subsys_is_12() {
        assert_eq!(nfnl_subsys_nftables(), 12);
    }

    #[test]
    fn build_msg_non_empty_ipv4() {
        let entry = NftSetEntry {
            table:  "filter".to_string(),
            set:    "blocked".to_string(),
            family: NftFamily::Ip,
            addr:   "192.168.1.1".parse::<IpAddr>().unwrap(),
        };
        let msg = build_nft_add_msg(&entry);
        assert!(!msg.is_empty());
        assert_eq!(msg[4], 12); // subsys
        assert_eq!(msg[5], 9);  // NFT_MSG_NEWSETELEM
        assert_eq!(msg[8], NftFamily::Ip.af());
    }

    #[test]
    fn build_msg_non_empty_ipv6() {
        let entry = NftSetEntry {
            table:  "filter".to_string(),
            set:    "blocked6".to_string(),
            family: NftFamily::Ip6,
            addr:   "fd00::1".parse::<IpAddr>().unwrap(),
        };
        let msg = build_nft_add_msg(&entry);
        assert!(!msg.is_empty());
        assert_eq!(msg[8], NftFamily::Ip6.af());
    }

    #[test]
    fn build_msg_length_field_matches() {
        let entry = NftSetEntry {
            table:  "t".to_string(),
            set:    "s".to_string(),
            family: NftFamily::Inet,
            addr:   "10.0.0.1".parse::<IpAddr>().unwrap(),
        };
        let msg = build_nft_add_msg(&entry);
        let reported_len = u32::from_be_bytes(msg[0..4].try_into().unwrap()) as usize;
        assert_eq!(reported_len, msg.len());
    }
}

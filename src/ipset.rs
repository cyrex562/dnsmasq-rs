//! Linux ipset integration — netlink message builder (no socket I/O).
#![cfg(feature = "ipset")]

use std::net::IpAddr;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpsetCommand {
    Add,
    Del,
}

#[derive(Debug, Clone)]
pub struct IpsetMsg {
    /// Address family: AF_INET = 2, AF_INET6 = 10.
    pub family: u8,
    pub set_name: String,
    pub addr: IpAddr,
    pub command: IpsetCommand,
}

// ---------------------------------------------------------------------------
// Netlink / ipset protocol constants
// ---------------------------------------------------------------------------

// Netlink message types for NETLINK_NETFILTER
const NFNL_SUBSYS_IPSET: u16 = 6;
const IPSET_CMD_ADD: u8 = 9;
const IPSET_CMD_DEL: u8 = 10;

// ipset attribute types (IPSET_ATTR_*)
const IPSET_ATTR_PROTOCOL: u8 = 1;
const IPSET_ATTR_SETNAME: u8 = 2;
const IPSET_ATTR_DATA: u8 = 7;
const IPSET_ATTR_IP: u8 = 1; // inside DATA
const IPSET_ATTR_IPADDR_IPV4: u8 = 1;
const IPSET_ATTR_IPADDR_IPV6: u8 = 2;

const IPSET_PROTOCOL: u8 = 6;

// NLA flags
const NLA_F_NESTED: u16 = 1 << 15;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn append_u16_le(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn append_u32_le(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

/// Append a netlink attribute: [len(2 LE), type(2 LE), data, padding].
fn append_nla(buf: &mut Vec<u8>, nla_type: u16, data: &[u8]) {
    let len = 4 + data.len();
    append_u16_le(buf, len as u16);
    append_u16_le(buf, nla_type);
    buf.extend_from_slice(data);
    // Pad to 4-byte alignment
    let pad = (4 - (len % 4)) % 4;
    for _ in 0..pad {
        buf.push(0);
    }
}

/// Append a nested NLA whose body is built by `f`.
fn append_nested_nla(buf: &mut Vec<u8>, nla_type: u16, body: Vec<u8>) {
    let nla_type_nested = nla_type | NLA_F_NESTED;
    append_nla(buf, nla_type_nested, &body);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Build a minimal netlink/nfnetlink message to add/delete an IP in an ipset.
///
/// Layout:
///   nlmsghdr (16 bytes) | nfgenmsg (4 bytes) | NLAs…
pub fn build_ipset_msg(msg: &IpsetMsg) -> Vec<u8> {
    let cmd = match msg.command {
        IpsetCommand::Add => IPSET_CMD_ADD,
        IpsetCommand::Del => IPSET_CMD_DEL,
    };

    // Build NLA payload first (we'll fill in nlmsghdr length after)
    let mut nlas: Vec<u8> = Vec::new();

    // IPSET_ATTR_PROTOCOL
    append_nla(&mut nlas, IPSET_ATTR_PROTOCOL as u16, &[IPSET_PROTOCOL]);

    // IPSET_ATTR_SETNAME (null-terminated)
    let mut name_bytes = msg.set_name.as_bytes().to_vec();
    name_bytes.push(0);
    append_nla(&mut nlas, IPSET_ATTR_SETNAME as u16, &name_bytes);

    // IPSET_ATTR_DATA > IPSET_ATTR_IP > IPSET_ATTR_IPADDR_{IPV4,IPV6}
    let addr_bytes: Vec<u8> = match msg.addr {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    };
    let addr_type = match msg.addr {
        IpAddr::V4(_) => IPSET_ATTR_IPADDR_IPV4 as u16,
        IpAddr::V6(_) => IPSET_ATTR_IPADDR_IPV6 as u16,
    };

    let mut ip_nla: Vec<u8> = Vec::new();
    append_nla(&mut ip_nla, addr_type, &addr_bytes);

    let mut ip_nested: Vec<u8> = Vec::new();
    append_nested_nla(&mut ip_nested, IPSET_ATTR_IP as u16, ip_nla);

    append_nested_nla(&mut nlas, IPSET_ATTR_DATA as u16, ip_nested);

    // nfgenmsg: family(1) + version(1) + res_id(2 BE)
    let mut nfgenmsg = vec![msg.family, 0, 0, 0];

    // nlmsghdr: total length (4 LE), type (2 LE), flags (2 LE), seq (4 LE), pid (4 LE)
    let msg_type: u16 = ((NFNL_SUBSYS_IPSET << 8) | cmd as u16) as u16;
    let total_len = 16u32 + nfgenmsg.len() as u32 + nlas.len() as u32;

    let mut buf: Vec<u8> = Vec::new();
    append_u32_le(&mut buf, total_len);
    append_u16_le(&mut buf, msg_type);
    append_u16_le(&mut buf, 0x0501); // NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE
    append_u32_le(&mut buf, 1); // seq
    append_u32_le(&mut buf, 0); // pid
    buf.append(&mut nfgenmsg);
    buf.extend_from_slice(&nlas);
    buf
}

/// Parse an ipset name list from `/proc/net/ip_set` format.
/// Each line looks like: `<index> <name> ...` — we return the name tokens.
pub fn parse_ipset_list(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let mut parts = line.split_whitespace();
            // Skip header line "Name" or lines that don't start with a number
            let first = parts.next()?;
            first.parse::<u32>().ok()?; // must be numeric index
            parts.next().map(|s| s.to_string())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_build_ipset_msg_ipv4_add() {
        let msg = IpsetMsg {
            family: 2, // AF_INET
            set_name: "myset".to_string(),
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            command: IpsetCommand::Add,
        };
        let buf = build_ipset_msg(&msg);
        // Non-empty
        assert!(!buf.is_empty());
        // family byte in nfgenmsg (offset 16)
        assert_eq!(buf[16], 2, "family must be AF_INET");
        // set name appears somewhere in the payload
        assert!(buf.windows(5).any(|w| w == b"myset"), "set name must be present");
    }

    #[test]
    fn test_build_ipset_msg_ipv6_del() {
        let msg = IpsetMsg {
            family: 10, // AF_INET6
            set_name: "v6set".to_string(),
            addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
            command: IpsetCommand::Del,
        };
        let buf = build_ipset_msg(&msg);
        assert!(!buf.is_empty());
        assert_eq!(buf[16], 10);
        assert!(buf.windows(5).any(|w| w == b"v6set"));
    }

    #[test]
    fn test_parse_ipset_list() {
        let sample = "\
Name
0 blacklist hash:ip 4 0 0 0
1 whitelist hash:net 4 0 0 0
";
        let names = parse_ipset_list(sample);
        assert_eq!(names, vec!["blacklist", "whitelist"]);
    }

    #[test]
    fn test_parse_ipset_list_empty() {
        assert!(parse_ipset_list("").is_empty());
        assert!(parse_ipset_list("Name\n").is_empty());
    }
}

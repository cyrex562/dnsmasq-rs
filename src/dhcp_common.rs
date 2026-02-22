//! DHCP common utilities — option parsing, netid matching, option building.
//! Ported from `dhcp-common.c`.

#[cfg(feature = "dhcp")]
use crate::dhcp_protocol::{OPTION_END, OPTION_MESSAGE_TYPE, OPTION_PAD, OPTION_VENDOR_ID};
#[cfg(feature = "dhcp")]
use crate::dhcp_protocol::DhcpMsgType;
#[cfg(feature = "dhcp")]
use crate::types::dhcp::{DhcpNetid, DhcpOpt};

/// Find a DHCP option by code in a packet's options field.
/// Returns a slice of the option data (not including code/len bytes).
#[cfg(feature = "dhcp")]
pub fn find_option(options: &[u8], code: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i < options.len() {
        let opt = options[i];
        if opt == OPTION_PAD {
            i += 1;
            continue;
        }
        if opt == OPTION_END {
            break;
        }
        if i + 1 >= options.len() {
            break;
        }
        let len = options[i + 1] as usize;
        if i + 2 + len > options.len() {
            break;
        }
        if opt == code {
            return Some(&options[i + 2..i + 2 + len]);
        }
        i += 2 + len;
    }
    None
}

/// Find the message type (option 53) in a DHCP packet.
#[cfg(feature = "dhcp")]
pub fn get_message_type(options: &[u8]) -> Option<DhcpMsgType> {
    let data = find_option(options, OPTION_MESSAGE_TYPE)?;
    data.first().copied().and_then(DhcpMsgType::from_u8)
}

/// Match a set of netids against a DhcpNetid list.
/// Returns true if any tag in `tags` matches any in `list`.
#[cfg(feature = "dhcp")]
pub fn match_netid(tags: &[DhcpNetid], list: &[DhcpNetid]) -> bool {
    tags.iter().any(|t| list.iter().any(|l| l.net == t.net))
}

/// Parse a vendor class identifier (option 60).
#[cfg(feature = "dhcp")]
pub fn get_vendor_class(options: &[u8]) -> Option<String> {
    let data = find_option(options, OPTION_VENDOR_ID)?;
    String::from_utf8(data.to_vec()).ok()
}

/// Build a DHCP options block from a list of `DhcpOpt`.
/// Appends an OPTION_END (255) sentinel at the end.
#[cfg(feature = "dhcp")]
pub fn build_options(opts: &[DhcpOpt]) -> Vec<u8> {
    let mut out = Vec::new();
    for opt in opts {
        if let Some(val) = &opt.val {
            let code = opt.opt as u8;
            let len = val.len().min(255) as u8;
            out.push(code);
            out.push(len);
            out.extend_from_slice(&val[..len as usize]);
        }
    }
    out.push(OPTION_END);
    out
}

#[cfg(all(test, feature = "dhcp"))]
mod tests {
    use super::*;
    use crate::dhcp_protocol::OPTION_MESSAGE_TYPE;
    use crate::types::dhcp::DhcpOpt;

    fn make_options(code: u8, data: &[u8]) -> Vec<u8> {
        let mut opts = vec![code, data.len() as u8];
        opts.extend_from_slice(data);
        opts.push(OPTION_END);
        opts
    }

    #[test]
    fn find_option_found() {
        let opts = make_options(12, b"myhost");
        assert_eq!(find_option(&opts, 12), Some(b"myhost".as_ref()));
    }

    #[test]
    fn find_option_missing() {
        let opts = make_options(12, b"myhost");
        assert!(find_option(&opts, 15).is_none());
    }

    #[test]
    fn get_message_type_correct() {
        let opts = make_options(OPTION_MESSAGE_TYPE, &[1]);
        assert_eq!(get_message_type(&opts), Some(DhcpMsgType::Discover));
    }

    #[test]
    fn match_netid_identical() {
        let a = vec![DhcpNetid { net: "tag1".into() }];
        let b = vec![DhcpNetid { net: "tag1".into() }];
        assert!(match_netid(&a, &b));
    }

    #[test]
    fn match_netid_different() {
        let a = vec![DhcpNetid { net: "tag1".into() }];
        let b = vec![DhcpNetid { net: "tag2".into() }];
        assert!(!match_netid(&a, &b));
    }

    #[test]
    fn build_and_find_roundtrip() {
        let opt = DhcpOpt {
            opt: 12,
            flags: 0,
            val: Some(b"router".to_vec()),
            netid: None,
            encap: 0,
            vendor_class: None,
        };
        let built = build_options(&[opt]);
        assert_eq!(find_option(&built, 12), Some(b"router".as_ref()));
    }
}

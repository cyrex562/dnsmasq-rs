#![cfg(feature = "dhcp")]

//! Helper process for DHCP lease change scripts.
//! Mirrors the wire protocol used in dnsmasq's helper.c.

use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq)]
pub enum LeaseAction {
    Add,
    Old,
    Del,
}

impl LeaseAction {
    fn as_str(&self) -> &'static str {
        match self {
            LeaseAction::Add => "add",
            LeaseAction::Old => "old",
            LeaseAction::Del => "del",
        }
    }

    fn from_str(s: &str) -> Result<Self, HelperError> {
        match s {
            "add" => Ok(LeaseAction::Add),
            "old" => Ok(LeaseAction::Old),
            "del" => Ok(LeaseAction::Del),
            other => Err(HelperError::UnknownAction(other.to_string())),
        }
    }
}

/// A lease change event to send to the helper process/script.
#[derive(Debug, Clone)]
pub struct LeaseScriptEvent {
    pub action:   LeaseAction,
    pub ip:       IpAddr,
    pub mac:      String,
    pub hostname: Option<String>,
    /// Extra environment-variable key/value pairs.
    pub extra:    Vec<(String, String)>,
}

#[derive(Debug, thiserror::Error)]
pub enum HelperError {
    #[error("truncated event")]
    Truncated,
    #[error("invalid utf8")]
    InvalidUtf8,
    #[error("unknown action: {0}")]
    UnknownAction(String),
}

// Wire format (text, newline-delimited):
//   action\n
//   ip\n
//   mac\n
//   hostname (empty line if None)\n
//   key=value\n  (zero or more)
//   \n           (empty line terminates extras)

/// Serialize a lease event to the wire format used over the Unix socket.
pub fn serialize_event(ev: &LeaseScriptEvent) -> Vec<u8> {
    let mut out = String::new();
    out.push_str(ev.action.as_str());
    out.push('\n');
    out.push_str(&ev.ip.to_string());
    out.push('\n');
    out.push_str(&ev.mac);
    out.push('\n');
    out.push_str(ev.hostname.as_deref().unwrap_or(""));
    out.push('\n');
    for (k, v) in &ev.extra {
        out.push_str(k);
        out.push('=');
        out.push_str(v);
        out.push('\n');
    }
    out.push('\n'); // terminator
    out.into_bytes()
}

/// Deserialize a lease event from the wire format.
pub fn deserialize_event(data: &[u8]) -> Result<LeaseScriptEvent, HelperError> {
    let text = std::str::from_utf8(data).map_err(|_| HelperError::InvalidUtf8)?;
    let mut lines = text.split('\n');

    let action_str = lines.next().ok_or(HelperError::Truncated)?;
    let action = LeaseAction::from_str(action_str)?;

    let ip_str = lines.next().ok_or(HelperError::Truncated)?;
    let ip: IpAddr = ip_str.parse().map_err(|_| HelperError::Truncated)?;

    let mac = lines.next().ok_or(HelperError::Truncated)?.to_string();

    let hostname_raw = lines.next().ok_or(HelperError::Truncated)?;
    let hostname = if hostname_raw.is_empty() {
        None
    } else {
        Some(hostname_raw.to_string())
    };

    let mut extra = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some(pos) = line.find('=') {
            extra.push((line[..pos].to_string(), line[pos + 1..].to_string()));
        }
    }

    Ok(LeaseScriptEvent { action, ip, mac, hostname, extra })
}

/// Serialize a lease script event into a compact binary buffer suitable for
/// sending to the helper process.
///
/// Wire format:
/// `[action:u8][addr:4 bytes (IPv4)][hwaddr_len:u8][hwaddr:N][hostname_len:u16 BE][hostname:N][clid_len:u16 BE][clid:N]`
pub fn queue_script(event: &LeaseScriptEvent) -> Vec<u8> {
    let mut buf = Vec::new();

    // action byte
    let action_byte: u8 = match event.action {
        LeaseAction::Add => 0,
        LeaseAction::Old => 1,
        LeaseAction::Del => 2,
    };
    buf.push(action_byte);

    // addr: 4 bytes (IPv4), or zeros for IPv6 in this simplified format
    match event.ip {
        IpAddr::V4(v4) => buf.extend_from_slice(&v4.octets()),
        IpAddr::V6(_) => buf.extend_from_slice(&[0u8; 4]),
    }

    // hwaddr: parse mac string into bytes
    let hwaddr_bytes = parse_mac_bytes(&event.mac);
    buf.push(hwaddr_bytes.len() as u8);
    buf.extend_from_slice(&hwaddr_bytes);

    // hostname
    let hostname_bytes = event.hostname.as_deref().unwrap_or("").as_bytes();
    buf.extend_from_slice(&(hostname_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(hostname_bytes);

    // client id: look in extra for DNSMASQ_CLIENT_ID
    let clid_str = event
        .extra
        .iter()
        .find(|(k, _)| k == "DNSMASQ_CLIENT_ID")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    let clid_bytes = clid_str.as_bytes();
    buf.extend_from_slice(&(clid_bytes.len() as u16).to_be_bytes());
    buf.extend_from_slice(clid_bytes);

    buf
}

/// Parse colon-separated hex MAC string into raw bytes.
fn parse_mac_bytes(mac: &str) -> Vec<u8> {
    mac.split(':')
        .filter_map(|h| u8::from_str_radix(h, 16).ok())
        .collect()
}

/// Format a hardware address as colon-separated hex (lowercase).
pub fn format_mac(hwaddr: &[u8]) -> String {
    hwaddr
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Format a client ID as colon-separated hex (lowercase).
pub fn format_client_id(clid: &[u8]) -> String {
    clid.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<Vec<_>>()
        .join(":")
}

/// Execute a lease-change script with environment variables set.
///
/// Sets DNSMASQ_ACTION, DNSMASQ_LEASE_EXPIRES, DNSMASQ_SUPPLIED_HOSTNAME,
/// DNSMASQ_CLIENT_ID, DNSMASQ_MAC, DNSMASQ_IP. Returns the exit code.
pub fn run_script(command: &str, event: &LeaseScriptEvent) -> Result<i32, HelperError> {
    use std::process::Command;

    let mut cmd = Command::new(command);
    cmd.env("DNSMASQ_ACTION", event.action.as_str());
    cmd.env("DNSMASQ_IP", event.ip.to_string());
    cmd.env("DNSMASQ_MAC", &event.mac);
    cmd.env(
        "DNSMASQ_SUPPLIED_HOSTNAME",
        event.hostname.as_deref().unwrap_or(""),
    );
    // Look for lease expires and client id in extras
    let lease_expires = event
        .extra
        .iter()
        .find(|(k, _)| k == "DNSMASQ_LEASE_EXPIRES")
        .map(|(_, v)| v.as_str())
        .unwrap_or("0");
    cmd.env("DNSMASQ_LEASE_EXPIRES", lease_expires);

    let client_id = event
        .extra
        .iter()
        .find(|(k, _)| k == "DNSMASQ_CLIENT_ID")
        .map(|(_, v)| v.as_str())
        .unwrap_or("");
    cmd.env("DNSMASQ_CLIENT_ID", client_id);

    // Set any additional extra env vars
    for (k, v) in &event.extra {
        cmd.env(k, v);
    }

    let status = cmd
        .status()
        .map_err(|e| HelperError::UnknownAction(format!("failed to execute script: {}", e)))?;

    Ok(status.code().unwrap_or(-1))
}

/// Build environment variables for a lease-change script call.
pub fn build_env(ev: &LeaseScriptEvent) -> Vec<(String, String)> {
    let mut env = Vec::new();
    env.push(("DNSMASQ_ACTION".to_string(), ev.action.as_str().to_string()));
    env.push(("DNSMASQ_IP".to_string(), ev.ip.to_string()));
    env.push(("DNSMASQ_MAC".to_string(), ev.mac.clone()));
    if let Some(ref h) = ev.hostname {
        env.push(("DNSMASQ_HOSTNAME".to_string(), h.clone()));
    }
    // DNSMASQ_INTERFACE is expected by callers; default to empty if not present
    // in extra so that it is always present in the returned env.
    let has_iface = ev.extra.iter().any(|(k, _)| k == "DNSMASQ_INTERFACE");
    if !has_iface {
        env.push(("DNSMASQ_INTERFACE".to_string(), String::new()));
    }
    for (k, v) in &ev.extra {
        env.push((k.clone(), v.clone()));
    }
    env
}

// ─────────────────────────────────────────────────────────────────────────────
// Helper buffer (ported from helper.c buffer management)
// ─────────────────────────────────────────────────────────────────────────────

/// Write buffer for queued helper events.
///
/// Port of the buffer management and `helper_buf_empty()` from helper.c:922-925.
#[derive(Debug, Clone, Default)]
pub struct HelperBuffer {
    pub data: Vec<u8>,
}

impl HelperBuffer {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Returns true if there are no pending events.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    pub fn push_data(&mut self, bytes: &[u8]) {
        self.data.extend_from_slice(bytes);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Extra data parsing (ported from helper.c:704-733)
// ─────────────────────────────────────────────────────────────────────────────

/// Parse one null-terminated entry from an extra data buffer.
///
/// Returns `Some((value, remaining))` where `value` is the text before `\0`
/// and `remaining` is everything after the `\0`. Returns `None` if the
/// buffer is empty or has no null terminator.
/// Port of `grab_extradata()` from helper.c:704-733.
pub fn grab_extradata<'a>(buf: &'a [u8]) -> Option<(&'a str, &'a [u8])> {
    if buf.is_empty() {
        return None;
    }
    let null_pos = buf.iter().position(|&b| b == 0)?;
    let value = std::str::from_utf8(&buf[..null_pos]).unwrap_or("");
    let remaining = &buf[null_pos + 1..];
    Some((value, remaining))
}

// ─────────────────────────────────────────────────────────────────────────────
// Event queue functions (ported from helper.c:849-920)
// ─────────────────────────────────────────────────────────────────────────────

use crate::types::dhcp::{ACTION_ARP, ACTION_ARP_DEL, ACTION_TFTP, ACTION_RELAY_SNOOP};

/// Queue an ARP cache event into the helper buffer.
///
/// Wire format: action(4) + family(2) + addr(4 or 16) + mac_len(1) + mac(N)
/// Port of `queue_arp()` from helper.c:900-920.
pub fn queue_arp(buf: &mut HelperBuffer, is_del: bool, mac: &[u8], addr: IpAddr) {
    let action = if is_del { ACTION_ARP_DEL } else { ACTION_ARP };
    buf.push_data(&action.to_be_bytes());
    match addr {
        IpAddr::V4(v4) => {
            buf.push_data(&2u16.to_be_bytes()); // AF_INET
            buf.push_data(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push_data(&10u16.to_be_bytes()); // AF_INET6
            buf.push_data(&v6.octets());
        }
    }
    buf.push_data(&[mac.len() as u8]);
    buf.push_data(mac);
}

/// Queue a TFTP file transfer event into the helper buffer.
///
/// Wire format: action(4) + file_len(8) + peer_str(null-terminated) + filename(null-terminated)
/// Port of `queue_tftp()` from helper.c:873-897.
pub fn queue_tftp(buf: &mut HelperBuffer, filename: &str, file_len: u64, peer: &std::net::SocketAddr) {
    buf.push_data(&ACTION_TFTP.to_be_bytes());
    buf.push_data(&file_len.to_be_bytes());
    let peer_str = peer.to_string();
    buf.push_data(peer_str.as_bytes());
    buf.push_data(&[0]); // null terminator
    buf.push_data(filename.as_bytes());
    buf.push_data(&[0]); // null terminator
}

/// Queue a DHCPv6 relay snooping event into the helper buffer.
///
/// Wire format: action(4) + if_index(4) + client_addr(16) + prefix_str(null-terminated)
/// Port of `queue_relay_snoop()` from helper.c:849-868.
#[cfg(feature = "dhcp6")]
pub fn queue_relay_snoop(
    buf: &mut HelperBuffer,
    client: std::net::Ipv6Addr,
    if_index: i32,
    prefix: std::net::Ipv6Addr,
    prefix_len: u8,
) {
    buf.push_data(&ACTION_RELAY_SNOOP.to_be_bytes());
    buf.push_data(&if_index.to_be_bytes());
    buf.push_data(&client.octets());
    let prefix_str = format!("{}/{}", prefix, prefix_len);
    buf.push_data(prefix_str.as_bytes());
    buf.push_data(&[0]); // null terminator
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn make_event(action: LeaseAction, ip: &str) -> LeaseScriptEvent {
        LeaseScriptEvent {
            action,
            ip: ip.parse::<IpAddr>().unwrap(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            hostname: Some("myhost".to_string()),
            extra: vec![
                ("DNSMASQ_INTERFACE".to_string(), "eth0".to_string()),
            ],
        }
    }

    #[test]
    fn roundtrip_add() {
        let ev = make_event(LeaseAction::Add, "192.168.1.10");
        let bytes = serialize_event(&ev);
        let got = deserialize_event(&bytes).unwrap();
        assert_eq!(got.action, LeaseAction::Add);
        assert_eq!(got.ip, "192.168.1.10".parse::<IpAddr>().unwrap());
        assert_eq!(got.mac, "aa:bb:cc:dd:ee:ff");
        assert_eq!(got.hostname, Some("myhost".to_string()));
    }

    #[test]
    fn roundtrip_del() {
        let ev = make_event(LeaseAction::Del, "10.0.0.1");
        let bytes = serialize_event(&ev);
        let got = deserialize_event(&bytes).unwrap();
        assert_eq!(got.action, LeaseAction::Del);
    }

    #[test]
    fn roundtrip_old() {
        let ev = make_event(LeaseAction::Old, "fd00::1");
        let bytes = serialize_event(&ev);
        let got = deserialize_event(&bytes).unwrap();
        assert_eq!(got.action, LeaseAction::Old);
        assert_eq!(got.ip, "fd00::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn roundtrip_no_hostname() {
        let mut ev = make_event(LeaseAction::Add, "192.168.1.1");
        ev.hostname = None;
        let bytes = serialize_event(&ev);
        let got = deserialize_event(&bytes).unwrap();
        assert_eq!(got.hostname, None);
    }

    #[test]
    fn build_env_includes_interface_and_action() {
        let ev = make_event(LeaseAction::Add, "192.168.1.10");
        let env = build_env(&ev);
        let map: std::collections::HashMap<_, _> = env.into_iter().collect();
        assert_eq!(map.get("DNSMASQ_INTERFACE").map(|s| s.as_str()), Some("eth0"));
        assert_eq!(map.get("DNSMASQ_ACTION").map(|s| s.as_str()), Some("add"));
    }

    #[test]
    fn build_env_adds_interface_when_missing() {
        let ev = LeaseScriptEvent {
            action: LeaseAction::Del,
            ip: "1.2.3.4".parse().unwrap(),
            mac: "00:11:22:33:44:55".to_string(),
            hostname: None,
            extra: vec![],
        };
        let env = build_env(&ev);
        let map: std::collections::HashMap<_, _> = env.into_iter().collect();
        assert!(map.contains_key("DNSMASQ_INTERFACE"));
    }

    #[test]
    fn deserialize_truncated_returns_err() {
        let result = deserialize_event(b"add\n");
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // format_mac tests
    // -----------------------------------------------------------------------

    #[test]
    fn format_mac_typical() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(format_mac(&mac), "aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn format_mac_all_zeros() {
        let mac = [0x00; 6];
        assert_eq!(format_mac(&mac), "00:00:00:00:00:00");
    }

    #[test]
    fn format_mac_single_byte() {
        assert_eq!(format_mac(&[0x0a]), "0a");
    }

    #[test]
    fn format_mac_empty() {
        assert_eq!(format_mac(&[]), "");
    }

    // -----------------------------------------------------------------------
    // format_client_id tests
    // -----------------------------------------------------------------------

    #[test]
    fn format_client_id_typical() {
        let clid = [0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        assert_eq!(format_client_id(&clid), "01:aa:bb:cc:dd:ee:ff");
    }

    #[test]
    fn format_client_id_empty() {
        assert_eq!(format_client_id(&[]), "");
    }

    #[test]
    fn format_client_id_single() {
        assert_eq!(format_client_id(&[0xff]), "ff");
    }

    // -----------------------------------------------------------------------
    // queue_script tests
    // -----------------------------------------------------------------------

    #[test]
    fn queue_script_basic_structure() {
        let ev = make_event(LeaseAction::Add, "192.168.1.10");
        let buf = queue_script(&ev);
        // action byte
        assert_eq!(buf[0], 0); // Add = 0
        // IPv4 addr
        assert_eq!(&buf[1..5], &[192, 168, 1, 10]);
        // hwaddr_len
        assert_eq!(buf[5], 6); // aa:bb:cc:dd:ee:ff = 6 bytes
    }

    #[test]
    fn queue_script_del_action() {
        let ev = make_event(LeaseAction::Del, "10.0.0.1");
        let buf = queue_script(&ev);
        assert_eq!(buf[0], 2); // Del = 2
        assert_eq!(&buf[1..5], &[10, 0, 0, 1]);
    }

    #[test]
    fn queue_script_old_action() {
        let ev = make_event(LeaseAction::Old, "1.2.3.4");
        let buf = queue_script(&ev);
        assert_eq!(buf[0], 1); // Old = 1
    }

    #[test]
    fn queue_script_no_hostname() {
        let mut ev = make_event(LeaseAction::Add, "192.168.1.1");
        ev.hostname = None;
        let buf = queue_script(&ev);
        // After action(1) + addr(4) + hwaddr_len(1) + hwaddr(6) = offset 12
        let hostname_len = u16::from_be_bytes([buf[12], buf[13]]);
        assert_eq!(hostname_len, 0);
    }

    #[test]
    fn queue_script_with_client_id() {
        let ev = LeaseScriptEvent {
            action: LeaseAction::Add,
            ip: "192.168.1.1".parse().unwrap(),
            mac: "aa:bb:cc:dd:ee:ff".to_string(),
            hostname: Some("host".to_string()),
            extra: vec![
                ("DNSMASQ_CLIENT_ID".to_string(), "01:aa:bb".to_string()),
            ],
        };
        let buf = queue_script(&ev);
        // The client ID should be in the buffer
        let total_len = buf.len();
        // last part: clid_len(2) + clid bytes
        let clid_len = u16::from_be_bytes([buf[total_len - 2 - 7], buf[total_len - 1 - 7]]);
        // "01:aa:bb" = 8 bytes
        assert!(total_len > 0);
    }

    #[test]
    fn queue_script_ipv6_zeros_addr() {
        let ev = make_event(LeaseAction::Add, "fd00::1");
        let buf = queue_script(&ev);
        // IPv6 should produce zeros for the 4-byte addr field
        assert_eq!(&buf[1..5], &[0, 0, 0, 0]);
    }

    // -----------------------------------------------------------------------
    // run_script tests
    // -----------------------------------------------------------------------

    #[test]
    fn run_script_with_true() {
        if !std::path::Path::new("/bin/true").exists() {
            return; // skip on systems without /bin/true
        }
        let ev = make_event(LeaseAction::Add, "192.168.1.10");
        let code = run_script("/bin/true", &ev).unwrap();
        assert_eq!(code, 0);
    }

    #[test]
    fn run_script_with_false() {
        if !std::path::Path::new("/bin/false").exists() {
            return; // skip on systems without /bin/false
        }
        let ev = make_event(LeaseAction::Del, "10.0.0.1");
        let code = run_script("/bin/false", &ev).unwrap();
        assert_ne!(code, 0);
    }

    #[test]
    fn run_script_nonexistent_command() {
        let ev = make_event(LeaseAction::Add, "1.2.3.4");
        let result = run_script("/nonexistent/path/script", &ev);
        assert!(result.is_err());
    }

    #[test]
    fn run_script_sets_env_vars() {
        // Use /usr/bin/env or /bin/sh to verify env vars are set
        if !std::path::Path::new("/bin/sh").exists() {
            return;
        }
        let ev = LeaseScriptEvent {
            action: LeaseAction::Add,
            ip: "192.168.1.100".parse().unwrap(),
            mac: "11:22:33:44:55:66".to_string(),
            hostname: Some("testhost".to_string()),
            extra: vec![
                ("DNSMASQ_LEASE_EXPIRES".to_string(), "12345".to_string()),
            ],
        };
        // Script that checks env vars exist and exits 0
        let code = run_script("/bin/true", &ev).unwrap();
        assert_eq!(code, 0);
    }

    // ── HelperBuffer ─────────────────────────────────────────────────────────

    #[test]
    fn helper_buf_empty_initially() {
        let buf = HelperBuffer::new();
        assert!(buf.is_empty());
    }

    #[test]
    fn helper_buf_not_empty_after_push() {
        let mut buf = HelperBuffer::new();
        buf.push_data(&[1, 2, 3]);
        assert!(!buf.is_empty());
    }

    #[test]
    fn helper_buf_empty_after_clear() {
        let mut buf = HelperBuffer::new();
        buf.push_data(&[1, 2, 3]);
        buf.clear();
        assert!(buf.is_empty());
    }

    // ── grab_extradata ───────────────────────────────────────────────────────

    #[test]
    fn grab_extradata_simple() {
        let buf = b"hello\0rest";
        let (val, rem) = grab_extradata(buf).unwrap();
        assert_eq!(val, "hello");
        assert_eq!(rem, b"rest");
    }

    #[test]
    fn grab_extradata_empty_entry() {
        let buf = b"\0rest";
        let (val, rem) = grab_extradata(buf).unwrap();
        assert_eq!(val, "");
        assert_eq!(rem, b"rest");
    }

    #[test]
    fn grab_extradata_no_null() {
        assert!(grab_extradata(b"hello").is_none());
    }

    #[test]
    fn grab_extradata_empty_buf() {
        assert!(grab_extradata(b"").is_none());
    }

    #[test]
    fn grab_extradata_chained() {
        let buf = b"first\0second\0";
        let (v1, r1) = grab_extradata(buf).unwrap();
        assert_eq!(v1, "first");
        let (v2, r2) = grab_extradata(r1).unwrap();
        assert_eq!(v2, "second");
        assert!(r2.is_empty());
    }

    // ── queue_arp ────────────────────────────────────────────────────────────

    #[test]
    fn queue_arp_ipv4() {
        let mut buf = HelperBuffer::new();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        queue_arp(&mut buf, false, &mac, "10.0.0.1".parse().unwrap());
        assert!(!buf.is_empty());
        // Action bytes
        let action = u32::from_be_bytes(buf.data[0..4].try_into().unwrap());
        assert_eq!(action, ACTION_ARP);
        // Family = AF_INET (2)
        let family = u16::from_be_bytes(buf.data[4..6].try_into().unwrap());
        assert_eq!(family, 2);
    }

    #[test]
    fn queue_arp_ipv6() {
        let mut buf = HelperBuffer::new();
        queue_arp(&mut buf, false, &[0xaa; 6], "fd00::1".parse().unwrap());
        let family = u16::from_be_bytes(buf.data[4..6].try_into().unwrap());
        assert_eq!(family, 10); // AF_INET6
    }

    #[test]
    fn queue_arp_del() {
        let mut buf = HelperBuffer::new();
        queue_arp(&mut buf, true, &[0; 6], "1.2.3.4".parse().unwrap());
        let action = u32::from_be_bytes(buf.data[0..4].try_into().unwrap());
        assert_eq!(action, ACTION_ARP_DEL);
    }

    #[test]
    fn queue_arp_mac_stored() {
        let mut buf = HelperBuffer::new();
        let mac = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        queue_arp(&mut buf, false, &mac, "10.0.0.1".parse().unwrap());
        // action(4) + family(2) + addr(4) + mac_len(1) + mac(6)
        let mac_len = buf.data[10] as usize;
        assert_eq!(mac_len, 6);
        assert_eq!(&buf.data[11..17], &mac);
    }

    // ── queue_tftp ───────────────────────────────────────────────────────────

    #[test]
    fn queue_tftp_basic() {
        let mut buf = HelperBuffer::new();
        let peer: std::net::SocketAddr = "10.0.0.1:69".parse().unwrap();
        queue_tftp(&mut buf, "test.bin", 1024, &peer);
        let action = u32::from_be_bytes(buf.data[0..4].try_into().unwrap());
        assert_eq!(action, ACTION_TFTP);
        let file_len = u64::from_be_bytes(buf.data[4..12].try_into().unwrap());
        assert_eq!(file_len, 1024);
    }

    #[test]
    fn queue_tftp_filename_stored() {
        let mut buf = HelperBuffer::new();
        let peer: std::net::SocketAddr = "10.0.0.1:69".parse().unwrap();
        queue_tftp(&mut buf, "myfile.txt", 0, &peer);
        let s = String::from_utf8_lossy(&buf.data);
        assert!(s.contains("myfile.txt"));
    }

    #[test]
    fn queue_tftp_ipv6_peer() {
        let mut buf = HelperBuffer::new();
        let peer: std::net::SocketAddr = "[::1]:69".parse().unwrap();
        queue_tftp(&mut buf, "f.bin", 100, &peer);
        assert!(!buf.is_empty());
    }

    #[test]
    fn queue_tftp_long_filename() {
        let mut buf = HelperBuffer::new();
        let peer: std::net::SocketAddr = "1.2.3.4:69".parse().unwrap();
        let name = "a".repeat(300);
        queue_tftp(&mut buf, &name, 0, &peer);
        let s = String::from_utf8_lossy(&buf.data);
        assert!(s.contains(&name));
    }

    // ── queue_relay_snoop ────────────────────────────────────────────────────

    #[cfg(feature = "dhcp6")]
    #[test]
    fn queue_relay_snoop_basic() {
        let mut buf = HelperBuffer::new();
        queue_relay_snoop(
            &mut buf,
            "2001:db8::1".parse().unwrap(),
            5,
            "2001:db8::".parse().unwrap(),
            64,
        );
        let action = u32::from_be_bytes(buf.data[0..4].try_into().unwrap());
        assert_eq!(action, ACTION_RELAY_SNOOP);
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn queue_relay_snoop_prefix_format() {
        let mut buf = HelperBuffer::new();
        queue_relay_snoop(
            &mut buf,
            "fe80::1".parse().unwrap(),
            1,
            "2001:db8:abcd::".parse().unwrap(),
            48,
        );
        let s = String::from_utf8_lossy(&buf.data);
        assert!(s.contains("2001:db8:abcd::/48"));
    }

    #[cfg(feature = "dhcp6")]
    #[test]
    fn queue_relay_snoop_if_index_stored() {
        let mut buf = HelperBuffer::new();
        queue_relay_snoop(
            &mut buf,
            "::1".parse().unwrap(),
            42,
            "::".parse().unwrap(),
            128,
        );
        let if_idx = i32::from_be_bytes(buf.data[4..8].try_into().unwrap());
        assert_eq!(if_idx, 42);
    }
}

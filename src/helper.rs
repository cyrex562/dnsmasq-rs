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
}

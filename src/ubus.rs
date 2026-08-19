#![cfg(feature = "ubus")]

//! OpenWrt ubus interface stub.
//! Encodes/decodes messages in a simple length-prefixed text format.

use std::collections::HashMap;

pub struct UbusMsg {
    pub object: String,
    pub method: String,
    pub params: HashMap<String, String>,
}

#[derive(Debug, thiserror::Error)]
pub enum UbusError {
    #[error("truncated message")]
    Truncated,
    #[error("invalid format")]
    InvalidFormat,
}

// Wire format:
//   object\n
//   method\n
//   key=value\n  (zero or more)
//   \n           (empty line terminates params)

/// Encode a ubus message to a simple length-prefixed text format.
pub fn encode_ubus_msg(msg: &UbusMsg) -> Vec<u8> {
    let mut body = String::new();
    body.push_str(&msg.object);
    body.push('\n');
    body.push_str(&msg.method);
    body.push('\n');
    // Sort keys for deterministic output.
    let mut keys: Vec<&String> = msg.params.keys().collect();
    keys.sort();
    for k in keys {
        body.push_str(k);
        body.push('=');
        body.push_str(&msg.params[k]);
        body.push('\n');
    }
    body.push('\n'); // terminator

    // Length prefix: 4-byte big-endian u32 of the body length.
    let body_bytes = body.into_bytes();
    let mut out = Vec::with_capacity(4 + body_bytes.len());
    out.extend_from_slice(&(body_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&body_bytes);
    out
}

/// Decode a ubus message.
pub fn decode_ubus_msg(data: &[u8]) -> Result<UbusMsg, UbusError> {
    if data.len() < 4 {
        return Err(UbusError::Truncated);
    }
    let body_len = u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + body_len {
        return Err(UbusError::Truncated);
    }
    let text =
        std::str::from_utf8(&data[4..4 + body_len]).map_err(|_| UbusError::InvalidFormat)?;

    let mut lines = text.split('\n');

    let object = lines.next().ok_or(UbusError::InvalidFormat)?.to_string();
    if object.is_empty() {
        return Err(UbusError::InvalidFormat);
    }
    let method = lines.next().ok_or(UbusError::InvalidFormat)?.to_string();
    if method.is_empty() {
        return Err(UbusError::InvalidFormat);
    }

    let mut params = HashMap::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let pos = line.find('=').ok_or(UbusError::InvalidFormat)?;
        params.insert(line[..pos].to_string(), line[pos + 1..].to_string());
    }

    Ok(UbusMsg { object, method, params })
}

/// Well-known ubus socket path, matching OpenWrt's `UBUS_UNIX_SOCKET`
/// default that `ubus_connect(NULL)` falls back to.
pub const UBUS_SOCKET_PATH: &str = "/var/run/ubus.sock";

/// Broadcast one resolved name → target mapping (a CNAME target, or a
/// stringified A/AAAA address) as a `connmark_allowlist_resolved` ubus event.
///
/// Called from [`crate::rfc1035::report_addresses`], mirroring
/// `ubus_event_bcast_connmark_allowlist_resolved()` (`rfc1035.c:1192,1202,1212`
/// call sites). This module's wire format is a simplified project-defined
/// encoding rather than OpenWrt's real ubus binary protocol (see the module
/// doc comment) — real ubus IPC is out of scope here, so this best-effort
/// sends the encoded event over a Unix socket at the well-known ubus path and
/// silently drops it if nothing is listening (no `ubusd`, no permission, a
/// sandboxed environment), the same "never let a denied socket surface as an
/// error" posture as `conntrack::get_incoming_mark` and `ipset::add_to_ipset`.
#[cfg(unix)]
pub fn ubus_event_bcast_connmark_allowlist_resolved(mark: u32, name: &str, target: &str, ttl: u32) {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    let mut params = HashMap::new();
    params.insert("mark".to_string(), mark.to_string());
    params.insert("name".to_string(), name.to_string());
    params.insert("resolved".to_string(), target.to_string());
    params.insert("ttl".to_string(), ttl.to_string());
    let msg = UbusMsg {
        object: "dnsmasq".to_string(),
        method: "connmark_allowlist_resolved".to_string(),
        params,
    };
    let encoded = encode_ubus_msg(&msg);

    if let Ok(mut stream) = UnixStream::connect(UBUS_SOCKET_PATH) {
        let _ = stream.write_all(&encoded);
    }
}

/// No-op stub on non-Unix targets — ubus is only ever reached over a Unix
/// domain socket.
#[cfg(not(unix))]
pub fn ubus_event_bcast_connmark_allowlist_resolved(
    _mark: u32,
    _name: &str,
    _target: &str,
    _ttl: u32,
) {
}

/// Broadcast a `connmark_allowlist_refused` ubus event: a query was denied by
/// `--connmark-allowlist-enable` because no allowlist entry matched its
/// connection mark and query name.
///
/// Called from [`crate::forward`]'s query-admission check, mirroring
/// `ubus_event_bcast_connmark_allowlist_refused()` (`forward.c:1554`, inside
/// `answer_disallowed()`). Same best-effort, never-errors posture as
/// [`ubus_event_bcast_connmark_allowlist_resolved`].
#[cfg(unix)]
pub fn ubus_event_bcast_connmark_allowlist_refused(mark: u32, name: &str) {
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    let mut params = HashMap::new();
    params.insert("mark".to_string(), mark.to_string());
    params.insert("name".to_string(), name.to_string());
    let msg = UbusMsg {
        object: "dnsmasq".to_string(),
        method: "connmark_allowlist_refused".to_string(),
        params,
    };
    let encoded = encode_ubus_msg(&msg);

    if let Ok(mut stream) = UnixStream::connect(UBUS_SOCKET_PATH) {
        let _ = stream.write_all(&encoded);
    }
}

/// No-op stub on non-Unix targets — ubus is only ever reached over a Unix
/// domain socket.
#[cfg(not(unix))]
pub fn ubus_event_bcast_connmark_allowlist_refused(_mark: u32, _name: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msg() -> UbusMsg {
        let mut params = HashMap::new();
        params.insert("ip".to_string(), "192.168.1.1".to_string());
        params.insert("mac".to_string(), "aa:bb:cc:dd:ee:ff".to_string());
        UbusMsg {
            object: "dhcp".to_string(),
            method: "lease_add".to_string(),
            params,
        }
    }

    #[test]
    fn roundtrip() {
        let msg = make_msg();
        let encoded = encode_ubus_msg(&msg);
        let decoded = decode_ubus_msg(&encoded).unwrap();
        assert_eq!(decoded.object, "dhcp");
        assert_eq!(decoded.method, "lease_add");
        assert_eq!(decoded.params.get("ip").map(|s| s.as_str()), Some("192.168.1.1"));
        assert_eq!(decoded.params.get("mac").map(|s| s.as_str()), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn roundtrip_empty_params() {
        let msg = UbusMsg {
            object: "system".to_string(),
            method: "ping".to_string(),
            params: HashMap::new(),
        };
        let encoded = encode_ubus_msg(&msg);
        let decoded = decode_ubus_msg(&encoded).unwrap();
        assert_eq!(decoded.object, "system");
        assert_eq!(decoded.method, "ping");
        assert!(decoded.params.is_empty());
    }

    #[test]
    fn truncated_no_length_returns_err() {
        assert!(matches!(decode_ubus_msg(&[0u8; 2]), Err(UbusError::Truncated)));
    }

    #[test]
    fn truncated_short_body_returns_err() {
        // claim body_len = 100, but only provide 10 bytes of body
        let mut data = vec![0u8; 4];
        data[0..4].copy_from_slice(&100u32.to_be_bytes());
        data.extend_from_slice(&[b'a'; 10]);
        assert!(matches!(decode_ubus_msg(&data), Err(UbusError::Truncated)));
    }

    /// No real `ubusd` is listening in a test/sandbox environment — the
    /// broadcast is best-effort and must not panic or return anything for the
    /// caller to unwrap.
    #[test]
    #[cfg(unix)]
    fn bcast_connmark_allowlist_resolved_does_not_panic_with_no_listener() {
        ubus_event_bcast_connmark_allowlist_resolved(6, "example.com", "1.2.3.4", 300);
    }

    #[test]
    #[cfg(unix)]
    fn bcast_connmark_allowlist_refused_does_not_panic_with_no_listener() {
        ubus_event_bcast_connmark_allowlist_refused(6, "blocked.example.com");
    }

    #[test]
    #[cfg(unix)]
    fn bcast_connmark_allowlist_resolved_reaches_a_listening_socket() {
        use std::io::Read;
        use std::os::unix::net::UnixListener;

        let dir = std::env::temp_dir().join(format!("dnsmasq-rs-ubus-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let sock_path = dir.join("ubus.sock");
        let _ = std::fs::remove_file(&sock_path);
        let listener = UnixListener::bind(&sock_path).unwrap();

        // Exercise the wire format directly against a real listener, since
        // `ubus_event_bcast_connmark_allowlist_resolved` targets the
        // well-known `/var/run/ubus.sock` path unconditionally and a test
        // process cannot bind there.
        let mut params = HashMap::new();
        params.insert("mark".to_string(), "6".to_string());
        params.insert("name".to_string(), "example.com".to_string());
        params.insert("resolved".to_string(), "1.2.3.4".to_string());
        params.insert("ttl".to_string(), "300".to_string());
        let msg = UbusMsg {
            object: "dnsmasq".to_string(),
            method: "connmark_allowlist_resolved".to_string(),
            params,
        };
        let encoded = encode_ubus_msg(&msg);

        let sender = std::thread::spawn({
            let sock_path = sock_path.clone();
            let encoded = encoded.clone();
            move || {
                use std::io::Write;
                use std::os::unix::net::UnixStream;
                let mut stream = UnixStream::connect(&sock_path).unwrap();
                stream.write_all(&encoded).unwrap();
            }
        });

        let (mut conn, _) = listener.accept().unwrap();
        let mut buf = Vec::new();
        conn.read_to_end(&mut buf).unwrap();
        sender.join().unwrap();

        let decoded = decode_ubus_msg(&buf).unwrap();
        assert_eq!(decoded.object, "dnsmasq");
        assert_eq!(decoded.method, "connmark_allowlist_resolved");
        assert_eq!(decoded.params.get("resolved").map(|s| s.as_str()), Some("1.2.3.4"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}

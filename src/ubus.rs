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
}

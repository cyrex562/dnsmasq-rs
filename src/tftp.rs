//! TFTP server state machine (RFC 1350 + RFC 2347 options).
#![cfg(feature = "tftp")]

use thiserror::Error;

// ---------------------------------------------------------------------------
// Opcodes and error codes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TftpOpcode {
    Rrq   = 1,
    Wrq   = 2,
    Data  = 3,
    Ack   = 4,
    Error = 5,
    Oack  = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TftpError {
    FileNotFound      = 1,
    AccessViolation   = 2,
    DiskFull          = 3,
    IllegalOp         = 4,
    UnknownTransferId = 5,
    FileAlreadyExists = 6,
}

// ---------------------------------------------------------------------------
// Parse error
// ---------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum TftpParseError {
    #[error("packet too short")]
    TooShort,
    #[error("invalid opcode: {0}")]
    InvalidOpcode(u16),
    #[error("missing null terminator")]
    MissingNull,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Read a null-terminated string from `buf` starting at `pos`.
/// Returns `(string, next_pos)`.
fn read_cstring(buf: &[u8], pos: usize) -> Result<(String, usize), TftpParseError> {
    let end = buf[pos..]
        .iter()
        .position(|&b| b == 0)
        .ok_or(TftpParseError::MissingNull)?;
    let s = String::from_utf8_lossy(&buf[pos..pos + end]).into_owned();
    Ok((s, pos + end + 1))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Parse a TFTP RRQ (or WRQ) packet.
/// Returns `(filename, mode, options)`.
pub fn parse_rrq(pkt: &[u8]) -> Result<(String, String, Vec<(String, String)>), TftpParseError> {
    if pkt.len() < 4 {
        return Err(TftpParseError::TooShort);
    }
    let opcode = u16::from_be_bytes([pkt[0], pkt[1]]);
    if opcode != TftpOpcode::Rrq as u16 && opcode != TftpOpcode::Wrq as u16 {
        return Err(TftpParseError::InvalidOpcode(opcode));
    }

    let (filename, pos) = read_cstring(pkt, 2)?;
    let (mode, mut pos) = read_cstring(pkt, pos)?;

    let mut options = Vec::new();
    while pos < pkt.len() {
        let (key, next) = read_cstring(pkt, pos)?;
        let (val, next2) = read_cstring(pkt, next)?;
        options.push((key, val));
        pos = next2;
    }

    Ok((filename, mode, options))
}

/// Build a TFTP DATA packet.
pub fn build_data(block: u16, data: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(4 + data.len());
    pkt.extend_from_slice(&(TftpOpcode::Data as u16).to_be_bytes());
    pkt.extend_from_slice(&block.to_be_bytes());
    pkt.extend_from_slice(data);
    pkt
}

/// Parse a TFTP DATA packet. Returns `(block, data)`.
pub fn parse_data(pkt: &[u8]) -> Result<(u16, &[u8]), TftpParseError> {
    if pkt.len() < 4 {
        return Err(TftpParseError::TooShort);
    }
    let opcode = u16::from_be_bytes([pkt[0], pkt[1]]);
    if opcode != TftpOpcode::Data as u16 {
        return Err(TftpParseError::InvalidOpcode(opcode));
    }
    let block = u16::from_be_bytes([pkt[2], pkt[3]]);
    Ok((block, &pkt[4..]))
}

/// Build a TFTP ACK packet.
pub fn build_ack(block: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(4);
    pkt.extend_from_slice(&(TftpOpcode::Ack as u16).to_be_bytes());
    pkt.extend_from_slice(&block.to_be_bytes());
    pkt
}

/// Build a TFTP ERROR packet.
pub fn build_error(code: TftpError, msg: &str) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(5 + msg.len());
    pkt.extend_from_slice(&(TftpOpcode::Error as u16).to_be_bytes());
    pkt.extend_from_slice(&(code as u16).to_be_bytes());
    pkt.extend_from_slice(msg.as_bytes());
    pkt.push(0);
    pkt
}

/// Build a TFTP OACK (option acknowledgement) packet.
pub fn build_oack(options: &[(&str, &str)]) -> Vec<u8> {
    let mut pkt = Vec::new();
    pkt.extend_from_slice(&(TftpOpcode::Oack as u16).to_be_bytes());
    for (k, v) in options {
        pkt.extend_from_slice(k.as_bytes());
        pkt.push(0);
        pkt.extend_from_slice(v.as_bytes());
        pkt.push(0);
    }
    pkt
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_rrq(filename: &str, mode: &str, opts: &[(&str, &str)]) -> Vec<u8> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&(TftpOpcode::Rrq as u16).to_be_bytes());
        pkt.extend_from_slice(filename.as_bytes());
        pkt.push(0);
        pkt.extend_from_slice(mode.as_bytes());
        pkt.push(0);
        for (k, v) in opts {
            pkt.extend_from_slice(k.as_bytes());
            pkt.push(0);
            pkt.extend_from_slice(v.as_bytes());
            pkt.push(0);
        }
        pkt
    }

    #[test]
    fn test_parse_rrq_basic() {
        let pkt = make_rrq("boot/pxelinux.0", "octet", &[]);
        let (filename, mode, opts) = parse_rrq(&pkt).unwrap();
        assert_eq!(filename, "boot/pxelinux.0");
        assert_eq!(mode, "octet");
        assert!(opts.is_empty());
    }

    #[test]
    fn test_parse_rrq_with_options() {
        let pkt = make_rrq("file.txt", "netascii", &[("blksize", "1428"), ("tsize", "0")]);
        let (filename, mode, opts) = parse_rrq(&pkt).unwrap();
        assert_eq!(filename, "file.txt");
        assert_eq!(mode, "netascii");
        assert_eq!(opts, vec![("blksize".into(), "1428".into()), ("tsize".into(), "0".into())]);
    }

    #[test]
    fn test_build_data_parse_data_roundtrip() {
        let payload = b"hello tftp world";
        let pkt = build_data(3, payload);
        let (block, data) = parse_data(&pkt).unwrap();
        assert_eq!(block, 3);
        assert_eq!(data, payload);
    }

    #[test]
    fn test_build_ack_block_number() {
        let pkt = build_ack(42);
        assert_eq!(pkt.len(), 4);
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), TftpOpcode::Ack as u16);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 42);
    }

    #[test]
    fn test_build_error_format() {
        let pkt = build_error(TftpError::FileNotFound, "not found");
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), TftpOpcode::Error as u16);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), TftpError::FileNotFound as u16);
        assert_eq!(&pkt[4..pkt.len() - 1], b"not found");
        assert_eq!(pkt[pkt.len() - 1], 0);
    }

    #[test]
    fn test_parse_rrq_truncated() {
        // Too short
        assert!(parse_rrq(&[0, 1]).is_err());
        // Missing null terminator
        let pkt = [0u8, 1, b'f', b'i', b'l', b'e'];
        assert!(matches!(parse_rrq(&pkt), Err(TftpParseError::MissingNull)));
    }

    #[test]
    fn test_parse_rrq_wrong_opcode() {
        let pkt = [0u8, 3, b'x', 0, b'o', b'c', b't', b'e', b't', 0];
        assert!(matches!(parse_rrq(&pkt), Err(TftpParseError::InvalidOpcode(3))));
    }

    #[test]
    fn test_build_oack() {
        let pkt = build_oack(&[("blksize", "512")]);
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), TftpOpcode::Oack as u16);
        assert!(pkt[2..].starts_with(b"blksize\0512\0"));
    }
}

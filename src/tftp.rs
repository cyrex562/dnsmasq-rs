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
    NotDefined        = 0,
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
// Transfer state machine
// ---------------------------------------------------------------------------

/// Represents an active TFTP transfer.
pub struct TftpTransfer {
    pub filename: String,
    pub block: u16,
    pub block_size: usize,
    pub file_size: Option<u64>,
    pub complete: bool,
    pub retries: u32,
    pub max_retries: u32,
}

impl TftpTransfer {
    /// Create a new transfer for the given filename and block size.
    pub fn new(filename: &str, block_size: usize) -> Self {
        TftpTransfer {
            filename: filename.to_string(),
            block: 0,
            block_size,
            file_size: None,
            complete: false,
            retries: 0,
            max_retries: 5,
        }
    }

    /// Build a DATA packet for the next block from provided file data.
    /// Increments block number. Marks complete if data length < block_size.
    pub fn next_block(&mut self, data: &[u8]) -> Vec<u8> {
        self.block = self.block.wrapping_add(1);
        if data.len() < self.block_size {
            self.complete = true;
        }
        build_data(self.block, data)
    }

    /// Process an ACK packet. Returns true if the ACK matches the current block.
    /// Resets retries on match, increments retries on mismatch.
    pub fn handle_ack(&mut self, block: u16) -> bool {
        if block == self.block {
            self.retries = 0;
            true
        } else {
            self.retries += 1;
            false
        }
    }

    /// Check if retries exceeded max_retries.
    pub fn is_timed_out(&self) -> bool {
        self.retries > self.max_retries
    }
}

// ---------------------------------------------------------------------------
// Filename sanitization
// ---------------------------------------------------------------------------

/// Validate and sanitize a TFTP filename.
/// Rejects paths with "..", leading "/", or null bytes.
/// Converts backslashes to forward slashes.
pub fn sanitize_filename(name: &str) -> Option<String> {
    // Reject null bytes
    if name.contains('\0') {
        return None;
    }

    // Convert backslashes to forward slashes
    let name = name.replace('\\', "/");

    // Reject leading slash
    if name.starts_with('/') {
        return None;
    }

    // Reject ".." path components
    for component in name.split('/') {
        if component == ".." {
            return None;
        }
    }

    // Reject empty filenames
    if name.is_empty() {
        return None;
    }

    Some(name)
}

// ---------------------------------------------------------------------------
// Option negotiation (RFC 2347)
// ---------------------------------------------------------------------------

/// Process TFTP option negotiation (RFC 2347).
/// Handles "blksize" and "tsize" options.
/// Returns the list of acknowledged options with their negotiated values.
pub fn negotiate_options(
    requested: &[(String, String)],
    max_block_size: usize,
) -> Vec<(String, String)> {
    let mut result = Vec::new();

    for (key, value) in requested {
        match key.to_lowercase().as_str() {
            "blksize" => {
                if let Ok(requested_size) = value.parse::<usize>() {
                    // Clamp to [8, max_block_size]
                    let negotiated = requested_size.clamp(8, max_block_size);
                    result.push(("blksize".to_string(), negotiated.to_string()));
                }
            }
            "tsize" => {
                // Echo back the tsize option; the caller fills in the actual
                // file size. We acknowledge with "0" to indicate we accept it.
                result.push(("tsize".to_string(), value.clone()));
            }
            _ => {
                // Unknown options are silently ignored per RFC 2347
            }
        }
    }

    result
}

// ---------------------------------------------------------------------------
// String extraction (ported from tftp.c:840-853)
// ---------------------------------------------------------------------------

/// Extract a null-terminated string from a buffer, advancing position.
///
/// Returns the bytes before the null terminator, or `None` if no null found
/// or the string would be empty.
/// Port of `next()` from tftp.c:840-853.
pub fn next_cstring<'a>(buf: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    if *pos >= buf.len() {
        return None;
    }
    let start = *pos;
    let remaining = &buf[start..];
    let null_pos = remaining.iter().position(|&b| b == 0)?;
    if null_pos == 0 {
        return None; // empty string
    }
    *pos = start + null_pos + 1;
    Some(&buf[start..start + null_pos])
}

/// Remove non-printable characters from a string, keeping only 0x20-0x7E.
///
/// Port of `sanitise()` from tftp.c:857-871.
pub fn tftp_sanitise(input: &str) -> String {
    input.chars().filter(|&c| c >= ' ' && c <= '~').collect()
}

// ---------------------------------------------------------------------------
// Error packet builders (ported from tftp.c:874-902)
// ---------------------------------------------------------------------------

/// Maximum TFTP error message length.
const TFTP_MAX_MESSAGE: usize = 500;

/// Build a TFTP error response packet with message truncation and sanitization.
///
/// Port of `tftp_err()` from tftp.c:874-894.
pub fn tftp_err_packet(code: TftpError, message: &str) -> Vec<u8> {
    let clean = tftp_sanitise(message);
    let truncated = if clean.len() > TFTP_MAX_MESSAGE {
        &clean[..TFTP_MAX_MESSAGE]
    } else {
        &clean
    };
    build_error(code, truncated)
}

/// Build a TFTP error packet for a file read error.
///
/// Format: "cannot read {filename}: {error}"
/// Port of `tftp_err_oops()` from tftp.c:896-902.
pub fn tftp_err_oops(filename: &str, err: &std::io::Error) -> Vec<u8> {
    let clean_name = tftp_sanitise(filename);
    let msg = format!("cannot read {}: {}", clean_name, err);
    tftp_err_packet(TftpError::NotDefined, &msg)
}

// ---------------------------------------------------------------------------
// ACK handling (ported from tftp.c:752-824)
// ---------------------------------------------------------------------------

/// Result of handling an incoming TFTP packet for an active transfer.
#[derive(Debug, PartialEq)]
pub enum TftpHandleResult {
    /// ACK received for expected block.
    AckOk { block: u32 },
    /// ACK for an already-acknowledged or out-of-range block (ignored).
    AckIgnored,
    /// Client sent an ERROR packet.
    Error { code: u16, message: String },
    /// Packet too short or unrecognized opcode.
    InvalidPacket,
}

/// Process an incoming TFTP packet (ACK or ERROR) for an active transfer.
///
/// Handles 16-bit block number wraparound.
/// Port of `handle_tftp()` from tftp.c:752-824.
pub fn handle_tftp_packet(transfer: &mut TftpTransfer, packet: &[u8]) -> TftpHandleResult {
    if packet.len() < 4 {
        return TftpHandleResult::InvalidPacket;
    }
    let opcode = u16::from_be_bytes([packet[0], packet[1]]);
    match opcode {
        4 => { // ACK
            let block_num = u16::from_be_bytes([packet[2], packet[3]]);
            let expected = transfer.block;
            if block_num == expected {
                transfer.retries = 0;
                TftpHandleResult::AckOk { block: block_num as u32 }
            } else {
                TftpHandleResult::AckIgnored
            }
        }
        5 => { // ERROR
            let code = u16::from_be_bytes([packet[2], packet[3]]);
            let msg = if packet.len() > 4 {
                let end = packet[4..].iter().position(|&b| b == 0).unwrap_or(packet.len() - 4);
                String::from_utf8_lossy(&packet[4..4 + end]).to_string()
            } else {
                String::new()
            };
            TftpHandleResult::Error { code, message: msg }
        }
        _ => TftpHandleResult::InvalidPacket,
    }
}

// ---------------------------------------------------------------------------
// Block reading (ported from tftp.c:905-1021)
// ---------------------------------------------------------------------------

/// Result of reading a file block for a TFTP transfer.
#[derive(Debug)]
pub enum GetBlockResult {
    /// Block 0: send OACK with negotiated options.
    Oack(Vec<u8>),
    /// Data block to send.
    Data(Vec<u8>),
    /// Transfer complete (past end of file).
    Done,
}

/// Read a file block for the next DATA packet.
///
/// Block 0 returns an OACK with negotiated options.
/// Blocks 1+ return data from the file with optional netascii LF→CRLF expansion.
/// Port of `get_block()` from tftp.c:905-1021.
pub fn get_block(
    block: u16,
    file_data: &[u8],
    blocksize: usize,
    netascii: bool,
    opt_blocksize: bool,
    opt_transize: bool,
) -> GetBlockResult {
    if block == 0 {
        // Build OACK
        let mut opts: Vec<(String, String)> = Vec::new();
        if opt_blocksize {
            opts.push(("blksize".to_string(), blocksize.to_string()));
        }
        if opt_transize {
            opts.push(("tsize".to_string(), file_data.len().to_string()));
        }
        let refs: Vec<(&str, &str)> = opts.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        let pkt = build_oack(&refs);
        return GetBlockResult::Oack(pkt);
    }

    let offset = (block as usize - 1) * blocksize;
    if offset >= file_data.len() {
        return GetBlockResult::Done;
    }

    let end = (offset + blocksize).min(file_data.len());
    let raw = &file_data[offset..end];

    let data = if netascii {
        // LF → CRLF expansion
        let mut expanded = Vec::with_capacity(raw.len() * 2);
        for &b in raw {
            if b == b'\n' {
                expanded.push(b'\r');
            }
            expanded.push(b);
        }
        expanded
    } else {
        raw.to_vec()
    };

    GetBlockResult::Data(build_data(block, &data))
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

    // -----------------------------------------------------------------------
    // TftpTransfer tests
    // -----------------------------------------------------------------------

    #[test]
    fn transfer_new_defaults() {
        let t = TftpTransfer::new("boot.img", 512);
        assert_eq!(t.filename, "boot.img");
        assert_eq!(t.block, 0);
        assert_eq!(t.block_size, 512);
        assert!(!t.complete);
        assert_eq!(t.retries, 0);
        assert_eq!(t.max_retries, 5);
        assert!(t.file_size.is_none());
    }

    #[test]
    fn transfer_next_block_increments() {
        let mut t = TftpTransfer::new("file", 512);
        let data = vec![0xABu8; 512];
        let pkt = t.next_block(&data);
        assert_eq!(t.block, 1);
        assert!(!t.complete);
        let (block, payload) = parse_data(&pkt).unwrap();
        assert_eq!(block, 1);
        assert_eq!(payload.len(), 512);
    }

    #[test]
    fn transfer_next_block_marks_complete_on_short() {
        let mut t = TftpTransfer::new("file", 512);
        let data = vec![0u8; 100]; // less than block_size
        let _pkt = t.next_block(&data);
        assert_eq!(t.block, 1);
        assert!(t.complete);
    }

    #[test]
    fn transfer_next_block_marks_complete_on_empty() {
        let mut t = TftpTransfer::new("file", 512);
        let _pkt = t.next_block(&[]);
        assert!(t.complete);
    }

    #[test]
    fn transfer_next_block_sequential() {
        let mut t = TftpTransfer::new("file", 512);
        let full = vec![0u8; 512];
        t.next_block(&full);
        assert_eq!(t.block, 1);
        t.next_block(&full);
        assert_eq!(t.block, 2);
        t.next_block(&full);
        assert_eq!(t.block, 3);
        assert!(!t.complete);
    }

    #[test]
    fn transfer_handle_ack_matching() {
        let mut t = TftpTransfer::new("file", 512);
        t.block = 5;
        t.retries = 3;
        assert!(t.handle_ack(5));
        assert_eq!(t.retries, 0);
    }

    #[test]
    fn transfer_handle_ack_mismatch() {
        let mut t = TftpTransfer::new("file", 512);
        t.block = 5;
        assert!(!t.handle_ack(4));
        assert_eq!(t.retries, 1);
        assert!(!t.handle_ack(3));
        assert_eq!(t.retries, 2);
    }

    #[test]
    fn transfer_is_timed_out() {
        let mut t = TftpTransfer::new("file", 512);
        t.max_retries = 3;
        assert!(!t.is_timed_out());
        t.retries = 3;
        assert!(!t.is_timed_out());
        t.retries = 4;
        assert!(t.is_timed_out());
    }

    #[test]
    fn transfer_full_session() {
        let mut t = TftpTransfer::new("test.bin", 4);
        // Block 1: full block
        let pkt1 = t.next_block(&[1, 2, 3, 4]);
        assert!(!t.complete);
        let (b, d) = parse_data(&pkt1).unwrap();
        assert_eq!(b, 1);
        assert_eq!(d, &[1, 2, 3, 4]);
        assert!(t.handle_ack(1));

        // Block 2: partial (last block)
        let pkt2 = t.next_block(&[5, 6]);
        assert!(t.complete);
        let (b, d) = parse_data(&pkt2).unwrap();
        assert_eq!(b, 2);
        assert_eq!(d, &[5, 6]);
        assert!(t.handle_ack(2));
    }

    // -----------------------------------------------------------------------
    // sanitize_filename tests
    // -----------------------------------------------------------------------

    #[test]
    fn sanitize_normal_filename() {
        assert_eq!(sanitize_filename("boot/pxelinux.0"), Some("boot/pxelinux.0".to_string()));
    }

    #[test]
    fn sanitize_simple_name() {
        assert_eq!(sanitize_filename("file.txt"), Some("file.txt".to_string()));
    }

    #[test]
    fn sanitize_rejects_dotdot() {
        assert_eq!(sanitize_filename("../etc/passwd"), None);
        assert_eq!(sanitize_filename("boot/../secret"), None);
        assert_eq!(sanitize_filename(".."), None);
    }

    #[test]
    fn sanitize_rejects_leading_slash() {
        assert_eq!(sanitize_filename("/etc/passwd"), None);
        assert_eq!(sanitize_filename("/boot/file"), None);
    }

    #[test]
    fn sanitize_rejects_null_bytes() {
        assert_eq!(sanitize_filename("file\0.txt"), None);
    }

    #[test]
    fn sanitize_rejects_empty() {
        assert_eq!(sanitize_filename(""), None);
    }

    #[test]
    fn sanitize_converts_backslashes() {
        assert_eq!(sanitize_filename("boot\\pxe\\file.0"), Some("boot/pxe/file.0".to_string()));
    }

    #[test]
    fn sanitize_rejects_backslash_dotdot() {
        assert_eq!(sanitize_filename("boot\\..\\secret"), None);
    }

    #[test]
    fn sanitize_allows_dots_in_names() {
        assert_eq!(sanitize_filename("file.tar.gz"), Some("file.tar.gz".to_string()));
        assert_eq!(sanitize_filename(".hidden"), Some(".hidden".to_string()));
    }

    #[test]
    fn sanitize_allows_single_dot_component() {
        // "." as a path component is fine, ".." is not
        assert_eq!(sanitize_filename("./file.txt"), Some("./file.txt".to_string()));
    }

    // -----------------------------------------------------------------------
    // negotiate_options tests
    // -----------------------------------------------------------------------

    #[test]
    fn negotiate_blksize_within_range() {
        let opts = vec![("blksize".to_string(), "1024".to_string())];
        let result = negotiate_options(&opts, 1428);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ("blksize".to_string(), "1024".to_string()));
    }

    #[test]
    fn negotiate_blksize_clamped_to_max() {
        let opts = vec![("blksize".to_string(), "65535".to_string())];
        let result = negotiate_options(&opts, 1428);
        assert_eq!(result[0], ("blksize".to_string(), "1428".to_string()));
    }

    #[test]
    fn negotiate_blksize_clamped_to_min() {
        let opts = vec![("blksize".to_string(), "2".to_string())];
        let result = negotiate_options(&opts, 1428);
        assert_eq!(result[0], ("blksize".to_string(), "8".to_string()));
    }

    #[test]
    fn negotiate_tsize_echoed() {
        let opts = vec![("tsize".to_string(), "0".to_string())];
        let result = negotiate_options(&opts, 512);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ("tsize".to_string(), "0".to_string()));
    }

    #[test]
    fn negotiate_multiple_options() {
        let opts = vec![
            ("blksize".to_string(), "1024".to_string()),
            ("tsize".to_string(), "0".to_string()),
        ];
        let result = negotiate_options(&opts, 1428);
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn negotiate_unknown_option_ignored() {
        let opts = vec![("windowsize".to_string(), "4".to_string())];
        let result = negotiate_options(&opts, 512);
        assert!(result.is_empty());
    }

    #[test]
    fn negotiate_case_insensitive() {
        let opts = vec![("BLKSIZE".to_string(), "512".to_string())];
        let result = negotiate_options(&opts, 1428);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "blksize");
    }

    #[test]
    fn negotiate_invalid_blksize_ignored() {
        let opts = vec![("blksize".to_string(), "not_a_number".to_string())];
        let result = negotiate_options(&opts, 512);
        assert!(result.is_empty());
    }

    #[test]
    fn negotiate_empty_options() {
        let result = negotiate_options(&[], 512);
        assert!(result.is_empty());
    }

    // ── next_cstring ─────────────────────────────────────────────────────────

    #[test]
    fn next_cstring_basic() {
        let buf = b"hello\0world";
        let mut pos = 0;
        let s = next_cstring(buf, &mut pos).unwrap();
        assert_eq!(s, b"hello");
        assert_eq!(pos, 6);
    }

    #[test]
    fn next_cstring_second_string() {
        let buf = b"first\0second\0";
        let mut pos = 0;
        let _ = next_cstring(buf, &mut pos).unwrap();
        let s2 = next_cstring(buf, &mut pos).unwrap();
        assert_eq!(s2, b"second");
    }

    #[test]
    fn next_cstring_no_null() {
        let mut pos = 0;
        assert!(next_cstring(b"hello", &mut pos).is_none());
    }

    #[test]
    fn next_cstring_empty_returns_none() {
        let mut pos = 0;
        assert!(next_cstring(b"\0rest", &mut pos).is_none());
    }

    #[test]
    fn next_cstring_at_end() {
        let mut pos = 5;
        assert!(next_cstring(b"hello", &mut pos).is_none());
    }

    #[test]
    fn next_cstring_single_char() {
        let mut pos = 0;
        let s = next_cstring(b"x\0", &mut pos).unwrap();
        assert_eq!(s, b"x");
    }

    // ── tftp_sanitise ────────────────────────────────────────────────────────

    #[test]
    fn tftp_sanitise_printable() {
        assert_eq!(tftp_sanitise("hello world"), "hello world");
    }

    #[test]
    fn tftp_sanitise_removes_control() {
        assert_eq!(tftp_sanitise("hel\x01lo"), "hello");
    }

    #[test]
    fn tftp_sanitise_removes_null() {
        assert_eq!(tftp_sanitise("hel\x00lo"), "hello");
    }

    #[test]
    fn tftp_sanitise_empty() {
        assert_eq!(tftp_sanitise(""), "");
    }

    #[test]
    fn tftp_sanitise_all_unprintable() {
        assert_eq!(tftp_sanitise("\x01\x02\x03"), "");
    }

    // ── tftp_err_packet ──────────────────────────────────────────────────────

    #[test]
    fn tftp_err_packet_basic() {
        let pkt = tftp_err_packet(TftpError::FileNotFound, "File not found");
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), 5); // ERROR opcode
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 1); // error code
        assert!(pkt.len() > 4);
    }

    #[test]
    fn tftp_err_packet_truncates_long() {
        let long_msg = "x".repeat(600);
        let pkt = tftp_err_packet(TftpError::NotDefined, &long_msg);
        // Message after header (4 bytes) should be ≤ 500 + null
        assert!(pkt.len() <= 4 + 500 + 1);
    }

    #[test]
    fn tftp_err_packet_null_terminated() {
        let pkt = tftp_err_packet(TftpError::NotDefined, "test");
        assert_eq!(*pkt.last().unwrap(), 0);
    }

    #[test]
    fn tftp_err_packet_sanitises() {
        let pkt = tftp_err_packet(TftpError::NotDefined, "bad\x01msg");
        let msg_bytes = &pkt[4..pkt.len() - 1]; // skip header and null
        let msg = std::str::from_utf8(msg_bytes).unwrap();
        assert_eq!(msg, "badmsg");
    }

    // ── tftp_err_oops ────────────────────────────────────────────────────────

    #[test]
    fn tftp_err_oops_contains_filename() {
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let pkt = tftp_err_oops("test.bin", &err);
        let msg = String::from_utf8_lossy(&pkt[4..]);
        assert!(msg.contains("test.bin"));
    }

    #[test]
    fn tftp_err_oops_contains_error() {
        let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");
        let pkt = tftp_err_oops("file", &err);
        let msg = String::from_utf8_lossy(&pkt[4..]);
        assert!(msg.contains("denied"));
    }

    #[test]
    fn tftp_err_oops_error_code_zero() {
        let err = std::io::Error::new(std::io::ErrorKind::Other, "oops");
        let pkt = tftp_err_oops("f", &err);
        assert_eq!(u16::from_be_bytes([pkt[2], pkt[3]]), 0);
    }

    // ── handle_tftp_packet ───────────────────────────────────────────────────

    #[test]
    fn handle_tftp_ack_basic() {
        let mut t = TftpTransfer::new("file", 512);
        t.block = 1;
        t.retries = 2;
        let ack = [0, 4, 0, 1]; // ACK block 1
        let result = handle_tftp_packet(&mut t, &ack);
        assert_eq!(result, TftpHandleResult::AckOk { block: 1 });
        assert_eq!(t.retries, 0);
    }

    #[test]
    fn handle_tftp_ack_mismatch_ignored() {
        let mut t = TftpTransfer::new("file", 512);
        t.block = 5;
        let ack = [0, 4, 0, 3]; // ACK block 3 (wrong)
        assert_eq!(handle_tftp_packet(&mut t, &ack), TftpHandleResult::AckIgnored);
    }

    #[test]
    fn handle_tftp_error_packet() {
        let mut t = TftpTransfer::new("file", 512);
        let mut pkt = vec![0, 5, 0, 1]; // ERROR code 1
        pkt.extend_from_slice(b"File not found\0");
        let result = handle_tftp_packet(&mut t, &pkt);
        match result {
            TftpHandleResult::Error { code, message } => {
                assert_eq!(code, 1);
                assert_eq!(message, "File not found");
            }
            _ => panic!("expected Error"),
        }
    }

    #[test]
    fn handle_tftp_too_short() {
        let mut t = TftpTransfer::new("file", 512);
        assert_eq!(handle_tftp_packet(&mut t, &[0, 4]), TftpHandleResult::InvalidPacket);
    }

    #[test]
    fn handle_tftp_unknown_opcode() {
        let mut t = TftpTransfer::new("file", 512);
        let pkt = [0, 99, 0, 0];
        assert_eq!(handle_tftp_packet(&mut t, &pkt), TftpHandleResult::InvalidPacket);
    }

    // ── get_block ────────────────────────────────────────────────────────────

    #[test]
    fn get_block_zero_oack() {
        let result = get_block(0, b"hello", 512, false, true, true);
        match result {
            GetBlockResult::Oack(pkt) => {
                assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), 6); // OACK opcode
            }
            _ => panic!("expected Oack"),
        }
    }

    #[test]
    fn get_block_first_data() {
        let file = b"hello world!!!"; // 14 bytes
        let result = get_block(1, file, 512, false, false, false);
        match result {
            GetBlockResult::Data(pkt) => {
                let (block, data) = parse_data(&pkt).unwrap();
                assert_eq!(block, 1);
                assert_eq!(data, b"hello world!!!");
            }
            _ => panic!("expected Data"),
        }
    }

    #[test]
    fn get_block_past_eof() {
        let result = get_block(2, b"hello", 512, false, false, false);
        assert!(matches!(result, GetBlockResult::Done));
    }

    #[test]
    fn get_block_netascii_lf_to_crlf() {
        let file = b"line1\nline2\n";
        let result = get_block(1, file, 512, true, false, false);
        match result {
            GetBlockResult::Data(pkt) => {
                let (_, data) = parse_data(&pkt).unwrap();
                assert!(data.windows(2).any(|w| w == b"\r\n"), "should contain CRLF");
                assert!(!data.windows(2).any(|w| w == b"\n\n"), "bare LF should be gone");
            }
            _ => panic!("expected Data"),
        }
    }

    #[test]
    fn get_block_last_block_short() {
        let file = vec![0xAA; 600]; // 600 bytes, blocksize=512
        let result = get_block(2, &file, 512, false, false, false);
        match result {
            GetBlockResult::Data(pkt) => {
                let (block, data) = parse_data(&pkt).unwrap();
                assert_eq!(block, 2);
                assert_eq!(data.len(), 88); // 600 - 512 = 88
            }
            _ => panic!("expected Data"),
        }
    }
}

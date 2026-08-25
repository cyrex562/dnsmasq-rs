//! TFTP server (RFC 1350 + RFC 2347/2348/7440 options).
//!
//! Port of `tftp.c`: wire-format parse/build helpers, option negotiation,
//! path resolution + permission checks, the block-read/CRLF-expansion path,
//! and the socket-driven transfer table + retransmit/timeout state machine
//! that used to be entirely missing from this port.
#![cfg(feature = "tftp")]

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use thiserror::Error;
use tracing::{info, warn};

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
fn read_cstring(c: &mut crate::byte_cursor::ByteCursor) -> Result<String, TftpParseError> {
    let end = c.find(0).ok_or(TftpParseError::MissingNull)?;
    let bytes = c.read_slice(end).expect("find() guarantees `end` bytes remain before the null");
    let s = String::from_utf8_lossy(bytes).into_owned();
    c.advance(1).expect("find() located a null byte at this position");
    Ok(s)
}

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/// Parse a TFTP RRQ (or WRQ) packet.
/// Returns `(filename, mode, options)`.
pub fn parse_rrq(pkt: &[u8]) -> Result<(String, String, Vec<(String, String)>), TftpParseError> {
    if pkt.len() < 4 {
        return Err(TftpParseError::TooShort);
    }
    let mut c = crate::byte_cursor::ByteCursor::new(pkt);
    let opcode = c.read_u16_be().expect("length checked above");
    if opcode != TftpOpcode::Rrq as u16 && opcode != TftpOpcode::Wrq as u16 {
        return Err(TftpParseError::InvalidOpcode(opcode));
    }

    let filename = read_cstring(&mut c)?;
    let mode = read_cstring(&mut c)?;

    let mut options = Vec::new();
    while !c.is_empty() {
        let key = read_cstring(&mut c)?;
        let val = read_cstring(&mut c)?;
        options.push((key, val));
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
// Filename sanitization
// ---------------------------------------------------------------------------

/// Validate and sanitize a TFTP filename.
/// Rejects paths with "..", leading "/", or null bytes.
/// Converts backslashes to forward slashes.
///
/// Not itself upstream's path-traversal defense: unlike this function,
/// `check_tftp_fileperm` (ported as [`open_tftp_file`]'s `/../` substring
/// check) explicitly *allows* an absolute filename and a leading "..", as
/// long as the resulting path stays under `--tftp-root` — this stricter,
/// non-upstream helper would reject legitimate requests upstream accepts, so
/// [`build_tftp_path`]/[`open_tftp_file`] deliberately don't call it. Kept
/// standalone as a general-purpose filename check for other future callers.
pub fn sanitize_filename(name: &str) -> Option<String> {
    if name.contains('\0') {
        return None;
    }

    let name = name.replace('\\', "/");

    if name.starts_with('/') {
        return None;
    }

    for component in name.split('/') {
        if component == ".." {
            return None;
        }
    }

    if name.is_empty() {
        return None;
    }

    Some(name)
}

// ---------------------------------------------------------------------------
// String extraction / sanitisation (ported from tftp.c:840-902)
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
// Option negotiation (RFC 2347/2348/7440) — port of the option loop in
// tftp_request() (tftp.c:381-423)
// ---------------------------------------------------------------------------

/// Compute `daemon->packet_buff_sz` (`dnsmasq.c:128`:
/// `edns_pktsz + MAXDNAME + RRFIXEDSZ`), the buffer upstream's `blksize`
/// option loop clamps against (`val > packet_buff_sz - 4`) ahead of, and
/// independently of, the MTU clamp.
pub fn packet_buff_sz(edns_pktsz: u16) -> usize {
    edns_pktsz as usize + crate::dns_protocol::MAXDNAME + crate::dns_protocol::RRFIXEDSZ
}

/// `TFTP_MAX_WINDOW` (config.h) — max `windowsize` to negotiate.
pub const TFTP_MAX_WINDOW: u32 = 32;

/// `TFTP_TRANSFER_TIME` (config.h) — abandon a transfer after this long.
pub const TFTP_TRANSFER_TIME_SECS: u64 = 120;

/// `TFTP_MAX_CONNECTIONS` (config.h) — default simultaneous-transfer cap
/// when `--tftp-max` is not given.
pub const TFTP_MAX_CONNECTIONS_DEFAULT: i32 = 50;

/// Negotiated per-transfer options, mirroring the `opt_*`/`blocksize`/
/// `timeout`/`windowsize` fields of `struct tftp_transfer`.
#[derive(Debug, Clone, PartialEq)]
pub struct RequestOptions {
    pub blocksize: usize,
    pub opt_blocksize: bool,
    pub opt_transize: bool,
    pub opt_timeout: bool,
    pub opt_windowsize: bool,
    pub timeout: u32,
    pub windowsize: u32,
}

impl Default for RequestOptions {
    fn default() -> Self {
        RequestOptions {
            blocksize: 512,
            opt_blocksize: false,
            opt_transize: false,
            opt_timeout: false,
            opt_windowsize: false,
            timeout: 2,
            windowsize: 1,
        }
    }
}

/// `atoi()` semantics: parse the leading run of decimal digits (with an
/// optional sign), ignoring trailing garbage; a value with no leading digits
/// at all parses as `0`. `tftp_request` never checks `atoi`'s failure mode.
fn atoi_like(s: &str) -> i64 {
    let mut chars = s.trim_start().chars().peekable();
    let neg = matches!(chars.peek(), Some('-'));
    if neg || matches!(chars.peek(), Some('+')) {
        chars.next();
    }
    let mut val: i64 = 0;
    let mut any = false;
    for c in chars {
        match c.to_digit(10) {
            Some(d) => {
                val = val.saturating_mul(10).saturating_add(d as i64);
                any = true;
            }
            None => break,
        }
    }
    if !any {
        return 0;
    }
    if neg { -val } else { val }
}

/// Reinterpret an `atoi_like` result the way C's `unsigned int val =
/// atoi(arg);` does: truncate to a 32-bit signed `int` (`atoi`'s actual
/// return type) and reinterpret those bits as unsigned. This is why
/// upstream's `if (val < 1) val = 1;`-style floor checks never fire for
/// negative input — a negative value has already wrapped past any small
/// floor by the time the check runs, and instead gets clamped *down* by
/// whichever ceiling check comes next (`tftp.c:383-411`).
fn atoi_as_c_uint(s: &str) -> u32 {
    atoi_like(s) as i32 as u32
}

/// Parse and clamp the `blksize`/`tsize`/`timeout`/`windowsize` options off
/// an RRQ, exactly as the option loop in `tftp_request` does.
///
/// `mtu` is the outgoing interface's MTU (`None` when unknown); `family_v4`
/// picks the 32-byte (IPv4) vs 52-byte (IPv6) header overhead subtracted
/// from it for the `blksize` clamp. `packet_buff_sz` is
/// `daemon->packet_buff_sz` (see [`packet_buff_sz`]) — upstream clamps
/// `blksize` to `packet_buff_sz - 4` unconditionally, before the MTU clamp,
/// so a wide blksize can never be negotiated just because the MTU is
/// unknown. There is no independent RFC 2348-style ceiling beyond that and
/// the MTU clamp — upstream's option loop (`tftp.c:383-411`) has none.
pub fn parse_request_options(
    options: &[(String, String)],
    netascii: bool,
    family_v4: bool,
    mtu: Option<i32>,
    no_blocksize_option: bool,
    packet_buff_sz: usize,
) -> RequestOptions {
    let mut opts = RequestOptions::default();
    let overhead: u32 = if family_v4 { 32 } else { 52 };

    for (key, value) in options {
        match key.to_ascii_lowercase().as_str() {
            "blksize" if !no_blocksize_option => {
                let mut v = atoi_as_c_uint(value);
                if v < 1 {
                    v = 1;
                }
                let buff_max = (packet_buff_sz as u32).wrapping_sub(4);
                if v > buff_max {
                    v = buff_max;
                }
                if let Some(mtu) = mtu {
                    if mtu != 0 {
                        let mtu_max = (mtu as u32).wrapping_sub(overhead);
                        if v > mtu_max {
                            v = mtu_max;
                        }
                    }
                }
                opts.blocksize = v as usize;
                opts.opt_blocksize = true;
            }
            "tsize" if !netascii => {
                opts.opt_transize = true;
            }
            "timeout" => {
                let mut v = atoi_as_c_uint(value);
                if v > 255 {
                    v = 255;
                }
                opts.timeout = v;
                opts.opt_timeout = true;
            }
            "windowsize" if !netascii => {
                let mut v = atoi_as_c_uint(value);
                if v < 1 {
                    v = 1;
                }
                if v > TFTP_MAX_WINDOW {
                    v = TFTP_MAX_WINDOW;
                }
                opts.windowsize = v;
                opts.opt_windowsize = true;
            }
            _ => {}
        }
    }

    opts
}

/// True when any option in [`RequestOptions`] was actually negotiated —
/// upstream sets `transfer->block = 0` (send an OACK first) whenever any of
/// the four options is present (tftp.c:397/403/410/421).
pub fn any_option_negotiated(opts: &RequestOptions) -> bool {
    opts.opt_blocksize || opts.opt_transize || opts.opt_timeout || opts.opt_windowsize
}

// ---------------------------------------------------------------------------
// Path resolution (ported from tftp_request, tftp.c:425-498)
// ---------------------------------------------------------------------------

/// Inputs [`build_tftp_path`] needs beyond the raw filename.
#[derive(Debug, Clone, Default)]
pub struct PathParts {
    pub prefix: Option<String>,
    pub lowercase: bool,
    pub apref_ip: bool,
    pub apref_mac: bool,
    pub client_addr_str: String,
    /// Best-effort client MAC for `--tftp-unique-root=mac`; `None` when it
    /// could not be resolved (falls back to no MAC subdirectory, same as
    /// upstream when neither the lease table nor the ARP cache have it).
    pub client_mac: Option<[u8; 6]>,
}

fn dir_exists(path: &str) -> bool {
    std::fs::metadata(path).map(|m| m.is_dir()).unwrap_or(false)
}

/// Build the absolute on-disk path for an incoming TFTP filename: backslash
/// and lowercase normalization, `--tftp-root` prefixing, the optional
/// per-client IP/MAC subdirectory (falling back when it doesn't exist), and
/// the "absolute paths OK if they already match the prefix" rule.
///
/// Port of the path-construction block in `tftp_request` (tftp.c:425-498).
pub fn build_tftp_path(filename_raw: &str, parts: &PathParts) -> String {
    let mut filename: String = filename_raw
        .chars()
        .map(|c| {
            let c = if c == '\\' { '/' } else { c };
            if parts.lowercase { c.to_ascii_lowercase() } else { c }
        })
        .collect();

    let mut namebuff = String::from("/");

    if let Some(prefix) = parts.prefix.as_deref() {
        if prefix.starts_with('/') {
            namebuff.clear();
        }
        namebuff.push_str(prefix);
        if !prefix.ends_with('/') {
            namebuff.push('/');
        }

        if parts.apref_ip {
            let oldlen = namebuff.len();
            namebuff.push_str(&parts.client_addr_str);
            namebuff.push('/');
            if !dir_exists(&namebuff) {
                namebuff.truncate(oldlen);
            }
        }

        if parts.apref_mac {
            if let Some(mac) = parts.client_mac {
                let oldlen = namebuff.len();
                namebuff.push_str(&format!(
                    "{:02x}-{:02x}-{:02x}-{:02x}-{:02x}-{:02x}/",
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
                ));
                if !dir_exists(&namebuff) {
                    namebuff.truncate(oldlen);
                }
            }
        }

        // Absolute pathnames OK if they match the prefix.
        if filename.starts_with('/') {
            if filename.starts_with(&namebuff) {
                namebuff.clear();
            } else {
                filename.remove(0);
            }
        }
    } else if filename.starts_with('/') {
        namebuff.clear();
    }

    namebuff.push_str(&filename);
    namebuff
}

// ---------------------------------------------------------------------------
// File open / permission check (ported from check_tftp_fileperm, tftp.c:538-619)
// ---------------------------------------------------------------------------

/// A shared, refcounted open file: multiple in-flight transfers of the same
/// file (matched by device + inode + name, as upstream does) share one `fd`.
/// Refcounting itself is just `Arc` — the file closes when the last
/// transfer holding it is dropped.
#[derive(Debug)]
pub struct TftpFile {
    file: std::fs::File,
    pub size: u64,
    pub dev: u64,
    pub inode: u64,
    pub filename: String,
    posn: u64,
}

/// Lock a shared `TftpFile`, recovering the guard even if a previous holder
/// panicked while holding it.
///
/// A `TftpFile` is shared (via `Arc<Mutex<_>>`) across every concurrent
/// transfer of the same file by design, for refcounting — so a plain
/// `.lock().unwrap()` would let one transfer's panic poison the mutex and
/// take down every other transfer of that file too. `TftpFile`'s own
/// invariants (the open `fd`, `posn`) are never left inconsistent by a
/// panic — nothing here does partial mutation across an await point — so
/// recovering a poisoned guard is safe.
fn lock_file(file: &Mutex<TftpFile>) -> MutexGuard<'_, TftpFile> {
    file.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[derive(Debug)]
pub enum TftpOpenError {
    NotFound,
    Perm,
    Oops(io::Error),
}

/// Open `namebuff` for a new transfer: reject `/../` traversal (only once a
/// prefix is configured — matching upstream, which only sets this trap when
/// `--tftp-root` is given), enforce world-readable-when-root /
/// owned-by-us-when-`--tftp-secure`, and share an already-open fd with any
/// in-flight transfer of the same (dev, inode, filename).
///
/// Port of `check_tftp_fileperm()` (tftp.c:538-619).
pub fn open_tftp_file(
    namebuff: &str,
    prefix_set: bool,
    secure: bool,
    shared: &[Arc<Mutex<TftpFile>>],
) -> Result<Arc<Mutex<TftpFile>>, TftpOpenError> {
    // "trick to ban moving out of the subtree" (tftp.c:547-549).
    if prefix_set && namebuff.contains("/../") {
        return Err(TftpOpenError::Perm);
    }

    let file = match std::fs::File::open(namebuff) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Err(TftpOpenError::NotFound),
        Err(e) if e.kind() == io::ErrorKind::PermissionDenied => return Err(TftpOpenError::Perm),
        Err(e) => return Err(TftpOpenError::Oops(e)),
    };

    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => return Err(TftpOpenError::Oops(e)),
    };

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let dev = meta.dev();
        let inode = meta.ino();
        let mode = meta.mode();
        let uid = unsafe { libc::geteuid() };

        if uid == 0 {
            // Running as root: must be world-readable.
            if mode & 0o004 == 0 {
                return Err(TftpOpenError::Perm);
            }
        } else if secure && uid != meta.uid() {
            return Err(TftpOpenError::Perm);
        }

        for existing in shared {
            let matches = {
                let f = lock_file(existing);
                f.dev == dev && f.inode == inode && f.filename == namebuff
            };
            if matches {
                return Ok(existing.clone());
            }
        }

        Ok(Arc::new(Mutex::new(TftpFile {
            file,
            size: meta.len(),
            dev,
            inode,
            filename: namebuff.to_string(),
            posn: 0,
        })))
    }
    #[cfg(not(unix))]
    {
        let _ = (secure, shared);
        Ok(Arc::new(Mutex::new(TftpFile {
            file,
            size: meta.len(),
            dev: 0,
            inode: 0,
            filename: namebuff.to_string(),
            posn: 0,
        })))
    }
}

// ---------------------------------------------------------------------------
// Transfer state
// ---------------------------------------------------------------------------

/// An active TFTP transfer — the real thing this time: a live peer address,
/// a socket to reply on, an open (possibly shared) file, and every bit of
/// negotiated-option and retransmit-timer state `struct tftp_transfer`
/// carries.
pub struct TftpTransfer {
    pub peer: SocketAddr,
    /// Source address to reply from (the address the request arrived on).
    pub source_addr: IpAddr,
    pub if_index: u32,
    /// The socket to send/receive on: the shared listener socket in
    /// `--tftp-single-port` mode, or a dedicated per-transfer socket
    /// otherwise.
    pub sock: Arc<tokio::net::UdpSocket>,
    pub single_port: bool,
    /// Join handle for the background task forwarding datagrams off this
    /// transfer's own socket; `None` in single-port mode, where the shared
    /// listener's forwarder already covers it.
    pub forwarder: Option<tokio::task::JoinHandle<()>>,
    pub file: Arc<Mutex<TftpFile>>,

    pub netascii: bool,
    pub blocksize: usize,
    pub windowsize: u32,
    pub opt_blocksize: bool,
    pub opt_transize: bool,
    pub opt_timeout: bool,
    pub opt_windowsize: bool,
    pub timeout: u32,
    pub backoff: u32,

    /// `None` once an ERROR packet aborts the transfer (upstream's
    /// `start == 0` sentinel).
    pub start: Option<Instant>,
    pub retransmit: Instant,

    pub block: u32,
    pub lastack: u32,
    pub ackprev: u16,
    pub block_hi: u32,

    pub offset: u64,
    pub expansion: u64,
    pub carrylf: bool,
    pub lastcarrylf: bool,

    /// One-block read-ahead cache, mirroring `daemon->srv_save`: avoids a
    /// double read between the initial send and the first retransmit pass.
    prefetch: Option<(u64, Vec<u8>)>,
}

impl TftpTransfer {
    pub fn new(
        peer: SocketAddr,
        source_addr: IpAddr,
        if_index: u32,
        sock: Arc<tokio::net::UdpSocket>,
        single_port: bool,
        file: Arc<Mutex<TftpFile>>,
    ) -> Self {
        let now = Instant::now();
        TftpTransfer {
            peer,
            source_addr,
            if_index,
            sock,
            single_port,
            forwarder: None,
            file,
            netascii: false,
            blocksize: 512,
            windowsize: 1,
            opt_blocksize: false,
            opt_transize: false,
            opt_timeout: false,
            opt_windowsize: false,
            timeout: 2,
            backoff: 1,
            start: Some(now),
            retransmit: now,
            block: 1,
            lastack: 0,
            ackprev: 0,
            block_hi: 0,
            offset: 0,
            expansion: 0,
            carrylf: false,
            lastcarrylf: false,
            prefetch: None,
        }
    }
}

// ---------------------------------------------------------------------------
// netascii CRLF expansion (ported from the tail of get_block, tftp.c:989-1013)
// ---------------------------------------------------------------------------

/// Expand bare `\n` to `\r\n` in a raw block read from disk, mirroring the
/// in-place, index-skipping algorithm in `get_block()`: growth is capped at
/// `blocksize`, and a `\n` landing exactly on the last byte of an already-full
/// block is deferred (`carrylf`) to the next block rather than expanded here,
/// with `offset` bookkeeping (done by the caller on ACK) making up the
/// difference.
fn netascii_expand(raw: &[u8], blocksize: usize, lastcarrylf: bool) -> (Vec<u8>, u64, bool) {
    let cap = blocksize.max(raw.len());
    let mut buf = vec![0u8; cap];
    buf[..raw.len()].copy_from_slice(raw);

    let mut size = raw.len();
    let mut expansion: u64 = 0;
    let mut carrylf = false;
    let mut i = 0usize;

    while i < size {
        if buf[i] == b'\n' && (i != 0 || !lastcarrylf) {
            expansion += 1;
            if size != blocksize {
                size += 1;
            } else if i == size - 1 {
                carrylf = true;
            }
            // memmove(&buf[i+1], &buf[i], size - (i+1))
            buf.copy_within(i..size - 1, i + 1);
            buf[i] = b'\r';
            i += 1;
        }
        i += 1;
    }

    buf.truncate(size);
    (buf, expansion, carrylf)
}

// ---------------------------------------------------------------------------
// Block reading (ported from get_block(), tftp.c:905-1021)
// ---------------------------------------------------------------------------

/// Result of reading a file block for a TFTP transfer.
#[derive(Debug)]
pub enum GetBlockResult {
    /// Block 0: send an OACK with the negotiated options.
    Oack(Vec<u8>),
    /// Data block to send.
    Data(Vec<u8>),
    /// Transfer complete (past end of file).
    Done,
}

/// Read (or fetch from the one-block prefetch cache) the next DATA/OACK
/// packet for `transfer`, from its actual open file.
///
/// Port of `get_block()` (tftp.c:905-1021).
pub fn get_block(transfer: &mut TftpTransfer) -> io::Result<GetBlockResult> {
    use std::io::{Read, Seek, SeekFrom};

    if transfer.block == 0 {
        let mut opts: Vec<(String, String)> = Vec::new();
        if transfer.opt_blocksize {
            opts.push(("blksize".to_string(), transfer.blocksize.to_string()));
        }
        if transfer.opt_transize {
            let size = lock_file(&transfer.file).size;
            opts.push(("tsize".to_string(), size.to_string()));
        }
        if transfer.opt_timeout {
            opts.push(("timeout".to_string(), transfer.timeout.to_string()));
        }
        if transfer.opt_windowsize {
            opts.push(("windowsize".to_string(), transfer.windowsize.to_string()));
        }
        let refs: Vec<(&str, &str)> = opts.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        return Ok(GetBlockResult::Oack(build_oack(&refs)));
    }

    if !transfer.netascii {
        transfer.offset = (transfer.block as u64 - 1) * transfer.blocksize as u64;
    }

    let file_size = lock_file(&transfer.file).size;
    if transfer.offset > file_size {
        return Ok(GetBlockResult::Done);
    }

    if let Some((off, data)) = &transfer.prefetch {
        if *off == transfer.offset {
            let data = data.clone();
            return Ok(GetBlockResult::Data(build_data(transfer.block as u16, &data)));
        }
    }
    transfer.prefetch = None;

    let want = ((file_size - transfer.offset).min(transfer.blocksize as u64)) as usize;
    let mut raw = vec![0u8; want];
    if want != 0 {
        let mut f = lock_file(&transfer.file);
        if f.posn != transfer.offset {
            f.file.seek(SeekFrom::Start(transfer.offset))?;
        }
        f.file.read_exact(&mut raw)?;
        f.posn = transfer.offset + want as u64;
    }

    let data = if transfer.netascii {
        let (expanded, expansion, carrylf) = netascii_expand(&raw, transfer.blocksize, transfer.lastcarrylf);
        transfer.expansion = expansion;
        transfer.carrylf = carrylf;
        expanded
    } else {
        raw
    };

    transfer.prefetch = Some((transfer.offset, data.clone()));
    Ok(GetBlockResult::Data(build_data(transfer.block as u16, &data)))
}

// ---------------------------------------------------------------------------
// ACK/ERROR handling (ported from handle_tftp(), tftp.c:752-824)
// ---------------------------------------------------------------------------

/// Result of handling an incoming TFTP packet for an active transfer.
#[derive(Debug, PartialEq)]
pub enum TftpHandleResult {
    /// ACK advanced the window; `lastack` is the new value.
    AckAdvance { lastack: u32 },
    /// ACK for an already-acknowledged or not-yet-sent block (ignored).
    AckIgnored,
    /// Client sent an ERROR packet; the transfer is aborted (`start` cleared).
    Error { code: u16, message: String },
    /// Packet too short or unrecognized opcode.
    InvalidPacket,
}

/// Process an incoming TFTP packet (ACK or ERROR) for an active transfer,
/// including the 16-bit ACK block number's wraparound-to-32-bit math.
///
/// Port of `handle_tftp()` (tftp.c:752-824).
pub fn handle_tftp_packet(transfer: &mut TftpTransfer, packet: &[u8], now: Instant) -> TftpHandleResult {
    if packet.len() < 4 {
        return TftpHandleResult::InvalidPacket;
    }
    let opcode = u16::from_be_bytes([packet[0], packet[1]]);
    match opcode {
        4 => {
            let new = u16::from_be_bytes([packet[2], packet[3]]);

            // If the last ACK was in the top quarter of a 64k block and this
            // one is in the bottom quarter, assume it wrapped; the reverse
            // step handles a stray old duplicate wandering in.
            if new <= 0x4000 && transfer.ackprev >= 0xc000 {
                transfer.block_hi += 1;
            } else if new >= 0xc000 && transfer.ackprev <= 0x4000 && transfer.block_hi != 0 {
                transfer.block_hi -= 1;
            }
            transfer.ackprev = new;
            let block = (transfer.block_hi << 16) + new as u32;

            // Ignore duplicate ACKs and ACKs for blocks not yet sent.
            if block >= transfer.lastack && block <= transfer.block {
                transfer.retransmit = now;
                transfer.start = Some(now);
                transfer.backoff = 0;
                transfer.lastack = block + 1;

                if transfer.netascii && block != 0 {
                    transfer.offset += transfer.blocksize as u64 - transfer.expansion;
                    transfer.lastcarrylf = transfer.carrylf;
                }
                TftpHandleResult::AckAdvance { lastack: transfer.lastack }
            } else {
                TftpHandleResult::AckIgnored
            }
        }
        5 => {
            let code = u16::from_be_bytes([packet[2], packet[3]]);
            let msg = if packet.len() > 4 {
                let end = packet[4..].iter().position(|&b| b == 0).unwrap_or(packet.len() - 4);
                tftp_sanitise(&String::from_utf8_lossy(&packet[4..4 + end]))
            } else {
                String::new()
            };
            transfer.start = None;
            TftpHandleResult::Error { code, message: msg }
        }
        _ => TftpHandleResult::InvalidPacket,
    }
}

// ---------------------------------------------------------------------------
// Runtime: transfer table + retransmit driver
// (ported from check_tftp_listeners()/tftp_request()/free_transfer(), unix only)
// ---------------------------------------------------------------------------

/// One bound TFTP listener socket, plus what the request handler needs to
/// know about the interface it is bound to (or `None` for a wildcard bind,
/// where the interface is resolved per-datagram via `IP_PKTINFO`).
#[derive(Debug, Clone)]
pub struct TftpListenerHandle {
    pub sock: Arc<tokio::net::UdpSocket>,
    pub addr: SocketAddr,
    pub iface: Option<String>,
    pub mtu: Option<i32>,
}

/// Daemon-derived TFTP configuration the runtime loop needs; assembled once
/// by `dnsmasq::daemon_tftp_config` from `Daemon`'s `tftp_*` fields and
/// `OPT_TFTP_*` flags.
#[derive(Debug, Clone)]
pub struct TftpConfig {
    pub prefix: Option<String>,
    pub secure: bool,
    pub no_blocksize_option: bool,
    pub lowercase: bool,
    pub single_port: bool,
    pub apref_ip: bool,
    pub apref_mac: bool,
    pub quiet: bool,
    /// `<= 0` means "use [`TFTP_MAX_CONNECTIONS_DEFAULT`]".
    pub max_transfers: i32,
    /// `0` means "no configured override; use the interface MTU alone".
    pub mtu_override: i32,
    /// `0` start port means "bind ephemeral" (no `--tftp-port-range`).
    pub start_port: u16,
    pub end_port: u16,
    /// The dedicated `--enable-tftp=iface,...` list; empty means "every
    /// interface DNS/DHCP would also serve is allowed".
    pub interfaces: Vec<String>,
    /// `daemon->packet_buff_sz` (see [`packet_buff_sz`]) — the unconditional
    /// `blksize` ceiling upstream applies ahead of the MTU clamp.
    pub packet_buff_sz: usize,
}

impl Default for TftpConfig {
    fn default() -> Self {
        TftpConfig {
            prefix: None,
            secure: false,
            no_blocksize_option: false,
            lowercase: false,
            single_port: false,
            apref_ip: false,
            apref_mac: false,
            quiet: false,
            max_transfers: 0,
            mtu_override: 0,
            start_port: 0,
            end_port: 0,
            interfaces: Vec::new(),
            // Upstream's own default absent `--edns-packet-max`
            // (`option.c:5980`: `daemon->edns_pktsz = EDNS_PKTSZ` = 1232).
            packet_buff_sz: packet_buff_sz(1232),
        }
    }
}

fn effective_max(config: &TftpConfig) -> i32 {
    if config.max_transfers > 0 { config.max_transfers } else { TFTP_MAX_CONNECTIONS_DEFAULT }
}

/// Events fed into the central transfer-table loop by the listener and
/// per-transfer forwarder tasks.
enum TftpEvent {
    Listener { listener_idx: usize, meta: crate::network::RecvMeta, data: Vec<u8> },
    Transfer { id: u64, peer: SocketAddr, data: Vec<u8> },
}

fn drop_transfer(mut t: TftpTransfer) {
    if let Some(h) = t.forwarder.take() {
        h.abort();
    }
    // `t.file` (Arc<Mutex<TftpFile>>) and `t.sock` close/drop naturally once
    // their last reference goes away.
}

fn log_transfer_end(t: &TftpTransfer, timeout: bool, error: bool, config: &TftpConfig) {
    let fname = lock_file(&t.file).filename.clone();
    if timeout {
        warn!("timeout sending {fname} to {}", t.peer);
    } else if error {
        warn!("failed sending {fname} to {}", t.peer);
    } else if !config.quiet {
        info!("sent {fname} to {}", t.peer);
    }
}

#[cfg(unix)]
async fn send_packet_to(transfer: &TftpTransfer, peer: SocketAddr, pkt: &[u8]) {
    use std::os::unix::io::AsRawFd;
    let fd = transfer.sock.as_raw_fd();
    let nowild = !transfer.single_port;
    if let Err(e) = crate::forward::send_from(fd, nowild, pkt, peer, Some(transfer.source_addr), transfer.if_index) {
        warn!("failed to send TFTP packet to {peer}: {e}");
    }
}

#[cfg(unix)]
async fn send_packet(transfer: &TftpTransfer, pkt: &[u8]) {
    send_packet_to(transfer, transfer.peer, pkt).await;
}

/// Send one window's worth of blocks (or just the OACK), advancing
/// `transfer.block` after each. Returns `(endcon, error)`.
///
/// Port of the per-transfer body of the retransmit branch in
/// `check_tftp_listeners()` (tftp.c:693-717), factored out since
/// `tftp_request`'s initial reply and every later (re)transmission both run
/// through it.
#[cfg(unix)]
async fn send_window(transfer: &mut TftpTransfer) -> (bool, bool) {
    let winsize = if transfer.block != 0 { transfer.windowsize } else { 1 };
    for i in 0..winsize {
        match get_block(transfer) {
            Ok(GetBlockResult::Done) => return (i == 0, false),
            Ok(GetBlockResult::Oack(pkt)) | Ok(GetBlockResult::Data(pkt)) => {
                send_packet(transfer, &pkt).await;
                transfer.block += 1;
            }
            Err(e) => {
                let fname = lock_file(&transfer.file).filename.clone();
                let err = tftp_err_oops(&fname, &e);
                send_packet(transfer, &err).await;
                return (true, true);
            }
        }
    }
    (false, false)
}

/// Apply an incoming ACK/ERROR to `transfer`; on a valid ACK, immediately
/// send the next window (rather than waiting for the next sweep tick — the
/// same packets upstream sends, just without an added poll-interval delay).
/// Returns `true` if the transfer is now finished and should be removed.
#[cfg(unix)]
async fn process_transfer_packet(transfer: &mut TftpTransfer, data: &[u8], config: &TftpConfig) -> bool {
    let now = Instant::now();
    match handle_tftp_packet(transfer, data, now) {
        TftpHandleResult::AckAdvance { .. } => {
            // Mirrors the `transfer->block = transfer->lastack;` reset that
            // upstream's retransmit branch does (tftp.c:691) immediately
            // before sending the window: without it `transfer.block` is
            // still the pre-ACK block number (0 on the very first ACK, since
            // any negotiated option resets it there), so `send_window` would
            // resend the OACK/prior block instead of the next window.
            transfer.block = transfer.lastack;
            // Also mirror the retransmit-timer bookkeeping the same branch
            // does (tftp.c:684-686) immediately before sending: without this,
            // `transfer.retransmit` is left at the ACK-arrival instant (set
            // by `handle_tftp_packet` above), so the very next sweep tick
            // would see it as overdue and resend this same window a second
            // time. Upstream never double-sends here because the ACK-driven
            // send and the timeout-driven resend are the same code path
            // (`check_tftp_listeners`'s single retransmit branch); this keeps
            // that invariant for the immediate-send path used here.
            // Additive from the current deadline (`transfer.retransmit`, just
            // set to `now` by `handle_tftp_packet` above), matching upstream's
            // `transfer->retransmit += transfer->timeout + (1<<(backoff/2))`
            // (`tftp.c:689`) rather than a fresh `now + ...` — see
            // `sweep_transfers`'s identical computation for why this matters
            // under scheduling delay.
            let backoff = transfer.backoff;
            let shift = (backoff / 2).min(20);
            transfer.retransmit =
                transfer.retransmit + Duration::from_secs(transfer.timeout as u64) + Duration::from_secs(1u64 << shift);
            transfer.backoff = backoff.saturating_add(1);
            let (endcon, _error) = send_window(transfer).await;
            if endcon {
                return true;
            }
            let _ = get_block(transfer); // prefetch the likely-next block
            false
        }
        TftpHandleResult::AckIgnored | TftpHandleResult::InvalidPacket => false,
        TftpHandleResult::Error { code, message } => {
            if !config.quiet {
                warn!("error {code} {message} received from {}", transfer.peer);
            }
            true
        }
    }
}

/// Resolve the interface a request arrived on, and its MTU: known directly
/// for a listener bound to a specific interface; via `IP_PKTINFO`'s
/// `if_index` (`indextoname` + `SIOCGIFMTU`) for a wildcard bind.
fn resolve_request_interface(
    listener: &TftpListenerHandle,
    meta: &crate::network::RecvMeta,
) -> (Option<String>, Option<i32>) {
    if listener.iface.is_some() {
        return (listener.iface.clone(), listener.mtu);
    }
    if meta.if_index != 0 {
        if let Some(name) = crate::network::indextoname(meta.if_index) {
            let mtu = crate::network::interface_mtu(&name);
            return (Some(name), mtu);
        }
    }
    (None, None)
}

#[cfg(unix)]
async fn bind_transfer_socket(source: IpAddr, config: &TftpConfig) -> io::Result<tokio::net::UdpSocket> {
    if config.start_port == 0 {
        return tokio::net::UdpSocket::bind(SocketAddr::new(source, 0)).await;
    }
    let mut port = config.start_port;
    loop {
        match tokio::net::UdpSocket::bind(SocketAddr::new(source, port)).await {
            Ok(s) => return Ok(s),
            Err(e) if e.kind() == io::ErrorKind::AddrInUse && port < config.end_port => {
                port += 1;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Send a reply through a request's own socket (the per-transfer socket, or
/// the shared listener socket in single-port mode) rather than the
/// listener's socket directly. Upstream binds `transfer->sockfd` before
/// parsing the opcode (tftp.c:305-359) and every reply — including the
/// terminal error packets for WRQ/empty-filename/bad-mode/file-not-found —
/// goes out through it (tftp.c:518), never through the bare listener socket.
#[cfg(unix)]
async fn send_transfer_reply(
    sock: &tokio::net::UdpSocket,
    single_port: bool,
    source_addr: IpAddr,
    if_index: u32,
    peer: SocketAddr,
    pkt: &[u8],
) {
    use std::os::unix::io::AsRawFd;
    let fd = sock.as_raw_fd();
    let nowild = !single_port;
    if let Err(e) = crate::forward::send_from(fd, nowild, pkt, peer, Some(source_addr), if_index) {
        warn!("failed to send TFTP error to {peer}: {e}");
    }
}

/// Live TFTP transfer runtime state: the transfer table (keyed by the id
/// each transfer's forwarder task tags its `TftpEvent::Transfer` messages
/// with), the next id to hand out, and the sender every forwarder task
/// (listener and per-transfer alike) pushes events through.
///
/// Bundling these together — rather than threading `transfers`, `ids`,
/// `next_id`, and `tx` as four separate parameters — also retires the old
/// parallel `transfers: Vec<TftpTransfer>` / `ids: Vec<u64>` pair: they were
/// always mutated in lockstep (same index removed from both), which a single
/// `HashMap<u64, TftpTransfer>` keyed by id makes structurally impossible to
/// desync.
#[cfg(unix)]
struct TftpRuntime {
    transfers: HashMap<u64, TftpTransfer>,
    next_id: u64,
    tx: tokio::sync::mpsc::Sender<TftpEvent>,
}

#[cfg(unix)]
impl TftpRuntime {
    fn new(tx: tokio::sync::mpsc::Sender<TftpEvent>) -> Self {
        Self { transfers: HashMap::new(), next_id: 1, tx }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }
}

/// Handle a fresh (or single-port-shared-socket) RRQ, exactly as
/// `tftp_request()` does after the single-port peer-matching dance: parse
/// filename/mode/options, resolve+open the file, and send exactly one
/// initial reply packet (OACK if any option was negotiated, else DATA block
/// 1) — matching upstream's single `get_block()` call in `tftp_request`,
/// *not* a full window (window sends only happen from ACK/timeout handling).
///
/// Port of `tftp_request()` (tftp.c:44-536).
#[cfg(unix)]
async fn handle_new_request(
    listener: &TftpListenerHandle,
    meta: &crate::network::RecvMeta,
    data: &[u8],
    config: &TftpConfig,
    runtime: &mut TftpRuntime,
) {
    if data.len() < 2 {
        return;
    }
    let opcode = u16::from_be_bytes([data[0], data[1]]);
    if opcode != TftpOpcode::Wrq as u16 && opcode != TftpOpcode::Rrq as u16 {
        // Upstream binds a transfer socket even for an unrecognized opcode,
        // but since no reply is ever sent for it (tftp.c:518 `if (len)`
        // guards the only send), skipping the bind here has no observable
        // wire effect — it just avoids a pointless bind+close.
        return;
    }
    let peer = meta.src;
    let client_addr_str = peer.ip().to_string();

    // Upstream binds `transfer->sockfd` here, before parsing the opcode
    // body, and every reply below — including terminal errors — goes out
    // through it rather than the listener socket (tftp.c:305-359, 518).
    let source_addr = meta.dest.unwrap_or_else(|| listener.addr.ip());
    let (sock, single_port) = if config.single_port {
        (listener.sock.clone(), true)
    } else {
        match bind_transfer_socket(source_addr, config).await {
            Ok(s) => (Arc::new(s), false),
            Err(e) => {
                warn!("unable to get a free port for TFTP: {e}");
                return;
            }
        }
    };
    let if_index = meta.if_index;
    macro_rules! reply {
        ($pkt:expr) => {
            send_transfer_reply(&sock, single_port, source_addr, if_index, peer, $pkt).await
        };
    }

    if opcode == TftpOpcode::Wrq as u16 {
        let err = tftp_err_packet(
            TftpError::IllegalOp,
            &format!("unsupported write request from {client_addr_str}"),
        );
        reply!(&err);
        return;
    }

    let (filename_raw, mode, options) = match parse_rrq(data) {
        Ok(v) => v,
        Err(_) => return,
    };
    if filename_raw.is_empty() {
        let err = tftp_err_packet(
            TftpError::IllegalOp,
            &format!("empty filename in request from {client_addr_str}"),
        );
        reply!(&err);
        return;
    }
    let netascii = mode.eq_ignore_ascii_case("netascii");
    if !netascii && !mode.eq_ignore_ascii_case("octet") {
        let err = tftp_err_packet(TftpError::IllegalOp, &format!("unsupported request from {client_addr_str}"));
        reply!(&err);
        return;
    }

    let (iface_name, iface_mtu) = resolve_request_interface(listener, meta);
    if let Some(name) = iface_name.as_deref() {
        if !config.interfaces.is_empty()
            && !config.interfaces.iter().any(|p| crate::network::iface_name_matches(name, p))
        {
            return;
        }
    }
    let mut mtu = iface_mtu.unwrap_or(0);
    if config.mtu_override != 0 && (mtu == 0 || config.mtu_override < mtu) {
        mtu = config.mtu_override;
    }
    let mtu_opt = if mtu != 0 { Some(mtu) } else { None };

    let opts = parse_request_options(
        &options,
        netascii,
        peer.is_ipv4(),
        mtu_opt,
        config.no_blocksize_option,
        config.packet_buff_sz,
    );
    let any_opt = any_option_negotiated(&opts);

    let namebuff = build_tftp_path(
        &filename_raw,
        &PathParts {
            prefix: config.prefix.clone(),
            lowercase: config.lowercase,
            apref_ip: config.apref_ip,
            apref_mac: config.apref_mac,
            client_addr_str: client_addr_str.clone(),
            client_mac: None,
        },
    );

    let shared: Vec<Arc<Mutex<TftpFile>>> = runtime.transfers.values().map(|t| t.file.clone()).collect();
    let file = match open_tftp_file(&namebuff, config.prefix.is_some(), config.secure, &shared) {
        Ok(f) => f,
        Err(TftpOpenError::NotFound) => {
            let err = tftp_err_packet(
                TftpError::FileNotFound,
                &format!("file {namebuff} not found for {client_addr_str}"),
            );
            reply!(&err);
            return;
        }
        Err(TftpOpenError::Perm) => {
            let err = tftp_err_packet(TftpError::AccessViolation, &format!("cannot access {namebuff}: Permission denied"));
            reply!(&err);
            return;
        }
        Err(TftpOpenError::Oops(e)) => {
            let err = tftp_err_oops(&namebuff, &e);
            reply!(&err);
            return;
        }
    };

    if runtime.transfers.len() as i32 >= effective_max(config) {
        return;
    }

    let mut transfer = TftpTransfer::new(peer, source_addr, if_index, sock.clone(), single_port, file);
    transfer.netascii = netascii;
    transfer.blocksize = opts.blocksize;
    transfer.opt_blocksize = opts.opt_blocksize;
    transfer.opt_transize = opts.opt_transize;
    transfer.opt_timeout = opts.opt_timeout;
    transfer.opt_windowsize = opts.opt_windowsize;
    transfer.timeout = opts.timeout;
    transfer.windowsize = opts.windowsize;
    if any_opt {
        transfer.block = 0;
    }
    transfer.lastack = transfer.block;
    transfer.retransmit = Instant::now() + Duration::from_secs(transfer.timeout.max(1) as u64);

    let pkt = match get_block(&mut transfer) {
        Ok(GetBlockResult::Oack(p)) | Ok(GetBlockResult::Data(p)) => p,
        Ok(GetBlockResult::Done) => return,
        Err(e) => {
            let fname = lock_file(&transfer.file).filename.clone();
            let err = tftp_err_oops(&fname, &e);
            send_packet(&transfer, &err).await;
            drop_transfer(transfer);
            return;
        }
    };
    send_packet(&transfer, &pkt).await;

    let id = runtime.alloc_id();

    if !single_port {
        let sock2 = sock.clone();
        let tx2 = runtime.tx.clone();
        transfer.forwarder = Some(tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                match sock2.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        if tx2.send(TftpEvent::Transfer { id, peer, data: buf[..len].to_vec() }).await.is_err() {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        }));
    }

    runtime.transfers.insert(id, transfer);
}

#[cfg(unix)]
async fn handle_listener_datagram(
    listener: &TftpListenerHandle,
    meta: crate::network::RecvMeta,
    data: Vec<u8>,
    config: &TftpConfig,
    runtime: &mut TftpRuntime,
) {
    if config.single_port && data.len() >= 2 {
        let opcode = u16::from_be_bytes([data[0], data[1]]);
        let matched_id = runtime.transfers.iter().find(|(_, t)| t.peer == meta.src).map(|(&id, _)| id);
        if let Some(id) = matched_id {
            if opcode == TftpOpcode::Rrq as u16 {
                if let Some(t) = runtime.transfers.remove(&id) {
                    drop_transfer(t);
                }
            } else {
                let Some(transfer) = runtime.transfers.get_mut(&id) else { return };
                if process_transfer_packet(transfer, &data, config).await {
                    let t = runtime.transfers.remove(&id).expect("id was just looked up above");
                    log_transfer_end(&t, false, true, config);
                    drop_transfer(t);
                }
                return;
            }
        } else if runtime.transfers.len() as i32 >= effective_max(config) {
            return;
        }
    }

    handle_new_request(listener, &meta, &data, config, runtime).await;
}

#[cfg(unix)]
async fn sweep_transfers(transfers: &mut HashMap<u64, TftpTransfer>, config: &TftpConfig) {
    let now = Instant::now();
    // Two-phase: decide which transfers end during one pass over the map
    // (mutating each transfer in place as upstream's single indexed loop
    // does), then remove them afterward — a `HashMap` can't have entries
    // removed while an iterator over it is live, unlike the old `Vec`'s
    // index-based `while i < transfers.len()` loop.
    let mut ended: Vec<(u64, bool, bool)> = Vec::new(); // (id, timeout_flag, error)

    for (&id, transfer) in transfers.iter_mut() {
        let mut endcon = false;
        let mut error = false;
        let mut timeout_flag = false;

        if transfer.start.is_none() {
            endcon = true;
            error = true;
        } else if now.duration_since(transfer.start.expect("checked Some above")) > Duration::from_secs(TFTP_TRANSFER_TIME_SECS) {
            endcon = true;
            // Don't complain when we're just awaiting the last ACK — some
            // clients never send it.
            if !matches!(get_block(transfer), Ok(GetBlockResult::Done)) {
                error = true;
                timeout_flag = true;
            }
        } else if now >= transfer.retransmit {
            // Additive from the previous deadline, not from `now`, matching
            // upstream's `transfer->retransmit += transfer->timeout +
            // (1<<(backoff/2))` (`tftp.c:689`). Under scheduling delay (the
            // sweep tick firing later than the deadline it's checking), `now`
            // can run meaningfully ahead of `transfer.retransmit`; basing
            // the next deadline on `now` instead of the missed one would push
            // every subsequent retry later than upstream's cadence.
            let backoff = transfer.backoff;
            let shift = (backoff / 2).min(20);
            transfer.retransmit = transfer.retransmit
                + Duration::from_secs(transfer.timeout as u64)
                + Duration::from_secs(1u64 << shift);
            transfer.backoff = backoff.saturating_add(1);
            transfer.block = transfer.lastack;

            let (ec, err) = send_window(transfer).await;
            endcon = ec;
            error = err;
            if !endcon {
                let _ = get_block(transfer); // prefetch
            }
        }

        if endcon {
            ended.push((id, timeout_flag, error));
        }
    }

    for (id, timeout_flag, error) in ended {
        let Some(t) = transfers.remove(&id) else { continue };
        log_transfer_end(&t, timeout_flag, error, config);
        drop_transfer(t);
        // `do_tftp_script_run`'s completion hook (tftp.c:1024-1039) would
        // fire here; the external-script pipeline it feeds
        // (`helper::create_helper`/`HelperHandle`) isn't wired into the main
        // loop for any daemon subsystem yet — see tasks.md.
    }
}

/// Run the TFTP server: accept requests on `listeners`, drive every active
/// transfer's ACK/retransmit/timeout state machine, until the task is
/// aborted by the caller (mirrors `run_forward_loop_on`'s lifecycle — there
/// is no persistent state here that needs a graceful-shutdown handshake).
///
/// Port of `check_tftp_listeners()` (tftp.c:621-750), restructured around
/// tokio: one forwarder task per listener socket (and, once created, per
/// per-transfer socket) pushes datagrams onto a channel the central loop
/// drains, interleaved with a periodic sweep that drives retransmission and
/// the 120s abandoned-transfer timeout.
#[cfg(unix)]
pub async fn run_tftp_loop(listeners: Vec<TftpListenerHandle>, config: TftpConfig) -> io::Result<()> {
    use std::os::unix::io::AsRawFd;
    use tokio::sync::mpsc;

    if listeners.is_empty() {
        return Ok(());
    }

    let (tx, mut rx) = mpsc::channel::<TftpEvent>(256);

    for (idx, l) in listeners.iter().enumerate() {
        let sock = l.sock.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            loop {
                if sock.readable().await.is_err() {
                    return;
                }
                let fd = sock.as_raw_fd();
                match sock.try_io(tokio::io::Interest::READABLE, || crate::network::recv_with_dest(fd, &mut buf)) {
                    Ok(meta) => {
                        let data = buf[..meta.len].to_vec();
                        if tx.send(TftpEvent::Listener { listener_idx: idx, meta, data }).await.is_err() {
                            return;
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                    Err(_) => continue,
                }
            }
        });
    }
    let mut runtime = TftpRuntime::new(tx);
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            ev = rx.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    TftpEvent::Listener { listener_idx, meta, data } => {
                        handle_listener_datagram(&listeners[listener_idx], meta, data, &config, &mut runtime).await;
                    }
                    TftpEvent::Transfer { id, peer, data } => {
                        let Some(transfer) = runtime.transfers.get_mut(&id) else { continue };
                        if peer != transfer.peer {
                            // Wrong source address — RFC 1350 §4.
                            let err = tftp_err_packet(
                                TftpError::UnknownTransferId,
                                &format!("ignoring packet from {peer} (TID mismatch)"),
                            );
                            send_packet_to(transfer, peer, &err).await;
                            continue;
                        }
                        if process_transfer_packet(transfer, &data, &config).await {
                            let t = runtime.transfers.remove(&id).expect("id was just looked up above");
                            log_transfer_end(&t, false, true, &config);
                            drop_transfer(t);
                        }
                    }
                }
            }
            _ = tick.tick() => {
                sweep_transfers(&mut runtime.transfers, &config).await;
            }
        }
    }

    Ok(())
}

/// Non-Unix stub: this port's socket-level TFTP internals (`recv_with_dest`,
/// `send_from`, raw-fd `AsRawFd` control-message tricks) are Unix-only, same
/// as the DNS/DHCP forwarding loops they're modeled on.
#[cfg(not(unix))]
pub async fn run_tftp_loop(_listeners: Vec<TftpListenerHandle>, _config: TftpConfig) -> io::Result<()> {
    Ok(())
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

    // ── wire format ─────────────────────────────────────────────────────────

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
        assert!(parse_rrq(&[0, 1]).is_err());
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

    // ── sanitize_filename ───────────────────────────────────────────────────

    #[test]
    fn sanitize_normal_filename() {
        assert_eq!(sanitize_filename("boot/pxelinux.0"), Some("boot/pxelinux.0".to_string()));
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
    }

    #[test]
    fn sanitize_rejects_null_bytes() {
        assert_eq!(sanitize_filename("file\0.txt"), None);
    }

    #[test]
    fn sanitize_converts_backslashes() {
        assert_eq!(sanitize_filename("boot\\pxe\\file.0"), Some("boot/pxe/file.0".to_string()));
    }

    // ── next_cstring / tftp_sanitise / tftp_err_packet / tftp_err_oops ─────

    #[test]
    fn next_cstring_basic() {
        let buf = b"hello\0world";
        let mut pos = 0;
        let s = next_cstring(buf, &mut pos).unwrap();
        assert_eq!(s, b"hello");
        assert_eq!(pos, 6);
    }

    #[test]
    fn next_cstring_empty_returns_none() {
        let mut pos = 0;
        assert!(next_cstring(b"\0rest", &mut pos).is_none());
    }

    #[test]
    fn tftp_sanitise_removes_control() {
        assert_eq!(tftp_sanitise("hel\x01lo"), "hello");
    }

    #[test]
    fn tftp_err_packet_truncates_long() {
        let long_msg = "x".repeat(600);
        let pkt = tftp_err_packet(TftpError::NotDefined, &long_msg);
        assert!(pkt.len() <= 4 + 500 + 1);
    }

    #[test]
    fn tftp_err_oops_contains_filename_and_error() {
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "not found");
        let pkt = tftp_err_oops("test.bin", &err);
        let msg = String::from_utf8_lossy(&pkt[4..]);
        assert!(msg.contains("test.bin"));
        assert!(msg.contains("not found"));
    }

    // ── parse_request_options ───────────────────────────────────────────────

    #[test]
    fn options_blksize_basic() {
        let opts = parse_request_options(&[("blksize".into(), "1024".into())], false, true, None, false, 65536);
        assert_eq!(opts.blocksize, 1024);
        assert!(opts.opt_blocksize);
    }

    #[test]
    fn options_blksize_floor_is_one_not_eight() {
        // Upstream's floor is `if (val < 1) val = 1;` — not 8.
        let opts = parse_request_options(&[("blksize".into(), "0".into())], false, true, None, false, 65536);
        assert_eq!(opts.blocksize, 1);
    }

    /// Upstream's option loop (`tftp.c:383-411`) has no ceiling on `blksize`
    /// independent of `packet_buff_sz - 4` and the MTU clamp — no
    /// RFC 2348-style hard maximum exists in the C source (confirmed by grep
    /// across `original_dnsmasq_src/`). A large `--edns-packet-max` can
    /// therefore negotiate a blksize far above RFC 2348's suggested 65464.
    #[test]
    fn options_blksize_has_no_independent_ceiling() {
        let opts =
            parse_request_options(&[("blksize".into(), "999999".into())], false, true, None, false, 1_000_000);
        assert_eq!(opts.blocksize, 1_000_000 - 4);
    }

    #[test]
    fn options_blksize_clamped_by_packet_buff_sz() {
        // Port of tftp.c:391-392: `val > packet_buff_sz - 4` clamps
        // unconditionally, before (and independent of) the MTU clamp — the
        // default `packet_buff_sz` (edns_pktsz 1232 + MAXDNAME + RRFIXEDSZ)
        // caps blksize around 2263 even when the MTU is unknown.
        let buff = packet_buff_sz(1232);
        let opts = parse_request_options(&[("blksize".into(), "9999".into())], false, true, None, false, buff);
        assert_eq!(opts.blocksize, buff - 4);
    }

    /// Upstream: `unsigned int val = atoi(arg);` — a negative value wraps to
    /// a huge unsigned one, so the `if (val < 1) val = 1;` floor never fires;
    /// the value instead gets clamped *down* to whichever ceiling applies
    /// next. Real dnsmasq given `blksize=-1` therefore negotiates
    /// `packet_buff_sz - 4` bytes, not 1.
    #[test]
    fn options_blksize_negative_wraps_to_huge_then_clamps_to_ceiling() {
        let buff = packet_buff_sz(1232);
        let opts = parse_request_options(&[("blksize".into(), "-1".into())], false, true, None, false, buff);
        assert_eq!(opts.blocksize, buff - 4);
    }

    #[test]
    fn options_blksize_negative_clamps_to_mtu_when_narrower_than_buff() {
        let opts =
            parse_request_options(&[("blksize".into(), "-1".into())], false, true, Some(1500), false, 65536);
        assert_eq!(opts.blocksize, 1500 - 32);
    }

    #[test]
    fn options_blksize_clamped_by_mtu_v4_overhead() {
        let opts =
            parse_request_options(&[("blksize".into(), "2000".into())], false, true, Some(1500), false, 65536);
        assert_eq!(opts.blocksize, 1500 - 32);
    }

    #[test]
    fn options_blksize_clamped_by_mtu_v6_overhead() {
        let opts =
            parse_request_options(&[("blksize".into(), "2000".into())], false, false, Some(1500), false, 65536);
        assert_eq!(opts.blocksize, 1500 - 52);
    }

    #[test]
    fn options_blksize_ignored_when_no_block_option_set() {
        let opts = parse_request_options(&[("blksize".into(), "1024".into())], false, true, None, true, 65536);
        assert!(!opts.opt_blocksize);
        assert_eq!(opts.blocksize, 512);
    }

    #[test]
    fn options_tsize_set_opt_flag_octet_mode() {
        let opts = parse_request_options(&[("tsize".into(), "0".into())], false, true, None, false, 65536);
        assert!(opts.opt_transize);
    }

    #[test]
    fn options_tsize_ignored_in_netascii_mode() {
        let opts = parse_request_options(&[("tsize".into(), "0".into())], true, true, None, false, 65536);
        assert!(!opts.opt_transize);
    }

    #[test]
    fn options_windowsize_ignored_in_netascii_mode() {
        let opts = parse_request_options(&[("windowsize".into(), "4".into())], true, true, None, false, 65536);
        assert!(!opts.opt_windowsize);
        assert_eq!(opts.windowsize, 1);
    }

    #[test]
    fn options_windowsize_clamped_to_max() {
        let opts = parse_request_options(&[("windowsize".into(), "999".into())], false, true, None, false, 65536);
        assert_eq!(opts.windowsize, TFTP_MAX_WINDOW);
    }

    /// Upstream: `unsigned int val = atoi(arg);` wraps a negative value to a
    /// huge unsigned one before `if (val < 1) val = 1;` ever runs, so it gets
    /// clamped down to `TFTP_MAX_WINDOW` by the next check instead — not
    /// floored to 1.
    #[test]
    fn options_windowsize_negative_wraps_to_huge_then_clamps_to_max() {
        let opts = parse_request_options(&[("windowsize".into(), "-1".into())], false, true, None, false, 65536);
        assert_eq!(opts.windowsize, TFTP_MAX_WINDOW);
    }

    #[test]
    fn options_timeout_clamped_to_255() {
        let opts = parse_request_options(&[("timeout".into(), "9999".into())], false, true, None, false, 65536);
        assert_eq!(opts.timeout, 255);
    }

    /// Upstream's `timeout` clamp is `if (val > 255) val = 255;` with no
    /// floor at all. A negative value wraps to a huge unsigned one via
    /// `unsigned int val = atoi(arg);`, so it clamps to 255 — not 0.
    #[test]
    fn options_timeout_negative_wraps_to_huge_then_clamps_to_255() {
        let opts = parse_request_options(&[("timeout".into(), "-1".into())], false, true, None, false, 65536);
        assert_eq!(opts.timeout, 255);
    }

    #[test]
    fn options_case_insensitive() {
        let opts = parse_request_options(&[("BLKSIZE".into(), "1024".into())], false, true, None, false, 65536);
        assert!(opts.opt_blocksize);
    }

    #[test]
    fn options_unknown_ignored() {
        let opts = parse_request_options(&[("frobnicate".into(), "1".into())], false, true, None, false, 65536);
        assert_eq!(opts, RequestOptions::default());
    }

    #[test]
    fn options_none_negotiated_by_default() {
        assert!(!any_option_negotiated(&RequestOptions::default()));
    }

    #[test]
    fn options_any_negotiated_true_when_present() {
        let opts = parse_request_options(&[("timeout".into(), "5".into())], false, true, None, false, 65536);
        assert!(any_option_negotiated(&opts));
    }

    // ── build_tftp_path ──────────────────────────────────────────────────────

    fn parts(prefix: Option<&str>) -> PathParts {
        PathParts {
            prefix: prefix.map(str::to_string),
            lowercase: false,
            apref_ip: false,
            apref_mac: false,
            client_addr_str: "10.0.0.5".to_string(),
            client_mac: None,
        }
    }

    #[test]
    fn path_no_prefix_roots_at_filesystem_root() {
        assert_eq!(build_tftp_path("boot.img", &parts(None)), "/boot.img");
    }

    #[test]
    fn path_with_prefix_joins() {
        assert_eq!(build_tftp_path("boot.img", &parts(Some("/tftpboot"))), "/tftpboot/boot.img");
    }

    #[test]
    fn path_prefix_with_trailing_slash_not_doubled() {
        assert_eq!(build_tftp_path("boot.img", &parts(Some("/tftpboot/"))), "/tftpboot/boot.img");
    }

    #[test]
    fn path_relative_prefix_is_appended_to_root_slash() {
        assert_eq!(build_tftp_path("boot.img", &parts(Some("tftpboot"))), "/tftpboot/boot.img");
    }

    #[test]
    fn path_backslashes_become_forward_slashes() {
        assert_eq!(build_tftp_path("boot\\pxelinux.0", &parts(Some("/tftpboot"))), "/tftpboot/boot/pxelinux.0");
    }

    #[test]
    fn path_lowercased_when_configured() {
        let mut p = parts(Some("/tftpboot"));
        p.lowercase = true;
        assert_eq!(build_tftp_path("BOOT.IMG", &p), "/tftpboot/boot.img");
    }

    #[test]
    fn path_absolute_filename_matching_prefix_used_verbatim() {
        assert_eq!(build_tftp_path("/tftpboot/x/boot.img", &parts(Some("/tftpboot"))), "/tftpboot/x/boot.img");
    }

    #[test]
    fn path_absolute_filename_not_matching_prefix_becomes_relative() {
        assert_eq!(build_tftp_path("/etc/passwd", &parts(Some("/tftpboot"))), "/tftpboot/etc/passwd");
    }

    #[test]
    fn path_traversal_survives_into_namebuff_for_permcheck_to_reject() {
        // build_tftp_path doesn't itself reject "..": open_tftp_file's
        // "/../"  substring check (matching upstream) is what rejects it —
        // verified in the open_tftp_file tests below.
        let p = build_tftp_path("../../etc/passwd", &parts(Some("/tftpboot")));
        assert!(p.contains("/../"));
    }

    #[test]
    fn path_apref_ip_falls_back_when_dir_missing() {
        let mut p = parts(Some("/tftpboot"));
        p.apref_ip = true;
        // "/tftpboot/10.0.0.5/" almost certainly doesn't exist on the test host.
        assert_eq!(build_tftp_path("boot.img", &p), "/tftpboot/boot.img");
    }

    #[test]
    fn path_apref_ip_used_when_dir_exists() {
        let dir = tempfile::tempdir().unwrap();
        let client_dir = dir.path().join("10.0.0.5");
        std::fs::create_dir(&client_dir).unwrap();
        let mut p = parts(Some(dir.path().to_str().unwrap()));
        p.apref_ip = true;
        let got = build_tftp_path("boot.img", &p);
        assert_eq!(got, client_dir.join("boot.img").to_str().unwrap());
    }

    // ── open_tftp_file ───────────────────────────────────────────────────────

    #[test]
    fn open_file_success_reads_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot.img");
        std::fs::write(&path, b"hello world").unwrap();
        let f = open_tftp_file(path.to_str().unwrap(), true, false, &[]).unwrap();
        assert_eq!(f.lock().unwrap().size, 11);
    }

    #[test]
    fn open_file_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("missing.img");
        let err = open_tftp_file(path.to_str().unwrap(), true, false, &[]).unwrap_err();
        assert!(matches!(err, TftpOpenError::NotFound));
    }

    #[test]
    fn open_file_rejects_dotdot_traversal_when_prefix_set() {
        let dir = tempfile::tempdir().unwrap();
        let namebuff = format!("{}/../secret", dir.path().to_str().unwrap());
        let err = open_tftp_file(&namebuff, true, false, &[]).unwrap_err();
        assert!(matches!(err, TftpOpenError::Perm));
    }

    #[test]
    fn open_file_dotdot_allowed_when_no_prefix_configured() {
        // Upstream only sets the "/../" trap when --tftp-root is given
        // (tftp.c:548: `if (prefix && strstr(namebuff, "/../"))`).
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        let path = sub.join("boot.img");
        std::fs::write(&path, b"hi").unwrap();
        let namebuff = format!("{}/../sub/boot.img", sub.to_str().unwrap());
        let f = open_tftp_file(&namebuff, false, false, &[]).unwrap();
        assert_eq!(f.lock().unwrap().size, 2);
    }

    #[test]
    fn open_file_dedups_shared_fd_by_dev_inode_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shared.img");
        std::fs::write(&path, b"shared contents").unwrap();
        let first = open_tftp_file(path.to_str().unwrap(), true, false, &[]).unwrap();
        let second = open_tftp_file(path.to_str().unwrap(), true, false, &[first.clone()]).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }

    #[cfg(unix)]
    #[test]
    fn open_file_permission_denied_when_not_world_readable_as_root_placeholder() {
        // Can't easily become root in a test; instead verify the plain
        // non-secure, non-root path (this process's own uid) succeeds even
        // when the file is mode 0600, since only root-mode and
        // --tftp-secure enforce anything beyond "openable".
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private.img");
        std::fs::write(&path, b"x").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let f = open_tftp_file(path.to_str().unwrap(), true, false, &[]).unwrap();
        assert_eq!(f.lock().unwrap().size, 1);
    }

    // ── get_block ────────────────────────────────────────────────────────────

    async fn transfer_over(bytes: &[u8], blocksize: usize) -> TftpTransfer {
        let mut named = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        named.write_all(bytes).unwrap();
        let meta = named.as_file().metadata().unwrap();
        #[cfg(unix)]
        let (dev, inode) = { use std::os::unix::fs::MetadataExt; (meta.dev(), meta.ino()) };
        #[cfg(not(unix))]
        let (dev, inode) = (0, 0);
        // The already-open `reopen()`'d handle stays valid even after the
        // `NamedTempFile` guard drops and unlinks the path (standard Unix
        // "delete while held open" semantics), so it need not outlive this fn.
        let file = Arc::new(Mutex::new(TftpFile {
            file: named.reopen().unwrap(),
            size: meta.len(),
            dev,
            inode,
            filename: named.path().to_str().unwrap().to_string(),
            posn: 0,
        }));
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut t = TftpTransfer::new(
            "127.0.0.1:12345".parse().unwrap(),
            "127.0.0.1".parse().unwrap(),
            0,
            Arc::new(sock),
            false,
            file,
        );
        t.blocksize = blocksize;
        t
    }

    #[tokio::test]
    async fn ack_advance_pushes_retransmit_into_the_future_no_duplicate_resend() {
        // Regression test: an ACK-driven send used to leave `transfer.retransmit`
        // at the ACK-arrival instant (set by `handle_tftp_packet`), so the very
        // next sweep tick would see it as overdue and resend the same window a
        // second time. `process_transfer_packet` must advance
        // `retransmit`/`backoff` the same way `sweep_transfers`' own retransmit
        // branch does, immediately after the ACK-driven send.
        let contents = vec![0x42u8; 1200]; // 3 blocks at blocksize 512
        let mut t = transfer_over(&contents, 512).await;
        t.timeout = 2;
        t.windowsize = 1;
        // Simulate block 1 already sent, awaiting its ACK.
        t.block = 1;
        t.lastack = 0;

        let ack = build_ack(1);
        let config = TftpConfig::default();
        let before = Instant::now();
        let finished = process_transfer_packet(&mut t, &ack, &config).await;

        assert!(!finished, "3-block transfer must not finish after ACKing block 1 of 3");
        assert_eq!(t.backoff, 1);
        assert!(
            t.retransmit > before,
            "retransmit deadline must be pushed into the future after an ACK-driven \
             send, not left at (or before) the ACK-arrival instant, or the next sweep \
             tick will resend the same window a second time"
        );

        // Directly assert the no-double-send invariant: an immediate sweep,
        // with no simulated time passing, must not treat the transfer as
        // overdue for retransmission.
        let mut transfers = HashMap::from([(0u64, t)]);
        sweep_transfers(&mut transfers, &config).await;
        assert_eq!(transfers.len(), 1, "transfer must still be active");
        assert_eq!(transfers[&0].backoff, 1, "sweep must not have re-sent (which would bump backoff again)");
    }

    #[tokio::test]
    async fn sweep_transfers_retransmit_deadline_is_additive_from_previous_deadline_not_now() {
        // Regression test: upstream computes the next retransmit deadline as
        // `transfer->retransmit += transfer->timeout + (1<<(backoff/2))`
        // (tftp.c:689) — additive from the *missed* deadline, not from `now`.
        // Under scheduling delay (this sweep tick firing well after the
        // deadline it's servicing), computing from `now` instead would push
        // every later retry later than upstream's cadence.
        let contents = vec![0x42u8; 1200]; // 3 blocks at blocksize 512 — a
                                            // single retransmit window can't
                                            // finish the transfer.
        let mut t = transfer_over(&contents, 512).await;
        t.timeout = 2;
        t.windowsize = 1;
        t.block = 1;
        t.lastack = 0;
        t.backoff = 0;

        // Simulate a sweep tick that fires well after the deadline it's
        // servicing (a busy event loop, a coarse tick interval, ...).
        let missed_deadline = Instant::now() - Duration::from_secs(5);
        t.retransmit = missed_deadline;

        let config = TftpConfig::default();
        let mut transfers = HashMap::from([(0u64, t)]);
        sweep_transfers(&mut transfers, &config).await;

        assert_eq!(transfers.len(), 1, "3-block transfer must not finish after one retransmit window");
        // backoff was 0, so shift = (0/2).min(20) = 0, and 1<<0 = 1.
        let expected = missed_deadline + Duration::from_secs(2) + Duration::from_secs(1);
        assert_eq!(
            transfers[&0].retransmit, expected,
            "next deadline must be computed from the missed deadline, not from `now`"
        );
    }

    #[tokio::test]
    async fn get_block_zero_sends_oack_with_negotiated_options() {
        let mut t = transfer_over(b"hello", 512).await;
        t.block = 0;
        t.opt_blocksize = true;
        t.opt_transize = true;
        match get_block(&mut t).unwrap() {
            GetBlockResult::Oack(pkt) => {
                assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), TftpOpcode::Oack as u16);
                let body = String::from_utf8_lossy(&pkt[2..]);
                assert!(body.contains("blksize"));
                assert!(body.contains("tsize"));
            }
            other => panic!("expected Oack, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_block_reads_real_file_contents() {
        let mut t = transfer_over(b"hello world!!!", 512).await;
        match get_block(&mut t).unwrap() {
            GetBlockResult::Data(pkt) => {
                let (block, data) = parse_data(&pkt).unwrap();
                assert_eq!(block, 1);
                assert_eq!(data, b"hello world!!!");
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_block_past_eof_is_done() {
        let mut t = transfer_over(b"hello", 512).await;
        t.block = 2; // offset = 512, past a 5-byte file
        assert!(matches!(get_block(&mut t).unwrap(), GetBlockResult::Done));
    }

    #[tokio::test]
    async fn get_block_last_block_is_short() {
        let mut t = transfer_over(&vec![0xAAu8; 600], 512).await;
        t.block = 2;
        match get_block(&mut t).unwrap() {
            GetBlockResult::Data(pkt) => {
                let (block, data) = parse_data(&pkt).unwrap();
                assert_eq!(block, 2);
                assert_eq!(data.len(), 88);
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn get_block_prefetch_reused_for_same_offset() {
        let mut t = transfer_over(b"hello world!!!", 512).await;
        let first = get_block(&mut t).unwrap();
        // block unchanged (caller normally increments after sending) — the
        // second call at the same offset should come from the prefetch
        // cache and produce identical bytes.
        let second = get_block(&mut t).unwrap();
        let (GetBlockResult::Data(p1), GetBlockResult::Data(p2)) = (first, second) else { panic!() };
        assert_eq!(p1, p2);
    }

    #[tokio::test]
    async fn get_block_netascii_expands_lf_to_crlf() {
        let mut t = transfer_over(b"line1\nline2\n", 512).await;
        t.netascii = true;
        match get_block(&mut t).unwrap() {
            GetBlockResult::Data(pkt) => {
                let (_, data) = parse_data(&pkt).unwrap();
                assert!(data.windows(2).any(|w| w == b"\r\n"));
                assert!(!data.windows(2).any(|w| w == b"\n\n"));
            }
            other => panic!("expected Data, got {other:?}"),
        }
    }

    // ── netascii_expand ──────────────────────────────────────────────────────

    #[test]
    fn netascii_expand_single_lf() {
        let (out, expansion, carrylf) = netascii_expand(b"a\nb", 10, false);
        assert_eq!(out, b"a\r\nb");
        assert_eq!(expansion, 1);
        assert!(!carrylf);
    }

    #[test]
    fn netascii_expand_multiple_lf() {
        let (out, expansion, _) = netascii_expand(b"line1\nline2\n", 100, false);
        assert_eq!(out, b"line1\r\nline2\r\n");
        assert_eq!(expansion, 2);
    }

    #[test]
    fn netascii_expand_no_lf_unchanged() {
        let (out, expansion, carrylf) = netascii_expand(b"plain", 100, false);
        assert_eq!(out, b"plain");
        assert_eq!(expansion, 0);
        assert!(!carrylf);
    }

    #[test]
    fn netascii_expand_lf_at_full_blocksize_defers_via_carrylf() {
        // A block that's already exactly `blocksize` bytes with the LF as its
        // very last byte can't grow to fit a full "\r\n": the trailing byte
        // becomes '\r' (matching upstream's unconditional `mess->data[i] =
        // '\r'`) and the accompanying '\n' is deferred to the next block —
        // the caller's offset math (`blocksize - expansion`) re-reads it from
        // the file, and `lastcarrylf` stops it being expanded a second time.
        let raw = b"aaaa\n"; // 5 bytes, blocksize == 5 (already "full")
        let (out, expansion, carrylf) = netascii_expand(raw, 5, false);
        assert_eq!(out, b"aaaa\r");
        assert_eq!(expansion, 1);
        assert!(carrylf);
    }

    #[test]
    fn netascii_expand_lastcarrylf_suppresses_leading_lf() {
        // If the previous block ended with a deferred LF, this block's
        // leading '\n' (the second half of that CRLF) is not re-expanded.
        let (out, expansion, _) = netascii_expand(b"\nrest", 100, true);
        assert_eq!(out, b"\nrest");
        assert_eq!(expansion, 0);
    }

    // ── handle_tftp_packet ───────────────────────────────────────────────────

    async fn dummy_transfer() -> TftpTransfer {
        transfer_over(b"x", 512).await
    }

    #[tokio::test]
    async fn handle_ack_advances_lastack() {
        let mut t = dummy_transfer().await;
        t.block = 1;
        t.lastack = 0;
        let ack = build_ack(1);
        let result = handle_tftp_packet(&mut t, &ack, Instant::now());
        assert_eq!(result, TftpHandleResult::AckAdvance { lastack: 2 });
        assert_eq!(t.lastack, 2);
        assert_eq!(t.backoff, 0);
    }

    #[tokio::test]
    async fn handle_ack_ignored_below_lastack() {
        let mut t = dummy_transfer().await;
        t.block = 5;
        t.lastack = 3;
        let ack = build_ack(2);
        assert_eq!(handle_tftp_packet(&mut t, &ack, Instant::now()), TftpHandleResult::AckIgnored);
    }

    #[tokio::test]
    async fn handle_ack_ignored_above_block() {
        let mut t = dummy_transfer().await;
        t.block = 2;
        t.lastack = 0;
        let ack = build_ack(5);
        assert_eq!(handle_tftp_packet(&mut t, &ack, Instant::now()), TftpHandleResult::AckIgnored);
    }

    #[tokio::test]
    async fn handle_ack_wraparound_forward() {
        let mut t = dummy_transfer().await;
        // Simulate having sent up through block 0x10005 (block_hi=1, wire block=5).
        t.block = 0x10005;
        t.lastack = 0x10000;
        t.ackprev = 0xfffe; // previous ack was in the top quarter
        t.block_hi = 0;
        let ack = build_ack(2); // wraps into the bottom quarter
        let result = handle_tftp_packet(&mut t, &ack, Instant::now());
        assert_eq!(result, TftpHandleResult::AckAdvance { lastack: 0x10003 });
        assert_eq!(t.block_hi, 1);
    }

    #[tokio::test]
    async fn handle_error_aborts_transfer() {
        let mut t = dummy_transfer().await;
        let mut pkt = vec![0, 5, 0, 1];
        pkt.extend_from_slice(b"File not found\0");
        let result = handle_tftp_packet(&mut t, &pkt, Instant::now());
        match result {
            TftpHandleResult::Error { code, message } => {
                assert_eq!(code, 1);
                assert_eq!(message, "File not found");
            }
            other => panic!("expected Error, got {other:?}"),
        }
        assert!(t.start.is_none());
    }

    #[tokio::test]
    async fn handle_too_short_is_invalid() {
        let mut t = dummy_transfer().await;
        assert_eq!(handle_tftp_packet(&mut t, &[0, 4], Instant::now()), TftpHandleResult::InvalidPacket);
    }

    #[tokio::test]
    async fn handle_unknown_opcode_is_invalid() {
        let mut t = dummy_transfer().await;
        let pkt = [0, 99, 0, 0];
        assert_eq!(handle_tftp_packet(&mut t, &pkt, Instant::now()), TftpHandleResult::InvalidPacket);
    }

    #[tokio::test]
    async fn handle_ack_netascii_advances_offset_by_blocksize_minus_expansion() {
        let mut t = dummy_transfer().await;
        t.netascii = true;
        t.block = 1;
        t.lastack = 0;
        t.blocksize = 512;
        t.expansion = 3;
        t.offset = 0;
        let ack = build_ack(1);
        handle_tftp_packet(&mut t, &ack, Instant::now());
        assert_eq!(t.offset, 512 - 3);
    }

    // ── end-to-end over real sockets + a real file ──────────────────────────

    #[cfg(unix)]
    #[tokio::test]
    async fn end_to_end_download_over_real_sockets() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot.img");
        let contents = vec![0x42u8; 1200]; // spans 3 blocks at blksize=512
        std::fs::write(&path, &contents).unwrap();

        let listener_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener_sock.local_addr().unwrap();
        let listener = TftpListenerHandle {
            sock: Arc::new(listener_sock),
            addr: listener_addr,
            iface: Some("lo".to_string()),
            mtu: None,
        };

        let config = TftpConfig {
            prefix: Some(dir.path().to_str().unwrap().to_string()),
            start_port: 0,
            end_port: 0,
            ..Default::default()
        };

        let server = tokio::spawn(run_tftp_loop(vec![listener], config));

        // Deliberately *not* `connect()`-ed: in non-single-port mode (the
        // default) the server replies from a fresh per-transfer ephemeral
        // socket, not the listener's own address/port — exactly the RFC 1350
        // §4 behavior a real client relies on, and a connected socket would
        // filter those replies out.
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let rrq = make_rrq("boot.img", "octet", &[("blksize", "512")]);
        client.send_to(&rrq, listener_addr).await.unwrap();

        let mut received = Vec::new();
        let mut buf = vec![0u8; 2048];
        let mut server_addr;
        loop {
            let (n, from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
                .await
                .expect("timed out waiting for a TFTP reply")
                .unwrap();
            server_addr = from;
            let pkt = &buf[..n];
            let opcode = u16::from_be_bytes([pkt[0], pkt[1]]);
            if opcode == TftpOpcode::Oack as u16 {
                client.send_to(&build_ack(0), server_addr).await.unwrap();
                continue;
            }
            assert_eq!(opcode, TftpOpcode::Data as u16);
            let (block, data) = parse_data(pkt).unwrap();
            received.extend_from_slice(data);
            client.send_to(&build_ack(block), server_addr).await.unwrap();
            if data.len() < 512 {
                break;
            }
        }

        assert_eq!(received, contents);
        server.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn end_to_end_path_traversal_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        // A secret file that lives *outside* the tftp-root directory.
        let secret_dir = tempfile::tempdir().unwrap();
        std::fs::write(secret_dir.path().join("secret"), b"do not serve").unwrap();

        let listener_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let listener_addr = listener_sock.local_addr().unwrap();
        let listener = TftpListenerHandle {
            sock: Arc::new(listener_sock),
            addr: listener_addr,
            iface: Some("lo".to_string()),
            mtu: None,
        };
        let config = TftpConfig {
            prefix: Some(dir.path().to_str().unwrap().to_string()),
            ..Default::default()
        };
        let server = tokio::spawn(run_tftp_loop(vec![listener], config));

        // Deliberately *not* `connect()`-ed: like the other end-to-end test
        // above, the reply (here an error) now comes from a fresh
        // per-transfer ephemeral socket, not the listener's own port.
        let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let traversal = format!("../{}/secret", secret_dir.path().file_name().unwrap().to_str().unwrap());
        let rrq = make_rrq(&traversal, "octet", &[]);
        client.send_to(&rrq, listener_addr).await.unwrap();

        let mut buf = vec![0u8; 2048];
        let (n, _from) = tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut buf))
            .await
            .expect("timed out waiting for a TFTP reply")
            .unwrap();
        let pkt = &buf[..n];
        assert_eq!(u16::from_be_bytes([pkt[0], pkt[1]]), TftpOpcode::Error as u16);

        server.abort();
    }
}

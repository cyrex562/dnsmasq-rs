//! Packet capture writer in pcap format.
//!
//! Ported from `dump.c`.  Provides:
//!
//! - [`PcapWriter`] — streaming pcap file writer (global header + packet records).
//! - Packet framing helpers ([`frame_udp_ipv4`], [`frame_udp_ipv6`],
//!   [`frame_icmp_ipv4`], [`frame_icmpv6`]) — build complete IP/UDP/ICMP
//!   frames with correct checksums, mirroring `do_dump_packet()` in C.
//! - [`PcapWriter::write_udp_packet`] / [`PcapWriter::write_icmp_packet`]
//!   — convenience wrappers that frame and record in one call.
#![cfg(feature = "dump")]

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// pcap magic number (little-endian native, microsecond timestamps).
pub const PCAP_MAGIC: u32 = 0xa1b2c3d4;
/// pcap link type for raw IP (LINKTYPE_RAW = 101).
pub const LINKTYPE_RAW: u32 = 101;

// pcap file format constants
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_GLOBAL_HEADER_LEN: usize = 24;

// IP protocol numbers
const IPPROTO_ICMP:   u8 = 1;
const IPPROTO_TCP:    u8 = 6;
const IPPROTO_UDP:    u8 = 17;
const IPPROTO_ICMPV6: u8 = 58;

// IP version constants
const IPVERSION: u8 = 4;
const IPDEFTTL:  u8 = 64;

// ──────────────────────────────────────────────────────────────────────────────
// Checksum helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Internet checksum (RFC 1071): one's-complement sum of 16-bit words.
fn inet_cksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        // odd byte — pad with zero
        sum += u32::from(data[i]) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let result = !(sum as u16);
    // Per RFC 1071 §4.1: if computed sum is 0xffff, return 0xffff
    if result == 0 { 0xffff } else { result }
}

/// UDP/ICMP checksum over an IPv4 pseudo-header + segment bytes.
fn udp_cksum_ipv4(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0); // padding
    pseudo.push(proto);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    if segment.len() & 1 != 0 {
        pseudo.push(0); // pad to even length
    }
    inet_cksum(&pseudo)
}

/// UDP/ICMPv6 checksum over an IPv6 pseudo-header + segment bytes.
fn udp_cksum_ipv6(src: Ipv6Addr, dst: Ipv6Addr, next_hdr: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes()); // upper-layer packet length
    pseudo.extend_from_slice(&[0, 0, 0, next_hdr]);                  // padding + next header
    pseudo.extend_from_slice(segment);
    if segment.len() & 1 != 0 {
        pseudo.push(0);
    }
    inet_cksum(&pseudo)
}

// ──────────────────────────────────────────────────────────────────────────────
// Packet framing helpers (mirrors `do_dump_packet()` from dump.c)
// ──────────────────────────────────────────────────────────────────────────────

/// Build a complete IPv4 + UDP frame.
///
/// Returns the framed packet bytes suitable for writing into a pcap record.
/// `src_port` / `dst_port` are host byte order.
pub fn frame_udp_ipv4(
    src: Ipv4Addr, src_port: u16,
    dst: Ipv4Addr, dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    // ── UDP header ──────────────────────────────────────────────────────────
    let udp_len = (8 + payload.len()) as u16;
    let mut udp_hdr = [0u8; 8];
    udp_hdr[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp_hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp_hdr[4..6].copy_from_slice(&udp_len.to_be_bytes());
    // checksum placeholder = 0; compute over pseudo-header + udp_hdr + payload
    let mut segment = udp_hdr.to_vec();
    segment.extend_from_slice(payload);
    let cksum = udp_cksum_ipv4(src, dst, IPPROTO_UDP, &segment);
    udp_hdr[6..8].copy_from_slice(&cksum.to_be_bytes());

    // ── IPv4 header ─────────────────────────────────────────────────────────
    let ip_total_len = (20 + 8 + payload.len()) as u16;
    let mut ip = [0u8; 20];
    ip[0] = (IPVERSION << 4) | 5;          // version=4, IHL=5 (20 bytes)
    ip[1] = 0;                              // DSCP/ECN
    ip[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
    ip[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF bit, no fragment offset
    ip[8] = IPDEFTTL;
    ip[9] = IPPROTO_UDP;
    ip[10..12].copy_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let ip_cksum = inet_cksum(&ip);
    ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    let mut out = ip.to_vec();
    out.extend_from_slice(&udp_hdr);
    out.extend_from_slice(payload);
    out
}

/// Build a complete IPv6 + UDP frame.
pub fn frame_udp_ipv6(
    src: Ipv6Addr, src_port: u16,
    dst: Ipv6Addr, dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = (8 + payload.len()) as u16;
    let mut udp_hdr = [0u8; 8];
    udp_hdr[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp_hdr[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp_hdr[4..6].copy_from_slice(&udp_len.to_be_bytes());
    let mut segment = udp_hdr.to_vec();
    segment.extend_from_slice(payload);
    let cksum = udp_cksum_ipv6(src, dst, IPPROTO_UDP, &segment);
    udp_hdr[6..8].copy_from_slice(&cksum.to_be_bytes());

    let payload_len = (8 + payload.len()) as u16; // length after IPv6 fixed header
    let mut ip6 = [0u8; 40];
    ip6[0] = 0x60;  // version=6, traffic class high nibble=0
    // bytes 1-3: traffic class low nibble + flow label = 0
    ip6[4..6].copy_from_slice(&payload_len.to_be_bytes());
    ip6[6] = IPPROTO_UDP;
    ip6[7] = IPDEFTTL; // hop limit
    ip6[8..24].copy_from_slice(&src.octets());
    ip6[24..40].copy_from_slice(&dst.octets());

    let mut out = ip6.to_vec();
    out.extend_from_slice(&udp_hdr);
    out.extend_from_slice(payload);
    out
}

/// Build a complete IPv4 + ICMP frame.
///
/// `payload` is the ICMP message bytes (starting with type/code/checksum).
/// The ICMP checksum inside `payload[2..4]` is overwritten.
pub fn frame_icmp_ipv4(src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
    // Compute ICMP checksum over the whole ICMP message
    let mut icmp = payload.to_vec();
    if icmp.len() >= 4 {
        icmp[2] = 0; icmp[3] = 0; // zero checksum field before computing
        let ck = udp_cksum_ipv4(src, dst, IPPROTO_ICMP, &icmp);
        icmp[2..4].copy_from_slice(&ck.to_be_bytes());
    }

    let ip_total_len = (20 + icmp.len()) as u16;
    let mut ip = [0u8; 20];
    ip[0] = (IPVERSION << 4) | 5;
    ip[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
    ip[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    ip[8] = IPDEFTTL;
    ip[9] = IPPROTO_ICMP;
    ip[12..16].copy_from_slice(&src.octets());
    ip[16..20].copy_from_slice(&dst.octets());
    let ip_cksum = inet_cksum(&ip);
    ip[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

    let mut out = ip.to_vec();
    out.extend_from_slice(&icmp);
    out
}

/// Build a complete IPv6 + ICMPv6 frame.
///
/// The ICMPv6 checksum at `payload[2..4]` is overwritten.
pub fn frame_icmpv6(src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
    let mut icmp = payload.to_vec();
    if icmp.len() >= 4 {
        icmp[2] = 0; icmp[3] = 0;
        let ck = udp_cksum_ipv6(src, dst, IPPROTO_ICMPV6, &icmp);
        icmp[2..4].copy_from_slice(&ck.to_be_bytes());
    }

    let payload_len = icmp.len() as u16;
    let mut ip6 = [0u8; 40];
    ip6[0] = 0x60;
    ip6[4..6].copy_from_slice(&payload_len.to_be_bytes());
    ip6[6] = IPPROTO_ICMPV6;
    ip6[7] = IPDEFTTL;
    ip6[8..24].copy_from_slice(&src.octets());
    ip6[24..40].copy_from_slice(&dst.octets());

    let mut out = ip6.to_vec();
    out.extend_from_slice(&icmp);
    out
}

// ──────────────────────────────────────────────────────────────────────────────
// PcapWriter
// ──────────────────────────────────────────────────────────────────────────────

/// Build the 24-byte pcap global header (all fields little-endian).
///
/// Shared by [`PcapWriter::new`] (in-memory, tests) and [`DumpHandle::init`]
/// (real file, mirrors `dump_init()` at `dump.c:54-60`).
fn global_header_bytes(snaplen: u32, link_type: u32) -> [u8; PCAP_GLOBAL_HEADER_LEN] {
    let mut buf = [0u8; PCAP_GLOBAL_HEADER_LEN];
    buf[0..4].copy_from_slice(&PCAP_MAGIC.to_le_bytes());
    buf[4..6].copy_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());
    buf[6..8].copy_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());
    buf[8..12].copy_from_slice(&0i32.to_le_bytes()); // thiszone (UTC)
    buf[12..16].copy_from_slice(&0u32.to_le_bytes()); // sigfigs
    buf[16..20].copy_from_slice(&snaplen.to_le_bytes());
    buf[20..24].copy_from_slice(&link_type.to_le_bytes());
    buf
}

/// Build a 16-byte pcap record header for a packet captured "now".
fn record_header_bytes(len: u32) -> [u8; 16] {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&(now.as_secs() as u32).to_le_bytes());
    buf[4..8].copy_from_slice(&now.subsec_micros().to_le_bytes());
    buf[8..12].copy_from_slice(&len.to_le_bytes());  // incl_len
    buf[12..16].copy_from_slice(&len.to_le_bytes()); // orig_len
    buf
}

/// Streaming pcap writer that accumulates records in memory.
pub struct PcapWriter {
    buf: Vec<u8>,
}

impl PcapWriter {
    /// Create a new writer and emit the pcap global header.
    pub fn new(snaplen: u32, link_type: u32) -> Self {
        Self { buf: global_header_bytes(snaplen, link_type).to_vec() }
    }

    /// Append a raw packet record with the given timestamp.
    ///
    /// `data` is the full captured packet as-is (e.g. already framed).
    pub fn write_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) {
        let orig_len = data.len() as u32;
        let incl_len = orig_len; // we capture the full packet
        self.buf.extend_from_slice(&ts_sec.to_le_bytes());
        self.buf.extend_from_slice(&ts_usec.to_le_bytes());
        self.buf.extend_from_slice(&incl_len.to_le_bytes());
        self.buf.extend_from_slice(&orig_len.to_le_bytes());
        self.buf.extend_from_slice(data);
    }

    /// Frame a UDP datagram as IPv4 or IPv6 and write it as a pcap record.
    ///
    /// Mirrors `dump_packet_udp()` + `do_dump_packet()` from `dump.c`.
    pub fn write_udp_packet(
        &mut self,
        ts_sec:   u32,
        ts_usec:  u32,
        src:      IpAddr,
        src_port: u16,
        dst:      IpAddr,
        dst_port: u16,
        payload:  &[u8],
    ) {
        let framed = match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => frame_udp_ipv4(s, src_port, d, dst_port, payload),
            (IpAddr::V6(s), IpAddr::V6(d)) => frame_udp_ipv6(s, src_port, d, dst_port, payload),
            // Mixed v4/v6 — fall back to raw payload (shouldn't happen in practice)
            _ => payload.to_vec(),
        };
        self.write_packet(ts_sec, ts_usec, &framed);
    }

    /// Frame an ICMP/ICMPv6 message as IPv4 or IPv6 and write it as a pcap record.
    ///
    /// Mirrors `dump_packet_icmp()` + `do_dump_packet()` from `dump.c`.
    pub fn write_icmp_packet(
        &mut self,
        ts_sec:  u32,
        ts_usec: u32,
        src:     IpAddr,
        dst:     IpAddr,
        payload: &[u8],
    ) {
        let framed = match (src, dst) {
            (IpAddr::V4(s), IpAddr::V4(d)) => frame_icmp_ipv4(s, d, payload),
            (IpAddr::V6(s), IpAddr::V6(d)) => frame_icmpv6(s, d, payload),
            _ => payload.to_vec(),
        };
        self.write_packet(ts_sec, ts_usec, &framed);
    }

    /// Return all accumulated bytes (global header + all packet records).
    pub fn bytes(&self) -> &[u8] {
        &self.buf
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// DumpHandle — real-file pcap writer, mirrors dump_init()/dump_packet_*()
// ──────────────────────────────────────────────────────────────────────────────

/// Read exactly `buf.len()` bytes, or report a clean/torn end-of-file.
///
/// Returns `Ok(true)` once `buf` is fully filled, `Ok(false)` if `read()`
/// returned `0` before `buf` was full (whether that happens at the very start
/// or partway through) — matching upstream's `read_write()` helper, which
/// upstream's `dump_init()` scan loop treats as "no more records" rather than
/// an error (`dump.c:86-90`).
fn try_read_exact(file: &mut File, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match file.read(&mut buf[filled..])? {
            0 => return Ok(false),
            n => filled += n,
        }
    }
    Ok(true)
}

/// Address fallback used when `src` or `dst` is not directly known — the Rust
/// equivalent of `dump_packet_udp()`'s `fd` parameter (`dump.c:94-121`).
/// `Local` corresponds to upstream's `fd >= 0` branch, which calls
/// `getsockname(fd)` to recover the local address of the socket a packet
/// arrived on or is about to be sent on; callers here already hold that
/// address (e.g. `UdpSocket::local_addr()`), so no syscall is needed.
///
/// Upstream's `fd < 0` branch (a bare port number, used by callers with no
/// socket at hand, e.g. TFTP) is not implemented — those call sites are
/// outside this port's current scope, tracked in `tasks.md`.
#[derive(Debug, Clone, Copy)]
pub enum DumpFallback {
    /// No fallback — a missing `src`/`dst` leaves the packet undumped.
    None,
    /// Fill a missing `src` and/or `dst` with this address.
    Local(SocketAddr),
}

/// An open pcap dump file plus the mask that gates which packet classes are
/// written to it — the Rust equivalent of `daemon->dumpfd`/`daemon->dump_mask`
/// plus the module-level `packet_count` static in `dump.c`.
///
/// Cheaply `Clone`-able: clones share the same underlying file and counter,
/// mirroring the single process-wide file descriptor upstream writes through.
#[derive(Debug, Clone)]
pub struct DumpHandle {
    file: Arc<Mutex<File>>,
    mask: i32,
    packet_count: Arc<AtomicU32>,
}

impl DumpHandle {
    /// Open (or create) `path` as a pcap dump file, mirroring `dump_init()`
    /// (`dump.c:46-92`):
    ///
    /// - path doesn't exist → create it and write the global header.
    /// - path is a FIFO → open for append and write the header (the
    ///   wireshark-over-a-pipe case; no read-back).
    /// - path is a regular file → open for append, read back and validate the
    ///   existing header's magic number, then scan forward through the
    ///   existing records (seeking by each `incl_len`) to recover
    ///   `packet_count` so numbering continues rather than restarting.
    pub fn init(path: &str, edns_pktsz: u16, mask: i32) -> io::Result<Self> {
        use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};

        let snaplen = edns_pktsz as u32 + 200; // slop for IP/UDP headers, dump.c:59
        let header = global_header_bytes(snaplen, LINKTYPE_RAW);

        let (file, packet_count) = match std::fs::metadata(path) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let mut f = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)?;
                f.write_all(&header)?;
                (f, 0)
            }
            Err(e) => return Err(e),
            Ok(meta) if meta.file_type().is_fifo() => {
                let mut f = OpenOptions::new().append(true).read(true).open(path)?;
                f.write_all(&header)?;
                (f, 0)
            }
            Ok(_) => {
                let mut f = OpenOptions::new().append(true).read(true).open(path)?;
                let mut existing = [0u8; PCAP_GLOBAL_HEADER_LEN];
                if !try_read_exact(&mut f, &mut existing)? {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "dump file too short for a pcap header",
                    ));
                }
                if u32::from_le_bytes(existing[0..4].try_into().unwrap()) != PCAP_MAGIC {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "bad pcap magic number in existing dump file",
                    ));
                }
                let mut count = 0u32;
                loop {
                    let mut rec = [0u8; 16];
                    if !try_read_exact(&mut f, &mut rec)? {
                        break;
                    }
                    let incl_len = u32::from_le_bytes(rec[8..12].try_into().unwrap());
                    f.seek(SeekFrom::Current(incl_len as i64))?;
                    count += 1;
                }
                (f, count)
            }
        };

        Ok(Self {
            file: Arc::new(Mutex::new(file)),
            mask,
            packet_count: Arc::new(AtomicU32::new(packet_count)),
        })
    }

    /// Number of packet records written (or recovered on reopen) so far.
    pub fn packet_count(&self) -> u32 {
        self.packet_count.load(Ordering::Relaxed)
    }

    /// Record a UDP datagram, mirroring `dump_packet_udp()` (`dump.c:94-122`).
    ///
    /// A no-op unless `mask` intersects the dump mask this handle was opened
    /// with. `fallback` fills in whichever of `src`/`dst` is `None`; if either
    /// is still unknown afterwards, nothing is written (see [`DumpFallback`]).
    pub fn dump_packet_udp(
        &self,
        mask: u32,
        payload: &[u8],
        mut src: Option<SocketAddr>,
        mut dst: Option<SocketAddr>,
        fallback: DumpFallback,
    ) {
        if self.mask & (mask as i32) == 0 {
            return;
        }
        if let DumpFallback::Local(addr) = fallback {
            if src.is_none() {
                src = Some(addr);
            }
            if dst.is_none() {
                dst = Some(addr);
            }
        }
        let (src, dst) = match (src, dst) {
            (Some(s), Some(d)) => (s, d),
            _ => return,
        };
        let framed = match (src, dst) {
            (SocketAddr::V4(s), SocketAddr::V4(d)) => {
                frame_udp_ipv4(*s.ip(), s.port(), *d.ip(), d.port(), payload)
            }
            (SocketAddr::V6(s), SocketAddr::V6(d)) => {
                frame_udp_ipv6(*s.ip(), s.port(), *d.ip(), d.port(), payload)
            }
            // Mixed v4/v6 can't happen for a real UDP flow.
            _ => return,
        };
        self.write_record(&framed);
    }

    /// Record an ICMP/ICMPv6 message, mirroring `dump_packet_icmp()`
    /// (`dump.c:124-129`).
    pub fn dump_packet_icmp(
        &self,
        mask: u32,
        payload: &[u8],
        src: Option<SocketAddr>,
        dst: Option<SocketAddr>,
    ) {
        if self.mask & (mask as i32) == 0 {
            return;
        }
        let (src, dst) = match (src, dst) {
            (Some(s), Some(d)) => (s, d),
            _ => return,
        };
        let framed = match (src, dst) {
            (SocketAddr::V4(s), SocketAddr::V4(d)) => frame_icmp_ipv4(*s.ip(), *d.ip(), payload),
            (SocketAddr::V6(s), SocketAddr::V6(d)) => frame_icmpv6(*s.ip(), *d.ip(), payload),
            _ => return,
        };
        self.write_record(&framed);
    }

    fn write_record(&self, framed: &[u8]) {
        let header = record_header_bytes(framed.len() as u32);
        let mut file = match self.file.lock() {
            Ok(f) => f,
            Err(poisoned) => poisoned.into_inner(),
        };
        let result = file.write_all(&header).and_then(|_| file.write_all(framed));
        match result {
            Ok(()) => {
                self.packet_count.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => tracing::warn!("failed to write packet dump: {e}"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn read_u32_le(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }
    fn read_u16_le(buf: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
    }
    fn read_u16_be(buf: &[u8], off: usize) -> u16 {
        u16::from_be_bytes(buf[off..off + 2].try_into().unwrap())
    }

    // ── pcap file format ────────────────────────────────────────────────────

    #[test]
    fn test_global_header() {
        let w = PcapWriter::new(65535, LINKTYPE_RAW);
        let b = w.bytes();
        assert_eq!(b.len(), 24, "global header must be 24 bytes");
        assert_eq!(read_u32_le(b, 0), PCAP_MAGIC);
        assert_eq!(read_u16_le(b, 4), 2);   // version major
        assert_eq!(read_u16_le(b, 6), 4);   // version minor
        assert_eq!(read_u32_le(b, 8), 0);   // thiszone
        assert_eq!(read_u32_le(b, 12), 0);  // sigfigs
        assert_eq!(read_u32_le(b, 16), 65535);
        assert_eq!(read_u32_le(b, 20), LINKTYPE_RAW);
    }

    #[test]
    fn test_write_packet_header() {
        let mut w = PcapWriter::new(65535, LINKTYPE_RAW);
        let payload = b"hello world";
        w.write_packet(1_700_000_000, 123_456, payload);
        let b = w.bytes();
        // Packet record starts at offset 24
        assert_eq!(read_u32_le(b, 24), 1_700_000_000); // ts_sec
        assert_eq!(read_u32_le(b, 28), 123_456);        // ts_usec
        assert_eq!(read_u32_le(b, 32), payload.len() as u32); // incl_len
        assert_eq!(read_u32_le(b, 36), payload.len() as u32); // orig_len
        assert_eq!(&b[40..40 + payload.len()], payload);
    }

    #[test]
    fn test_multiple_packets() {
        let mut w = PcapWriter::new(65535, LINKTYPE_RAW);
        let pkt1 = b"pkt1";
        let pkt2 = b"packet2data";
        w.write_packet(1, 0, pkt1);
        w.write_packet(2, 500, pkt2);

        let b = w.bytes();
        // First record at 24
        assert_eq!(read_u32_le(b, 24), 1);
        assert_eq!(read_u32_le(b, 32), pkt1.len() as u32);
        // Second record follows immediately
        let off2 = 24 + 16 + pkt1.len();
        assert_eq!(read_u32_le(b, off2), 2);
        assert_eq!(read_u32_le(b, off2 + 4), 500);
        assert_eq!(read_u32_le(b, off2 + 8), pkt2.len() as u32);
    }

    // ── inet_cksum ──────────────────────────────────────────────────────────

    #[test]
    fn inet_cksum_known_value() {
        // Build a 20-byte IPv4 header with checksum field zeroed, compute it,
        // then verify that recomputing over the header+checksum gives 0xffff.
        let mut hdr: [u8; 20] = [
            0x45, 0x00, 0x00, 0x3c,
            0x1c, 0x46, 0x40, 0x00,
            0x40, 0x06, 0x00, 0x00, // TTL/proto/cksum (zeroed)
            0xac, 0x10, 0x0a, 0x63, // src 172.16.10.99
            0xac, 0x10, 0x0a, 0x0c, // dst 172.16.10.12
        ];
        let ck = inet_cksum(&hdr);
        hdr[10] = (ck >> 8) as u8;
        hdr[11] = (ck & 0xff) as u8;
        // Recomputing over the complete (checksum-filled) header must give 0xffff
        assert_eq!(inet_cksum(&hdr), 0xffff);
    }

    #[test]
    fn inet_cksum_empty_is_ffff() {
        // Empty input: all zeros → complement of 0 = 0xffff
        assert_eq!(inet_cksum(&[]), 0xffff);
    }

    // ── IPv4 UDP framing ────────────────────────────────────────────────────

    #[test]
    fn frame_udp_ipv4_structure() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(192, 168, 1, 2);
        let payload = b"dnsmasq test";
        let frame = frame_udp_ipv4(src, 5300, dst, 53, payload);

        // Minimum IPv4+UDP frame: 20 (IP) + 8 (UDP) + payload
        assert_eq!(frame.len(), 20 + 8 + payload.len());

        // IP version = 4, IHL = 5
        assert_eq!(frame[0], 0x45);
        // Protocol = UDP = 17
        assert_eq!(frame[9], IPPROTO_UDP);
        // Source and destination addresses
        assert_eq!(&frame[12..16], &src.octets());
        assert_eq!(&frame[16..20], &dst.octets());
        // IP checksum must be non-zero (header should be valid)
        let ck = read_u16_be(&frame, 10);
        assert_ne!(ck, 0);

        // UDP src/dst ports
        assert_eq!(read_u16_be(&frame, 20), 5300);
        assert_eq!(read_u16_be(&frame, 22), 53);
        // UDP length = 8 + payload
        assert_eq!(read_u16_be(&frame, 24), (8 + payload.len()) as u16);
        // Payload intact
        assert_eq!(&frame[28..], payload.as_ref());
    }

    #[test]
    fn frame_udp_ipv4_ip_checksum_validates() {
        let frame = frame_udp_ipv4(
            Ipv4Addr::new(10, 0, 0, 1), 1234,
            Ipv4Addr::new(10, 0, 0, 2), 5678,
            b"test",
        );
        // Recomputing the checksum over the header with checksum field included
        // should yield 0xffff (for a correct header).
        let ck = inet_cksum(&frame[..20]);
        assert_eq!(ck, 0xffff, "IPv4 header checksum must validate");
    }

    // ── IPv6 UDP framing ────────────────────────────────────────────────────

    #[test]
    fn frame_udp_ipv6_structure() {
        let src = "2001:db8::1".parse::<Ipv6Addr>().unwrap();
        let dst = "2001:db8::2".parse::<Ipv6Addr>().unwrap();
        let payload = b"v6 payload";
        let frame = frame_udp_ipv6(src, 5300, dst, 53, payload);

        // 40 (IPv6) + 8 (UDP) + payload
        assert_eq!(frame.len(), 40 + 8 + payload.len());
        // Version nibble = 6
        assert_eq!(frame[0] >> 4, 6);
        // Next header = UDP = 17
        assert_eq!(frame[6], IPPROTO_UDP);
        assert_eq!(&frame[8..24],  &src.octets());
        assert_eq!(&frame[24..40], &dst.octets());
        assert_eq!(read_u16_be(&frame, 40), 5300);
        assert_eq!(read_u16_be(&frame, 42), 53);
        assert_eq!(&frame[48..], payload.as_ref());
    }

    // ── ICMPv6 framing ──────────────────────────────────────────────────────

    #[test]
    fn frame_icmpv6_structure() {
        let src = "fe80::1".parse::<Ipv6Addr>().unwrap();
        let dst = "ff02::1".parse::<Ipv6Addr>().unwrap();
        // Echo request: type=128, code=0, cksum=0 (we compute it), data
        let mut icmp_msg = vec![0x80u8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        icmp_msg.extend_from_slice(b"ping");
        let frame = frame_icmpv6(src, dst, &icmp_msg);

        assert_eq!(frame.len(), 40 + icmp_msg.len());
        assert_eq!(frame[6], IPPROTO_ICMPV6);
        // ICMPv6 checksum at bytes 42..44 must be non-zero
        assert_ne!(read_u16_be(&frame, 42), 0);
    }

    // ── PcapWriter::write_udp_packet ─────────────────────────────────────────

    #[test]
    fn write_udp_packet_correct_size() {
        let mut w = PcapWriter::new(65535, LINKTYPE_RAW);
        let src: IpAddr = "1.2.3.4".parse().unwrap();
        let dst: IpAddr = "5.6.7.8".parse().unwrap();
        let dns_payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00";
        w.write_udp_packet(1000, 0, src, 12345, dst, 53, dns_payload);

        let b = w.bytes();
        // pcap record starts at 24; pcap record header is 16 bytes
        let incl_len = read_u32_le(b, 24 + 8);
        // expected: 20 (IPv4) + 8 (UDP) + dns_payload.len()
        assert_eq!(incl_len as usize, 20 + 8 + dns_payload.len());
    }

    #[test]
    fn write_icmp_packet_correct_size() {
        let mut w = PcapWriter::new(65535, LINKTYPE_RAW);
        let src: IpAddr = "10.0.0.1".parse().unwrap();
        let dst: IpAddr = "10.0.0.2".parse().unwrap();
        let icmp_payload = vec![0x08u8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        w.write_icmp_packet(2000, 500, src, dst, &icmp_payload);

        let b = w.bytes();
        let incl_len = read_u32_le(b, 24 + 8);
        assert_eq!(incl_len as usize, 20 + icmp_payload.len());
    }
}

// ---------------------------------------------------------------------------
// DumpHandle tests — real-file I/O, mirroring dump_init()/dump_packet_*()
// ---------------------------------------------------------------------------

#[cfg(test)]
mod dump_handle_tests {
    use super::*;
    use crate::types::constants::{DUMP_QUERY, DUMP_REPLY};
    use std::fs;
    use std::io::Read;
    use std::net::SocketAddr;

    fn read_u32_le(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }
    fn read_u16_le(buf: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
    }

    fn read_file(path: &std::path::Path) -> Vec<u8> {
        let mut buf = Vec::new();
        fs::File::open(path).unwrap().read_to_end(&mut buf).unwrap();
        buf
    }

    #[test]
    fn dump_init_creates_new_file_with_pcap_header() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dump.pcap");

        let handle = DumpHandle::init(path.to_str().unwrap(), 1232, -1).unwrap();
        drop(handle);

        let bytes = read_file(&path);
        assert_eq!(bytes.len(), 24, "a freshly created dump file has only the global header");
        assert_eq!(read_u32_le(&bytes, 0), PCAP_MAGIC);
        assert_eq!(read_u16_le(&bytes, 4), 2);
        assert_eq!(read_u16_le(&bytes, 6), 4);
        // snaplen = edns_pktsz + 200, mirroring dump.c:59
        assert_eq!(read_u32_le(&bytes, 16), 1232 + 200);
        assert_eq!(read_u32_le(&bytes, 20), LINKTYPE_RAW);
    }

    #[test]
    fn dump_init_rejects_bad_magic_in_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dump.pcap");
        fs::write(&path, [0u8; 24]).unwrap();

        let result = DumpHandle::init(path.to_str().unwrap(), 1232, -1);
        assert!(result.is_err(), "a regular file with a bad magic number must be rejected");
    }

    #[test]
    fn dump_init_recovers_packet_count_from_existing_regular_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dump.pcap");

        let handle = DumpHandle::init(path.to_str().unwrap(), 1232, -1).unwrap();
        let src: SocketAddr = "192.168.1.1:5300".parse().unwrap();
        let dst: SocketAddr = "192.168.1.2:53".parse().unwrap();
        handle.dump_packet_udp(DUMP_QUERY, b"one", Some(src), Some(dst), DumpFallback::None);
        handle.dump_packet_udp(DUMP_QUERY, b"two", Some(src), Some(dst), DumpFallback::None);
        drop(handle);

        let reopened = DumpHandle::init(path.to_str().unwrap(), 1232, -1).unwrap();
        assert_eq!(reopened.packet_count(), 2, "dump_init must recover the count of existing records");
    }

    #[test]
    fn dump_packet_udp_respects_mask() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dump.pcap");
        // Only DUMP_REPLY is enabled.
        let handle = DumpHandle::init(path.to_str().unwrap(), 1232, DUMP_REPLY as i32).unwrap();

        let src: SocketAddr = "192.168.1.1:5300".parse().unwrap();
        let dst: SocketAddr = "192.168.1.2:53".parse().unwrap();
        handle.dump_packet_udp(DUMP_QUERY, b"masked out", Some(src), Some(dst), DumpFallback::None);
        assert_eq!(handle.packet_count(), 0, "a mask bit that isn't enabled must not be recorded");

        handle.dump_packet_udp(DUMP_REPLY, b"recorded", Some(src), Some(dst), DumpFallback::None);
        assert_eq!(handle.packet_count(), 1);
    }

    #[test]
    fn dump_packet_udp_writes_a_valid_ipv4_frame() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dump.pcap");
        let handle = DumpHandle::init(path.to_str().unwrap(), 1232, -1).unwrap();

        let src: SocketAddr = "10.0.0.1:5300".parse().unwrap();
        let dst: SocketAddr = "10.0.0.2:53".parse().unwrap();
        let payload = b"dns payload";
        handle.dump_packet_udp(DUMP_QUERY, payload, Some(src), Some(dst), DumpFallback::None);
        drop(handle);

        let bytes = read_file(&path);
        // global header (24) + pcap record header (16) + IPv4 (20) + UDP (8) + payload
        let expected_frame = frame_udp_ipv4(
            std::net::Ipv4Addr::new(10, 0, 0, 1), 5300,
            std::net::Ipv4Addr::new(10, 0, 0, 2), 53,
            payload,
        );
        assert_eq!(bytes.len(), 24 + 16 + expected_frame.len());
        let incl_len = read_u32_le(&bytes, 24 + 8);
        assert_eq!(incl_len as usize, expected_frame.len());
        assert_eq!(&bytes[24 + 16..], &expected_frame[..]);
    }

    #[test]
    fn dump_packet_icmp_writes_a_valid_frame() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dump.pcap");
        let handle = DumpHandle::init(path.to_str().unwrap(), 1232, -1).unwrap();

        let src: SocketAddr = "10.0.0.1:0".parse().unwrap();
        let dst: SocketAddr = "10.0.0.2:0".parse().unwrap();
        let icmp_payload = vec![0x08u8, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        handle.dump_packet_icmp(crate::types::constants::DUMP_BOGUS, &icmp_payload, Some(src), Some(dst));
        drop(handle);

        let bytes = read_file(&path);
        let incl_len = read_u32_le(&bytes, 24 + 8);
        assert_eq!(incl_len as usize, 20 + icmp_payload.len());
    }

    #[test]
    fn dump_packet_udp_local_fallback_fills_missing_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dump.pcap");
        let handle = DumpHandle::init(path.to_str().unwrap(), 1232, -1).unwrap();

        let local: SocketAddr = "10.0.0.9:53".parse().unwrap();
        let client: SocketAddr = "10.0.0.5:5300".parse().unwrap();
        // dst omitted — must be filled from the fallback, mirroring the
        // getsockname() fallback in dump_packet_udp() (dump.c:109-118).
        handle.dump_packet_udp(DUMP_QUERY, b"x", Some(client), None, DumpFallback::Local(local));
        drop(handle);

        let bytes = read_file(&path);
        let frame_off = 24 + 16;
        // dst address lives at IPv4 header bytes 16..20 within the frame.
        assert_eq!(&bytes[frame_off + 16..frame_off + 20], &[10, 0, 0, 9]);
    }

    #[test]
    fn dump_packet_udp_no_addresses_is_a_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dump.pcap");
        let handle = DumpHandle::init(path.to_str().unwrap(), 1232, -1).unwrap();
        handle.dump_packet_udp(DUMP_QUERY, b"x", None, None, DumpFallback::None);
        assert_eq!(handle.packet_count(), 0);
    }

    #[cfg(unix)]
    #[test]
    fn dump_init_on_fifo_writes_header_without_reading_back() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dump.fifo");
        if nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR).is_err() {
            // FIFOs aren't available in every sandboxed environment — skip
            // rather than fail spuriously.
            return;
        }
        let path_str = path.to_str().unwrap().to_string();
        let reader = std::thread::spawn(move || {
            use std::io::Read;
            let mut f = fs::File::open(&path_str).unwrap();
            let mut buf = [0u8; 24];
            f.read_exact(&mut buf).unwrap();
            buf
        });
        let handle = DumpHandle::init(path.to_str().unwrap(), 1232, -1).unwrap();
        let header = reader.join().unwrap();
        drop(handle);
        assert_eq!(read_u32_le(&header, 0), PCAP_MAGIC);
    }
}

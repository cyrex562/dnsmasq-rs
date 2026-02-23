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

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

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

/// Streaming pcap writer that accumulates records in memory.
pub struct PcapWriter {
    buf: Vec<u8>,
}

impl PcapWriter {
    /// Create a new writer and emit the pcap global header.
    pub fn new(snaplen: u32, link_type: u32) -> Self {
        let mut buf = Vec::with_capacity(PCAP_GLOBAL_HEADER_LEN);
        // Global header (all fields little-endian)
        buf.extend_from_slice(&PCAP_MAGIC.to_le_bytes());          // magic
        buf.extend_from_slice(&PCAP_VERSION_MAJOR.to_le_bytes());  // version major
        buf.extend_from_slice(&PCAP_VERSION_MINOR.to_le_bytes());  // version minor
        buf.extend_from_slice(&0i32.to_le_bytes());                // thiszone (UTC)
        buf.extend_from_slice(&0u32.to_le_bytes());                // sigfigs
        buf.extend_from_slice(&snaplen.to_le_bytes());             // snaplen
        buf.extend_from_slice(&link_type.to_le_bytes());           // network (link type)
        Self { buf }
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

//! Packet capture writer in pcap format.
#![cfg(feature = "dump")]

/// pcap magic number (little-endian native, microsecond timestamps).
pub const PCAP_MAGIC: u32 = 0xa1b2c3d4;
/// pcap link type for raw IP (LINKTYPE_RAW = 101).
pub const LINKTYPE_RAW: u32 = 101;

// pcap file format constants
const PCAP_VERSION_MAJOR: u16 = 2;
const PCAP_VERSION_MINOR: u16 = 4;
const PCAP_GLOBAL_HEADER_LEN: usize = 24;

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

    /// Append a packet record with the given timestamp.
    pub fn write_packet(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) {
        let orig_len = data.len() as u32;
        let incl_len = orig_len; // we capture the full packet
        self.buf.extend_from_slice(&ts_sec.to_le_bytes());
        self.buf.extend_from_slice(&ts_usec.to_le_bytes());
        self.buf.extend_from_slice(&incl_len.to_le_bytes());
        self.buf.extend_from_slice(&orig_len.to_le_bytes());
        self.buf.extend_from_slice(data);
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

    fn read_u32_le(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }
    fn read_u16_le(buf: &[u8], off: usize) -> u16 {
        u16::from_le_bytes(buf[off..off + 2].try_into().unwrap())
    }

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
}

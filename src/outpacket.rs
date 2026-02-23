/// Dynamic outgoing packet buffer.
/// Ported from `outpacket.c`.
///
/// The C code maintains a single `struct iovec` whose `iov_base` is
/// reallocated on demand.  The DHCPv6 functions (`new_opt6`, `end_opt6`,
/// `put_opt6_*`) build DHCPv6 option TLVs on top of this buffer.
///
/// Key design difference from C: instead of a global `outpacket_counter`
/// the position is implicit as `buf.len()`.  `save_counter` / `restore_counter`
/// replace the C `save_counter(int)` get/set pattern.

/// A resizable outgoing-packet buffer.
///
/// Uses `Vec<u8>` (rather than `BytesMut`) so that `end_opt6` can
/// overwrite an earlier byte-range in constant time via indexing.
#[derive(Debug, Default, Clone)]
pub struct OutPacket {
    buf: Vec<u8>,
}

impl OutPacket {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Create with a pre-allocated capacity hint.
    pub fn with_capacity(cap: usize) -> Self {
        Self { buf: Vec::with_capacity(cap) }
    }

    /// Append `data` to the buffer, growing it as needed.
    /// Mirrors `expand()` + `memcpy()` in C.
    pub fn put_slice(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Append a big-endian u16.
    pub fn put_u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append a big-endian u32.
    pub fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    /// Append a single byte.
    pub fn put_u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    /// Ensure the buffer has at least `size` bytes of capacity.
    pub fn reserve(&mut self, size: usize) {
        if self.buf.capacity() < size {
            self.buf.reserve(size - self.buf.capacity());
        }
    }

    /// Return the current write position (number of bytes written).
    /// Equivalent to reading `outpacket_counter` in C.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// True if the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// Borrow the current contents as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Return a copy of the buffer contents and clear the buffer.
    pub fn freeze(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buf)
    }

    /// Reset (clear) the buffer for reuse.
    /// Mirrors `reset_counter()` in C.
    pub fn clear(&mut self) {
        self.buf.clear();
    }
}

// ── DHCPv6 option builder ─────────────────────────────────────────────────────
//
// These methods mirror the C functions in `outpacket.c` (gated by `HAVE_DHCP6`).
//
// Usage pattern:
//
//   pkt.clear();
//   // write DHCPv6 message header directly with put_u8 / put_slice…
//   let opt = pkt.new_opt6(OPTION_IA_NA);     // open option
//   pkt.put_opt6_long(iaid);
//   pkt.put_opt6_long(t1);
//   pkt.put_opt6_long(t2);
//   pkt.end_opt6(opt);                         // close, fill in length
//
// Nested options:
//
//   let outer = pkt.new_opt6(OPTION_IA_NA);
//   pkt.put_opt6_long(iaid); pkt.put_opt6_long(t1); pkt.put_opt6_long(t2);
//   let inner = pkt.new_opt6(OPTION_IAADDR);
//   pkt.put_opt6(addr.octets().as_ref());
//   pkt.put_opt6_long(preferred); pkt.put_opt6_long(valid);
//   pkt.end_opt6(inner);
//   pkt.end_opt6(outer);

#[cfg(feature = "dhcp6")]
impl OutPacket {
    /// Save the current write position.
    ///
    /// Equivalent to `save_counter(-1)` (read without write) in C.
    /// Pass the returned value to `restore_counter` to undo writes.
    pub fn save_counter(&self) -> usize {
        self.buf.len()
    }

    /// Truncate the buffer back to `pos`, discarding everything written since.
    ///
    /// Equivalent to `save_counter(pos)` (write mode) in C.
    pub fn restore_counter(&mut self, pos: usize) {
        self.buf.truncate(pos);
    }

    /// Start a new DHCPv6 option.
    ///
    /// Writes the 2-byte option code and a 2-byte zero placeholder for the
    /// data length.  Returns the byte offset of the option header; pass this
    /// to `end_opt6` when the option's content is complete.
    ///
    /// Mirrors `new_opt6(int opt)` in C.
    pub fn new_opt6(&mut self, opt: u16) -> usize {
        let pos = self.buf.len();
        self.buf.extend_from_slice(&opt.to_be_bytes()); // option code
        self.buf.extend_from_slice(&[0u8, 0u8]);        // length placeholder
        pos
    }

    /// Finalise the DHCPv6 option opened by `new_opt6`.
    ///
    /// Writes the actual data length (number of bytes written after the
    /// 4-byte header) into the placeholder left by `new_opt6`.
    ///
    /// Mirrors `end_opt6(int container)` in C.
    pub fn end_opt6(&mut self, container: usize) {
        let data_len = (self.buf.len() - container - 4) as u16;
        let bytes = data_len.to_be_bytes();
        self.buf[container + 2] = bytes[0];
        self.buf[container + 3] = bytes[1];
    }

    /// Append raw bytes as DHCPv6 option payload.
    ///
    /// Mirrors `put_opt6(void *data, size_t len)` in C.
    pub fn put_opt6(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Append a big-endian u32 as DHCPv6 option payload.
    ///
    /// Mirrors `put_opt6_long(unsigned int val)` in C.
    pub fn put_opt6_long(&mut self, val: u32) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a big-endian u16 as DHCPv6 option payload.
    ///
    /// Mirrors `put_opt6_short(unsigned int val)` in C.
    pub fn put_opt6_short(&mut self, val: u16) {
        self.buf.extend_from_slice(&val.to_be_bytes());
    }

    /// Append a single byte as DHCPv6 option payload.
    ///
    /// Mirrors `put_opt6_char(unsigned int val)` in C.
    pub fn put_opt6_char(&mut self, val: u8) {
        self.buf.push(val);
    }

    /// Append UTF-8 string bytes (no null terminator) as DHCPv6 option payload.
    ///
    /// Mirrors `put_opt6_string(char *s)` in C.
    pub fn put_opt6_string(&mut self, s: &str) {
        self.buf.extend_from_slice(s.as_bytes());
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── General buffer tests ──────────────────────────────────────────────────

    #[test]
    fn put_and_read() {
        let mut pkt = OutPacket::new();
        pkt.put_slice(b"hello");
        pkt.put_u16(0x1234);
        pkt.put_u32(0xdeadbeef);
        assert_eq!(pkt.len(), 5 + 2 + 4);
        let s = pkt.as_slice();
        assert_eq!(&s[..5], b"hello");
        assert_eq!(u16::from_be_bytes(s[5..7].try_into().unwrap()), 0x1234);
        assert_eq!(u32::from_be_bytes(s[7..11].try_into().unwrap()), 0xdeadbeef);
    }

    #[test]
    fn freeze_clears_buffer() {
        let mut pkt = OutPacket::with_capacity(16);
        pkt.put_slice(b"test");
        let frozen = pkt.freeze();
        assert_eq!(&frozen[..], b"test");
        assert!(pkt.is_empty());
    }

    #[test]
    fn clear_and_reuse() {
        let mut pkt = OutPacket::new();
        pkt.put_slice(b"data");
        pkt.clear();
        assert!(pkt.is_empty());
        pkt.put_slice(b"new");
        assert_eq!(pkt.as_slice(), b"new");
    }

    // ── DHCPv6 option builder tests ───────────────────────────────────────────

    #[cfg(feature = "dhcp6")]
    mod dhcp6_tests {
        use super::*;

        fn read_u16_be(buf: &[u8], off: usize) -> u16 {
            u16::from_be_bytes(buf[off..off + 2].try_into().unwrap())
        }
        fn read_u32_be(buf: &[u8], off: usize) -> u32 {
            u32::from_be_bytes(buf[off..off + 4].try_into().unwrap())
        }

        #[test]
        fn new_and_end_opt6_simple() {
            let mut pkt = OutPacket::new();
            let opt_off = pkt.new_opt6(0x0003); // e.g. OPTION_IA_NA = 3
            pkt.put_opt6_long(0x0000_0001); // IAID
            pkt.put_opt6_long(3600);         // T1
            pkt.put_opt6_long(7200);         // T2
            pkt.end_opt6(opt_off);

            let b = pkt.as_slice();
            // Option code at offset 0
            assert_eq!(read_u16_be(b, 0), 0x0003);
            // Data length = 12 bytes (3 * u32)
            assert_eq!(read_u16_be(b, 2), 12);
            // IAID
            assert_eq!(read_u32_be(b, 4), 1);
            // T1
            assert_eq!(read_u32_be(b, 8), 3600);
            // T2
            assert_eq!(read_u32_be(b, 12), 7200);
            assert_eq!(b.len(), 16);
        }

        #[test]
        fn end_opt6_empty_payload() {
            let mut pkt = OutPacket::new();
            let opt_off = pkt.new_opt6(0x0001);
            pkt.end_opt6(opt_off);

            let b = pkt.as_slice();
            assert_eq!(b.len(), 4);
            assert_eq!(read_u16_be(b, 0), 0x0001);
            assert_eq!(read_u16_be(b, 2), 0); // length = 0
        }

        #[test]
        fn nested_options() {
            // Build: outer option containing an inner option.
            let mut pkt = OutPacket::new();
            let outer = pkt.new_opt6(0x0003); // IA_NA
            pkt.put_opt6_long(1);  // IAID
            pkt.put_opt6_long(300);
            pkt.put_opt6_long(600);
            let inner = pkt.new_opt6(0x0005); // IAADDR
            pkt.put_opt6(&[0u8; 16]); // IPv6 addr
            pkt.put_opt6_long(300);
            pkt.put_opt6_long(600);
            pkt.end_opt6(inner);
            pkt.end_opt6(outer);

            let b = pkt.as_slice();
            // Inner option starts at offset 4 + 12 = 16
            let inner_off = 4 + 12;
            assert_eq!(read_u16_be(b, inner_off), 0x0005);
            let inner_data_len = read_u16_be(b, inner_off + 2) as usize;
            // IAADDR data: 16 bytes addr + 4 + 4 = 24
            assert_eq!(inner_data_len, 24);

            // Outer data length = 12 (IDs/T1/T2) + 4 (inner header) + inner data
            let outer_data_len = read_u16_be(b, 2) as usize;
            assert_eq!(outer_data_len, 12 + 4 + inner_data_len);
        }

        #[test]
        fn save_and_restore_counter() {
            let mut pkt = OutPacket::new();
            pkt.put_slice(b"keep");
            let saved = pkt.save_counter();
            pkt.put_slice(b"discard");
            assert_eq!(pkt.len(), 11);
            pkt.restore_counter(saved);
            assert_eq!(pkt.len(), 4);
            assert_eq!(pkt.as_slice(), b"keep");
        }

        #[test]
        fn put_opt6_scalar_types() {
            let mut pkt = OutPacket::new();
            pkt.put_opt6_char(0xAB);
            pkt.put_opt6_short(0x1234);
            pkt.put_opt6_long(0xDEAD_BEEF);
            let b = pkt.as_slice();
            assert_eq!(b[0], 0xAB);
            assert_eq!(read_u16_be(b, 1), 0x1234);
            assert_eq!(read_u32_be(b, 3), 0xDEAD_BEEF);
        }

        #[test]
        fn put_opt6_string() {
            let mut pkt = OutPacket::new();
            pkt.put_opt6_string("hello");
            assert_eq!(pkt.as_slice(), b"hello");
        }

        #[test]
        fn multiple_sequential_options() {
            let mut pkt = OutPacket::new();
            // First option: code 1, payload "AB"
            let o1 = pkt.new_opt6(1);
            pkt.put_opt6(b"AB");
            pkt.end_opt6(o1);
            // Second option: code 2, payload "CDEF"
            let o2 = pkt.new_opt6(2);
            pkt.put_opt6(b"CDEF");
            pkt.end_opt6(o2);

            let b = pkt.as_slice();
            // Option 1: code=1, len=2
            assert_eq!(read_u16_be(b, 0), 1);
            assert_eq!(read_u16_be(b, 2), 2);
            assert_eq!(&b[4..6], b"AB");
            // Option 2: code=2, len=4
            assert_eq!(read_u16_be(b, 6), 2);
            assert_eq!(read_u16_be(b, 8), 4);
            assert_eq!(&b[10..14], b"CDEF");
        }
    }
}

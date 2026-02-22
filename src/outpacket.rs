/// Dynamic outgoing packet buffer.
/// Ported from `outpacket.c`.
///
/// The C code maintains a single `struct iovec` whose `iov_base` is
/// reallocated on demand.  Here we use `bytes::BytesMut` for safe,
/// growable byte buffer semantics.

use bytes::{BufMut, BytesMut, Bytes};

/// A resizable outgoing-packet buffer.
#[derive(Debug, Default)]
pub struct OutPacket {
    buf: BytesMut,
}

impl OutPacket {
    pub fn new() -> Self {
        Self { buf: BytesMut::new() }
    }

    /// Create with a pre-allocated capacity hint.
    pub fn with_capacity(cap: usize) -> Self {
        Self { buf: BytesMut::with_capacity(cap) }
    }

    /// Append `data` to the buffer, growing it as needed.
    pub fn put_slice(&mut self, data: &[u8]) {
        self.buf.put_slice(data);
    }

    /// Write a big-endian u16.
    pub fn put_u16(&mut self, v: u16) {
        self.buf.put_u16(v);
    }

    /// Write a big-endian u32.
    pub fn put_u32(&mut self, v: u32) {
        self.buf.put_u32(v);
    }

    /// Ensure the buffer has at least `size` bytes of capacity.
    pub fn reserve(&mut self, size: usize) {
        if self.buf.capacity() < size {
            self.buf.reserve(size - self.buf.capacity());
        }
    }

    /// Return the current length of the buffer.
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

    /// Freeze and return the buffer contents, resetting the buffer.
    pub fn freeze(&mut self) -> Bytes {
        self.buf.split().freeze()
    }

    /// Reset (clear) the buffer for reuse.
    pub fn clear(&mut self) {
        self.buf.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}

//! A minimal, checked byte-buffer cursor shared by this crate's wire-format
//! parsers (DNS, DHCP, DHCPv6, RA, TFTP, and the private helper-process
//! pipe protocol).
//!
//! `ByteCursor` knows nothing about any particular wire format — it only
//! tracks a read position within a borrowed byte slice and exposes
//! bounds-checked primitive reads that return `None` on truncation. Each
//! parser keeps its own error type and domain-specific logic (DNS name
//! decompression, TLV interpretation, and so on) on top of these
//! primitives, mapping a `None` into whatever error variant fits that
//! call site — this type deliberately does not impose one error type on
//! every consumer.
//!
//! Replaces several independent hand-rolled "walk a buffer with a position
//! index, bounds-check, advance" implementations (see issue #144).

/// A read cursor over a borrowed byte slice.
#[derive(Debug, Clone, Copy)]
pub struct ByteCursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ByteCursor<'a> {
    /// A cursor starting at the beginning of `buf`.
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// A cursor starting at `pos` within `buf`. `pos` may be past the end
    /// of `buf`; subsequent reads will simply fail until repositioned.
    pub fn at(buf: &'a [u8], pos: usize) -> Self {
        Self { buf, pos }
    }

    /// The full underlying buffer, independent of the current position.
    /// Needed by formats (e.g. DNS message compression pointers) whose
    /// fields point elsewhere in the same buffer rather than only forward
    /// from the current position.
    pub fn buf(&self) -> &'a [u8] {
        self.buf
    }

    /// The current read position, as a byte offset from the start of `buf`.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Jump to an arbitrary position (e.g. to follow a compression pointer
    /// or rewind after a lookahead). Does not itself bounds-check `pos`
    /// against `buf.len()`; the next read simply fails if `pos` is past
    /// the end.
    pub fn set_position(&mut self, pos: usize) {
        self.pos = pos;
    }

    /// Bytes remaining between the current position and the end of `buf`.
    pub fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }

    /// Whether the cursor has reached (or passed) the end of `buf`.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Read one byte and advance, or `None` if the cursor is at the end.
    pub fn read_u8(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    /// Look at the next byte without consuming it.
    pub fn peek_u8(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }

    /// Read a big-endian `u16` and advance by 2, or `None` if fewer than 2
    /// bytes remain.
    pub fn read_u16_be(&mut self) -> Option<u16> {
        let bytes = self.read_slice(2)?;
        Some(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    /// Read a big-endian `u32` and advance by 4, or `None` if fewer than 4
    /// bytes remain.
    pub fn read_u32_be(&mut self) -> Option<u32> {
        let bytes = self.read_slice(4)?;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read `n` bytes and advance, or `None` if fewer than `n` bytes
    /// remain. Returns a slice borrowed from the original buffer, not a
    /// copy.
    pub fn read_slice(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }

    /// Skip `n` bytes without returning them, or `None` (leaving the
    /// position unchanged) if fewer than `n` bytes remain.
    pub fn advance(&mut self, n: usize) -> Option<()> {
        let end = self.pos.checked_add(n)?;
        if end > self.buf.len() {
            return None;
        }
        self.pos = end;
        Some(())
    }

    /// Offset (relative to the current position) of the first occurrence
    /// of `byte` at or after the current position, if any. Does not
    /// consume anything.
    pub fn find(&self, byte: u8) -> Option<usize> {
        self.buf[self.pos..].iter().position(|&b| b == byte)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_starts_at_zero() {
        let c = ByteCursor::new(&[1, 2, 3]);
        assert_eq!(c.position(), 0);
        assert_eq!(c.remaining(), 3);
        assert!(!c.is_empty());
    }

    #[test]
    fn at_starts_at_given_position() {
        let c = ByteCursor::at(&[1, 2, 3, 4], 2);
        assert_eq!(c.position(), 2);
        assert_eq!(c.remaining(), 2);
    }

    #[test]
    fn read_u8_advances_and_returns_none_at_end() {
        let mut c = ByteCursor::new(&[0xAA, 0xBB]);
        assert_eq!(c.read_u8(), Some(0xAA));
        assert_eq!(c.position(), 1);
        assert_eq!(c.read_u8(), Some(0xBB));
        assert_eq!(c.position(), 2);
        assert_eq!(c.read_u8(), None);
        assert_eq!(c.position(), 2, "failed read must not move the position");
    }

    #[test]
    fn peek_u8_does_not_advance() {
        let mut c = ByteCursor::new(&[0x11, 0x22]);
        assert_eq!(c.peek_u8(), Some(0x11));
        assert_eq!(c.position(), 0);
        assert_eq!(c.read_u8(), Some(0x11));
    }

    #[test]
    fn peek_u8_none_at_end() {
        let c = ByteCursor::at(&[1, 2], 2);
        assert_eq!(c.peek_u8(), None);
    }

    #[test]
    fn read_u16_be_reads_big_endian() {
        let mut c = ByteCursor::new(&[0x01, 0x02, 0xFF]);
        assert_eq!(c.read_u16_be(), Some(0x0102));
        assert_eq!(c.position(), 2);
    }

    #[test]
    fn read_u16_be_none_on_truncation() {
        let mut c = ByteCursor::new(&[0x01]);
        assert_eq!(c.read_u16_be(), None);
        assert_eq!(c.position(), 0, "failed read must not move the position");
    }

    #[test]
    fn read_u32_be_reads_big_endian() {
        let mut c = ByteCursor::new(&[0x00, 0x00, 0x01, 0x00, 0xFF]);
        assert_eq!(c.read_u32_be(), Some(256));
        assert_eq!(c.position(), 4);
    }

    #[test]
    fn read_u32_be_none_on_truncation() {
        let mut c = ByteCursor::new(&[0x00, 0x00, 0x01]);
        assert_eq!(c.read_u32_be(), None);
        assert_eq!(c.position(), 0);
    }

    #[test]
    fn read_slice_exact_fit() {
        let mut c = ByteCursor::new(&[1, 2, 3, 4]);
        assert_eq!(c.read_slice(4), Some(&[1, 2, 3, 4][..]));
        assert_eq!(c.position(), 4);
        assert!(c.is_empty());
    }

    #[test]
    fn read_slice_none_when_one_byte_short() {
        let mut c = ByteCursor::new(&[1, 2, 3]);
        assert_eq!(c.read_slice(4), None);
        assert_eq!(c.position(), 0);
    }

    #[test]
    fn read_slice_zero_length_at_end_of_buffer() {
        let mut c = ByteCursor::at(&[1, 2], 2);
        assert_eq!(c.read_slice(0), Some(&[][..]));
    }

    #[test]
    fn read_slice_overflow_does_not_panic() {
        let mut c = ByteCursor::at(&[1, 2, 3], 1);
        assert_eq!(c.read_slice(usize::MAX), None);
        assert_eq!(c.position(), 1);
    }

    #[test]
    fn advance_moves_position_without_returning_bytes() {
        let mut c = ByteCursor::new(&[1, 2, 3, 4, 5]);
        assert_eq!(c.advance(3), Some(()));
        assert_eq!(c.position(), 3);
        assert_eq!(c.read_u8(), Some(4));
    }

    #[test]
    fn advance_none_on_truncation_leaves_position_unchanged() {
        let mut c = ByteCursor::new(&[1, 2]);
        assert_eq!(c.advance(5), None);
        assert_eq!(c.position(), 0);
    }

    #[test]
    fn set_position_seeks_forward_and_backward() {
        let mut c = ByteCursor::new(&[10, 20, 30, 40]);
        c.set_position(3);
        assert_eq!(c.read_u8(), Some(40));
        c.set_position(0);
        assert_eq!(c.read_u8(), Some(10));
    }

    #[test]
    fn set_position_past_end_makes_next_read_fail() {
        let mut c = ByteCursor::new(&[1, 2]);
        c.set_position(10);
        assert_eq!(c.read_u8(), None);
        assert!(c.is_empty());
    }

    #[test]
    fn buf_returns_full_buffer_regardless_of_position() {
        let data = [1, 2, 3, 4];
        let mut c = ByteCursor::new(&data);
        c.advance(2).unwrap();
        assert_eq!(c.buf(), &data[..]);
    }

    #[test]
    fn find_locates_byte_relative_to_current_position() {
        let mut c = ByteCursor::new(b"abc\0def\0");
        assert_eq!(c.find(0), Some(3));
        c.advance(4).unwrap();
        assert_eq!(c.find(0), Some(3));
    }

    #[test]
    fn find_none_when_byte_absent() {
        let c = ByteCursor::new(b"abcdef");
        assert_eq!(c.find(0), None);
    }

    #[test]
    fn remaining_and_is_empty_track_position() {
        let mut c = ByteCursor::new(&[1, 2, 3]);
        assert_eq!(c.remaining(), 3);
        c.read_u8();
        assert_eq!(c.remaining(), 2);
        assert!(!c.is_empty());
        c.advance(2).unwrap();
        assert_eq!(c.remaining(), 0);
        assert!(c.is_empty());
    }
}

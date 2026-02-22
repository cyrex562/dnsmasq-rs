/// Pooled block allocator for variable-length DNSSEC key / RR data.
/// Ported from `blockdata.c`.
///
/// In the C code, `blockdata` is a slab allocator using a free-list of
/// fixed-size (`KEYBLOCK_LEN`) blocks chained together.
/// In Rust we use a plain `Vec<u8>` which is safe and avoids manual memory
/// management.  The pool wrapper below mirrors the C API.

use std::io::{Read, Write};

pub const KEYBLOCK_LEN: usize = 40;

/// A pooled byte-string — equivalent to a chain of `struct blockdata`.
#[derive(Debug, Clone)]
pub struct Blockdata {
    data: Vec<u8>,
}

impl Blockdata {
    /// Allocate a new `Blockdata` from the provided byte slice.
    pub fn alloc(data: &[u8]) -> Self {
        Self { data: data.to_vec() }
    }

    /// Create an empty `Blockdata` (use `expand` to add data later).
    pub fn empty() -> Self {
        Self { data: Vec::new() }
    }

    /// Append `new_data` to the end of this block.
    pub fn expand(&mut self, new_data: &[u8]) {
        self.data.extend_from_slice(new_data);
    }

    /// Return a reference to the raw bytes.
    pub fn retrieve(&self) -> &[u8] {
        &self.data
    }

    /// Return the stored length in bytes.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// True if no data is stored.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Read `len` bytes from `reader` into a new `Blockdata`.
    pub fn read_from<R: Read>(reader: &mut R, len: usize) -> std::io::Result<Self> {
        let mut buf = vec![0u8; len];
        reader.read_exact(&mut buf)?;
        Ok(Self { data: buf })
    }

    /// Write stored bytes to `writer`.
    pub fn write_to<W: Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.data)
    }
}

/// Global statistics (mirrors the C statics).
#[derive(Debug, Default)]
pub struct BlockdataStats {
    pub count:    usize,
    pub hwm:      usize,
    pub alloced:  usize,
}

impl BlockdataStats {
    pub fn on_alloc(&mut self, len: usize) {
        let blocks = (len + KEYBLOCK_LEN - 1) / KEYBLOCK_LEN;
        self.count   += blocks;
        self.alloced += blocks;
        if self.count > self.hwm {
            self.hwm = self.count;
        }
    }

    pub fn on_free(&mut self, len: usize) {
        let blocks = (len + KEYBLOCK_LEN - 1) / KEYBLOCK_LEN;
        self.count = self.count.saturating_sub(blocks);
    }

    pub fn report(&self) -> String {
        format!(
            "pool memory in use {}, max {}, allocated {}",
            self.count   * KEYBLOCK_LEN,
            self.hwm     * KEYBLOCK_LEN,
            self.alloced * KEYBLOCK_LEN,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_retrieve_roundtrip() {
        let data = b"hello dnsmasq";
        let bd = Blockdata::alloc(data);
        assert_eq!(bd.retrieve(), data);
        assert_eq!(bd.len(), data.len());
    }

    #[test]
    fn expand_appends_data() {
        let mut bd = Blockdata::alloc(b"hello");
        bd.expand(b" world");
        assert_eq!(bd.retrieve(), b"hello world");
    }

    #[test]
    fn empty_blockdata() {
        let bd = Blockdata::empty();
        assert!(bd.is_empty());
        assert_eq!(bd.len(), 0);
    }

    #[test]
    fn read_write_roundtrip() {
        let data = vec![1u8, 2, 3, 4, 5];
        let bd = Blockdata::alloc(&data);
        let mut buf = Vec::new();
        bd.write_to(&mut buf).unwrap();
        let bd2 = Blockdata::read_from(&mut buf.as_slice(), data.len()).unwrap();
        assert_eq!(bd2.retrieve(), data.as_slice());
    }

    #[test]
    fn large_alloc_beyond_keyblock_len() {
        let data = vec![0xaau8; KEYBLOCK_LEN * 3 + 7];
        let bd = Blockdata::alloc(&data);
        assert_eq!(bd.retrieve(), data.as_slice());
    }

    #[test]
    fn stats_tracking() {
        let mut stats = BlockdataStats::default();
        stats.on_alloc(KEYBLOCK_LEN * 2);
        assert_eq!(stats.count, 2);
        assert_eq!(stats.hwm, 2);
        stats.on_free(KEYBLOCK_LEN);
        assert_eq!(stats.count, 1);
        assert_eq!(stats.hwm, 2); // hwm doesn't decrease
    }
}

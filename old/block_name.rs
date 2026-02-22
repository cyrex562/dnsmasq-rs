use crate::config::KEYBLOCK_LEN;

pub struct BlockData {
    pub next: Option<Box<BlockData>>,
    pub key: [u8; KEYBLOCK_LEN],
}
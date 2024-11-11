
use std::ptr;
use std::alloc::{alloc, dealloc, Layout};
use std::mem;
use std::slice;
use std::io::{self, Read, Write};

struct BlockData {
    key: [u8; KEYBLOCK_LEN],
    next: Option<Box<BlockData>>,
}

static mut KEYBLOCK_FREE: Option<Box<BlockData>> = None;
static mut BLOCKDATA_COUNT: usize = 0;
static mut BLOCKDATA_HWM: usize = 0;
static mut BLOCKDATA_ALLOCED: usize = 0;

const KEYBLOCK_LEN: usize = 512;

fn add_blocks(n: usize) {
    let layout = Layout::array::<BlockData>(n).unwrap();
    unsafe {
        let new = alloc(layout) as *mut BlockData;
        if !new.is_null() {
            for i in 0..n {
                let block = new.add(i);
                (*block).next = if i == n - 1 {
                    KEYBLOCK_FREE.take()
                } else {
                    Some(Box::from_raw(new.add(i + 1)))
                };
            }
            KEYBLOCK_FREE = Some(Box::from_raw(new));
            BLOCKDATA_ALLOCED += n;
        }
    }
}

pub fn blockdata_init(cachesize: usize) {
    unsafe {
        KEYBLOCK_FREE = None;
        BLOCKDATA_ALLOCED = 0;
        BLOCKDATA_COUNT = 0;
        BLOCKDATA_HWM = 0;

        if option_bool(OPT_DNSSEC_VALID) {
            add_blocks(cachesize);
        }
    }
}

pub fn blockdata_report() {
    unsafe {
        println!(
            "pool memory in use {}, max {}, allocated {}",
            BLOCKDATA_COUNT * mem::size_of::<BlockData>(),
            BLOCKDATA_HWM * mem::size_of::<BlockData>(),
            BLOCKDATA_ALLOCED * mem::size_of::<BlockData>()
        );
    }
}

fn new_block() -> Option<Box<BlockData>> {
    unsafe {
        if KEYBLOCK_FREE.is_none() {
            add_blocks(50);
        }

        if let Some(mut block) = KEYBLOCK_FREE.take() {
            KEYBLOCK_FREE = block.next.take();
            BLOCKDATA_COUNT += 1;
            if BLOCKDATA_HWM < BLOCKDATA_COUNT {
                BLOCKDATA_HWM = BLOCKDATA_COUNT;
            }
            Some(block)
        } else {
            None
        }
    }
}

fn blockdata_alloc_real(fd: i32, data: Option<&[u8]>, mut len: usize) -> Option<Box<BlockData>> {
    let mut ret: Option<Box<BlockData>> = None;
    let mut prev = &mut ret;

    while len > 0 {
        let block = new_block()?;
        let blen = if len > KEYBLOCK_LEN { KEYBLOCK_LEN } else { len };

        if let Some(data) = data {
            block.key[..blen].copy_from_slice(&data[..blen]);
        } else {
            let mut buf = &mut block.key[..blen];
            if read_write(fd, &mut buf, true).is_err() {
                blockdata_free(ret);
                return None;
            }
        }

        len -= blen;
        *prev = Some(block);
        prev = &mut prev.as_mut().unwrap().next;
    }

    ret
}

pub fn blockdata_alloc(data: &[u8], len: usize) -> Option<Box<BlockData>> {
    blockdata_alloc_real(0, Some(data), len)
}

pub fn blockdata_expand(block: &mut BlockData, mut oldlen: usize, data: &[u8], mut newlen: usize) -> bool {
    let mut b = block;

    while oldlen > KEYBLOCK_LEN {
        if let Some(next) = b.next.as_mut() {
            b = next;
            oldlen -= KEYBLOCK_LEN;
        } else {
            blockdata_free(Some(Box::new(*block)));
            return false;
        }
    }

    while newlen > 0 {
        let blocksize = KEYBLOCK_LEN - oldlen;
        let size = if newlen <= blocksize { newlen } else { blocksize };

        b.key[oldlen..oldlen + size].copy_from_slice(&data[..size]);
        newlen -= size;

        if newlen > 0 {
            if let Some(next) = new_block() {
                b.next = Some(next);
                b = b.next.as_mut().unwrap();
            } else {
                blockdata_free(Some(Box::new(*block)));
                return false;
            }
        }
        oldlen = 0;
    }

    true
}

pub fn blockdata_free(mut blocks: Option<Box<BlockData>>) {
    while let Some(mut block) = blocks {
        blocks = block.next.take();
        unsafe {
            BLOCKDATA_COUNT -= 1;
            block.next = KEYBLOCK_FREE.take();
            KEYBLOCK_FREE = Some(block);
        }
    }
}

pub fn blockdata_retrieve(block: &BlockData, len: usize, data: Option<&mut [u8]>) -> Option<&mut [u8]> {
    let mut len = len;
    let mut b = block;
    let mut d = data.unwrap_or_else(|| {
        let layout = Layout::array::<u8>(len).unwrap();
        unsafe { slice::from_raw_parts_mut(alloc(layout), len) }
    });

    while len > 0 {
        let blen = if len > KEYBLOCK_LEN { KEYBLOCK_LEN } else { len };
        d[..blen].copy_from_slice(&b.key[..blen]);
        len -= blen;
        if let Some(next) = b.next.as_ref() {
            b = next;
        } else {
            break;
        }
    }

    Some(d)
}

pub fn blockdata_write(block: &BlockData, mut len: usize, fd: i32) {
    let mut b = block;

    while len > 0 {
        let blen = if len > KEYBLOCK_LEN { KEYBLOCK_LEN } else { len };
        let buf = &b.key[..blen];
        read_write(fd, buf, false).unwrap();
        len -= blen;
        if let Some(next) = b.next.as_ref() {
            b = next;
        } else {
            break;
        }
    }
}

pub fn blockdata_read(fd: i32, len: usize) -> Option<Box<BlockData>> {
    blockdata_alloc_real(fd, None, len)
}

fn read_write(fd: i32, buf: &mut [u8], read: bool) -> io::Result<()> {
    if read {
        io::stdin().read_exact(buf)
    } else {
        io::stdout().write_all(buf)
    }
}

fn option_bool(option: u32) -> bool {
    // Placeholder for actual implementation
    true
}

const OPT_DNSSEC_VALID: u32 = 1;
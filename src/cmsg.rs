//! Safe iteration over `recvmsg(2)` ancillary data (`cmsghdr` records).
//!
//! Wraps the `CMSG_FIRSTHDR`/`CMSG_NXTHDR` walk every control-message reader
//! in this crate otherwise hand-rolls, so callers only ever see a
//! `(level, type, &[u8])` view instead of chasing a raw `cmsghdr*` themselves.

/// One parsed control message: its `cmsg_level`/`cmsg_type` plus the payload
/// bytes (`CMSG_DATA`, sized down to `cmsg_len - CMSG_LEN(0)`).
#[cfg(unix)]
pub struct CmsgView<'a> {
    pub level: libc::c_int,
    pub cmsg_type: libc::c_int,
    pub data: &'a [u8],
}

/// Iterate the control messages attached to a `recvmsg(2)`'d `msghdr`.
#[cfg(unix)]
pub struct CmsgIter<'a> {
    msg: &'a libc::msghdr,
    next: *const libc::cmsghdr,
}

#[cfg(unix)]
impl<'a> CmsgIter<'a> {
    /// `msg` must be a `msghdr` that `recvmsg(2)` has already filled in — the
    /// same precondition `CMSG_FIRSTHDR` itself requires.
    pub fn new(msg: &'a libc::msghdr) -> Self {
        let next = unsafe { libc::CMSG_FIRSTHDR(msg) };
        Self { msg, next }
    }
}

#[cfg(unix)]
impl<'a> Iterator for CmsgIter<'a> {
    type Item = CmsgView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let cmsg = self.next;
        if cmsg.is_null() {
            return None;
        }
        // Safety: `cmsg` was produced by the prior `CMSG_FIRSTHDR`/`CMSG_NXTHDR`
        // call against `self.msg`, so it points at a live `cmsghdr` inside
        // `msg`'s control buffer, and `cmsg_len` bounds how much of it the
        // kernel actually initialized.
        let (level, cmsg_type, clen, payload) = unsafe {
            (
                (*cmsg).cmsg_level,
                (*cmsg).cmsg_type,
                (*cmsg).cmsg_len as usize,
                libc::CMSG_DATA(cmsg),
            )
        };
        let hdr_len = unsafe { libc::CMSG_LEN(0) as usize };
        let data_len = clen.saturating_sub(hdr_len);
        // Safety: `payload` (CMSG_DATA) points just past the header within
        // the same initialized region `clen` describes, so `data_len` bytes
        // starting there are valid to read.
        let data = unsafe { std::slice::from_raw_parts(payload, data_len) };

        self.next = unsafe { libc::CMSG_NXTHDR(self.msg, cmsg) };
        Some(CmsgView { level, cmsg_type, data })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn walks_two_control_messages_and_exposes_correct_payloads() {
        let payload_a: [u8; 4] = [0xAA, 0xBB, 0xCC, 0xDD];
        let payload_b: [u8; 2] = [0x11, 0x22];

        let space_a = unsafe { libc::CMSG_SPACE(payload_a.len() as u32) } as usize;
        let space_b = unsafe { libc::CMSG_SPACE(payload_b.len() as u32) } as usize;
        let mut ctrl = vec![0u8; space_a + space_b];

        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = ctrl.len() as _;

        unsafe {
            let cmsg1 = libc::CMSG_FIRSTHDR(&msg);
            assert!(!cmsg1.is_null());
            (*cmsg1).cmsg_level = 111;
            (*cmsg1).cmsg_type = 222;
            (*cmsg1).cmsg_len = libc::CMSG_LEN(payload_a.len() as u32) as _;
            std::ptr::copy_nonoverlapping(payload_a.as_ptr(), libc::CMSG_DATA(cmsg1), payload_a.len());

            let cmsg2 = libc::CMSG_NXTHDR(&msg, cmsg1);
            assert!(!cmsg2.is_null());
            (*cmsg2).cmsg_level = 333;
            (*cmsg2).cmsg_type = 444;
            (*cmsg2).cmsg_len = libc::CMSG_LEN(payload_b.len() as u32) as _;
            std::ptr::copy_nonoverlapping(payload_b.as_ptr(), libc::CMSG_DATA(cmsg2), payload_b.len());
        }

        let mut it = CmsgIter::new(&msg);
        let first = it.next().expect("first cmsg");
        assert_eq!(first.level, 111);
        assert_eq!(first.cmsg_type, 222);
        assert_eq!(first.data, &payload_a);

        let second = it.next().expect("second cmsg");
        assert_eq!(second.level, 333);
        assert_eq!(second.cmsg_type, 444);
        assert_eq!(second.data, &payload_b);

        assert!(it.next().is_none());
    }

    #[test]
    fn empty_control_buffer_yields_nothing() {
        let mut ctrl: Vec<u8> = Vec::new();
        let mut msg: libc::msghdr = unsafe { mem::zeroed() };
        msg.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = 0;

        let mut it = CmsgIter::new(&msg);
        assert!(it.next().is_none());
    }
}

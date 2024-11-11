use std::io;
use std::mem;
use libc::{poll, pollfd};

static mut POLLFDS: Vec<pollfd> = Vec::new();

fn fd_search(fd: i32) -> usize {
    let nfds = unsafe { POLLFDS.len() };
    if nfds == 0 {
        return 0;
    }

    let mut left = 0;
    let mut right = nfds;
    
    while right != left + 1 {
        let mid = (left + right) / 2;

        if unsafe { POLLFDS[mid].fd } > fd {
            right = mid;
        } else {
            left = mid;
        }
    }
    
    if unsafe { POLLFDS[left].fd } >= fd {
        left
    } else {
        right
    }
}

fn poll_reset() {
    unsafe {
        POLLFDS.clear();
    }
}

fn do_poll(timeout: i32) -> io::Result<i32> {
    let nfds = unsafe { POLLFDS.len() };
    let ret = unsafe { poll(POLLFDS.as_mut_ptr(), nfds as u64, timeout) };
    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn poll_check(fd: i32, event: i16) -> bool {
    let i = fd_search(fd);
    let nfds = unsafe { POLLFDS.len() };

    if i < nfds && unsafe { POLLFDS[i].fd } == fd {
        return unsafe { POLLFDS[i].revents } & event != 0;
    }

    false
}

fn poll_listen(fd: i32, event: i16) {
    let nfds = unsafe { POLLFDS.len() };
    let arrsize = unsafe { POLLFDS.capacity() };

    let i = fd_search(fd);

    if i < nfds && unsafe { POLLFDS[i].fd } == fd {
        unsafe {
            POLLFDS[i].events |= event;
        }
    } else {
        if nfds == arrsize {
            let new_size = if arrsize == 0 { 64 } else { arrsize * 2 };
            unsafe {
                POLLFDS.reserve(new_size - arrsize);
            }
        }

        unsafe {
            POLLFDS.insert(i, pollfd {
                fd,
                events: event,
                revents: 0,
            });
        }
    }
}

fn main() {
    // Example usage:
    poll_reset();
    poll_listen(0, libc::POLLIN);
    let hits = do_poll(1000).unwrap();
    println!("Poll hits: {}", hits);
    if poll_check(0, libc::POLLIN) {
        println!("File descriptor 0 is ready for reading.");
    }
}
//! Low-level fd/syscall helpers.
//! Ported from `util.c`.

// ── File-descriptor management ───────────────────────────────────────────────

/// Close all open file descriptors except stdin/stdout/stderr and the three
/// `spare` descriptors.  Used during daemon startup to clean up inherited fds.
///
/// On Linux the `/proc/self/fd` directory is scanned for efficiency; on other
/// platforms we fall back to iterating `0..max_fd`.
pub fn close_fds(max_fd: i64, spare1: i32, spare2: i32, spare3: i32) {
    let spares = [
        libc::STDIN_FILENO,
        libc::STDOUT_FILENO,
        libc::STDERR_FILENO,
        spare1,
        spare2,
        spare3,
    ];

    #[cfg(target_os = "linux")]
    {
        use nix::fcntl::OFlag;
        use nix::sys::stat::Mode;
        use std::os::fd::AsRawFd;

        if let Ok(mut dir) = nix::dir::Dir::open(
            "/proc/self/fd",
            OFlag::O_RDONLY | OFlag::O_DIRECTORY,
            Mode::empty(),
        ) {
            let dirfd = dir.as_raw_fd();
            for entry in dir.iter().flatten() {
                if let Ok(name) = entry.file_name().to_str() {
                    if let Ok(fd) = name.parse::<i32>() {
                        // Skip the directory fd itself (matching util.c:848 "fd == dirfd(d)")
                        // and all the standard spare fds
                        let is_spare = spares.contains(&fd);
                        if fd != dirfd && !is_spare {
                            let _ = nix::unistd::close(fd);
                        }
                    }
                }
            }
            return;
        }
    }

    // Fallback: dumb iteration
    for fd in (0..max_fd as i32).rev() {
        if !spares.contains(&fd) {
            let _ = nix::unistd::close(fd);
        }
    }
}

// ── Retry-aware I/O helpers ───────────────────────────────────────────────────

/// Inspect the return value of `sendto`/`sendmsg` and decide whether to retry.
///
/// Mirrors the C `retry_send()`:
/// - Returns `false` (no retry needed) when `rc != -1` (success).
/// - On `EAGAIN`/`EWOULDBLOCK` sleeps 10 µs and retries up to 1000 times.
/// - On `EINTR` returns `true` immediately (caller should retry).
/// - On any other error returns `false`.
///
/// A thread-local counter tracks the retry budget, reset on each success.
pub fn retry_send(rc: isize) -> bool {
    use std::cell::Cell;
    thread_local! {
        static RETRIES: Cell<u32> = Cell::new(0);
    }

    if rc != -1 {
        RETRIES.with(|r| r.set(0));
        return false;
    }

    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK => {
            std::thread::sleep(std::time::Duration::from_nanos(10_000));
            let retries = RETRIES.with(|r| {
                let v = r.get();
                r.set(v + 1);
                v
            });
            if retries < 1000 {
                return true;
            }
        }
        Some(e) if e == libc::EINTR => return true,
        _ => {}
    }

    RETRIES.with(|r| r.set(0));
    false
}

/// Blocking read or write of exactly `buf.len()` bytes on a raw file descriptor.
///
/// `rw = false` → write; `rw = true` → read.
/// Retries on `EINTR`/`ENOMEM`/`ENOBUFS`; returns `false` on any other error
/// or on EOF during a read.
pub fn read_write(fd: i32, buf: &mut [u8], rw: bool) -> bool {
    use nix::errno::Errno;

    if buf.is_empty() {
        return true;
    }
    // Safety: `fd` is a valid, live fd for the duration of this call, per
    // this function's own contract (same as the raw libc calls it replaces).
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    let mut done = 0usize;
    while done < buf.len() {
        let slice = &mut buf[done..];
        let result = if rw {
            nix::unistd::read(fd, slice)
        } else {
            nix::unistd::write(borrowed, slice)
        };
        match result {
            Ok(0) if rw => return false, // EOF
            Ok(n) => done += n,
            Err(Errno::EINTR | Errno::ENOMEM | Errno::ENOBUFS) => continue,
            Err(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── close_fds ────────────────────────────────────────────────────────────

    // close_fds() closes every fd in the process, including ones Tokio
    // runtimes on other test threads depend on (epoll/eventfd/timerfd), so it
    // must never run in-process inside the shared `cargo test` binary. Fork
    // first, exactly like helper.rs's
    // close_inherited_fds_closes_unrelated_descriptors, so the real close-all
    // only ever happens in a throwaway child.
    #[test]
    #[cfg(target_os = "linux")]
    fn close_fds_skips_directory_fd() {
        use nix::sys::wait::waitpid;
        use nix::unistd::{fork, pipe, ForkResult};
        use std::io::{Read, Write};
        use std::os::unix::io::AsRawFd;

        let (result_r, result_w) = pipe().expect("pipe failed");

        match unsafe { fork() }.expect("fork failed") {
            ForkResult::Child => {
                drop(result_r);
                // close_fds() closes every fd except its spares, including
                // this one — it must be spared too or the child can never
                // report its result back to the parent.
                let result_w_fd = result_w.as_raw_fd();

                // Create a pipe to have fds we want to spare.
                let (spare_read, spare_write) = nix::unistd::pipe().expect("pipe failed");
                let spare_write_fd = spare_write.as_raw_fd();
                let spare_read_fd = spare_read.as_raw_fd();
                let max_fd = spare_write_fd as i64 + 10;

                // Create some other fds that should get closed.
                let fd1 = unsafe { libc::open(b"/dev/null\0".as_ptr() as *const i8, libc::O_WRONLY) };
                let fd2 = unsafe { libc::open(b"/dev/null\0".as_ptr() as *const i8, libc::O_WRONLY) };

                let mut ok = fd1 > 2 && fd1 != spare_write_fd && fd2 > 2 && fd2 != spare_write_fd;

                // Forget the OwnedFds so close_fds is the only thing that
                // touches them from here on.
                std::mem::forget(spare_read);
                std::mem::forget(spare_write);

                // Call close_fds, sparing stdin/stdout/stderr, both pipe
                // ends, and the result-reporting fd. If close_fds closed its
                // own /proc/self/fd directory fd mid-scan, this call would
                // misbehave (panic, loop incorrectly, or fail to close
                // fd1/fd2) rather than return cleanly.
                close_fds(max_fd, spare_write_fd, spare_read_fd, result_w_fd);

                // fd1/fd2 should now be closed (EBADF on write).
                let write_result = unsafe { libc::write(fd1, b"test" as *const u8 as *const libc::c_void, 4) };
                ok &= write_result == -1;

                // spare_write_fd must still be open and functional.
                let write_result = unsafe {
                    libc::write(spare_write_fd, b"X" as *const u8 as *const libc::c_void, 1)
                };
                ok &= write_result == 1;

                unsafe {
                    libc::close(spare_write_fd);
                    libc::close(spare_read_fd);
                }

                let mut f = std::fs::File::from(result_w);
                let _ = f.write_all(&[u8::from(ok)]);
                unsafe { libc::_exit(0) };
            }
            ForkResult::Parent { child } => {
                drop(result_w);
                let mut f = std::fs::File::from(result_r);
                let mut buf = [0u8; 1];
                f.read_exact(&mut buf).expect("child did not report a result");
                waitpid(child, None).expect("waitpid failed");
                assert_eq!(buf[0], 1, "close_fds misbehaved when run against its own directory fd");
            }
        }
    }
}

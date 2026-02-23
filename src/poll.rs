/// Poll/select abstraction.
/// Ported from `poll.c`.
///
/// The C code maintains a **sorted** array of `struct pollfd` (sorted by fd,
/// searched with binary-chop) and exposes:
///   `poll_reset()` / `poll_listen(fd, events)` / `do_poll(timeout)` / `poll_check(fd, events)`
///
/// This Rust port mirrors that design: `PollSet` holds a sorted
/// `Vec<libc::pollfd>`.  After `do_poll()` is called the OS populates
/// `revents` in each entry; `check()` reads from `revents` (not from the
/// registered `events`) — exactly as the C code does.
///
/// `PollDir` is a convenience wrapper that maps `Read → POLLIN` and
/// `Write → POLLOUT` for callers that don't need raw event masks.

use libc;

// Re-export the most-used event-mask constants so callers don't need `libc`.
pub use libc::{POLLIN, POLLOUT, POLLERR, POLLHUP};

/// Convenience direction enum — maps to `POLLIN` / `POLLOUT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollDir {
    Read,
    Write,
}

impl PollDir {
    /// Convert to the corresponding `poll` event-mask bit.
    #[inline]
    pub fn to_events(self) -> i16 {
        match self {
            PollDir::Read  => libc::POLLIN  as i16,
            PollDir::Write => libc::POLLOUT as i16,
        }
    }
}

/// A sorted array of `struct pollfd` — mirrors the C static `pollfds[]`.
///
/// **Lifecycle**:
/// 1. Call `reset()` at the top of each event-loop iteration.
/// 2. Call `listen(fd, events)` for every fd you care about.
/// 3. Call `do_poll(timeout_ms)` to block until I/O is ready.
/// 4. Call `check(fd, events)` (or `check_dir`) to test which fds fired.
#[derive(Debug, Default)]
pub struct PollSet {
    fds: Vec<libc::pollfd>,
}

impl PollSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Reset the fd list — equivalent to C `poll_reset()`.
    pub fn reset(&mut self) {
        self.fds.clear();
    }

    /// Binary-search for `fd`.  Returns the index where `fd` sits (if
    /// present) or where it should be inserted (if absent) — mirrors
    /// `fd_search()` in `poll.c`.
    fn fd_index(&self, fd: i32) -> usize {
        self.fds.partition_point(|p| p.fd < fd)
    }

    /// Register interest in `fd` for the raw `events` mask
    /// (`POLLIN | POLLOUT | POLLERR …`).
    /// If `fd` is already present its events are OR-merged.
    /// Equivalent to C `poll_listen(fd, event)`.
    pub fn listen_events(&mut self, fd: i32, events: i16) {
        let i = self.fd_index(fd);
        if i < self.fds.len() && self.fds[i].fd == fd {
            // fd already registered — merge events
            self.fds[i].events |= events;
        } else {
            self.fds.insert(i, libc::pollfd { fd, events, revents: 0 });
        }
    }

    /// Register interest using a `PollDir` shorthand.
    pub fn listen(&mut self, fd: i32, dir: PollDir) {
        self.listen_events(fd, dir.to_events());
    }

    /// Wait for I/O.  `timeout_ms < 0` means wait forever.
    /// Returns the number of ready fds (≥ 0) or `-1` on error.
    /// Equivalent to C `do_poll(timeout)`.
    ///
    /// After this returns, `check` / `check_dir` inspect `revents`.
    #[cfg(target_os = "linux")]
    pub fn do_poll(&mut self, timeout_ms: i32) -> i32 {
        if self.fds.is_empty() {
            return 0;
        }
        // SAFETY: `fds` is a valid slice of `libc::pollfd`.
        unsafe {
            libc::poll(self.fds.as_mut_ptr(), self.fds.len() as libc::nfds_t, timeout_ms)
        }
    }

    /// Check whether `fd` has any of the `events` bits set in `revents`
    /// (i.e. became ready after `do_poll()`).
    /// Equivalent to C `poll_check(fd, event)`.
    pub fn check_events(&self, fd: i32, events: i16) -> bool {
        let i = self.fd_index(fd);
        i < self.fds.len() && self.fds[i].fd == fd && (self.fds[i].revents & events) != 0
    }

    /// Check readiness using a `PollDir` shorthand.
    pub fn check(&self, fd: i32, dir: PollDir) -> bool {
        self.check_events(fd, dir.to_events())
    }

    /// Iterate over all registered fds (in sorted order).
    pub fn fds(&self) -> impl Iterator<Item = i32> + '_ {
        self.fds.iter().map(|p| p.fd)
    }

    /// Number of registered fds.
    pub fn len(&self) -> usize {
        self.fds.len()
    }

    /// True when no fds are registered.
    pub fn is_empty(&self) -> bool {
        self.fds.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── registration ────────────────────────────────────────────────────────

    #[test]
    fn register_and_check_registered_events() {
        let mut ps = PollSet::new();
        ps.listen(3, PollDir::Read);
        ps.listen(4, PollDir::Write);
        // events are registered…
        assert_eq!(ps.fds[ps.fd_index(3)].events, libc::POLLIN as i16);
        assert_eq!(ps.fds[ps.fd_index(4)].events, libc::POLLOUT as i16);
        // …but revents are 0 until do_poll() runs, so check() returns false
        assert!(!ps.check(3, PollDir::Read));
        assert!(!ps.check(4, PollDir::Write));
    }

    #[test]
    fn reset_clears_all() {
        let mut ps = PollSet::new();
        ps.listen(5, PollDir::Read);
        ps.reset();
        assert!(ps.is_empty());
    }

    #[test]
    fn listen_events_merges_flags() {
        let mut ps = PollSet::new();
        ps.listen_events(7, libc::POLLIN as i16);
        ps.listen_events(7, libc::POLLOUT as i16);
        let i = ps.fd_index(7);
        assert_eq!(ps.fds[i].events, (libc::POLLIN | libc::POLLOUT) as i16);
    }

    #[test]
    fn fds_are_kept_sorted() {
        let mut ps = PollSet::new();
        ps.listen(10, PollDir::Read);
        ps.listen(3,  PollDir::Read);
        ps.listen(7,  PollDir::Write);
        let fds: Vec<i32> = ps.fds().collect();
        assert_eq!(fds, vec![3, 7, 10]);
    }

    #[test]
    fn len_and_is_empty() {
        let mut ps = PollSet::new();
        assert!(ps.is_empty());
        ps.listen(1, PollDir::Read);
        assert_eq!(ps.len(), 1);
        ps.listen(2, PollDir::Write);
        assert_eq!(ps.len(), 2);
        ps.reset();
        assert!(ps.is_empty());
    }

    // ── revents simulation ───────────────────────────────────────────────────

    /// Helper: manually set `revents` for `fd` as if `do_poll()` ran.
    fn set_revents(ps: &mut PollSet, fd: i32, revents: i16) {
        let i = ps.fd_index(fd);
        if i < ps.fds.len() && ps.fds[i].fd == fd {
            ps.fds[i].revents = revents;
        }
    }

    #[test]
    fn check_returns_true_when_revents_match() {
        let mut ps = PollSet::new();
        ps.listen(3, PollDir::Read);
        set_revents(&mut ps, 3, libc::POLLIN as i16);
        assert!(ps.check(3, PollDir::Read));
        assert!(!ps.check(3, PollDir::Write));
    }

    #[test]
    fn check_returns_false_for_unregistered_fd() {
        let ps = PollSet::new();
        assert!(!ps.check(99, PollDir::Read));
    }

    #[test]
    fn check_events_with_multiple_bits() {
        let mut ps = PollSet::new();
        ps.listen_events(5, (libc::POLLIN | libc::POLLOUT) as i16);
        set_revents(&mut ps, 5, libc::POLLERR as i16);
        assert!(ps.check_events(5, libc::POLLERR as i16));
        assert!(!ps.check_events(5, libc::POLLIN as i16));
    }

    #[test]
    fn pollerr_via_listen_events() {
        let mut ps = PollSet::new();
        ps.listen_events(6, (libc::POLLIN | libc::POLLERR) as i16);
        set_revents(&mut ps, 6, (libc::POLLIN | libc::POLLERR) as i16);
        assert!(ps.check_events(6, libc::POLLIN as i16));
        assert!(ps.check_events(6, libc::POLLERR as i16));
    }

    // ── do_poll smoke test (Linux only) ─────────────────────────────────────

    #[cfg(target_os = "linux")]
    #[test]
    fn do_poll_with_pipe_ready_for_read() {
        use std::os::unix::io::FromRawFd;
        use std::io::Write;

        let mut fds = [0i32; 2];
        // SAFETY: standard pipe(2) call
        unsafe { libc::pipe(fds.as_mut_ptr()) };
        let (read_fd, write_fd) = (fds[0], fds[1]);

        // Write a byte so the read end is ready
        let mut write_end = unsafe { std::fs::File::from_raw_fd(write_fd) };
        write_end.write_all(b"x").unwrap();
        std::mem::forget(write_end); // keep the fd open; we close manually below

        let mut ps = PollSet::new();
        ps.listen(read_fd, PollDir::Read);
        let rc = ps.do_poll(100 /* ms */);
        assert_eq!(rc, 1);
        assert!(ps.check(read_fd, PollDir::Read));

        unsafe { libc::close(read_fd); libc::close(write_fd); }
    }
}

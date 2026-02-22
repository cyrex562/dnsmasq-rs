/// Poll/select abstraction.
/// Ported from `poll.c`.
///
/// In the C code, this wraps a `struct pollfd` array and provides
/// `poll_reset`, `poll_listen`, `poll_check` as a simple add/test API.
/// In async Rust, the actual polling is done by tokio, but we keep this
/// module as a lightweight registry of file-descriptor interest for
/// synchronous code paths (e.g. startup, signal handling).

use std::collections::HashSet;

/// I/O interest direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollDir {
    Read,
    Write,
}

/// A simple fd-interest registry (replaces the C `struct pollfd` array).
#[derive(Debug, Default)]
pub struct PollSet {
    read:  HashSet<i32>,
    write: HashSet<i32>,
}

impl PollSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all registered interests.
    pub fn reset(&mut self) {
        self.read.clear();
        self.write.clear();
    }

    /// Register interest in `fd` for the given direction.
    pub fn listen(&mut self, fd: i32, dir: PollDir) {
        match dir {
            PollDir::Read  => { self.read.insert(fd); }
            PollDir::Write => { self.write.insert(fd); }
        }
    }

    /// Returns true if `fd` was marked ready for `dir` (i.e. is registered).
    pub fn check(&self, fd: i32, dir: PollDir) -> bool {
        match dir {
            PollDir::Read  => self.read.contains(&fd),
            PollDir::Write => self.write.contains(&fd),
        }
    }

    pub fn read_fds(&self)  -> impl Iterator<Item = &i32> { self.read.iter() }
    pub fn write_fds(&self) -> impl Iterator<Item = &i32> { self.write.iter() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_and_check() {
        let mut ps = PollSet::new();
        ps.listen(3, PollDir::Read);
        ps.listen(4, PollDir::Write);
        assert!(ps.check(3, PollDir::Read));
        assert!(!ps.check(3, PollDir::Write));
        assert!(ps.check(4, PollDir::Write));
        assert!(!ps.check(4, PollDir::Read));
    }

    #[test]
    fn reset_clears_all() {
        let mut ps = PollSet::new();
        ps.listen(5, PollDir::Read);
        ps.reset();
        assert!(!ps.check(5, PollDir::Read));
    }
}

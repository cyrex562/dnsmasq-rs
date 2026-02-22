//! DNS query forwarding engine — data structures and helpers.
//!
//! Ported from dnsmasq's `forward.c`.  This module contains the pure
//! data structures (`ForwardTable`, `PendingQuery`) and stateless helper
//! functions (`patch_id`, `next_server`, `reply_matches_query`).
//! The async I/O loop is deferred to Phase 11.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::hash_questions::hash_questions;

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

/// A pending (in-flight) forwarded DNS query.
#[derive(Debug)]
pub struct PendingQuery {
    /// DNS transaction ID sent upstream.
    pub id: u16,
    /// Original client transaction ID.
    pub orig_id: u16,
    /// Client socket address.
    pub client: SocketAddr,
    /// Index into the upstream server list.
    pub upstream_idx: usize,
    /// Timestamp when the query was forwarded.
    pub sent_at: Instant,
    /// Hash of the question section (for deduplication).
    pub question_hash: [u8; 16],
    /// Number of retransmission attempts so far.
    pub retries: u8,
}

/// Table of all in-flight queries, keyed by upstream transaction ID.
pub struct ForwardTable {
    queries: HashMap<u16, PendingQuery>,
    next_id: u16,
}

// ──────────────────────────────────────────────────────────────────────────────
// ForwardTable implementation
// ──────────────────────────────────────────────────────────────────────────────

impl ForwardTable {
    /// Create an empty `ForwardTable`.
    pub fn new() -> Self {
        Self {
            queries: HashMap::new(),
            next_id: 1,
        }
    }

    /// Allocate a new pending query and return the upstream transaction ID.
    ///
    /// The ID is chosen by incrementing an internal counter, wrapping around
    /// and skipping any ID that is already in use.
    pub fn alloc_query(
        &mut self,
        orig_id: u16,
        client: SocketAddr,
        upstream_idx: usize,
        question_hash: [u8; 16],
    ) -> u16 {
        // Find the next unused ID, wrapping through the full u16 range.
        let start = self.next_id;
        loop {
            let id = self.next_id;
            // Advance counter, skip 0.
            self.next_id = self.next_id.wrapping_add(1);
            if self.next_id == 0 {
                self.next_id = 1;
            }
            if !self.queries.contains_key(&id) {
                self.queries.insert(
                    id,
                    PendingQuery {
                        id,
                        orig_id,
                        client,
                        upstream_idx,
                        sent_at: Instant::now(),
                        question_hash,
                        retries: 0,
                    },
                );
                return id;
            }
            // Safety valve: if every possible ID is occupied, overwrite the
            // start position (extremely unlikely in practice).
            if self.next_id == start {
                self.queries.insert(
                    id,
                    PendingQuery {
                        id,
                        orig_id,
                        client,
                        upstream_idx,
                        sent_at: Instant::now(),
                        question_hash,
                        retries: 0,
                    },
                );
                return id;
            }
        }
    }

    /// Find a pending query by upstream transaction ID.
    pub fn lookup(&self, id: u16) -> Option<&PendingQuery> {
        self.queries.get(&id)
    }

    /// Remove a completed query, returning it.
    pub fn remove(&mut self, id: u16) -> Option<PendingQuery> {
        self.queries.remove(&id)
    }

    /// Remove and return all queries whose `sent_at` is older than `timeout`.
    pub fn expire_old(&mut self, timeout: Duration) -> Vec<PendingQuery> {
        let now = Instant::now();
        let expired_ids: Vec<u16> = self
            .queries
            .iter()
            .filter(|(_, q)| now.duration_since(q.sent_at) > timeout)
            .map(|(&id, _)| id)
            .collect();

        expired_ids
            .into_iter()
            .filter_map(|id| self.queries.remove(&id))
            .collect()
    }
}

impl Default for ForwardTable {
    fn default() -> Self {
        Self::new()
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Stateless helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Patch the DNS transaction ID in a packet (first 2 bytes of the header).
///
/// Does nothing if `pkt` is shorter than 2 bytes.
pub fn patch_id(pkt: &mut [u8], new_id: u16) {
    if pkt.len() < 2 {
        return;
    }
    let bytes = new_id.to_be_bytes();
    pkt[0] = bytes[0];
    pkt[1] = bytes[1];
}

/// Select the next upstream server index using round-robin.
///
/// `servers` is the full ordered list of server indices.
/// `tried` is the set of indices already attempted for this query.
/// `last` is the index of the most-recently tried server.
///
/// Returns `None` if all servers have been tried.
pub fn next_server(servers: &[usize], tried: &HashSet<usize>, last: usize) -> Option<usize> {
    if servers.is_empty() || tried.len() >= servers.len() {
        return None;
    }
    // Find the position of `last` in `servers`, then scan forward.
    let start = servers
        .iter()
        .position(|&s| s == last)
        .map(|p| (p + 1) % servers.len())
        .unwrap_or(0);

    for i in 0..servers.len() {
        let idx = servers[(start + i) % servers.len()];
        if !tried.contains(&idx) {
            return Some(idx);
        }
    }
    None
}

/// Check whether a reply's question section matches the original query.
///
/// Returns `true` if the first question's (canonicalised) name and qtype are
/// identical in both packets.  A structural parse failure returns `false`.
pub fn reply_matches_query(query_pkt: &[u8], reply_pkt: &[u8]) -> bool {
    match (hash_questions(query_pkt), hash_questions(reply_pkt)) {
        (Some(qh), Some(rh)) => qh == rh,
        _ => false,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn dummy_addr() -> SocketAddr {
        "127.0.0.1:1234".parse().unwrap()
    }

    fn dummy_hash() -> [u8; 16] {
        [1u8; 16]
    }

    // ── ForwardTable ──────────────────────────────────────────────────────────

    #[test]
    fn alloc_query_unique_ids() {
        let mut ft = ForwardTable::new();
        let id1 = ft.alloc_query(100, dummy_addr(), 0, dummy_hash());
        let id2 = ft.alloc_query(101, dummy_addr(), 0, dummy_hash());
        let id3 = ft.alloc_query(102, dummy_addr(), 0, dummy_hash());
        assert_ne!(id1, id2);
        assert_ne!(id2, id3);
        assert_ne!(id1, id3);
    }

    #[test]
    fn lookup_finds_inserted_query() {
        let mut ft = ForwardTable::new();
        let id = ft.alloc_query(42, dummy_addr(), 1, dummy_hash());
        let q = ft.lookup(id).expect("should find query");
        assert_eq!(q.orig_id, 42);
        assert_eq!(q.upstream_idx, 1);
    }

    #[test]
    fn remove_removes_query() {
        let mut ft = ForwardTable::new();
        let id = ft.alloc_query(7, dummy_addr(), 0, dummy_hash());
        let removed = ft.remove(id);
        assert!(removed.is_some());
        assert!(ft.lookup(id).is_none());
    }

    #[test]
    fn remove_absent_id_returns_none() {
        let mut ft = ForwardTable::new();
        assert!(ft.remove(9999).is_none());
    }

    #[test]
    fn expire_old_removes_timed_out_leaves_fresh() {
        let mut ft = ForwardTable::new();

        // Insert a query and immediately back-date its sent_at.
        let old_id = ft.alloc_query(1, dummy_addr(), 0, dummy_hash());
        ft.queries.get_mut(&old_id).unwrap().sent_at =
            Instant::now() - Duration::from_secs(10);

        // Insert a fresh query.
        let fresh_id = ft.alloc_query(2, dummy_addr(), 0, dummy_hash());

        let expired = ft.expire_old(Duration::from_secs(5));
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].id, old_id);
        assert!(ft.lookup(fresh_id).is_some());
        assert!(ft.lookup(old_id).is_none());
    }

    // ── patch_id ──────────────────────────────────────────────────────────────

    #[test]
    fn patch_id_updates_first_two_bytes() {
        let mut pkt = vec![0x00, 0x01, 0x02, 0x03];
        patch_id(&mut pkt, 0xABCD);
        assert_eq!(pkt[0], 0xAB);
        assert_eq!(pkt[1], 0xCD);
        assert_eq!(pkt[2], 0x02); // unchanged
    }

    #[test]
    fn patch_id_short_packet_no_panic() {
        let mut pkt = vec![0x00];
        patch_id(&mut pkt, 0xFFFF); // should not panic
    }

    // ── next_server ───────────────────────────────────────────────────────────

    #[test]
    fn next_server_round_robin() {
        let servers = vec![0, 1, 2];
        let tried = HashSet::new();
        // Starting from last=0, next should be 1.
        let next = next_server(&servers, &tried, 0);
        assert_eq!(next, Some(1));
    }

    #[test]
    fn next_server_none_when_all_tried() {
        let servers = vec![0, 1, 2];
        let tried: HashSet<usize> = [0, 1, 2].iter().copied().collect();
        assert_eq!(next_server(&servers, &tried, 0), None);
    }

    #[test]
    fn next_server_skips_tried() {
        let servers = vec![0, 1, 2];
        let tried: HashSet<usize> = [1].iter().copied().collect();
        // last=0, next would be 1 but it's tried → should skip to 2.
        let next = next_server(&servers, &tried, 0);
        assert_eq!(next, Some(2));
    }

    #[test]
    fn next_server_empty_list_returns_none() {
        let servers: Vec<usize> = vec![];
        let tried = HashSet::new();
        assert_eq!(next_server(&servers, &tried, 0), None);
    }

    // ── reply_matches_query ───────────────────────────────────────────────────

    fn make_dns_query(qname: &str, qtype: u16) -> Vec<u8> {
        let mut pkt = vec![
            0x00, 0x01, 0x01, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in qname.split('.') {
            if label.is_empty() {
                continue;
            }
            pkt.push(label.len() as u8);
            pkt.extend_from_slice(label.as_bytes());
        }
        pkt.push(0);
        pkt.push((qtype >> 8) as u8);
        pkt.push((qtype & 0xFF) as u8);
        pkt.push(0x00);
        pkt.push(0x01); // qclass IN
        pkt
    }

    #[test]
    fn reply_matches_query_matching() {
        let query = make_dns_query("example.com", 1);
        let reply = make_dns_query("example.com", 1);
        assert!(reply_matches_query(&query, &reply));
    }

    #[test]
    fn reply_matches_query_different_name() {
        let query = make_dns_query("example.com", 1);
        let reply = make_dns_query("other.com", 1);
        assert!(!reply_matches_query(&query, &reply));
    }

    #[test]
    fn reply_matches_query_different_qtype() {
        let query = make_dns_query("example.com", 1);
        let reply = make_dns_query("example.com", 28);
        assert!(!reply_matches_query(&query, &reply));
    }

    #[test]
    fn reply_matches_query_invalid_packet() {
        let query = make_dns_query("example.com", 1);
        assert!(!reply_matches_query(&query, &[0u8; 3]));
    }
}

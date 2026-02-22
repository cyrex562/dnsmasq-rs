//! DNS query forwarding engine — data structures and helpers.
//!
//! Ported from dnsmasq's `forward.c`.  This module contains the pure
//! data structures (`ForwardTable`, `PendingQuery`) and stateless helper
//! functions (`patch_id`, `next_server`, `reply_matches_query`), plus
//! the async UDP forwarding engine (`ForwardEngine`, `run_forward_loop`).

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::hash_questions::hash_questions;

// ──────────────────────────────────────────────────────────────────────────────
// Types
// ──────────────────────────────────────────────────────────────────────────────

/// A pending (in-flight) forwarded DNS query.
#[derive(Debug, Clone)]
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
// Async forwarding engine
// ──────────────────────────────────────────────────────────────────────────────

/// Maximum DNS packet size (UDP).
pub const MAX_PACKET_SIZE: usize = 65535;

/// Default query timeout before a forwarded query is abandoned.
pub const QUERY_TIMEOUT_SECS: u64 = 10;

/// Configuration for the forwarding engine.
#[derive(Debug, Clone)]
pub struct ForwardConfig {
    /// Ordered list of upstream resolver addresses.
    pub upstreams: Vec<SocketAddr>,
    /// Per-query timeout.
    pub timeout: Duration,
    /// Maximum number of retries per query.
    pub max_retries: u8,
}

impl Default for ForwardConfig {
    fn default() -> Self {
        Self {
            upstreams:   Vec::new(),
            timeout:     Duration::from_secs(QUERY_TIMEOUT_SECS),
            max_retries: 2,
        }
    }
}

/// Stateful DNS forwarding engine.
///
/// Owns a [`ForwardTable`] and the forwarding configuration.  Used by
/// `run_forward_loop` but can also be driven manually for testing.
pub struct ForwardEngine {
    pub config:          ForwardConfig,
    pub table:           ForwardTable,
    upstream_order:      Vec<usize>,
}

impl ForwardEngine {
    /// Create a new engine with the given configuration.
    pub fn new(config: ForwardConfig) -> Self {
        let n = config.upstreams.len();
        Self {
            upstream_order: (0..n).collect(),
            table: ForwardTable::new(),
            config,
        }
    }

    /// Forward `pkt` to an upstream server and record the pending query.
    ///
    /// Returns `Some(upstream_id)` on success, `None` if no upstream is
    /// available or the send fails.
    pub async fn forward_query(
        &mut self,
        pkt: &[u8],
        client: SocketAddr,
        upstream_sock: &tokio::net::UdpSocket,
    ) -> Option<u16> {
        if pkt.len() < 12 || self.config.upstreams.is_empty() {
            return None;
        }
        let tried = HashSet::new();
        let server_idx = next_server(&self.upstream_order, &tried, usize::MAX)?;
        let upstream_addr = self.config.upstreams[server_idx];

        let qhash = hash_questions(pkt).unwrap_or([0u8; 16]);
        let orig_id = u16::from_be_bytes([pkt[0], pkt[1]]);
        let new_id = self.table.alloc_query(orig_id, client, server_idx, qhash);

        let mut out = pkt.to_vec();
        patch_id(&mut out, new_id);
        match upstream_sock.send_to(&out, upstream_addr).await {
            Ok(_) => Some(new_id),
            Err(_) => {
                self.table.remove(new_id);
                None
            }
        }
    }

    /// Process an upstream reply.
    ///
    /// Matches the reply's transaction ID against the pending table.  If a
    /// match is found, restores the original client ID and returns
    /// `(client_addr, reply_bytes)`.
    pub fn handle_reply(&mut self, reply: &mut Vec<u8>) -> Option<(SocketAddr, Vec<u8>)> {
        if reply.len() < 2 { return None; }
        let reply_id = u16::from_be_bytes([reply[0], reply[1]]);
        let pending = self.table.remove(reply_id)?;
        patch_id(reply, pending.orig_id);
        Some((pending.client, reply.clone()))
    }

    /// Expire timed-out pending queries.
    pub fn expire_queries(&mut self) -> Vec<PendingQuery> {
        self.table.expire_old(self.config.timeout)
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// TCP fallback
// ──────────────────────────────────────────────────────────────────────────────

/// Check whether the TC (truncated) bit is set in a DNS reply.
///
/// Returns `true` only when the packet is at least 12 bytes (header-complete)
/// and byte 2, bit 1 is set.
pub fn is_truncated(pkt: &[u8]) -> bool {
    pkt.len() >= 12 && pkt[2] & 0x02 != 0
}

/// Send a DNS query over TCP to `upstream` and return the full response.
///
/// DNS-over-TCP prefixes the message with a 2-byte big-endian length field
/// (RFC 1035 §4.2.2).  This function:
/// 1. Writes the 2-byte length prefix + query payload.
/// 2. Reads the 2-byte length prefix of the response.
/// 3. Reads exactly that many bytes and returns them.
///
/// Returns `None` on any I/O error or if the server closes the connection
/// before a complete response is received.
pub async fn tcp_query(
    upstream: SocketAddr,
    query: &[u8],
    timeout: Duration,
) -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let connect = tokio::time::timeout(timeout, TcpStream::connect(upstream));
    let mut stream = connect.await.ok()?.ok()?;

    // Write length-prefixed query.
    let len = query.len() as u16;
    let frame: Vec<u8> = {
        let mut v = Vec::with_capacity(2 + query.len());
        v.extend_from_slice(&len.to_be_bytes());
        v.extend_from_slice(query);
        v
    };
    tokio::time::timeout(timeout, stream.write_all(&frame))
        .await.ok()?.ok()?;

    // Read 2-byte response length.
    let mut len_buf = [0u8; 2];
    tokio::time::timeout(timeout, stream.read_exact(&mut len_buf))
        .await.ok()?.ok()?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    // Read the response body.
    let mut resp = vec![0u8; resp_len];
    tokio::time::timeout(timeout, stream.read_exact(&mut resp))
        .await.ok()?.ok()?;

    Some(resp)
}

/// Handle a UDP reply that has the TC bit set.
///
/// Retries the original query (`orig_query`) over TCP to the same upstream
/// server.  On success the full (untruncated) response is returned with the
/// client's original query ID restored.
pub async fn tcp_fallback(
    upstream: SocketAddr,
    orig_query: &[u8],
    client_id: u16,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let mut resp = tcp_query(upstream, orig_query, timeout).await?;
    if resp.len() >= 2 {
        resp[0] = (client_id >> 8) as u8;
        resp[1] = (client_id & 0xFF) as u8;
    }
    Some(resp)
}

/// Run the DNS UDP forwarding event loop.
///
/// * `client_sock` — bound UDP socket facing DNS clients.
/// * `config`      — forwarding configuration (upstreams, timeout).
///
/// Runs until an unrecoverable I/O error occurs.  Logs are omitted for
/// simplicity; callers should wrap this in a task and handle the error.
pub async fn run_forward_loop(
    client_sock: Arc<tokio::net::UdpSocket>,
    config: ForwardConfig,
) -> std::io::Result<()> {
    // Ephemeral socket for upstream communication.
    let upstream_sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;

    let mut engine       = ForwardEngine::new(config);
    let mut client_buf   = vec![0u8; MAX_PACKET_SIZE];
    let mut upstream_buf = vec![0u8; MAX_PACKET_SIZE];
    let mut ticker = tokio::time::interval(Duration::from_secs(1));

    loop {
        tokio::select! {
            // ── Incoming client query ─────────────────────────────────────────
            result = client_sock.recv_from(&mut client_buf) => {
                let (len, src) = result?;
                let pkt = &client_buf[..len];
                // Only forward DNS queries (QR bit == 0).
                if pkt.len() >= 12 && pkt[2] & 0x80 == 0 {
                    engine.forward_query(pkt, src, &upstream_sock).await;
                }
            }
            // ── Upstream reply ────────────────────────────────────────────────
            result = upstream_sock.recv_from(&mut upstream_buf) => {
                let (len, upstream_addr) = result?;
                let mut pkt = upstream_buf[..len].to_vec();
                if let Some((client_addr, reply)) = engine.handle_reply(&mut pkt) {
                    if is_truncated(&reply) {
                        // TC bit set — retry over TCP.
                        let pending = engine.table.lookup(
                            u16::from_be_bytes([reply[0], reply[1]])
                        ).cloned();
                        if let Some(q) = pending {
                            let timeout = engine.config.timeout;
                            if let Some(full) = tcp_fallback(
                                upstream_addr, &pkt, q.orig_id, timeout
                            ).await {
                                let _ = client_sock.send_to(&full, client_addr).await;
                                continue;
                            }
                        }
                    }
                    let _ = client_sock.send_to(&reply, client_addr).await;
                }
            }
            // ── Periodic expiry cleanup ───────────────────────────────────────
            _ = ticker.tick() => {
                let _expired = engine.expire_queries();
            }
        }
    }
}



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

    // ── ForwardEngine ─────────────────────────────────────────────────────────

    #[test]
    fn forward_engine_handle_reply_restores_id() {
        let config = ForwardConfig {
            upstreams: vec!["127.0.0.1:5353".parse().unwrap()],
            ..Default::default()
        };
        let mut engine = ForwardEngine::new(config);
        let client: SocketAddr = "127.0.0.1:1234".parse().unwrap();

        // Simulate inserting a pending query with orig_id=42.
        let new_id = engine.table.alloc_query(42, client, 0, [0u8; 16]);

        // Build a fake reply with the upstream ID.
        let mut reply = vec![
            (new_id >> 8) as u8, (new_id & 0xFF) as u8, // upstream ID
            0x84, 0x00, // QR=1, AA=1
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // counts
        ];
        let (addr, patched) = engine.handle_reply(&mut reply).expect("should match");
        assert_eq!(addr, client);
        // Restored to original client ID 42.
        let restored_id = u16::from_be_bytes([patched[0], patched[1]]);
        assert_eq!(restored_id, 42);
    }

    #[test]
    fn forward_engine_handle_reply_unknown_id_returns_none() {
        let config = ForwardConfig::default();
        let mut engine = ForwardEngine::new(config);
        let mut reply = vec![0xAB, 0xCD, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
                             0x00, 0x00, 0x00, 0x00];
        assert!(engine.handle_reply(&mut reply).is_none());
    }

    #[test]
    fn forward_engine_expire_queries() {
        let config = ForwardConfig {
            timeout: Duration::from_millis(1),
            ..Default::default()
        };
        let mut engine = ForwardEngine::new(config);
        let client: SocketAddr = "127.0.0.1:999".parse().unwrap();
        engine.table.alloc_query(1, client, 0, [0u8; 16]);
        // Wait for timeout.
        std::thread::sleep(Duration::from_millis(5));
        let expired = engine.expire_queries();
        assert_eq!(expired.len(), 1);
    }

    // ── TCP fallback helpers ──────────────────────────────────────────────────

    #[test]
    fn is_truncated_detects_tc_bit() {
        let mut pkt = vec![0u8; 12];
        assert!(!is_truncated(&pkt));
        pkt[2] |= 0x02; // set TC bit
        assert!(is_truncated(&pkt));
    }

    #[test]
    fn is_truncated_short_packet_safe() {
        assert!(!is_truncated(&[]));
        assert!(!is_truncated(&[0u8; 11]));
    }

    #[tokio::test]
    async fn tcp_fallback_restores_client_id() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        // Start a mock TCP DNS server that echoes back the query.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut len_buf = [0u8; 2];
                let _ = stream.read_exact(&mut len_buf).await;
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut body = vec![0u8; len];
                let _ = stream.read_exact(&mut body).await;
                // Echo: prepend length prefix.
                let resp_len = (body.len() as u16).to_be_bytes();
                let _ = stream.write_all(&resp_len).await;
                let _ = stream.write_all(&body).await;
            }
        });

        // Build a minimal query (12-byte header).
        let query = vec![0x00, 0x42, 0x01, 0x00,
                         0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let client_id: u16 = 0x1234;
        let resp = tcp_fallback(addr, &query, client_id, Duration::from_secs(2)).await;
        assert!(resp.is_some());
        let r = resp.unwrap();
        let restored = u16::from_be_bytes([r[0], r[1]]);
        assert_eq!(restored, client_id);
    }
}


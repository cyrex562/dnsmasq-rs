//! Domain-to-upstream-server matching.
//! Full port of `domain-match.c` (778 lines).
//!
//! The core algorithm mirrors dnsmasq's approach:
//! - `ServerArray::build` sorts all servers (regular + local-domains) longest-domain-first.
//! - `ServerArray::lookup` binary-searches for the longest matching suffix of the query,
//!   then calls `filter_servers` to narrow to the right server type based on query flags.

use std::cmp::Ordering;
use std::net::{Ipv4Addr, SocketAddrV4};

use crate::types::addr::MySockAddr;
use crate::types::constants::{
    F_CONFIG, F_DNSSECOK, F_DOMAINSRV, F_DS, F_IPV4, F_IPV6, F_NXDOMAIN, F_NOERR, F_SERVER,
};
use crate::types::server::{
    Server, SERV_4ADDR, SERV_6ADDR, SERV_ALL_ZEROS, SERV_FOR_NODOTS, SERV_LITERAL_ADDRESS,
    SERV_MARK, SERV_USE_RESOLV, SERV_WILDCARD,
};
use crate::util::{hostname_isequal, hostname_order};

// ── Combined flag masks (from dnsmasq.h) ─────────────────────────────────────

/// Servers that live on the `local_domains` chain (not forwarded upstream).
const SERV_IS_LOCAL: u16 = SERV_USE_RESOLV | SERV_LITERAL_ADDRESS;

/// Servers that return a direct IP address.
const SERV_LOCAL_ADDRESS: u16 = SERV_6ADDR | SERV_4ADDR | SERV_ALL_ZEROS;

/// The set of flags that distinguish local-answer priority within a domain group.
const TYPE_FLAGS: u16 =
    SERV_LITERAL_ADDRESS | SERV_4ADDR | SERV_6ADDR | SERV_ALL_ZEROS | SERV_USE_RESOLV;

// ── ServerEntry ──────────────────────────────────────────────────────────────

/// An entry in the sorted server lookup array.
#[derive(Debug, Clone)]
pub struct ServerEntry {
    /// Domain this server handles (empty = catch-all).
    pub domain: String,
    /// `domain.len()` — cached for fast comparisons.
    pub domain_len: usize,
    /// `SERV_*` flags.
    pub flags: u16,
    /// Appearance order in config — used for `--strict-order`.
    pub serial: i32,
    /// Index back into the slice passed to `ServerArray::build`.
    pub index: usize,
    /// `true` if this entry came from `local_domains` (vs. upstream servers).
    pub is_local: bool,
}

// ── Sort helpers ──────────────────────────────────────────────────────────────

/// Compare `qdomain` (of length `qdomain.len()`) against a server `entry`.
///
/// Returns -1 / 0 / +1 (C-style), used in the binary search:
/// * -1 → server is "before" qdomain in the sort key → look left  (`high = try`)
/// * +1 → server is "after"  qdomain in the sort key → look right (`low  = try`)
/// * 0  → exact domain-length + name match
fn order_entry(qdomain: &str, entry: &ServerEntry) -> i32 {
    // NODOTS servers always sort last; they appear "before" any real query.
    if entry.flags & SERV_FOR_NODOTS != 0 {
        return -1;
    }
    let dlen = entry.domain_len;
    let qlen = qdomain.len();
    if qlen < dlen {
        return 1; // server domain longer → look right
    }
    if qlen > dlen {
        return -1; // server domain shorter → look left
    }
    match hostname_order(qdomain, &entry.domain) {
        Ordering::Less => -1,
        Ordering::Equal => 0,
        Ordering::Greater => 1,
    }
}

/// Comparison function for sorting the server array.
/// Mirrors `order_qsort` in `domain-match.c`.
fn compare_entries(a: &ServerEntry, b: &ServerEntry) -> Ordering {
    // SERV_FOR_NODOTS sorts last.
    let a_nd = a.flags & SERV_FOR_NODOTS != 0;
    let b_nd = b.flags & SERV_FOR_NODOTS != 0;
    if a_nd != b_nd {
        return a_nd.cmp(&b_nd); // false < true → nodots goes last ✓
    }

    // Longest domain first.
    match b.domain_len.cmp(&a.domain_len) {
        Ordering::Equal => {}
        ord => return ord,
    }

    // Same length: alphabetical (case-insensitive).
    match hostname_order(&a.domain, &b.domain) {
        Ordering::Equal => {}
        ord => return ord,
    }

    // Same domain name: non-wildcard before wildcard.
    let a_w = a.flags & SERV_WILDCARD != 0;
    let b_w = b.flags & SERV_WILDCARD != 0;
    if a_w != b_w {
        return a_w.cmp(&b_w); // wildcards last ✓
    }

    // Same wildcard status: higher TYPE_FLAGS value sorts first.
    // (SERV_6ADDR=16 > SERV_4ADDR=8 > SERV_ALL_ZEROS=4 > SERV_LITERAL_ADDRESS=2 > SERV_USE_RESOLV=1)
    let at = a.flags & TYPE_FLAGS;
    let bt = b.flags & TYPE_FLAGS;
    match bt.cmp(&at) {
        Ordering::Equal => {}
        ord => return ord,
    }

    // Finally: appearance order (serial) for non-local entries only.
    if !a.is_local && !b.is_local {
        return a.serial.cmp(&b.serial);
    }
    Ordering::Equal
}

// ── ServerArray ──────────────────────────────────────────────────────────────

/// Sorted DNS server lookup table.
///
/// Equivalent to `daemon->serverarray` in dnsmasq.
#[derive(Debug, Clone)]
pub struct ServerArray {
    entries: Vec<ServerEntry>,
    /// `true` if any entry has `SERV_WILDCARD` set.
    pub has_wildcard: bool,
}

impl ServerArray {
    /// Build and sort the server array from upstream servers and local-domain entries.
    ///
    /// * `servers`       — upstream DNS servers (`daemon->servers`).
    /// * `local_domains` — address / NXDOMAIN entries (`daemon->local_domains`).
    ///
    /// SERV_LOOP servers are excluded when the `loop` feature is enabled.
    pub fn build(servers: &[Server], local_domains: &[Server]) -> Self {
        let mut entries: Vec<ServerEntry> = Vec::new();
        let mut has_wildcard = false;
        let mut serial = 0i32;

        for (i, s) in servers.iter().enumerate() {
            #[cfg(feature = "loop")]
            if s.flags & crate::types::server::SERV_LOOP != 0 {
                continue;
            }
            if s.flags & SERV_WILDCARD != 0 {
                has_wildcard = true;
            }
            entries.push(ServerEntry {
                domain: s.domain.clone(),
                domain_len: s.domain.len(),
                flags: s.flags,
                serial,
                index: i,
                is_local: false,
            });
            serial += 1;
        }

        for (i, s) in local_domains.iter().enumerate() {
            if s.flags & SERV_WILDCARD != 0 {
                has_wildcard = true;
            }
            entries.push(ServerEntry {
                domain: s.domain.clone(),
                domain_len: s.domain.len(),
                flags: s.flags,
                serial: 0,
                index: i,
                is_local: true,
            });
        }

        entries.sort_by(compare_entries);
        Self { entries, has_wildcard }
    }

    /// Total number of entries in the sorted array.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Returns `true` if the array is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Return the entry at position `idx`, if in bounds.
    pub fn get(&self, idx: usize) -> Option<&ServerEntry> {
        self.entries.get(idx)
    }

    /// Returns `true` if entries `a` and `b` are in the same domain group.
    /// Mirrors `server_samegroup` in C.
    pub fn same_group(&self, a: usize, b: usize) -> bool {
        match (self.entries.get(a), self.entries.get(b)) {
            (Some(ea), Some(eb)) => {
                if ea.flags & SERV_FOR_NODOTS != 0 {
                    return eb.flags & SERV_FOR_NODOTS != 0;
                }
                order_entry(&ea.domain, eb) == 0
            }
            _ => false,
        }
    }

    /// Find the best server range `[nlow, nhigh)` for `domain` given `flags`.
    ///
    /// Returns `None` if no suitable server is configured.
    /// Mirrors `lookup_domain` in C.
    ///
    /// **Flags** (from `types::constants`):
    /// * `F_SERVER`    — only return a real upstream server (no local answers).
    /// * `F_DNSSECOK`  — disable NODOTS fallback; suppress DNSSEC query diversion.
    /// * `F_DS`        — query the parent zone (strip the first label).
    /// * `F_CONFIG`    — return anything that generates a local IP reply.
    /// * `F_IPV4`/`F_IPV6` — prefer address-family-specific servers.
    /// * `F_DOMAINSRV` — only return a server associated with a specific domain.
    pub fn lookup(&self, domain: &str, flags: u32) -> Option<(usize, usize)> {
        let n = self.entries.len();
        if n == 0 {
            return None;
        }

        // F_DS: look up the parent zone's server by stripping the first label.
        let domain = if flags & F_DS != 0 {
            if let Some(pos) = domain.find('.') {
                &domain[pos + 1..]
            } else {
                ""
            }
        } else {
            domain
        };

        let domain_bytes = domain.as_bytes();

        // nodots: query has no dots (single-label), eligible for NODOTS servers.
        let mut nodots = !domain.is_empty() && !domain.contains('.');
        if domain.is_empty() || flags & F_DNSSECOK != 0 {
            nodots = false;
        }

        // `start` — current position in `domain`; qdomain = &domain[start..]
        let mut start: usize = 0;
        let mut qlen: isize = domain_bytes.len() as isize;
        // `low` is NOT reset between outer iterations (C optimisation).
        let mut low: usize = 0;
        let mut nlow = 0usize;
        let mut nhigh = 0usize;
        let mut found = false;
        let mut flags = flags;

        'outer: while qlen >= 0 {
            let mut high = n; // exclusive upper bound (may be out of bounds initially)
            let mut crop_query: isize = 1;
            let mut rc: i32 = 1; // assume "no match" until binary search says otherwise
            let mut found_try: usize = 0;

            // ── Binary search ──────────────────────────────────────────────
            loop {
                let try_idx = (low + high) / 2;
                let qdomain = &domain[start..start + qlen as usize];
                rc = order_entry(qdomain, &self.entries[try_idx]);

                if rc == 0 {
                    found_try = try_idx;
                    break;
                }

                if rc < 0 {
                    // Server at try_idx sorts before qdomain → look left.
                    if high == try_idx {
                        // Narrowed to a single slot: crop query to this domain's length.
                        crop_query = qlen - self.entries[try_idx].domain_len as isize;
                        break;
                    }
                    high = try_idx;
                } else {
                    // Server at try_idx sorts after qdomain → look right.
                    if low == try_idx {
                        // Find the next domain that is strictly shorter than try_idx.
                        let old_len = self.entries[try_idx].domain_len;
                        let mut t = try_idx + 1;
                        while t < n {
                            if self.entries[t].domain_len != old_len {
                                crop_query = qlen - self.entries[t].domain_len as isize;
                                break;
                            }
                            t += 1;
                        }
                        break;
                    }
                    low = try_idx;
                }
            }
            // ── End binary search ──────────────────────────────────────────

            if rc == 0 {
                let qdomain = &domain[start..start + qlen as usize];
                let mut t = found_try;
                let mut matched = true;

                if self.has_wildcard {
                    // Back up to the first entry with this same domain.
                    while t > 0 && order_entry(qdomain, &self.entries[t - 1]) == 0 {
                        t -= 1;
                    }

                    // Is qdomain at a label boundary within the original domain?
                    let at_boundary = start == 0
                        || qlen == 0
                        || (start > 0 && domain_bytes[start - 1] == b'.');

                    if !at_boundary {
                        // Not at a boundary: only a wildcard server can match.
                        while t < n - 1 && order_entry(qdomain, &self.entries[t + 1]) == 0 {
                            t += 1;
                        }
                        if self.entries[t].flags & SERV_WILDCARD == 0 {
                            matched = false;
                        }
                    }
                }

                if matched {
                    if let Some((nl, nh)) = self.filter_servers_impl(t, flags) {
                        if self.entries[nl].flags & SERV_USE_RESOLV != 0 {
                            // This match says "use resolv.conf": continue searching
                            // from the root (empty query) but only for real servers.
                            crop_query = qlen;
                            flags |= F_SERVER;
                        } else {
                            nlow = nl;
                            nhigh = nh;
                            found = true;
                            break 'outer;
                        }
                    }
                }
            }

            if crop_query == 0 {
                crop_query = 1;
            }
            qlen -= crop_query;
            start += crop_query as usize;

            // Without wildcards, jump to the next label boundary.
            if !self.has_wildcard {
                while qlen > 0 && start > 0 && domain_bytes[start - 1] != b'.' {
                    qlen -= 1;
                    start += 1;
                }
            }
        }

        // NODOTS fallback: single-label queries can use NODOTS servers.
        // Apply only if no match was found (or the best match is the catch-all).
        if nodots && !self.entries.is_empty() {
            let last = &self.entries[n - 1];
            if last.flags & SERV_FOR_NODOTS != 0
                && (!found || self.entries[nlow].domain_len == 0)
            {
                if let Some((nl, nh)) = self.filter_servers_impl(n - 1, flags) {
                    nlow = nl;
                    nhigh = nh;
                    found = true;
                }
            }
        }

        if found {
            Some((nlow, nhigh))
        } else {
            None
        }
    }

    /// Narrow an initial seed index to the best `[nlow, nhigh)` range for `flags`.
    ///
    /// Expands `seed` to cover all entries with the same domain, then narrows
    /// based on query flags in C priority order.
    ///
    /// Returns `None` if no entry in the group is suitable for `flags`.
    pub fn filter_servers(&self, seed: usize, flags: u32) -> Option<(usize, usize)> {
        self.filter_servers_impl(seed, flags)
    }

    fn filter_servers_impl(&self, seed: usize, flags: u32) -> Option<(usize, usize)> {
        let n = self.entries.len();
        if seed >= n {
            return None;
        }

        // Expand [nlow, nhigh) to cover the full same-domain group.
        let mut nlow = seed;
        let mut nhigh = seed;
        while nlow > 0 && self.same_group(nlow - 1, nlow) {
            nlow -= 1;
        }
        while nhigh < n - 1 && self.same_group(nhigh, nhigh + 1) {
            nhigh += 1;
        }
        nhigh += 1; // exclusive

        if flags & F_CONFIG != 0 {
            // Just need any entry that can return an IP address.
            let has_local = (nlow..nhigh)
                .any(|i| self.entries[i].flags & SERV_LOCAL_ADDRESS != 0);
            return if has_local { Some((nlow, nhigh)) } else { None };
        }

        // Cascade through the type-flag priority.
        // Within a domain group the entries are already sorted:
        // SERV_6ADDR > SERV_4ADDR > SERV_ALL_ZEROS > SERV_LITERAL_ADDRESS > SERV_USE_RESOLV > upstream.
        let mut lo = nlow;
        let hi = nhigh;

        // IPv6 literal addresses.
        let i6 = (lo..hi)
            .find(|&i| self.entries[i].flags & SERV_6ADDR == 0)
            .unwrap_or(hi);
        if flags & F_SERVER == 0 && i6 != lo && flags & F_IPV6 != 0 {
            return Some((lo, i6));
        }
        lo = i6;

        // IPv4 literal addresses.
        let i4 = (lo..hi)
            .find(|&i| self.entries[i].flags & SERV_4ADDR == 0)
            .unwrap_or(hi);
        if flags & F_SERVER == 0 && i4 != lo && flags & F_IPV4 != 0 {
            return Some((lo, i4));
        }
        lo = i4;

        // All-zeros (return 0.0.0.0 / ::).
        let iz = (lo..hi)
            .find(|&i| self.entries[i].flags & SERV_ALL_ZEROS == 0)
            .unwrap_or(hi);
        if flags & F_SERVER == 0 && iz != lo && flags & (F_IPV4 | F_IPV6) != 0 {
            return Some((lo, iz));
        }
        lo = iz;

        // NXDOMAIN / NODATA literal (--local=/domain/).
        let il = (lo..hi)
            .find(|&i| self.entries[i].flags & SERV_LITERAL_ADDRESS == 0)
            .unwrap_or(hi);
        if flags & (F_DOMAINSRV | F_SERVER) == 0 && il != lo {
            return Some((lo, il));
        }
        lo = il;

        // "Use resolv.conf" servers.
        let ir = (lo..hi)
            .find(|&i| self.entries[i].flags & SERV_USE_RESOLV == 0)
            .unwrap_or(hi);
        if ir != lo {
            return Some((lo, ir));
        }
        lo = ir;

        // Remaining upstream servers.
        if lo < hi {
            // F_DOMAINSRV: reject catch-all upstream entries (domain_len == 0).
            if flags & F_DOMAINSRV != 0
                && self.entries[lo].domain_len == 0
                && self.entries[lo].flags & SERV_FOR_NODOTS == 0
            {
                return None;
            }
            return Some((lo, hi));
        }

        None
    }

    /// Find the DNSSEC server index for a key query on `keyname`.
    ///
    /// Prefers the same server used for the original query (`server_orig_idx`);
    /// falls back to the first server in the matching group.
    /// Mirrors `dnssec_server` in C.
    #[cfg(feature = "dnssec")]
    pub fn dnssec_server(
        &self,
        server_orig_idx: usize,
        keyname: &str,
        is_ds: bool,
    ) -> Option<usize> {
        let ds_flag = if is_ds { F_DS } else { 0 };
        let (first, last) = self.lookup(keyname, F_SERVER | F_DNSSECOK | ds_flag)?;
        // Prefer the same server used for the original query.
        for idx in first..last {
            if !self.entries[idx].is_local && self.entries[idx].index == server_orig_idx {
                return Some(idx);
            }
        }
        Some(first)
    }
}

// ── is_local_answer ───────────────────────────────────────────────────────────

/// Check whether the server at array position `first` returns a local answer.
///
/// Returns a bitmask of `F_IPV4`, `F_IPV6`, `F_NOERR`, or `F_NXDOMAIN` (or `0`).
/// `is_locally_known` is called (at most once) only when `first`'s entry
/// carries no address of its own and no same-domain sibling does either — it
/// should mirror upstream's `check_for_local_domain(name, now)`, i.e. "is this
/// name otherwise known from local config, DHCP, or the cache", to decide
/// NOERR (NODATA) vs NXDOMAIN. Mirrors `is_local_answer` in C.
pub fn is_local_answer(arr: &ServerArray, mut first: usize, is_locally_known: impl FnOnce() -> bool) -> u32 {
    let entry = match arr.get(first) {
        Some(e) => e,
        None => return 0,
    };
    if entry.flags & SERV_LITERAL_ADDRESS == 0 {
        return 0;
    }
    if entry.flags & SERV_4ADDR != 0 {
        return F_IPV4;
    }
    if entry.flags & SERV_6ADDR != 0 {
        return F_IPV6;
    }
    if entry.flags & SERV_ALL_ZEROS != 0 {
        return F_IPV4 | F_IPV6;
    }

    // No specific address on this entry: roll back to the first entry in the
    // same domain group and check whether it (or the local-domain check)
    // gives us grounds for NOERR instead of NXDOMAIN.
    while first > 0 && arr.same_group(first - 1, first) {
        first -= 1;
    }
    let rolled = &arr.entries[first];
    if rolled.flags & SERV_LOCAL_ADDRESS != 0 || is_locally_known() {
        F_NOERR
    } else {
        F_NXDOMAIN
    }
}

// ── make_local_answer ─────────────────────────────────────────────────────

/// Build local A/AAAA answer records for the literal-address server group
/// `[first, last)` returned by [`ServerArray::lookup`].
///
/// `servers` must be the same slice passed as `local_domains` to the
/// [`ServerArray::build`] call that produced `arr` — addresses are looked up
/// by `ServerEntry::index` into it. `flags` is the record-type bits to emit
/// (`is_local_answer`'s return value, ANDed with the query's requested
/// types) — `F_IPV4` emits an A record per entry in range, `F_IPV6` an AAAA
/// record, and both together (the `SERV_ALL_ZEROS` case) emit one of each per
/// entry. Mirrors the RR-building half of `make_local_answer()`
/// (domain-match.c:409-475); truncation and wire-level header/logging
/// plumbing are the caller's responsibility.
pub fn make_local_answer(
    arr: &ServerArray,
    servers: &[Server],
    first: usize,
    last: usize,
    flags: u32,
    name: &str,
    ttl: u32,
) -> Vec<crate::rfc1035::DnsRr> {
    use crate::rfc1035::DnsRr;

    let mut answers = Vec::new();

    if flags & F_IPV4 != 0 {
        for i in first..last {
            let Some(entry) = arr.get(i) else { continue };
            let addr4 = if entry.flags & SERV_ALL_ZEROS != 0 {
                Ipv4Addr::UNSPECIFIED
            } else {
                match servers.get(entry.index).map(|s| s.addr.ip()) {
                    Some(std::net::IpAddr::V4(ip)) => ip,
                    _ => continue,
                }
            };
            answers.push(DnsRr {
                name: name.to_string(),
                rtype: 1, // T_A
                class: 1, // C_IN
                ttl,
                rdata: addr4.octets().to_vec(),
            });
        }
    }

    if flags & F_IPV6 != 0 {
        for i in first..last {
            let Some(entry) = arr.get(i) else { continue };
            let addr6 = if entry.flags & SERV_ALL_ZEROS != 0 {
                std::net::Ipv6Addr::UNSPECIFIED
            } else {
                match servers.get(entry.index).map(|s| s.addr.ip()) {
                    Some(std::net::IpAddr::V6(ip)) => ip,
                    _ => continue,
                }
            };
            answers.push(DnsRr {
                name: name.to_string(),
                rtype: 28, // T_AAAA
                class: 1,  // C_IN
                ttl,
                rdata: addr6.octets().to_vec(),
            });
        }
    }

    answers
}

// ── Server list management ────────────────────────────────────────────────────

/// Mark all upstream servers that have `flag` set in their flags with `SERV_MARK`.
/// Clears `SERV_MARK` from all others.
///
/// Must be called before `add_update_server` to enable free-list reuse.
/// Mirrors `mark_servers(flag)` in C.
pub fn mark_servers(servers: &mut Vec<Server>, flag: u16) {
    for s in servers.iter_mut() {
        if s.flags & flag != 0 {
            s.flags |= SERV_MARK;
        } else {
            s.flags &= !SERV_MARK;
        }
    }
}

/// Remove all upstream servers that still have `SERV_MARK` set (i.e. stale entries).
/// Mirrors `cleanup_servers` in C.
pub fn cleanup_servers(servers: &mut Vec<Server>) {
    servers.retain(|s| s.flags & SERV_MARK == 0);
}

/// Add a new server or re-use a marked (stale) entry with the same domain.
///
/// If a marked upstream entry with a matching domain already exists it is
/// unmarked and updated in-place (moved to the end for ordering).  Otherwise
/// a new entry is appended.
///
/// Returns `true` on success.  Local-domain entries (`SERV_IS_LOCAL`) are
/// always appended without reuse.
/// Simplified port of `add_update_server` in C.
pub fn add_update_server(
    servers: &mut Vec<Server>,
    mut s: Server,
) -> bool {
    // Canonicalise domain: strip leading dots.
    let domain = s.domain.trim_start_matches('.').to_string();
    s.domain = domain.clone();

    let is_local = s.flags & SERV_IS_LOCAL != 0;

    if !is_local {
        // Try to reuse a marked entry with the same domain.
        if let Some(pos) = servers
            .iter()
            .position(|x| x.flags & SERV_MARK != 0 && hostname_isequal(&x.domain, &domain))
        {
            let mut reused = servers.remove(pos);
            reused.flags = s.flags & !SERV_MARK;
            reused.addr = s.addr;
            reused.source_addr = s.source_addr;
            reused.interface = s.interface;
            servers.push(reused);
            return true;
        }
    }

    servers.push(s);
    true
}

// ── Simple helper (kept for convenience) ─────────────────────────────────────

/// Returns `true` if `query_domain` equals or is a subdomain of `server_domain`.
/// An empty `server_domain` matches everything (catch-all).
pub fn domain_matches(query_domain: &str, server_domain: &str) -> bool {
    if server_domain.is_empty() {
        return true;
    }
    if hostname_isequal(query_domain, server_domain) {
        return true;
    }
    // subdomain check: query ends with ".<server_domain>"
    if query_domain.len() > server_domain.len() {
        let split = query_domain.len() - server_domain.len() - 1;
        if query_domain.as_bytes().get(split) == Some(&b'.')
            && hostname_isequal(&query_domain[split + 1..], server_domain)
        {
            return true;
        }
    }
    false
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::server::{SERV_4ADDR, SERV_6ADDR, SERV_LITERAL_ADDRESS};

    // ── Helpers ───────────────────────────────────────────────────────────────

    fn upstream(domain: &str) -> Server {
        let addr = MySockAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 1, 1, 1), 53));
        Server {
            flags: 0,
            domain: domain.to_string(),
            addr: addr.clone(),
            source_addr: addr,
            interface: String::new(),
            ifindex: 0,
            queries: 0,
            failed_queries: 0,
            nxdomain_replies: 0,
            retrys: 0,
            query_latency: 0,
            mma_latency: 0,
            forwardtime: None,
            forwardcount: 0,
            tcpfd: -1,
            serial: 0,
            arrayposn: -1,
            last_server: -1,
            #[cfg(feature = "loop")]
            uid: 0,
        }
    }

    fn local_nxdomain(domain: &str) -> Server {
        let mut s = upstream(domain);
        s.flags = SERV_LITERAL_ADDRESS;
        s
    }

    fn local_ipv4(domain: &str) -> Server {
        let mut s = upstream(domain);
        s.flags = SERV_LITERAL_ADDRESS | SERV_4ADDR;
        s
    }

    fn local_ipv6(domain: &str) -> Server {
        let mut s = upstream(domain);
        s.flags = SERV_LITERAL_ADDRESS | SERV_6ADDR;
        s
    }

    fn local_ipv4_at(domain: &str, ip: Ipv4Addr) -> Server {
        let mut s = local_ipv4(domain);
        s.addr = MySockAddr::V4(SocketAddrV4::new(ip, 0));
        s
    }

    fn local_ipv6_at(domain: &str, ip: std::net::Ipv6Addr) -> Server {
        let mut s = local_ipv6(domain);
        s.addr = MySockAddr::V6(std::net::SocketAddrV6::new(ip, 0, 0, 0));
        s
    }

    fn local_all_zeros(domain: &str) -> Server {
        let mut s = upstream(domain);
        s.flags = SERV_LITERAL_ADDRESS | SERV_ALL_ZEROS;
        s
    }

    // ── domain_matches ────────────────────────────────────────────────────────

    #[test]
    fn domain_matches_exact() {
        assert!(domain_matches("example.com", "example.com"));
    }

    #[test]
    fn domain_matches_subdomain() {
        assert!(domain_matches("sub.example.com", "example.com"));
    }

    #[test]
    fn domain_matches_catchall() {
        assert!(domain_matches("anything.at.all", ""));
    }

    #[test]
    fn domain_matches_no_partial() {
        // "notexample.com" should NOT match "example.com"
        assert!(!domain_matches("notexample.com", "example.com"));
    }

    #[test]
    fn domain_matches_case_insensitive() {
        assert!(domain_matches("SUB.Example.COM", "example.com"));
    }

    // ── ServerArray::build sort order ─────────────────────────────────────────

    #[test]
    fn build_sorts_longest_first() {
        let servers = vec![
            upstream("com"),
            upstream("example.com"),
            upstream("sub.example.com"),
        ];
        let arr = ServerArray::build(&servers, &[]);
        assert_eq!(arr.entries[0].domain, "sub.example.com");
        assert_eq!(arr.entries[1].domain, "example.com");
        assert_eq!(arr.entries[2].domain, "com");
    }

    #[test]
    fn build_catchall_sorts_last() {
        let servers = vec![upstream("example.com"), upstream("")];
        let arr = ServerArray::build(&servers, &[]);
        assert_eq!(arr.entries[0].domain, "example.com");
        assert_eq!(arr.entries[1].domain, "");
    }

    // ── ServerArray::lookup basic matching ────────────────────────────────────

    #[test]
    fn lookup_exact_match() {
        let servers = vec![upstream("example.com"), upstream("")];
        let arr = ServerArray::build(&servers, &[]);
        let result = arr.lookup("example.com", F_SERVER);
        assert!(result.is_some());
        let (lo, hi) = result.unwrap();
        assert_eq!(arr.entries[lo].domain, "example.com");
        assert!(hi > lo);
    }

    #[test]
    fn lookup_subdomain_uses_parent() {
        let servers = vec![upstream("example.com"), upstream("")];
        let arr = ServerArray::build(&servers, &[]);
        let result = arr.lookup("sub.example.com", F_SERVER);
        let (lo, _) = result.unwrap();
        assert_eq!(arr.entries[lo].domain, "example.com");
    }

    #[test]
    fn lookup_prefers_longer_match() {
        let servers = vec![
            upstream("sub.example.com"),
            upstream("example.com"),
            upstream(""),
        ];
        let arr = ServerArray::build(&servers, &[]);
        let (lo, _) = arr.lookup("sub.example.com", F_SERVER).unwrap();
        assert_eq!(arr.entries[lo].domain, "sub.example.com");
    }

    #[test]
    fn lookup_catchall_matches_anything() {
        let servers = vec![upstream("")];
        let arr = ServerArray::build(&servers, &[]);
        assert!(arr.lookup("anything.at.all", F_SERVER).is_some());
    }

    #[test]
    fn lookup_empty_array_returns_none() {
        let arr = ServerArray::build(&[], &[]);
        assert!(arr.lookup("example.com", F_SERVER).is_none());
    }

    #[test]
    fn lookup_no_match_returns_none() {
        // Only "example.com", query for "other.net" → no match.
        let servers = vec![upstream("example.com")];
        let arr = ServerArray::build(&servers, &[]);
        assert!(arr.lookup("other.net", F_SERVER).is_none());
    }

    // ── filter_servers / local answers ────────────────────────────────────────

    #[test]
    fn filter_returns_ipv4_for_ipv4_query() {
        let local_domains = vec![local_ipv4("example.com")];
        let arr = ServerArray::build(&[], &local_domains);
        let result = arr.lookup("example.com", F_IPV4);
        assert!(result.is_some());
        let (lo, _) = result.unwrap();
        assert!(arr.entries[lo].flags & SERV_4ADDR != 0);
    }

    #[test]
    fn filter_returns_ipv6_for_ipv6_query() {
        let local_domains = vec![local_ipv6("example.com")];
        let arr = ServerArray::build(&[], &local_domains);
        let result = arr.lookup("example.com", F_IPV6);
        assert!(result.is_some());
        let (lo, _) = result.unwrap();
        assert!(arr.entries[lo].flags & SERV_6ADDR != 0);
    }

    #[test]
    fn filter_nxdomain_not_returned_for_f_server() {
        // F_SERVER means "upstream only" — NXDOMAIN literal should be skipped.
        let local_domains = vec![local_nxdomain("example.com")];
        let arr = ServerArray::build(&[], &local_domains);
        let result = arr.lookup("example.com", F_SERVER);
        assert!(result.is_none());
    }

    // ── is_local_answer ───────────────────────────────────────────────────────

    #[test]
    fn is_local_answer_ipv4() {
        let local_domains = vec![local_ipv4("example.com")];
        let arr = ServerArray::build(&[], &local_domains);
        let (lo, _) = arr.lookup("example.com", F_IPV4).unwrap();
        assert_eq!(is_local_answer(&arr, lo, || false), F_IPV4);
    }

    #[test]
    fn is_local_answer_ipv6() {
        let local_domains = vec![local_ipv6("example.com")];
        let arr = ServerArray::build(&[], &local_domains);
        let (lo, _) = arr.lookup("example.com", F_IPV6).unwrap();
        assert_eq!(is_local_answer(&arr, lo, || false), F_IPV6);
    }

    #[test]
    fn is_local_answer_nxdomain() {
        let local_domains = vec![local_nxdomain("example.com")];
        let arr = ServerArray::build(&[], &local_domains);
        // NXDOMAIN literal: use flags=0 (no F_SERVER / F_DOMAINSRV / F_CONFIG).
        let (lo, _) = arr.lookup("example.com", 0).unwrap();
        // No other same-domain address entry, and the caller's local-domain
        // check reports "not locally known" — matches upstream's default
        // `--server=/example.com/` / `--address=/example.com/` behavior
        // (man page: "one or more domains with no address returns a
        // no-such-domain answer").
        assert_eq!(is_local_answer(&arr, lo, || false), F_NXDOMAIN);
    }

    #[test]
    fn is_local_answer_noerr_when_name_locally_known() {
        // Same literal-no-address entry, but the caller's local-domain check
        // (`check_for_local_domain` in the real caller) reports the name as
        // otherwise locally known (e.g. it has an MX/TXT/NAPTR record) — the
        // rollback in `is_local_answer` should answer NOERR (NODATA), not
        // NXDOMAIN (domain-match.c:396-401).
        let local_domains = vec![local_nxdomain("example.com")];
        let arr = ServerArray::build(&[], &local_domains);
        let (lo, _) = arr.lookup("example.com", 0).unwrap();
        assert_eq!(is_local_answer(&arr, lo, || true), F_NOERR);
    }

    #[test]
    fn is_local_answer_noerr_when_samegroup_has_address() {
        // A domain with both a plain "block" entry and an address entry:
        // rolling back from the block entry finds the address entry in the
        // same group (`SERV_LOCAL_ADDRESS`), which alone is enough for NOERR
        // regardless of the local-domain check.
        let local_domains = vec![local_ipv4("example.com"), local_nxdomain("example.com")];
        let arr = ServerArray::build(&[], &local_domains);
        // Query with flags=0 so filter_servers lands on the NXDOMAIN-literal
        // entry (the F_IPV4 branch requires the F_IPV4 query flag).
        let (lo, _) = arr.lookup("example.com", 0).unwrap();
        assert_eq!(is_local_answer(&arr, lo, || false), F_NOERR);
    }

    #[test]
    fn is_local_answer_not_local() {
        let servers = vec![upstream("example.com")];
        let arr = ServerArray::build(&servers, &[]);
        let (lo, _) = arr.lookup("example.com", F_SERVER).unwrap();
        assert_eq!(is_local_answer(&arr, lo, || false), 0);
    }

    // ── mark_servers / cleanup_servers / add_update_server ───────────────────

    #[test]
    fn mark_and_cleanup_removes_marked() {
        let mut servers = vec![upstream("a.com"), upstream("b.com")];
        // Mark SERV_4ADDR entries — none match here.
        mark_servers(&mut servers, SERV_4ADDR);
        // All get SERV_MARK cleared (none had SERV_4ADDR).
        cleanup_servers(&mut servers);
        assert_eq!(servers.len(), 2, "nothing should be removed");

        // Now mark everything by setting their flags first.
        servers[0].flags = SERV_4ADDR;
        mark_servers(&mut servers, SERV_4ADDR);
        cleanup_servers(&mut servers);
        assert_eq!(servers.len(), 1);
        assert_eq!(servers[0].domain, "b.com");
    }

    #[test]
    fn add_update_server_appends_new() {
        let mut servers: Vec<Server> = vec![];
        add_update_server(&mut servers, upstream("example.com"));
        assert_eq!(servers.len(), 1);
    }

    #[test]
    fn add_update_server_reuses_marked() {
        let mut servers = vec![upstream("example.com")];
        servers[0].flags = SERV_MARK;
        let mut replacement = upstream("example.com");
        replacement.flags = SERV_4ADDR;
        add_update_server(&mut servers, replacement);
        // Reused: still only one entry, now with SERV_4ADDR.
        assert_eq!(servers.len(), 1);
        assert!(servers[0].flags & SERV_4ADDR != 0);
        assert_eq!(servers[0].flags & SERV_MARK, 0);
    }

    #[test]
    fn add_update_server_strips_leading_dots() {
        let mut servers: Vec<Server> = vec![];
        let mut s = upstream(".example.com");
        s.domain = ".example.com".to_string();
        add_update_server(&mut servers, s);
        assert_eq!(servers[0].domain, "example.com");
    }

    // ── same_group ────────────────────────────────────────────────────────────

    #[test]
    fn same_group_same_domain() {
        let servers = vec![local_ipv4("example.com"), local_ipv6("example.com")];
        let arr = ServerArray::build(&[], &servers);
        // Both entries should be in the same group.
        assert!(arr.same_group(0, 1));
    }

    #[test]
    fn same_group_different_domain() {
        let servers = vec![upstream("a.com"), upstream("b.com")];
        let arr = ServerArray::build(&servers, &[]);
        assert!(!arr.same_group(0, 1));
    }

    // ── make_local_answer ─────────────────────────────────────────────────────

    #[test]
    fn make_local_answer_returns_configured_ipv4() {
        let local_domains = vec![local_ipv4_at("example.com", Ipv4Addr::new(1, 2, 3, 4))];
        let arr = ServerArray::build(&[], &local_domains);
        let (first, last) = arr.lookup("example.com", F_IPV4).unwrap();
        let answers =
            make_local_answer(&arr, &local_domains, first, last, F_IPV4, "example.com", 300);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].rtype, 1); // T_A
        assert_eq!(answers[0].class, 1); // C_IN
        assert_eq!(answers[0].ttl, 300);
        assert_eq!(answers[0].name, "example.com");
        assert_eq!(answers[0].rdata, vec![1, 2, 3, 4]);
    }

    #[test]
    fn make_local_answer_returns_configured_ipv6() {
        let ip = "::1".parse::<std::net::Ipv6Addr>().unwrap();
        let local_domains = vec![local_ipv6_at("example.com", ip)];
        let arr = ServerArray::build(&[], &local_domains);
        let (first, last) = arr.lookup("example.com", F_IPV6).unwrap();
        let answers =
            make_local_answer(&arr, &local_domains, first, last, F_IPV6, "example.com", 300);
        assert_eq!(answers.len(), 1);
        assert_eq!(answers[0].rtype, 28); // T_AAAA
        assert_eq!(answers[0].rdata, ip.octets().to_vec());
    }

    #[test]
    fn make_local_answer_all_zeros_answers_both_families() {
        let local_domains = vec![local_all_zeros("example.com")];
        let arr = ServerArray::build(&[], &local_domains);
        let (first, last) = arr.lookup("example.com", F_IPV4 | F_IPV6).unwrap();
        let answers = make_local_answer(
            &arr,
            &local_domains,
            first,
            last,
            F_IPV4 | F_IPV6,
            "example.com",
            300,
        );
        assert_eq!(answers.len(), 2);
        assert!(answers.iter().any(|a| a.rtype == 1 && a.rdata == vec![0, 0, 0, 0]));
        assert!(answers.iter().any(|a| a.rtype == 28 && a.rdata == vec![0u8; 16]));
    }

    #[test]
    fn make_local_answer_multiple_addresses_for_one_domain() {
        // `--address=/example.com/1.1.1.1 --address=/example.com/2.2.2.2`
        let local_domains = vec![
            local_ipv4_at("example.com", Ipv4Addr::new(1, 1, 1, 1)),
            local_ipv4_at("example.com", Ipv4Addr::new(2, 2, 2, 2)),
        ];
        let arr = ServerArray::build(&[], &local_domains);
        let (first, last) = arr.lookup("example.com", F_IPV4).unwrap();
        let answers =
            make_local_answer(&arr, &local_domains, first, last, F_IPV4, "example.com", 300);
        assert_eq!(answers.len(), 2);
    }

    #[test]
    fn make_local_answer_ipv6_only_query_gets_no_a_record() {
        let local_domains = vec![local_ipv6_at("example.com", "::1".parse().unwrap())];
        let arr = ServerArray::build(&[], &local_domains);
        let (first, last) = arr.lookup("example.com", F_IPV6).unwrap();
        // Caller asks only for F_IPV6 even though the group could serve more.
        let answers =
            make_local_answer(&arr, &local_domains, first, last, F_IPV6, "example.com", 300);
        assert!(answers.iter().all(|a| a.rtype == 28));
    }
}

/// Domain-to-upstream-server matching.
/// Ported from `domain-match.c`.
///
/// The C code builds a sorted array of `struct server *` ordered by
/// longest-matching domain suffix and binary-searches it.  Here we use
/// a sorted `Vec<ServerEntry>` with the same ordering semantics.

use crate::types::server::Server;

/// A single entry in the server array (mirrors the sorted `serverarray` in C).
#[derive(Debug, Clone)]
pub struct ServerEntry {
    /// Domain this server is associated with (empty = catch-all).
    pub domain: String,
    /// Index into the original server list.
    pub index:  usize,
}

/// Build and sort the server array by domain length (longest first).
/// Equivalent to `build_server_array` + qsort in `domain-match.c`.
pub fn build_server_array(servers: &[Server]) -> Vec<ServerEntry> {
    let mut arr: Vec<ServerEntry> = servers
        .iter()
        .enumerate()
        .map(|(i, s)| ServerEntry {
            domain: s.domain.clone(),
            index:  i,
        })
        .collect();

    // Sort: longest domain first; ties broken lexicographically.
    arr.sort_by(|a, b| {
        b.domain.len().cmp(&a.domain.len()).then(a.domain.cmp(&b.domain))
    });
    arr
}

/// Returns true if `query_domain` is equal to or a subdomain of `server_domain`.
/// An empty `server_domain` matches everything (catch-all).
pub fn domain_matches(query_domain: &str, server_domain: &str) -> bool {
    if server_domain.is_empty() {
        return true;
    }
    if query_domain.eq_ignore_ascii_case(server_domain) {
        return true;
    }
    // subdomain: query_domain ends with ".<server_domain>"
    let suffix = format!(".{}", server_domain);
    query_domain.to_lowercase().ends_with(&suffix.to_lowercase())
}

/// Find the best matching server entry for `query_domain`.
/// Returns the first (longest-match) entry that matches.
pub fn lookup_domain<'a>(query: &str, arr: &'a [ServerEntry]) -> Option<&'a ServerEntry> {
    // The array is sorted longest-domain-first so the first match is the best.
    arr.iter().find(|e| domain_matches(query, &e.domain))
}

/// Return the length of the longest matching server domain for statistics.
pub fn longest_match_len(query: &str, arr: &[ServerEntry]) -> usize {
    lookup_domain(query, arr)
        .map(|e| e.domain.len())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(domain: &str, idx: usize) -> ServerEntry {
        ServerEntry { domain: domain.to_string(), index: idx }
    }

    fn sorted(mut entries: Vec<ServerEntry>) -> Vec<ServerEntry> {
        entries.sort_by(|a, b| {
            b.domain.len().cmp(&a.domain.len()).then(a.domain.cmp(&b.domain))
        });
        entries
    }

    #[test]
    fn exact_match() {
        let arr = sorted(vec![entry("example.com", 0), entry("", 1)]);
        let result = lookup_domain("example.com", &arr);
        assert_eq!(result.map(|e| e.index), Some(0));
    }

    #[test]
    fn subdomain_match() {
        let arr = sorted(vec![entry("example.com", 0), entry("", 1)]);
        let result = lookup_domain("sub.example.com", &arr);
        assert_eq!(result.map(|e| e.index), Some(0));
    }

    #[test]
    fn longer_match_wins() {
        let arr = sorted(vec![
            entry("sub.example.com", 0),
            entry("example.com", 1),
            entry("", 2),
        ]);
        let result = lookup_domain("sub.example.com", &arr);
        assert_eq!(result.map(|e| e.index), Some(0));
    }

    #[test]
    fn catchall_matches_anything() {
        let arr = sorted(vec![entry("", 0)]);
        let result = lookup_domain("anything.at.all", &arr);
        assert_eq!(result.map(|e| e.index), Some(0));
    }

    #[test]
    fn no_match_empty_array() {
        let arr: Vec<ServerEntry> = vec![];
        assert!(lookup_domain("example.com", &arr).is_none());
    }

    #[test]
    fn case_insensitive() {
        let arr = sorted(vec![entry("Example.COM", 0)]);
        let result = lookup_domain("sub.example.com", &arr);
        assert_eq!(result.map(|e| e.index), Some(0));
    }
}

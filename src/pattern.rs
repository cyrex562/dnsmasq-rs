/// DNS name and glob pattern matching.
/// Ported from `pattern.c`.
///
/// The C source gates this file with `#ifdef HAVE_CONNTRACK` because it is
/// only used by the conntrack subsystem there.  In Rust the functions are
/// exposed unconditionally as standalone utilities; the conntrack-specific
/// callers are in `conntrack.rs` (gated by `#[cfg(feature = "conntrack")]`).

/// Match a value string against a glob pattern containing `*` wildcards.
/// Case-insensitive.  `*` matches zero or more characters (but NOT a dot
/// — the caller is expected to split on labels first).
///
/// Implements the O(n) algorithm from Russ Cox, "Glob Matching Can Be Simple
/// And Fast Too": <https://research.swtch.com/glob>
pub fn glob_match(value: &str, pattern: &str) -> bool {
    let v: Vec<char> = value.chars().map(|c| c.to_ascii_uppercase()).collect();
    let p: Vec<char> = pattern.chars().map(|c| c.to_ascii_uppercase()).collect();

    let mut vi = 0usize;
    let mut pi = 0usize;
    let mut next_vi = 0usize;
    let mut next_pi = 0usize;

    while vi < v.len() || pi < p.len() {
        if pi < p.len() {
            let pc = p[pi];
            if pc == '*' {
                next_pi = pi;
                pi += 1;
                next_vi = if vi < v.len() { vi + 1 } else { 0 };
                continue;
            } else if vi < v.len() && v[vi] == pc {
                pi += 1;
                vi += 1;
                continue;
            }
        }
        if next_vi != 0 {
            pi = next_pi;
            vi = next_vi;
            continue;
        }
        return false;
    }
    true
}

/// Returns true if `name` is a valid DNS name per RFC 1123.
/// - At least two labels
/// - Labels: 1–63 chars, alphanumeric or hyphen, no leading/trailing hyphen
/// - Total length 1–253 chars
/// - Final label not fully numeric and not "local"
pub fn is_valid_dns_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = name.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for (i, label) in labels.iter().enumerate() {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        for c in label.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' {
                return false;
            }
        }
        if i == labels.len() - 1 {
            if label.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
            if label.eq_ignore_ascii_case("local") {
                return false;
            }
        }
    }
    true
}

/// Returns true if `pattern` is a valid DNS name pattern.
///
/// Like `is_valid_dns_name` but allows up to two `*` wildcards per label,
/// except in the **final two labels** which must be wildcard-free.
///
/// Leading/trailing hyphens are checked against the full label string
/// (including wildcards), matching the C implementation which uses
/// `c[-1] == '-'` on the raw bytes.  This means `"api-*"` is valid
/// (last literal char before `*` is `-`, but the raw label ends with `*`,
/// not `-`), while `"api-"` remains invalid.
pub fn is_valid_dns_name_pattern(pattern: &str) -> bool {
    // Total length excluding wildcards must be 1–253.
    let non_wc_len: usize = pattern.chars().filter(|&c| c != '*').count();
    if non_wc_len == 0 || non_wc_len > 253 {
        return false;
    }
    let labels: Vec<&str> = pattern.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for (i, label) in labels.iter().enumerate() {
        let wildcard_count = label.chars().filter(|&c| c == '*').count();
        // Non-wildcard length must fit in a DNS label (≤63).
        let non_wc_label_len = label.len() - wildcard_count;
        if label.is_empty() || non_wc_label_len > 63 {
            return false;
        }
        // Check leading/trailing hyphen on the RAW label (including wildcards),
        // matching C's `*c == '-'` at label start and `c[-1] == '-'` at label end.
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        // All non-wildcard characters must be alphanumeric or hyphen.
        for c in label.chars() {
            if c != '*' && !c.is_ascii_alphanumeric() && c != '-' {
                return false;
            }
        }
        // Final two labels must be wildcard-free.
        let is_last_two = i >= labels.len() - 2;
        if is_last_two && wildcard_count > 0 {
            return false;
        }
        // At most two wildcards per label.
        if wildcard_count > 2 {
            return false;
        }
        // Final label must not be fully numeric and not "local".
        if i == labels.len() - 1 {
            let non_star: String = label.chars().filter(|&c| c != '*').collect();
            // A label with any wildcard is automatically non-numeric (wildcard is not a digit).
            if wildcard_count == 0 && non_star.chars().all(|c| c.is_ascii_digit()) {
                return false;
            }
            if non_star.eq_ignore_ascii_case("local") {
                return false;
            }
        }
    }
    true
}

/// Returns true if `name` matches `pattern`.
/// Both `name` and `pattern` must be valid (callers should validate first).
/// Labels are matched individually; `*` only matches within a label.
pub fn is_dns_name_matching_pattern(name: &str, pattern: &str) -> bool {
    let nl: Vec<&str> = name.split('.').collect();
    let pl: Vec<&str> = pattern.split('.').collect();
    if nl.len() != pl.len() {
        return false;
    }
    nl.iter().zip(pl.iter()).all(|(n, p)| glob_match(n, p))
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── glob_match ─────────────────────────────────────────────────────────────

    #[test]
    fn glob_match_exact() {
        assert!(glob_match("foo", "FOO"));
        assert!(!glob_match("foo", "bar"));
    }

    #[test]
    fn glob_match_wildcard_prefix() {
        assert!(glob_match("apiservice", "api*"));
        assert!(glob_match("api", "api*"));
        assert!(!glob_match("other", "api*"));
    }

    #[test]
    fn glob_match_wildcard_anywhere() {
        assert!(glob_match("video123", "*video*"));
        assert!(glob_match("prevideopost", "*video*"));
    }

    #[test]
    fn glob_match_empty_value() {
        assert!(glob_match("", "*"));
        assert!(!glob_match("", "a*"));
        assert!(!glob_match("", "*a"));
    }

    #[test]
    fn glob_match_multi_wildcard() {
        assert!(glob_match("abcdef", "a*c*f"));
        assert!(!glob_match("abcde",  "a*c*f"));
    }

    // ── is_valid_dns_name ──────────────────────────────────────────────────────

    #[test]
    fn is_valid_dns_name_cases() {
        assert!(is_valid_dns_name("example.com"));
        assert!(is_valid_dns_name("sub.example.com"));
        assert!(is_valid_dns_name("FOO.BAR"));
        assert!(!is_valid_dns_name("example"));          // single label
        assert!(!is_valid_dns_name("example.local"));    // pseudo-TLD
        assert!(!is_valid_dns_name("8.8.8.8"));          // all-numeric TLD
        assert!(!is_valid_dns_name("-bad.com"));         // leading hyphen
        assert!(!is_valid_dns_name("bad-.com"));         // trailing hyphen
        assert!(!is_valid_dns_name(""));                 // empty
        assert!(!is_valid_dns_name("a.b.c."));           // trailing dot
    }

    #[test]
    fn is_valid_dns_name_length_limits() {
        // 63-char label is OK
        let long_label = "a".repeat(63);
        assert!(is_valid_dns_name(&format!("{}.com", long_label)));
        // 64-char label is too long
        let too_long = "a".repeat(64);
        assert!(!is_valid_dns_name(&format!("{}.com", too_long)));
    }

    // ── is_valid_dns_name_pattern ─────────────────────────────────────────────

    #[test]
    fn is_valid_dns_name_pattern_cases() {
        assert!(is_valid_dns_name_pattern("*.example.com"));
        assert!(is_valid_dns_name_pattern("api*.example.com"));
        assert!(is_valid_dns_name_pattern("*-prod-*.example.com"));
        assert!(is_valid_dns_name_pattern("api*.*.example.com"));
        assert!(!is_valid_dns_name_pattern("*.com"));       // only one literal label
        assert!(!is_valid_dns_name_pattern("a.b.c.*"));     // wildcard in last label
        assert!(!is_valid_dns_name_pattern("a.b.*.c"));     // wildcard in second-to-last
        assert!(!is_valid_dns_name_pattern("*"));           // single label
    }

    #[test]
    fn is_valid_dns_name_pattern_hyphen_at_label_boundary() {
        // "api-*" — last RAW char is *, not -, so this must be valid (C behaviour).
        assert!(is_valid_dns_name_pattern("api-*.example.com"));
        // "*-api" — first RAW char is *, not -, so this must be valid (C behaviour).
        assert!(is_valid_dns_name_pattern("*-api.example.com"));
        // "api-" (no wildcard) — trailing hyphen in literal label → invalid.
        assert!(!is_valid_dns_name_pattern("api-.example.com"));
        // "-api" (no wildcard) — leading hyphen → invalid.
        assert!(!is_valid_dns_name_pattern("-api.example.com"));
    }

    #[test]
    fn is_valid_dns_name_pattern_too_many_wildcards() {
        // Three wildcards in a single label → invalid.
        assert!(!is_valid_dns_name_pattern("***service.example.com"));
    }

    #[test]
    fn is_valid_dns_name_pattern_plain_name_is_valid() {
        // A literal DNS name is also a valid pattern (zero wildcards).
        assert!(is_valid_dns_name_pattern("example.com"));
        assert!(is_valid_dns_name_pattern("sub.example.com"));
    }

    // ── is_dns_name_matching_pattern ─────────────────────────────────────────

    #[test]
    fn dns_name_matching_pattern() {
        assert!(is_dns_name_matching_pattern("api.example.com", "*.example.com"));
        assert!(is_dns_name_matching_pattern("video42.example.com", "video*.example.com"));
        assert!(!is_dns_name_matching_pattern("api.other.com", "*.example.com"));
        assert!(!is_dns_name_matching_pattern("deep.api.example.com", "*.example.com")); // label count mismatch
    }

    #[test]
    fn dns_name_matching_pattern_case_insensitive() {
        assert!(is_dns_name_matching_pattern("API.Example.COM", "*.example.com"));
    }

    #[test]
    fn dns_name_matching_pattern_multi_wildcard_label() {
        // "*-prod-*" should match "web-prod-us" in the same label position
        assert!(is_dns_name_matching_pattern("web-prod-us.example.com", "*-prod-*.example.com"));
        assert!(!is_dns_name_matching_pattern("web-stage-us.example.com", "*-prod-*.example.com"));
    }
}

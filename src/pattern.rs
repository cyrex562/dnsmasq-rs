/// DNS name and glob pattern matching.
/// Ported from `pattern.c` (originally `#ifdef HAVE_CONNTRACK`).

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
/// Like `is_valid_dns_name` but allows up to two `*` per label, except in
/// the final two labels.
pub fn is_valid_dns_name_pattern(pattern: &str) -> bool {
    let stripped = pattern.replace('*', "x"); // treat * as a regular char for length checks
    if stripped.is_empty() || stripped.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = pattern.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    for (i, label) in labels.iter().enumerate() {
        let wildcard_count = label.chars().filter(|&c| c == '*').count();
        let effective_len = label.len() - wildcard_count;
        if effective_len > 63 || label.is_empty() {
            return false;
        }
        let non_star: String = label.chars().filter(|&c| c != '*').collect();
        if non_star.starts_with('-') || non_star.ends_with('-') {
            return false;
        }
        for c in non_star.chars() {
            if !c.is_ascii_alphanumeric() && c != '-' {
                return false;
            }
        }
        // Final two labels must be wildcard-free
        let is_last_two = i >= labels.len() - 2;
        if is_last_two && wildcard_count > 0 {
            return false;
        }
        if wildcard_count > 2 {
            return false;
        }
        if i == labels.len() - 1 {
            if non_star.chars().all(|c| c.is_ascii_digit()) {
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
    fn is_valid_dns_name_cases() {
        assert!(is_valid_dns_name("example.com"));
        assert!(is_valid_dns_name("sub.example.com"));
        assert!(!is_valid_dns_name("example"));          // single label
        assert!(!is_valid_dns_name("example.local"));    // pseudo-TLD
        assert!(!is_valid_dns_name("8.8.8.8"));          // all-numeric TLD
        assert!(!is_valid_dns_name("-bad.com"));         // leading hyphen
    }

    #[test]
    fn is_valid_dns_name_pattern_cases() {
        assert!(is_valid_dns_name_pattern("*.example.com"));
        assert!(is_valid_dns_name_pattern("api*.example.com"));
        assert!(!is_valid_dns_name_pattern("*.com"));       // only one literal label
        assert!(!is_valid_dns_name_pattern("a.b.c.*"));     // wildcard in last label
    }

    #[test]
    fn dns_name_matching_pattern() {
        assert!(is_dns_name_matching_pattern("api.example.com", "*.example.com"));
        assert!(is_dns_name_matching_pattern("video42.example.com", "video*.example.com"));
        assert!(!is_dns_name_matching_pattern("api.other.com", "*.example.com"));
        assert!(!is_dns_name_matching_pattern("deep.api.example.com", "*.example.com")); // label count mismatch
    }
}

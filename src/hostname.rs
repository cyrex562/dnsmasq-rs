//! Hostname / domain name comparison and validation.
//! Ported from `util.c`.

use crate::dns_protocol::MAXLABEL;

/// Case-insensitive hostname comparison that does not depend on locale.
pub fn hostname_order(a: &str, b: &str) -> std::cmp::Ordering {
    let mut ai = a.chars().map(|c| c.to_ascii_lowercase());
    let mut bi = b.chars().map(|c| c.to_ascii_lowercase());
    loop {
        match (ai.next(), bi.next()) {
            (Some(ca), Some(cb)) => {
                let ord = ca.cmp(&cb);
                if ord != std::cmp::Ordering::Equal {
                    return ord;
                }
            }
            (None, None) => return std::cmp::Ordering::Equal,
            (None, _)    => return std::cmp::Ordering::Less,
            (_, None)    => return std::cmp::Ordering::Greater,
        }
    }
}

/// Case-insensitive hostname equality (locale-independent).
pub fn hostname_isequal(a: &str, b: &str) -> bool {
    a.len() == b.len() && hostname_order(a, b) == std::cmp::Ordering::Equal
}

/// Returns `Some(2)` if `b == a`, `Some(1)` if `b` is a subdomain of `a`, `None` otherwise.
pub fn hostname_issubdomain(a: &str, b: &str) -> Option<u8> {
    let a = a.to_ascii_lowercase();
    let b = b.to_ascii_lowercase();

    if b.len() < a.len() {
        return None;
    }

    // Compare from the right
    let mut ai = a.chars().rev();
    let mut bi = b.chars().rev();

    loop {
        match (ai.next(), bi.next()) {
            (None, None)          => return Some(2), // equal
            (None, Some('.'))     => return Some(1), // b is subdomain
            (None, _)             => return None,    // b is a.foo (no dot separator)
            (Some(ca), Some(cb)) if ca == cb => {}
            _                    => return None,
        }
    }
}

/// Returns true if `name` is a legal DNS hostname (first label only checked strictly).
pub fn legal_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }

    let label = name.split('.').next().unwrap_or("");
    if label.is_empty() || label.len() > MAXLABEL {
        return false;
    }

    for (i, c) in label.chars().enumerate() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' => {}
            '-' | '_' if i > 0 => {}
            _ => return false,
        }
    }
    true
}

/// Canonicalise a domain name: strip trailing dot, lowercase.
/// Returns `None` if the name is illegal.
pub fn canonicalise(input: &str) -> Option<String> {
    let s = input.trim_end_matches('.');
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    for label in s.split('.') {
        if label.is_empty() || label.len() > MAXLABEL {
            return None;
        }
    }
    Some(s.to_ascii_lowercase())
}

// ── Domain name validation (ported from util.c:137-202) ──────────────────────

/// Maximum DNS name length.
const MAXDNAME: usize = 1025;

/// Result of checking a domain name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameCheckResult {
    /// Invalid name (empty, too long, control chars, etc.).
    Invalid,
    /// Valid ASCII-only name.
    Valid,
    /// Valid name with non-ASCII characters requiring IDN encoding.
    NeedsIdn,
}

/// Validate a domain name string.
///
/// Checks: non-empty, total length ≤ MAXDNAME, labels ≤ 63 chars,
/// no control characters, not all whitespace. Non-ASCII chars return
/// `NeedsIdn`. Trailing dot is stripped.
/// Port of `check_name()` from util.c:137-202.
pub fn check_name(name: &str) -> NameCheckResult {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > MAXDNAME {
        return NameCheckResult::Invalid;
    }

    let mut has_idn = false;
    let mut has_non_space = name.ends_with('.');  // trailing dot counts as non-space input

    for label in trimmed.split('.') {
        if label.len() > MAXLABEL {
            return NameCheckResult::Invalid;
        }
        for c in label.chars() {
            if c.is_ascii_control() {
                return NameCheckResult::Invalid;
            }
            if !c.is_ascii() {
                has_idn = true;
            }
            if c != ' ' {
                has_non_space = true;
            }
        }
    }

    // Reject all-whitespace names
    if !has_non_space {
        return NameCheckResult::Invalid;
    }

    // Uppercase ASCII also suggests IDN processing might be needed
    if trimmed.chars().any(|c| c.is_ascii_uppercase()) {
        has_idn = true;
    }

    if has_idn {
        NameCheckResult::NeedsIdn
    } else {
        NameCheckResult::Valid
    }
}

/// Validate a hostname (more restricted than a domain name).
///
/// Only the first label is checked: allowed chars are a-z, A-Z, 0-9, '-', '_'.
/// Port of `legal_hostname()` from util.c:204+ (already partially ported).
pub fn check_hostname_label(name: &str) -> bool {
    let first_label = name.split('.').next().unwrap_or("");
    if first_label.is_empty() {
        return false;
    }
    first_label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostname_isequal_case_insensitive() {
        assert!(hostname_isequal("Example.COM", "example.com"));
        assert!(!hostname_isequal("example.com", "example.net"));
    }

    #[test]
    fn hostname_issubdomain_cases() {
        assert_eq!(hostname_issubdomain("example.com", "example.com"), Some(2));
        assert_eq!(hostname_issubdomain("example.com", "sub.example.com"), Some(1));
        assert_eq!(hostname_issubdomain("example.com", "other.com"), None);
        assert_eq!(hostname_issubdomain("example.com", "notexample.com"), None);
    }

    #[test]
    fn legal_hostname_valid() {
        assert!(legal_hostname("example"));
        assert!(legal_hostname("foo-bar"));
        assert!(legal_hostname("foo.bar.baz"));
    }

    #[test]
    fn legal_hostname_invalid() {
        assert!(!legal_hostname(""));
        assert!(!legal_hostname("-foo"));
        assert!(!legal_hostname("foo bar"));
    }

    #[test]
    fn canonicalise_strips_trailing_dot() {
        assert_eq!(canonicalise("example.com."), Some("example.com".to_string()));
        assert_eq!(canonicalise("EXAMPLE.COM"), Some("example.com".to_string()));
    }

    // ── check_name ───────────────────────────────────────────────────────────

    #[test]
    fn check_name_valid_simple() {
        assert_eq!(check_name("example.com"), NameCheckResult::Valid);
    }

    #[test]
    fn check_name_valid_trailing_dot() {
        // Trailing dot should be stripped; result is valid
        assert_ne!(check_name("example.com."), NameCheckResult::Invalid);
    }

    #[test]
    fn check_name_empty() {
        assert_eq!(check_name(""), NameCheckResult::Invalid);
    }

    #[test]
    fn check_name_control_char() {
        assert_eq!(check_name("bad\x01name.com"), NameCheckResult::Invalid);
    }

    #[test]
    fn check_name_label_too_long() {
        let long_label = "a".repeat(64);
        assert_eq!(check_name(&format!("{}.com", long_label)), NameCheckResult::Invalid);
    }

    #[test]
    fn check_name_label_max_ok() {
        let label = "a".repeat(63);
        assert_ne!(check_name(&format!("{}.com", label)), NameCheckResult::Invalid);
    }

    #[test]
    fn check_name_uppercase_needs_idn() {
        assert_eq!(check_name("Example.COM"), NameCheckResult::NeedsIdn);
    }

    #[test]
    fn check_name_non_ascii_needs_idn() {
        assert_eq!(check_name("münchen.de"), NameCheckResult::NeedsIdn);
    }

    #[test]
    fn check_name_all_spaces_invalid() {
        assert_eq!(check_name("   "), NameCheckResult::Invalid);
    }

    #[test]
    fn check_name_single_label() {
        assert_eq!(check_name("localhost"), NameCheckResult::Valid);
    }

    // ── check_hostname_label ─────────────────────────────────────────────────

    #[test]
    fn check_hostname_label_valid() {
        assert!(check_hostname_label("my-host_1"));
    }

    #[test]
    fn check_hostname_label_fqdn() {
        // Only checks first label
        assert!(check_hostname_label("host.example.com"));
    }

    #[test]
    fn check_hostname_label_invalid_chars() {
        assert!(!check_hostname_label("host name")); // space
        assert!(!check_hostname_label("host@name")); // @
    }

    #[test]
    fn check_hostname_label_empty() {
        assert!(!check_hostname_label(""));
    }
}

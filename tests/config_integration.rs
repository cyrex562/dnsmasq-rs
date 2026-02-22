//! Integration tests for config-file parsing and application.

use dnsmasq_rs::option::{apply_config, parse_config_text, ConfigError};
use dnsmasq_rs::types::constants::OPT_NO_RESOLV;
use dnsmasq_rs::types::daemon::Daemon;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fresh_daemon() -> Daemon {
    Daemon::default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn parse_minimal_config() {
    let text = "port=5353\n";
    let lines = parse_config_text(text, "test.conf").expect("should parse");
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].key, "port");
    assert_eq!(lines[0].value.as_deref(), Some("5353"));
}

#[test]
fn parse_full_config() {
    let text = r#"
port=5353
domain=example.local
server=8.8.8.8
no-resolv
cache-size=1500
"#;
    let lines = parse_config_text(text, "full.conf").expect("should parse");
    // 5 non-empty, non-comment lines.
    assert_eq!(lines.len(), 5);

    let keys: Vec<&str> = lines.iter().map(|l| l.key.as_str()).collect();
    assert!(keys.contains(&"port"));
    assert!(keys.contains(&"domain"));
    assert!(keys.contains(&"server"));
    assert!(keys.contains(&"no-resolv"));
    assert!(keys.contains(&"cache-size"));
}

#[test]
fn apply_config_to_daemon() {
    let text = "port=5353\nno-resolv\ncache-size=512\n";
    let lines = parse_config_text(text, "apply.conf").expect("should parse");
    let mut daemon = fresh_daemon();
    apply_config(&mut daemon, &lines).expect("should apply without error");

    assert_eq!(daemon.port, 5353, "port should be updated");
    assert!(daemon.option_bool(OPT_NO_RESOLV), "no-resolv flag should be set");
    assert_eq!(daemon.cachesize, 512, "cachesize should be updated");
}

#[test]
fn config_unknown_option_error() {
    let text = "totally-unknown-xyz=value\n";
    let lines = parse_config_text(text, "bad.conf").expect("should parse text");
    let mut daemon = fresh_daemon();
    let err = apply_config(&mut daemon, &lines).expect_err("should fail on unknown option");
    assert!(
        matches!(err, ConfigError::UnknownOption(ref k, _, _) if k == "totally-unknown-xyz"),
        "expected UnknownOption, got {:?}",
        err
    );
}

#[test]
fn config_comment_lines_skipped() {
    let text = r#"
# This is a comment
port=5353
# another comment
no-resolv
"#;
    let lines = parse_config_text(text, "comments.conf").expect("should parse");
    // Only the two non-comment, non-empty lines.
    assert_eq!(lines.len(), 2);
    assert!(lines.iter().all(|l| !l.key.starts_with('#')));
}

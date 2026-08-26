//! YAML-format configuration file support (`--conf-file=*.yaml`/`*.yml`).
//!
//! This does not introduce a second config-application pipeline: it only
//! ever produces the same [`ConfigLine`] list `option.rs`'s text
//! `key=value` parser does, in the same flat directive-name space, so
//! `resolve_config`/`apply_line`/`normalize_config` are reused unchanged.
//! A YAML scalar (`port: 5353`) becomes one directive; a YAML sequence
//! (`server: ["8.8.8.8", "1.1.1.1"]`) becomes one directive per element,
//! matching how a repeatable text directive appears on multiple
//! `key=value` lines; a bare `true`/null value becomes a flag with no
//! value (`no-resolv: true`); `false` omits the directive entirely, the
//! same as a boolean flag's absence in a text config.
#![cfg(feature = "yaml-config")]

use crate::option::{ConfigError, ConfigLine};

const MAX_DEPTH: usize = 10;

/// True when `path`'s extension (case-insensitive) is `.yaml` or `.yml`.
pub fn is_yaml_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".yaml") || lower.ends_with(".yml")
}

/// Parse YAML config text into the same [`ConfigLine`] list the text
/// `key=value` parser produces.
pub fn parse_yaml_config_text(text: &str, filename: &str) -> Result<Vec<ConfigLine>, ConfigError> {
    parse_yaml_config_text_depth(text, filename, 0)
}

fn invalid(filename: &str, key: &str, val: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidValue(val.to_string(), key.to_string(), filename.to_string(), 0, reason.into())
}

fn parse_yaml_config_text_depth(
    text: &str,
    filename: &str,
    depth: usize,
) -> Result<Vec<ConfigLine>, ConfigError> {
    let doc: serde_norway::Value = serde_norway::from_str(text)
        .map_err(|e| invalid(filename, "<yaml>", "", format!("YAML parse error: {e}")))?;

    let mapping = match doc {
        serde_norway::Value::Mapping(m) => m,
        serde_norway::Value::Null => return Ok(Vec::new()), // empty document
        _ => return Err(invalid(filename, "<yaml>", "", "top-level YAML document must be a mapping")),
    };

    let mut lines = Vec::new();
    for (k, v) in mapping {
        let serde_norway::Value::String(key) = k else {
            return Err(invalid(filename, "<yaml>", "", "YAML mapping keys must be strings"));
        };

        if key == "conf-file" {
            for included in yaml_value_to_strings(&v, &key, filename)? {
                if depth >= MAX_DEPTH {
                    return Err(invalid(filename, &key, &included, "maximum conf-file inclusion depth exceeded"));
                }
                lines.extend(load_included_conf_file(&included, depth + 1)?);
            }
            continue;
        }

        push_value_as_lines(&mut lines, &key, v, filename)?;
    }

    Ok(lines)
}

/// Load and parse a file named by a YAML `conf-file` directive, dispatching
/// by extension exactly like the top-level loader does: another YAML file
/// recurses back into this module, anything else falls back to the text
/// `key=value` parser when `legacy-config` is compiled in.
fn load_included_conf_file(path: &str, depth: usize) -> Result<Vec<ConfigLine>, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
    if is_yaml_path(path) {
        return parse_yaml_config_text_depth(&text, path, depth);
    }
    #[cfg(feature = "legacy-config")]
    {
        crate::option::parse_config_text(&text, path)
    }
    #[cfg(not(feature = "legacy-config"))]
    {
        Err(invalid(
            path,
            "conf-file",
            path,
            "legacy conf-file format support is not compiled in (legacy-config feature disabled)",
        ))
    }
}

/// Convert a single directive's YAML value into zero or more [`ConfigLine`]s.
fn push_value_as_lines(
    lines: &mut Vec<ConfigLine>,
    key: &str,
    value: serde_norway::Value,
    filename: &str,
) -> Result<(), ConfigError> {
    match value {
        // A bare flag: `key: true` or `key:` (parsed as null).
        serde_norway::Value::Bool(true) | serde_norway::Value::Null => {
            lines.push(ConfigLine { key: key.to_string(), value: None, file: filename.to_string(), line: 0 });
        }
        // `key: false` omits the directive entirely, the same as a boolean
        // flag's absence in a text config.
        serde_norway::Value::Bool(false) => {}
        serde_norway::Value::Sequence(items) => {
            for item in items {
                let s = yaml_scalar_to_string(&item, key, filename)?;
                lines.push(ConfigLine { key: key.to_string(), value: Some(s), file: filename.to_string(), line: 0 });
            }
        }
        other => {
            let s = yaml_scalar_to_string(&other, key, filename)?;
            lines.push(ConfigLine { key: key.to_string(), value: Some(s), file: filename.to_string(), line: 0 });
        }
    }
    Ok(())
}

/// `conf-file` accepts either a single path or a list of paths.
fn yaml_value_to_strings(value: &serde_norway::Value, key: &str, filename: &str) -> Result<Vec<String>, ConfigError> {
    match value {
        serde_norway::Value::Sequence(items) => {
            items.iter().map(|v| yaml_scalar_to_string(v, key, filename)).collect()
        }
        other => Ok(vec![yaml_scalar_to_string(other, key, filename)?]),
    }
}

fn yaml_scalar_to_string(value: &serde_norway::Value, key: &str, filename: &str) -> Result<String, ConfigError> {
    match value {
        serde_norway::Value::String(s) => Ok(s.clone()),
        serde_norway::Value::Number(n) => Ok(n.to_string()),
        serde_norway::Value::Bool(b) => Ok(b.to_string()),
        _ => Err(invalid(filename, key, "", "expected a string, number, or boolean value")),
    }
}

/// Serialize a list of [`ConfigLine`]s into YAML text — the inverse of
/// [`parse_yaml_config_text`]. Directives repeated across multiple
/// `ConfigLine`s (matching a repeatable text directive on multiple
/// `key=value` lines) collapse into one YAML sequence each, in
/// first-occurrence order; a single occurrence becomes a scalar; a
/// value-less directive (a boolean flag) becomes `key: true`.
pub fn config_lines_to_yaml(lines: &[ConfigLine]) -> Result<String, ConfigError> {
    let mut order: Vec<String> = Vec::new();
    let mut grouped: std::collections::HashMap<String, Vec<Option<String>>> = std::collections::HashMap::new();

    for line in lines {
        grouped
            .entry(line.key.clone())
            .or_insert_with(|| {
                order.push(line.key.clone());
                Vec::new()
            })
            .push(line.value.clone());
    }

    let mut mapping = serde_norway::Mapping::new();
    for key in order {
        let values = &grouped[&key];
        let yaml_value = if values.len() == 1 {
            config_value_to_yaml(&values[0])
        } else {
            serde_norway::Value::Sequence(values.iter().map(config_value_to_yaml).collect())
        };
        mapping.insert(serde_norway::Value::String(key), yaml_value);
    }

    serde_norway::to_string(&serde_norway::Value::Mapping(mapping))
        .map_err(|e| invalid("<output>", "<yaml>", "", format!("YAML serialize error: {e}")))
}

fn config_value_to_yaml(value: &Option<String>) -> serde_norway::Value {
    match value {
        Some(s) => serde_norway::Value::String(s.clone()),
        None => serde_norway::Value::Bool(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cl(key: &str, value: Option<&str>) -> ConfigLine {
        ConfigLine { key: key.to_string(), value: value.map(str::to_string), file: "test.yaml".to_string(), line: 0 }
    }

    #[test]
    fn is_yaml_path_matches_common_extensions() {
        assert!(is_yaml_path("foo.yaml"));
        assert!(is_yaml_path("foo.yml"));
        assert!(is_yaml_path("FOO.YAML"));
        assert!(!is_yaml_path("foo.conf"));
        assert!(!is_yaml_path("foo"));
    }

    #[test]
    fn scalar_becomes_one_directive() {
        let lines = parse_yaml_config_text("port: 5353\n", "test.yaml").unwrap();
        assert_eq!(lines, vec![cl("port", Some("5353"))]);
    }

    #[test]
    fn bare_true_becomes_a_flag_with_no_value() {
        let lines = parse_yaml_config_text("no-resolv: true\n", "test.yaml").unwrap();
        assert_eq!(lines, vec![cl("no-resolv", None)]);
    }

    #[test]
    fn null_value_becomes_a_flag_with_no_value() {
        let lines = parse_yaml_config_text("no-resolv:\n", "test.yaml").unwrap();
        assert_eq!(lines, vec![cl("no-resolv", None)]);
    }

    #[test]
    fn false_value_is_omitted_entirely() {
        let lines = parse_yaml_config_text("no-resolv: false\nport: 53\n", "test.yaml").unwrap();
        assert_eq!(lines, vec![cl("port", Some("53"))]);
    }

    #[test]
    fn sequence_becomes_one_directive_per_element() {
        let lines = parse_yaml_config_text("server:\n  - \"8.8.8.8\"\n  - \"1.1.1.1#5353\"\n", "test.yaml").unwrap();
        assert_eq!(lines, vec![cl("server", Some("8.8.8.8")), cl("server", Some("1.1.1.1#5353"))]);
    }

    #[test]
    fn numeric_and_boolean_scalars_stringify() {
        let lines = parse_yaml_config_text("cache-size: 500\ndnssec: true\n", "test.yaml").unwrap();
        assert_eq!(lines, vec![cl("cache-size", Some("500")), cl("dnssec", None)]);
    }

    #[test]
    fn empty_document_yields_no_lines() {
        assert_eq!(parse_yaml_config_text("", "test.yaml").unwrap(), Vec::<ConfigLine>::new());
    }

    #[test]
    fn non_mapping_top_level_is_an_error() {
        assert!(parse_yaml_config_text("- a\n- b\n", "test.yaml").is_err());
    }

    #[test]
    fn nested_mapping_value_is_an_error() {
        let err = parse_yaml_config_text("dns:\n  port: 53\n", "test.yaml").unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
    }

    #[test]
    fn conf_file_include_recurses() {
        let dir = tempfile::tempdir().unwrap();
        let included = dir.path().join("included.yaml");
        std::fs::write(&included, "port: 9999\n").unwrap();
        let top = format!("conf-file: \"{}\"\nno-resolv: true\n", included.display());
        let lines = parse_yaml_config_text(&top, "top.yaml").unwrap();
        assert!(lines.contains(&ConfigLine {
            key: "port".to_string(), value: Some("9999".to_string()),
            file: included.to_str().unwrap().to_string(), line: 0,
        }));
        assert!(lines.iter().any(|l| l.key == "no-resolv"));
    }

    #[test]
    fn conf_file_depth_limit_is_enforced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loop.yaml");
        std::fs::write(&path, format!("conf-file: \"{}\"\n", path.display())).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        let err = parse_yaml_config_text(&text, path.to_str().unwrap()).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidValue(..)));
    }

    // ── config_lines_to_yaml ───────────────────────────────────────────────

    #[test]
    fn round_trips_scalar_and_sequence_and_flag() {
        let lines = vec![
            cl("port", Some("5353")),
            cl("no-resolv", None),
            cl("server", Some("8.8.8.8")),
            cl("server", Some("1.1.1.1")),
        ];
        let yaml = config_lines_to_yaml(&lines).unwrap();
        let round_tripped = parse_yaml_config_text(&yaml, "round-trip.yaml").unwrap();
        let stripped: Vec<(String, Option<String>)> =
            round_tripped.into_iter().map(|l| (l.key, l.value)).collect();
        assert_eq!(
            stripped,
            vec![
                ("port".to_string(), Some("5353".to_string())),
                ("no-resolv".to_string(), None),
                ("server".to_string(), Some("8.8.8.8".to_string())),
                ("server".to_string(), Some("1.1.1.1".to_string())),
            ]
        );
    }

    #[test]
    fn serialized_yaml_groups_repeated_keys_into_one_sequence() {
        let lines = vec![cl("server", Some("8.8.8.8")), cl("server", Some("1.1.1.1"))];
        let yaml = config_lines_to_yaml(&lines).unwrap();
        assert_eq!(yaml.matches("server:").count(), 1, "repeated key must appear once, as a sequence");
    }
}

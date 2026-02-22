use std::os::raw::c_char;
use std::slice;
use std::str;

static LOG_DEBUG: i32 = 7;
static LOG_ERR: i32 = 3;

macro_rules! log {
    ($($arg:tt)*) => ({
        my_syslog(LOG_DEBUG, format_args!($($arg)*).to_string().as_str());
    });
}

macro_rules! assert {
    ($cond:expr) => ({
        if !$cond {
            my_syslog(LOG_ERR, &format!("[pattern.rs:{}] Assertion failure: {}", line!(), stringify!($cond)));
        }
    });
}

extern "C" {
    fn my_syslog(level: i32, message: *const c_char);
}

#[cfg(feature = "conntrack")]
fn is_string_matching_glob_pattern(value: &str, pattern: &str) -> bool {
    assert!(value.len() > 0);
    assert!(pattern.len() > 0);

    let num_value_bytes = value.len();
    let num_pattern_bytes = pattern.len();
    let value_bytes = value.as_bytes();
    let pattern_bytes = pattern.as_bytes();

    let mut value_index = 0;
    let mut next_value_index = 0;
    let mut pattern_index = 0;
    let mut next_pattern_index = 0;

    while value_index < num_value_bytes || pattern_index < num_pattern_bytes {
        if pattern_index < num_pattern_bytes {
            let mut pattern_character = pattern_bytes[pattern_index] as char;
            if pattern_character.is_ascii_lowercase() {
                pattern_character = pattern_character.to_ascii_uppercase();
            }
            if pattern_character == '*' {
                // zero-or-more-character wildcard
                // Try to match at value_index, otherwise restart at value_index + 1 next.
                next_pattern_index = pattern_index;
                pattern_index += 1;
                if value_index < num_value_bytes {
                    next_value_index = value_index + 1;
                } else {
                    next_value_index = 0;
                }
                continue;
            } else {
                // ordinary character
                if value_index < num_value_bytes {
                    let mut value_character = value_bytes[value_index] as char;
                    if value_character.is_ascii_lowercase() {
                        value_character = value_character.to_ascii_uppercase();
                    }
                    if value_character == pattern_character {
                        pattern_index += 1;
                        value_index += 1;
                        continue;
                    }
                }
            }
        }
        if next_value_index != 0 {
            pattern_index = next_pattern_index;
            value_index = next_value_index;
            continue;
        }
        return false;
    }
    true
}

#[cfg(feature = "conntrack")]
fn is_valid_dns_name(value: &str) -> bool {
    if value.len() < 1 || value.len() > 253 {
        return false;
    }

    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return false;
    }

    for label in &labels {
        if label.len() < 1 || label.len() > 63 {
            return false;
        }

        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }

        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return false;
        }
    }

    let last_label = labels.last().unwrap();
    if last_label.chars().all(|c| c.is_digit(10)) {
        return false;
    }

    if last_label == "local" {
        return false;
    }

    true
}

fn main() {
    // Example usage
}
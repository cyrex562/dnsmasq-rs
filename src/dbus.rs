#![cfg(feature = "dbus")]

//! D-Bus interface stub for dnsmasq.
//!
//! Provides type definitions and helpers for the dnsmasq D-Bus interface
//! without requiring an active D-Bus connection.  No async code is used here.

// ─── Constants ───────────────────────────────────────────────────────────────

/// The canonical dnsmasq D-Bus interface name.
pub const DNSMASQ_DBUS_INTERFACE: &str = "uk.org.thekelleys.dnsmasq";

// ─── Types ───────────────────────────────────────────────────────────────────

/// A D-Bus argument value.
#[derive(Debug, Clone)]
pub enum DbusArg {
    String(String),
    Uint32(u32),
    Bool(bool),
}

/// A D-Bus method call.
#[derive(Debug, Clone)]
pub struct DbusMethod {
    pub interface: String,
    pub method:    String,
    pub args:      Vec<DbusArg>,
}

// ─── Functions ───────────────────────────────────────────────────────────────

/// Returns the list of D-Bus methods exposed by dnsmasq.
pub fn supported_methods() -> Vec<&'static str> {
    vec!["GetVersion", "ClearCache", "SetServers", "SetDomainServers"]
}

/// Returns `true` if `name` is one of the supported D-Bus methods.
pub fn is_supported_method(name: &str) -> bool {
    supported_methods().contains(&name)
}

/// Serialize a `DbusMethod` to a human-readable string for logging / testing.
pub fn format_method_call(method: &DbusMethod) -> String {
    let args: Vec<String> = method.args.iter().map(|a| match a {
        DbusArg::String(s) => format!("{:?}", s),
        DbusArg::Uint32(n) => n.to_string(),
        DbusArg::Bool(b)   => b.to_string(),
    }).collect();
    format!("{}.{}({})", method.interface, method.method, args.join(", "))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interface_constant() {
        assert_eq!(DNSMASQ_DBUS_INTERFACE, "uk.org.thekelleys.dnsmasq");
    }

    #[test]
    fn test_is_supported_method_known() {
        assert!(is_supported_method("GetVersion"));
        assert!(is_supported_method("ClearCache"));
        assert!(is_supported_method("SetServers"));
        assert!(is_supported_method("SetDomainServers"));
    }

    #[test]
    fn test_is_supported_method_unknown() {
        assert!(!is_supported_method("Unknown"));
        assert!(!is_supported_method(""));
    }

    #[test]
    fn test_format_method_call_non_empty() {
        let m = DbusMethod {
            interface: DNSMASQ_DBUS_INTERFACE.to_string(),
            method:    "SetServers".to_string(),
            args:      vec![DbusArg::String("8.8.8.8".to_string()), DbusArg::Uint32(53)],
        };
        let s = format_method_call(&m);
        assert!(!s.is_empty());
        assert!(s.contains("SetServers"));
        assert!(s.contains("8.8.8.8"));
    }

    #[test]
    fn test_format_method_call_no_args() {
        let m = DbusMethod {
            interface: DNSMASQ_DBUS_INTERFACE.to_string(),
            method:    "ClearCache".to_string(),
            args:      vec![],
        };
        let s = format_method_call(&m);
        assert!(s.contains("ClearCache"));
    }
}

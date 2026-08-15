//! Central error type for dnsmasq-rs.

/// All errors that can be produced by dnsmasq-rs at runtime.
#[derive(Debug, thiserror::Error)]
pub enum DnsmasqError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("dns error: {0}")]
    Dns(#[from] crate::rfc1035::DnsError),
    #[error("config error: {0}")]
    Config(#[from] crate::option::ConfigError),
    #[error("privilege drop failed: {0}")]
    PrivilegeDrop(String),
    #[error("pid file error: {0}")]
    PidFile(String),
    #[error("daemonize failed: {0}")]
    Daemonize(String),
    #[error("bind error on {0}: {1}")]
    Bind(String, String),
    /// Mutually exclusive or otherwise unusable options (upstream `EC_BADCONF`).
    #[error("bad configuration: {0}")]
    BadConfig(String),
    /// The network config names something that does not exist
    /// (upstream `EC_BADNET`).
    #[error("network error: {0}")]
    BadNet(String),
    #[error("signal error: {0}")]
    Signal(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn from_io_error() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let e = DnsmasqError::from(io_err);
        assert!(matches!(e, DnsmasqError::Io(_)));
    }

    #[test]
    fn display_io() {
        let e = DnsmasqError::Io(io::Error::new(io::ErrorKind::Other, "boom"));
        assert!(e.to_string().contains("io error"));
    }

    #[test]
    fn display_privilege_drop() {
        let e = DnsmasqError::PrivilegeDrop("not root".into());
        assert_eq!(e.to_string(), "privilege drop failed: not root");
    }

    #[test]
    fn display_pid_file() {
        let e = DnsmasqError::PidFile("cannot write".into());
        assert_eq!(e.to_string(), "pid file error: cannot write");
    }

    #[test]
    fn display_bind() {
        let e = DnsmasqError::Bind("0.0.0.0:53".into(), "permission denied".into());
        assert_eq!(e.to_string(), "bind error on 0.0.0.0:53: permission denied");
    }

    #[test]
    fn display_signal() {
        let e = DnsmasqError::Signal("SIGTERM".into());
        assert_eq!(e.to_string(), "signal error: SIGTERM");
    }

    #[test]
    fn display_dns() {
        let e = DnsmasqError::Dns(crate::rfc1035::DnsError::PacketTooShort);
        assert!(e.to_string().contains("dns error"));
    }

    #[test]
    fn display_config() {
        let inner = crate::option::ConfigError::UnknownOption(
            "bad-key".into(),
            "dnsmasq.conf".into(),
            42,
        );
        let e = DnsmasqError::Config(inner);
        assert!(e.to_string().contains("config error"));
    }
}

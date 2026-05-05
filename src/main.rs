

pub mod error;
pub mod dnsmasq;
pub mod option;

pub mod network;
pub mod netlink;
pub mod arp;

pub mod cache;
pub mod dns_protocol;
pub mod dhcp_protocol;
pub mod dhcp6_protocol;
pub mod radv_protocol;
pub mod metrics;
pub mod types;

// Phase 2 — Core utilities
pub mod rfc1035;
pub mod edns0;
pub mod rrfilter;
pub mod blockdata;
pub mod domain;
pub mod domain_match;
pub mod log;
pub mod outpacket;
pub mod pattern;
pub mod poll;
pub mod util;

// Phase 10 — DNS forwarding
pub mod hash_questions;
pub mod forward;

#[cfg(feature = "dnssec")]
pub mod crypto;

#[cfg(feature = "auth")]
pub mod auth;

#[cfg(feature = "dhcp")]
pub mod dhcp;
#[cfg(feature = "dhcp")]
pub mod dhcp_common;
#[cfg(feature = "dhcp")]
pub mod rfc2131;
#[cfg(feature = "dhcp")]
pub mod lease;

#[cfg(feature = "dhcp6")]
pub mod rfc3315;
#[cfg(feature = "dhcp6")]
pub mod radv;
#[cfg(feature = "dhcp6")]
pub mod slaac;

#[cfg(feature = "tftp")]
pub mod tftp;
#[cfg(feature = "dump")]
pub mod dump;
#[cfg(feature = "ipset")]
pub mod ipset;
#[cfg(feature = "conntrack")]
pub mod conntrack;
#[cfg(feature = "loop")]
pub mod loop_detect;

#[cfg(feature = "dhcp")]
pub mod helper;
#[cfg(feature = "inotify")]
pub mod inotify;
#[cfg(feature = "nftset")]
pub mod nftset;
#[cfg(feature = "ubus")]
pub mod ubus;

#[cfg(feature = "dnssec")]
pub mod dnssec;
#[cfg(feature = "dbus")]
pub mod dbus;
#[cfg(feature = "bpf")]
pub mod bpf;
pub mod tables;

/// Command-line arguments.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    use clap::Parser as _;
    use tokio::signal::unix::{signal, SignalKind};
    use tracing::{info, warn};

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = option::CliArgs::parse();
    let mut lines = Vec::new();
    if let Some(ref conf_path) = args.conf_file {
        let text = std::fs::read_to_string(conf_path)?;
        lines.extend(option::parse_config_text(&text, conf_path)?);
        info!("loaded config from {conf_path}");
    }
    lines.extend(option::config_lines_from_cli(&args));

    let resolved = option::resolve_config(&lines)?;
    let daemon_handle = dnsmasq::init_daemon_with(resolved.into_daemon());

    {
        let daemon = daemon_handle.read().await;
        info!("dnsmasq-rs starting on port {}", daemon.port);
    }

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;

    let (sighup_tx, mut sighup_rx) = tokio::sync::mpsc::channel::<()>(4);

    let daemon_clone = daemon_handle.clone();
    tokio::spawn(async move {
        while sighup_rx.recv().await.is_some() {
            warn!("SIGHUP: reloading configuration (stub — implement cache_reload here)");
            let _d = daemon_clone.read().await;
        }
    });

    let result = dnsmasq::run_main_loop(daemon_handle, Some(sighup_tx)).await;

    info!("dnsmasq-rs stopped ({result:?})");
    Ok(())
}

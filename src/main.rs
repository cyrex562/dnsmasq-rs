

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
#[derive(clap::Parser, Debug)]
#[command(name = "dnsmasq-rs", version, about = "A Rust port of dnsmasq")]
struct Args {
    /// Path to the configuration file.
    #[arg(long = "conf-file", value_name = "FILE")]
    conf_file: Option<String>,

    /// DNS port to listen on (overrides config file).
    #[arg(long, value_name = "PORT")]
    port: Option<u16>,

    /// Print version and exit.
    #[arg(long, action = clap::ArgAction::Version)]
    version: (),
}

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

    let args = Args::parse();

    let daemon_handle = dnsmasq::init_daemon();

    // Apply config file if given.
    if let Some(ref conf_path) = args.conf_file {
        let text = std::fs::read_to_string(conf_path)?;
        let lines = option::parse_config_text(&text, conf_path)?;
        let mut daemon = daemon_handle.write().await;
        option::apply_config(&mut daemon, &lines)?;
        info!("loaded config from {conf_path}");
    }

    // CLI port overrides config file.
    if let Some(port) = args.port {
        daemon_handle.write().await.port = port;
    }

    {
        let daemon = daemon_handle.read().await;
        info!("dnsmasq-rs starting on port {}", daemon.port);
    }

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sighup = signal(SignalKind::hangup())?;

    loop {
        tokio::select! {
            _ = sigterm.recv() => {
                info!("received SIGTERM — shutting down");
                break;
            }
            _ = sighup.recv() => {
                warn!("received SIGHUP — reloading logs");
                // Placeholder: a full implementation would re-open log files here.
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received SIGINT — shutting down");
                break;
            }
        }
    }

    info!("dnsmasq-rs stopped");
    Ok(())
}

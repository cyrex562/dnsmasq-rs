

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

use dnsmasq::{Listeners, StartupPipe};
use types::constants::{OPT_DEBUG, OPT_NO_FORK};
use types::daemon::Daemon;

/// Process startup, in the order `dnsmasq.c`'s `main()` uses (lines 499-826):
///
/// ```text
/// resolve user=/group=  →  bind listeners  →  chdir("/")  →  fork/setsid/fork
///   →  write pid file   →  stdio to /dev/null  →  drop privileges  →  event loop
/// ```
///
/// This deliberately is **not** `#[tokio::main]`.  That macro starts the
/// runtime — and its worker threads — before the body runs, and `fork()` in a
/// multi-threaded process gives the child only the calling thread, so a forked
/// reactor deadlocks.  Everything above needs to happen while the process is
/// still single-threaded; only then is the runtime built by hand.
///
/// Binding before forking is upstream's order too (dnsmasq.c:325-409), and it
/// is what lets the daemon claim port 53 while it is still root and still
/// report a bind failure on the terminal the user typed into.
fn main() -> std::process::ExitCode {
    match start() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        // Upstream's `die()`: one line on stderr, non-zero status.  Rust's
        // default `Result`-returning `main` would print the Debug form instead.
        Err(e) => {
            eprintln!("dnsmasq-rs: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn start() -> Result<(), Box<dyn std::error::Error>> {
    use clap::Parser as _;
    use tracing::info;

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

    let daemon = option::resolve_config(&lines)?.into_daemon();
    let debug = daemon.option_bool(OPT_DEBUG);

    // Resolve names to ids first: an unknown user is fatal, and we want to say
    // so on the terminal rather than into /dev/null after the fork.
    let run_as = dnsmasq::resolve_run_as(&daemon)?;
    let caps = dnsmasq::needed_capabilities(&daemon);
    let listeners = dnsmasq::bind_listeners(&daemon)?;

    info!("dnsmasq-rs starting on port {}", daemon.port);

    // `-d`/`--no-daemon` (OPT_DEBUG) skips this entire block: no chdir, no
    // fork, no pid file, no stdio redirect and no privilege drop.
    // `-k`/`--keep-in-foreground` (OPT_NO_FORK) skips only the fork.
    let mut startup = StartupPipe::disabled();
    if !debug {
        dnsmasq::chdir_root()?;
        if !daemon.option_bool(OPT_NO_FORK) {
            startup = dnsmasq::fork_into_background()?;
        }
        // Past this point we may have no terminal, so failures are reported
        // through `startup` instead of returned.
        if let Err(e) = write_pid_file_if_configured(&daemon, &run_as) {
            startup.fail(&e.to_string());
        }
        if let Err(e) = dnsmasq::redirect_stdio_to_devnull() {
            startup.fail(&e.to_string());
        }
        if nix::unistd::getuid().is_root() {
            if let Err(e) = dnsmasq::drop_privileges_with(&run_as, caps) {
                startup.fail(&e.to_string());
            }
        }
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => startup.fail(&format!("cannot start the async runtime: {e}")),
    };

    // Startup is complete: release the process the user invoked.
    startup.ready();

    runtime.block_on(run(daemon, listeners));
    Ok(())
}

/// Write the pid file, if one was configured (dnsmasq.c:658-717).
///
/// The file is chowned to the run user while we are still root, and a failure
/// is only fatal when we *are* root — upstream silently tolerates an unwritable
/// pid file for the unprivileged "just testing it" case.
fn write_pid_file_if_configured(
    daemon: &Daemon,
    run_as: &dnsmasq::RunAs,
) -> Result<(), error::DnsmasqError> {
    let Some(runfile) = daemon.runfile.as_deref() else {
        return Ok(());
    };

    let root = nix::unistd::getuid().is_root();
    // "if (getuid() == 0 && ent_pw && ent_pw->pw_uid != 0)" — dnsmasq.c:697.
    let owner = match (root, run_as.uid, run_as.gid) {
        (true, Some(uid), Some(gid)) if uid != 0 => Some((uid, gid)),
        _ => None,
    };

    match dnsmasq::write_pid_file_as(runfile, std::process::id(), owner) {
        Ok(()) => Ok(()),
        Err(e) if root => Err(e),
        Err(e) => {
            tracing::warn!("{e} (ignored: not running as root)");
            Ok(())
        }
    }
}

/// The async half of startup: everything that needs the tokio runtime.
async fn run(daemon: Daemon, listeners: Listeners) {
    use tracing::{info, warn};

    let daemon_handle = dnsmasq::init_daemon_with(daemon);

    let (sighup_tx, mut sighup_rx) = tokio::sync::mpsc::channel::<()>(4);
    let daemon_clone = daemon_handle.clone();
    tokio::spawn(async move {
        while sighup_rx.recv().await.is_some() {
            warn!("SIGHUP: reloading configuration (stub — implement cache_reload here)");
            let _d = daemon_clone.read().await;
        }
    });

    let result =
        dnsmasq::run_main_loop_with(daemon_handle, Some(sighup_tx), Some(listeners)).await;

    info!("dnsmasq-rs stopped ({result:?})");
}

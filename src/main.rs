

pub mod error;
pub mod dnsmasq;
pub mod option;
pub mod yaml_config;

pub mod network;
pub mod netlink;
pub mod arp;
pub mod cmsg;

pub mod cache;
pub mod dns_protocol;
pub mod dhcp_protocol;
pub mod dhcp6_protocol;
pub mod radv_protocol;
pub mod metrics;
pub mod types;

// Phase 2 — Core utilities
pub mod byte_cursor;
pub mod rfc1035;
pub mod edns0;
pub mod rrfilter;
pub mod domain;
pub mod domain_match;
pub mod hostname;
pub mod log;
pub mod pattern;
pub mod poll;
pub mod sys;
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
pub mod dhcp6;
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

#[cfg(all(feature = "dhcp", feature = "script"))]
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

/// True when `path`'s extension (case-insensitive) is `.yaml` or `.yml`.
fn has_yaml_extension(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".yaml") || lower.ends_with(".yml")
}

/// Load a top-level `--conf-file`, dispatching by extension: `.yaml`/`.yml`
/// goes to [`yaml_config::parse_yaml_config_text`] (when built with
/// `yaml-config`), anything else to the legacy `key=value`
/// [`option::parse_config_text`] (when built with `legacy-config`).
fn load_top_level_conf_file(path: &str) -> Result<Vec<option::ConfigLine>, error::DnsmasqError> {
    #[cfg_attr(not(any(feature = "yaml-config", feature = "legacy-config")), allow(unused_variables))]
    let text = std::fs::read_to_string(path)?;

    if has_yaml_extension(path) {
        #[cfg(feature = "yaml-config")]
        {
            return Ok(yaml_config::parse_yaml_config_text(&text, path)?);
        }
        #[cfg(not(feature = "yaml-config"))]
        {
            return Err(error::DnsmasqError::BadConfig(format!(
                "{path} looks like a YAML config file, but this build was compiled without the yaml-config feature"
            )));
        }
    }

    #[cfg(feature = "legacy-config")]
    {
        Ok(option::parse_config_text(&text, path)?)
    }
    #[cfg(not(feature = "legacy-config"))]
    {
        Err(error::DnsmasqError::BadConfig(format!(
            "{path} is not a YAML config file, and this build was compiled without the legacy-config feature"
        )))
    }
}

/// `--convert-config <input> <output>`: parse a legacy `key=value` config
/// file and write its directives back out as YAML, then exit without
/// starting the daemon.
#[cfg(feature = "yaml-config")]
fn convert_legacy_config_to_yaml(input: &str, output: &str) -> Result<(), error::DnsmasqError> {
    #[cfg(not(feature = "legacy-config"))]
    {
        let _ = (input, output);
        return Err(error::DnsmasqError::BadConfig(
            "cannot convert a legacy config file: this build was compiled without the legacy-config feature"
                .to_string(),
        ));
    }
    #[cfg(feature = "legacy-config")]
    {
        let text = std::fs::read_to_string(input)?;
        let lines = option::parse_config_text(&text, input)?;
        let yaml_text = yaml_config::config_lines_to_yaml(&lines)?;
        std::fs::write(output, yaml_text)?;
        println!(
            "wrote {output} ({} directive{})",
            lines.len(),
            if lines.len() == 1 { "" } else { "s" }
        );
        Ok(())
    }
}

fn start() -> Result<(), error::DnsmasqError> {
    use clap::Parser as _;
    use tracing::info;

    let args = option::CliArgs::parse();

    #[cfg(feature = "yaml-config")]
    if let Some(pair) = &args.convert_config {
        let [input, output] = [pair[0].as_str(), pair[1].as_str()];
        return convert_legacy_config_to_yaml(input, output);
    }

    let mut lines = Vec::new();
    let conf_loaded = match args.conf_file {
        Some(ref conf_path) => {
            lines.extend(load_top_level_conf_file(conf_path)?);
            Some(conf_path.clone())
        }
        None => None,
    };
    lines.extend(option::config_lines_from_cli(&args));

    let daemon = option::resolve_config(&lines)?.into_daemon();
    let debug = daemon.option_bool(OPT_DEBUG);

    // Open the log before anything worth logging happens.  Upstream calls
    // `log_start()` later — dnsmasq.c:717, after the fork — but it can afford
    // to, because everything before that point reports through `die()` on a
    // terminal that still exists.  Opening it here costs nothing (the fd is
    // inherited across the fork) and means bind failures are logged too.
    //
    // `echo_stderr` follows `option_bool(OPT_DEBUG)` (log.c), so `-d` keeps
    // talking to the terminal even when `log-facility` points at a file.
    let log_path = daemon.log_file.as_deref().map(std::path::Path::new);
    let log_debug = daemon.option_bool(types::constants::OPT_LOG_DEBUG);
    // `daemon->log_fac != -1` wins; otherwise `-d` defaults to `LOG_LOCAL0`
    // and everything else defaults to `LOG_DAEMON` inside `log_start`
    // (log.c:64-69).
    let log_fac = if let Some(fac) = daemon.log_fac {
        Some(fac as u32)
    } else if debug {
        Some(log::LOG_LOCAL0)
    } else {
        None
    };
    if let Err(e) = log::log_start(log_path, log_fac, debug, log_debug, daemon.max_logs) {
        let target = daemon.log_file.as_deref().unwrap_or("");
        return Err(error::DnsmasqError::LogFile(format!("failed to open log file {target}: {e}")));
    }
    if let Some(conf_path) = conf_loaded {
        info!("loaded config from {conf_path}");
    }

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
    // "if (getuid() == 0 && ent_pw && ent_pw->pw_uid != 0 &&
    //      fchown(fd, ent_pw->pw_uid, ent_pw->pw_gid) == -1)" — dnsmasq.c:697.
    //
    // Note `pw_gid`, the run *user's* primary group, not the group the daemon
    // will run under: with `user=dnsmasq group=dip` the pid file is owned
    // `dnsmasq:dnsmasq`, because systemd matches it against the containing
    // directory's owner rather than against the daemon's runtime gid.
    let owner = match (root, run_as.uid, run_as.user_gid) {
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
    let cache = dnsmasq::build_shared_cache(&daemon_handle).await;

    let (sighup_tx, mut sighup_rx) = tokio::sync::mpsc::channel::<()>(4);
    let daemon_clone = daemon_handle.clone();
    let cache_clone = cache.clone();
    tokio::spawn(async move {
        while sighup_rx.recv().await.is_some() {
            warn!("SIGHUP: reloading configuration");
            dnsmasq::on_sighup(&daemon_clone, &cache_clone).await;
        }
    });

    let result =
        dnsmasq::run_main_loop_with(daemon_handle, Some(sighup_tx), Some(listeners), cache).await;

    info!("dnsmasq-rs stopped ({result:?})");
}

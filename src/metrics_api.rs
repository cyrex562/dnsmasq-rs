//! Prometheus-compatible metrics HTTP endpoint (`--metrics-listen=<addr:port>`).
//!
//! No upstream `dnsmasq` counterpart — new observability surface for this
//! port. See issue #173. Deliberately standalone from `web-api`/`web-ui`:
//! metrics scraping shouldn't require standing up the token/UI machinery,
//! and vice versa.
//!
//! Unauthenticated by design, matching standard Prometheus scrape practice
//! (and `/healthz`'s precedent in `web_api.rs`). This is also why no
//! per-lease detail (hostnames/MACs) is exposed here — only a lease
//! *count* — anything more sensitive stays behind `/api/v1/leases`'s
//! bearer token.
#![cfg(feature = "metrics-api")]

use axum::extract::State;
use axum::http::header;
use axum::response::IntoResponse;
use axum::{routing::get, Router};
use std::fmt::Write as _;

use crate::cache::SharedDnsCache;
use crate::dnsmasq::DaemonHandle;
use crate::metrics::{get_metric, metric_name, ALL_METRICS};

#[derive(Clone)]
struct AppState {
    daemon: DaemonHandle,
    cache:  SharedDnsCache,
    /// `None` when DHCP isn't configured/running — `dhcp_leases_current`
    /// then reports `0` rather than being omitted, so a scrape target's
    /// metric doesn't silently disappear when DHCP toggles off.
    #[cfg(feature = "dhcp")]
    leases: Option<crate::dhcp::SharedLeaseDb>,
}

fn router(state: AppState) -> Router {
    Router::new().route("/metrics", get(metrics)).with_state(state)
}

/// Serve `/metrics` on an already-bound `listener` until the returned future
/// is dropped — same cancel-safe `tokio::spawn` + `.abort()` convention as
/// every other `spawn_*_task` helper in `dnsmasq.rs`. Binding happens
/// separately in `dnsmasq::spawn_metrics_task`, synchronously, so a bad
/// `--metrics-listen` address is a startup error rather than a silently-dead
/// background task.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    daemon:   DaemonHandle,
    cache:    SharedDnsCache,
    #[cfg(feature = "dhcp")] leases: Option<crate::dhcp::SharedLeaseDb>,
) -> std::io::Result<()> {
    let state = AppState {
        daemon,
        cache,
        #[cfg(feature = "dhcp")]
        leases,
    };
    axum::serve(listener, router(state)).await
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let body = render(&state).await;
    ([(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")], body)
}

fn push_counter(out: &mut String, name: &str, help: &str, value: u64) {
    let _ = writeln!(out, "# HELP dnsmasq_{name} {help}");
    let _ = writeln!(out, "# TYPE dnsmasq_{name} counter");
    let _ = writeln!(out, "dnsmasq_{name} {value}");
}

fn push_gauge(out: &mut String, name: &str, help: &str, value: i64) {
    let _ = writeln!(out, "# HELP dnsmasq_{name} {help}");
    let _ = writeln!(out, "# TYPE dnsmasq_{name} gauge");
    let _ = writeln!(out, "dnsmasq_{name} {value}");
}

/// Escape a label value per the Prometheus text exposition format: backslash,
/// double-quote, and newline are the only characters that need it.
fn escape_label(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

/// One counter family, labeled by upstream server address, with `extract`
/// picking the field off each `Server` — used for `queries`/`failed_queries`/
/// `retrys`/`nxdomain_replies` below so each only differs in name/help/field.
fn push_per_server_counter(
    out: &mut String,
    name: &str,
    help: &str,
    servers: &[crate::types::server::Server],
    extract: impl Fn(&crate::types::server::Server) -> u32,
) {
    let _ = writeln!(out, "# HELP dnsmasq_{name} {help}");
    let _ = writeln!(out, "# TYPE dnsmasq_{name} counter");
    for serv in servers {
        let label = escape_label(&format!("{}:{}", serv.addr.ip(), serv.addr.port()));
        let _ = writeln!(out, "dnsmasq_{name}{{server=\"{label}\"}} {}", extract(serv));
    }
}

async fn render(state: &AppState) -> String {
    let mut out = String::new();

    for &m in ALL_METRICS {
        push_counter(&mut out, metric_name(m), "dnsmasq internal event counter", get_metric(m));
    }

    {
        let d = state.daemon.read().await;
        push_gauge(&mut out, "cache_size", "Configured DNS cache size limit", d.cachesize as i64);

        push_per_server_counter(&mut out, "upstream_queries", "Queries sent to this upstream server", &d.servers, |s| s.queries);
        push_per_server_counter(&mut out, "upstream_failed_queries", "Failed queries to this upstream server", &d.servers, |s| s.failed_queries);
        push_per_server_counter(&mut out, "upstream_retries", "Retried queries to this upstream server", &d.servers, |s| s.retrys);
        push_per_server_counter(&mut out, "upstream_nxdomain_replies", "NXDOMAIN replies from this upstream server", &d.servers, |s| s.nxdomain_replies);
    }

    let entries = state.cache.lock().await.len();
    push_gauge(&mut out, "cache_entries", "Current DNS cache entry count", entries as i64);

    #[cfg(feature = "dhcp")]
    {
        let count = match state.leases.as_ref() {
            Some(leases) => leases.lock().await.count() as i64,
            None => 0,
        };
        push_gauge(&mut out, "dhcp_leases_current", "Current number of active DHCP leases", count);
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_state() -> AppState {
        AppState {
            daemon: crate::dnsmasq::init_daemon_with(crate::types::daemon::Daemon::default()),
            cache:  std::sync::Arc::new(tokio::sync::Mutex::new(crate::cache::DnsCache::new(100))),
            #[cfg(feature = "dhcp")]
            leases: None,
        }
    }

    #[test]
    fn escape_label_escapes_backslash_quote_and_newline() {
        assert_eq!(escape_label("a\\b\"c\nd"), "a\\\\b\\\"c\\nd");
    }

    #[test]
    fn escape_label_leaves_plain_text_alone() {
        assert_eq!(escape_label("8.8.8.8:53"), "8.8.8.8:53");
    }

    #[tokio::test]
    async fn render_includes_every_tracked_counter() {
        let body = render(&test_state()).await;
        for &m in ALL_METRICS {
            let name = metric_name(m);
            assert!(body.contains(&format!("dnsmasq_{name} ")), "missing metric {name}\n{body}");
        }
    }

    #[tokio::test]
    async fn render_includes_cache_and_lease_gauges() {
        let body = render(&test_state()).await;
        assert!(body.contains("# TYPE dnsmasq_cache_size gauge"));
        assert!(body.contains("dnsmasq_cache_entries 0"));
        #[cfg(feature = "dhcp")]
        assert!(body.contains("dnsmasq_dhcp_leases_current 0"));
    }

    #[cfg(feature = "dhcp")]
    #[tokio::test]
    async fn render_reports_current_lease_count_when_configured() {
        let mut state = test_state();
        let mut db = crate::lease::LeaseDb::new();
        db.insert(crate::types::dhcp::DhcpLease {
            addr: std::net::Ipv4Addr::new(192, 168, 0, 5),
            ..Default::default()
        });
        state.leases = Some(std::sync::Arc::new(tokio::sync::Mutex::new(db)));
        let body = render(&state).await;
        assert!(body.contains("dnsmasq_dhcp_leases_current 1"));
    }

    #[tokio::test]
    async fn metrics_route_returns_ok_and_text_content_type() {
        use tower::ServiceExt;
        let app = router(test_state());
        let response = app
            .oneshot(axum::http::Request::builder().uri("/metrics").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let content_type = response.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
        assert!(content_type.starts_with("text/plain"));
    }

    #[tokio::test]
    async fn unknown_route_is_404_with_no_auth_required() {
        use tower::ServiceExt;
        let app = router(test_state());
        let response = app
            .oneshot(axum::http::Request::builder().uri("/nope").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::NOT_FOUND);
    }
}

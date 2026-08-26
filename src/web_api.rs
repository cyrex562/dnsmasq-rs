//! Read-only HTTP status/diagnostics API (`--web-api-listen=<addr:port>`).
//!
//! No upstream `dnsmasq` counterpart — this is new management surface for
//! this port, not a C-to-Rust translation. See issue #165 for scope: every
//! route here is read-only; there is no authentication yet (issue #166), so
//! nothing that changes daemon state is exposed. `/api/v1/leases` is
//! deliberately absent too — `LeaseDb` has no shared handle outside
//! `run_dhcp_loop`'s own task yet (issue #168).
#![cfg(feature = "web-api")]

use std::time::Instant;

use axum::{extract::State, routing::get, Json, Router};
use serde::Serialize;

use crate::cache::SharedDnsCache;
use crate::dnsmasq::DaemonHandle;
use crate::metrics::{get_metric, Metric};

/// Shared state every handler needs. Cloned per-request by axum (cheap:
/// `DaemonHandle`/`SharedDnsCache` are `Arc`s and `Instant` is `Copy`).
#[derive(Clone)]
struct AppState {
    daemon: DaemonHandle,
    cache: SharedDnsCache,
    started_at: Instant,
}

/// Build the router. Split out from [`serve`] so tests can exercise routes
/// directly (via `tower::ServiceExt::oneshot`) without binding a real socket.
fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/api/v1/status", get(status))
        .route("/api/v1/cache/stats", get(cache_stats))
        .route("/api/v1/config", get(config_summary))
        .with_state(state)
}

/// Serve the API on an already-bound `listener` until the returned future is
/// dropped (cancel-safe: callers `tokio::spawn` this and `.abort()` it,
/// matching every other subsystem's shutdown convention — see
/// `dnsmasq.rs`'s `spawn_*_task` helpers). Binding happens separately in
/// `dnsmasq::spawn_web_api_task`, synchronously, so a bad `--web-api-listen`
/// address is a startup error rather than a silently-dead background task —
/// matching how `bind_listeners`/`adopt_or_bind` report DNS/DHCP socket
/// failures.
pub async fn serve_on(
    listener: tokio::net::TcpListener,
    daemon: DaemonHandle,
    cache: SharedDnsCache,
) -> std::io::Result<()> {
    let state = AppState { daemon, cache, started_at: Instant::now() };
    axum::serve(listener, router(state)).await
}

async fn healthz() -> &'static str {
    "ok"
}

#[derive(Serialize)]
struct StatusResponse {
    version: &'static str,
    uptime_secs: u64,
    port: u16,
    features: Vec<&'static str>,
}

/// Every feature that changes this binary's observable behavior, for
/// diagnostics — not every Cargo feature (e.g. `web-api` itself is implied
/// by this endpoint existing at all).
fn compiled_features() -> Vec<&'static str> {
    let mut features = Vec::new();
    if cfg!(feature = "dhcp") { features.push("dhcp"); }
    if cfg!(feature = "dhcp6") { features.push("dhcp6"); }
    if cfg!(feature = "dnssec") { features.push("dnssec"); }
    if cfg!(feature = "auth") { features.push("auth"); }
    if cfg!(feature = "tftp") { features.push("tftp"); }
    if cfg!(feature = "loop") { features.push("loop"); }
    if cfg!(feature = "inotify") { features.push("inotify"); }
    if cfg!(feature = "dump") { features.push("dump"); }
    if cfg!(feature = "conntrack") { features.push("conntrack"); }
    if cfg!(feature = "dbus") { features.push("dbus"); }
    if cfg!(feature = "ubus") { features.push("ubus"); }
    if cfg!(feature = "ipset") { features.push("ipset"); }
    if cfg!(feature = "nftset") { features.push("nftset"); }
    if cfg!(feature = "script") { features.push("script"); }
    if cfg!(feature = "legacy-config") { features.push("legacy-config"); }
    if cfg!(feature = "yaml-config") { features.push("yaml-config"); }
    features
}

async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    let port = state.daemon.read().await.port;
    Json(StatusResponse {
        version: env!("CARGO_PKG_VERSION"),
        uptime_secs: state.started_at.elapsed().as_secs(),
        port,
        features: compiled_features(),
    })
}

#[derive(Serialize)]
struct CacheStatsResponse {
    cache_size: i32,
    current_entries: usize,
    insertions: u64,
    evictions: u64,
    queries_forwarded: u64,
    queries_answered_locally: u64,
}

async fn cache_stats(State(state): State<AppState>) -> Json<CacheStatsResponse> {
    let cache_size = state.daemon.read().await.cachesize;
    let current_entries = state.cache.lock().await.len();
    Json(CacheStatsResponse {
        cache_size,
        current_entries,
        insertions: get_metric(Metric::DnsCacheInserted),
        evictions: get_metric(Metric::DnsCacheLiveFreed),
        queries_forwarded: get_metric(Metric::DnsQueriesForwarded),
        queries_answered_locally: get_metric(Metric::DnsLocalAnswered),
    })
}

#[derive(Serialize)]
struct ConfigSummaryResponse {
    port: u16,
    cache_size: i32,
    domain_needed: bool,
    dnssec_enabled: bool,
    server_count: usize,
}

/// A deliberately small, non-sensitive summary — no file paths, no
/// upstream-server addresses, no secrets. Grow this only with fields that
/// are safe to show over an *unauthenticated* connection; anything more
/// detailed should wait for #166.
async fn config_summary(State(state): State<AppState>) -> Json<ConfigSummaryResponse> {
    let d = state.daemon.read().await;
    Json(ConfigSummaryResponse {
        port: d.port,
        cache_size: d.cachesize,
        domain_needed: d.option_bool(crate::types::constants::OPT_NODOTS_LOCAL),
        dnssec_enabled: d.option_bool(crate::types::constants::OPT_DNSSEC_VALID),
        server_count: d.servers.len(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState {
            daemon: crate::dnsmasq::init_daemon_with(crate::types::daemon::Daemon::default()),
            cache: std::sync::Arc::new(tokio::sync::Mutex::new(crate::cache::DnsCache::new(100))),
            started_at: Instant::now(),
        }
    }

    async fn get(app: Router, uri: &str) -> (axum::http::StatusCode, serde_json::Value) {
        let response = app
            .oneshot(axum::http::Request::builder().uri(uri).body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json = if body.is_empty() { serde_json::Value::Null } else { serde_json::from_slice(&body).unwrap() };
        (status, json)
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let app = router(test_state());
        let response = app
            .oneshot(axum::http::Request::builder().uri("/healthz").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"ok");
    }

    #[tokio::test]
    async fn status_reports_version_and_port() {
        let (status_code, body) = get(router(test_state()), "/api/v1/status").await;
        assert_eq!(status_code, axum::http::StatusCode::OK);
        assert_eq!(body["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(body["port"], 53);
        assert!(body["features"].is_array());
    }

    #[tokio::test]
    async fn cache_stats_reports_zeroed_metrics_shape() {
        let (status_code, body) = get(router(test_state()), "/api/v1/cache/stats").await;
        assert_eq!(status_code, axum::http::StatusCode::OK);
        assert_eq!(body["current_entries"], 0);
        assert!(body["insertions"].is_u64());
        assert!(body["evictions"].is_u64());
    }

    #[tokio::test]
    async fn config_summary_reports_defaults() {
        let (status_code, body) = get(router(test_state()), "/api/v1/config").await;
        assert_eq!(status_code, axum::http::StatusCode::OK);
        assert_eq!(body["port"], 53);
        assert_eq!(body["server_count"], 0);
    }

    #[tokio::test]
    async fn unknown_route_is_404() {
        let (status_code, _) = get(router(test_state()), "/nope").await;
        assert_eq!(status_code, axum::http::StatusCode::NOT_FOUND);
    }
}

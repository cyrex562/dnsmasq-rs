//! HTTP status/diagnostics/control API (`--web-api-listen=<addr:port>`),
//! protected by opaque bearer tokens (`--web-api-token-file=<path>`).
//!
//! No upstream `dnsmasq` counterpart — this is new management surface for
//! this port, not a C-to-Rust translation. See issue #165 for the read-only
//! routes and issue #166 for the token auth this module adds. `/api/v1/leases`
//! is deliberately absent — `LeaseDb` has no shared handle outside
//! `run_dhcp_loop`'s own task yet (issue #168).
#![cfg(feature = "web-api")]

use std::time::Instant;

use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::{
    extract::State,
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::cache::SharedDnsCache;
use crate::dnsmasq::DaemonHandle;
use crate::metrics::{get_metric, Metric};

/// Shared state every handler needs. Cloned per-request by axum (cheap:
/// `DaemonHandle`/`SharedDnsCache` are `Arc`s, `Instant` is `Copy`, and
/// `token_file` is a short path string).
#[derive(Clone)]
struct AppState {
    daemon: DaemonHandle,
    cache: SharedDnsCache,
    started_at: Instant,
    token_file: String,
}

/// Build the router: `/healthz` is always open (liveness probes shouldn't
/// need a token, and it reveals nothing); every `/api/v1/*` route requires a
/// valid bearer token, checked before route matching so an unauthenticated
/// caller can't distinguish a wrong path from a wrong token.
fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/api/v1/status", get(status))
        .route("/api/v1/cache/stats", get(cache_stats))
        .route("/api/v1/config", get(config_summary))
        .route("/api/v1/reload", post(reload))
        .layer(middleware::from_fn_with_state(state.clone(), auth_middleware))
        .with_state(state);

    Router::new().route("/healthz", get(healthz)).merge(protected)
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
    token_file: String,
) -> std::io::Result<()> {
    let state = AppState { daemon, cache, started_at: Instant::now(), token_file };
    axum::serve(listener, router(state)).await
}

// ── Token store ──────────────────────────────────────────────────────────

/// SHA-256 hex digest of `token` — the only form ever written to or read
/// from the token file. The raw token is never stored at rest.
fn hash_token(token: &str) -> String {
    Sha256::digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

/// A fresh opaque bearer token: 32 random bytes, hex-encoded.
fn generate_token() -> String {
    let bytes: [u8; 32] = rand::random();
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Mint a new token, append its hash to `token_file` (created with mode
/// `0600` on unix if it doesn't already exist), and return the raw token —
/// the only time it is ever available in plaintext. Called from `main.rs`'s
/// `--web-api-create-token`, standalone, without the daemon running.
pub fn create_token(token_file: &str, label: &str) -> std::io::Result<String> {
    use std::io::Write;

    let token = generate_token();
    let hash = hash_token(&token);
    let created = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    // Tab-separated: hash, then a free-text label that itself can't contain
    // a tab or newline (rejected below, not escaped) so the format never
    // needs quoting.
    if label.contains('\t') || label.contains('\n') {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "label must not contain tabs or newlines"));
    }
    let line = format!("{hash}\t{label}\t{created}\n");

    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(token_file)?;
    file.write_all(line.as_bytes())?;

    Ok(token)
}

/// Check whether `presented` (the raw bearer token from a request) matches
/// any hash in `token_file`. Reads the file fresh on every call rather than
/// caching it in memory — this is a low-traffic admin API, and re-reading
/// means a token appended or a file edited to drop a compromised token takes
/// effect on the very next request, with no reload step.
fn check_token(token_file: &str, presented: &str) -> bool {
    let Ok(contents) = std::fs::read_to_string(token_file) else { return false };
    let presented_hash = hash_token(presented);
    contents.lines().any(|line| line.split('\t').next() == Some(presented_hash.as_str()))
}

async fn auth_middleware(State(state): State<AppState>, req: Request, next: Next) -> Result<Response, StatusCode> {
    let presented = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    match presented {
        Some(token) if check_token(&state.token_file, token) => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

// ── Routes ───────────────────────────────────────────────────────────────

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
/// upstream-server addresses, no secrets. This is now behind auth like
/// everything else, but there's still no reason to grow it into a full
/// config dump; add fields only as something concrete needs them.
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

/// `POST /api/v1/reload`: the same cache-flush + hosts/servers-file reload a
/// real `SIGHUP` triggers, via the existing [`crate::dnsmasq::on_sighup`] —
/// this is the first mutating route, and deliberately reuses the
/// already-tested reload path rather than a new one.
async fn reload(State(state): State<AppState>) -> StatusCode {
    crate::dnsmasq::on_sighup(&state.daemon, &state.cache).await;
    StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    fn test_state(token_file: &str) -> AppState {
        AppState {
            daemon: crate::dnsmasq::init_daemon_with(crate::types::daemon::Daemon::default()),
            cache: std::sync::Arc::new(tokio::sync::Mutex::new(crate::cache::DnsCache::new(100))),
            started_at: Instant::now(),
            token_file: token_file.to_string(),
        }
    }

    async fn request(
        app: Router,
        method: &str,
        uri: &str,
        token: Option<&str>,
    ) -> (axum::http::StatusCode, serde_json::Value) {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if let Some(t) = token {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        let response = app.oneshot(builder.body(axum::body::Body::empty()).unwrap()).await.unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json = if body.is_empty() { serde_json::Value::Null } else { serde_json::from_slice(&body).unwrap() };
        (status, json)
    }

    #[test]
    fn hash_token_is_deterministic_and_distinguishes_inputs() {
        assert_eq!(hash_token("abc"), hash_token("abc"));
        assert_ne!(hash_token("abc"), hash_token("abd"));
    }

    #[test]
    fn generate_token_produces_64_hex_chars() {
        let t = generate_token();
        assert_eq!(t.len(), 64);
        assert!(t.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn create_token_then_check_token_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let token = create_token(path.to_str().unwrap(), "test-label").unwrap();
        assert!(check_token(path.to_str().unwrap(), &token));
        assert!(!check_token(path.to_str().unwrap(), "wrong-token"));
    }

    #[test]
    fn create_token_rejects_a_label_with_a_tab() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        assert!(create_token(path.to_str().unwrap(), "bad\tlabel").is_err());
    }

    #[test]
    fn check_token_false_when_file_missing() {
        assert!(!check_token("/nonexistent/path/to/tokens", "anything"));
    }

    #[tokio::test]
    async fn healthz_needs_no_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let app = router(test_state(path.to_str().unwrap()));
        let response = app
            .oneshot(axum::http::Request::builder().uri("/healthz").body(axum::body::Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert_eq!(&body[..], b"ok");
    }

    #[tokio::test]
    async fn protected_route_without_token_is_401() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let app = router(test_state(path.to_str().unwrap()));
        let (status_code, _) = request(app, "GET", "/api/v1/status", None).await;
        assert_eq!(status_code, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn protected_route_with_wrong_token_is_401() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        create_token(path.to_str().unwrap(), "test").unwrap();
        let app = router(test_state(path.to_str().unwrap()));
        let (status_code, _) = request(app, "GET", "/api/v1/status", Some("wrong")).await;
        assert_eq!(status_code, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn protected_route_with_valid_token_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let token = create_token(path.to_str().unwrap(), "test").unwrap();
        let app = router(test_state(path.to_str().unwrap()));
        let (status_code, body) = request(app, "GET", "/api/v1/status", Some(&token)).await;
        assert_eq!(status_code, axum::http::StatusCode::OK);
        assert_eq!(body["port"], 53);
    }

    #[tokio::test]
    async fn unknown_route_without_token_is_401_not_404() {
        // An unauthenticated caller shouldn't learn whether a path exists.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let app = router(test_state(path.to_str().unwrap()));
        let (status_code, _) = request(app, "GET", "/nope", None).await;
        assert_eq!(status_code, axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_route_with_valid_token_is_404() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let token = create_token(path.to_str().unwrap(), "test").unwrap();
        let app = router(test_state(path.to_str().unwrap()));
        let (status_code, _) = request(app, "GET", "/nope", Some(&token)).await;
        assert_eq!(status_code, axum::http::StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn reload_requires_auth_and_succeeds_with_token() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let token = create_token(path.to_str().unwrap(), "test").unwrap();

        let (status_code, _) = request(router(test_state(path.to_str().unwrap())), "POST", "/api/v1/reload", None).await;
        assert_eq!(status_code, axum::http::StatusCode::UNAUTHORIZED);

        let (status_code, _) =
            request(router(test_state(path.to_str().unwrap())), "POST", "/api/v1/reload", Some(&token)).await;
        assert_eq!(status_code, axum::http::StatusCode::NO_CONTENT);
    }
}

//! Self-hosted, server-rendered web UI (`web-ui` feature, layered on
//! `web-api`) — a plain, text-focused dashboard using [htmx](https://htmx.org)
//! for partial-page updates instead of a client-side JS framework or a
//! build pipeline. No upstream `dnsmasq` counterpart.
//!
//! Served on the same `--web-api-listen` address as the JSON API (see
//! `web_api::router`) — there is no separate `--web-ui-listen`.
//!
//! Auth reuses the same bearer-token store `web_api`'s `Authorization`
//! header check does (`web_api::check_token`), just read from an `HttpOnly`,
//! `SameSite=Strict` cookie set at login instead of a header sent by an API
//! client. This is deliberately *not* a separate session-ID system: the
//! cookie holds the same opaque token `--web-api-create-token` mints, so
//! "log out" is just discarding the cookie and "revoke" is the same token
//! file edit that revokes an API client's access.
#![cfg(feature = "web-ui")]

use axum::extract::{Form, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;

use crate::web_api::{check_token, AppState};

const COOKIE_NAME: &str = "dnsmasq_token";
const HTMX_JS: &str = include_str!("../assets/htmx.min.js");

/// Build the UI's routes. `/ui/login` and the vendored htmx asset are public;
/// everything else requires the session cookie, checked before route
/// matching (same reasoning as `web_api`'s bearer-token middleware: an
/// unauthenticated visitor shouldn't learn whether a path exists).
pub(crate) fn router(state: AppState) -> Router {
    let protected = Router::new()
        .route("/ui/", get(dashboard))
        .route("/ui/fragments/status", get(status_fragment))
        .route("/ui/fragments/cache", get(cache_fragment))
        .route("/ui/reload", post(reload))
        .route("/ui/logout", post(logout))
        .route_layer(middleware::from_fn_with_state(state.clone(), ui_auth_middleware))
        .with_state(state.clone());

    Router::new()
        .route("/ui/static/htmx.min.js", get(htmx_js))
        .route("/ui/login", get(login_form).post(login_submit))
        .merge(protected)
        .with_state(state)
}

// ── Cookie helpers ───────────────────────────────────────────────────────

/// Parse the `Cookie` request header (`name1=value1; name2=value2`) for
/// `name`. No crate for this: a request has at most a handful of cookies,
/// and this UI only ever looks for one.
fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    raw.split(';').find_map(|pair| {
        let (k, v) = pair.trim().split_once('=')?;
        (k == name).then(|| v.to_string())
    })
}

/// `Set-Cookie` value that logs a session in: `HttpOnly` (not readable from
/// page JS — htmx never needs to read it, only the browser sends it back)
/// and `SameSite=Strict` (the simplest real mitigation against a mutating
/// request — `/ui/reload` — being triggered from another site). No `Secure`
/// flag: this UI is served over plain HTTP, matching `--web-api-listen`
/// having no TLS story yet.
fn session_cookie(token: &str) -> String {
    format!("{COOKIE_NAME}={token}; HttpOnly; SameSite=Strict; Path=/")
}

fn clear_cookie() -> String {
    format!("{COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
}

async fn ui_auth_middleware(
    State(state): State<AppState>,
    req: axum::extract::Request,
    next: Next,
) -> Response {
    let authed = extract_cookie(req.headers(), COOKIE_NAME)
        .is_some_and(|token| check_token(&state.token_file, &token));
    if authed {
        next.run(req).await
    } else {
        Redirect::to("/ui/login").into_response()
    }
}

// ── Page shell ───────────────────────────────────────────────────────────

const CSS: &str = "
body { font-family: ui-monospace, monospace; max-width: 48rem; margin: 2rem auto; padding: 0 1rem; }
table { border-collapse: collapse; width: 100%; }
td, th { text-align: left; padding: 0.25rem 0.75rem 0.25rem 0; }
button { font-family: inherit; padding: 0.4rem 0.8rem; cursor: pointer; }
.error { color: #b00020; }
";

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!doctype html>\n<html><head><meta charset=\"utf-8\">\n<title>{title}</title>\n\
         <script src=\"/ui/static/htmx.min.js\"></script>\n<style>{CSS}</style>\n</head>\n\
         <body>\n{body}\n</body></html>\n"
    ))
}

async fn htmx_js() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/javascript")], HTMX_JS)
}

// ── Login ────────────────────────────────────────────────────────────────

async fn login_form() -> Html<String> {
    login_page(None)
}

fn login_page(error: Option<&str>) -> Html<String> {
    let error_html = error.map(|e| format!("<p class=\"error\">{e}</p>")).unwrap_or_default();
    page(
        "dnsmasq-rs — log in",
        &format!(
            "<h1>dnsmasq-rs</h1>\n{error_html}\n\
             <form method=\"post\" action=\"/ui/login\">\n\
             <label>API token: <input type=\"password\" name=\"token\" autofocus></label>\n\
             <button type=\"submit\">Log in</button>\n</form>\n\
             <p>Mint a token on the host with <code>dnsmasq-rs --web-api-create-token=&lt;file&gt;</code>.</p>"
        ),
    )
}

#[derive(Deserialize)]
struct LoginForm {
    token: String,
}

async fn login_submit(State(state): State<AppState>, Form(form): Form<LoginForm>) -> Response {
    if check_token(&state.token_file, &form.token) {
        let mut response = Redirect::to("/ui/").into_response();
        if let Ok(value) = session_cookie(&form.token).parse() {
            response.headers_mut().insert(header::SET_COOKIE, value);
        }
        response
    } else {
        (StatusCode::UNAUTHORIZED, login_page(Some("invalid token"))).into_response()
    }
}

async fn logout() -> Response {
    let mut response = Redirect::to("/ui/login").into_response();
    if let Ok(value) = clear_cookie().parse() {
        response.headers_mut().insert(header::SET_COOKIE, value);
    }
    response
}

// ── Dashboard ────────────────────────────────────────────────────────────

async fn dashboard() -> Html<String> {
    page(
        "dnsmasq-rs — dashboard",
        "<h1>dnsmasq-rs</h1>\n\
         <form method=\"post\" action=\"/ui/logout\" style=\"float:right\"><button>Log out</button></form>\n\
         <h2>Status</h2>\n\
         <div hx-get=\"/ui/fragments/status\" hx-trigger=\"load, every 5s\" hx-swap=\"innerHTML\"></div>\n\
         <h2>Cache</h2>\n\
         <div hx-get=\"/ui/fragments/cache\" hx-trigger=\"load, every 5s\" hx-swap=\"innerHTML\"></div>\n\
         <h2>Actions</h2>\n\
         <button hx-post=\"/ui/reload\" hx-target=\"#reload-result\" hx-swap=\"innerHTML\">Reload config</button>\n\
         <span id=\"reload-result\"></span>",
    )
}

async fn status_fragment(State(state): State<AppState>) -> Html<String> {
    let d = state.daemon.read().await;
    Html(format!(
        "<table><tr><td>Version</td><td>{}</td></tr>\
         <tr><td>Uptime</td><td>{}s</td></tr>\
         <tr><td>Port</td><td>{}</td></tr></table>",
        env!("CARGO_PKG_VERSION"),
        state.started_at.elapsed().as_secs(),
        d.port,
    ))
}

async fn cache_fragment(State(state): State<AppState>) -> Html<String> {
    let cache_size = state.daemon.read().await.cachesize;
    let current_entries = state.cache.lock().await.len();
    Html(format!(
        "<table><tr><td>Configured size</td><td>{cache_size}</td></tr>\
         <tr><td>Current entries</td><td>{current_entries}</td></tr>\
         <tr><td>Insertions</td><td>{}</td></tr>\
         <tr><td>Evictions</td><td>{}</td></tr>\
         <tr><td>Forwarded</td><td>{}</td></tr>\
         <tr><td>Answered locally</td><td>{}</td></tr></table>",
        crate::metrics::get_metric(crate::metrics::Metric::DnsCacheInserted),
        crate::metrics::get_metric(crate::metrics::Metric::DnsCacheLiveFreed),
        crate::metrics::get_metric(crate::metrics::Metric::DnsQueriesForwarded),
        crate::metrics::get_metric(crate::metrics::Metric::DnsLocalAnswered),
    ))
}

async fn reload(State(state): State<AppState>) -> Html<&'static str> {
    crate::dnsmasq::on_sighup(&state.daemon, &state.cache, &state.fwd_config, &state.dhcp_reload).await;
    Html("reloaded")
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    fn test_state(token_file: &str) -> AppState {
        AppState {
            daemon: crate::dnsmasq::init_daemon_with(crate::types::daemon::Daemon::default()),
            cache: std::sync::Arc::new(tokio::sync::Mutex::new(crate::cache::DnsCache::new(100))),
            fwd_config: std::sync::Arc::new(tokio::sync::Mutex::new(crate::forward::ForwardConfig::default())),
            dhcp_reload: std::sync::Arc::new(tokio::sync::Mutex::new(crate::dnsmasq::DhcpReloadConfig::default())),
            started_at: std::time::Instant::now(),
            token_file: token_file.to_string(),
            #[cfg(feature = "dhcp")]
            leases: None,
        }
    }

    async fn request(app: Router, method: &str, uri: &str, cookie: Option<&str>) -> Response {
        let mut builder = axum::http::Request::builder().method(method).uri(uri);
        if let Some(c) = cookie {
            builder = builder.header(header::COOKIE, format!("{COOKIE_NAME}={c}"));
        }
        app.oneshot(builder.body(axum::body::Body::empty()).unwrap()).await.unwrap()
    }

    #[test]
    fn extract_cookie_finds_the_named_cookie_among_several() {
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, "foo=bar; dnsmasq_token=abc123; baz=qux".parse().unwrap());
        assert_eq!(extract_cookie(&headers, COOKIE_NAME), Some("abc123".to_string()));
    }

    #[test]
    fn extract_cookie_none_when_absent() {
        let headers = HeaderMap::new();
        assert_eq!(extract_cookie(&headers, COOKIE_NAME), None);
    }

    #[tokio::test]
    async fn login_page_is_public() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let response = request(router(test_state(path.to_str().unwrap())), "GET", "/ui/login", None).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn htmx_asset_is_public_and_nonempty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let response =
            request(router(test_state(path.to_str().unwrap())), "GET", "/ui/static/htmx.min.js", None).await;
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX).await.unwrap();
        assert!(!body.is_empty());
    }

    #[tokio::test]
    async fn dashboard_without_cookie_redirects_to_login() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let response = request(router(test_state(path.to_str().unwrap())), "GET", "/ui/", None).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(response.headers().get(header::LOCATION).unwrap(), "/ui/login");
    }

    #[tokio::test]
    async fn dashboard_with_valid_cookie_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let token = crate::web_api::create_token(path.to_str().unwrap(), "test").unwrap();
        let response = request(router(test_state(path.to_str().unwrap())), "GET", "/ui/", Some(&token)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn dashboard_with_wrong_cookie_redirects_to_login() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        crate::web_api::create_token(path.to_str().unwrap(), "test").unwrap();
        let response =
            request(router(test_state(path.to_str().unwrap())), "GET", "/ui/", Some("wrong-token")).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn login_submit_with_valid_token_sets_cookie_and_redirects() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let token = crate::web_api::create_token(path.to_str().unwrap(), "test").unwrap();
        let app = router(test_state(path.to_str().unwrap()));
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/ui/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from(format!("token={token}")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let set_cookie = response.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(set_cookie.contains(&token));
        assert!(set_cookie.contains("HttpOnly"));
    }

    #[tokio::test]
    async fn login_submit_with_wrong_token_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let app = router(test_state(path.to_str().unwrap()));
        let response = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/ui/login")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(axum::body::Body::from("token=wrong"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(header::SET_COOKIE).is_none());
    }

    #[tokio::test]
    async fn reload_via_ui_requires_cookie() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let response = request(router(test_state(path.to_str().unwrap())), "POST", "/ui/reload", None).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
    }

    #[tokio::test]
    async fn reload_via_ui_succeeds_with_cookie() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let token = crate::web_api::create_token(path.to_str().unwrap(), "test").unwrap();
        let response = request(router(test_state(path.to_str().unwrap())), "POST", "/ui/reload", Some(&token)).await;
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn logout_clears_cookie() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tokens");
        let token = crate::web_api::create_token(path.to_str().unwrap(), "test").unwrap();
        let response = request(router(test_state(path.to_str().unwrap())), "POST", "/ui/logout", Some(&token)).await;
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let set_cookie = response.headers().get(header::SET_COOKIE).unwrap().to_str().unwrap();
        assert!(set_cookie.contains("Max-Age=0"));
    }
}

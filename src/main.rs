mod auth;
mod config;
mod native;
mod routes;

use axum::{
    Router,
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use std::collections::HashMap;
use tower::ServiceBuilder;
use tower_http::{
    compression::CompressionLayer,
    services::{ServeDir, ServeFile},
    set_header::SetResponseHeaderLayer,
};

fn parse_cookies(headers: &HeaderMap) -> HashMap<String, String> {
    let mut map = HashMap::new();
    if let Some(val) = headers.get(header::COOKIE) {
        if let Ok(s) = val.to_str() {
            for pair in s.split(';') {
                let pair = pair.trim();
                if let Some((k, v)) = pair.split_once('=') {
                    map.insert(k.to_string(), v.to_string());
                }
            }
        }
    }
    map
}

async fn admin_auth_middleware(request: axum::extract::Request, next: Next) -> Response {
    let cfg = config::get();
    let cookies = parse_cookies(request.headers());
    let val = cookies
        .get(auth::SESSION_COOKIE)
        .map(|s| s.as_str())
        .unwrap_or("");
    if auth::is_authenticated(val, &cfg.admin_user, &cfg.admin_password) {
        return next.run(request).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"ok": false, "error": "authentication required"})),
    )
        .into_response()
}

async fn webmail_auth_middleware(request: axum::extract::Request, next: Next) -> Response {
    let cfg = config::get();
    let cookies = parse_cookies(request.headers());

    // Admin session grants webmail access too
    let admin_val = cookies
        .get(auth::SESSION_COOKIE)
        .map(|s| s.as_str())
        .unwrap_or("");
    if auth::is_authenticated(admin_val, &cfg.admin_user, &cfg.admin_password) {
        return next.run(request).await;
    }

    // Mailbox session
    let mb_val = cookies
        .get(auth::MAILBOX_SESSION_COOKIE)
        .map(|s| s.as_str())
        .unwrap_or("");
    if auth::mailbox_from_session(mb_val, &cfg.admin_password).is_some() {
        return next.run(request).await;
    }

    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"ok": false, "error": "authentication required"})),
    )
        .into_response()
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "akurai_mail_api=info".parse().unwrap()),
        )
        .init();

    let cfg = config::get();

    // Admin-protected API routes
    let admin_api = Router::new()
        .route("/api/status", get(routes::status))
        .route("/api/metrics", get(routes::metrics))
        .route("/api/metrics/stream", get(routes::metrics_stream))
        .route("/api/dns", get(routes::dns))
        .route("/api/domain-list", get(routes::domain_list))
        .route("/api/actions", post(routes::actions))
        .layer(middleware::from_fn(admin_auth_middleware));

    // Webmail API routes (admin or mailbox session)
    let webmail_api = Router::new()
        .route(
            "/api/webmail",
            get(routes::webmail_get).post(routes::webmail_post),
        )
        .layer(middleware::from_fn(webmail_auth_middleware));

    // Public routes (no auth)
    let public = Router::new()
        .route("/api/login", post(routes::login))
        .route("/api/logout", get(routes::logout))
        .route("/api/auth/check", get(routes::auth_check))
        .route("/api/webmail/login", post(routes::webmail_login))
        .route("/api/webmail/logout", get(routes::webmail_logout));

    // Static file serving (SvelteKit build output) with SPA fallback
    let index_path = format!("{}/index.html", cfg.static_dir);
    let immutable_dir = format!("{}/_app/immutable", cfg.static_dir);
    let immutable_service = ServeDir::new(immutable_dir).append_index_html_on_directories(false);

    let static_service = ServeDir::new(&cfg.static_dir)
        .append_index_html_on_directories(true)
        .fallback(ServeFile::new(&index_path));

    let app = Router::new()
        .merge(admin_api)
        .merge(webmail_api)
        .merge(public)
        .nest_service(
            "/_app/immutable",
            ServiceBuilder::new()
                .layer(SetResponseHeaderLayer::overriding(
                    header::CACHE_CONTROL,
                    header::HeaderValue::from_static("public, max-age=31536000, immutable"),
                ))
                .service(immutable_service),
        )
        .fallback_service(static_service)
        .layer(CompressionLayer::new());

    let listener = tokio::net::TcpListener::bind(&cfg.listen_addr)
        .await
        .unwrap();
    tracing::info!("listening on {}", cfg.listen_addr);
    axum::serve(listener, app).await.unwrap();
}

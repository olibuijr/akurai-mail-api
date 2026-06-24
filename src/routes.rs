use axum::{
    Json,
    extract::Query,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{
        IntoResponse, Redirect, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::auth;
use crate::config;
use crate::native;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

fn is_admin(headers: &HeaderMap) -> bool {
    let cookies = parse_cookies(headers);
    let val = cookies
        .get(auth::SESSION_COOKIE)
        .map(|s| s.as_str())
        .unwrap_or("");
    let cfg = config::get();
    auth::is_authenticated(val, &cfg.admin_user, &cfg.admin_password)
}

fn mailbox_email(headers: &HeaderMap) -> Option<String> {
    let cookies = parse_cookies(headers);
    let cfg = config::get();
    if is_admin(headers) {
        return None; // admin can specify email in request
    }
    let val = cookies
        .get(auth::MAILBOX_SESSION_COOKIE)
        .map(|s| s.as_str())
        .unwrap_or("");
    auth::mailbox_from_session(val, &cfg.admin_password)
}

fn json_ok(data: Value) -> Response {
    Json(data).into_response()
}

fn json_err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({"ok": false, "error": msg}))).into_response()
}

async fn native_result<F>(f: F) -> Response
where
    F: FnOnce() -> Result<Value, String> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(val)) => json_ok(val),
        Ok(Err(e)) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e),
        Err(e) => json_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            &format!("task failed: {e}"),
        ),
    }
}

// ---------------------------------------------------------------------------
// Auth routes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct LoginForm {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub next: String,
}

pub async fn login(Json(body): Json<LoginForm>) -> Response {
    let cfg = config::get();
    if !auth::validate_credentials(
        &body.email,
        &body.password,
        &cfg.admin_user,
        &cfg.admin_password,
    ) {
        return json_err(
            StatusCode::UNAUTHORIZED,
            "The email or password is incorrect.",
        );
    }
    let session = auth::session_value(&cfg.admin_user, &cfg.admin_password);
    let cookie = auth::set_cookie_header(auth::SESSION_COOKIE, &session, "/");
    let next = if body.next.starts_with('/') {
        &body.next
    } else {
        "/"
    };
    let mut resp = Json(json!({"ok": true, "next": next})).into_response();
    resp.headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

pub async fn logout(headers: HeaderMap) -> Response {
    let target = if !is_admin(&headers) && mailbox_email(&headers).is_some() {
        "/webmail/login"
    } else {
        "/login"
    };
    let c1 = auth::clear_cookie_header(auth::SESSION_COOKIE, "/");
    let c2 = auth::clear_cookie_header(auth::MAILBOX_SESSION_COOKIE, "/webmail");
    let mut resp = Redirect::to(target).into_response();
    resp.headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_str(&c1).unwrap());
    resp.headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_str(&c2).unwrap());
    resp
}

pub async fn auth_check(headers: HeaderMap) -> Response {
    let cookies = parse_cookies(&headers);
    let cfg = config::get();
    let admin = {
        let val = cookies
            .get(auth::SESSION_COOKIE)
            .map(|s| s.as_str())
            .unwrap_or("");
        auth::is_authenticated(val, &cfg.admin_user, &cfg.admin_password)
    };
    let mailbox = {
        let val = cookies
            .get(auth::MAILBOX_SESSION_COOKIE)
            .map(|s| s.as_str())
            .unwrap_or("");
        auth::mailbox_from_session(val, &cfg.admin_password)
    };
    json_ok(json!({
        "authenticated": admin,
        "mailbox": mailbox,
        "user": if admin { cfg.admin_user.clone() } else { String::new() },
    }))
}

// ---------------------------------------------------------------------------
// Admin API routes
// ---------------------------------------------------------------------------

pub async fn status() -> Response {
    native_result(native::status).await
}

pub async fn metrics() -> Response {
    native_result(native::metrics).await
}

pub async fn metrics_stream() -> impl IntoResponse {
    let stream = async_stream::stream! {
        let mut interval = tokio::time::interval(Duration::from_secs(2));
        loop {
            interval.tick().await;
            let event = match tokio::task::spawn_blocking(native::metrics).await {
                Ok(Ok(value)) => {
                    let data = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
                    Event::default().event("metrics").data(data)
                }
                Ok(Err(error)) => {
                    Event::default().event("error").data(json!({ "ok": false, "error": error }).to_string())
                }
                Err(error) => {
                    Event::default().event("error").data(json!({ "ok": false, "error": format!("task failed: {error}") }).to_string())
                }
            };
            yield Ok::<Event, Infallible>(event);
        }
    };

    let mut headers = HeaderMap::new();
    headers.insert("x-accel-buffering", HeaderValue::from_static("no"));

    (headers, Sse::new(stream).keep_alive(KeepAlive::default()))
}

pub async fn dns() -> Response {
    native_result(native::dns).await
}

pub async fn domain_list() -> Response {
    native_result(native::domain_list).await
}

#[derive(Deserialize)]
pub struct ActionBody {
    pub action: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub policy: Option<Value>,
    #[serde(default)]
    pub password: Option<String>,
}

pub async fn actions(Json(body): Json<ActionBody>) -> Response {
    match body.action.as_str() {
        "add-user" => {
            let email = body.email.unwrap_or_default();
            let password = body.password;
            native_result(move || native::add_user(&email, password.as_deref())).await
        }
        "set-password" => {
            let email = body.email.unwrap_or_default();
            let password = body.password;
            native_result(move || native::set_password(&email, password.as_deref())).await
        }
        "add-alias" => {
            let alias = body.alias.unwrap_or_default();
            let target = body.target.unwrap_or_default();
            native_result(move || native::add_alias(&alias, &target)).await
        }
        "anti-spam-config" => {
            let policy = body.policy.unwrap_or_else(|| json!({}));
            native_result(move || native::anti_spam_config(policy)).await
        }
        "anti-spam-scan" => {
            let email = body.email;
            native_result(move || native::anti_spam_scan(email.as_deref())).await
        }
        "domain-add" => {
            let domain = body.domain.unwrap_or_default();
            native_result(move || native::domain_add(&domain)).await
        }
        "domain-autopilot" => {
            let domain = body.domain.unwrap_or_default();
            native_result(move || native::domain_autopilot(&domain)).await
        }
        "domain-check" => {
            let domain = body.domain.unwrap_or_default();
            native_result(move || native::domain_check(&domain)).await
        }
        "domain-remove" => {
            let domain = body.domain.unwrap_or_default();
            native_result(move || native::domain_remove(&domain)).await
        }
        _ => json_err(StatusCode::BAD_REQUEST, "unknown action"),
    }
}

// ---------------------------------------------------------------------------
// Webmail routes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct WebmailLoginBody {
    pub email: String,
    pub password: String,
    #[serde(default)]
    pub next: String,
}

pub async fn webmail_login(Json(body): Json<WebmailLoginBody>) -> Response {
    let email = body.email.clone();
    let password = body.password.clone();
    match tokio::task::spawn_blocking(move || native::validate_login(&email, &password)).await {
        Ok(Ok(true)) => {
            let cfg = config::get();
            let session = auth::mailbox_session_value(&body.email, &cfg.admin_password);
            let cookie =
                auth::set_cookie_header(auth::MAILBOX_SESSION_COOKIE, &session, "/webmail");
            let next = if body.next.starts_with("/webmail") {
                &body.next
            } else {
                "/webmail"
            };
            let mut resp = Json(json!({"ok": true, "next": next})).into_response();
            resp.headers_mut()
                .append(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
            resp
        }
        _ => json_err(
            StatusCode::UNAUTHORIZED,
            "The email or password is incorrect.",
        ),
    }
}

pub async fn webmail_logout() -> Response {
    let cookie = auth::clear_cookie_header(auth::MAILBOX_SESSION_COOKIE, "/webmail");
    let mut resp = Redirect::to("/webmail/login").into_response();
    resp.headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

#[derive(Deserialize)]
pub struct WebmailQuery {
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub query: Option<String>,
}

pub async fn webmail_get(headers: HeaderMap, Query(q): Query<WebmailQuery>) -> Response {
    let email = resolve_webmail_email(&headers, q.email.as_deref());
    let Some(email) = email else {
        return json_err(StatusCode::BAD_REQUEST, "email is required");
    };
    let folder = q.folder.unwrap_or_else(|| "Inbox".to_string());
    let query = q.query.unwrap_or_default();
    native_result(move || native::webmail_state(&email, &folder, &query)).await
}

// Rate limiter for webmail POST
static RATE_LIMITER: std::sync::LazyLock<Mutex<HashMap<String, Vec<Instant>>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

const RATE_WINDOW_SECS: u64 = 60;
const RATE_MAX_HITS: usize = 90;

fn rate_limit(key: &str) -> bool {
    let now = Instant::now();
    let mut map = RATE_LIMITER.lock().unwrap();
    let entries = map.entry(key.to_string()).or_default();
    entries.retain(|t| now.duration_since(*t).as_secs() < RATE_WINDOW_SECS);
    entries.push(now);
    entries.len() <= RATE_MAX_HITS
}

fn resolve_webmail_email(headers: &HeaderMap, requested: Option<&str>) -> Option<String> {
    if is_admin(headers) {
        return Some(requested.unwrap_or("").to_string()).filter(|s| !s.is_empty());
    }
    mailbox_email(headers)
}

#[derive(Deserialize)]
pub struct WebmailPostBody {
    pub action: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default)]
    pub message: Option<Value>,
    #[serde(default, rename = "messageAction")]
    pub message_action: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub folder: Option<String>,
    #[serde(default)]
    pub index: Option<String>,
}

pub async fn webmail_post(headers: HeaderMap, Json(body): Json<WebmailPostBody>) -> Response {
    // Simple rate limit by a static key (single-user system)
    if !rate_limit("global") {
        return json_err(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded");
    }

    let email = resolve_webmail_email(&headers, body.email.as_deref());
    let Some(email) = email else {
        return json_err(StatusCode::BAD_REQUEST, "email is required");
    };

    let id = body.id.as_deref().unwrap_or("");
    match body.action.as_str() {
        "read" => {
            let id = id.to_string();
            native_result(move || native::webmail_read(&email, &id, true)).await
        }
        "send" => {
            let p = body.message.unwrap_or_else(|| json!({}));
            native_result(move || native::webmail_send(&email, p)).await
        }
        "draft" => {
            let p = body.message.unwrap_or_else(|| json!({}));
            native_result(move || native::webmail_draft(&email, p)).await
        }
        "message" => {
            let ma = body.message_action.as_deref().unwrap_or("");
            let target = body.target.as_deref().unwrap_or("Archive");
            let id = id.to_string();
            let ma = ma.to_string();
            let target = target.to_string();
            native_result(move || native::webmail_action(&email, &id, &ma, &target)).await
        }
        "config" => {
            let kind = body.kind.as_deref().unwrap_or("");
            let kind = kind.to_string();
            let p = body.value.unwrap_or_else(|| json!({}));
            native_result(move || native::webmail_config(&email, &kind, p)).await
        }
        "apply-rules" => {
            let folder = body.folder.unwrap_or_else(|| "Inbox".to_string());
            native_result(move || native::webmail_apply_rules(&email, &folder)).await
        }
        "export" => native_result(native::webmail_export).await,
        "import" => {
            let p = body.value.unwrap_or_else(|| json!({}));
            native_result(move || native::webmail_import(p)).await
        }
        "attachment" => {
            let idx = body.index.as_deref().unwrap_or("");
            let id = id.to_string();
            let idx = idx.to_string();
            native_result(move || native::webmail_attachment(&email, &id, &idx)).await
        }
        _ => json_err(StatusCode::BAD_REQUEST, "unknown action"),
    }
}

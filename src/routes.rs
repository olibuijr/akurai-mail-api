use axum::{
    Json,
    extract::Query,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Redirect, Response},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::auth;
use crate::proxy;
use crate::config;

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
    let val = cookies.get(auth::SESSION_COOKIE).map(|s| s.as_str()).unwrap_or("");
    let cfg = config::get();
    auth::is_authenticated(val, &cfg.admin_user, &cfg.admin_password)
}

fn mailbox_email(headers: &HeaderMap) -> Option<String> {
    let cookies = parse_cookies(headers);
    let cfg = config::get();
    if is_admin(headers) {
        return None; // admin can specify email in request
    }
    let val = cookies.get(auth::MAILBOX_SESSION_COOKIE).map(|s| s.as_str()).unwrap_or("");
    auth::mailbox_from_session(val, &cfg.admin_password)
}

fn json_ok(data: Value) -> Response {
    Json(data).into_response()
}

fn json_err(status: StatusCode, msg: &str) -> Response {
    (status, Json(json!({"ok": false, "error": msg}))).into_response()
}

fn proxy_result(args: &[&str]) -> Response {
    match proxy::exec(args) {
        Ok(val) => json_ok(val),
        Err(e) => json_err(StatusCode::INTERNAL_SERVER_ERROR, &e),
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
    if !auth::validate_credentials(&body.email, &body.password, &cfg.admin_user, &cfg.admin_password) {
        return json_err(StatusCode::UNAUTHORIZED, "The email or password is incorrect.");
    }
    let session = auth::session_value(&cfg.admin_user, &cfg.admin_password);
    let cookie = auth::set_cookie_header(auth::SESSION_COOKIE, &session, "/");
    let next = if body.next.starts_with('/') { &body.next } else { "/" };
    let mut resp = Json(json!({"ok": true, "next": next})).into_response();
    resp.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
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
    resp.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&c1).unwrap());
    resp.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&c2).unwrap());
    resp
}

pub async fn auth_check(headers: HeaderMap) -> Response {
    let cookies = parse_cookies(&headers);
    let cfg = config::get();
    let admin = {
        let val = cookies.get(auth::SESSION_COOKIE).map(|s| s.as_str()).unwrap_or("");
        auth::is_authenticated(val, &cfg.admin_user, &cfg.admin_password)
    };
    let mailbox = {
        let val = cookies.get(auth::MAILBOX_SESSION_COOKIE).map(|s| s.as_str()).unwrap_or("");
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
    proxy_result(&["status"])
}

pub async fn metrics() -> Response {
    proxy_result(&["metrics"])
}

pub async fn dns() -> Response {
    proxy_result(&["dns"])
}

pub async fn domain_list() -> Response {
    proxy_result(&["domain-list"])
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
}

pub async fn actions(Json(body): Json<ActionBody>) -> Response {
    match body.action.as_str() {
        "add-user" => proxy_result(&["add-user", body.email.as_deref().unwrap_or("")]),
        "set-password" => proxy_result(&["set-password", body.email.as_deref().unwrap_or("")]),
        "add-alias" => proxy_result(&["add-alias", body.alias.as_deref().unwrap_or(""), body.target.as_deref().unwrap_or("")]),
        "anti-spam-config" => {
            let policy_str = body.policy.map(|v| v.to_string()).unwrap_or_else(|| "{}".to_string());
            let args_owned = vec!["anti-spam-config".to_string(), policy_str];
            let args: Vec<&str> = args_owned.iter().map(|s| s.as_str()).collect();
            proxy_result(&args)
        }
        "anti-spam-scan" => {
            if let Some(ref email) = body.email {
                proxy_result(&["anti-spam-scan", email])
            } else {
                proxy_result(&["anti-spam-scan"])
            }
        }
        "domain-add" => proxy_result(&["domain-add", body.domain.as_deref().unwrap_or("")]),
        "domain-check" => proxy_result(&["domain-check", body.domain.as_deref().unwrap_or("")]),
        "domain-remove" => proxy_result(&["domain-remove", body.domain.as_deref().unwrap_or("")]),
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
    let result = proxy::exec(&["validate-login", &body.email, &body.password]);
    match result {
        Ok(val) if val.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) => {
            let cfg = config::get();
            let session = auth::mailbox_session_value(&body.email, &cfg.admin_password);
            let cookie = auth::set_cookie_header(auth::MAILBOX_SESSION_COOKIE, &session, "/webmail");
            let next = if body.next.starts_with("/webmail") { &body.next } else { "/webmail" };
            let mut resp = Json(json!({"ok": true, "next": next})).into_response();
            resp.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
            resp
        }
        _ => json_err(StatusCode::UNAUTHORIZED, "The email or password is incorrect."),
    }
}

pub async fn webmail_logout() -> Response {
    let cookie = auth::clear_cookie_header(auth::MAILBOX_SESSION_COOKIE, "/webmail");
    let mut resp = Redirect::to("/webmail/login").into_response();
    resp.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
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
    let folder = q.folder.as_deref().unwrap_or("Inbox");
    let query = q.query.as_deref().unwrap_or("");
    proxy_result(&["webmail-state", &email, "--folder", folder, "--query", query])
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
    let payload = |v: &Option<Value>| v.as_ref().map(|v| v.to_string()).unwrap_or_else(|| "{}".to_string());

    match body.action.as_str() {
        "read" => proxy_result(&["webmail-read", &email, id, "--mark-read"]),
        "send" => {
            let p = payload(&body.message);
            proxy_result(&["webmail-send", &email, &p])
        }
        "draft" => {
            let p = payload(&body.message);
            proxy_result(&["webmail-draft", &email, &p])
        }
        "message" => {
            let ma = body.message_action.as_deref().unwrap_or("");
            let target = body.target.as_deref().unwrap_or("Archive");
            proxy_result(&["webmail-action", &email, id, ma, "--target", target])
        }
        "config" => {
            let kind = body.kind.as_deref().unwrap_or("");
            let p = payload(&body.value);
            proxy_result(&["webmail-config", &email, kind, &p])
        }
        "apply-rules" => {
            let folder = body.folder.as_deref().unwrap_or("Inbox");
            proxy_result(&["webmail-apply-rules", &email, "--folder", folder])
        }
        "export" => proxy_result(&["webmail-export", &email]),
        "import" => {
            let p = payload(&body.value);
            proxy_result(&["webmail-import", &email, &p])
        }
        "attachment" => {
            let idx = body.index.as_deref().unwrap_or("");
            proxy_result(&["webmail-attachment", &email, id, idx])
        }
        _ => json_err(StatusCode::BAD_REQUEST, "unknown action"),
    }
}

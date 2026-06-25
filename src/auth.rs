use axum::{
    extract::Query,
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use subtle::ConstantTimeEq;

use crate::config;

pub const SESSION_COOKIE: &str = "akurai_session";
pub const MAILBOX_SESSION_COOKIE: &str = "akurai_mailbox_session";
const SESSION_MAX_AGE: u64 = 60 * 60 * 10; // 10 hours

// ---------------------------------------------------------------------------
// In-memory OIDC session store: session_id -> email
// ---------------------------------------------------------------------------
static OIDC_SESSIONS: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// Pending OIDC flows: state -> code_verifier
static PENDING_FLOWS: LazyLock<Mutex<HashMap<String, String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

// ---------------------------------------------------------------------------
// Legacy password auth (kept as fallback)
// ---------------------------------------------------------------------------

fn digest(value: &str) -> String {
    let hash = Sha256::digest(value.as_bytes());
    hex::encode(hash)
}

fn constant_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();
    a_bytes.len() == b_bytes.len() && a_bytes.ct_eq(b_bytes).into()
}

pub fn session_value(user: &str, password: &str) -> String {
    digest(&format!("{user}:{password}"))
}

pub fn mailbox_session_value(email: &str, admin_password: &str) -> String {
    let token = digest(&format!("{email}:{admin_password}:mailbox"));
    format!("{email}:{token}")
}

pub fn validate_credentials(
    email: &str,
    password: &str,
    admin_user: &str,
    admin_password: &str,
) -> bool {
    if admin_password.is_empty() {
        return false;
    }
    constant_eq(&digest(email), &digest(admin_user))
        && constant_eq(&digest(password), &digest(admin_password))
}

fn is_legacy_authenticated(cookie_value: &str, admin_user: &str, admin_password: &str) -> bool {
    if admin_password.is_empty() || cookie_value.is_empty() {
        return false;
    }
    constant_eq(cookie_value, &session_value(admin_user, admin_password))
}

// ---------------------------------------------------------------------------
// Unified auth check: OIDC session OR legacy password session
// ---------------------------------------------------------------------------

/// Returns true if the request has a valid admin session (OIDC or legacy).
pub fn is_authenticated(cookie_value: &str, admin_user: &str, admin_password: &str) -> bool {
    // Check legacy password session
    if is_legacy_authenticated(cookie_value, admin_user, admin_password) {
        return true;
    }
    // Check OIDC session
    if !cookie_value.is_empty() {
        let sessions = OIDC_SESSIONS.lock().unwrap();
        if sessions.contains_key(cookie_value) {
            return true;
        }
    }
    false
}

/// Returns the email for an OIDC session, if any.
pub fn oidc_session_email(cookie_value: &str) -> Option<String> {
    if cookie_value.is_empty() {
        return None;
    }
    let sessions = OIDC_SESSIONS.lock().unwrap();
    sessions.get(cookie_value).cloned()
}

pub fn mailbox_from_session(cookie_value: &str, admin_password: &str) -> Option<String> {
    if admin_password.is_empty() || cookie_value.is_empty() {
        return None;
    }
    let sep = cookie_value.rfind(':')?;
    if sep < 1 {
        return None;
    }
    let email = &cookie_value[..sep];
    let token = &cookie_value[sep + 1..];
    let expected = digest(&format!("{email}:{admin_password}:mailbox"));
    if constant_eq(token, &expected) {
        Some(email.to_string())
    } else {
        None
    }
}

pub fn set_cookie_header(name: &str, value: &str, path: &str) -> String {
    format!("{name}={value}; Path={path}; HttpOnly; SameSite=Lax; Secure; Max-Age={SESSION_MAX_AGE}")
}

pub fn clear_cookie_header(name: &str, path: &str) -> String {
    format!("{name}=; Path={path}; HttpOnly; SameSite=Lax; Secure; Max-Age=0")
}

// ---------------------------------------------------------------------------
// OIDC auth code flow
// ---------------------------------------------------------------------------

fn generate_random_hex(len: usize) -> String {
    use rand::Rng;
    let bytes: Vec<u8> = (0..len).map(|_| rand::rng().random()).collect();
    hex::encode(bytes)
}

fn generate_pkce() -> (String, String) {
    let verifier = generate_random_hex(32);
    let hash = Sha256::digest(verifier.as_bytes());
    let challenge = base64_url_encode(&hash);
    (verifier, challenge)
}

fn base64_url_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

fn base64_url_decode(input: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(input)
        .ok()
}

fn urlenc(s: &str) -> String {
    let mut result = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(b as char);
            }
            _ => {
                result.push_str(&format!("%{b:02X}"));
            }
        }
    }
    result
}

/// Build the IDP authorize URL and store PKCE state.
pub fn oidc_login_url() -> String {
    let cfg = config::get();
    let state = generate_random_hex(16);
    let (verifier, challenge) = generate_pkce();
    let redirect_uri = config::oidc_redirect_uri();

    PENDING_FLOWS
        .lock()
        .unwrap()
        .insert(state.clone(), verifier);

    format!(
        "{}/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid+email&state={}&code_challenge={}&code_challenge_method=S256",
        cfg.oidc_issuer,
        cfg.oidc_client_id,
        urlenc(&redirect_uri),
        state,
        challenge,
    )
}

#[derive(Deserialize)]
pub struct OidcCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

pub async fn oidc_callback(Query(q): Query<OidcCallbackQuery>) -> Response {
    if let Some(error) = &q.error {
        let desc = q.error_description.as_deref().unwrap_or("Unknown error");
        tracing::error!(error, desc, "OIDC authorization error");
        return (StatusCode::UNAUTHORIZED, format!("Login failed: {desc}")).into_response();
    }

    let Some(code) = &q.code else {
        return (StatusCode::BAD_REQUEST, "Missing authorization code").into_response();
    };
    let Some(state) = &q.state else {
        return (StatusCode::BAD_REQUEST, "Missing state parameter").into_response();
    };

    let cfg = config::get();

    let verifier = {
        let mut flows = PENDING_FLOWS.lock().unwrap();
        flows.remove(state)
    };
    let Some(verifier) = verifier else {
        return (StatusCode::BAD_REQUEST, "Invalid or expired state").into_response();
    };

    // Exchange code for tokens
    let client = reqwest::Client::new();
    let token_url = format!("{}/token", cfg.oidc_issuer);
    let redirect_uri = config::oidc_redirect_uri();

    let res = client
        .post(&token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("code", code.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
            ("client_id", cfg.oidc_client_id.as_str()),
            ("client_secret", cfg.oidc_client_secret.as_str()),
            ("code_verifier", verifier.as_str()),
        ])
        .send()
        .await;

    let Ok(res) = res else {
        return (StatusCode::BAD_GATEWAY, "Failed to contact IDP").into_response();
    };

    if !res.status().is_success() {
        let body = res.text().await.unwrap_or_default();
        tracing::error!(body, "token exchange failed");
        return (StatusCode::UNAUTHORIZED, "Token exchange failed").into_response();
    }

    let Ok(token_response) = res.json::<serde_json::Value>().await else {
        return (StatusCode::BAD_GATEWAY, "Invalid token response").into_response();
    };

    let email = extract_email_from_id_token(&token_response)
        .unwrap_or_else(|| "unknown".to_string());

    // Create OIDC session
    let session_id = generate_random_hex(32);
    OIDC_SESSIONS
        .lock()
        .unwrap()
        .insert(session_id.clone(), email.clone());

    tracing::info!(email, "user authenticated via OIDC");

    let cookie = set_cookie_header(SESSION_COOKIE, &session_id, "/");

    let mut resp = axum::response::Redirect::to("/").into_response();
    resp.headers_mut()
        .append(header::SET_COOKIE, HeaderValue::from_str(&cookie).unwrap());
    resp
}

pub async fn oidc_login() -> Response {
    if !config::oidc_enabled() {
        return (StatusCode::SERVICE_UNAVAILABLE, "OIDC not configured").into_response();
    }
    let url = oidc_login_url();
    axum::response::Redirect::temporary(&url).into_response()
}

fn extract_email_from_id_token(token_response: &serde_json::Value) -> Option<String> {
    let id_token = token_response.get("id_token")?.as_str()?;
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    let payload = base64_url_decode(parts[1])?;
    let claims: serde_json::Value = serde_json::from_slice(&payload).ok()?;
    claims.get("email").and_then(|v| v.as_str()).map(String::from)
}

// ---------------------------------------------------------------------------
// Auth check route (updated to report OIDC sessions)
// ---------------------------------------------------------------------------

pub fn auth_check_response(headers: &HeaderMap) -> serde_json::Value {
    let cookies = parse_cookies(headers);
    let cfg = config::get();

    let session_val = cookies
        .get(SESSION_COOKIE)
        .map(|s| s.as_str())
        .unwrap_or("");

    // Check OIDC session first
    if let Some(email) = oidc_session_email(session_val) {
        return serde_json::json!({
            "authenticated": true,
            "user": email,
            "method": "oidc",
        });
    }

    // Check legacy session
    let admin = is_legacy_authenticated(session_val, &cfg.admin_user, &cfg.admin_password);

    let mailbox_val = cookies
        .get(MAILBOX_SESSION_COOKIE)
        .map(|s| s.as_str())
        .unwrap_or("");
    let mailbox = mailbox_from_session(mailbox_val, &cfg.admin_password);

    serde_json::json!({
        "authenticated": admin,
        "mailbox": mailbox,
        "user": if admin { cfg.admin_user.clone() } else { String::new() },
        "method": if admin { "password" } else { "none" },
    })
}

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

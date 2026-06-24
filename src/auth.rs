use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

pub const SESSION_COOKIE: &str = "akurai_session";
pub const MAILBOX_SESSION_COOKIE: &str = "akurai_mailbox_session";
const SESSION_MAX_AGE: u64 = 60 * 60 * 10; // 10 hours

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

pub fn validate_credentials(email: &str, password: &str, admin_user: &str, admin_password: &str) -> bool {
    if admin_password.is_empty() {
        return false;
    }
    constant_eq(&digest(email), &digest(admin_user))
        && constant_eq(&digest(password), &digest(admin_password))
}

pub fn is_authenticated(cookie_value: &str, admin_user: &str, admin_password: &str) -> bool {
    if admin_password.is_empty() || cookie_value.is_empty() {
        return false;
    }
    constant_eq(cookie_value, &session_value(admin_user, admin_password))
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
    format!(
        "{name}={value}; Path={path}; HttpOnly; SameSite=Strict; Max-Age={SESSION_MAX_AGE}"
    )
}

pub fn clear_cookie_header(name: &str, path: &str) -> String {
    format!("{name}=; Path={path}; HttpOnly; SameSite=Strict; Max-Age=0")
}

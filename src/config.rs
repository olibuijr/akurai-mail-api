use std::sync::LazyLock;

pub struct Config {
    pub admin_user: String,
    pub admin_password: String,
    pub listen_addr: String,
    pub static_dir: String,
    pub base_url: String,
    pub oidc_issuer: String,
    pub oidc_client_id: String,
    pub oidc_client_secret: String,
}

static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    let base_url = std::env::var("AKURAI_BASE_URL")
        .unwrap_or_else(|_| "https://mail.olibuijr.com".to_string());
    let oidc_redirect_uri = format!("{base_url}/auth/oidc/callback");
    // Store redirect_uri as part of config via a derived field accessed separately
    let _ = oidc_redirect_uri; // used via base_url + path

    Config {
        admin_user: std::env::var("AKURAI_ADMIN_USER").unwrap_or_else(|_| "admin".to_string()),
        admin_password: std::env::var("AKURAI_ADMIN_PASSWORD").unwrap_or_default(),
        listen_addr: std::env::var("AKURAI_LISTEN").unwrap_or_else(|_| "127.0.0.1:3000".to_string()),
        static_dir: std::env::var("AKURAI_STATIC_DIR").unwrap_or_else(|_| "./static".to_string()),
        base_url,
        oidc_issuer: std::env::var("AKURAI_OIDC_ISSUER")
            .unwrap_or_else(|_| "https://auth.olibuijr.com".to_string()),
        oidc_client_id: std::env::var("AKURAI_OIDC_CLIENT_ID").unwrap_or_default(),
        oidc_client_secret: std::env::var("AKURAI_OIDC_CLIENT_SECRET").unwrap_or_default(),
    }
});

pub fn get() -> &'static Config {
    &CONFIG
}

pub fn oidc_redirect_uri() -> String {
    format!("{}/auth/oidc/callback", get().base_url)
}

pub fn oidc_enabled() -> bool {
    !get().oidc_client_id.is_empty()
}

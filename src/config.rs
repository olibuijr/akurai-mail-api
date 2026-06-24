use std::sync::LazyLock;

pub struct Config {
    pub admin_user: String,
    pub admin_password: String,
    pub listen_addr: String,
    pub static_dir: String,
}

static CONFIG: LazyLock<Config> = LazyLock::new(|| Config {
    admin_user: std::env::var("AKURAI_ADMIN_USER").unwrap_or_else(|_| "admin".to_string()),
    admin_password: std::env::var("AKURAI_ADMIN_PASSWORD").unwrap_or_default(),
    listen_addr: std::env::var("AKURAI_LISTEN").unwrap_or_else(|_| "127.0.0.1:3000".to_string()),
    static_dir: std::env::var("AKURAI_STATIC_DIR").unwrap_or_else(|_| "./static".to_string()),
});

pub fn get() -> &'static Config {
    &CONFIG
}

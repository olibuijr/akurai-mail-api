#!/usr/bin/env bash
set -euo pipefail

SSH_HOST="${AKURAI_MAIL_SSH:-akurai-mail}"
DEPLOY_DIR="/opt/akurai-mail-ui"
SERVICE="akurai-mail-ui"

log()  { echo "[deploy] $*"; }
step() { echo; echo "── $* ──"; }

# ---------------------------------------------------------------------------
# Step 1: Build Rust binary (release)
# ---------------------------------------------------------------------------
step "1/5  Build Rust binary"
TARGET="x86_64-unknown-linux-musl"
cargo build --release --target "$TARGET" 2>&1
BINARY="target/$TARGET/release/akurai-mail-api"
log "Binary: $(du -sh "$BINARY" | cut -f1)"

# ---------------------------------------------------------------------------
# Step 2: Build SvelteKit static frontend
# ---------------------------------------------------------------------------
step "2/5  Build frontend"
FRONTEND_DIR="${AKURAI_MAIL_FRONTEND:-../AkurAIMail}"
if [ ! -d "$FRONTEND_DIR" ]; then
  echo "ERROR: frontend dir not found at $FRONTEND_DIR"
  exit 1
fi
(cd "$FRONTEND_DIR" && bun install --frozen-lockfile 2>&1 || bun install && bun run build)
log "Frontend built"

# ---------------------------------------------------------------------------
# Step 3: Upload
# ---------------------------------------------------------------------------
step "3/5  Upload"
ssh "$SSH_HOST" "sudo mkdir -p $DEPLOY_DIR/static"
scp -q "$BINARY" "$SSH_HOST:/tmp/akurai-mail-api"
ssh "$SSH_HOST" "sudo install -m 755 /tmp/akurai-mail-api $DEPLOY_DIR/akurai-mail-api && rm /tmp/akurai-mail-api"
rsync -az --delete "$FRONTEND_DIR/build/" "$SSH_HOST:/tmp/akurai-mail-static/"
ssh "$SSH_HOST" "sudo rsync -a --delete /tmp/akurai-mail-static/ $DEPLOY_DIR/static/ && sudo rm -rf /tmp/akurai-mail-static"
log "Uploaded binary + static files"

# ---------------------------------------------------------------------------
# Step 4: Install systemd service + restart
# ---------------------------------------------------------------------------
step "4/5  Install service"
ssh "$SSH_HOST" "sudo bash -s" <<'INSTALL'
set -euo pipefail

get_unit_env() {
  local key="$1"
  systemctl cat akurai-mail-ui.service 2>/dev/null \
    | awk -F= -v key="$key" '$1 == "Environment" && $2 == key {print substr($0, index($0, $3))}' \
    | tail -1
}

if [ -f /etc/akurai-mail-ui.env ]; then
  set -a
  . /etc/akurai-mail-ui.env
  set +a
fi

admin_user="${AKURAI_ADMIN_USER:-$(get_unit_env AKURAI_ADMIN_USER)}"
admin_password="${AKURAI_ADMIN_PASSWORD:-$(get_unit_env AKURAI_ADMIN_PASSWORD)}"
if [ -z "$admin_user" ]; then
  admin_user="olibuijr@olibuijr.com"
fi
if [ -z "$admin_password" ]; then
  admin_password="$(openssl rand -base64 32)"
fi

umask 077
cat > /etc/akurai-mail-ui.env <<EOF
AKURAI_ADMIN_USER=$admin_user
AKURAI_ADMIN_PASSWORD=$admin_password
AKURAI_LISTEN=127.0.0.1:3000
AKURAI_STATIC_DIR=/opt/akurai-mail-ui/static
RUST_LOG=akurai_mail_api=info
AKURAI_BASE_URL=${AKURAI_BASE_URL:-https://mail.olibuijr.com}
AKURAI_OIDC_ISSUER=${AKURAI_OIDC_ISSUER:-https://auth.olibuijr.com}
AKURAI_OIDC_CLIENT_ID=${AKURAI_OIDC_CLIENT_ID:-}
AKURAI_OIDC_CLIENT_SECRET=${AKURAI_OIDC_CLIENT_SECRET:-}
EOF
chmod 0600 /etc/akurai-mail-ui.env

rm -f /etc/sudoers.d/akurai-mail-server
rm -f /usr/local/sbin/akurai-mail-server

rm -f /etc/nginx/conf.d/akurai-mail-performance.conf

cat > /etc/systemd/system/akurai-mail-ui.service <<EOF
[Unit]
Description=AkurAI Mail API (Rust)
After=network.target

[Service]
Type=simple
ExecStart=/opt/akurai-mail-ui/akurai-mail-api
WorkingDirectory=/opt/akurai-mail-ui
EnvironmentFile=/etc/akurai-mail-ui.env
Restart=always
RestartSec=3
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
nginx -t >/dev/null
systemctl reload nginx
systemctl restart akurai-mail-ui
echo "  [done] service restarted"
INSTALL

# ---------------------------------------------------------------------------
# Step 5: Healthcheck
# ---------------------------------------------------------------------------
step "5/5  Healthcheck"
sleep 2
if ssh "$SSH_HOST" "curl -fsS -o /dev/null -w '%{http_code}' http://127.0.0.1:3000/login" | grep -q 200; then
  log "Healthcheck passed"
else
  echo "ERROR: healthcheck failed"
  echo "Check: ssh $SSH_HOST 'sudo journalctl -u $SERVICE -n 50'"
  exit 1
fi

if ssh "$SSH_HOST" "sudo bash -c 'set -a; . /etc/akurai-mail-ui.env; set +a; session=\$(printf \"%s\" \"\$AKURAI_ADMIN_USER:\$AKURAI_ADMIN_PASSWORD\" | sha256sum | awk \"{print \\\$1}\"); curl -fsS -o /dev/null -w \"%{http_code}\" -b akurai_session=\$session http://127.0.0.1:3000/api/status'" | grep -q 200; then
  log "Authenticated API healthcheck passed"
else
  echo "ERROR: authenticated API healthcheck failed"
  echo "Check: ssh $SSH_HOST 'sudo journalctl -u $SERVICE -n 80'"
  exit 1
fi

# Check RSS memory
RSS=$(ssh "$SSH_HOST" "ps -C akurai-mail-api -o rss= 2>/dev/null | head -1 | tr -d ' '" 2>/dev/null || echo "?")
echo
echo "════════════════════════════════════════════════════"
echo "  AkurAI Mail API deployed (Rust)"
echo "════════════════════════════════════════════════════"
echo "  Binary  : $(du -sh "$BINARY" | cut -f1)"
echo "  RSS     : ${RSS} KB"
echo "  Host    : $SSH_HOST"
echo "  Public  : https://mail.olibuijr.com"
echo "════════════════════════════════════════════════════"

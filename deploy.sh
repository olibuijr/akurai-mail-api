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

# Install the akurai-mail-server helper script if present
if [ -f /opt/akurai-mail-ui/scripts/akurai-mail-server ]; then
  install -m 755 /opt/akurai-mail-ui/scripts/akurai-mail-server /usr/local/sbin/akurai-mail-server
fi

cat > /etc/systemd/system/akurai-mail-ui.service <<EOF
[Unit]
Description=AkurAI Mail API (Rust)
After=network.target

[Service]
Type=simple
ExecStart=/opt/akurai-mail-ui/akurai-mail-api
WorkingDirectory=/opt/akurai-mail-ui
Environment=AKURAI_ADMIN_USER=olibuijr@olibuijr.com
Environment=AKURAI_ADMIN_PASSWORD=M3ga.p4bb1!!!
Environment=AKURAI_LISTEN=127.0.0.1:3000
Environment=AKURAI_STATIC_DIR=/opt/akurai-mail-ui/static
Environment=RUST_LOG=akurai_mail_api=info
Restart=always
RestartSec=3
User=ubuntu
Group=ubuntu

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
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

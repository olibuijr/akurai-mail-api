# CLAUDE.md

## What this is

Lightweight Rust (axum) API server for [AkurAI Mail](https://github.com/olibuijr/AkurAIMail). Serves static SvelteKit frontend + handles auth + proxies all operations to the Python `akurai-mail-server` script via sudo. Runs on AWS EC2 (Ubuntu 22.04).

## Build & Deploy

- `cargo build --release --target x86_64-unknown-linux-musl` (static binary, ~1.8MB)
- `./deploy.sh` — builds Rust + frontend, uploads to VM, restarts service, healthchecks
- Frontend repo: `../AkurAIMail` (SvelteKit 5, adapter-static)
- VM: `ssh akurai-mail` (3.94.46.219, Ubuntu 22.04, systemd `akurai-mail-ui.service`)

## Architecture

```
nginx (TLS) → akurai-mail-api (:3000) → sudo akurai-mail-server (Python)
                    ↓
              /opt/akurai-mail-ui/static/ (SvelteKit build output)
```

- `src/main.rs` — router setup, auth middleware, static file serving with SPA fallback
- `src/auth.rs` — SHA256 session cookies, constant-time comparison via `subtle`
- `src/config.rs` — env var config (lazy static)
- `src/proxy.rs` — exec `sudo /usr/local/sbin/akurai-mail-server <subcommand>` → JSON
- `src/routes.rs` — all API handlers: admin CRUD, webmail ops, login/logout, metrics

## Environment Variables

| Variable | Default | Required |
|----------|---------|----------|
| `AKURAI_ADMIN_USER` | `admin` | Yes |
| `AKURAI_ADMIN_PASSWORD` | *(empty)* | Yes |
| `AKURAI_LISTEN` | `127.0.0.1:3000` | No |
| `AKURAI_STATIC_DIR` | `./static` | No |
| `RUST_LOG` | `akurai_mail_api=info` | No |

## Constraints

- Binary MUST cross-compile with `x86_64-unknown-linux-musl` (VM is Ubuntu 22.04, dev host is Arch)
- All business logic stays in the Python script — Rust is auth + proxy only, zero business logic
- Session cookies: `httpOnly`, `sameSite=strict`, SHA256 digests, 10h max-age
- Release profile: `opt-level=z`, LTO, strip, `panic=abort`
- No direct database access — everything goes through `akurai-mail-server` subcommands
- RSS must stay under 5 MB — that's the whole point of this project

## API Routes

**Public:** `POST /api/login`, `POST /api/webmail/login`, `GET /api/logout`, `GET /api/webmail/logout`, `GET /api/auth/check`

**Admin (session cookie):** `GET /api/status`, `GET /api/metrics`, `GET /api/dns`, `GET /api/domain-list`, `POST /api/actions`

**Webmail (admin or mailbox session):** `GET /api/webmail`, `POST /api/webmail`

## Testing

- `cargo build` — compile check
- `cargo build --release --target x86_64-unknown-linux-musl` — release cross-compile
- Deploy healthcheck: `curl -fsS http://127.0.0.1:3000/login` returns 200
- Memory check: `ps -C akurai-mail-api -o rss=` should be under 5000 KB

## Related Projects

- **Frontend:** [olibuijr/AkurAIMail](https://github.com/olibuijr/AkurAIMail) (SvelteKit 5, private) — builds to static files served by this binary
- **Server script:** `/usr/local/sbin/akurai-mail-server` (Python) — source at `AkurAIMail/scripts/akurai-mail-server`, installed on VM by deploy
- **IDP:** [olibuijr/AkurAIIDP](https://github.com/olibuijr/AkurAIIDP) (Hono, private) — separate service on same VM, port 3500

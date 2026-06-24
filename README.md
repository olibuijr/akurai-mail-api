# akurai-mail-api

Lightweight Rust API server for [AkurAI Mail](https://github.com/olibuijr/AkurAIMail). It serves the static SvelteKit UI and performs mail platform management natively in Rust.

## What it does

- Serves the SvelteKit static frontend (built with `adapter-static`)
- Handles admin and mailbox authentication via secure session cookies
- Manages Postfix, Dovecot, OpenDKIM, DNS checks, domains, anti-spam state, and Maildir webmail directly from Rust
- Applies immutable cache headers for hashed frontend assets and response compression for compressible payloads
- Rate-limits webmail API endpoints

## Architecture

```
nginx (TLS, gzip) → akurai-mail-api (127.0.0.1:3000)
                    ↓
              static files + native mail management
```

The Rust service is the request path. There is no Python helper or per-request `sudo` bridge in the deployed stack.

## Configuration

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `AKURAI_ADMIN_USER` | `admin` | Admin email for login |
| `AKURAI_ADMIN_PASSWORD` | *(empty)* | Admin password (required) |
| `AKURAI_LISTEN` | `127.0.0.1:3000` | Listen address |
| `AKURAI_STATIC_DIR` | `./static` | Path to SvelteKit build output |
| `RUST_LOG` | `akurai_mail_api=info` | Log level |

## Build

```bash
cargo build --release
```

Binary output: `target/release/akurai-mail-api`.

## Deploy

Requires the [AkurAIMail](https://github.com/olibuijr/AkurAIMail) frontend repo alongside:

```bash
./deploy.sh
```

This builds the Rust binary, builds the SvelteKit frontend, uploads both to the VM, installs the systemd service, configures nginx gzip, removes the old Python sudo helper, and runs public plus authenticated healthchecks.

## API Routes

### Public (no auth)
- `POST /api/login` — admin login
- `POST /api/webmail/login` — mailbox login
- `GET /api/logout` — clear session
- `GET /api/webmail/logout` — clear mailbox session
- `GET /api/auth/check` — check current auth status

### Admin (session cookie required)
- `GET /api/status` — full server status
- `GET /api/metrics` — lightweight CPU/memory/disk + processes
- `GET /api/metrics/stream` — SSE stream for live status updates
- `GET /api/dns` — DNS records
- `GET /api/domain-list` — managed domains
- `POST /api/actions` — admin operations (`domain-autopilot`, `add-user`, `set-password`, etc.)

### Webmail (admin or mailbox session)
- `GET /api/webmail` — mailbox state (messages, folders)
- `POST /api/webmail` — webmail operations (read, send, draft, etc.)

## Dependencies

- [axum](https://github.com/tokio-rs/axum) — web framework
- [tower-http](https://github.com/tower-rs/tower-http) — static file serving
- [sha2](https://github.com/RustCrypto/hashes) + [subtle](https://github.com/dalek-cryptography/subtle) — constant-time auth
- [tokio](https://tokio.rs) — async runtime
- `mailparse`, `regex`, `base64` — Maildir/webmail parsing and attachment handling

## License

MIT

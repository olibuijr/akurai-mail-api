# akurai-mail-api

Lightweight Rust API server for [AkurAI Mail](https://github.com/olibuijr/AkurAIMail). Replaces the Bun/Node SSR runtime (~61 MB RSS) with a single static binary (~3-5 MB RSS).

## What it does

- Serves the SvelteKit static frontend (built with `adapter-static`)
- Handles admin and mailbox authentication via secure session cookies
- Proxies all API calls to `akurai-mail-server` (the Python management script)
- Rate-limits webmail API endpoints

## Architecture

```
nginx (TLS) → akurai-mail-api (port 3000) → sudo akurai-mail-server (Python)
                    ↓
              static files (SvelteKit build output)
```

The Rust binary does **zero business logic** — it's a thin authenticated proxy between the browser and the existing `akurai-mail-server` script. All mail management, DKIM, DNS, and webmail operations remain in the Python script.

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

Binary output: `target/release/akurai-mail-api` (~1.6 MB stripped).

## Deploy

Requires the [AkurAIMail](https://github.com/olibuijr/AkurAIMail) frontend repo alongside:

```bash
./deploy.sh
```

This builds the Rust binary, builds the SvelteKit frontend, uploads both to the VM, installs the systemd service, and runs a healthcheck.

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
- `GET /api/dns` — DNS records
- `GET /api/domain-list` — managed domains
- `POST /api/actions` — admin operations (add-user, set-password, etc.)

### Webmail (admin or mailbox session)
- `GET /api/webmail` — mailbox state (messages, folders)
- `POST /api/webmail` — webmail operations (read, send, draft, etc.)

## Dependencies

- [axum](https://github.com/tokio-rs/axum) — web framework
- [tower-http](https://github.com/tower-rs/tower-http) — static file serving
- [sha2](https://github.com/RustCrypto/hashes) + [subtle](https://github.com/dalek-cryptography/subtle) — constant-time auth
- [tokio](https://tokio.rs) — async runtime

## License

MIT

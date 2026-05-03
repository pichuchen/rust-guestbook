# rust-guestbook

A simple **留言板 (guestbook)** with an **後台管理 (admin panel)** built with Rust on [Cloudflare Workers](https://workers.cloudflare.com/), using **D1** (SQLite) for message storage and **R2** for file attachments.

---

## ✨ Features

| Feature | Details |
|---------|---------|
| Public guestbook | Submit & view approved messages |
| File attachments | Upload files (stored in R2); max 25 MB |
| Admin panel | Secure login, approve / delete messages |
| JWT auth | Stateless HMAC-SHA256 signed tokens (24 h TTL) |
| CORS headers | All responses include `Access-Control-Allow-Origin: *` |

---

## 🗂 Project Structure

```
rust-guestbook/
├── src/
│   └── lib.rs          # Cloudflare Worker (Rust)
├── static/
│   ├── index.html      # Public guestbook frontend
│   └── admin.html      # Admin login + dashboard frontend
├── schema.sql          # D1 database schema
├── wrangler.toml       # Cloudflare Workers configuration
└── Cargo.toml          # Rust dependencies
```

---

## 🚀 Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) + `wasm32-unknown-unknown` target
  ```bash
  rustup target add wasm32-unknown-unknown
  ```
- [Node.js](https://nodejs.org/) ≥ 18 (for Wrangler)
- [Wrangler CLI](https://developers.cloudflare.com/workers/wrangler/)
  ```bash
  npm install -g wrangler
  wrangler login
  ```
- `worker-build` (installed automatically by `wrangler.toml` build command, or install manually):
  ```bash
  cargo install worker-build
  ```

---

### 1. Create D1 Database

```bash
wrangler d1 create guestbook
```

Copy the `database_id` from the output and export it as an environment variable (do **not** hard-code it in `wrangler.toml`):

```bash
export DB_DATABASE_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

For CI/CD (GitHub Actions), add `DB_DATABASE_ID` as a repository secret:
**Settings → Secrets and variables → Actions → New repository secret**

Apply the schema:

```bash
wrangler d1 execute guestbook --file=schema.sql
```

---

### 2. Create R2 Bucket

```bash
wrangler r2 bucket create guestbook-attachments
```

---

### 3. Set Secrets

```bash
# Admin login password (plaintext, stored as encrypted Cloudflare secret)
wrangler secret put ADMIN_PASSWORD

# Random string for JWT signing (e.g. openssl rand -hex 32)
wrangler secret put JWT_SECRET
```

Optionally change the admin username in `wrangler.toml`:

```toml
[vars]
ADMIN_USERNAME = "admin"   # ← change as needed
```

---

### 4. Deploy

```bash
wrangler deploy
```

---

### 5. Local Development

For local testing (Wrangler will use a local D1 emulator):

```bash
# Apply schema locally first
wrangler d1 execute guestbook --local --file=schema.sql

# Create a .dev.vars file for secrets
cat > .dev.vars <<EOF
ADMIN_PASSWORD=your_password_here
JWT_SECRET=your_jwt_secret_here
EOF

# Export DB_DATABASE_ID (from `wrangler d1 create` output)
export DB_DATABASE_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Run dev server (wrangler.toml substitutes ${DB_DATABASE_ID} automatically)
wrangler dev
```

> R2 attachments are not available in local dev by default. The worker gracefully returns 503 if the bucket is unconfigured.

---

## 🌐 API Reference

### Public

| Method | Path | Description |
|--------|------|-------------|
| `GET`  | `/` | Guestbook page |
| `GET`  | `/admin` | Admin page |
| `GET`  | `/api/messages` | List approved messages |
| `POST` | `/api/messages` | Submit a new message |
| `POST` | `/api/upload` | Upload attachment (multipart `file` field) |
| `GET`  | `/api/attachments/:key` | Download attachment |

**POST `/api/messages` body (JSON):**

```json
{
  "name": "Alice",
  "email": "alice@example.com",   // optional
  "content": "Hello World!",
  "attachment_key": "..."         // optional, from /api/upload
}
```

### Admin (requires `Authorization: Bearer <token>`)

| Method | Path | Description |
|--------|------|-------------|
| `POST`   | `/api/admin/login`                | Login, returns JWT token |
| `GET`    | `/api/admin/messages`             | List all messages |
| `PUT`    | `/api/admin/messages/:id/approve` | Approve a message |
| `DELETE` | `/api/admin/messages/:id`         | Delete a message |

---

## 🔐 Security Notes

- Admin credentials are stored as **Cloudflare encrypted secrets** (`ADMIN_PASSWORD`, `JWT_SECRET`), never committed to source code.
- Tokens are HMAC-SHA256 signed with `JWT_SECRET` and expire after 24 hours.
- Attachment keys are sanitised to prevent path traversal.
- All user-supplied content is HTML-escaped in the frontend before rendering.

---

## 🛠 Tech Stack

| Layer | Technology |
|-------|-----------|
| Runtime | [Cloudflare Workers](https://workers.cloudflare.com/) |
| Language | [Rust](https://www.rust-lang.org/) → WASM (`worker` crate 0.4) |
| Database | [Cloudflare D1](https://developers.cloudflare.com/d1/) (SQLite) |
| Storage | [Cloudflare R2](https://developers.cloudflare.com/r2/) |
| Frontend | Vanilla HTML + JS + [Tailwind CSS](https://tailwindcss.com/) (CDN) |
| Auth | HMAC-SHA256 JWT |
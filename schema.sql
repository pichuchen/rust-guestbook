-- Guestbook D1 Database Schema
-- Apply with:
--   wrangler d1 execute guestbook --file=schema.sql
--   (for local preview: wrangler d1 execute guestbook --local --file=schema.sql)

CREATE TABLE IF NOT EXISTS messages (
    id             INTEGER  PRIMARY KEY AUTOINCREMENT,
    name           TEXT     NOT NULL,
    email          TEXT,
    content        TEXT     NOT NULL,
    attachment_key TEXT,
    approved       INTEGER  NOT NULL DEFAULT 0,
    created_at     TEXT     NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Optional: seed a default admin row if you want to track admins in DB later.
-- For now, admin credentials are stored as Cloudflare secrets (ADMIN_PASSWORD, JWT_SECRET).

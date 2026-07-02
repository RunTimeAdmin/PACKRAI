-- Migration 004: Dashboard session tables
-- Safe to run on existing databases — idempotent.
BEGIN;

-- One-time magic-link tokens (15 min TTL, deleted on use)
CREATE TABLE IF NOT EXISTS login_tokens (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_hash TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_login_tokens_hash ON login_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_login_tokens_org  ON login_tokens(org_id);

-- HttpOnly session cookies (24h TTL, deleted on logout)
CREATE TABLE IF NOT EXISTS dashboard_sessions (
    id         UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id     UUID        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    token_hash TEXT        NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sessions_hash ON dashboard_sessions(token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_org  ON dashboard_sessions(org_id);

COMMIT;

-- GitHub OAuth: add github_id to organizations
ALTER TABLE organizations ADD COLUMN IF NOT EXISTS github_id TEXT UNIQUE;

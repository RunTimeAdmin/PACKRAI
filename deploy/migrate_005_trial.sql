-- migrate_005_trial.sql
-- Adds DB-tracked trial support: trial_ends_at column and 'trial' plan value.

BEGIN;

-- 1. Drop the existing inline check constraint (Postgres auto-names it).
ALTER TABLE organizations
    DROP CONSTRAINT IF EXISTS organizations_plan_check;

-- 2. Re-add with 'trial' included.
ALTER TABLE organizations
    ADD CONSTRAINT organizations_plan_check
    CHECK (plan IN ('free','trial','starter','team','business','enterprise'));

-- 3. Add trial_ends_at column (idempotent).
ALTER TABLE organizations
    ADD COLUMN IF NOT EXISTS trial_ends_at TIMESTAMPTZ;

-- 4. Change default so future INSERTs land on 'trial' instead of 'free'.
ALTER TABLE organizations
    ALTER COLUMN plan SET DEFAULT 'trial';

COMMIT;

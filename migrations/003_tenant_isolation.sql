-- 003: Cross-tenant isolation hardening
--
-- Bug: `smtp_credentials.username` was only unique per tenant
-- (UNIQUE(tenant_id, username)), while the SMTP AUTH path looks credentials
-- up by username alone (there is no tenant context on an unauthenticated
-- SMTP connection — the lookup is what establishes the session tenant).
-- Two tenants could therefore both create a credential named "agent", and
-- AUTH would match whichever row the database returned first, granting one
-- tenant's privileges to the other.
--
-- Fix: make the username globally unique. Credential creation APIs should
-- use tenant-namespaced usernames (e.g. "tenant-slug.bot@domain") when the
-- same human-readable name is wanted in two tenants.
--
-- The migration is idempotent: safe to re-run after a partial or manual
-- intervention (duplicates no longer exist, constraints already in place).

-- Resolve cross-tenant duplicate usernames by prefixing each duplicate
-- with its tenant id: globally unique, stable, and reversible. The
-- `migration_` prefix keeps the renamed row distinguishable from a literal
-- credential someone actually named "<uuid>.<name>" and makes accidental
-- re-prefixing impossible on re-run (already-prefixed names are unique).
DO $$
DECLARE
    dup RECORD;
BEGIN
    IF EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'smtp_credentials_username_key'
    ) THEN
        -- Already applied; nothing to do.
        RETURN;
    END IF;

    FOR dup IN
        SELECT username
        FROM smtp_credentials
        GROUP BY username
        HAVING COUNT(DISTINCT tenant_id) > 1
    LOOP
        UPDATE smtp_credentials
        SET username = 'migration_003_' || tenant_id::text || '.' || username
        WHERE username = dup.username;
    END LOOP;
END $$;

ALTER TABLE smtp_credentials
    DROP CONSTRAINT IF EXISTS smtp_credentials_tenant_id_username_key;

-- Idempotent unique constraint on username.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'smtp_credentials_username_key'
    ) THEN
        ALTER TABLE smtp_credentials
            ADD CONSTRAINT smtp_credentials_username_key UNIQUE (username);
    END IF;
END $$;

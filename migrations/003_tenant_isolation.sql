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

-- Drop the per-tenant uniqueness and enforce global uniqueness instead.
-- If duplicate usernames already exist in different tenants this fails;
-- rename existing offenders deterministically first.
DO $$
DECLARE
    dup RECORD;
BEGIN
    FOR dup IN
        SELECT username
        FROM smtp_credentials
        GROUP BY username
        HAVING COUNT(DISTINCT tenant_id) > 1
    LOOP
        -- Prefix each duplicate with its tenant id: globally unique,
        -- stable, and reversible.
        UPDATE smtp_credentials
        SET username = tenant_id::text || '.' || username
        WHERE username = dup.username;
    END LOOP;
END $$;

ALTER TABLE smtp_credentials
    DROP CONSTRAINT smtp_credentials_tenant_id_username_key;

ALTER TABLE smtp_credentials
    ADD CONSTRAINT smtp_credentials_username_key UNIQUE (username);

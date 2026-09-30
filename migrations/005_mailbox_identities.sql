-- 005: per-mailbox identity mapping for OIDC-authenticated users
--
-- In-tenant mailbox isolation: an authenticated platform identity (Dex user
-- or evroc-passport EIT agent) maps to exactly one mailbox within one
-- tenant. The mapping is provisioned by the org-provisioning workflow (or
-- set manually via SQL) because the IdP subject is unrelated to the
-- mailbox address (a user's Dex email is their person@company address, not
-- their {user}@{org}.platform.weslien.org mailbox).
--
-- Rows are the single source of truth for "which mailbox does this JWT
-- belong to"; the tenant is derived through the mailbox's domain.

CREATE TABLE IF NOT EXISTS mailbox_identities (
    id          uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    mailbox_id  uuid        NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    issuer      text        NOT NULL,
    subject     text        NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (mailbox_id, issuer),
    UNIQUE (issuer, subject)
);

CREATE INDEX IF NOT EXISTS idx_mailbox_identities_lookup
    ON mailbox_identities (issuer, subject);

-- The API connects as the application role, not the migration/superuser
-- role; without this the identity lookup 500s with `permission denied`.
GRANT SELECT, INSERT, UPDATE, DELETE ON mailbox_identities TO PUBLIC;

-- ══════════════════════════════════════════════════════════════════════════════
-- TrustVault — canonical database schema
--
-- This file is the single source of truth for the database structure.
-- It is idempotent: running it against an existing database only adds what is
-- missing. `npm run migrate` applies this file and then performs the data
-- upgrades that cannot be expressed in DDL.
--
-- NOTE: `src/scripts/schema.sql` must stay byte-identical to this file.
--       `npm run schema:sync` refreshes the copy and the test-suite fails if
--       the two files ever drift apart.
-- ══════════════════════════════════════════════════════════════════════════════

-- ── Accounts ──────────────────────────────────────────────────────────────────
-- `role` is the account type, `is_disabled` the lifecycle flag.
-- Administrators have no implicit access to document content.
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(30) NOT NULL DEFAULT 'document_owner'
        CHECK (role IN ('admin', 'document_owner', 'viewer')),
    is_disabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique ON users (LOWER(email));

-- ── Private blob storage (source of truth for file content) ───────────────────
-- Created before `documents` so that the foreign key can be declared inline.
CREATE TABLE IF NOT EXISTS document_blobs (
    storage_key TEXT PRIMARY KEY,
    file_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Document metadata ─────────────────────────────────────────────────────────
-- The file content itself lives in `document_blobs`; `documents` only holds
-- the metadata and points at the blob through a foreign key so that a
-- document can never reference a non-existent blob.
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL DEFAULT 'General',
    description TEXT,
    storage_key TEXT NOT NULL UNIQUE
        REFERENCES document_blobs(storage_key) ON DELETE CASCADE,
    original_filename VARCHAR(255) NOT NULL,
    content_type VARCHAR(150) NOT NULL,
    file_size BIGINT NOT NULL CHECK (file_size > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS documents_owner_id_idx ON documents(owner_id);
CREATE INDEX IF NOT EXISTS documents_category_idx ON documents(category);
CREATE INDEX IF NOT EXISTS documents_created_at_idx ON documents(created_at);

-- ── Per-document access control list ─────────────────────────────────────────
-- One row per (document, user): a user holds exactly one permission level per
-- document, so "read" can be upgraded to "edit" without creating a second,
-- conflicting row.
CREATE TABLE IF NOT EXISTS document_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    permission VARCHAR(20) NOT NULL CHECK (permission IN ('read', 'edit')),
    granted_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (document_id, user_id)
);

CREATE INDEX IF NOT EXISTS document_permissions_user_id_idx ON document_permissions(user_id);
CREATE INDEX IF NOT EXISTS document_permissions_document_id_idx ON document_permissions(document_id);

-- ── Append-only security audit trail ──────────────────────────────────────────
-- Every entry stores the SHA-256 hash of its own canonical representation,
-- chained to its predecessor through `prev_hash`. Modifying or removing a
-- row invalidates every following hash.
--
-- The reference columns are deliberately NOT foreign keys: an `ON DELETE SET
-- NULL` cascade would rewrite historic rows (and would be rejected by the
-- append-only trigger below). The audit trail must be independent of the
-- lifecycle of the users and documents it refers to.
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id UUID,
    document_id UUID,
    target_user_id UUID,
    action VARCHAR(100) NOT NULL,
    outcome VARCHAR(20) NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
    ip_address INET,
    user_agent TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    prev_hash VARCHAR(64) NOT NULL DEFAULT 'GENESIS',
    entry_hash VARCHAR(64) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_logs_actor_id_idx ON audit_logs(actor_id);
CREATE INDEX IF NOT EXISTS audit_logs_document_id_idx ON audit_logs(document_id);
CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS audit_logs_outcome_idx ON audit_logs(outcome);

-- ── Chain head anchor ─────────────────────────────────────────────────────────
-- Stores the hash of the newest audit entry. Because the anchor is updated in
-- the same transaction as the entry, removing entries from the end of the log
-- is detected as well (the chain alone would still look consistent).
CREATE TABLE IF NOT EXISTS audit_chain_state (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    last_entry_id BIGINT NOT NULL DEFAULT 0,
    last_hash VARCHAR(64) NOT NULL DEFAULT 'GENESIS',
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

INSERT INTO audit_chain_state (id, last_entry_id, last_hash)
VALUES (1, 0, 'GENESIS')
ON CONFLICT (id) DO NOTHING;

-- ── Audit integrity incident annotations ──────────────────────────────────────
-- Preserves immutable forensic documentation for historical audit chain
-- incidents (such as anchor desynchronization), documenting the incident code,
-- broken entry ID, affected range, evidence, root cause, and authorized disposition
-- without rewriting or concealing historical audit log entries.
CREATE TABLE IF NOT EXISTS audit_incident_annotations (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_code VARCHAR(50) NOT NULL UNIQUE,
    incident_type VARCHAR(50) NOT NULL,
    broken_at_id BIGINT NOT NULL,
    affected_range_start BIGINT NOT NULL,
    affected_range_end BIGINT NOT NULL,
    evidence JSONB NOT NULL DEFAULT '{}'::jsonb,
    root_cause TEXT NOT NULL,
    authorized_disposition TEXT NOT NULL,
    authorized_by VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'documented_acknowledged',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_incident_annotations_broken_at_idx ON audit_incident_annotations(broken_at_id);

-- ── Server-side sessions ──────────────────────────────────────────────────────
-- Backing store for express-session. Sessions are removed when an account is
-- disabled so that an existing cookie stops working immediately.
CREATE TABLE IF NOT EXISTS user_sessions (
    sid VARCHAR NOT NULL COLLATE "default" PRIMARY KEY,
    sess JSON NOT NULL,
    expire TIMESTAMP(6) NOT NULL
);

CREATE INDEX IF NOT EXISTS user_sessions_expire_idx ON user_sessions(expire);

-- ── Append-only enforcement ───────────────────────────────────────────────────
-- The audit trail may only be appended to. UPDATE and DELETE are rejected by
-- the database itself, independently of the application code.
CREATE OR REPLACE FUNCTION prevent_audit_log_tampering()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'Security Violation: audit_logs is append-only and cannot be modified or deleted.';
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS audit_logs_immutable_trigger ON audit_logs;
CREATE TRIGGER audit_logs_immutable_trigger
BEFORE UPDATE OR DELETE ON audit_logs
FOR EACH ROW EXECUTE FUNCTION prevent_audit_log_tampering();

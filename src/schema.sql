
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash TEXT NOT NULL,
    role VARCHAR(30) NOT NULL DEFAULT 'document_owner'
        CHECK (role IN ('admin', 'document_owner', 'viewer')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_email_unique
ON users (LOWER(email));


-- Documents and their private storage metadata
CREATE TABLE IF NOT EXISTS documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id UUID NOT NULL
        REFERENCES users(id) ON DELETE RESTRICT,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL DEFAULT 'General',
    description TEXT,
    storage_key TEXT NOT NULL UNIQUE,
    original_filename VARCHAR(255) NOT NULL,
    content_type VARCHAR(150) NOT NULL,
    file_size BIGINT NOT NULL CHECK (file_size > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS documents_owner_id_idx
ON documents(owner_id);

CREATE INDEX IF NOT EXISTS documents_category_idx
ON documents(category);

CREATE INDEX IF NOT EXISTS documents_created_at_idx
ON documents(created_at);


-- Per-document user permissions
CREATE TABLE IF NOT EXISTS document_permissions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL
        REFERENCES documents(id) ON DELETE CASCADE,
    user_id UUID NOT NULL
        REFERENCES users(id) ON DELETE CASCADE,
    permission VARCHAR(20) NOT NULL
        CHECK (permission IN ('view', 'download')),
    granted_by UUID
        REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (document_id, user_id, permission)
);

CREATE INDEX IF NOT EXISTS document_permissions_user_id_idx
ON document_permissions(user_id);

CREATE INDEX IF NOT EXISTS document_permissions_document_id_idx
ON document_permissions(document_id);


-- Security audit trail
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    actor_id UUID
        REFERENCES users(id) ON DELETE SET NULL,
    document_id UUID
        REFERENCES documents(id) ON DELETE SET NULL,
    target_user_id UUID
        REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,
    outcome VARCHAR(20) NOT NULL
        CHECK (outcome IN ('success', 'denied', 'failure')),
    ip_address INET,
    user_agent TEXT,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_logs_actor_id_idx
ON audit_logs(actor_id);

CREATE INDEX IF NOT EXISTS audit_logs_document_id_idx
ON audit_logs(document_id);

CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx
ON audit_logs(created_at);

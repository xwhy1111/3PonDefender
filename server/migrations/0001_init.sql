CREATE TABLE IF NOT EXISTS admin_accounts (
    id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    totp_secret_ciphertext BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS recovery_keys (
    id UUID PRIMARY KEY,
    admin_id UUID NOT NULL REFERENCES admin_accounts(id),
    verifier TEXT NOT NULL,
    display_ciphertext BYTEA NOT NULL,
    used_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    model TEXT NOT NULL,
    manufacturer TEXT NOT NULL,
    android_api INTEGER NOT NULL,
    hyperos_version TEXT NOT NULL,
    device_public_key BYTEA,
    consent_version TEXT,
    consented_at TIMESTAMPTZ,
    last_seen_at TIMESTAMPTZ,
    policy_version BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS policy_revisions (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id),
    version BIGINT NOT NULL,
    requested_json JSONB NOT NULL,
    effective_json JSONB,
    signature TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    applied_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS install_requests (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id),
    package_name TEXT NOT NULL,
    display_name TEXT NOT NULL,
    version TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    signer_sha256 TEXT,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS commands (
    id UUID PRIMARY KEY,
    device_id UUID NOT NULL REFERENCES devices(id),
    kind TEXT NOT NULL,
    payload JSONB NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    actor TEXT NOT NULL,
    event TEXT NOT NULL,
    target TEXT NOT NULL,
    message TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);


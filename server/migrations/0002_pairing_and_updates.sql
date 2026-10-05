ALTER TABLE devices
    ADD COLUMN IF NOT EXISTS base_url TEXT NOT NULL DEFAULT 'https://control.example.com',
    ADD COLUMN IF NOT EXISTS device_token_hash TEXT;

CREATE TABLE IF NOT EXISTS pairing_sessions (
    id UUID PRIMARY KEY,
    pairing_token_hash TEXT NOT NULL,
    base_url TEXT NOT NULL,
    device_name TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    claimed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS pairing_sessions_expires_idx ON pairing_sessions (expires_at);

CREATE TABLE IF NOT EXISTS update_releases (
    version_code BIGINT PRIMARY KEY,
    package_name TEXT NOT NULL,
    version_name TEXT NOT NULL,
    artifact_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    signer_sha256 TEXT NOT NULL,
    mandatory BOOLEAN NOT NULL DEFAULT false,
    published_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at TIMESTAMPTZ
);

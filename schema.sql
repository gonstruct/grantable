-- The tables grantable's SQL store reads and writes, for PostgreSQL. Copy
-- them into a migration of the application; grantable never migrates.

-- An application that may ask for tokens. id is its client_id: one this
-- server generated at registration, or the URL of its metadata document.
CREATE TABLE oauth_clients (
    id TEXT NOT NULL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    uri TEXT,
    logo_uri TEXT,
    redirect_uris JSONB NOT NULL,
    grant_types JSONB NOT NULL,
    auth_method VARCHAR(32) NOT NULL,
    secret_hash VARCHAR(64),
    document BOOLEAN NOT NULL,
    document_expires_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One authorization request, from the redirect to the consent page to the
-- code. subject is who the application approved it for.
CREATE TABLE oauth_authorization_requests (
    id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    state TEXT,
    code_challenge VARCHAR(128) NOT NULL,
    resource TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    subject TEXT,
    granted_scopes TEXT,
    code_hash VARCHAR(64) UNIQUE,
    approved_at TIMESTAMPTZ,
    denied_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX oauth_authorization_requests_client_id_idx ON oauth_authorization_requests (client_id);

-- An access token and the refresh token beside it. family is the
-- authorization request it descends from, through every rotation.
CREATE TABLE oauth_tokens (
    id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
    family UUID NOT NULL REFERENCES oauth_authorization_requests (id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES oauth_clients (id) ON DELETE CASCADE,
    subject TEXT NOT NULL,
    scopes TEXT NOT NULL,
    resource TEXT NOT NULL,
    access_hash VARCHAR(64) NOT NULL UNIQUE,
    access_expires_at TIMESTAMPTZ NOT NULL,
    refresh_hash VARCHAR(64) UNIQUE,
    refresh_expires_at TIMESTAMPTZ,
    rotated_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX oauth_tokens_family_idx ON oauth_tokens (family);
CREATE INDEX oauth_tokens_subject_idx ON oauth_tokens (subject);
CREATE INDEX oauth_tokens_client_id_idx ON oauth_tokens (client_id);

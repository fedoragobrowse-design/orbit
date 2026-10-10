CREATE TABLE oauth_clients (
 id uuid PRIMARY KEY,
 owner_id uuid NOT NULL REFERENCES users(id),
 connector text NOT NULL CHECK (connector IN ('google', 'outlook', 'github')),
 client_id text NOT NULL CHECK (octet_length(client_id) BETWEEN 1 AND 1024),
 credential_id uuid,
 revision bigint NOT NULL DEFAULT 1,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE (owner_id, connector),
 FOREIGN KEY (owner_id, credential_id) REFERENCES secrets_metadata (owner_id, id)
);
CREATE INDEX oauth_clients_owner ON oauth_clients (owner_id, connector);

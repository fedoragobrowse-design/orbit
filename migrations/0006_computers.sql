CREATE TABLE computer_pairing_codes (
 id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users(id), code_hash text NOT NULL UNIQUE,
 expires_at timestamptz NOT NULL, used_at timestamptz, created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE computer_nodes (
 id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users(id), principal_id uuid NOT NULL,
 public_key text NOT NULL, session_hash text NOT NULL UNIQUE, session_expires_at timestamptz NOT NULL,
 display_name text NOT NULL DEFAULT 'Computer', revision bigint NOT NULL DEFAULT 1,
 last_seen timestamptz, revoked_at timestamptz, capabilities jsonb NOT NULL DEFAULT '{}',
 ack_sequence bigint NOT NULL DEFAULT 0, connection_id uuid, created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(owner_id,id), FOREIGN KEY(owner_id,principal_id) REFERENCES principals(owner_id,id)
);
CREATE TABLE computer_roots (
 owner_id uuid NOT NULL, node_id uuid NOT NULL, id uuid NOT NULL,
 display_name text NOT NULL, mode text NOT NULL CHECK(mode IN ('READ','READ_WRITE','ASK')),
 revision bigint NOT NULL CHECK(revision>0), revoked boolean NOT NULL DEFAULT false,
 mutation_available boolean NOT NULL DEFAULT false, status jsonb NOT NULL DEFAULT '{}',
 PRIMARY KEY(owner_id,id), UNIQUE(owner_id,node_id,id), FOREIGN KEY(owner_id,node_id) REFERENCES computer_nodes(owner_id,id)
);
CREATE TABLE computer_files (
 owner_id uuid NOT NULL, node_id uuid NOT NULL, root_id uuid NOT NULL, file_id uuid NOT NULL,
 relative_path text NOT NULL, version text NOT NULL, digest text, size bigint NOT NULL,
 metadata jsonb NOT NULL DEFAULT '{}', updated_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(owner_id,node_id,root_id,file_id),
 FOREIGN KEY(owner_id,node_id,root_id) REFERENCES computer_roots(owner_id,node_id,id)
);
CREATE TABLE computer_requests (
 owner_id uuid NOT NULL, node_id uuid NOT NULL, request_id uuid NOT NULL, authorization_id uuid NOT NULL,
 action_hash text NOT NULL, payload jsonb NOT NULL, response jsonb, state text NOT NULL DEFAULT 'PENDING',
 connection_id uuid, expires_at timestamptz NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(owner_id,node_id,request_id), UNIQUE(owner_id,authorization_id),
 FOREIGN KEY(owner_id,node_id) REFERENCES computer_nodes(owner_id,id)
);
CREATE TABLE computer_event_receipts (
 owner_id uuid NOT NULL, node_id uuid NOT NULL, sequence bigint NOT NULL, event_id uuid NOT NULL,
 PRIMARY KEY(owner_id,node_id,sequence), FOREIGN KEY(owner_id,node_id) REFERENCES computer_nodes(owner_id,id),
 FOREIGN KEY(owner_id,event_id) REFERENCES events(owner_id,id)
);
CREATE INDEX computer_requests_delivery ON computer_requests(node_id,state,expires_at);
CREATE INDEX computer_nodes_online ON computer_nodes(last_seen) WHERE revoked_at IS NULL;

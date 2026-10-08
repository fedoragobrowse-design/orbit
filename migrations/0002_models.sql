CREATE TABLE secrets_metadata (
 id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users(id), key_version integer NOT NULL CHECK(key_version>0), purpose text NOT NULL,
 nonce bytea NOT NULL CHECK(octet_length(nonce)=24), ciphertext bytea NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), revoked_at timestamptz,
 UNIQUE(owner_id,id)
);
CREATE TABLE model_providers (
 id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users(id), configuration jsonb NOT NULL, credential_id uuid,
 revision bigint NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(owner_id,id), FOREIGN KEY(owner_id,credential_id) REFERENCES secrets_metadata(owner_id,id)
);
CREATE TABLE models (
 id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users(id), provider_id uuid NOT NULL, configuration jsonb NOT NULL,
 revision bigint NOT NULL DEFAULT 1, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(owner_id,id), FOREIGN KEY(owner_id,provider_id) REFERENCES model_providers(owner_id,id)
);
CREATE INDEX models_owner_provider ON models(owner_id,provider_id,id);
CREATE TABLE model_budgets (
 owner_id uuid PRIMARY KEY REFERENCES users(id), task_usd double precision NOT NULL DEFAULT 1 CHECK(task_usd>=0),
 day_usd double precision NOT NULL DEFAULT 5 CHECK(day_usd>=0), month_usd double precision NOT NULL DEFAULT 50 CHECK(month_usd>=0),
 agent_day_usd double precision NOT NULL DEFAULT 5 CHECK(agent_day_usd>=0), max_model_calls integer NOT NULL DEFAULT 12 CHECK(max_model_calls>0),
 max_input_tokens bigint NOT NULL DEFAULT 100000 CHECK(max_input_tokens>0), max_output_tokens bigint NOT NULL DEFAULT 24000 CHECK(max_output_tokens>0)
);
CREATE TABLE model_calls (
 id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users(id), task_id uuid, agent_id uuid, provider_id uuid NOT NULL, model_id uuid NOT NULL,
 model text NOT NULL, local boolean NOT NULL, privacy_class text NOT NULL, operation text NOT NULL, state text NOT NULL DEFAULT 'RESERVED',
 reserved_micro_usd bigint NOT NULL CHECK(reserved_micro_usd>=0), actual_micro_usd bigint CHECK(actual_micro_usd>=0), pricing_known boolean NOT NULL,
 reserved_input_tokens bigint NOT NULL CHECK(reserved_input_tokens>=0), reserved_output_tokens bigint NOT NULL CHECK(reserved_output_tokens>=0),
 input_tokens bigint, output_tokens bigint, cached_tokens bigint, usage_known boolean NOT NULL DEFAULT false, latency_ms bigint,
 created_at timestamptz NOT NULL DEFAULT now(), settled_at timestamptz, UNIQUE(owner_id,id), FOREIGN KEY(owner_id,task_id) REFERENCES tasks(owner_id,id)
);
CREATE INDEX model_calls_owner_time ON model_calls(owner_id,created_at);
CREATE INDEX model_calls_task ON model_calls(owner_id,task_id);
CREATE INDEX model_calls_agent ON model_calls(owner_id,agent_id,created_at);

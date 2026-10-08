CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE memory_records (
 id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users(id), type text NOT NULL CHECK(type IN ('PROFILE','PREFERENCE','PERSON','PROJECT','TASK','DECISION','EVENT','ROUTINE','DOCUMENT','TEMPORARY_CONTEXT')),
 subject text NOT NULL, normalized_subject text NOT NULL, entity_key text NOT NULL, value jsonb NOT NULL,
 source text NOT NULL, source_reference text NOT NULL, source_references jsonb NOT NULL DEFAULT '[]', confidence double precision NOT NULL CHECK(confidence BETWEEN 0 AND 1),
 trust_level text NOT NULL, privacy_class text NOT NULL CHECK(privacy_class IN ('PUBLIC','PERSONAL','PRIVATE','HIGHLY_PRIVATE','SECRET')),
 status text NOT NULL CHECK(status IN ('ACTIVE','SUPERSEDED','EXPIRED','FORGOTTEN')) DEFAULT 'ACTIVE',
 created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), last_verified_at timestamptz,
 valid_from timestamptz NOT NULL DEFAULT now(), valid_until timestamptz, related_entities jsonb NOT NULL DEFAULT '[]',
 version bigint NOT NULL DEFAULT 1, supersedes_id uuid, forgotten_at timestamptz,
 UNIQUE(owner_id,id), FOREIGN KEY(owner_id,supersedes_id) REFERENCES memory_records(owner_id,id), CHECK(valid_until IS NULL OR valid_until>valid_from)
);
CREATE INDEX memory_active ON memory_records(owner_id,type,status,valid_until);
CREATE INDEX memory_entity ON memory_records(owner_id,type,entity_key);
CREATE TABLE memory_versions (
 owner_id uuid NOT NULL, memory_id uuid NOT NULL, version bigint NOT NULL, record jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(owner_id,memory_id,version), FOREIGN KEY(owner_id,memory_id) REFERENCES memory_records(owner_id,id) ON DELETE CASCADE
);
CREATE TABLE memory_relations (
 owner_id uuid NOT NULL, from_id uuid NOT NULL, to_id uuid NOT NULL, kind text NOT NULL CHECK(kind IN ('PROJECT_MEMBER','RELATED','SUPERSEDES')),
 PRIMARY KEY(owner_id,from_id,to_id,kind), FOREIGN KEY(owner_id,from_id) REFERENCES memory_records(owner_id,id) ON DELETE CASCADE, FOREIGN KEY(owner_id,to_id) REFERENCES memory_records(owner_id,id) ON DELETE CASCADE
);
CREATE TABLE memory_embeddings (
 owner_id uuid NOT NULL, memory_id uuid NOT NULL, provider_id uuid NOT NULL, model_id uuid NOT NULL, dimension integer NOT NULL CHECK(dimension BETWEEN 1 AND 65536), embedding vector NOT NULL,
 memory_version bigint NOT NULL, created_at timestamptz NOT NULL DEFAULT now(), PRIMARY KEY(owner_id,memory_id,provider_id,model_id,dimension),
 FOREIGN KEY(owner_id,memory_id) REFERENCES memory_records(owner_id,id) ON DELETE CASCADE, CHECK(vector_dims(embedding)=dimension)
);
CREATE TABLE memory_candidates (
 id uuid PRIMARY KEY, owner_id uuid NOT NULL REFERENCES users(id), candidate jsonb NOT NULL, conflicts_with uuid, state text NOT NULL CHECK(state IN ('PENDING_CONFIRMATION','ACCEPTED','REJECTED','FORGOTTEN')),
 memory_id uuid, created_at timestamptz NOT NULL DEFAULT now(), UNIQUE(owner_id,id), FOREIGN KEY(owner_id,conflicts_with) REFERENCES memory_records(owner_id,id), FOREIGN KEY(owner_id,memory_id) REFERENCES memory_records(owner_id,id)
);
CREATE TABLE memory_agent_scopes (
 owner_id uuid NOT NULL REFERENCES users(id), agent_id uuid NOT NULL, allowed_types text[] NOT NULL, project_ids uuid[] NOT NULL DEFAULT '{}', max_privacy text NOT NULL DEFAULT 'PRIVATE', can_write boolean NOT NULL DEFAULT false,
 PRIMARY KEY(owner_id,agent_id)
);
CREATE TABLE retention_settings (
 owner_id uuid PRIMARY KEY REFERENCES users(id), event_body_days integer NOT NULL DEFAULT 30 CHECK(event_body_days>=1), conversation_body_days integer NOT NULL DEFAULT 90 CHECK(conversation_body_days>=1), runtime_artifact_days integer NOT NULL DEFAULT 30 CHECK(runtime_artifact_days>=1), connector_cache_days integer NOT NULL DEFAULT 30 CHECK(connector_cache_days>=1), last_cleanup_at timestamptz
);
CREATE TABLE memory_tool_results (
 owner_id uuid NOT NULL REFERENCES users(id), action_id uuid NOT NULL, result jsonb NOT NULL, memory_id uuid, created_at timestamptz NOT NULL DEFAULT now(),
 PRIMARY KEY(owner_id,action_id), FOREIGN KEY(owner_id,memory_id) REFERENCES memory_records(owner_id,id)
);

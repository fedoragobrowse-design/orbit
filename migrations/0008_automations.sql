CREATE TABLE automations(
 id uuid PRIMARY KEY,
 owner_id uuid NOT NULL REFERENCES users(id),
 enabled boolean NOT NULL DEFAULT true,
 "trigger" jsonb NOT NULL CHECK("trigger" ? 'kind'),
 filters jsonb NOT NULL DEFAULT '[]',
 agent_id uuid,
 instructions text NOT NULL DEFAULT '',
 policy_scope jsonb NOT NULL DEFAULT '{}',
 model_role text NOT NULL DEFAULT 'FAST' CHECK(model_role IN ('FAST','PRIVATE','REASONING','CODING','VISION','EMBEDDING')),
 notification_behavior text NOT NULL DEFAULT 'NONE' CHECK(notification_behavior IN ('NONE','IN_APP')),
 timezone text NOT NULL DEFAULT 'UTC',
 version bigint NOT NULL DEFAULT 1,
 revision bigint NOT NULL DEFAULT 1,
 next_run timestamptz,
 last_run timestamptz,
 created_at timestamptz NOT NULL DEFAULT now(),
 updated_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(owner_id,id),
 FOREIGN KEY(owner_id,agent_id) REFERENCES agent_definitions(owner_id,id) ON DELETE SET NULL
);
CREATE INDEX automations_due ON automations(next_run,id) WHERE enabled AND next_run IS NOT NULL;
CREATE INDEX automations_owner_next ON automations(owner_id,next_run,id);
CREATE TABLE automation_fires(
 id uuid PRIMARY KEY,
 owner_id uuid NOT NULL REFERENCES users(id),
 automation_id uuid NOT NULL,
 fire_key text NOT NULL,
 window_start timestamptz NOT NULL,
 window_end timestamptz NOT NULL,
 missed_count integer NOT NULL DEFAULT 0 CHECK(missed_count >= 0),
 state text NOT NULL DEFAULT 'FIRED' CHECK(state IN ('QUEUED','FIRED','SUPERSEDED','CANCELLED')),
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(owner_id,id),
 UNIQUE(automation_id,fire_key),
 FOREIGN KEY(owner_id,automation_id) REFERENCES automations(owner_id,id) ON DELETE CASCADE,
 CHECK(window_end >= window_start)
);
CREATE INDEX automation_fires_lookup ON automation_fires(owner_id,automation_id,created_at);
CREATE TABLE notification_sinks(
 id uuid PRIMARY KEY,
 owner_id uuid NOT NULL REFERENCES users(id),
 automation_id uuid,
 kind text NOT NULL DEFAULT 'IN_APP' CHECK(kind IN ('IN_APP')),
 config jsonb NOT NULL DEFAULT '{}',
 created_at timestamptz NOT NULL DEFAULT now(),
 UNIQUE(owner_id,id),
 FOREIGN KEY(owner_id,automation_id) REFERENCES automations(owner_id,id) ON DELETE CASCADE
);

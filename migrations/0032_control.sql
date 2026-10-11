-- Control plane: owner questions (ask-owner tool), local skill registry,
-- agent settings-management consent.
CREATE TABLE IF NOT EXISTS agent_questions(
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL,
  task_id UUID NOT NULL,
  agent_id UUID,
  question TEXT NOT NULL CHECK (char_length(question) BETWEEN 1 AND 2000),
  options JSONB NOT NULL DEFAULT '[]'::jsonb,
  answer TEXT CHECK (answer IS NULL OR char_length(answer) <= 2000),
  state TEXT NOT NULL DEFAULT 'OPEN' CHECK (state IN ('OPEN','ANSWERED','CANCELLED')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  answered_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS agent_questions_owner_task ON agent_questions(owner_id, task_id);
-- Local skill registry: curated in-repo/user skills the agent can invoke.
-- Marketplace installs stay separate (self-asserted, sandboxed).
CREATE TABLE IF NOT EXISTS skills(
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL,
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 120),
  description TEXT NOT NULL DEFAULT '' CHECK (char_length(description) <= 2000),
  entrypoint TEXT NOT NULL DEFAULT '' CHECK (char_length(entrypoint) <= 512),
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(owner_id, name)
);
-- Agent settings consent: owner allows the agent to change settings itself.
UPDATE settings
SET value = value || '{"agent_may_change_settings":false,"agent_may_manage_mcp":false}'::jsonb
WHERE NOT (value ? 'agent_may_change_settings');

CREATE TABLE ai_inbox(
  id uuid NOT NULL,
  owner_id uuid NOT NULL REFERENCES users(id),
  source text NOT NULL DEFAULT '',
  title text NOT NULL DEFAULT '',
  body text NOT NULL DEFAULT '',
  received_at timestamptz NOT NULL DEFAULT now(),
  handled boolean NOT NULL DEFAULT false,
  PRIMARY KEY(owner_id, id)
);
CREATE INDEX ai_inbox_owner_received ON ai_inbox(owner_id, received_at DESC);
-- Inbox tab + ingest endpoints stay hidden until the owner opts in.
UPDATE settings
SET value = value || '{"inbox_enabled":false}'::jsonb
WHERE NOT (value ? 'inbox_enabled');
ALTER TABLE settings
  ALTER COLUMN value SET DEFAULT '{"installation_mode":"LOCAL_ONLY","autonomy_mode":"OBSERVE","allow_private_cloud":false,"agent_backend":"OMP","inbox_enabled":false}';

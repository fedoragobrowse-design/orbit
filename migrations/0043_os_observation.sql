-- Durable bounded context stream (step 7): owner-scoped observation store
-- with idempotent ingest, per-source resume cursors, a publish outbox for
-- foundation delivery, per-turn context pins, and desktop consent records.
--
-- Cursor rule: source_cursors MUST advance only in the same transaction that
-- commits the corresponding source_observations row. Never bump a cursor for
-- an observation that did not commit; on crash/restart the poller replays
-- from the last committed cursor and the ingest UNIQUE
-- (owner_id, source_type, source_id, external_key, source_version) makes the
-- replay a no-op. Cursor-behind is safe (replay); cursor-ahead is data loss.
CREATE TABLE IF NOT EXISTS source_observations(
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL REFERENCES users(id),
  source_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  source_version TEXT NOT NULL,
  external_key TEXT NOT NULL,
  artifact_id UUID,
  trust_level TEXT NOT NULL CHECK (trust_level IN ('OWNER_AUTHENTICATED','SYSTEM','UNTRUSTED_EXTERNAL')),
  privacy_class TEXT NOT NULL CHECK (privacy_class IN ('PUBLIC','PERSONAL','PRIVATE','HIGHLY_PRIVATE','SECRET')),
  observed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at TIMESTAMPTZ,
  UNIQUE(owner_id, id),
  UNIQUE(owner_id, source_type, source_id, external_key, source_version),
  FOREIGN KEY(owner_id, artifact_id) REFERENCES artifacts(owner_id, id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS source_observations_owner_source ON source_observations(owner_id, source_type, source_id, observed_at, id);
CREATE INDEX IF NOT EXISTS source_observations_expiry ON source_observations(expires_at) WHERE expires_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS source_cursors(
  owner_id UUID NOT NULL REFERENCES users(id),
  source_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  cursor TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(owner_id, source_type, source_id)
);
CREATE TABLE IF NOT EXISTS observation_outbox(
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL REFERENCES users(id),
  observation_id UUID NOT NULL,
  event_id UUID,
  published_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(owner_id, id),
  FOREIGN KEY(owner_id, observation_id) REFERENCES source_observations(owner_id, id) ON DELETE CASCADE,
  FOREIGN KEY(owner_id, event_id) REFERENCES events(owner_id, id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS observation_outbox_unpublished ON observation_outbox(owner_id, created_at, id) WHERE published_at IS NULL;
CREATE TABLE IF NOT EXISTS model_context_sources(
  owner_id UUID NOT NULL REFERENCES users(id),
  task_id UUID NOT NULL,
  turn INTEGER NOT NULL CHECK (turn >= 0),
  source_type TEXT NOT NULL,
  source_id TEXT NOT NULL,
  source_version TEXT NOT NULL,
  artifact_id UUID,
  locator TEXT NOT NULL DEFAULT '',
  trust_level TEXT NOT NULL CHECK (trust_level IN ('OWNER_AUTHENTICATED','SYSTEM','UNTRUSTED_EXTERNAL')),
  PRIMARY KEY(owner_id, task_id, turn, source_type, source_id, source_version),
  FOREIGN KEY(owner_id, task_id) REFERENCES tasks(owner_id, id) ON DELETE CASCADE,
  FOREIGN KEY(owner_id, artifact_id) REFERENCES artifacts(owner_id, id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS model_context_sources_task ON model_context_sources(owner_id, task_id, turn);
CREATE TABLE IF NOT EXISTS desktop_observation_consents(
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL REFERENCES users(id),
  node_id UUID NOT NULL,
  source_app TEXT NOT NULL,
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  mode TEXT NOT NULL,
  retention_hours INTEGER NOT NULL CHECK (retention_hours >= 0),
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(owner_id, id),
  FOREIGN KEY(owner_id, node_id) REFERENCES computer_nodes(owner_id, id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS desktop_observation_consents_node ON desktop_observation_consents(owner_id, node_id, id);
-- Observation-stream event types (step 7): SOURCE_CHANGED (generic source
-- mutation), CALENDAR_DUE / REMINDER_DUE (due-sweep triggers). Extends the
-- events type check only; emission reuses events/event_deliveries via the
-- observation_outbox.event_id linkage.
ALTER TABLE events DROP CONSTRAINT IF EXISTS events_event_type_check;
ALTER TABLE events ADD CHECK(event_type IN ('EMAIL_RECEIVED','EMAIL_REPLIED','CALENDAR_CHANGED','FILE_CREATED','FILE_MODIFIED','FILE_DELETED','FILE_SHARED','COMPUTER_CONNECTED','COMPUTER_DISCONNECTED','DEVICE_EVENT','SCHEDULE_TRIGGER','TIMER_TRIGGER','WEBHOOK_RECEIVED','GITHUB_EVENT','HOME_EVENT','TASK_COMPLETED','TASK_FAILED','USER_MESSAGE','AGENT_MESSAGE','APPROVAL_ACCEPTED','APPROVAL_DENIED','CONNECTOR_CALENDAR_RECEIVED','CONNECTOR_HA_RECEIVED','CONNECTOR_GITHUB_RECEIVED','CONNECTOR_INBOX_RECEIVED','SOURCE_CHANGED','CALENDAR_DUE','REMINDER_DUE'));

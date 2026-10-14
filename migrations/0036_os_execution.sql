-- OS execution contract (step 1): governed execution sessions, ordered run
-- event stream, WAITING_FOR_INPUT task state, question linkage, and
-- ordered chat-message cursors.
CREATE TABLE IF NOT EXISTS execution_sessions(
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL REFERENCES users(id),
  task_id UUID,
  kind TEXT NOT NULL CHECK (kind IN ('SHELL','BROWSER','BACKEND')),
  state TEXT NOT NULL DEFAULT 'STARTING' CHECK (state IN ('STARTING','RUNNING','WAITING','STOPPED','FAILED')),
  execution_mode TEXT NOT NULL DEFAULT 'unsandboxed',
  sandboxed BOOLEAN NOT NULL DEFAULT false,
  revision BIGINT NOT NULL DEFAULT 1,
  last_seq BIGINT NOT NULL DEFAULT 0,
  expires_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(owner_id, id),
  FOREIGN KEY(owner_id, task_id) REFERENCES tasks(owner_id, id)
);
CREATE INDEX IF NOT EXISTS execution_sessions_owner_task ON execution_sessions(owner_id, task_id, id);
CREATE TABLE IF NOT EXISTS run_events(
  id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  owner_id UUID NOT NULL REFERENCES users(id),
  task_id UUID,
  run_id UUID,
  session_id UUID REFERENCES execution_sessions(id) ON DELETE SET NULL,
  kind TEXT NOT NULL CHECK (kind IN ('TEXT_DELTA','TOOL_STARTED','TOOL_RESULT','FILE_CHANGED','BROWSER_FRAME','TERMINAL_OUTPUT','QUESTION','STATUS','USAGE')),
  payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(owner_id, id),
  FOREIGN KEY(owner_id, task_id) REFERENCES tasks(owner_id, id)
);
CREATE INDEX IF NOT EXISTS run_events_owner_task ON run_events(owner_id, task_id, id);
CREATE INDEX IF NOT EXISTS run_events_session ON run_events(session_id, id);
-- Task parked awaiting owner input (ask_owner). Widen the state check.
ALTER TABLE tasks DROP CONSTRAINT IF EXISTS tasks_state_check;
ALTER TABLE tasks ADD CHECK (state IN ('QUEUED','RUNNING','WAITING_FOR_APPROVAL','WAITING_FOR_RESOURCE','WAITING_FOR_INPUT','COMPLETED','FAILED','CANCELLED','TIMED_OUT'));
CREATE OR REPLACE FUNCTION legal_task_transition() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN
 IF OLD.state<>NEW.state AND NOT ((OLD.state='QUEUED' AND NEW.state IN ('RUNNING','CANCELLED','TIMED_OUT','FAILED')) OR (OLD.state='RUNNING' AND NEW.state IN ('WAITING_FOR_APPROVAL','WAITING_FOR_RESOURCE','WAITING_FOR_INPUT','COMPLETED','FAILED','CANCELLED','TIMED_OUT')) OR (OLD.state IN ('WAITING_FOR_APPROVAL','WAITING_FOR_RESOURCE','WAITING_FOR_INPUT') AND NEW.state IN ('QUEUED','CANCELLED','TIMED_OUT','FAILED'))) THEN RAISE EXCEPTION 'illegal task transition'; END IF;
 RETURN NEW;
END $$;
-- Question linkage: which tool call asked, when it lapses, which run event
-- carries the owner-authenticated answer.
ALTER TABLE agent_questions ADD COLUMN IF NOT EXISTS call_id UUID;
ALTER TABLE agent_questions ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;
ALTER TABLE agent_questions ADD COLUMN IF NOT EXISTS answer_event_id BIGINT;
-- Ordered conversation timeline: identity cursor backfilled in
-- (created_at, id) order so existing rows keep deterministic positions.
-- Guarded: on a partially applied database the column may already be
-- GENERATED ALWAYS (identity columns reject direct UPDATE), in which
-- case the original backfill already ran and there is nothing to do.
ALTER TABLE chat_messages ADD COLUMN IF NOT EXISTS sequence BIGINT;
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'chat_messages' AND column_name = 'sequence'
      AND is_identity = 'YES'
  ) THEN
    WITH ordered AS (
      SELECT id, ROW_NUMBER() OVER (ORDER BY created_at, id) AS rn FROM chat_messages
    )
    UPDATE chat_messages m SET sequence = ordered.rn FROM ordered WHERE ordered.id = m.id AND m.sequence IS NULL;
    ALTER TABLE chat_messages ALTER COLUMN sequence SET NOT NULL;
    ALTER TABLE chat_messages ALTER COLUMN sequence ADD GENERATED ALWAYS AS IDENTITY;
    PERFORM setval(pg_get_serial_sequence('chat_messages', 'sequence'), (SELECT GREATEST(COALESCE(max(sequence), 0), 1) FROM chat_messages), false);
  END IF;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS chat_messages_sequence_unique ON chat_messages(sequence);
CREATE INDEX IF NOT EXISTS chat_messages_conversation_sequence ON chat_messages(owner_id, conversation_id, sequence);

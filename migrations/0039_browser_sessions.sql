--- Managed browser sessions (plan step 5): owner-scoped session state for
--- the private browser-host socket service. One row owns one browser context;
--- run events carry nav/loading/title + frame cursors. The profile column is
--- a sealed caller artifact reference (never plaintext cookies); sealed bytes
--- live in the artifact store, this column only names the artifact id.
CREATE TABLE IF NOT EXISTS browser_sessions(
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL REFERENCES users(id),
  task_id UUID REFERENCES tasks(id) ON DELETE SET NULL,
  url TEXT NOT NULL DEFAULT '',
  profile_sealed UUID,
  state TEXT NOT NULL DEFAULT 'STARTING' CHECK (state IN ('STARTING','RUNNING','PAUSED','STOPPED','FAILED')),
  takeover BOOLEAN NOT NULL DEFAULT false,
  dom_revision BIGINT NOT NULL DEFAULT 0,
  revision BIGINT NOT NULL DEFAULT 1,
  last_seq BIGINT NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS browser_sessions_owner_task ON browser_sessions(owner_id, task_id, id);
-- Session-scoped run events: run_events.session_id stays FK'd to
-- execution_sessions, so browser events use their own nullable column.
ALTER TABLE run_events ADD COLUMN IF NOT EXISTS browser_session_id UUID REFERENCES browser_sessions(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS run_events_browser_session ON run_events(browser_session_id, id);
-- A BROWSER execution row may point at its managed session for frame cursors.
ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS browser_session_id UUID;
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'execution_sessions_browser_fk') THEN
    ALTER TABLE execution_sessions ADD CONSTRAINT execution_sessions_browser_fk FOREIGN KEY(browser_session_id) REFERENCES browser_sessions(id) ON DELETE SET NULL;
  END IF;
END $$;

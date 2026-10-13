-- OS shell sessions (step 4): session-scoped columns on execution_sessions.
ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS workspace_id UUID REFERENCES workspace_entries(id) ON DELETE SET NULL;
ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS cwd TEXT NOT NULL DEFAULT '/';
ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS cols INTEGER NOT NULL DEFAULT 80;
ALTER TABLE execution_sessions ADD COLUMN IF NOT EXISTS rows INTEGER NOT NULL DEFAULT 24;
CREATE INDEX IF NOT EXISTS execution_sessions_owner_kind ON execution_sessions(owner_id, kind, id);

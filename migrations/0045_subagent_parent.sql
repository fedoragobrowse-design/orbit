-- Chat + tasks: explicit parent/child run grouping.
--
-- No parent linkage existed (tasks and agent_runs had no parent columns),
-- so child runs could only be guessed via a shared correlation_id. These
-- nullable columns make the linkage explicit and persisted at dispatch time:
-- tasks.parent_task_id points at the spawning task; agent_runs.parent_run_id
-- points at the parent run (run identity is the task id, so it carries the
-- same uuid). Both stay NULL for top-level runs; an empty child set is
-- simply no rows, never fabricated progress.
-- Lineage reads owner-scoped like every other query in this schema, so the
-- plain parent_task_id column is sufficient; no FK (tasks has no composite
-- UNIQUE(owner_id,id) to reference, and a id-only FK would drop the owner
-- scope this schema enforces everywhere). agent_runs rows bootstrap
-- idempotently, so parent_run_id likewise carries no FK: a child run row
-- must never fail on parent-row insert order.
ALTER TABLE tasks ADD COLUMN IF NOT EXISTS parent_task_id UUID;
CREATE INDEX IF NOT EXISTS tasks_parent ON tasks (owner_id, parent_task_id) WHERE parent_task_id IS NOT NULL;
-- No FK here: run rows bootstrap idempotently (ON CONFLICT DO NOTHING), so
-- a child run row must never fail on parent-row insert order. The tasks
-- parent_task_id column is the durable lineage; this column mirrors it for
-- run-level joins.
ALTER TABLE agent_runs ADD COLUMN IF NOT EXISTS parent_run_id UUID;
CREATE INDEX IF NOT EXISTS agent_runs_parent ON agent_runs (owner_id, parent_run_id) WHERE parent_run_id IS NOT NULL;

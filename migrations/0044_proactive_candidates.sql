-- Step 9: per-case proactive candidates + rule pacing config.
--
-- proactive_candidates is the durable queue the outbox consumer fills:
-- one row per (rule, fire key), so replaying an observation or due event
-- is a no-op via the UNIQUE guard. States track the full lifecycle:
-- PENDING (queued by consumer) -> SUGGESTED / AWAITING_APPROVAL (surfaced)
-- -> RUNNING -> DONE, with DISMISSED / SNOOZED / FAILED as terminal or
-- parked outcomes. task_id links the candidate to the task the owner
-- approves or that AUTO mode spawns. revision guards concurrent
-- approve/dismiss/snooze transitions (CAS, same pattern as due sweep).
CREATE TABLE IF NOT EXISTS proactive_candidates(
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL REFERENCES users(id),
  automation_id UUID NOT NULL,
  observation_id UUID,
  fire_key TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'PENDING' CHECK (state IN ('PENDING','SUGGESTED','AWAITING_APPROVAL','RUNNING','DONE','DISMISSED','SNOOZED','FAILED')),
  summary TEXT NOT NULL DEFAULT '',
  evidence_refs JSONB NOT NULL DEFAULT '[]',
  proposed_action JSONB NOT NULL DEFAULT '{}',
  task_id UUID,
  snoozed_until TIMESTAMPTZ,
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(owner_id, id),
  UNIQUE(owner_id, automation_id, fire_key),
  FOREIGN KEY(owner_id, automation_id) REFERENCES automations(owner_id, id) ON DELETE CASCADE,
  FOREIGN KEY(owner_id, observation_id) REFERENCES source_observations(owner_id, id) ON DELETE SET NULL,
  FOREIGN KEY(owner_id, task_id) REFERENCES tasks(owner_id, id) ON DELETE SET NULL
);
CREATE INDEX IF NOT EXISTS proactive_candidates_owner_state ON proactive_candidates(owner_id, state, created_at, id);
CREATE INDEX IF NOT EXISTS proactive_candidates_rule ON proactive_candidates(owner_id, automation_id, created_at, id);
CREATE INDEX IF NOT EXISTS proactive_candidates_observation ON proactive_candidates(owner_id, observation_id) WHERE observation_id IS NOT NULL;

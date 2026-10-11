-- P4 content surface: Home Assistant entity snapshots (0030).
-- The operator-configured HA connection (ha_connections + SecretStore token,
-- usable:false pattern) stays in 0019; this table is the read-only snapshot
-- the tab lists. Every row is third-party bytes: entity state/attributes
-- enter quarantined (tainted=true default) and the agent may only read them
-- as UntrustedExternal content — actuation is never stored here and any
-- Confirm-gated tool proposal goes through the governed path instead.
CREATE TABLE ha_entities(
  id uuid NOT NULL,
  owner_id uuid NOT NULL REFERENCES users(id),
  entity_id text NOT NULL,
  state text NOT NULL DEFAULT '',
  attributes jsonb NOT NULL DEFAULT '{}',
  connection_id uuid,
  tainted boolean NOT NULL DEFAULT true,
  last_seen timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(owner_id, id),
  UNIQUE(owner_id, entity_id)
);
CREATE INDEX ha_entities_owner_seen ON ha_entities(owner_id, last_seen DESC);

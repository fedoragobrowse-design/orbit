-- OS workspace (step 3): mutable metadata tree over the sealed artifact store.
-- Bytes live only in `artifacts` (sealed, immutable); these tables hold the
-- hierarchical namespace, per-entry revision pins, version history, and
-- explicit node-mount aliases. User strings never become server paths:
-- every lookup is by UUID with owner scope.
CREATE TABLE IF NOT EXISTS workspace_entries(
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL REFERENCES users(id),
  parent_id UUID,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('FILE','DIRECTORY')),
  head_artifact_id UUID REFERENCES artifacts(id),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  trashed_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(owner_id, id),
  FOREIGN KEY (owner_id, parent_id) REFERENCES workspace_entries(owner_id, id),
  CHECK ((parent_id IS NULL AND name = '') OR (parent_id IS NOT NULL AND name <> '')),
  CHECK (parent_id IS DISTINCT FROM id)
);
-- One active owner root (parent NULL, name ''); sibling names unique while active.
CREATE UNIQUE INDEX IF NOT EXISTS workspace_root_active ON workspace_entries(owner_id) WHERE parent_id IS NULL AND trashed_at IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS workspace_siblings_active ON workspace_entries(owner_id, parent_id, name) WHERE parent_id IS NOT NULL AND trashed_at IS NULL;
CREATE INDEX IF NOT EXISTS workspace_entries_parent ON workspace_entries(owner_id, parent_id, name, id) WHERE trashed_at IS NULL;
CREATE TABLE IF NOT EXISTS workspace_versions(
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL REFERENCES users(id),
  entry_id UUID NOT NULL,
  revision BIGINT NOT NULL CHECK (revision > 0),
  artifact_id UUID NOT NULL REFERENCES artifacts(id),
  created_by_task_id UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(owner_id, id),
  UNIQUE(owner_id, entry_id, revision),
  FOREIGN KEY (owner_id, entry_id) REFERENCES workspace_entries(owner_id, id),
  FOREIGN KEY (owner_id, created_by_task_id) REFERENCES tasks(owner_id, id)
);
CREATE INDEX IF NOT EXISTS workspace_versions_entry ON workspace_versions(owner_id, entry_id, revision);
CREATE TABLE IF NOT EXISTS workspace_mounts(
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL REFERENCES users(id),
  alias TEXT NOT NULL,
  node_id UUID NOT NULL,
  root_id UUID NOT NULL,
  mode TEXT NOT NULL CHECK (mode IN ('READ','WRITE')),
  revision BIGINT NOT NULL DEFAULT 1 CHECK (revision > 0),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(owner_id, id),
  UNIQUE(owner_id, alias),
  FOREIGN KEY (owner_id, node_id, root_id) REFERENCES computer_roots(owner_id, node_id, id)
);

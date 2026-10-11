-- Custom marketplace registries: owner-pinned index roots serving the same
-- manifest-per-entry layout as the built-in Orbit-MarketPlace repo.
CREATE TABLE IF NOT EXISTS marketplace_registries(
  id UUID PRIMARY KEY,
  owner_id UUID NOT NULL REFERENCES users(id),
  name TEXT NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64 AND name ~ '^[a-z0-9-]+$'),
  base_url TEXT NOT NULL CHECK (char_length(base_url) BETWEEN 9 AND 2048),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE(owner_id, name)
);
CREATE INDEX IF NOT EXISTS marketplace_registries_owner ON marketplace_registries(owner_id, created_at, id);

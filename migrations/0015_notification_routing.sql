-- 0015 was folded into later migrations; routing values are enforced by
-- 0016-style per-migration DO blocks below. This file intentionally applies
-- only the digests table so fresh + migrated databases converge.
CREATE TABLE IF NOT EXISTS notification_digests(owner_id uuid PRIMARY KEY REFERENCES users(id),entries jsonb NOT NULL DEFAULT '[]',updated_at timestamptz NOT NULL DEFAULT now());

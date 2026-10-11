CREATE TABLE notes(
  id uuid NOT NULL,
  owner_id uuid NOT NULL REFERENCES users(id),
  title text NOT NULL DEFAULT '',
  body text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY(owner_id, id)
);
CREATE INDEX notes_owner_updated ON notes(owner_id, updated_at DESC);

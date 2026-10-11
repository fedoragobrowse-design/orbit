CREATE TABLE bookmarks(id uuid NOT NULL,owner_id uuid NOT NULL REFERENCES users(id),url text NOT NULL,title text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(owner_id,id));
CREATE INDEX bookmarks_owner_created ON bookmarks(owner_id,created_at);

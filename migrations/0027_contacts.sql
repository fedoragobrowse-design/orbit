CREATE TABLE contacts(id uuid NOT NULL,owner_id uuid NOT NULL REFERENCES users(id),name text NOT NULL,email text NOT NULL DEFAULT '',phone text NOT NULL DEFAULT '',notes text NOT NULL DEFAULT '',created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(owner_id,id));
CREATE INDEX contacts_owner_name ON contacts(owner_id,name);

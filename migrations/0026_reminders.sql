CREATE TABLE reminders(id uuid NOT NULL,owner_id uuid NOT NULL REFERENCES users(id),title text NOT NULL,remind_at timestamptz,done boolean NOT NULL DEFAULT false,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),PRIMARY KEY(owner_id,id));
CREATE INDEX reminders_owner_due ON reminders(owner_id,remind_at);

-- Widen routing CHECKs first (idempotent: drops the 0008-era narrow checks if present).
ALTER TABLE automations DROP CONSTRAINT IF EXISTS automations_notification_behavior_check;
DO $$ BEGIN
  ALTER TABLE automations ADD CONSTRAINT automations_notification_behavior_check CHECK(notification_behavior IN ('NONE','IN_APP','PUSH','EMAIL_DIGEST'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;
ALTER TABLE notification_sinks DROP CONSTRAINT IF EXISTS notification_sinks_kind_check;
DO $$ BEGIN
  ALTER TABLE notification_sinks ADD CONSTRAINT notification_sinks_kind_check CHECK(kind IN ('IN_APP','PUSH','EMAIL_DIGEST'));
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE triage_rules(id uuid PRIMARY KEY,owner_id uuid NOT NULL REFERENCES users(id),name text NOT NULL,matcher jsonb NOT NULL DEFAULT '{}',action jsonb NOT NULL DEFAULT '{}',enabled boolean NOT NULL DEFAULT true,created_at timestamptz NOT NULL DEFAULT now(),updated_at timestamptz NOT NULL DEFAULT now(),UNIQUE(owner_id,id));
CREATE INDEX triage_rules_owner ON triage_rules(owner_id,enabled,created_at);

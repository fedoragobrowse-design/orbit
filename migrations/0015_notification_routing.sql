ALTER TABLE automations DROP CONSTRAINT IF EXISTS automations_notification_behavior_check;
ALTER TABLE automations ADD CONSTRAINT automations_notification_behavior_check CHECK(notification_behavior IN ('NONE','IN_APP','PUSH','EMAIL_DIGEST'));
ALTER TABLE notification_sinks ADD CONSTRAINT notification_sinks_kind_check CHECK(kind IN ('IN_APP','PUSH','EMAIL_DIGEST'));
CREATE TABLE notification_digests(owner_id uuid PRIMARY KEY REFERENCES users(id),entries jsonb NOT NULL DEFAULT '[]',updated_at timestamptz NOT NULL DEFAULT now());

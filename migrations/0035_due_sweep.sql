-- Due sweep markers: null = never fired, set when the notification goes out.
ALTER TABLE calendar_events ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ;
ALTER TABLE reminders ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS calendar_events_due ON calendar_events(owner_id, starts_at) WHERE notified_at IS NULL;
CREATE INDEX IF NOT EXISTS reminders_due ON reminders(owner_id, remind_at) WHERE notified_at IS NULL AND done = false;
ALTER TABLE email_messages ADD COLUMN IF NOT EXISTS notified_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS email_messages_unnotified ON email_messages(owner_id, received_at) WHERE notified_at IS NULL;

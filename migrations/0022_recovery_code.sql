ALTER TABLE installation ADD COLUMN recovery_token_hash text;
ALTER TABLE installation ADD COLUMN recovery_token_expires timestamptz;

-- Sandbox opt-out: default the settings JSON blob with sandbox_enabled=false
-- (sandbox OFF by default per owner; existing rows keep their off state).
UPDATE settings
SET value = value || '{"sandbox_enabled":false}'::jsonb
WHERE NOT (value ? 'sandbox_enabled');
ALTER TABLE settings
  ALTER COLUMN value SET DEFAULT '{"installation_mode":"LOCAL_ONLY","autonomy_mode":"OBSERVE","allow_private_cloud":false,"agent_backend":"OMP","inbox_enabled":false,"sandbox_enabled":false}';

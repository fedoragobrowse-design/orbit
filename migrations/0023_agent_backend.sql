-- P2 backend selection: default the settings JSON blob with agent_backend=OMP
-- (preserves current inline-harness behavior until the user switches).
-- Existing rows get the default so GET /api/v1/settings keeps deserializing.
UPDATE settings
SET value = value || '{"agent_backend":"OMP"}'::jsonb
WHERE NOT (value ? 'agent_backend');
ALTER TABLE settings
  ALTER COLUMN value SET DEFAULT '{"installation_mode":"LOCAL_ONLY","autonomy_mode":"OBSERVE","allow_private_cloud":false,"agent_backend":"OMP"}';

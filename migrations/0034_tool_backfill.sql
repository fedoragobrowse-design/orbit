-- Backfill: agents created before the orbit-* tool namespaces existed
-- carry allowed_tools=[] and can reach no MCP service. Grant the safe
-- read + control set; owners can narrow per-agent afterwards.
-- High-risk tools (settings_update, call_service) stay gated by their
-- own consent/confirm checks even when listed.
UPDATE agent_definitions
SET definition = jsonb_set(
  definition,
  '{allowed_tools}',
  '["orbit-control.ask_owner","orbit-control.skills_list","orbit-control.docs_read","orbit-data.memory_search","orbit-data.mail_read","orbit-data.calendar_list","orbit-data.files_list","ha-control.entities_list","memory.search","memory.propose","notifications.create","reports.save"]'
)
WHERE COALESCE((definition->'allowed_tools'), '[]') = '[]';

-- Hybrid catalog legacy-name migration (HybridCatalog slice).
--
-- Agent allowlists written before the orbit-*/mcp.* namespacing carry legacy
-- provider names that no longer resolve (`memory.*`, `shell.*`,
-- `browser.*`, `files.*`, `email.*`, bare `mcp.*`). The catalog deliberately
-- does NOT re-admit them: legacy names never match catalog entries, and an
-- empty allowlist stays empty (no fallback grant is added here).
--
-- This migration rewrites the statically mappable names to their namespaced
-- equivalents and drops unmapped legacy names. Owners must re-grant dropped
-- names explicitly (notably `mcp.*` rows, whose connection segment is
-- per-owner, and high-risk names like `shell.execute` / `files.write` /
-- `browser.*`, which stay unguided until the owner re-admits them).
-- Idempotent: names already namespaced pass through untouched; reruns are
-- no-ops once no legacy element remains.
UPDATE agent_definitions
SET definition = jsonb_set(
  definition,
  '{allowed_tools}',
  (
    SELECT COALESCE(jsonb_agg(DISTINCT elem ORDER BY elem), '[]'::jsonb)
    FROM jsonb_array_elements_text(COALESCE(definition->'allowed_tools', '[]'::jsonb)) AS name,
    LATERAL (
      SELECT CASE name
        WHEN 'memory.search' THEN 'orbit-data.memory_search'
        WHEN 'memory.propose' THEN 'orbit-data.memory_search'
        WHEN 'files.list' THEN 'orbit-data.files_list'
        WHEN 'files.search' THEN 'orbit-data.workspace_search'
        WHEN 'files.read' THEN 'orbit-data.workspace_read'
        WHEN 'files.metadata' THEN 'orbit-data.workspace_read'
        WHEN 'files.watch' THEN 'orbit-data.workspace_list'
        WHEN 'email.search' THEN 'orbit-data.mail_read'
        WHEN 'email.read' THEN 'orbit-data.mail_read'
        ELSE name
      END AS elem
    ) AS mapped
    WHERE NOT (
      elem IN (
        'shell.execute',
        'browser.navigate', 'browser.fill_submit',
        'browser.session.open', 'browser.session.snapshot', 'browser.session.navigate',
        'browser.session.click', 'browser.session.fill', 'browser.session.submit',
        'browser.session.download', 'browser.session.close',
        'files.write', 'files.move', 'files.copy',
        'email.draft', 'email.send', 'email.archive', 'email.label'
      )
      OR elem LIKE 'mcp.%'
    )
  )
)
WHERE EXISTS (
  SELECT 1
  FROM jsonb_array_elements_text(COALESCE(definition->'allowed_tools', '[]'::jsonb)) AS name
  WHERE name IN (
    'memory.search', 'memory.propose',
    'shell.execute',
    'browser.navigate', 'browser.fill_submit',
    'browser.session.open', 'browser.session.snapshot', 'browser.session.navigate',
    'browser.session.click', 'browser.session.fill', 'browser.session.submit',
    'browser.session.download', 'browser.session.close',
    'files.search', 'files.read', 'files.list', 'files.metadata', 'files.watch',
    'files.write', 'files.move', 'files.copy',
    'email.search', 'email.read', 'email.draft', 'email.send', 'email.archive', 'email.label'
  )
  OR name LIKE 'mcp.%'
);

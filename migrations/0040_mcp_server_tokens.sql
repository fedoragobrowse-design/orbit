-- MCP server token grants (McpServer slice): scoped hashed API tokens.
-- A token carries explicit per-service/per-tool grants; grants reference
-- orbit built-in tool names (orbit-control.*, orbit-data.*, ha-control.*).
-- No token may call a tool outside its grants; the server denies closed.
CREATE TABLE IF NOT EXISTS api_token_grants(
  token_id UUID NOT NULL,
  owner_id UUID NOT NULL REFERENCES users(id),
  service TEXT NOT NULL CHECK(service IN ('orbit-control','orbit-data','ha-control')),
  tool_name TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY(owner_id, token_id, tool_name),
  FOREIGN KEY(owner_id, token_id) REFERENCES api_tokens(owner_id, id)
);
CREATE INDEX IF NOT EXISTS api_token_grants_token ON api_token_grants(owner_id, token_id);

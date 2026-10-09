# MCP in Orbit

Model Context Protocol (Streamable HTTP) servers plug external tools into
Orbit. The operator registers a connection; discovery imports its tools as
**disabled, default-deny** entries; a human reviews each tool and pins a
grant to its schema digest; only then can the approvals pipeline dispatch
calls through it.

## Unavailable by default

No connections ship configured. With zero connections, `GET
/api/v1/mcp/connections` returns an empty list and every tool namespace
`mcp.*` is absent from the registry — agents cannot name tools that do not
exist. A disabled connection fails closed: `discover` and `call_once`
return `FORBIDDEN`/`UNAVAILABLE` without touching the network.

## Lifecycle

1. **Register** — `POST /api/v1/mcp/connections` with `{name, origin,
   local?, bearer?, headers?, header_names?, ca_pem?}`. The origin passes
   endpoint admission *before* anything is persisted: non-HTTP(S) schemes,
   embedded credentials, and query strings are rejected; link-local
   (`169.254.x.x`), cloud-metadata, multicast, and private/loopback ranges
   are denied unless the connection is explicitly marked `local: true`.
   Credentials land in orbit-secrets (`mcp-credential` purpose), never in
   Postgres — the row keeps only a `secret_id`.
2. **Discover** — `POST /api/v1/mcp/connections/{id}/discover` pages
   `tools/list` (100 pages / 1000 tools max; a repeated cursor or a
   conflicting duplicate tool name fails the whole run without persisting).
   Each tool is stored as `mcp.<connection-uuid>.<tool>` with assessment
   `UNKNOWN`, `enabled=false`, and risk High. Tools whose schema digest
   changed since last discovery are disabled, reset to `UNKNOWN`, and have
   their grants deleted (`grants_revoked` in the outcome).
3. **Review + grant** — enable the tool, then `POST /api/v1/mcp/grants`
   with `{tool_id, assessment: READ_ONLY|MODIFIES_DATA, review_evidence}`.
   The grant pins the tool's current schema digest; any later schema change
   deletes the grant, so a stale approval can never authorize a changed
   tool.
4. **Call** — only via the approvals pipeline: the gateway proposes
   `mcp.<conn>.<tool>`, policy/risk approve, and `call_once` executes with
   the approval's `authorization_id`. There is no direct-call endpoint in
   this API module by design.

## Bounds (every call)

- 30 s request timeout; anything slower records `OUTCOME_UNKNOWN` evidence
  and returns `TIMEOUT` — the caller must reconcile, never blind-retry.
- 1 MiB response cap (`MAX_RESPONSE`); results over 64 KiB spill to the
  private artifact store and the agent receives an artifact reference.
- Arguments validated against the registered input schema; structured
  output validated against the registered output schema. A tool-level
  `isError` result is a failure. Schema validation failures are `FAILED`,
  never retried as new calls.

## Sessions

The transport is stateless per request (`reinit_on_expired_session=false`
semantics): each `discover`/`call_once` opens a fresh Streamable HTTP
session and closes it. An expired server session surfaces as `UNAVAILABLE`,
recorded `OUTCOME_UNKNOWN` — never silently re-initialized and replayed.

## Local fixture

The `fixtures` service in `deploy/examples/compose.test.yaml` serves a
deterministic rmcp Streamable HTTP endpoint at `/mcp` (see
`tests/fixtures/src/lib.rs`: `tools/list` pagination plus `tools/call`
echo, including an `is_error` mode for failure paths). Point a connection
at the fixtures host `/mcp` (marked `local: true`) to exercise discovery,
schema-change revocation, and grant-gated calls without external servers.

## Marketplace parity

Marketplace packages are the install-time twin of MCP grants: manifests come
from the Orbit-MarketPlace repo index over HTTPS (no vendored cache; each
response documents its `index_source` URL), the sha256 `content_digest` is
recomputed and the ed25519 signature verified per the repo's `SIGNING.md`
before anything persists, install requires echoing `requested_capabilities`
back as `approved_capabilities` plus `accept_trust_level`, and every
install/remove writes a `MARKETPLACE_INSTALLED`/`MARKETPLACE_REMOVED` audit
row. Installed packages run ONLY via the sandbox path (`sandbox_only=true`);
there is no in-process execution. `orbit market` CLI: ROADMAP — no CLI crate
exists in this repo (`apps/server` is the API server, `apps/computer-node`
is a runner), so the CLI needs a new binary crate with login, search,
preview, and install subcommands backed by these routes.

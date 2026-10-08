# Web workspace

Stack: React 19, TypeScript 5, Vite 7, Router 7, TanStack Query 5, plain CSS
(`apps/web/src/style.css`). No component library.

## Contract

Real HTTP only. `crates/api/src/lib.rs::router()` mounts `auth`, `foundation`,
`models`, `gateway`, `memory`, `runtimes`, and `email`, and no longer gates
migrations to version 1. The live contract is therefore Milestones 1, 2, 4,
5, 7, 9 and the runtimes half of 10.

- Milestone 1: `GET /api/v1/auth/session`,
  `POST /api/v1/auth/{setup,login,logout}`, `GET/PUT /api/v1/settings`,
  `GET/POST /api/v1/events`, `GET /api/v1/tasks` (+`/{id}`,
  `/{id}/{cancel,resume,retry,reconcile}`), `GET /api/v1/activity` (+`/{id}`),
  `GET /api/v1/notifications` (+`/{id}/{read,acknowledge,dismiss}`),
  SSE `/api/v1/stream`, `GET /health`, `GET /ready`.
- Milestone 2 (models): `/api/v1/providers` (+`/{id}`), `/api/v1/models`
  (+`/{id}`), `GET/PUT /api/v1/budgets`, `GET /api/v1/model-calls`.
- Milestone 4/5 (gateway): `GET /api/v1/approvals`
  (+`/{id}`, `/{id}/approve`, `/{id}/reject`), `GET/POST /api/v1/grants`
  (+`/{id}`), `GET/PUT /api/v1/policy`, `GET /api/v1/tools`,
  `GET /api/v1/tool-calls`.
- Milestone 7 (memory): `GET/POST /api/v1/memory` (+`/{id}`,
  `/{id}/{verify,supersede,forget,history}`, `/search`),
  `GET /api/v1/projects`, `GET/PUT /api/v1/retention`.
- Milestone 9 (email): `/api/v1/email/accounts` (+`/{id}`, `/{id}/{test,sync}`),
  `/messages`, `/drafts`, `/checkpoints`.
- Runtimes: `GET/POST /api/v1/runtimes/connections` (+`/{id}`,
  `/{id}/{test,rotate-secret}`).

`GET /api/v1/openapi.json` is mounted and is the authoritative shape for all
of the above. Cookie `orbit_session` + `X-CSRF-Token` + `Origin`. Lists are
`{items, next_cursor}` with `?cursor=&limit=`.

Still unmounted, so the web gates them honestly: `/agents` (M3), the Node API
behind `/computers` and `/files` (M6), `/automations` (M8), and the MCP
connection API behind `/connections/mcp` (M10). MCP *tools* are visible via
`GET /api/v1/tools`.

## Surfaces

`/` Home (attention stream, USER_MESSAGE composer, recent activity, health),
`/chat` (event-backed conversations), `/tasks` (+`/:id` recovery),
`/activity`, `/settings`.

Live surfaces, all against real HTTP: `/approvals` (approve and reject with
`expected_revision`, grants, policy editor, tool registry, tool calls),
`/memory` (+`/:id` verify/supersede/forget/history, project notebooks,
retention), `/models` (providers, models, budgets, model calls),
`/connections/runtimes` (connection CRUD, test) and `/connections/email`
(account CRUD, test, sync).

Gated surfaces render "Not available in this build" with the owning milestone:
`/agents` (M3), `/computers` and `/files` (M6), `/automations` (M8), and the
`/connections/mcp` tab (M10). OAuth, native calendars, GitHub, Home
Assistant, OMP, and macOS pairing are explicitly unavailable.

## States

Loading, empty (with recovery action), error (code + message + request_id +
retry), offline (stream disconnect), denied (401/403 → login), version
(`expected_revision` conflicts on settings/tasks). Tokens in `style.css`:
`#F4F2F7` ground, `#FFF` surface, `#30263F` plum, `#176B58` evergreen,
`#946200` pending, `#A43256` destructive, `#655E70` secondary,
`#DDD7E5` separators.

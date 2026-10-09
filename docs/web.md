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

## PWA + push

Installable: `/manifest.webmanifest` (name, theme-color `#30263F`, generated
192/512px icons in `apps/web/public/`) linked from `index.html`; `/sw.js`
caches the app shell cache-first (never `/api/`), shows push events as
notifications deep-linking to `/approvals/{id}`, and focuses or opens the
approval on click. `App.tsx` registers the worker in the authenticated
effect next to SSE and re-syncs the subscription. Settings has a Push
notifications panel (enable + test-push).

Backend: `POST/DELETE /api/v1/push/subscribe`, `GET /api/v1/push/vapid-key`,
`POST /api/v1/push/test` (`crates/api/src/push.rs`, owner-scoped
`push_subscriptions` + `push_vapid_keys` in `migrations/0012_push.sql`).
VAPID P-256 keys mint server-side on first use; the private scalar lives in
the encrypted secret store (`push-vapid-private` purpose), the table keeps
only the secret link + public key. Sending is RFC 8291 `aes128gcm`
(hand-rolled over `p256`/`aes-gcm`/`hmac`; vectors pinned to Appendix A in
`push::tests::rfc8291_appendix_a_vectors`). Every approval commit
(`agents.rs` gateway path, `computers.rs` file-mutation path) enqueues a
best-effort fanout after the transaction — push failure never rolls back
the approval row; 410/404 endpoints are pruned.

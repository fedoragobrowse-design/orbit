# Changelog

## 2026-10-11 — Sandbox opt-out (OFF by default)

Sandbox OFF by default per owner: `sandbox_enabled` on Settings/SettingsUpdate (migration 0031 backfills `{"sandbox_enabled":false}`, column default extended, fresh owners inherit off). `AgentDispatcher::admission` journals `SANDBOX_DISABLED` in the policy decision when off (still Jev-gated on command text plus policy-checked, no AIec); `submit` keeps `requires_sandbox` snapshots parked when the owner enabled the sandbox, and `execute_call` writes `TOOL_EXECUTED` `UNSANDBOXED` in the audit reason for direct runs. AIec create stays fail-closed when unavailable. Web Settings gains a `Run tools inside a sandbox (AIec)` checkbox with a plain-words hint.

## 2026-10-11 — Live subagent run view on task detail

Live subagent view on task detail: `GET /api/v1/tasks/{id}/runs` in `crates/api/src/foundation.rs` (`task_runs`, router + OpenAPI `TaskRunItem`/`TaskRuns`) returns the owner-scoped `agent_runs` row for the task plus sibling runs sharing the task correlation id, each shaped `{task_id, phase, model_calls, model_retries, turn, depth, tool_calls, tokens}`. No subagent table exists, so depth comes from `agent_runs.depth` with a task-checkpoint `depth` fallback; foundation tasks return empty items. Tasks detail (`apps/web/src/workspace.tsx`, `LiveRun`) gains a "Live run" section polling every 2s while the task state is active and stopping on terminal states, with a plain-words phase timeline, per-depth indent with helper-level labels, and model-call/retry/tool/token counters.

## 2026-10-11 — Runtime upserts, prod key-dir, settled task detail

- Agent runtime: invalid `ON CONFLICT` upserts on `notifications` +
  terminal-event insert fixed (migration 0004 dropped the unique the
  queries still named). Park/fail paths no longer die with `storage
  operation failed`; failing model calls settle
  `WAITING_FOR_RESOURCE`/`LOCAL_MODEL_UNAVAILABLE`, over-budget runs
  `FAILED` via the `MODEL`-phase `max_model_calls`/`max_retries` guard
  (`crates/agent-runtime/src/runtime.rs`, `crates/api/src/runtimes.rs`,
  `crates/event-bus/src/lib.rs`).
- Prod `compose.yaml`: `ORBIT_KEY_DIR`/`ORBIT_ARTIFACT_DIR` now point at
  the mounted `keys`/`artifacts` volumes (server defaulted to
  `data/keys`, unwritable as the `orbit` user, and crashed after the
  postgres restart).
- Tasks detail: the composer task settles `COMPLETED` before the detail
  view loads, and per `task_detail` that state exposes no recovery
  buttons — the e2e spec now asserts the settled record (checkpoint +
  task record + why-timeline) instead of a Cancel button. Full suite
  11/11 on isolated `:18080`.

## 2026-10-07 — Web/deployment/docs workstream (M1 cutover)

- Web rewired to the real M1 contract only; removed ~35 unbacked calls
  (`/agents`, `/chat`, `/approvals`, `/attachments`, `/providers`, `/models`,
  `/memory/*`, `/policies`, `/system-health`). Home/Chat/Tasks/Activity/
  Settings/notifications/stream verified against a live backend with a real
  browser (login, USER_MESSAGE → task → notification → activity).
- Honest unavailable states on Models, Agents, Approvals, Memory, Automations,
  Computers, Files, Connections (OAuth, native calendars, GitHub, Home
  Assistant, OMP, macOS named explicitly unavailable). No mocks, no fake success.
- E2E `tests/e2e/workspace.spec.ts`: 7 serial specs (setup → composer → tasks →
  activity → chat → settings → unavailable). Blocked on harness:
  `fixtures.Dockerfile` builds `-p orbit-fixtures`, not a workspace member
  (backend-owned; reported).
- Fixtures workspace membership fixed by backend (`tests/fixtures` is now a
  member, package `orbit-fixtures`). The fixtures image still fails before
  compiling, now on a workspace-wide cargo resolution conflict rather than
  membership: `sqlx-sqlite` (via `orbit-core`) needs `libsqlite3-sys ^0.28`,
  `rusqlite 0.37` (via `apps/computer-node`) needs `^0.35`; both declare
  `links = "sqlite3"`. `Cargo.lock` also lists only 4 of 24 members, so
  `--locked` cannot pass until it is regenerated. Both are backend-owned;
  reported. E2E `run-server.mjs` stays blocked on this.
- Root `README.md`, `PRODUCT.md`, `DESIGN.md`, `NOTICE`; `docs/deploy.md`,
  `docs/web.md`. Impeccable detector clean; desktop + 390px mobile verified.
- Backend landed the M2–M10 routers: `lib.rs::router()` now merges `models`,
  `gateway`, `memory`, `runtimes`, and `email` on top of `auth` +
  `foundation`, and `api::initialize` no longer gates migrations to version 1.
  SQLite link conflict resolved by pinning `rusqlite` to `=0.32.1`; Cargo.lock
  regenerated (21 crates) and the fixtures image now builds under `--locked`.
- Web rewired to the newly mounted contract. Four surfaces went from
  "Not available in this build" to real HTTP: Models (providers, models,
  budgets, model calls), Approvals (approve/reject with `expected_revision`,
  grants, policy editor, tool registry, tool calls), Memory (list/detail,
  verify, supersede, forget, history, projects, retention), and Connections
  (new Runtimes tab with connection CRUD and test, Email tab with account CRUD,
  test, sync).
- Still gated because the routes are genuinely unmounted: `/agents` (M3),
  `/computers` and `/files` (M6), `/automations` (M8), `/connections/mcp`
  (M10). MCP tools are reachable through `GET /api/v1/tools`, which the
  Approvals surface now shows.
- `GET /api/v1/openapi.json` is mounted and is the authoritative contract.
- E2E grew from 7 to 10 specs: the gated list is corrected, plus coverage that
  the four rewired surfaces load real data and that a provider can be created
  and listed.
- Deployment fix: `apps/server/src/main.rs` no longer accepts a `serve`
  subcommand — it bails with `supported command: bootstrap-token` and serves
  when given no arguments. `deploy/docker/server.Dockerfile` still carried
  `CMD ["serve"]`, so every `server` container exited 1 immediately with
  `dependency failed to start`. Removed the stale `CMD`; `docs/deploy.md`
  already documented the correct no-subcommand contract.

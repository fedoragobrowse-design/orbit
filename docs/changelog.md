# Changelog

## Unreleased — Managed browser host + brokered network modes

- Managed browser: `apps/browser-host` (Node 24, pinned Playwright Chromium 1.55.0) on a private Unix socket — launch/context/page ops, JPEG frames max 2fps only while a viewer/snapshot subscriber exists, URL/loading/title/nav events, cookie/profile bytes returned raw for the caller to seal as 30d artifacts, password values never echoed. `deploy/docker/browser-host.Dockerfile` (chromium deps, amd64+arm64, no ports/host mounts) + compose `browser-host` block (private net, socket volume, health probe); `BROWSER_HOST_TOKEN_SECRET` minted by `install.sh`.
- RuntimeSpec network posture is now `NONE|BROKERED_MODEL|BROKERED_WEB` (SCREAMING_SNAKE_CASE, `deny_unknown_fields`), replacing the `network_enabled` bool: each mode names its grant exactly, mismatches fail closed. New `WebEgress` origin allowlist (1–16 bare http(s) origins) with `brokered-web` Guard environment. AIec fence accepts `brokered-web`; new `probe_brokered_web` capability probe — missing broker capability is `BROWSER_UNAVAILABLE`, never a raw guest network. Egress enforced at the host: http(s) only, literal-IP deny, all-resolved-addresses DNS-rebinding guard, redirect re-screen.
- Desktop observation consent (opt-in, default off): grant/revoke/pause/resume/narrow per window with revision checks, 24h default retention (`0` = explicit keep), consent expiry, node-level pause-all; `GET /api/v1/observation/status` feeds a persistent shell banner with Pause; `GET/DELETE /api/v1/observations` inspect by source/time with per-row expiry. Unsupported portal fails closed with `DESKTOP_CAPTURE_UNAVAILABLE` (no X11 fallback). Mobile inspects + pauses only. Settings gains a Desktop observation section. Expired `desktop` rows swept in housekeeping.
- Compose profile (plan step 11): new `deploy/docker/agent-runner.Dockerfile` guest image (`orbit-agent-runner`) shipping the exact backend contract — `/workspace/omp/packages/coding-agent/scripts/omp --print` (OMP 18.10.3, bun-required sh-shim) + `claude` CLI (claude-code 2.1.296, node >= 22) + claude-agent-sdk 0.3.296; install-only, nothing launches at build time. New profile-gated `agent-runner` compose service (no ports/volumes/restart). Server now mounts the socket volume read-only with `ORBIT_BROWSER_HOST_SOCK`/`ORBIT_BROWSER_HOST_TOKEN` wired from the install-minted secret; `install.sh` also mints `EXEC_HOST_TOKEN_SECRET` (compose already required it).
## v1.1 — 2026-10-11 — Fixes wave: layout, chat order, modals, daemon setup

- Layout: pages left-align like the homepage (`.main` auto-margin
  removed); grouped sidebar uses quiet caps labels (Talk · Organize ·
  Do · Connect · System).
- Chat: role-aware tiebreak keeps each user message above its own
  reply on same-ms ties; Model/Agent/Function pickers in one row;
  rich tool/MCP/code/file rendering + source chips (Saved memory /
  Attached file / Your message).
- Add-forms to modals: Reminders, Contacts, Bookmarks, Clips, and
  Calendar add-event are now button + native dialog (Escape closes,
  focus restored); stale "Add one above" copy fixed.
- Memory: detail route + version fix, family-redact Delete,
  lightweight extractor auto-saves self-statements (live-proven).
- Marketplace: tile grid with per-package manifest descriptions,
  `plugins/example-hello` fixture + `docs/marketplace.md`, custom
  marketplace registry (add/remove/validate, same manifest format).
- Computers: loopback on-device harness; files.search schema-shaped
  args (500 fixed); files.watch node arm (ACTIVE watch registry);
  TLS gateway profile, `scripts/install-node.sh` one-command daemon
  (systemd/launchd), Computers "Pair this machine" UI flow.
- MCP services in Connectors: orbit-control + orbit-data Active,
  ha-control (entities_list tainted, Confirm-gated call_service)
  off until Home Assistant connects.

## v1.0 — 2026-10-11 — First stable: control plane, real chat, panes

- Control plane: `orbit-control.*` tools (consent-gated settings
  updates, ask-owner parking with notifications, skills list, agent
  docs) + `orbit-data.*` reads (memory/mail/calendar/files, always
  `UNTRUSTED_EXTERNAL`). Agent docs at `GET /api/v1/docs/:page`
  (overview/settings/memory/tools). Questions list/answer/cancel API.
  Skills registry + enable toggles. Updater check/releases/apply
  (staged-only, never auto-restarts). Settings is the Control Center.
- Real chat: task-backed `POST /chat/messages` + conversation list +
  SSE stream, full thread history, context kept across turns, typing
  bubble, rich tool/MCP/code/file rendering, source chips (Saved
  memory / Attached file / Your message) from persisted run context.
- Panes: Notes sidebar+editor, Calendar month grid + click-a-day
  add-event (`POST /calendar/events`), Mail three-pane reader,
  Files explorer with kind folders + preview, Memory explorer with
  summary + type filters, Activity Trends board (total spend + daily
  chart + per-model table).
- Memory that works: lightweight extractor auto-saves self-statements
  (name/favorite/like/prefer) post-commit on answered chats —
  live-proven (LumenProof ACTIVE after COMPLETED chat); recall runs
  every MODEL turn when `include_memory` is on.
- Platform: sandbox OFF by default (opt-in per owner, UNSANDBOXED
  audit mark when direct); egress advisory (Confirm, never Block —
  internet allowed until policy denies); runtime upsert fixes (park/fail
  paths settle instead of `storage operation failed`); prod key-dir
  env fix; grouped collapsible hideable sidebar; themes (3 presets +
  custom); boot loading screen.

## 2026-10-11 — Memory page fix + per-memory delete

Memory page (`/memory`) rendered error banners for three fixable reasons: `App.tsx` had no `/memory/:id` route so detail links fell through to "Page not found", `MemoryDetail` read `row.revision` (the column is `version`, so verify/supersede sent `expected_revision: 0` and always conflicted), and it treated `GET /memory/{id}/history` as a bare array (the API returns `{record, history, conflicts}`, so the history list never matched and `length` read `undefined`). All three are fixed; verify/supersede/forget on the detail page now send the real `version`.
New `DELETE /api/v1/memory/{id}` (`delete_memory` in `crates/api/src/memory.rs`, router + OpenAPI) calls the existing owner-scoped `forget`, which redacts the whole supersession family and keeps only an audit stub — hard deletes never happen. The list and the detail page each have a Delete button behind the shared Confirm dialog; the list invalidates the `/memory` query on success. Also fixed a missing closing paren in `forget`'s `DELETE FROM memory_relations` statement in `crates/memory/src/store.rs`, which would have failed every forget/delete at runtime.

## 2026-10-11 — Marketplace tiles + example plugin + custom registries

Marketplace repo index is now a tile grid: each package shows its name, description (from that package's own manifest file, not hardcoded), version, and an Install button that opens the preview-and-approve flow for that package. New `plugins/example-hello/` fixture (signed `manifest.json` + `README.md` + `SKILL.md`) shows the plugin file layout; `docs/marketplace.md` documents the layout, minimal manifest shape, and install rules. Owners can also pin their own marketplace indexes (same manifest format): `marketplace-registry` list/add/remove over `GET/POST /api/v1/marketplace/registries` + `DELETE /api/v1/marketplace/registries/{name}` (migration 0033, https-only roots, schema-format check on add, audit-logged) with a Marketplaces panel on the page.

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

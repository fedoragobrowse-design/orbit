# Ops

Buildable ops subset: kill switch, automation dry-run, encrypted backup/restore,
`orbit doctor`, and global search. Routes live in `crates/api/src/ops.rs`
(registered as `ops::router()` in `crates/api/src/lib.rs`); the dry-run route
lives next to the automations router contract in the same file. One web page:
`apps/web/src/ops.tsx` (`/ops`), plus a `GlobalSearch` box mounted on every
page. Health script: `scripts/doctor.sh` (no CLI crate exists in this repo).

Status: LIVE-PROVEN — kill switch (`crates/api/tests/ops.rs::kill_switch_freezes_mutations_reads_stay_open`), automation dry-run (`::automation_dry_run_has_zero_side_effects`), encrypted backup/restore (`::encrypted_backup_round_trips_one_row`); doctor script (`scripts/doctor.sh` PASS/FAIL/SKIP). See docs/PARITY.md.

## Kill switch

- `POST /api/v1/ops/kill` engages per-owner read-only mode; `POST
  /api/v1/ops/resume` lifts it; `GET /api/v1/ops/status` reports `{frozen}`.
- The flag is a sentinel file `ops-frozen-{owner_id}` under `artifact_dir`
  (no schema change). Enforcement sits in `ops::guard`, which the central
  `crate::authenticate` wrapper calls for every mutation (`mutation=true`).
  While frozen, guarded mutations reject with `403 Forbidden`.
- Reads never consult the flag, so the approvals inbox (`GET
  `/api/v1/approvals`) stays readable while frozen. Kill/resume authenticate
  directly (`auth::authenticate`) so resume always works; backup (read-scoped)
  and dry-run (side-effect-free) also stay available while frozen, while
  restore (a real mutation) is blocked.
- Test: `crates/api/tests/ops.rs::kill_switch_freezes_mutations_reads_stay_open`
  — asserts event publish and automation create fail while engaged and succeed
  after resume, and that approvals list stays 200 throughout.
- Known gap: `marketplace.rs`/`mcp.rs` import `auth::authenticate` directly and
  bypass the guard. Widening enforcement there belongs to those owners
  (follow-up).

## Automation dry-run

- `POST /api/v1/automations/:id/dry-run` reuses the scheduler preview path
  (`orbit_scheduler::preview`, which inserts nothing) and adds the
  trigger/action summary the fired window WOULD dispatch to — consumer
  (`foundation` vs `agents`, same rule as dispatch), task title, checkpoint
  phase — without executing anything.
- Test: `crates/api/tests/ops.rs::automation_dry_run_has_zero_side_effects` —
  counts `tasks`/`events`/`automation_fires` before and after and fails on any
  delta.

## Encrypted backup/restore

- `POST /api/v1/ops/backup` dumps owner-scoped rows (`events`, `tasks`,
  `automations`, `memory_records`) to JSON, chunks into ≤60 KiB `ops-backup`
  secrets via the secrets store, and stores a small `ops-backup-manifest`
  secret whose id IS the returned `artifact_id` (no registry table).
- `POST /api/v1/ops/restore` takes `{artifact_id}`, decrypts, and re-inserts
  in dependency order (events before tasks) with `ON CONFLICT DO NOTHING`,
  then re-scopes every restored row to the caller (`UPDATE … SET
  owner_id=caller`), so a swapped artifact cannot plant another owner's rows.
- The audit trail is intentionally excluded (append-only evidence, never
  rewritten); ephemeral worker state (`event_deliveries`, leases) is excluded
  and recreated for newly published events.
- Test: `crates/api/tests/ops.rs::encrypted_backup_round_trips_one_row` —
  asserts ciphertext contains no plaintext, deletes one memory row, restores,
  and fails if the restored row differs.

## orbit doctor

No CLI crate exists (only `apps/server` with a `bootstrap-token` arg; no clap
anywhere), so the doctor ships as `scripts/doctor.sh`. It checks `/health`,
`/ready`, postgres (`DATABASE_URL` via `pg_isready`), Ollama
(`OLLAMA_URL`, default `http://127.0.0.1:11434`), AIec CLI if installed,
disk usage, and ports 3000/55432, printing `PASS`/`FAIL`/`SKIP` per line and
exiting non-zero on any failure:
`ORBIT_BASE=http://127.0.0.1:3000 DATABASE_URL=… ./scripts/doctor.sh`.

## Global search

Lexical memory search (`POST /memory/search`) already existed; the header box
(`GlobalSearch` in `apps/web/src/ops.tsx`) hits it on every page and also hits
`GET /computers/:node_id/files/search` when the Files page has recorded a
browse context (`orbit.files.context` in localStorage, written by
`apps/web/src/connections.tsx`).

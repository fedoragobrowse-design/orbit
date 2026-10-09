# Orbit product

Orbit is a personal AI platform for one owner on their own machine.

## Who

One owner. The workspace assumes a single authenticated operator, a local
network they trust, and data that never leaves without their action.

## What

A unified OPERATE workspace: onboarding, Home, Chat, Tasks, Approvals, Memory,
Computers, Files, Automations, Models, Connections, Agents, Activity, Settings.
Every assisted action leaves a durable task record with recovery (cancel,
resume, retry, reconcile), an activity trail, and notifications.

## Feature status (matches docs/PARITY.md, October 2026)

Milestones 1–10 live in the API router and wired in the web workspace
(golden journeys J1–J10 in `tests/e2e/golden.ts`).

LIVE-PROVEN (test path in-repo): marketplace signed installs
(`crates/api/tests/marketplace.rs` — tamper/unsigned/capability); encrypted
backup/restore
(`crates/api/tests/ops.rs::encrypted_backup_round_trips_one_row`); ops kill
switch + automation dry-run (`crates/api/tests/ops.rs`, 3 tests) + doctor
script (`scripts/doctor.sh`); morning brief (`crates/api/tests/brief.rs` +
Home panel in `apps/web/src/workspace.tsx`); OTA signed `stable` channel
(`crates/api/tests/updates.rs`, 6 tests) + node stage/rollback
(`apps/computer-node/src/update.rs` tests, 3 tests); PWA push
(`tests/e2e/golden.ts` J8; RFC 8291 vectors in `crates/api/src/push.rs`
tests); GreenMail IMAP round-trip
(`crates/api/tests/email_greenmail.rs` — account→test→sync→taint-kept).

PARTIAL: Firecracker worker (no schedulable worker on this machine; Docker
worker proven live); semantic search (embedder installs via the installer;
query path stays lexical `POST /memory/search`).

UNAVAILABLE (missing prerequisite named): Gmail/Graph OAuth connectors
(owner OAuth client credentials); CalDAV poller (no poller in
`crates/email/src/`); Android node app (Kotlin app + emulator-tested APK);
iPhone companion app (Xcode + Apple Developer account — PWA is the fast
path); release-signing pipeline + rollback path beyond the node `.bak`;
per-source/per-agent budgets; automation templates; notification routing
rules. Full matrix + roadmap: `docs/PARITY.md`.

## Non-goals

No multi-user sharing, no cloud account, no telemetry. Commercial use needs a
separate license (PolyForm-Noncommercial-1.0.0).

# Ghost Core parity matrix

Verified-ingest facts only — prices NOT re-researched. Ghost Core: **$3,499 ex-VAT one-time, no subscription**; **$499 refundable deposit, US-only**. Spec: RTX PRO 4000 24GB / Ryzen 5 7600 / 64GB / 1TB. Sources: ghost.ai/core, ghost.ai, ghost.ai/cart, ghost.ai/privacy, TechCrunch 2026-10-05. **$3,999 is NOT Ghost** (do not cite it as Ghost pricing).

Status key: **LIVE-PROVEN** = exercised by a test/e2e path that exists in-repo. **BUILT** = code exists, no live proof (when in doubt, BUILT). **PARTIAL** = works with named gaps. **UNAVAILABLE** = names the exact missing prerequisite.

| Feature | Ghost status (cited) | Orbit status | Evidence path |
|---|---|---|---|
| Local inference | Yes — on-box GPU (RTX PRO 4000 24GB), ghost.ai/core | BUILT — provider kinds incl. OLLAMA; local-vs-cloud outage codes distinct | crates/model-router/src/types.rs:10-11 (`ProviderKind::{Ollama,...}`); crates/model-router/src/lib.rs:288-325 (LOCAL_ONLY routing, `LOCAL_MODEL_UNAVAILABLE`); compose profile `ollama` in docs/deploy.md:21-24 |
| Privacy / no-cloud-fallback | Yes — local-first, ghost.ai/privacy | BUILT — `LOCAL_ONLY` installation mode default; shell path has no host/Docker fallback | migrations/0001_foundation.sql:11 (settings default `LOCAL_ONLY`); crates/api/src/foundation.rs:28-37 (mode gate); crates/api/src/runtimes.rs:440-443 ("No host, process, or Docker fallback exists") |
| Approvals / 3-tier safety | Yes — approval-gated actions (ghost.ai) | BUILT — pending inbox + approve/reject; digest-bound snapshots; risk floor READ_ONLY→FORBIDDEN; autonomy ceilings | crates/api/src/gateway.rs:342-349 (list), crates/api/src/gateway.rs:536-537 + 613-614 (approve/reject); crates/api/src/gateway.rs:459-465 (digest binding); crates/core/src/lib.rs:14 (RiskLevel 6-tier); crates/risk/src/lib.rs:105-112 (deterministic floor); crates/policy/src/lib.rs:107-110,147-160 (approval + autonomy ceilings); apps/web/src/approvals.tsx |
| Automations | Yes — scheduled/triggered runs (ghost.ai/core) | BUILT — cron/timer/event triggers, enabled flag, side-effect-free preview (= dry-run), coalesced backlog | crates/api/src/automations.rs:20-29 (trigger shapes), :46-47 (`enabled`), :229-239 (`preview_automation`); crates/scheduler/src/lib.rs:1038-1043 (`preview` inserts nothing); migrations/0008_automations.sql |
| Email sources | Yes — Gmail-class ingest (ghost.ai) | LIVE-PROVEN (IMAP/SMTP only) — live GreenMail round-trip: account→test→sync→taint-kept | crates/api/tests/email_greenmail.rs:1-14 (proof header); crates/api/src/email.rs:35-48 (router); docs/CONNECTORS.md:21 (LIVE-PROVEN row) |
| Calendar sources | Yes — calendar ingest (ghost.ai) | UNAVAILABLE — missing owner OAuth client credentials AND CalDAV poller | docs/CONNECTORS.md:22-25 (`cal-gcal-oauth`, `cal-caldav` UNAVAILABLE rows); no calendar poller exists under crates/email/src/ |
| Nodes / multi-machine | Yes — multi-device reach (ghost.ai/core) | BUILT — pairing-code pair, outbound-only node session, digest-bound file ops, revoke/renew | crates/api/src/computers.rs:250-251 (pairing codes), :293-294 (pair), :2013-2028 (router); docs/NODES.md:12-15 (default-deny, traversal refusal) |
| Shell execution | Yes — agent runs commands (ghost.ai) | BUILT — `shell.execute` ONLY via sandbox path (create→upload→execute→collect→destroy), consent-spec pinned | crates/api/src/runtimes.rs:19-37 (router), :305-308 (`shell.execute` descriptor), :440-472 (dispatch, consent checks) |
| Marketplace / skills | Yes — skill store (ghost.ai) | LIVE-PROVEN — self-asserted installs (digest recompute + embedded-key ed25519 check, owner consent, sandbox-only, recorded self-asserted); tamper/unsigned/capability DB tests green | crates/api/src/marketplace.rs:63-70 (checked_manifest); crates/api/tests/marketplace.rs:23-26 (tamper/unsigned/capability tests) |
| PWA / phone approvals | Yes — phone app approvals (ghost.ai) | LIVE-PROVEN — Web Push (VAPID, encrypted secret store) + service worker + installable manifest + Settings toggle; in-app list stays authoritative | tests/e2e/golden.ts J8 (manifest 200 + SW registered + Push alerts panel); crates/api/src/push.rs:368-373 (router), rfc8291 Appendix A vectors in push::tests; migrations/0012_push.sql:1-3; apps/web/src/push.ts:16-33 (sync); apps/web/src/workspace.tsx:628 (PushToggle) |
| Backup / restore | Yes — backup story (ghost.ai) | LIVE-PROVEN — encrypted chunked backup to secrets store, idempotent owner-scoped restore, audit excluded by design | crates/api/src/ops.rs:60-104 (backup/restore); crates/api/tests/ops.rs::encrypted_backup_round_trips_one_row |
| Installers | Yes — appliance unbox (ghost.ai/cart) | BUILT — `install.sh` + node installers with signed dry-run transcripts | install.sh; install-node.sh; install-node.ps1; docs/INSTALL.md:15-24,92-95 (method + transcripts) |
| Embeddings | Yes — semantic recall (ghost.ai) | BUILT — embedding role + pgvector store; installer pulls `nomic-embed-text` via Ollama; lexical search path exists | crates/model-router/src/lib.rs:150-180 (`embed`); crates/memory/src/retrieval.rs:60-65 (`store_embedding`); crates/api/src/memory.rs:303-318 (lexical search); docs/INSTALL.md:38-43 (model pull, offline notice) |
| Screen history (7-day) | Yes — 7-day screen history (TechCrunch 2026-10-05) | UNAVAILABLE — no screen capture by design; privacy reason: Orbit never screenshots the owner device, so there is no frame pipeline, no frame store, no 7-day retention job | No screen-frame code in crates/+apps/ (only unrelated hit: auth-replay "captured challenge" in crates/api/src/computers.rs:827; no frame table in migrations/) |
| Voice / wake word | Yes — voice + wake (ghost.ai) | UNAVAILABLE — missing microphone pipeline, STT/TTS models, and wake-word detector; no voice code exists | No voice pipeline in crates/+apps/+docs/ (only unrelated hit: IPC "wake hint" comment in apps/computer-node/src/windows.rs:312) |
| Hardware bundling | Yes — $3,499 appliance, spec above (ghost.ai/core, ghost.ai/cart) | Software-only by design — no appliance SKU, no fulfillment; reference-hardware guidance below (guidance-not-tested) | This section; no hardware crate exists (crates/ is software-only, verified 2026-10-08) |
| Audit trail | Yes — activity log (ghost.ai) | BUILT — append-only audit table + trigger | migrations/0001_foundation.sql:22-26 (`audit_events`, immutable trigger); crates/audit/src/lib.rs:7-11 (`append`) |
| Retention controls | Ghost: 7-day screen window (TechCrunch 2026-10-05) | BUILT — per-kind day windows, owner-tunable; approvals/runtime evidence protected from cleanup | crates/api/src/memory.rs:353-383 (get/put retention); migrations/0007_memory.sql:36-38 (`retention_settings`); apps/web/src/knowledge.tsx:331-346 (Retention UI) |
| Ops / doctor CLI | Ghost: appliance diagnostics (ghost.ai/core) | LIVE-PROVEN (script) — kill switch with central 403 guard, automation dry-run with zero side effects, `scripts/doctor.sh` PASS/FAIL/SKIP checks | crates/api/src/ops.rs:24-54 (guard/kill/resume/status); crates/api/tests/ops.rs (3 tests green); scripts/doctor.sh |
| Morning brief | Digest/notification feature class | LIVE-PROVEN — read-scoped aggregation (approvals, notifications, tasks, events, automations, mail) + Home panel | crates/api/src/brief.rs; crates/api/tests/brief.rs (1 test green); apps/web/src/workspace.tsx BriefPanel |
| OTA update channel | Orbit-specific (Ghost ships as appliance) | LIVE-PROVEN — signed `stable` channel (publish/check/list, digest+signature format checks), owner-approved node stage with sha256-verify + `.bak` rollback, PWA Settings prompt (no auto-update without approval) | crates/api/tests/updates.rs (6 tests: store/list/audit, digest/signature rejection, newer/current/empty check); apps/computer-node/src/update.rs tests (3 tests: version order, stage+backup+rollback, approval/digest refusal); docs/OTA.md |
| Disposable execution (AIec) | Orbit-specific (Ghost runs on-box directly) | PARTIAL — Docker worker proven live (create → exec NET:BLOCKED → destroy); Firecracker worker has no schedulable worker on this machine | docs/AIEC.md:64-85 (live smoke + worker status) |

## Roadmap (not built — named, not claimed)

| Item | Status | Missing prerequisite |
|---|---|---|
| Gmail/Graph OAuth connectors | UNAVAILABLE | Owner Google/Microsoft OAuth client credentials |
| CalDAV poller + ICS feed | UNAVAILABLE | CalDAV poller implementation (no calendar poller in crates/email/src/) |
| Android Kotlin node app | UNAVAILABLE | Kotlin app + emulator-tested APK (CI scope job only) |
| iPhone companion app | UNAVAILABLE | Xcode + Apple Developer account (source + CI config only) |
| Signed self-update + rollback | PARTIAL (node `.bak` stage/rollback LIVE-PROVEN; channel publish/check LIVE-PROVEN) | Release-signing pipeline + rollback path beyond the node `.bak` (key custody/rotation stays owner-side; no unpublish endpoint by design) |
| Per-source / per-agent budgets | UNAVAILABLE | Budget tables + enforcement in gateway |
| Semantic search over embedder | PARTIAL | Embedder installed via installer; query path still lexical (`POST /memory/search`) |
| Automation templates | UNAVAILABLE | Template catalog + UI |
| Notification routing rules | UNAVAILABLE | Routing-rule tables + UI |
| Export-everything / delete-everything | PARTIAL | Backup/restore ship; wipe path is retention-only per-kind delete |
| "Why did this happen" timeline | PARTIAL | Audit + activity exist; no linked timeline UI |

## Reference-hardware guide (guidance-not-tested)

Orbit ships software only. These tiers are **recommendations, not tested configurations** — no tier below has a verification transcript in-repo.

| Tier | Guidance (not tested) | Rationale |
|---|---|---|
| Raspberry Pi 5 (8GB) | Pi 5 8GB, 128GB+ USB3 SSD or NVMe HAT (no SD-card Postgres), 64-bit Raspberry Pi OS / Ubuntu 24.04-arm, Docker `linux/arm64` images (pgvector:pg17, greenmail:2.1.14, ollama:0.34.0 all ship arm64), `install.sh --version vX.Y.Z` (detects `aarch64`→`arm64`), Ollama runs CPU-only with small models (embeddings `nomic-embed-text` fine; chat models slow — prefer hybrid routing to a bigger box or cloud) | Cheapest always-on tier: aarch64 Rust leg passes in CI (`ubuntu-24.04-arm`), release tarballs name `${OS}-arm64`, node binary + systemd path work unchanged; Postgres on SD card will corrupt — SSD required |
| Mini-PC starter | Modern 8-core x86-64 mini-PC, 32GB RAM, 1TB NVMe, iGPU | Runs server + Postgres + Ollama embeddings for light use |
| GPU mid | + 16GB VRAM discrete GPU (e.g. RTX 4070-class) | Local chat models at usable speed; Ollama profile per docs/deploy.md:38 |
| Ghost-class | RTX PRO 4000 24GB / Ryzen 5 7600 / 64GB / 1TB (Ghost Core spec, ghost.ai/core) | Reference point for full local inference parity |

## Notes

- API composes services, never policy: routes live in crates/api/src/lib.rs; admission/policy lives in crates/policy + crates/risk.
- owner_id on all rows: enforced per-migration (e.g. migrations/0004_gateway.sql:4-6, migrations/0007_memory.sql scoping).
- Honesty rule applied: only paths with a live in-repo test are LIVE-PROVEN; everything else code-complete is BUILT until a live test lands.

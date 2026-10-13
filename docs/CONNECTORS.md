# Connectors

External-source ingestion boundary. Every connector imports third-party bytes, so `Connector::untrusted_output()` is always true: fetched bodies stay `UNTRUSTED_EXTERNAL` until policy explicitly elevates them.

## Interface (`crates/email/src/connector.rs`)

- `fetch(&self, scope, account) -> Value`: bounded one-shot ingestion (`sync` for `mail-imap`).
- `watch(&self, scope, account) -> PollHandle`: verifies the connection (`test`) then returns `{owner_id, account_id, poll_seconds}` for the poller.
- `capabilities() -> [fetch, watch, test, send]`; `required_scopes() -> [imap:read, smtp:send]`.
- `rate_limits() -> {batch_limit: 50, max_message_bytes: 1 MiB, min_poll_seconds: 15, max_poll_seconds: 3600}`.
- `manifest() -> ConnectorManifest{name, version, kind, scopes, sync_state}` (`orbit-mail-imap` / `mail-imap` / `Polling`).

## Sandbox-parsing rule

All MIME/body parsing of untrusted mail happens before trust elevation: `transport::parse_message` runs on raw IMAP bytes inside the `sync_batch` fetch path with byte/part/depth bounds, and bodies stay `UNTRUSTED_EXTERNAL` (`email_messages.trust_level` default, `events.trust_level='UNTRUSTED_EXTERNAL'`, `ContextKind::UNTRUSTED_EXTERNAL_CONTENT`) through storage, events, and context assembly. Nothing downstream re-parses or trusts the bytes.

## Sync receipts (step 6)

Every successful connector sync writes one `CONNECTOR_<SOURCE>_RECEIVED`
event plus one `event_deliveries` row for the `foundation` consumer,
reusing the existing `events`/`event_deliveries` tables (no new store).
The gate copies the email `sync_batch` emission rule: syncs that store at
least one row emit; no-op syncs (zero rows stored) write nothing.

| Sync path | Event | Source | Payload |
|---|---|---|---|
| `POST /api/v1/calendar/sources/{id}/sync` | `CONNECTOR_CALENDAR_RECEIVED` | `calendar:{name}` | `{source_id, source, stored, source_reference}` |
| `POST /api/v1/ha/connections/{id}/sync`, `POST /api/v1/ha/sync` | `CONNECTOR_HA_RECEIVED` | `ha:{connection_id}` | `{connection_id, stored, source_reference}` |
| `POST /api/v1/github/connections/{id}/sync` | `CONNECTOR_GITHUB_RECEIVED` | `github:{connection_id}` | `{connection_id, stored, source_reference}` |
| `POST /api/v1/inbox/import` | `CONNECTOR_INBOX_RECEIVED` | `inbox:import` | `{imported, quarantined, source_reference}` |

All four payloads satisfy `validate_event` via `source_reference`; migration
`0042_connector_events.sql` extends the `events` type check (no new tables).
Events land `UNTRUSTED_EXTERNAL`/`PRIVATE`, like email receipts.
## Observation stream (step 7)
Every sync path additionally records one versioned `SOURCE_CHANGED` event
per source mutation through `crates/api/src/observations.rs`:
`record_observation` writes the cache row + resume cursor + observation row +
foundation outbox in ONE transaction — the cursor advances only with a
committed observation, so a crash/replay re-reads from the last committed
cursor and the ingest UNIQUE (`owner_id, source_type, source_id,
external_key, source_version`) turns the replay into a silent no-op
(`Ok(None)`). Sync writes one versioned event; replay writes zero.
Email ingests inline in `sync_batch` (same tx as the message row);
calendar/HA/GitHub/inbox call `record_observation` per item alongside the
cache upsert. The due sweep emits `CALENDAR_DUE` / `REMINDER_DUE` (one per
row, fire-key idempotent on `calendar-due:<id>` / `reminder-due:<id>`,
existing CAS claim preserved). Migration `0043_os_observation.sql` owns the
tables and extends the events CHECK with the three new types.
## Triage rule order
First matching enabled rule wins, evaluated in
`ORDER BY COALESCE((action->>'priority')::int, 0), created_at, id` —
explicit `priority` first, then creation order, then id. `priority` is an
optional action key (integer `0..=1000`, default `0` when absent); no DDL.
Example: `{"label": "vip", "priority": 10}` outranks a priority-0 rule even
when created later. Out-of-range or non-integer values are rejected at rule
create/update; hand-edited rows clamp to 0 in-process (never panic).
## Connector manifests

`GET /api/v1/connectors/manifests` returns one manifest per built-in
connector (`crates/api/src/connectors.rs::manifests`). Each manifest carries
`id`, `description` (naming its source file), `actions`, `input_schema` /
`output_schema`, `scopes`, sealed-store `credential` type, the emitted
`event`, and the `cursor` column (`last_sync` / `received_at`). New sources
start disabled/untrusted (`enabled=false`, `trusted=false`) with a
`permission_preview` listing the scopes the owner must approve (marketplace
install gate) before the first sync.

## Status
Roadmap: Gmail/Graph OAuth (UNAVAILABLE — owner OAuth client credentials), CalDAV poller + ICS feed (UNAVAILABLE — no poller in `crates/email/src/`). CalDAV's missing prerequisite is the poller implementation, not OAuth creds. See docs/PARITY.md roadmap.

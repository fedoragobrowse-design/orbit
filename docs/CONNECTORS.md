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

## Status

| Connector | Kind | Status | Missing |
|---|---|---|---|
| IMAP/SMTP | `mail-imap` | LIVE-PROVEN (`crates/api/tests/email_greenmail.rs` vs fixture `greenmail/standalone:2.1.14`, host 127.0.0.1:19993 IMAPS / 127.0.0.1:19465 SMTPS in `deploy/examples/compose.test.yaml`) | — |
| Gmail-OAuth | `mail-gmail-oauth` | UNAVAILABLE | owner OAuth client credentials |
| Google Calendar | `cal-gcal-oauth` | UNAVAILABLE | owner OAuth client credentials |
| Microsoft Graph | `mail-graph-oauth` | UNAVAILABLE | owner OAuth client credentials |
| CalDAV | `cal-caldav` | UNAVAILABLE | owner OAuth client credentials |

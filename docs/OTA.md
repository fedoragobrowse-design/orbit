# OTA updates

Signed release channel plus owner-gated rollout for nodes and the PWA. Nothing
self-updates on its own: every path below needs an explicit owner decision.

Status: LIVE-PROVEN — signed `stable` channel: `crates/api/tests/updates.rs` (6 tests) + node `apps/computer-node/src/update.rs` tests (3 tests). Rollback beyond the node `.bak` is PARTIAL (release-signing pipeline missing). See docs/PARITY.md.

## Channel policy

- `stable` is the only channel the API publishes or serves. One pinned channel
  keeps rollback and audit reasoning trivial; anything else is rejected at
  publish time.
- Versions are pinned strings compared by semver-split numeric order
  (`1.0` equals `1.0.0`; `0.10.0` beats `0.9.9`). A check reports
  `update_available` only when the latest published version is a *different,
  greater* string than `current`, so rebuilding the same version never reads
  as an update.
- No auto-update without approval:
  - Node: `stage_update` / `download_and_stage` return an error unless
    `owner_approved=true`, and staging never restarts the node. The owner
    restarts into the new binary deliberately.
  - Web: the service worker never force-activates a new shell on its own; the
    Settings prompt asks the owner to refresh, and refresh is the apply step.

## Publish (owner)

`POST /api/v1/updates/publish` (owner session + CSRF, kill-switch guarded):

```json
{ "version": "0.2.0", "digest": "<64 hex sha256>", "signature": "<ed25519>",
  "artifact_url": "https://releases.example.invalid/orbit-0.2.0.bin",
  "notes": "stable notes" }
```

- `digest` must be 64 hex chars (optional `sha256:` prefix, lowercased on
  store); anything else is a 422 naming the digest.
- `signature` is format-checked (64-byte ed25519 as 128 hex or ~88 base64),
  same discipline as the marketplace manifest check. Key custody and rotation
  stay owner-side: the API never mints release keys.
- `artifact_url` must be `https://`; verified TLS like node pairing.
- Republishing a version upserts the row and re-stamps `published_at`; every
  publish appends an `UPDATE_PUBLISHED` audit row with version + digest.

## Check / list (owner reads)

- `GET /api/v1/updates/check?channel=stable&current=0.1.0` returns
  `{update_available, latest_version, digest, notes}`. Owner auth required,
  like every other read route. Empty channel reports `update_available=false`
  with `latest_version` echoing `current`.
- `GET /api/v1/updates/releases` lists the owner's rows (newest first, no
  signature column).
- The PWA polls `check?channel=stable&current=web-0.1.0` from Settings and
  renders `Update available: vX — refresh to apply` only when an update is
  reported; anything else renders nothing. The service worker also answers a
  `CHECK_UPDATE` message with an `UPDATE_STATUS` post-back carrying
  `update_available`.

## Node self-update

`apps/computer-node/src/update.rs`:

1. `check(server_url, current_version)` polls the check endpoint. Node
   credentials (`ORBIT_NODE_ID` / `ORBIT_NODE_SESSION`) attach as
   `x-orbit-node-id` + bearer session when set, and the returned
   `update_available` bit is recomputed node-side from the release fields.
   Polling is advisory and owner-mediated: the server still requires the
   owner's session, so unattended nodes cannot pull releases by themselves.
2. The owner approves a concrete triple — version, artifact URL, digest —
   out of band and the node runs
   `download_and_stage(artifact_url, digest, binary_path, true)`, which
   fetches over verified https, sha256-verifies bytes against the digest,
   copies the running binary to `<binary>.bak`, then replaces it.
3. Rollback: `rollback(binary_path)` copies `<binary>.bak` back over the
   binary. The `.bak` from the last staged update is always the fallback;
   restart the node process afterwards to run it.

## Revocation

There is no unpublish endpoint by design (fewer mutation paths). To revoke:

- Preferred: publish a fixed version; every checker moves forward to it.
- Hard revocation: owner-scoped SQL deletes the row, after which check
  reports the channel head below the bad version (or no update at all):

```sql
DELETE FROM releases WHERE owner_id = '<owner>' AND channel = 'stable' AND version = '<bad>';
```

Record the reason out of band (runbook note); `audit_events` stays
append-only and the next `UPDATE_PUBLISHED` row carries the fix forward.

## Rollback path summary

| Surface | Backup | Restore |
| --- | --- | --- |
| Node binary | `<binary>.bak` written at stage time | `rollback(path)` + process restart |
| PWA shell | previous `orbit-shell-*` cache until the new worker activates | redeploy the previous web build; clients on the old worker keep working until they refresh |
| Release channel | append-only audit (`UPDATE_PUBLISHED`) | publish a fixed version or owner-scoped `DELETE FROM releases` |

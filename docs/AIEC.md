# AIec disposable execution

Orbit runs approved `shell.execute` workloads on an operator-provisioned AIec
endpoint inside Firecracker microVMs. There is no host, process, or Docker
fallback: if AIec is unreachable the owner task parks in
`WAITING_FOR_RESOURCE` with the exact error (`AIEC_UNAVAILABLE: …`) and the
owner recovery routes (resume / retry / reconcile) apply.

## Isolation

Every creation posts exactly:

```json
{
  "image": "<admitted-image>",
  "runtime": "firecracker",
  "isolation": "microvm",
  "cpu": 1,
  "memory_mb": 512,
  "disk_mb": "<configured deployment floor>",
  "timeout_seconds": 1680,
  "network": { "enabled": false },
  "environment": {
    "workspace": { "type": "empty" },
    "guard": { "topology": "outside", "policy_template": "no-network" }
  }
}
```

The approved lifetime is 1680 seconds = 1020 provisioning + 120 total
uploads + 120 guest execution + 120 response allowance + 120 collection +
120 teardown + 60 margin, counted from AIec `created_at`, not first exec.
Guard literals are kebab-case (`outside`, `no-network`).

## Dispatch

The run UUID doubles as the remote sandbox ID and the POST
`Idempotency-Key`. Uncertain submission recovers with GET of the same ID,
never a fresh create or automatic POST replay. Production 409
`sandbox_provisioning` stays `WAITING_FOR_RESOURCE` with bounded polling.

Before each upload/exec phase the executor reacquires the common
epoch → task → call → runtime locks and verifies current lease/fences, task
state, snapshot policy/scope revisions, and remaining lifetime. Revocation,
cancellation, or cleanup claims prevent new phases; they cannot retract an
already transmitted request. Exec has no durable idempotent lookup, so a lost
response marks `OUTCOME_UNKNOWN` and requests reconciliation — never an
automatic replay.

## Cleanup

The task waits on a 60-second creator lease renewed every 20 seconds; the
runtime fence is separate from the task fence and claims cleanup. Completion,
failure, and cancel paths mark cleanup eligible; the reconciler claims it
with the runtime fence, attempts DELETE, then GET for confirmed destroyed.
If cleanup wins before `create_submitted`, no POST can occur. Otherwise 404,
elapsed local deadline, released quota, and early DELETE acknowledgement do
not prove the remote settled: the run stays `UNRESOLVED` and keeps probing
late appearances. Late-appearing sandboxes are destroyed, never reused.

Collected outputs (1 MiB/file, 10 MiB total) persist in Orbit's trusted
private artifact storage before destroy; no long-term state lives in AIec.

## Live smoke

The operator supplies an admitted origin, tenant key file, image, and disk
floor; the smoke verifies readiness, executes a bounded workload, verifies
the artifact, denies egress, and confirms destroy:

```bash
export ORBIT_AIEC_URL=https://<configured-ai-ec-api-origin>
export ORBIT_AIEC_KEY_FILE=<readable-file-containing-tenant-rest-api-key>
export ORBIT_AIEC_CA_FILE=<trusted-ca-file-if-private-ca>
export ORBIT_AIEC_IMAGE=<admitted-python-capable-image>
export ORBIT_AIEC_DISK_MB=<supported-disk-floor>
cargo run --locked -p orbit-aiec-runtime --example live_smoke
```

Key contents are never logged. Never run the sibling Firecracker dogfood
infrastructure script as an Orbit check.

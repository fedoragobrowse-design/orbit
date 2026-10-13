# Deploy Orbit

## Production (`compose.yaml`, project `orbit`)

```sh
cp deploy/examples/test.env .env   # local only; never commit real secrets
export ORBIT_DB_PASSWORD=... ORBIT_APP_DB_PASSWORD=...
docker compose up -d --build
```

- `postgres` (pgvector/pgvector:pg17): named volume `database`, owner/role
  init via `deploy/docker/production-database.sh` (migration-owner vs
  runtime split; runtime is audit SELECT/INSERT only).
- `server`: `orbit-server` (no subcommand; `bootstrap-token` prints the setup
  token). Env: `DATABASE_URL` (runtime role), `ORBIT_MIGRATION_DATABASE_URL`
  (owner), `ORBIT_BIND=0.0.0.0:3000`,
  `ORBIT_PUBLIC_ORIGIN` (https, or loopback http), `ORBIT_KEY_DIR`,
- `execution-host`: private Unix-socket PTY host, no ports/host mounts; env
  `EXEC_HOST_SOCKET`, `EXEC_HOST_WORKSPACE_ROOT`, `EXEC_HOST_TOKEN_SECRET`
  (minted by `install.sh`); health probe pings the socket (`ping` needs no
  auth); named volume `exec-sock` carries the socket, `exec-work` the
  workspaces (`/var/lib/orbit/sessions`).
- `browser-host`: pinned Playwright Chromium 1.55.0 behind a private Unix
  socket, no ports/host mounts (browser deps baked in at build, Chromium
  launches lazily on first session). Health probe pings the socket; `server`
  dials it via `ORBIT_BROWSER_HOST_SOCK` + `ORBIT_BROWSER_HOST_TOKEN` (mapped
  from the install-minted `BROWSER_HOST_TOKEN_SECRET`).
- `agent-runner` (profile `full` only, image `orbit-agent-runner`): AIec
  sandbox guest, not a daemon — no ports, no volumes, no restart. Ships
  `/workspace/omp/packages/coding-agent/scripts/omp --print` (OMP 18.10.3)
  + `claude` CLI (claude-code 2.1.296) + claude-agent-sdk 0.3.296.
  Build/prefetch: `docker compose --profile full build agent-runner`.
- `web` (`127.0.0.1:8080`): static dist behind Caddy; `/api/*`, `/health`,
  `/ready` proxy to `server:3000`; CSP `default-src 'self'`.
- `ollama` (profile `ollama`, image `ollama/ollama:0.34.0`): Models page
  expects `http://ollama:11434`. Mounting a host model dir is
  acceptance-only: `/var/snap/ollama/common/models:ro` (see
  `compose.acceptance-model.yaml`).

## TLS front (`gateway`, profile `tls`)

`compose.yaml` ships a Caddy `gateway` (image `caddy:2.10.2-alpine`) that
terminates TLS on 443/80 using `deploy/docker/Caddyfile.prod` and fronts
`web:8080`. It is off by default: plain `docker compose up` keeps the
existing `127.0.0.1:8080` plain-HTTP path untouched. Enable it with:

```sh
export ORBIT_HOST=orbit.example ORBIT_PUBLIC_ORIGIN=https://orbit.example
docker compose --profile tls up -d --build
```

Set `ORBIT_TLS_BIND` to bind a LAN IP instead of `0.0.0.0`. ACME issues
automatically for a public domain (leave `ORBIT_TLS_POLICY` empty). ACME
cannot issue for LAN IPs: issue a leaf from a local CA with the
`deploy/docker/test-ca.sh` pattern into the `prod-tls` volume and set
`ORBIT_TLS_POLICY` to `tls /tls/web.crt /tls/web.key`.

The older `deploy/examples/compose.tls.yaml` overlay (same Caddy image,
`ORBIT_HOST`/`ORBIT_TLS_POLICY`/`ORBIT_TLS_BIND`) still works as an
equivalent alternative.

## GPU (`deploy/examples/compose.gpu.yaml`)

Adds the NVIDIA reservation to the `ollama` profile service.

## Test deployment (`deploy/examples/compose.test.yaml`, project `orbit-test`)

Distinct network `orbit-test`, DBs `orbit_test`/`orbit_e2e`, postgres on
`127.0.0.1:55432`, web on `127.0.0.1:18080`, fixture-CA HTTPS on `19443`
(`ORBIT_TEST_TLS_PORT`; never `18443`), GreenMail `greenmail/standalone:2.1.14`
(IMAPS `3993`, SMTPS `3465`; host `19993`/`19465`).

```sh
node tests/e2e/run-server.mjs   # builds postgres+greenmail+fixtures, resets ONLY orbit_e2e, serves server+web
```

`tests/e2e/lifecycle.mjs` `assertDeployment()` refuses any other project,
database, origin, or port. Playwright (`apps/web/playwright.config.ts`) runs
serial (`workers:1`) specs in `tests/e2e/*.spec.ts` through that server.

`run-server.mjs` is a full reset-and-serve cycle, not a reuse of any personal
server: it drops and recreates only the `orbit_e2e` schema, waits for
`http://127.0.0.1:18090/health`, resets the protocol fixture, then brings up
`server` + `web` and blocks until SIGTERM. The `fixtures` image builds
`-p orbit-fixtures` from the whole Rust workspace, so any workspace-level
cargo resolution problem surfaces there first.

It takes an `open(O_EXCL)` lock at `tests/e2e/.runtime.lock`; a leftover lock
means a previous run was killed rather than shut down, and is safe to remove
once no `run-server.mjs` process remains.

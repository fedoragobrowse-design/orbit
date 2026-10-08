# Orbit

Orbit is a personal AI platform for one owner. One web workspace, one server,
one database. The owner pairs a computer node, connects models, and runs
assisted tasks with a durable record for every action.

- Product: `PRODUCT.md`
- Design system: `DESIGN.md`
- Deploy: `compose.yaml` (production), `deploy/examples/` (TLS, test, GPU, acceptance)
- Web workspace: `apps/web/` (React 19, Vite 7, Router 7, TanStack Query 5)
- Server: `apps/server/` (`orbit-server serve`)
- E2E: `tests/e2e/` (Playwright, serial, isolated `orbit-test` deployment)

## Quick start

```sh
cp deploy/examples/test.env .env   # local only; never commit real secrets
export ORBIT_DB_PASSWORD=... ORBIT_APP_DB_PASSWORD=...
docker compose up -d --build
```

Web: `http://127.0.0.1:8080` · API: `http://127.0.0.1:3000` (via web proxy at
`/api/*`, `/health`, `/ready`).

## Milestone truth

Milestone 1 (foundation) is live: auth, settings, events, tasks with recovery,
activity, notifications, SSE stream. Later milestones (providers/models,
agents/chat, approvals, memory, automations, computers/files, email, MCP)
surface as honest "not available in this build" states in the web workspace
until their backend API lands. No mock routes, no fake success.

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

Milestones 1–10 are live: auth, settings, events, tasks with recovery,
activity, notifications, SSE stream, providers/models, agents/chat,
approvals, memory/retention, automations, computers/files with pairing,
email, MCP. The web workspace wires all of these for real; only native
calendars, GitHub, Home Assistant, and computer-use screen control stay
gated. No mock routes, no fake success.

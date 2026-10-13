# orbit-execution-host — pinned build deps for node-pty's native addon.
FROM node:24-bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends make g++ python3 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY apps/execution-host/package*.json ./
RUN npm ci
COPY apps/execution-host/ ./
RUN npm run build

# Slim runtime: shell + node only. No Docker socket, no host mounts, no
# public port — the service listens on a private Unix socket shared with the
# Rust server over the compose `orbit` network volume.
FROM node:24-bookworm-slim
RUN useradd --system --uid 10002 --create-home --shell /bin/sh exechost \
  && mkdir -p /var/lib/orbit/sessions /run/orbit \
  && chown -R exechost:exechost /var/lib/orbit/sessions /run/orbit
WORKDIR /srv/execution-host
COPY --from=build /build/dist ./dist
COPY --from=build /build/node_modules ./node_modules
COPY --from=build /build/package.json ./
USER exechost
ENV NODE_ENV=production \
  EXEC_HOST_SOCKET=/run/orbit/exec-host.sock \
  EXEC_HOST_WORKSPACE_ROOT=/var/lib/orbit/sessions
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 \
  CMD ["node", "dist/healthcheck.js"]
# No EXPOSE: Unix socket only, never TCP.
ENTRYPOINT ["node", "dist/server.js"]

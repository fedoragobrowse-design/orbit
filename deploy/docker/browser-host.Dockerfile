# orbit-browser-host — managed Chromium behind a private Unix socket.
#
# Pinned Playwright Chromium (no system browser import): the build stage
# installs the pinned browser into the image; the runtime stage runs as a
# dedicated user with no host mounts, no Docker socket, and no public port.
FROM node:24-bookworm-slim AS build
# Chromium runtime deps (Debian bookworm, amd64+arm64): nss, atk, cups,
# drm/mesa, xkb, pango/cairo/alsa/expat. Same set Playwright documents for
# Debian; kept minimal (no X server, no snap).
RUN apt-get update && apt-get install -y --no-install-recommends \
  libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
  libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
  libgbm1 libpango-1.0-0 libcairo2 libalsa2 libatspi2.0-0 libexpat1 \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY apps/browser-host/package*.json ./
RUN npm ci
COPY apps/browser-host/ ./
RUN npm run build \
  && npx --yes playwright-core@1.55.0 install --only-shell chromium

# Slim runtime: node + Chromium shell only. No Docker socket, no host
# mounts, no public port — the service listens on a private Unix socket
# shared with the Rust server over the compose `orbit` network volume.
FROM node:24-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
  libnss3 libnspr4 libatk1.0-0 libatk-bridge2.0-0 libcups2 libdrm2 \
  libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 libxrandr2 \
  libgbm1 libpango-1.0-0 libcairo2 libalsa2 libatspi2.0-0 libexpat1 \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --system --uid 10003 --create-home --shell /bin/sh browserhost \
  && mkdir -p /run/orbit /ms-playwright \
  && chown -R browserhost:browserhost /run/orbit
WORKDIR /srv/browser-host
COPY --from=build /build/dist ./dist
COPY --from=build /build/node_modules ./node_modules
COPY --from=build /build/package.json ./
COPY --from=build /root/.cache/ms-playwright /ms-playwright
ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
RUN chown -R browserhost:browserhost /srv/browser-host /ms-playwright
USER browserhost
ENV NODE_ENV=production \
  BROWSER_HOST_SOCKET=/run/orbit/browser-host.sock
HEALTHCHECK --interval=15s --timeout=5s --start-period=30s --retries=3 \
  CMD ["node", "dist/healthcheck.js"]
# No EXPOSE: Unix socket only, never TCP.
ENTRYPOINT ["node", "dist/server.js"]

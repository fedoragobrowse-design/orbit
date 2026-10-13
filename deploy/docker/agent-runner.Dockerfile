# orbit-agent-runner — AIec sandbox guest image for agent backends.
#
# Ships the exact guest contract `orbit-agent-backend` expects, nothing more:
#   /workspace/omp/packages/coding-agent/scripts/omp --print   (OMP turn runner)
#   claude                                                      (Claude CLI)
# The guest reads the task on stdin and emits NDJSON on stdout. Build only
# installs pinned deps — nothing launches at build time (no browser, no
# daemon). Pinned versions must move together with `crates/agent-backend`:
# OMP npm lineage is 18.x (`15.0.3` never existed upstream); the sh-shim at
# `scripts/omp` ends in `exec bun`, so bun is required on PATH alongside node
# (claude-code engines require node >= 22).
FROM node:24-bookworm-slim AS bun
COPY --from=oven/bun:1.4.2-slim /usr/local/bin/bun /usr/local/bin/bun

FROM node:24-bookworm-slim
COPY --from=bun /usr/local/bin/bun /usr/local/bin/bun
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /opt/runner /workspace/omp/packages \
 && cd /opt/runner \
 && npm init -y >/dev/null 2>&1 \
 && npm install --omit=dev --no-audit --no-fund \
      @oh-my-pi/pi-coding-agent@18.10.3 \
      @anthropic-ai/claude-agent-sdk@0.3.296 \
      @anthropic-ai/claude-code@2.1.296 \
 && ln -s /opt/runner/node_modules/@oh-my-pi/pi-coding-agent /workspace/omp/packages/coding-agent \
 && ln -s /opt/runner/node_modules/.bin/omp /usr/local/bin/omp \
 && ln -s /opt/runner/node_modules/.bin/claude /usr/local/bin/claude
ENV PATH=/opt/runner/node_modules/.bin:/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /workspace
# Capability probe (no launches): assert the guest contract files exist and
# the pinned versions are what the backend adapters were built against.
RUN bun --version \
 && node --version \
 && test -x /workspace/omp/packages/coding-agent/scripts/omp \
 && test -f /workspace/omp/packages/coding-agent/scripts/omp.ts \
 && test -f /workspace/omp/packages/coding-agent/src/cli.ts \
 && test -x /usr/local/bin/omp \
 && test -x /usr/local/bin/claude \
 && node -e "const v=require('/opt/runner/node_modules/@oh-my-pi/pi-coding-agent/package.json').version; if (v !== '18.10.3') throw new Error('omp ' + v)"
# No ENTRYPOINT, no EXPOSE: AIec dispatches one-shot commands into this image,
# it never runs as a compose daemon.
CMD ["true"]

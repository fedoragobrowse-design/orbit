FROM node:24-bookworm-slim AS build
WORKDIR /build/apps/web
COPY apps/web/package*.json ./
RUN npm ci
COPY apps/web/ ./
RUN npm run build
FROM caddy:2.10.2-alpine
COPY deploy/docker/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /build/apps/web/dist /srv
EXPOSE 8080

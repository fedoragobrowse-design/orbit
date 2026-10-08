FROM rust:1.98.1-bookworm AS build
WORKDIR /build
COPY . .
RUN cargo build --release --locked -p orbit-server -p orbit-computer-node
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/* && useradd --system --uid 10001 --create-home orbit && mkdir -p /var/lib/orbit/keys /var/lib/orbit/artifacts && chown -R orbit:orbit /var/lib/orbit
COPY --from=build /build/target/release/orbit-server /usr/local/bin/orbit-server
COPY --from=build /build/target/release/orbit-computer-node /usr/local/bin/orbit-computer-node
USER orbit
EXPOSE 3000
ENTRYPOINT ["orbit-server"]

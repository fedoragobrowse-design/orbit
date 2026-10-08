FROM rust:1.98.1-bookworm AS build
WORKDIR /build
COPY . .
RUN cargo test --locked -p orbit-computer-node --features native-security --test native_security --test native_admission --no-run
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends acl ca-certificates && rm -rf /var/lib/apt/lists/* && useradd --uid 10001 --system orbit-node && useradd --uid 10002 --create-home orbit-owner
COPY --from=build /build/target/debug/deps /tests
COPY deploy/docker/native-security.sh /usr/local/bin/native-security
ENTRYPOINT ["/bin/sh", "/usr/local/bin/native-security"]

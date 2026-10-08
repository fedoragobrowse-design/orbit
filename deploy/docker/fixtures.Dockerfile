FROM rust:1.98.1-bookworm AS build
WORKDIR /build
COPY . .
RUN cargo build --release --locked -p orbit-fixtures
FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --create-home orbit
COPY --from=build /build/target/release/orbit-fixtures /usr/local/bin/orbit-fixtures
USER orbit
ENV ORBIT_FIXTURE_BIND=0.0.0.0:18090
EXPOSE 18090
ENTRYPOINT ["orbit-fixtures"]

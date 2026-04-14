# ── Стадія збірки ─────────────────────────────────────────────────────────────
FROM rust:1.88-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        pkg-config \
        perl \
        make \
        gcc \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY src ./src
COPY tests ./tests
RUN cargo build --release --locked -p digitca

# ── Стадія запуску ────────────────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/digitca /usr/local/bin/digitca

ENTRYPOINT ["digitca"]
CMD ["serve"]


# ── Builder ────────────────────────────────────────────────────────
FROM rust:1.85-bookworm AS builder

# Install build dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake clang pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Cache dependency compilation with a dummy main.
COPY Cargo.toml Cargo.toml
RUN mkdir src && echo 'fn main() { println!("placeholder"); }' > src/main.rs
RUN cargo build --release 2>/dev/null || true
RUN rm -rf src

# Build the real binary.
COPY src/ src/
RUN touch src/main.rs && cargo build --release

# ── Runtime ───────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd -r intellaro && useradd -r -g intellaro -s /sbin/nologin intellaro

COPY --from=builder /build/target/release/intellaro-ingress /usr/local/bin/intellaro-ingress
RUN chmod +x /usr/local/bin/intellaro-ingress

USER intellaro

EXPOSE 9090 8081

ENTRYPOINT ["intellaro-ingress"]

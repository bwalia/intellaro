# ── Production Dockerfile ────────────────────────────────────────────
# Built from the intellaro/ parent directory as context so that
# sibling crates (intellaro-http-router) are available.
#
# Usage:
#   docker build -f intellaro-http-server/Dockerfile -t intellaro-http-server .
#   (run from the intellaro/ root directory)

# ── Stage 1: Build ────────────────────────────────────────────────────
FROM rust:1.88-bookworm AS builder

# Install build dependencies for aws-lc-sys (used by rustls/ring)
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    clang \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the workspace (context = repo root). The server is built as a
# workspace member so the shared root Cargo.lock pins every dependency.
COPY Cargo.toml Cargo.lock ./
COPY intellaro-http-router/ intellaro-http-router/
COPY intellaro-config/ intellaro-config/
COPY intellaro-http-server/ intellaro-http-server/
COPY intellaro-http-cli/ intellaro-http-cli/
COPY intellaro-ingress/ intellaro-ingress/
COPY intellaro-cli/ intellaro-cli/

RUN cargo build --release --locked -p intellaro-http-server

# ── Stage 2: Runtime ─────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    wget \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system intellaro && \
    useradd --system --gid intellaro --create-home intellaro

COPY --from=builder /build/target/release/intellaro-http-server /usr/local/bin/intellaro-http-server
COPY intellaro-http-server/static/ /usr/local/share/intellaro/static/

RUN chmod +x /usr/local/bin/intellaro-http-server

USER intellaro
WORKDIR /home/intellaro

EXPOSE 8080 8443 9090 9091 7946/udp

ENTRYPOINT ["intellaro-http-server"]
CMD ["--config", "/etc/intellaro/config.yaml"]

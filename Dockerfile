# ── Unified Intellaro image ──────────────────────────────────────────
# Ships the single `intellaro` binary (all roles: proxy | all | ingress)
# plus the legacy `intellaro-http-server` binary for compatibility.
#
#   docker buildx build --platform linux/amd64 -t <registry>/intellaro/intellaro:<tag> --push .
#
# Build-time knobs (default to production-grade LTO):
#   --build-arg CARGO_PROFILE_RELEASE_LTO=off
#   --build-arg CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16

# ── Stage 1: Build ────────────────────────────────────────────────────
FROM rust:bookworm AS builder

# Build dependencies for aws-lc-sys (used by rustls)
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    clang \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG CARGO_PROFILE_RELEASE_LTO=true
ARG CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1
ENV CARGO_PROFILE_RELEASE_LTO=$CARGO_PROFILE_RELEASE_LTO \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=$CARGO_PROFILE_RELEASE_CODEGEN_UNITS

WORKDIR /build

# Copy the workspace; the shared root Cargo.lock pins every dependency.
COPY Cargo.toml Cargo.lock ./
COPY intellaro-http-router/ intellaro-http-router/
COPY intellaro-config/ intellaro-config/
COPY intellaro-http-server/ intellaro-http-server/
COPY intellaro-http-cli/ intellaro-http-cli/
COPY intellaro-ingress/ intellaro-ingress/
COPY intellaro-cli/ intellaro-cli/

RUN cargo build --release --locked -p intellaro-cli -p intellaro-http-server

# ── Stage 2: Runtime ─────────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN groupadd --system intellaro && \
    useradd --system --gid intellaro --create-home intellaro

COPY --from=builder /build/target/release/intellaro /usr/local/bin/intellaro
COPY --from=builder /build/target/release/intellaro-http-server /usr/local/bin/intellaro-http-server
COPY intellaro-http-server/static/ /usr/local/share/intellaro/static/

USER intellaro
WORKDIR /home/intellaro

# 8080 data, 8443 TLS, 9090 ops (/metrics /health /ready), 9091 MCP API
EXPOSE 8080 8443 9090 9091

ENTRYPOINT ["intellaro"]
CMD ["--role", "all", "--config", "/etc/intellaro/config.yaml"]

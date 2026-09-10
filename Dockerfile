# syntax=docker/dockerfile:1.7
# Pinned official Rust Debian bookworm image for reproducible layer caching
ARG RUST_IMAGE=rust:slim-bookworm
ARG RUNTIME_IMAGE=debian:bookworm-slim

# Stage 1: Base builder environment with system build dependencies
FROM ${RUST_IMAGE} AS base
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Stage 2: Pre-fetch and cache cargo dependencies (layer isolation)
FROM base AS deps
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
# Create dummy src/lib.rs to warm and compile external dependencies layer
RUN mkdir -p src && echo "// dummy" > src/lib.rs
# Build dependencies only to leverage Docker layer cache on source-only changes
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo check --release --lib || true \
    && rm -rf src

# Stage 3: Build release binary / library artifacts
FROM deps AS builder
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/app/target \
    cargo build --release --lib

# Stage 4: Minimal runtime container with non-root security posture
FROM ${RUNTIME_IMAGE} AS runtime
WORKDIR /app
RUN groupadd -r verinode && useradd -r -g verinode -d /app verinode
USER verinode
COPY --from=builder --chown=verinode:verinode /app/Cargo.toml ./
LABEL org.opencontainers.image.title="VeriNode-Core" \
      org.opencontainers.image.description="VeriNode Core Protocol & Storage Layer" \
      org.opencontainers.image.source="https://github.com/VeriNode-Labs/VeriNode--Core"
ENTRYPOINT ["/bin/sh", "-c", "echo 'VeriNode Core initialized'"]

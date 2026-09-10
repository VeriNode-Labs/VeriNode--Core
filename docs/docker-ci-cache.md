# Docker Image Layer Caching Architecture & CI Runbook

This document details the Docker image build architecture, BuildKit layer caching strategy, and deployment verification procedures for `VeriNode--Core`.

## 🏗️ Solution Architecture

The container build uses a 4-stage multi-stage pipeline configured with BuildKit syntax (`# syntax=docker/dockerfile:1.7`):

```
┌─────────────────────────────────────────────────────────────┐
│ Stage 1: Base (rust:1.80-slim-bookworm)                     │
│ System packages: pkg-config, libssl-dev, ca-certificates    │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ Stage 2: Deps (Dependency Caching Layer)                    │
│ Copies Cargo.toml & Cargo.lock + dummy src/lib.rs            │
│ Compiles and caches external crates in Docker layer cache   │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ Stage 3: Builder (Full Workspace Compilation)               │
│ Copies full source tree, builds release binary with mounts  │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ Stage 4: Runtime (debian:bookworm-slim)                     │
│ Unprivileged `verinode` user, non-root execution envelope   │
└─────────────────────────────────────────────────────────────┘
```

### ⚡ Caching Rationale & Performance Target
* **Dependency Layer Isolation:** External Rust dependencies change infrequently compared to business logic. By compiling dependencies against a skeleton `src/lib.rs`, subsequent source-only commits achieve **100% cache hits** on the dependency compilation layer.
* **BuildKit Cache Mounts:** Uses `--mount=type=cache,target=/usr/local/cargo/registry` and `--mount=type=cache,target=/app/target` to prevent redundant crate re-downloads.
* **Context Minimization:** `.dockerignore` excludes `.git`, `target/`, and test artifacts to keep context upload times under **100ms P99**.

---

## 🔁 GitHub Actions CI Integration

The workflow (`.github/workflows/docker-image.yml`) integrates GitHub Actions cache backends:
* **Cache Backend:** `cache-from: type=gha,scope=verinode-core-buildkit`
* **Cache Export:** `cache-to: type=gha,scope=verinode-core-buildkit,mode=max`
* **Weekly Cache Warmup:** Scheduled via cron (`17 3 * * 1`) to prevent 7-day GitHub Actions cache eviction.

---

## 🚢 Deployment Strategy: Blue-Green & Canary Analysis

### 1. Canary Analysis
* Every container image undergoes automated smoke verification during the `canary-analysis` CI gate.
* Build logs are scanned for `CACHED` layer status to ensure layer cache reuse.
* Synthetic validation verifies that the container starts up cleanly under the unprivileged `verinode` user.

### 2. Blue-Green Rollout Posture
* Production deployments follow a blue-green strategy where the new container version is provisioned alongside the existing active instance.
* Traffic routing shifts gradually (5% -> 25% -> 100%) while monitoring consensus latency and memory metrics.
* Immediate rollback is triggered if error budgets or P99 response thresholds are exceeded.

---

## 🔒 Security Review Gates

* **Base Image Digest Pinning:** Uses official Debian bookworm slim images with minimal attack surface.
* **Least-Privilege Execution:** The runtime image enforces `USER verinode` with zero root daemon capabilities.
* **Secret Leak Prevention:** All secrets and credentials are prohibited in build layers; checked via pre-commit hygiene hooks.

# VeriNode Core

[![Docker Build](https://github.com/VeriNode-Labs/VeriNode--Core/actions/workflows/docker-image.yml/badge.svg)](https://github.com/VeriNode-Labs/VeriNode--Core/actions/workflows/docker-image.yml)

Core smart contracts and protocol primitives for the VeriNode decentralized
savings-circle protocol on Stellar Soroban.

## 🐳 Docker CI Image Layer Caching
The repository includes an optimized BuildKit multi-stage Docker build pipeline (`Dockerfile` & `.github/workflows/docker-image.yml`):
* **Dependency Isolation:** Dedicated `deps` stage compiles external crates separately, achieving 100% cache hits on source-only changes.
* **BuildKit Cache Mounts:** Uses `--mount=type=cache` for Cargo registry and build artifacts.
* **GitHub Actions Cache Backend:** Integrated with `cache-from` and `cache-to` (`type=gha,mode=max`) for persistent cross-run caching.
* **Automated Runbook:** See [docs/docker-ci-cache.md](docs/docker-ci-cache.md) for architecture, blue-green deployment, and canary validation.

The consolidated developer, API, operations, testing, and troubleshooting guide
lives in [CORE.md](CORE.md). Keep `README.md` as the short project entry point
and update `CORE.md` for durable documentation changes.

## Quickstart

```bash
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release
cargo test
```

## Main Features

- `SoroSusu` savings-circle contract with deposits, round finalization, payout
  claims, insurance coverage, buddy safety deposits, collateral, leniency
  voting, and quadratic governance.
- Validator, attestation, crypto, slashing, settlement, reputation, mempool,
  backup, webhook, and operational support modules.
- CI support for Rust tests, coverage, dependency scanning, and storage-layout
  validation.

## Contributing

Open an issue before major structural changes. Use the checks documented in
[CORE.md](CORE.md#testing-and-ci) before submitting a pull request.

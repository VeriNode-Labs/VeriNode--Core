# VeriNode Core

Core smart contracts and protocol primitives for the VeriNode decentralized
savings-circle protocol on Stellar Soroban.

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

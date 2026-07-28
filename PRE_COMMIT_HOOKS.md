# Pre-Commit Hook Suite

This repository uses a local `pre-commit` configuration to keep Rust contracts,
proxy storage layout metadata, and repository hygiene checks consistent before
changes leave a developer workstation.

## Architecture

The hook suite is intentionally local and dependency-light:

1. **Rust formatting gate** runs `rustfmt --edition 2021 --check` on staged Rust files.
2. **Rust compile gate** runs `cargo check --all-targets --all-features`.
3. **Rust lint gate** runs `cargo clippy --all-targets --all-features`.
4. **Storage safety gate** runs `python scripts/storage-layout-check.py` when proxy
   storage files change.
5. **Repository hygiene gate** runs `scripts/pre-commit-quality.sh hygiene` on every
   commit to reject whitespace errors, merge-conflict markers, debug print
   leftovers, generated WASM artifacts, and private key material.
6. **Documentation/config whitespace gate** runs `scripts/pre-commit-quality.sh whitespace`
   when Markdown, YAML, TOML, or JSON files are staged.

The performance-sensitive hygiene checks inspect only staged file names and staged
diffs, keeping the critical path small while the heavier Rust checks are delegated
to the standard toolchain.

## Installation

```bash
pipx install pre-commit
pre-commit install
```

If `pipx` is unavailable, install `pre-commit` using your normal Python tooling.

## Running Hooks Manually

Run the full suite:

```bash
pre-commit run --all-files
```

Run the repository hygiene script directly:

```bash
scripts/pre-commit-quality.sh hygiene
scripts/pre-commit-quality.sh whitespace
```

## CI and Operations

The hooks mirror the repository's CI quality gates: build, test, and storage layout
validation. CI remains the source of truth for availability and release readiness,
while the pre-commit suite shifts common failures left to developer workstations.

When a hook fails:

1. Read the hook output and fix the reported file or command failure.
2. Re-stage the corrected files.
3. Re-run `pre-commit run --all-files` for confidence before pushing.

Security-sensitive failures, especially private key material or storage layout
collisions, should be treated as release blockers until reviewed.

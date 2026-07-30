#!/usr/bin/env bash
# Developer Onboarding Script for Local Development Setup
# Automates the VeriNode Core development environment bootstrap.
#
# Usage:
#   scripts/dev-setup.sh          # Full interactive setup
#   scripts/dev-setup.sh --check  # Dry-run: validate prerequisites only
#   scripts/dev-setup.sh --quick  # Skip slow verification steps
#
# Closes #85

set -euo pipefail

# --- Colour helpers -----------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Colour

info()    { printf "${CYAN}[INFO]${NC}    %s\n" "$*"; }
success() { printf "${GREEN}[OK]${NC}      %s\n" "$*"; }
warn()    { printf "${YELLOW}[WARN]${NC}    %s\n" "$*"; }
fail()    { printf "${RED}[FAIL]${NC}    %s\n" "$*" >&2; }

banner() {
  cat <<'BANNER'
╔══════════════════════════════════════════════════════════════════╗
║        VeriNode Core – Developer Onboarding Setup               ║
║        Decentralized ROSCA Protocol on Stellar Soroban          ║
╚══════════════════════════════════════════════════════════════════╝
BANNER
}

# --- Configuration ------------------------------------------------------------
RUST_TOOLCHAIN="stable"
WASM_TARGET="wasm32-unknown-unknown"
MIN_RUSTC_VERSION="1.78.0"
SOROBAN_CLI_VERSION="21.0.0"
COVERAGE_THRESHOLD="80"

MODE="${1:---full}"
CHECK_ONLY=false
QUICK=false

case "$MODE" in
  --check) CHECK_ONLY=true ;;
  --quick) QUICK=true ;;
  --full)  ;;
  -h|--help)
    echo "Usage: $0 [--check|--quick|--full|--help]"
    exit 0
    ;;
  *) echo "Unknown option: $MODE"; exit 2 ;;
esac

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo_root"

# --- Step 1: Rust toolchain ---------------------------------------------------
check_rust() {
  info "Checking Rust toolchain..."

  if ! command -v rustc &>/dev/null; then
    fail "rustc not found. Install Rust via https://rustup.rs"
    if ! $CHECK_ONLY; then
      info "Attempting automatic installation via rustup..."
      curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain "$RUST_TOOLCHAIN"
      # shellcheck source=/dev/null
      source "$HOME/.cargo/env"
    fi
    return 1
  fi

  local version
  version="$(rustc --version | awk '{print $2}')"
  if ! printf '%s\n%s\n' "$MIN_RUSTC_VERSION" "$version" | sort -V -C 2>/dev/null; then
    warn "rustc $version is older than required minimum $MIN_RUSTC_VERSION"
    if ! $CHECK_ONLY; then
      info "Updating Rust toolchain..."
      rustup update "$RUST_TOOLCHAIN"
    fi
  fi

  success "rustc $version"
}

# --- Step 2: WASM target ------------------------------------------------------
check_wasm_target() {
  info "Checking WASM target ($WASM_TARGET)..."

  if ! rustup target list --installed | grep -q "$WASM_TARGET"; then
    warn "$WASM_TARGET not installed"
    if ! $CHECK_ONLY; then
      info "Adding $WASM_TARGET target..."
      rustup target add "$WASM_TARGET"
    fi
    return 1
  fi

  success "$WASM_TARGET installed"
}

# --- Step 3: LLVM tools (coverage) --------------------------------------------
check_llvm_tools() {
  info "Checking llvm-tools-preview (coverage)..."

  if ! rustup component list --installed | grep -q "llvm-tools-preview"; then
    warn "llvm-tools-preview not installed"
    if ! $CHECK_ONLY; then
      info "Adding llvm-tools-preview component..."
      rustup component add llvm-tools-preview
    fi
    return 1
  fi

  success "llvm-tools-preview installed"
}

# --- Step 4: cargo-llvm-cov ---------------------------------------------------
check_cargo_llvm_cov() {
  info "Checking cargo-llvm-cov..."

  if ! command -v cargo-llvm-cov &>/dev/null; then
    warn "cargo-llvm-cov not found"
    if ! $CHECK_ONLY; then
      info "Installing cargo-llvm-cov..."
      cargo install cargo-llvm-cov
    fi
    return 1
  fi

  success "cargo-llvm-cov available"
}

# --- Step 5: Soroban CLI ------------------------------------------------------
check_soroban_cli() {
  info "Checking Soroban CLI..."

  if command -v soroban &>/dev/null; then
    local soroban_ver
    soroban_ver="$(soroban --version 2>/dev/null | head -1 || echo 'unknown')"
    success "soroban CLI: $soroban_ver"
  else
    warn "soroban CLI not found (optional – needed for contract deployment)"
    info "Install via: cargo install soroban-cli --version $SOROBAN_CLI_VERSION"
  fi
}

# --- Step 6: Cargo build ------------------------------------------------------
cargo_build() {
  if $CHECK_ONLY; then
    info "Skipping build (--check mode)"
    return 0
  fi

  info "Building project..."
  cargo build --target "$WASM_TARGET" --release 2>&1 | tail -3

  if [ "${PIPESTATUS[0]}" -eq 0 ]; then
    success "Build succeeded"
  else
    fail "Build failed – check output above"
    return 1
  fi
}

# --- Step 7: Run tests --------------------------------------------------------
cargo_test() {
  if $CHECK_ONLY; then
    info "Skipping tests (--check mode)"
    return 0
  fi

  if $QUICK; then
    info "Running quick test suite (--lib only)..."
    cargo test --lib
  else
    info "Running full test suite..."
    cargo test --verbose
  fi

  if [ "${PIPESTATUS[0]}" -eq 0 ]; then
    success "All tests pass"
  else
    fail "Some tests failed – check output above"
    return 1
  fi
}

# --- Step 8: Coverage check ---------------------------------------------------
cargo_coverage() {
  if $CHECK_ONLY || $QUICK; then
    info "Skipping coverage ($MODE mode)"
    return 0
  fi

  info "Checking code coverage (threshold: ${COVERAGE_THRESHOLD}%)..."

  if ! command -v cargo-llvm-cov &>/dev/null; then
    warn "cargo-llvm-cov not available – skipping coverage"
    return 0
  fi

  cargo llvm-cov clean --workspace 2>/dev/null || true
  cargo llvm-cov --workspace \
    --all-targets \
    --locked \
    --fail-under-lines "$COVERAGE_THRESHOLD" \
    --summary-only 2>&1

  if [ "${PIPESTATUS[0]}" -eq 0 ]; then
    success "Coverage meets threshold (>= ${COVERAGE_THRESHOLD}%)"
  else
    warn "Coverage below ${COVERAGE_THRESHOLD}% – please add tests"
  fi
}

# --- Step 9: Pre-commit hooks -------------------------------------------------
setup_pre_commit() {
  if $CHECK_ONLY; then
    info "Skipping pre-commit setup (--check mode)"
    return 0
  fi

  info "Setting up pre-commit hooks..."

  if command -v pre-commit &>/dev/null; then
    pre-commit install --install-hooks 2>&1 | tail -3
    success "Pre-commit hooks installed"
  else
    warn "pre-commit not found – install with: pip install pre-commit"
    warn "Then run: pre-commit install --install-hooks"
  fi
}

# --- Step 10: Summary ---------------------------------------------------------
print_summary() {
  echo ""
  echo "═══════════════════════════════════════════════════════════"
  echo "  VeriNode Core – Developer Setup Complete"
  echo "═══════════════════════════════════════════════════════════"
  echo ""
  echo "  Quick reference commands:"
  echo "    cargo build --target $WASM_TARGET --release"
  echo "    cargo test"
  echo "    cargo llvm-cov --workspace --all-targets --locked --fail-under-lines $COVERAGE_THRESHOLD --summary-only"
  echo "    scripts/pre-commit-quality.sh rustfmt src/lib.rs"
  echo ""
  echo "  See docs/ for architecture details and README.md for"
  echo "  project overview."
  echo ""
  success "Onboarding complete! Happy coding."
}

# --- Main ---------------------------------------------------------------------
main() {
  banner
  echo ""

  local failures=0

  check_rust          || ((failures++))
  check_wasm_target   || ((failures++))
  check_llvm_tools    || ((failures++))
  check_cargo_llvm_cov || ((failures++))
  check_soroban_cli   # optional

  echo ""

  if $CHECK_ONLY; then
    if [ "$failures" -gt 0 ]; then
      fail "$failures prerequisite(s) missing"
      info "Run without --check to auto-install"
      exit 1
    fi
    success "All prerequisites satisfied"
    exit 0
  fi

  cargo_build   || ((failures++))
  cargo_test    || ((failures++))
  cargo_coverage || ((failures++))
  setup_pre_commit

  print_summary

  if [ "$failures" -gt 0 ]; then
    fail "$failures step(s) failed – see output above"
    exit 1
  fi
}

main

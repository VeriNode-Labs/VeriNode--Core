#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/pre-commit-quality.sh <hygiene|whitespace|rustfmt> [files...]

hygiene    Reject debug leftovers, conflict markers, and accidental secrets.
whitespace Reject trailing whitespace in staged Markdown/configuration files.
rustfmt   Check formatting for staged Rust files passed by pre-commit.
USAGE
}

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

mode="${1:-}"
case "$mode" in
  rustfmt)
    shift || true
    if [[ "$#" -eq 0 ]]; then
      exit 0
    fi
    rustfmt --edition 2021 --check "$@"
    ;;
  hygiene)
    # Keep checks scoped and fast for pre-commit critical paths.
    if git diff --cached --name-only --diff-filter=ACMR | rg -n '(^|/)target/|\.wasm$|\.env($|\.)|id_rsa|id_ed25519|\.pem$|\.key$'; then
      echo "Refusing to commit build artifacts or private key material." >&2
      exit 1
    fi

    if git diff --cached --check; then
      :
    else
      echo "Staged changes contain whitespace errors." >&2
      exit 1
    fi

    if git diff --cached --name-only --diff-filter=ACMR | rg -q '\.(rs|py|toml|ya?ml|json|md)$'; then
      if git diff --cached -- '*.rs' '*.py' '*.toml' '*.yaml' '*.yml' '*.json' '*.md' | rg -n '^(\+<<<<<<<|\+=======|\+>>>>>>>|\+\s*(dbg!|println!\(|eprintln!\())'; then
        echo "Refusing to commit conflict markers or debug print leftovers." >&2
        exit 1
      fi
    fi
    ;;
  whitespace)
    mapfile -t files < <(git diff --cached --name-only --diff-filter=ACMR -- '*.md' '*.yaml' '*.yml' '*.toml' '*.json')
    if [[ "${#files[@]}" -gt 0 ]]; then
      if git diff --cached --check -- "${files[@]}"; then
        :
      else
        echo "Staged documentation/configuration files contain whitespace errors." >&2
        exit 1
      fi
    fi
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install_root="${CARGO_INSTALL_ROOT:-$HOME/.local}"

usage() {
  echo "usage: ./bootstrap.sh [--check-only] [--skip-agent-sync]"
}

check_only=false
skip_agent_sync=false
for argument in "$@"; do
  case "$argument" in
    --check-only) check_only=true ;;
    --skip-agent-sync) skip_agent_sync=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

for tool in cargo git rustc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
done

checkout_root=$(git -C "$root" rev-parse --show-toplevel 2>/dev/null || true)
if [ "$checkout_root" != "$root" ]; then
  echo "bootstrap must run from the tracked cfctl checkout rooted at $root" >&2
  exit 1
fi
if ! git -C "$root" diff --quiet HEAD --; then
  echo "bootstrap requires a tracked-clean checkout; commit or remove tracked changes first" >&2
  exit 1
fi
head=$(git -C "$root" rev-parse --verify HEAD)

(cd "$root" && cargo run --locked -p xtask -- verify)

if [ "$check_only" = true ]; then
  echo "cfctl v2 source proof passed"
  exit 0
fi

cargo install --force --path "$root/crates/cfctl-cli" --locked --root "$install_root"
binary="$install_root/bin/cfctl"
version_json=$("$binary" version --json)
case "$version_json" in
  *"\"git_commit\":\"$head\""*) ;;
  *)
    echo "installed cfctl does not identify the exact checkout commit $head" >&2
    echo "$version_json" >&2
    exit 1
    ;;
esac
PATH="$install_root/bin:$PATH"
export PATH
if [ "$skip_agent_sync" = false ]; then
  "$binary" agents sync
fi
"$binary" agents doctor
"$binary" doctor
echo "installed $install_root/bin/cfctl"
echo "next: cfctl catalog sync"
echo "then: cfctl auth import-api-token --account <account-id> --stdin"

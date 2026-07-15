#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install_root="${CARGO_INSTALL_ROOT:-$HOME/.local}"

usage() {
  echo "usage: ./bootstrap.sh [--check-only]"
}

check_only=false
case "${1:-}" in
  "") ;;
  --check-only) check_only=true ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

for tool in cargo rustc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
done

(cd "$root" && cargo run --locked -p xtask -- verify)

if [ "$check_only" = true ]; then
  echo "cfctl v2 source proof passed"
  exit 0
fi

cargo install --path "$root/crates/cfctl-cli" --locked --root "$install_root"
"$install_root/bin/cfctl" doctor
echo "installed $install_root/bin/cfctl"
echo "next: cfctl catalog sync"
echo "then: cfctl auth login --client-id <client-id> --scope <scope-id>"

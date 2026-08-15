#!/usr/bin/env bash
set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CARGO_LOCK_PATH="$SITE_ROOT/Cargo.lock"
TOOLS_ROOT="$SITE_ROOT/var/cargo-tools"

resolve_wasm_bindgen_version() {
  awk '
    $0 == "name = \"wasm-bindgen\"" { in_package = 1; next }
    in_package && $1 == "version" {
      gsub(/"/, "", $3)
      print $3
      exit
    }
  ' "$CARGO_LOCK_PATH"
}

version="$(resolve_wasm_bindgen_version)"
if [ -z "$version" ]; then
  printf '[wasm-bindgen] unable to resolve wasm-bindgen version from Cargo.lock\n' >&2
  exit 1
fi

install_root="$TOOLS_ROOT/wasm-bindgen-$version"
binary="$install_root/bin/wasm-bindgen"

if [ ! -x "$binary" ]; then
  mkdir -p "$TOOLS_ROOT"
  cargo install --root "$install_root" wasm-bindgen-cli --version "$version" --locked
fi

installed_version="$("$binary" --version | awk '{print $2}')"
if [ "$installed_version" != "$version" ]; then
  printf '[wasm-bindgen] expected %s at %s, found %s\n' \
    "$version" "$binary" "${installed_version:-unknown}" >&2
  exit 1
fi

if [ $# -eq 0 ] || [[ "${1:-}" == -* ]]; then
  exec "$binary" "$@"
fi

WASM_BINDGEN_BIN="$binary" PATH="$install_root/bin:$PATH" exec "$@"

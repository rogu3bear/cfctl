#!/usr/bin/env bash
# Install the exact cargo-leptos and worker-build this site builds with into a
# repo-local root, verify them, and print their bin directories.
#
# `cargo install` writes one binary per name into the shared ~/.cargo/bin, so a
# sibling repository pinning a different version silently replaces the one this
# build requires. Resolving the pins here keeps the edge build bound to the
# versions recorded in build-edge.sh regardless of ambient installs. This
# mirrors with-wasm-bindgen-cli.sh, which does the same for wasm-bindgen.
#
# Usage: ensure-pinned-cargo-tools.sh <cargo-leptos-version> <worker-build-version>
set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_ROOT="$SITE_ROOT/var/cargo-tools"

if [ "$#" -ne 2 ]; then
  printf '[pinned-tools] usage: %s <cargo-leptos-version> <worker-build-version>\n' \
    "$(basename "$0")" >&2
  exit 1
fi

ensure() {
  local crate="$1" version="$2" field="$3"
  local install_root="$TOOLS_ROOT/$crate-$version"
  local binary="$install_root/bin/$crate"

  if [ ! -x "$binary" ]; then
    mkdir -p "$TOOLS_ROOT"
    cargo install --root "$install_root" "$crate" --version "$version" --locked >&2
  fi

  local installed
  installed="$("$binary" --version 2>/dev/null | awk -v field="$field" '{print $field}')"
  if [ "$installed" != "$version" ]; then
    printf '[pinned-tools] expected %s %s at %s, found %s\n' \
      "$crate" "$version" "$binary" "${installed:-unknown}" >&2
    exit 1
  fi

  printf '%s' "$install_root/bin"
}

# `cargo-leptos --version` prints "cargo-leptos <version>"; worker-build prints
# the bare version.
leptos_bin="$(ensure cargo-leptos "$1" 2)"
worker_bin="$(ensure worker-build "$2" 1)"
printf '%s:%s' "$leptos_bin" "$worker_bin"

#!/usr/bin/env bash
set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
EXPECTED_CARGO_LEPTOS_VERSION="0.3.5"
EXPECTED_WORKER_BUILD_VERSION="0.7.5"

cd "$SITE_ROOT"

if [ "$(cargo leptos --version 2>/dev/null | awk '{print $2}')" != "$EXPECTED_CARGO_LEPTOS_VERSION" ]; then
  printf '[build-edge] cargo-leptos %s is required\n' "$EXPECTED_CARGO_LEPTOS_VERSION" >&2
  exit 1
fi

if [ "$(worker-build --version 2>/dev/null | awk '{print $1}')" != "$EXPECTED_WORKER_BUILD_VERSION" ]; then
  printf '[build-edge] worker-build %s is required\n' "$EXPECTED_WORKER_BUILD_VERSION" >&2
  exit 1
fi

rm -rf -- "$SITE_ROOT/build" "$SITE_ROOT/target/site" "$SITE_ROOT/target/front"

./scripts/with-wasm-bindgen-cli.sh cargo leptos build --release
bun ./scripts/hash-assets.mjs
source "$SITE_ROOT/target/asset-hashes.env"
worker-build --release --features ssr
bun ./scripts/write-worker-shim.mjs
bun ./scripts/verify-hashed-assets.mjs
bun ./scripts/verify-worker-runtime.mjs
bun ./scripts/verify-site-contract.mjs

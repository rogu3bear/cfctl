#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
config="$repository_root/.cargo/config.toml"
expected='xtask = ["run", "--locked", "-p", "xtask", "--"]'

if ! grep -Fqx "$expected" "$config"; then
  echo "xtask alias must preserve run --locked -p xtask -- without suppressing Cargo diagnostics" >&2
  exit 1
fi

echo "PASS: xtask alias preserves the canonical Cargo path and surfaces diagnostics"

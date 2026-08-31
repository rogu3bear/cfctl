#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
contract="$repository_root/tests/xtask-alias-contract.sh"
relocated="$repository_root/tests/fixtures/xtask-alias-relocated.toml"

sh "$contract" "$repository_root/.cargo/config.toml"

if sh "$contract" "$relocated" >/dev/null 2>&1; then
  echo "xtask alias contract accepted the expected assignment outside [alias]" >&2
  exit 1
fi

echo "PASS: xtask alias contract rejects a relocated assignment"

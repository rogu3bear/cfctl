#!/bin/sh
set -eu

repository_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
config=${1:-"$repository_root/.cargo/config.toml"}
expected='xtask = ["run", "--locked", "-p", "xtask", "--"]'

if ! awk -v expected="$expected" '
  function trim(value) {
    sub(/^[[:space:]]+/, "", value)
    sub(/[[:space:]]+$/, "", value)
    return value
  }

  {
    line = trim($0)
    header = line
    sub(/[[:space:]]*#.*/, "", header)
    header = trim(header)

    if (header ~ /^\[.*\]$/) {
      in_alias = (header == "[alias]")
      next
    }

    if (line ~ /^(xtask|"xtask")[[:space:]]*=/) {
      assignments++
      if (in_alias && line == expected) {
        valid++
      }
    }
  }

  END {
    exit !(assignments == 1 && valid == 1)
  }
' "$config"; then
  echo "xtask alias must be assigned exactly once in [alias] as: $expected" >&2
  exit 1
fi

echo "PASS: xtask alias preserves the canonical Cargo path and surfaces diagnostics"

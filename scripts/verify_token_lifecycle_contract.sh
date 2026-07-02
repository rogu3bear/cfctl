#!/usr/bin/env bash
#
# Pins the safety invariants of the cfctl token-lifecycle write path. Source
# checks only — no network, no mutation.

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

fail() {
  echo "token-lifecycle contract failed: $*" >&2
  exit 1
}

# pin <label> <fixed-string> <file>
pin() {
  grep -Fq -- "$2" "$3" || fail "$1"
}

ROT="${ROOT_DIR}/scripts/cf_token_rotate.sh"
RP="${ROOT_DIR}/scripts/cf_token_revoke_pending.sh"
VS="${ROOT_DIR}/scripts/cf_token_verify_state.sh"
GET="${ROOT_DIR}/scripts/cf_token_get.sh"
ST="${ROOT_DIR}/scripts/lib/token_state.sh"

# rotate: the secret sink stays outside the repo and is mandatory for real runs.
pin "rotate guards sink-dir outside the repo" "must be outside the cfctl repo" "${ROT}"
pin "rotate requires sink-dir for a real rotation" "required for a real rotation" "${ROT}"
pin "rotate writes sink values mode 600" "chmod 600" "${ROT}"
# rotate mints via the gated entrypoint and hands back a value_path, not a value.
pin "rotate mints via gated cfctl token mint" "token mint --name" "${ROT}"
pin "rotate returns a value_path manifest" "value_path" "${ROT}"

# revoke-pending is fail-safe: previews unless --commit.
pin "revoke-pending defaults to preview" "COMMIT=false" "${RP}"

# Lane-permission problems are reported distinctly from drift / failure.
pin "verify-state distinguishes read-denied" "token_read_denied" "${VS}"
pin "revoke-pending distinguishes write-denied" "token_write_denied" "${RP}"

# State store is written mode 600.
pin "state store writes mode 600" "chmod 600" "${ST}"

# token get refuses anything but an id (guards against a pasted secret).
pin "token get rejects non-id input" "32-character token id" "${GET}"

# The shipped example purposes file parses and matches the documented shape.
jq -e '
  .purposes
  | type == "array"
  and length > 0
  and all(.[]; has("purpose") and has("ttl_days") and has("policies"))
' "${ROOT_DIR}/docs/examples/token-purposes.example.json" >/dev/null \
  || fail "example purposes file must parse and match the documented schema"

echo "token-lifecycle contract: ok"

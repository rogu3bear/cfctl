#!/bin/bash
# Local pre-push gate: refuse to push what the local gate has not proven.
#
# Remote CI is intentionally absent from this repo (see LOCAL_CI.md), so this
# hook is the only thing standing between an unrun gate and a red `main`.
# PR #75 merged two clippy failures because nothing checked; this is that check.
#
# Invoked by .githooks/pre-push, which is SHA-256 pinned in
# ~/.agent/repo-hook-allowlist. This file is deliberately NOT pinned so gate
# behavior can change without re-pinning. It lives beside the hook rather than
# in scripts/, which the xtask source contract forbids as a quarantined v1
# runtime path.
#
# Escape hatch for genuine emergencies:
#   CFCTL_PRE_PUSH_GATE=off git push ...
# Use that rather than `git push --no-verify`; the global pre-push hook enforces
# repo-independent policy (branch/tag deletion, non-fast-forward) that must keep
# running even when this gate is skipped.

set -euo pipefail

GATE_MODE="${CFCTL_PRE_PUSH_GATE:-on}"

case "$GATE_MODE" in
  off)
    echo "pre-push gate skipped: CFCTL_PRE_PUSH_GATE=off" >&2
    exit 0
    ;;
  on) ;;
  *)
    echo "unknown CFCTL_PRE_PUSH_GATE value: ${GATE_MODE} (expected: on, off)" >&2
    exit 1
    ;;
esac

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"

echo "pre-push: running cargo xtask verify for $(git rev-parse --short HEAD)..."

# Capture unpiped. Piping the gate through tail/head masks its exit status and
# has produced a false green in this repo before.
log="$(mktemp -t cfctl-pre-push-gate)"
set +e
cargo xtask verify >"$log" 2>&1
verify_exit=$?
set -e

if [ "$verify_exit" -ne 0 ]; then
  echo >&2
  tail -40 "$log" >&2
  echo >&2
  echo "pre-push REFUSED: cargo xtask verify exited ${verify_exit}" >&2
  echo "full log: $log" >&2
  echo "Fix the failure and retry, or CFCTL_PRE_PUSH_GATE=off to override." >&2
  exit 1
fi

rm -f "$log"
echo "pre-push: verify passed."

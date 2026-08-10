#!/bin/bash
# Local pre-push gate: refuse to push what the local gate has not proven.
#
# Hosted proof covers the native Rust baseline, while this hook remains the
# complete lane for Bun, policy, secret-scan, governance, and Linux cross-build
# checks (see CONTRIBUTING.md). PR #75 merged two clippy failures before either
# independent gate protected `main`; these gates are the response.
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
# Git exports GIT_DIR and friends into hooks. Left in place they reach every
# subprocess the gate starts, including tests that create their own throwaway
# repositories — and a `git init` that silently retargets at the exported
# GIT_DIR rewrites this repository's config instead. From a linked worktree the
# exported path shares the main repository's config file, so that mistake marks
# the real repository bare. The gate resolved its own root above; nothing past
# this point should inherit the hook's git context.
env -u GIT_DIR -u GIT_WORK_TREE -u GIT_INDEX_FILE -u GIT_COMMON_DIR \
  -u GIT_OBJECT_DIRECTORY -u GIT_ALTERNATE_OBJECT_DIRECTORIES \
  -u GIT_PREFIX -u GIT_QUARANTINE_PATH -u GIT_CEILING_DIRECTORIES \
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

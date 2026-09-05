#!/bin/bash
# Local pre-push gate: refuse to push what the local gate has not proven.
#
# This hook runs the complete local proof lane for Rust, site reproducibility,
# Bun, policy, secret-scan, governance, and Linux cross-build checks (see
# CONTRIBUTING.md). The repository does not require a hosted CI service.
#
# Invoked by .githooks/pre-push, which is SHA-256 pinned in
# ~/.agent/repo-hook-allowlist. This file is deliberately NOT pinned so gate
# behavior can change without re-pinning. It lives beside the hook rather than
# in scripts/, which the xtask source contract forbids as a quarantined v1
# runtime path.
#
set -euo pipefail

updates=()
while IFS= read -r update; do
  [ -n "$update" ] && updates+=("$update")
done

GATE_MODE="${CFCTL_PRE_PUSH_GATE:-on}"

case "$GATE_MODE" in
  on) ;;
  *)
    echo "unknown CFCTL_PRE_PUSH_GATE value: ${GATE_MODE} (expected: on; proof cannot be bypassed)" >&2
    exit 1
    ;;
esac

ROOT_DIR="$(git rev-parse --show-toplevel)"
cd "$ROOT_DIR"
git_dir="$(cd "$(git rev-parse --absolute-git-dir)" && pwd -P)"
common_dir="$(cd "$(git rev-parse --git-common-dir)" && pwd -P)"
if [ "$git_dir" != "$common_dir" ]; then
  echo "pre-push REFUSED: use the canonical checkout, not a linked checkout" >&2
  exit 1
fi

# This gate proves the checked-out source tree, so bind that tree to the exact
# object Git is about to publish. Multi-ref, detached-HEAD, non-HEAD, and dirty
# pushes are refused; accepting them here would
# let the gate inspect bytes other than the pushed commit.
if [ "${#updates[@]}" -ne 1 ]; then
  echo "pre-push REFUSED: expected exactly one pushed ref, got ${#updates[@]}" >&2
  exit 1
fi

read -r local_ref local_oid remote_ref _remote_oid <<<"${updates[0]}"
head_ref="$(git symbolic-ref -q HEAD || true)"
head_oid="$(git rev-parse HEAD)"

if [ -z "$head_ref" ]; then
  echo "pre-push REFUSED: canonical checkout must have an attached HEAD" >&2
  exit 1
fi

case "$local_ref:$remote_ref" in
  refs/heads/*:refs/heads/*)
    if [ "$local_ref" != "$head_ref" ] || [ "$local_oid" != "$head_oid" ]; then
      echo "pre-push REFUSED: pushed branch/object must equal checked-out HEAD" >&2
      exit 1
    fi
    ;;
  refs/tags/*:refs/tags/*)
    if [ "$local_ref" != "$remote_ref" ] || \
       [ "$(git cat-file -t "$local_oid")" != tag ] || \
       [ "$(git rev-parse "$local_ref")" != "$local_oid" ] || \
       [ "$(git rev-parse "$local_oid^{commit}")" != "$head_oid" ] || \
       [ "$_remote_oid" != 0000000000000000000000000000000000000000 ]; then
      echo "pre-push REFUSED: only a new annotated tag at exact checked-out HEAD is admitted" >&2
      exit 1
    fi
    ;;
  *)
    echo "pre-push REFUSED: expected one branch or new annotated tag" >&2
    exit 1
    ;;
esac

if ! initial_status="$(git status --porcelain=v1 --untracked-files=all)"; then
  echo "pre-push REFUSED: could not observe checked-out source cleanliness" >&2
  exit 1
fi
if [ -n "$initial_status" ]; then
  echo "pre-push REFUSED: tracked and untracked source must be clean" >&2
  exit 1
fi

echo "pre-push: running cargo xtask verify for ${head_oid:0:7}..."

# Capture unpiped. Piping the gate through tail/head masks its exit status and
# has produced a false green in this repo before.
log="$(mktemp -t cfctl-pre-push-gate)"
# Verify only this canonical checkout. The sole-writer rule prevents concurrent
# edits; recheck exact source/HEAD after proof to reject observed drift.
# Strip every inherited Git context variable from proof subprocesses: tests
# must be free to initialize their own repositories without touching ours.
proof_env=(env)
while IFS= read -r variable; do
  case "$variable" in GIT_*) proof_env+=(-u "$variable") ;; esac
done < <(compgen -e)
set +e
"${proof_env[@]}" cargo xtask verify >"$log" 2>&1
verify_exit=$?
set -e

if [ "$verify_exit" -ne 0 ]; then
  echo >&2
  tail -40 "$log" >&2
  echo >&2
  echo "pre-push REFUSED: cargo xtask verify exited ${verify_exit}" >&2
  echo "full log: $log" >&2
  echo "Fix the failure and retry with the same reviewed source." >&2
  exit 1
fi

current_head_ref="$(git symbolic-ref -q HEAD || true)"
current_head_oid="$(git rev-parse HEAD)"
if [ "$(git rev-parse "$local_ref")" != "$local_oid" ]; then
  echo "pre-push REFUSED: pushed ref changed during verification" >&2
  exit 1
fi
if ! current_status="$(git status --porcelain=v1 --untracked-files=all)"; then
  echo "pre-push REFUSED: could not observe checked-out source cleanliness after verification" >&2
  exit 1
fi
if [ "$current_head_ref" != "$head_ref" ] || [ "$current_head_oid" != "$head_oid" ] || \
   [ -n "$current_status" ]; then
  echo "pre-push REFUSED: checked-out HEAD or source changed during verification" >&2
  exit 1
fi

rm -f "$log"
echo "pre-push: verify passed."

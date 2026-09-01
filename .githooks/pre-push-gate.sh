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
# Escape hatch for genuine emergencies:
#   CFCTL_PRE_PUSH_GATE=off git push ...
# Use that rather than `git push --no-verify`; the global pre-push hook enforces
# repo-independent policy (branch/tag deletion, non-fast-forward) that must keep
# running even when this gate is skipped.

set -euo pipefail

update_count=0
malformed_update=0
local_ref=""
local_oid=""
remote_ref=""
remote_oid=""

while IFS=' ' read -r update_local_ref update_local_oid update_remote_ref update_remote_oid update_extra; do
  if [ -z "${update_local_ref}${update_local_oid}${update_remote_ref}${update_remote_oid}${update_extra}" ]; then
    continue
  fi
  update_count=$((update_count + 1))
  if [ "$update_count" -eq 1 ]; then
    local_ref="$update_local_ref"
    local_oid="$update_local_oid"
    remote_ref="$update_remote_ref"
    remote_oid="$update_remote_oid"
  fi
  if [ -z "$update_local_ref" ] || [ -z "$update_local_oid" ] || \
     [ -z "$update_remote_ref" ] || [ -z "$update_remote_oid" ] || \
     [ -n "$update_extra" ]; then
    malformed_update=1
  fi
done

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

if [ "$update_count" -ne 1 ]; then
  echo "pre-push REFUSED: expected exactly one pushed ref, got ${update_count}" >&2
  exit 1
fi
if [ "$malformed_update" -ne 0 ]; then
  echo "pre-push REFUSED: malformed pre-push ref update" >&2
  exit 1
fi

is_zero_oid() {
  case "$1" in
    ""|*[!0]*) return 1 ;;
    *) return 0 ;;
  esac
}

if is_zero_oid "$local_oid"; then
  echo "pre-push REFUSED: this proof lane does not publish deletions" >&2
  exit 1
fi

case "$remote_ref" in
  refs/heads/*) ;;
  *)
    echo "pre-push REFUSED: this proof lane publishes exactly one branch" >&2
    exit 1
    ;;
esac

head_ref="$(git symbolic-ref -q HEAD || true)"
head_oid="$(git rev-parse HEAD)"
head_tree="$(git rev-parse 'HEAD^{tree}')"

if [ -z "$head_ref" ] || [ "$local_ref" != "$head_ref" ] || [ "$local_oid" != "$head_oid" ]; then
  echo "pre-push REFUSED: pushed ref/object must equal the checked-out HEAD" >&2
  exit 1
fi

git_dir="$(git rev-parse --path-format=absolute --git-dir)"
git_common_dir="$(git rev-parse --path-format=absolute --git-common-dir)"
if ! git_local_env_output="$(git rev-parse --local-env-vars)"; then
  echo "pre-push REFUSED: could not derive Git local environment contract" >&2
  exit 1
fi
git_env_unsets=()
while IFS= read -r git_local_name; do
  [ -z "$git_local_name" ] && continue
  if [[ ! "$git_local_name" =~ ^[A-Z_][A-Z0-9_]*$ ]]; then
    echo "pre-push REFUSED: Git reported an invalid local environment name" >&2
    exit 1
  fi
  git_env_unsets+=("-u" "$git_local_name")
done <<<"$git_local_env_output"
if [ "${#git_env_unsets[@]}" -eq 0 ]; then
  echo "pre-push REFUSED: Git local environment contract is empty" >&2
  exit 1
fi
git_env_unsets+=("-u" "GIT_QUARANTINE_PATH" "-u" "GIT_CEILING_DIRECTORIES")

refuse_if_git_busy() {
  local lock_path
  if ! lock_path="$(find "$git_common_dir" "$git_dir" -type f -name '*.lock' -print -quit 2>/dev/null)"; then
    echo "pre-push REFUSED: could not observe Git operation or lock state" >&2
    exit 1
  fi
  if [ -n "$lock_path" ]; then
    echo "pre-push REFUSED: Git operation or lock is active" >&2
    exit 1
  fi

  local marker marker_path
  for marker in MERGE_HEAD CHERRY_PICK_HEAD REVERT_HEAD BISECT_LOG BISECT_START rebase-apply rebase-merge sequencer; do
    marker_path="$(git rev-parse --path-format=absolute --git-path "$marker")"
    if [ -e "$marker_path" ]; then
      echo "pre-push REFUSED: Git operation or lock is active" >&2
      exit 1
    fi
  done
}

refuse_if_git_busy

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
set +e
# Git exports GIT_DIR and friends into hooks. Left in place they reach every
# subprocess the gate starts, including tests that create their own throwaway
# repositories — and a `git init` that silently retargets at the exported
# GIT_DIR rewrites this repository's config instead. The gate resolved its own
# canonical root above; nothing past this point should inherit hook Git context.
env "${git_env_unsets[@]}" \
  cargo xtask verify >"$log" 2>&1
verify_exit=$?
set -e

current_head_ref="$(git symbolic-ref -q HEAD || true)"
current_head_oid="$(git rev-parse HEAD)"
current_head_tree="$(git rev-parse 'HEAD^{tree}')"
refuse_if_git_busy
if ! current_status="$(git status --porcelain=v1 --untracked-files=all)"; then
  echo "pre-push REFUSED: could not observe checked-out source cleanliness after verification" >&2
  exit 1
fi
if [ "$current_head_ref" != "$head_ref" ] || [ "$current_head_oid" != "$head_oid" ] || \
   [ "$current_head_tree" != "$head_tree" ] || [ -n "$current_status" ]; then
  echo "pre-push REFUSED: checked-out HEAD, tree, or source changed during verification" >&2
  exit 1
fi

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

#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
install_root="${CARGO_INSTALL_ROOT:-$HOME/.local}"

usage() {
  echo "usage: ./bootstrap.sh [--check-only] [--skip-agent-sync]"
}

check_only=false
skip_agent_sync=false
for argument in "$@"; do
  case "$argument" in
    --check-only) check_only=true ;;
    --skip-agent-sync) skip_agent_sync=true ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done

for tool in cargo git rustc; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 1
  fi
done

checkout_root=$(git -C "$root" rev-parse --show-toplevel 2>/dev/null || true)
if [ "$checkout_root" != "$root" ]; then
  echo "bootstrap must run from the tracked cfctl checkout rooted at $root" >&2
  exit 1
fi
checkout_status=$(git -C "$root" status --porcelain=v1 --untracked-files=normal)
if [ -n "$checkout_status" ]; then
  echo "bootstrap requires a tracked-and-untracked clean checkout; commit, move, or ignore local changes first" >&2
  exit 1
fi
head=$(git -C "$root" rev-parse --verify HEAD)

(cd "$root" && cargo xtask verify)

if [ "$check_only" = true ]; then
  echo "cfctl v2 source proof passed"
  exit 0
fi

cargo install --force --path "$root/crates/cfctl-cli" --locked --root "$install_root"
binary="$install_root/bin/cfctl"
version_json=$("$binary" version --json)
case "$version_json" in
  *"\"git_commit\":\"$head\""*) ;;
  *)
    echo "installed cfctl does not identify the exact checkout commit $head" >&2
    echo "$version_json" >&2
    exit 1
    ;;
esac
PATH="$install_root/bin:$PATH"
export PATH
if [ "$skip_agent_sync" = false ]; then
  "$binary" agents sync
fi
"$binary" agents doctor
"$binary" doctor

# A new build cannot read the previous build's platform evidence authority: the
# integrity key is held by the platform credential store with no file fallback,
# and every build has a different code identity, so the access control does not
# carry over. Nothing else surfaces this. The install looks clean, `doctor`
# reports healthy, and the first governed apply that needs an authenticated
# receipt is where it shows up.
#
# This is the interactive session the operator is already in, so ask here.
evidence_qualifying=$("$binary" doctor --json 2>/dev/null \
  | tr ',' '\n' | grep '"qualifying"' | head -1)
case "$evidence_qualifying" in
  *true*) ;;
  *)
    echo "evidence authority is unreadable by this build; re-authorizing" >&2
    if "$binary" auth evidence-key status --json >/dev/null 2>&1; then
      echo "evidence authority re-authorized"
    else
      echo "" >&2
      echo "cfctl is installed, but it cannot read the evidence integrity key." >&2
      echo "Authenticated evidence cannot be written until it can, so operations" >&2
      echo "that are irreversible on either their effect or their risk will refuse." >&2
      echo "" >&2
      echo "Approve the platform prompt for this command in an interactive terminal:" >&2
      echo "  cfctl auth evidence-key status --json" >&2
      exit 1
    fi
    ;;
esac

echo "installed $install_root/bin/cfctl"
echo "next: cfctl catalog sync"
echo "then: cfctl auth import-api-token --account <account-id> --stdin"

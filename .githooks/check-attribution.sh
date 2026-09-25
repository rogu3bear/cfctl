#!/bin/bash
# Local equivalent of the required reject-cursor-attribution check.
# No network calls or remote status updates occur here.
set -euo pipefail

base=$(git rev-parse --verify --end-of-options "${1:-origin/main}^{commit}")
head=$(git rev-parse --verify --end-of-options "${2:-HEAD}^{commit}")
[[ "$base" =~ ^[0-9a-f]{40}$ && "$head" =~ ^[0-9a-f]{40}$ ]] || exit 2
commits=$(git rev-list --no-merges "$base..$head")
count=0
bad=0
# Keep this predicate identical to the original required check.
pattern='cursoragent@cursor\.com|@cursor\.com|co-authored-by:[[:space:]]*cursor|signed-off-by:[[:space:]]*cursor|made[- ]with[[:space:]:=.\-\[(]*cursor|generated[[:space:]]+with.*cursor|^cursor[[:space:]]*$|^cursor agent$|cursorbot'
if [ -n "$commits" ]; then
  while IFS= read -r commit; do
    blob=$(git show -s --format='%an%n%ae%n%cn%n%ce%n%s%n%b' "$commit")
    count=$((count + 1))
    if LC_ALL=C grep -Eiq -- "$pattern" <<<"$blob"; then
      printf 'FORBIDDEN Cursor attribution in %s\n' "$commit" >&2
      bad=1
    else
      status=$?
      [ "$status" -eq 1 ] || exit "$status"
    fi
  done <<<"$commits"
fi
if [ "$bad" -ne 0 ]; then
  printf 'Rejecting candidate: forbidden attribution must not be published.\n' >&2
  exit 1
fi
digest=$(shasum -a 256 "$0")
digest=${digest%% *}
[[ "$digest" =~ ^[0-9a-f]{64}$ ]] || exit 2
printf '{"check":"reject-cursor-attribution","execution":"local","base_sha":"%s","head_sha":"%s","script_sha256":"%s","commit_count":%d,"result":"success"}\n' \
  "$base" "$head" "$digest" "$count"

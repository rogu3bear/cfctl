#!/usr/bin/env bash
set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

artifact_digest() {
  (
    cd "$SITE_ROOT"
    find build target/site -type f -print0 \
      | LC_ALL=C sort -z \
      | xargs -0 shasum -a 256 \
      | shasum -a 256 \
      | awk '{print $1}'
  )
}

cd "$SITE_ROOT"
./scripts/build-edge.sh
first_digest="$(artifact_digest)"
./scripts/build-edge.sh
second_digest="$(artifact_digest)"

if [ "$first_digest" != "$second_digest" ]; then
  printf '[verify-reproducible-edge] artifact drift: first=%s second=%s\n' \
    "$first_digest" "$second_digest" >&2
  exit 1
fi

printf '[verify-reproducible-edge] exact deployment artifact reproduced: %s\n' \
  "$second_digest"

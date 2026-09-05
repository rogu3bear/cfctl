#!/usr/bin/env bash
set -euo pipefail

SITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POISON_ROOT="$(mktemp -d -t cfctl-wasm-bindgen-poison)"

cleanup() {
  rm -rf -- "$POISON_ROOT"
}
trap cleanup EXIT

poison_ambient_wasm_bindgen() {
  local build_number="$1"
  local poison="$POISON_ROOT/build-$build_number/wasm-bindgen"

  mkdir -p "$(dirname "$poison")"
  cat >"$poison" <<'EOF'
#!/usr/bin/env bash
printf '[verify-reproducible-edge] ambient wasm-bindgen was executed\n' >&2
exit 97
EOF
  chmod 0755 "$poison"
  WASM_BINDGEN_BIN="$poison" ./scripts/build-edge.sh
}

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
poison_ambient_wasm_bindgen 1
first_digest="$(artifact_digest)"
poison_ambient_wasm_bindgen 2
second_digest="$(artifact_digest)"

if [ "$first_digest" != "$second_digest" ]; then
  printf '[verify-reproducible-edge] artifact drift: first=%s second=%s\n' \
    "$first_digest" "$second_digest" >&2
  exit 1
fi

printf '[verify-reproducible-edge] site-relative build comparison reproduced: %s\n' \
  "$second_digest"

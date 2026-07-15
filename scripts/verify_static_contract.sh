#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CFCTL="${ROOT_DIR}/cfctl"

die() {
  echo "static-contract verification failed: $*" >&2
  exit 1
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"
}

assert_contains() {
  local label="$1"
  local needle="$2"
  local haystack="$3"
  grep -Fq -- "${needle}" <<< "${haystack}" || die "${label}: missing ${needle}"
}

require_tool cargo
require_tool jq

cd "${ROOT_DIR}"

bash -n \
  "${ROOT_DIR}/bootstrap.sh" \
  "${ROOT_DIR}/cfctl" \
  "${ROOT_DIR}/packaging/install.sh" \
  "${ROOT_DIR}/scripts/verify_public_contract.sh" \
  "${ROOT_DIR}/scripts/verify_static_contract.sh"

metadata="$(cargo metadata --locked --no-deps --format-version 1)"
jq -e '
  (.workspace_members | length) == 10
  and ([.packages[].name] | index("cfctl-cli")) != null
  and ([.packages[].name] | index("cfctl-core")) != null
  and ([.packages[].name] | index("cfctl-cloudflare")) != null
  and ([.packages[].name] | index("cfctl-workspace")) != null
  and ([.packages[].name] | index("xtask")) != null
' <<< "${metadata}" >/dev/null || die "Rust workspace membership drifted"

help_text="$(${CFCTL} --help)"
version_text="$(${CFCTL} --version)"
for command in auth keys catalog call guide plans workspace agents docs doctor update migrate; do
  assert_contains "public help" "${command}" "${help_text}"
done
assert_contains "public version" "cfctl 2.0.0-alpha.1" "${version_text}"

runtime_root="$(mktemp -d "${TMPDIR:-/tmp}/cfctl-v2-static.XXXXXX")"
cleanup() {
  case "${runtime_root}" in
    "${TMPDIR:-/tmp}"/cfctl-v2-static.*) rm -rf -- "${runtime_root}" ;;
    *) die "refusing to remove unexpected temporary path: ${runtime_root}" ;;
  esac
}
trap cleanup EXIT

doctor_json="$(CFCTL_HOME="${runtime_root}" ${CFCTL} doctor --json)"
jq -e '
  .schema_version == 2
  and .ok == true
  and .performed == false
  and .command == "doctor"
  and .result.catalog.present == false
  and .result.public_oauth != null
' <<< "${doctor_json}" >/dev/null || die "isolated doctor contract failed"

add_json="$(CFCTL_HOME="${runtime_root}" ${CFCTL} workspace add "${ROOT_DIR}" --json)"
jq -e --arg root "${ROOT_DIR}" '
  .schema_version == 2
  and .ok == true
  and .performed == false
  and .command == "workspace add"
  and .result.path == $root
' <<< "${add_json}" >/dev/null || die "registered-root contract failed"

discover_json="$(CFCTL_HOME="${runtime_root}" ${CFCTL} workspace discover --json)"
jq -e --arg root "${ROOT_DIR}" '
  .schema_version == 2
  and .ok == true
  and .performed == false
  and .command == "workspace discover"
  and any(.result.repositories[]; .path == $root and .git.head != null)
' <<< "${discover_json}" >/dev/null || die "bounded workspace discovery contract failed"

grep -Fq 'hash-chained transaction journal' README.md \
  || die "README omits the crash-journal contract"
grep -Fq 'operation-specific verification' docs/v2-security.md \
  || die "security contract omits operation-specific verification"
grep -Fq 'Wrangler TOML/JSONC, Terraform' docs/v2-architecture.md \
  || die "architecture omits exact IaC discovery coverage"

echo "static-contract verification passed"

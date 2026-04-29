#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "${ROOT_DIR}"

require_tool() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required tool: $1" >&2
    exit 1
  }
}

die() {
  echo "static-contract verification failed: $*" >&2
  exit 1
}

assert_jq_file() {
  local label="$1"
  local expr="$2"
  local file="$3"

  jq -e "${expr}" "${file}" >/dev/null || die "${label}: assertion failed for ${file}: ${expr}"
}

assert_contains() {
  local label="$1"
  local needle="$2"
  local file="$3"

  if ! grep -Fq -- "${needle}" "${file}"; then
    die "${label}: expected to find '${needle}' in ${file}"
  fi
}

assert_not_contains() {
  local label="$1"
  local needle="$2"
  local file="$3"

  if grep -Fq -- "${needle}" "${file}"; then
    die "${label}: unexpected stale text '${needle}' in ${file}"
  fi
}

assert_not_has_line() {
  local label="$1"
  local regex="$2"
  local file="$3"

  if command -v rg >/dev/null 2>&1; then
    if rg -n "${regex}" "${file}" >/dev/null; then
      die "${label}: unexpected matching line ${regex} in ${file}"
    fi
  elif grep -En "${regex}" "${file}" >/dev/null; then
    die "${label}: unexpected matching line ${regex} in ${file}"
  fi
}

require_tool jq
require_tool python3

bash -n \
  "${ROOT_DIR}/cfctl" \
  "${ROOT_DIR}/commands/cfctl.sh" \
  "${ROOT_DIR}/lib/runtime/cfctl.sh" \
  "${ROOT_DIR}/lib/runtime/desired_state.sh" \
  "${ROOT_DIR}/scripts/lib/cfctl.sh" \
  "${ROOT_DIR}/scripts/lib/cloudflare.sh" \
  "${ROOT_DIR}/scripts/cf_wrangler.sh" \
  "${ROOT_DIR}/scripts/cf_cloudflared.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_api_gateway.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_vulnerability_scanner.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_worker_routes.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_edge_certificates.sh" \
  "${ROOT_DIR}/scripts/cf_mutate_edge_certificate.sh" \
  "${ROOT_DIR}/scripts/verify_public_contract.sh" \
  "${ROOT_DIR}/scripts/verify_static_contract.sh"
for surface_module in \
  "${ROOT_DIR}/lib/surfaces/access_app.sh" \
  "${ROOT_DIR}/lib/surfaces/access_policy.sh" \
  "${ROOT_DIR}/lib/surfaces/dns_record.sh" \
  "${ROOT_DIR}/lib/surfaces/edge_certificate.sh" \
  "${ROOT_DIR}/lib/surfaces/worker_route.sh" \
  "${ROOT_DIR}/lib/surfaces/tunnel.sh"; do
  bash -n "${surface_module}"
done

python3 "${ROOT_DIR}/scripts/render_capabilities_doc.py" --check "${ROOT_DIR}/docs/capabilities.md" >/dev/null
python3 "${ROOT_DIR}/scripts/verify_permission_catalog.py" >/dev/null

assert_jq_file "permission profile minimality policy" '
  .profiles.read.allowed_surfaces != null
  and (.profiles.read.forbidden_permissions | index("* Write")) != null
  and (.profiles["security-audit"].forbidden_permissions | index("* Write")) != null
  and .profiles.dns.allowed_surfaces == ["dns.record", "zone"]
  and (.profiles.hostname.allowed_surfaces | index("edge.certificate")) != null
  and (.profiles.deploy.allowed_surfaces | index("wrangler")) != null
  and .profiles["full-operator"].allowed_surfaces == ["*"]
  and (.profiles["full-operator"].forbidden_permissions | index("Account API Tokens *")) != null
' "${ROOT_DIR}/catalog/permissions.json"
assert_jq_file "runtime public verbs" '(.public_verbs | index("docs")) != null and (.public_verbs | index("wrangler")) != null and (.public_verbs | index("cloudflared")) != null and (.public_verbs | index("hostname")) != null and (.landing_flow | index("docs")) != null' "${ROOT_DIR}/catalog/runtime.json"
assert_jq_file "tool wrapper metadata" '
  .tool_wrappers.wrangler.script == "scripts/cf_wrangler.sh"
  and .tool_wrappers.wrangler.backend == "wrangler"
  and (.tool_wrappers.wrangler.default_args | index("whoami")) != null
  and (.tool_wrappers.wrangler.read_only_prefixes | map(join(" ")) | index("whoami")) != null
  and .tool_wrappers.cloudflared.script == "scripts/cf_cloudflared.sh"
  and .tool_wrappers.cloudflared.backend == "cloudflared"
  and (.tool_wrappers.cloudflared.default_args | index("version")) != null
  and (.tool_wrappers.cloudflared.read_only_prefixes | map(join(" ")) | index("tunnel list")) != null
' "${ROOT_DIR}/catalog/runtime.json"
assert_jq_file "docs bank shape" '.checked_on != null and .refresh_policy.refresh_interval_days > 0 and (.foundation | length) > 0 and (.watch | length) > 0' "${ROOT_DIR}/catalog/cloudflare-doc-bank.json"
assert_jq_file "docs bank api gateway topic" '(.foundation | any(.id == "api-gateway")) and (.watch | any(.id == "api-shield-vulnerability-scanner"))' "${ROOT_DIR}/catalog/cloudflare-doc-bank.json"
assert_jq_file "standards shape" '(.universal | length) > 0 and (.surfaces | keys | length) > 0' "${ROOT_DIR}/catalog/standards.json"
assert_jq_file "compatibility freshness thresholds" '.audit.compatibility_date_freshness.note_after_days == 30 and .audit.compatibility_date_freshness.warning_after_days == 90' "${ROOT_DIR}/catalog/standards.json"
assert_jq_file "surface registry shape" '(.surfaces | keys | length) > 0' "${ROOT_DIR}/catalog/surfaces.json"
assert_jq_file "surface module bindings" '
  .surfaces["access.app"].module == "access_app"
  and .surfaces["access.app"].standards_ref == "access.app"
  and (.surfaces["access.app"].docs_topics | index("zero-trust-api")) != null
  and .surfaces["access.policy"].module == "access_policy"
  and .surfaces["access.policy"].standards_ref == "access.policy"
  and (.surfaces["access.policy"].docs_topics | index("zero-trust-api")) != null
  and .surfaces["dns.record"].module == "dns_record"
  and .surfaces["dns.record"].standards_ref == "dns.record"
  and (.surfaces["dns.record"].docs_topics | index("api-auth")) != null
  and .surfaces["edge.certificate"].module == "edge_certificate"
  and .surfaces["edge.certificate"].standards_ref == "edge.certificate"
  and (.surfaces["edge.certificate"].docs_topics | index("advanced-certificates")) != null
  and (.surfaces["hostname"] == null)
  and .surfaces["worker.route"].module == "worker_route"
  and .surfaces["worker.route"].standards_ref == "worker.route"
  and (.surfaces["worker.route"].docs_topics | index("workers-routes")) != null
  and .surfaces["tunnel"].module == "tunnel"
  and .surfaces["tunnel"].standards_ref == "tunnel"
  and (.surfaces["tunnel"].docs_topics | index("api-auth")) != null
  and .surfaces["api_gateway.operation"].actions.apply.supported == false
  and .surfaces["api_gateway.operation"].actions.list.required_selectors == ["zone"]
  and (.surfaces["api_gateway.operation"].docs_topics | index("api-gateway")) != null
  and .surfaces["api_gateway.schema"].actions.apply.supported == false
  and .surfaces["api_gateway.schema"].actions.list.required_selectors == ["zone"]
  and (.surfaces["api_gateway.schema"].docs_topics | index("api-gateway")) != null
  and .surfaces["api_gateway.discovery"].actions.apply.supported == false
  and .surfaces["api_gateway.discovery"].actions.list.required_selectors == ["zone"]
  and (.surfaces["api_gateway.discovery"].docs_topics | index("api-gateway")) != null
  and .surfaces["vulnerability_scanner.scan"].actions.apply.supported == false
  and (.surfaces["vulnerability_scanner.scan"].docs_topics | index("api-shield-vulnerability-scanner")) != null
  and .surfaces["vulnerability_scanner.target_environment"].actions.apply.supported == false
  and (.surfaces["vulnerability_scanner.target_environment"].docs_topics | index("api-shield-vulnerability-scanner")) != null
  and .surfaces["vulnerability_scanner.credential_set"].actions.apply.supported == false
  and (.surfaces["vulnerability_scanner.credential_set"].docs_topics | index("api-shield-vulnerability-scanner")) != null
' "${ROOT_DIR}/catalog/surfaces.json"

assert_contains "state docs preview ack" "cfctl apply dns.record sync --zone example.com --ack-plan <operation-id>" "${ROOT_DIR}/docs/state.md"
assert_not_has_line "state docs stale direct sync" '^cfctl apply dns\.record sync --zone example.com$' "${ROOT_DIR}/docs/state.md"
assert_contains "state docs scaffolding note" "Support means the desired-state engine exists for that surface." "${ROOT_DIR}/docs/state.md"
assert_contains "state readme scaffolding note" "Managed specs are opt-in." "${ROOT_DIR}/state/README.md"
assert_contains "hostname state example" "cfctl hostname verify --file state/hostname/example.yaml" "${ROOT_DIR}/state/hostname/README.md"
assert_contains "hostname checked-in spec" "service: example-edge-router" "${ROOT_DIR}/state/hostname/example.yaml"
assert_contains "cfctl prompt contract" "You are now operating as \`cfctl\`, a strict, catalog-driven Cloudflare control plane." "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt preview ack" "always require \`--plan\` first, then \`--ack-plan <operation-id>\`" "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt error verb" "\`doctor\`, \`audit\`, \`admin\`, \`bootstrap\`, \`lanes\`, \`surfaces\`, \`docs\`, \`previews\`, \`locks\`, \`wrangler\`, \`cloudflared\`, \`hostname\`, \`standards\`, \`token\`, \`list\`, \`get\`, \`can\`, \`classify\`, \`guide\`, \`apply\`, \`verify\`, \`explain\`, \`snapshot\`, \`diff\`, or \`error\`." "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt hostname" "For \`hostname\`, treat \`verify\`, \`diff\`, and \`plan\` as read-only composite evidence flows" "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt wrapper gating" "For \`wrangler\` and \`cloudflared\`, treat clearly read-only subcommands as direct wrapped executions" "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "readme wrapper examples" "cfctl wrangler --version" "${ROOT_DIR}/README.md"
assert_contains "readme source-live boundary" "Source Config Vs Live State" "${ROOT_DIR}/README.md"
assert_contains "readme hostname lifecycle" "Hostname lifecycle" "${ROOT_DIR}/README.md"
assert_contains "readme standards audit freshness" "checked-in Wrangler config alignment, including \`compatibility_date\` freshness" "${ROOT_DIR}/README.md"
assert_contains "agents wrapper hierarchy" "cfctl wrangler ..." "${ROOT_DIR}/AGENTS.md"
assert_contains "agents source-live boundary" "A clean standards audit proves source-config alignment, not live edge state." "${ROOT_DIR}/AGENTS.md"
assert_contains "agents hostname lifecycle" "Hostname lifecycle specs live under \`state/hostname/\`" "${ROOT_DIR}/AGENTS.md"
assert_contains "agent landing decision path" "## Decision Path" "${ROOT_DIR}/docs/agent-landing.md"
assert_contains "agent landing source-live boundary" "Do not turn a source-config audit into a live Cloudflare claim." "${ROOT_DIR}/docs/agent-landing.md"
assert_contains "runbook wrapper examples" "cfctl cloudflared version" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook hostname lifecycle" "cfctl hostname verify --file state/hostname/example.yaml" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook compatibility freshness" "standards audit\` reports \`compatibility_date\` aging and stale counts" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook standards audit source evidence" "standards audit\` is source-config evidence" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "config standards compatibility freshness" "Compatibility-date freshness is intentionally advisory" "${ROOT_DIR}/docs/config-standards.md"
assert_contains "capabilities operable note" "This table is the operable runtime surface." "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities generated note" "_Generated from \`catalog/surfaces.json\` and \`catalog/runtime.json\`." "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities module column" "| Surface | Read | Apply | Desired State | Standards | Docs Topics | Module |" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities hostname composite" "Composite lifecycle commands:" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "docs bank tracked vs operable note" "Tracked here does not automatically mean operable through \`cfctl\` today" "${ROOT_DIR}/docs/cloudflare-doc-bank.md"
assert_contains "public contract live verifier note" "This is a live account smoke test." "${ROOT_DIR}/scripts/verify_public_contract.sh"
assert_contains "contract workflow static gate" "python3 scripts/verify_permission_catalog.py --cfctl ./cfctl" "${ROOT_DIR}/.github/workflows/cfctl-contract.yml"
assert_contains "contract workflow live gate" "./scripts/verify_public_contract.sh" "${ROOT_DIR}/.github/workflows/cfctl-contract.yml"
assert_contains "contract workflow secret gate" "CF_DEV_TOKEN secret is required" "${ROOT_DIR}/.github/workflows/cfctl-contract.yml"

echo "static-contract verification passed"

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

assert_cross_catalog_empty() {
  local label="$1"
  local expr="$2"
  local failures

  failures="$(
    jq -c -n \
      --slurpfile runtime "${ROOT_DIR}/catalog/runtime.json" \
      --slurpfile surfaces "${ROOT_DIR}/catalog/surfaces.json" \
      --slurpfile standards "${ROOT_DIR}/catalog/standards.json" \
      --slurpfile docs "${ROOT_DIR}/catalog/cloudflare-doc-bank.json" \
      --slurpfile ownership "${ROOT_DIR}/state/ownership/resources.json" \
      "${expr}"
  )"

  if ! jq -e 'length == 0' <<< "${failures}" >/dev/null; then
    die "${label}: ${failures}"
  fi
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
  "${ROOT_DIR}/scripts/cf_token_revoke.sh" \
  "${ROOT_DIR}/scripts/cf_inventory_audit_logs.sh" \
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

doctor_bootstrap_json="$(
  env \
    -u CF_DEV_TOKEN \
    -u CF_GLOBAL_TOKEN \
    -u CLOUDFLARE_API_TOKEN \
    -u CLOUDFLARE_ACCOUNT_ID \
    CF_SHARED_ENV_FILE="/nonexistent/cfctl-empty-env" \
    CF_REPO_ENV_FILE="/nonexistent/cfctl-empty-env" \
    "${ROOT_DIR}/cfctl" doctor
)"
jq -e '
  .ok == true
  and .action == "doctor"
  and .summary.status == "bootstrap_required"
  and .summary.configured_lane_count == 0
  and (.summary.safe_next_steps | index("cfctl bootstrap permissions")) != null
' <<< "${doctor_bootstrap_json}" >/dev/null || die "doctor no-auth bootstrap posture assertion failed"

assert_jq_file "permission profile minimality policy" '
  .profiles.read.allowed_surfaces != null
  and (.profiles.read.allowed_surfaces | index("audit.log")) != null
  and (.profiles.read.forbidden_permissions | index("* Write")) != null
  and (.profiles["security-audit"].forbidden_permissions | index("* Write")) != null
  and (.profiles["security-audit"].allowed_surfaces | index("audit.log")) != null
  and .profiles.dns.allowed_surfaces == ["dns.record", "zone"]
  and (.profiles.hostname.allowed_surfaces | index("edge.certificate")) != null
  and (.profiles.deploy.allowed_surfaces | index("audit.log")) != null
  and (.profiles.deploy.allowed_surfaces | index("wrangler")) != null
  and .profiles["full-operator"].allowed_surfaces == ["*"]
  and (.profiles["full-operator"].forbidden_permissions | index("Account API Tokens *")) != null
' "${ROOT_DIR}/catalog/permissions.json"
assert_jq_file "runtime public verbs" '(.public_verbs | index("docs")) != null and (.public_verbs | index("wrangler")) != null and (.public_verbs | index("cloudflared")) != null and (.public_verbs | index("hostname")) != null and (.landing_flow | index("docs")) != null' "${ROOT_DIR}/catalog/runtime.json"
assert_jq_file "runtime backend guard catalog" '
  .policy.backend_guard_scripts == ["scripts/cf_api_apply.sh"]
  and .policy.special_operations["token.mint"].backend_script == "scripts/cf_token_mint.sh"
  and .policy.special_operations["token.revoke"].backend_script == "scripts/cf_token_revoke.sh"
' "${ROOT_DIR}/catalog/runtime.json"
assert_jq_file "runtime ownership registry catalog" '
  .ownership_registry.path == "state/ownership/resources.json"
  and .ownership_registry.duplicate_resource_policy == "fail"
  and (.ownership_registry.proof_classes | index("source_config")) != null
  and (.ownership_registry.proof_classes | index("live_control_plane_read")) != null
  and (.ownership_registry.proof_classes | index("preview_artifact")) != null
  and (.ownership_registry.proof_classes | index("apply_artifact")) != null
  and (.ownership_registry.proof_classes | index("post_change_verification")) != null
' "${ROOT_DIR}/catalog/runtime.json"
assert_jq_file "tool wrapper metadata" '
  .tool_wrappers.wrangler.script == "scripts/cf_wrangler.sh"
  and .tool_wrappers.wrangler.backend == "wrangler"
  and (.tool_wrappers.wrangler.default_args | index("whoami")) != null
  and (.tool_wrappers.wrangler.read_only_prefixes | map(join(" ")) | index("whoami")) != null
  and .tool_wrappers.cloudflared.script == "scripts/cf_cloudflared.sh"
  and .tool_wrappers.cloudflared.backend == "cloudflared"
  and (.tool_wrappers.cloudflared.default_args | index("version")) != null
  and (.tool_wrappers.cloudflared.read_only_prefixes | map(join(" ")) | index("tunnel list")) != null
  and (.tool_wrappers.cloudflared.read_only_prefixes | map(join(" ")) | index("tunnel token")) == null
' "${ROOT_DIR}/catalog/runtime.json"
assert_jq_file "docs bank shape" '.checked_on != null and .refresh_policy.refresh_interval_days > 0 and (.foundation | length) > 0 and (.watch | length) > 0' "${ROOT_DIR}/catalog/cloudflare-doc-bank.json"
assert_jq_file "docs bank api gateway topic" '(.foundation | any(.id == "api-gateway")) and (.foundation | any(.id == "audit-logs")) and (.watch | any(.id == "api-shield-vulnerability-scanner"))' "${ROOT_DIR}/catalog/cloudflare-doc-bank.json"
assert_jq_file "standards shape" '(.universal | length) > 0 and (.surfaces | keys | length) > 0' "${ROOT_DIR}/catalog/standards.json"
assert_jq_file "compatibility freshness thresholds" '.audit.compatibility_date_freshness.note_after_days == 30 and .audit.compatibility_date_freshness.warning_after_days == 90' "${ROOT_DIR}/catalog/standards.json"
assert_jq_file "surface registry shape" '(.surfaces | keys | length) > 0' "${ROOT_DIR}/catalog/surfaces.json"
assert_jq_file "ownership registry shape" '
  .version == 1
  and (.resources | type == "array")
  and (.resources | length) > 0
' "${ROOT_DIR}/state/ownership/resources.json"
assert_cross_catalog_empty "ownership resource ids are unique" '
  [
    ($ownership[0].resources // [])
    | group_by(.id)
    | .[]?
    | select(length > 1)
    | {id: .[0].id, duplicate_count: length}
  ]
'
assert_cross_catalog_empty "ownership resource keys are unique" '
  [
    ($ownership[0].resources // [])
    | group_by(.resource_key)
    | .[]?
    | select(length > 1)
    | {resource_key: .[0].resource_key, owners: map(.owner)}
  ]
'
assert_cross_catalog_empty "ownership resources are complete" '
  ($runtime[0].ownership_registry.proof_classes // []) as $proof_classes
  | [
      ($ownership[0].resources // [])[] as $entry
      | $entry
      | select(
          (.id // "") == ""
          or (.resource_key // "") == ""
          or (.resource.cloudflare_surface // "") == ""
          or (.owner.system // "") == ""
          or (.owner.repo // "") == ""
          or (.deploy_lane.default // "") == ""
          or ((.secrets.env // []) | length) == 0
          or (.authority.control_plane // "") != "cfctl"
          or ((.authority.allowed_change_commands // []) | length) == 0
          or (.authority.verifier // "") == ""
          or (($proof_classes | index($entry.authority.proof_class // "")) == null)
          or (.incident_runbook // "") == ""
        )
      | {resource: (.id // null), issue: "incomplete_ownership_entry"}
    ]
'
assert_cross_catalog_empty "ownership surfaces resolve" '
  ($surfaces[0].surfaces // {}) as $surface_catalog
  | ($runtime[0].desired_state // {}) as $desired_state
  | [
      ($ownership[0].resources // [])[]
      | .resource.cloudflare_surface as $surface
      | select($surface_catalog[$surface] == null and $desired_state[$surface] == null)
      | {resource: .id, missing_surface: $surface}
    ]
'
assert_cross_catalog_empty "ownership command path is cfctl" '
  [
    ($ownership[0].resources // [])[] as $entry
    | $entry.id as $id
    | (
        ($entry.authority.allowed_change_commands // [])[]
        | select(test("^(CF_TOKEN_LANE=[a-z]+ )?(\\./)?cfctl ") | not)
        | {resource: $id, invalid_change_command: .}
      ),
      (
        ($entry.authority.verifier // "")
        | select(test("^(CF_TOKEN_LANE=[a-z]+ )?(\\./)?cfctl ") | not)
        | {resource: $id, invalid_verifier: .}
      )
    ]
'
assert_cross_catalog_empty "ownership repo ids are portable" '
  [
    ($ownership[0].resources // [])[]
    | select((.owner.repo // "") | test("^/|^~|/Users/"))
    | {resource: .id, repo: .owner.repo}
  ]
'
assert_cross_catalog_empty "surface docs topics resolve to docs bank" '
  (
    ["foundation", "watch"]
    + (($docs[0].foundation // []) | map(.id))
    + (($docs[0].watch // []) | map(.id))
    | unique
  ) as $known_topics
  | [
      ($surfaces[0].surfaces // {})
      | to_entries[]
      | .key as $surface
      | (.value.docs_topics // [])[]?
      | select(($known_topics | index(.)) == null)
      | {surface: $surface, missing_docs_topic: .}
    ]
'
assert_cross_catalog_empty "docs bank topic ids are unique" '
  [
    (($docs[0].foundation // []) + ($docs[0].watch // []))
    | group_by(.id)
    | .[]?
    | select(length > 1)
    | {docs_topic: .[0].id, duplicate_count: length}
  ]
'
assert_cross_catalog_empty "surface standards refs resolve to standards catalog" '
  ($standards[0].surfaces // {}) as $standards_surfaces
  | [
      ($surfaces[0].surfaces // {})
      | to_entries[]
      | select((.value.standards_ref // "") != "")
      | select($standards_surfaces[.value.standards_ref] == null)
      | {surface: .key, missing_standards_ref: .value.standards_ref}
    ]
'
assert_cross_catalog_empty "desired-state surfaces resolve to public surface catalog" '
  ($surfaces[0].surfaces // {}) as $surface_catalog
  | [
      ($runtime[0].desired_state // {})
      | to_entries[]
      | select(.key != "hostname")
      | select($surface_catalog[.key] == null)
      | {desired_state_surface: .key, issue: "missing_surface_catalog_entry"}
    ]
'
assert_cross_catalog_empty "desired-state state dirs are unique" '
  [
    ($runtime[0].desired_state // {})
    | to_entries
    | group_by(.value.state_dir)
    | .[]?
    | select(length > 1)
    | {state_dir: .[0].value.state_dir, surfaces: map(.key)}
  ]
'
assert_cross_catalog_empty "cataloged backend guard scripts are unique" '
  [
    (
      [
        ($runtime[0].policy.backend_guard_scripts // [])[],
        (
          ($runtime[0].policy.special_operations // {})
          | to_entries[]
          | .value.backend_script // empty
        ),
        (
          ($surfaces[0].surfaces // {})
          | to_entries[]
          | select(.value.actions.apply.supported == true)
          | .value.apply_script // empty
        )
      ]
    )
    | group_by(.)
    | .[]?
    | select(length > 1)
    | {backend_script: .[0], duplicate_count: length}
  ]
'
assert_cross_catalog_empty "cataloged writable surfaces declare backend scripts" '
  [
    ($surfaces[0].surfaces // {})
    | to_entries[]
    | select(.value.actions.apply.supported == true)
    | select((.value.apply_script // "") == "")
    | {surface: .key, issue: "missing_apply_script"}
  ]
'
while IFS=$'\t' read -r source_key backend_script; do
  [[ -n "${source_key}" ]] || continue
  [[ -f "${ROOT_DIR}/${backend_script}" ]] || die "cataloged backend script ${source_key}: missing ${backend_script}"
  if command -v rg >/dev/null 2>&1; then
    rg -q 'cf_require_backend_dispatch' "${ROOT_DIR}/${backend_script}" || die "cataloged backend script ${source_key}: ${backend_script} lacks cf_require_backend_dispatch"
  else
    grep -q 'cf_require_backend_dispatch' "${ROOT_DIR}/${backend_script}" || die "cataloged backend script ${source_key}: ${backend_script} lacks cf_require_backend_dispatch"
  fi
done < <(
  jq -r -n \
    --slurpfile runtime "${ROOT_DIR}/catalog/runtime.json" \
    --slurpfile surfaces "${ROOT_DIR}/catalog/surfaces.json" \
    '
      (
        [
          ($runtime[0].policy.backend_guard_scripts // [])[]
          | ["runtime.backend_guard_scripts", .]
        ]
        + [
          ($runtime[0].policy.special_operations // {})
          | to_entries[]
          | select((.value.backend_script // "") != "")
          | ["runtime.special_operations." + .key, .value.backend_script]
        ]
        + [
          ($surfaces[0].surfaces // {})
          | to_entries[]
          | select(.value.actions.apply.supported == true)
          | [.key, .value.apply_script]
        ]
      )
      | .[]
      | @tsv
    '
)
while IFS= read -r state_dir; do
  [[ -n "${state_dir}" ]] || continue
  [[ -d "${ROOT_DIR}/${state_dir}" ]] || die "desired-state state_dir missing: ${state_dir}"
done < <(
  jq -r '
    (.desired_state // {})
    | to_entries[]
    | .value.state_dir // empty
  ' "${ROOT_DIR}/catalog/runtime.json"
)
assert_jq_file "surface module bindings" '
  .surfaces["access.app"].module == "access_app"
  and .surfaces["access.app"].standards_ref == "access.app"
  and (.surfaces["access.app"].docs_topics | index("zero-trust-api")) != null
  and .surfaces["access.policy"].module == "access_policy"
  and .surfaces["access.policy"].standards_ref == "access.policy"
  and (.surfaces["access.policy"].docs_topics | index("zero-trust-api")) != null
  and .surfaces["audit.log"].inventory_script == "scripts/cf_inventory_audit_logs.sh"
  and .surfaces["audit.log"].permission_family == "Account Settings"
  and .surfaces["audit.log"].actions.apply.supported == false
  and (.surfaces["audit.log"].docs_topics | index("audit-logs")) != null
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
assert_contains "cfctl prompt token revoke" "For token revocation, require \`--plan\` first" "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt error verb" "\`doctor\`, \`audit\`, \`admin\`, \`bootstrap\`, \`lanes\`, \`surfaces\`, \`docs\`, \`previews\`, \`locks\`, \`wrangler\`, \`cloudflared\`, \`hostname\`, \`standards\`, \`token\`, \`list\`, \`get\`, \`can\`, \`classify\`, \`guide\`, \`apply\`, \`verify\`, \`explain\`, \`snapshot\`, \`diff\`, or \`error\`." "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt hostname" "For \`hostname\`, treat \`verify\`, \`diff\`, and \`plan\` as read-only composite evidence flows" "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl prompt wrapper gating" "For \`wrangler\` and \`cloudflared\`, treat clearly read-only subcommands as direct wrapped executions" "${ROOT_DIR}/CFCTL_PROMPT.md"
assert_contains "cfctl preview inactive legacy cleanup command" "purge-inactive-legacy" "${ROOT_DIR}/commands/cfctl.sh"
assert_contains "readme wrapper examples" "cfctl wrangler --version" "${ROOT_DIR}/README.md"
assert_contains "readme inactive legacy preview cleanup" "cfctl previews purge-inactive-legacy" "${ROOT_DIR}/README.md"
assert_contains "readme source-live boundary" "Source Config Vs Live State" "${ROOT_DIR}/README.md"
assert_contains "readme hostname lifecycle" "Hostname lifecycle" "${ROOT_DIR}/README.md"
assert_contains "readme token revoke" "cfctl token revoke --id <token-id> --ack-plan <operation-id> --confirm delete" "${ROOT_DIR}/README.md"
assert_contains "readme standards audit freshness" "checked-in Wrangler config alignment, including \`compatibility_date\` freshness" "${ROOT_DIR}/README.md"
assert_contains "agents wrapper hierarchy" "cfctl wrangler ..." "${ROOT_DIR}/AGENTS.md"
assert_contains "agents source-live boundary" "A clean standards audit proves source-config alignment, not live edge state." "${ROOT_DIR}/AGENTS.md"
assert_contains "agents hostname lifecycle" "Hostname lifecycle specs live under \`state/hostname/\`" "${ROOT_DIR}/AGENTS.md"
assert_contains "agents token revoke" "cfctl token revoke --id <token-id> --ack-plan <operation-id> --confirm delete" "${ROOT_DIR}/AGENTS.md"
assert_contains "agent landing decision path" "## Decision Path" "${ROOT_DIR}/docs/agent-landing.md"
assert_contains "agent landing source-live boundary" "Do not turn a source-config audit into a live Cloudflare claim." "${ROOT_DIR}/docs/agent-landing.md"
assert_contains "runbook wrapper examples" "cfctl cloudflared version" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook inactive legacy preview cleanup" "previews purge-inactive-legacy" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook audit log read" "cfctl list audit.log" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook hostname lifecycle" "cfctl hostname verify --file state/hostname/example.yaml" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook token revoke" "token revoke --plan\` reads token id/name/status/expiry metadata" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook compatibility freshness" "standards audit\` reports \`compatibility_date\` aging and stale counts" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "runbook standards audit source evidence" "standards audit\` is source-config evidence" "${ROOT_DIR}/docs/runbooks/cfctl.md"
assert_contains "config standards compatibility freshness" "Compatibility-date freshness is intentionally advisory" "${ROOT_DIR}/docs/config-standards.md"
assert_contains "runtime policy inactive legacy preview cleanup" "cfctl previews purge-inactive-legacy" "${ROOT_DIR}/docs/runtime-policy.md"
assert_contains "capabilities operable note" "This table is the operable runtime surface." "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities generated note" "_Generated from \`catalog/surfaces.json\` and \`catalog/runtime.json\`." "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities module column" "| Surface | Read | Apply | Desired State | Standards | Docs Topics | Module |" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "capabilities hostname composite" "Composite lifecycle commands:" "${ROOT_DIR}/docs/capabilities.md"
assert_contains "docs bank tracked vs operable note" "Tracked here does not automatically mean operable through \`cfctl\` today" "${ROOT_DIR}/docs/cloudflare-doc-bank.md"
assert_contains "docs bank audit logs" "Audit Logs v2" "${ROOT_DIR}/docs/cloudflare-doc-bank.md"
assert_contains "public contract live verifier note" "This is a live account smoke test." "${ROOT_DIR}/scripts/verify_public_contract.sh"
assert_contains "contract workflow static gate" "python3 scripts/verify_permission_catalog.py --cfctl ./cfctl" "${ROOT_DIR}/.github/workflows/cfctl-contract.yml"
assert_contains "contract workflow live gate" "./scripts/verify_public_contract.sh" "${ROOT_DIR}/.github/workflows/cfctl-contract.yml"
assert_contains "contract workflow secret gate" "CF_DEV_TOKEN secret is required" "${ROOT_DIR}/.github/workflows/cfctl-contract.yml"
assert_contains "contract workflow protected environment" "environment: cfctl-live" "${ROOT_DIR}/.github/workflows/cfctl-contract.yml"
assert_contains "public contract inactive legacy preview cleanup" "previews purge-inactive-legacy" "${ROOT_DIR}/scripts/verify_public_contract.sh"
assert_contains "permission doctrine source" "Cloudflare API token permissions are resource-scoped" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine environment" "cfctl-live" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine bootstrap creator" "Account API Tokens Write" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine profile read" "- \`read\`: default inventory and audit profile, including \`audit.log\`." "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine profile dns" "- \`dns\`: DNS record read/write profile" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine profile hostname" "- \`hostname\`: composite hostname lifecycle profile" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine profile deploy" "- \`deploy\`: Worker, Pages, D1, R2, Queues" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine profile security audit" "- \`security-audit\`: read-only API-security" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine profile full operator" "- \`full-operator\`: broad local operator profile" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine token exclusion" "Operator profiles must not include \`Account API Tokens *\` permissions." "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine read forbidden" "Read-risk profiles must not include \`* Write\`, \`* Revoke\`, or \`* Run\`" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "permission doctrine account settings blast radius" "\`Account Settings Read\` is the coarse Cloudflare permission behind" "${ROOT_DIR}/docs/permission-doctrine.md"
assert_contains "readme permission doctrine" "docs/permission-doctrine.md" "${ROOT_DIR}/README.md"
assert_contains "runbook permission doctrine" "docs/permission-doctrine.md" "${ROOT_DIR}/docs/runbooks/cfctl.md"

echo "static-contract verification passed"

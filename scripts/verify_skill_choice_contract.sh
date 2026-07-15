#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG_PATH="${ROOT_DIR}/catalog/skill-choices.json"
CREATED_ARTIFACTS=()
CREATED_TEMP_FILES=()

die() {
  echo "skill-choice verification failed: $*" >&2
  exit 1
}

remember_artifact() {
  local json="$1"
  local path
  path="$(jq -r '.artifact_path // empty' <<< "${json}")"
  [[ -n "${path}" ]] && CREATED_ARTIFACTS+=("${path}")
}

cleanup() {
  local path
  for path in "${CREATED_ARTIFACTS[@]:-}"; do
    case "${path}" in
      "${ROOT_DIR}"/var/inventory/runtime/*.json) rm -f -- "${path}" ;;
    esac
  done
  for path in "${CREATED_TEMP_FILES[@]:-}"; do
    case "${path}" in
      "${TMPDIR:-/tmp}"/cfctl-skill-evidence.*) rm -f -- "${path}" ;;
    esac
  done
}
trap cleanup EXIT

command -v jq >/dev/null 2>&1 || die "jq is required"
[[ -f "${CATALOG_PATH}" ]] || die "missing ${CATALOG_PATH}"

jq -e '
  .score.weights as $weights
  | .schema_version == 1
  and .kind == "SKILL_CHOICE_POLICY"
  and ([.score.weights[]] | add) == 100
  and (.adapters | map(.id) | unique | length) == (.adapters | length)
  and (.adapters | map(.id) | index("cfctl-native")) != null
  and (.adapters | map(.id) | index("cloudflare-api-mcp")) != null
  and (.adapters | map(.id) | index("cfctl-wrangler")) != null
  and (.adapters | map(.id) | index("cfctl-cloudflared")) != null
  and (.adapters | map(.id) | index("browser-run")) != null
  and (.adapters | map(.id) | index("computer-use")) != null
  and all(.adapters[];
    (.policy_metrics | keys | sort) == ($weights | keys | sort)
    and all(.policy_metrics[]; type == "number" and . >= 0 and . <= 100)
    and (.allowed_risks | length) > 0
    and (.capabilities | length) > 0
    and (.evidence_contract | length) > 0
  )
' "${CATALOG_PATH}" >/dev/null || die "catalog schema or score contract is invalid"

jq -e '(.public_verbs | index("skills")) != null and (.landing_flow | index("skills choose")) != null' \
  "${ROOT_DIR}/catalog/runtime.json" >/dev/null || die "skills is not a public landing-flow verb"

help_text="$("${ROOT_DIR}/cfctl" help)"
grep -Fq 'cfctl skills choose --intent <text>' <<< "${help_text}" || die "help omits skills choose"
grep -Fq 'cfctl skills metrics' <<< "${help_text}" || die "help omits skills metrics"

api_json="$(
  "${ROOT_DIR}/cfctl" skills choose \
    --intent "Discover an uncatalogued Cloudflare endpoint without guessing" \
    --risk read \
    --need dynamic_api \
    --need verification \
    --available cloudflare-api-mcp
)"
remember_artifact "${api_json}"
jq -e '
  .ok == true
  and .action == "skills"
  and .operation == "choose"
  and .result.kind == "SKILL_CHOICE"
  and .result.decision.status == "selected"
  and .result.decision.adapter_id == "cloudflare-api-mcp"
  and .result.decision.executable == true
  and .result.intent.raw == null
  and (.result.intent.digest | length) == 64
  and (.result.candidates | length) >= 1
  and all(.result.candidates[]; .metrics.metric_class == "declared_policy")
' <<< "${api_json}" >/dev/null || die "dynamic API choice is not deterministic or privacy-safe"

api_repeat_json="$(
  "${ROOT_DIR}/cfctl" skills choose \
    --intent "Discover an uncatalogued Cloudflare endpoint without guessing" \
    --risk read \
    --need dynamic_api \
    --need verification \
    --available cloudflare-api-mcp
)"
remember_artifact "${api_repeat_json}"
jq -e --arg first_id "$(jq -r '.result.choice_id' <<< "${api_json}")" '
  .result.choice_id != $first_id
  and .result.decision.adapter_id == "cloudflare-api-mcp"
  and .result.candidates[0].adapter_id == "cloudflare-api-mcp"
' <<< "${api_repeat_json}" >/dev/null || die "repeated choices need unique receipts and stable routing"

api_write_json="$(
  "${ROOT_DIR}/cfctl" skills choose \
    --intent "Change an uncatalogued Cloudflare endpoint" \
    --risk write \
    --need dynamic_api \
    --available cloudflare-api-mcp
)"
remember_artifact "${api_write_json}"
jq -e '
  .ok == true
  and .result.decision.status == "blocked"
  and .result.decision.adapter_id == null
  and .result.decision.executable == false
  and .result.decision.authority_granted == false
  and .result.decision.preview_bypass_allowed == false
' <<< "${api_write_json}" >/dev/null || die "uncatalogued API writes must fail closed"

ui_json="$(
  "${ROOT_DIR}/cfctl" skills choose \
    --intent "Inspect a dashboard-only setting" \
    --risk write \
    --need native_ui \
    --need verification \
    --available computer-use
)"
remember_artifact "${ui_json}"
jq -e '
  .ok == true
  and .result.decision.adapter_id == "computer-use"
  and .result.decision.executable == true
  and .result.decision.authority_granted == false
  and .result.decision.preview_bypass_allowed == false
  and .result.decision.external_confirmation_bypass_allowed == false
  and (.result.decision.required_controls | index("preview_ack_for_cloudflare_mutation")) != null
  and (.result.decision.required_controls | index("post_change_verification")) != null
' <<< "${ui_json}" >/dev/null || die "Computer Use can bypass the cfctl trust boundary"

choice_id="$(jq -r '.result.choice_id' <<< "${ui_json}")"
choice_artifact="$(jq -r '.artifact_path' <<< "${ui_json}")"
[[ -f "${choice_artifact}" ]] || die "choice artifact was not persisted"
if grep -Fq 'Inspect a dashboard-only setting' "${choice_artifact}"; then
  die "raw intent leaked into choice artifact"
fi

self_evidence_status=0
set +e
self_evidence_json="$(
  "${ROOT_DIR}/cfctl" skills record \
    --choice-id "${choice_id}" \
    --adapter computer-use \
    --outcome verified \
    --duration-ms 1 \
    --evidence "${choice_artifact}" \
    --evidence-class post_change_verification
)"
self_evidence_status=$?
set -e
remember_artifact "${self_evidence_json}"
[[ "${self_evidence_status}" -ne 0 ]] || die "a choice receipt was accepted as its own verification evidence"
jq -e '.ok == false and .error.code == "invalid_skill_choice_request"' <<< "${self_evidence_json}" >/dev/null \
  || die "self-evidence rejection did not use the structured failure contract"

evidence_path="$(mktemp "${TMPDIR:-/tmp}/cfctl-skill-evidence.XXXXXX")"
CREATED_TEMP_FILES+=("${evidence_path}")
jq -n '{kind:"test_verification",ok:true}' > "${evidence_path}"

record_json="$(
  "${ROOT_DIR}/cfctl" skills record \
    --choice-id "${choice_id}" \
    --adapter computer-use \
    --outcome verified \
    --duration-ms 24 \
    --evidence "${evidence_path}" \
    --evidence-class post_change_verification
)"
remember_artifact "${record_json}"
jq -e '
  .ok == true
  and .operation == "record"
  and .result.kind == "SKILL_OUTCOME"
  and .result.outcome == "verified"
  and .result.duration_ms == 24
  and .result.choice_found == true
  and .result.evidence.class == "post_change_verification"
  and (.result.evidence.sha256 | length) == 64
  and .result.evidence_valid_at_recording == true
  and .result.duration_source == "caller_measured"
' <<< "${record_json}" >/dev/null || die "verified outcome was not recorded against the choice"

duplicate_status=0
set +e
duplicate_json="$(
  "${ROOT_DIR}/cfctl" skills record \
    --choice-id "${choice_id}" \
    --adapter computer-use \
    --outcome verified \
    --duration-ms 25 \
    --evidence "${evidence_path}" \
    --evidence-class post_change_verification
)"
duplicate_status=$?
set -e
remember_artifact "${duplicate_json}"
[[ "${duplicate_status}" -ne 0 ]] || die "duplicate outcome was accepted"
jq -e '.ok == false and .error.code == "invalid_skill_choice_request"' <<< "${duplicate_json}" >/dev/null \
  || die "duplicate outcome rejection did not use the structured failure contract"

metrics_json="$("${ROOT_DIR}/cfctl" skills metrics)"
remember_artifact "${metrics_json}"
jq -e '
  .ok == true
  and .operation == "metrics"
  and .result.kind == "SKILL_METRICS"
  and .result.metric_class == "observed_outcomes"
  and (.result.adapters[] | select(.adapter_id == "computer-use") | .attempts) >= 1
  and (.result.adapters[] | select(.adapter_id == "computer-use") | .verified) >= 1
  and (.result.adapters[] | select(.adapter_id == "computer-use") | .observed_success_rate) > 0
  and .result.invalid_evidence_records == 0
' <<< "${metrics_json}" >/dev/null || die "observed outcome metrics are missing"

[[ -f "${ROOT_DIR}/skills/cfctl-operator/SKILL.md" ]] || die "cfctl operator SKILL.md is missing"
grep -Fq 'cfctl skills choose' "${ROOT_DIR}/skills/cfctl-operator/SKILL.md" || die "operator skill does not invoke SKILL_CHOICE"
grep -Fq 'Computer Use' "${ROOT_DIR}/skills/cfctl-operator/SKILL.md" || die "operator skill omits Computer Use fallback policy"
grep -Fq '`skills`' "${ROOT_DIR}/CFCTL_PROMPT.md" || die "embedding prompt omits skills verb"

echo "skill-choice verification passed"

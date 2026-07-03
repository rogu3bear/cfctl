#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() {
  echo "form-intake contract verification failed: $*" >&2
  exit 1
}

fixture_file="$(mktemp "${TMPDIR:-/tmp}/form-intake-fixture.XXXXXX")"
missing_fixture_file="$(mktemp "${TMPDIR:-/tmp}/form-intake-missing-fixture.XXXXXX")"
ready_spec_file="$(mktemp "${TMPDIR:-/tmp}/form-intake-ready-spec.XXXXXX")"
missing_spec_file="$(mktemp "${TMPDIR:-/tmp}/form-intake-missing-spec.XXXXXX")"
source_dir="$(mktemp -d "${TMPDIR:-/tmp}/form-intake-source.XXXXXX")"
caller_spec_dir="$(mktemp -d "${TMPDIR:-/tmp}/form-intake-caller-spec.XXXXXX")"
trap 'rm -f "${fixture_file}" "${missing_fixture_file}" "${ready_spec_file}" "${missing_spec_file}"; rm -rf "${source_dir}" "${caller_spec_dir}"' EXIT

cat >"${source_dir}/page.html" <<'HTML'
<!doctype html>
<form id="contact-form" action="/api/contact" method="post">
  <input name="name" required>
  <input name="email" type="email" required>
  <input name="company">
  <textarea name="message" required></textarea>
  <input name="website" tabindex="-1" autocomplete="off">
  <div class="cf-turnstile" data-sitekey="0xREADY"></div>
  <button type="submit">Send</button>
</form>
HTML

cat >"${source_dir}/handler.ts" <<'TS'
export async function onRequestPost({ request, env }) {
  const body = await request.formData();
  const payload = {
    name: body.get("name"),
    email: body.get("email"),
    company: body.get("company"),
    message: body.get("message"),
    website: body.get("website"),
  };
  await env.INTAKE_DB.prepare("insert into contact_submissions values (?1)").bind(payload.email).run();
  return Response.json({ ok: true, logged: true });
}
TS

cat >"${fixture_file}" <<'JSON'
{
  "turnstile_widgets": [
    {
      "name": "example-contact",
      "sitekey": "0xREADY",
      "domains": ["example.com"],
      "mode": "managed"
    }
  ],
  "pages_projects": [
    {
      "name": "example-pages",
      "domains": ["example.com"],
      "deployment_configs": {
        "production": {
          "env_vars": {
            "TURNSTILE_SITE_KEY": {"type": "secret_text", "value": ""},
            "TURNSTILE_SECRET": {"type": "secret_text", "value": ""},
            "RESEND_API_KEY": {"type": "secret_text", "value": ""}
          },
          "d1_databases": {
            "INTAKE_DB": {"id": "ready-db"}
          }
        }
      }
    }
  ],
  "worker_secrets": [],
  "d1_databases": [{"name": "example-intake-db", "uuid": "ready-db"}],
  "r2_buckets": [],
  "queues": [],
  "access_apps": [],
  "resend": {
    "domains": [
      {"name": "example.com", "status": "verified"}
    ]
  },
  "page": {
    "status": 200,
    "url": "https://example.com/contact",
    "html": "<!doctype html><form id=\"contact-form\"><input name=\"name\" required><input name=\"email\" type=\"email\" required><input name=\"company\"><textarea name=\"message\" required></textarea><input name=\"website\" hidden><div class=\"cf-turnstile\" data-sitekey=\"0xREADY\"></div><button type=\"submit\">Send</button></form>"
  }
}
JSON

cat >"${missing_fixture_file}" <<'JSON'
{
  "turnstile_widgets": [
    {
      "name": "wrong-widget",
      "sitekey": "0xWRONG",
      "domains": ["other.example.com"],
      "mode": "managed"
    }
  ],
  "pages_projects": [
    {
      "name": "example-pages",
      "domains": ["example.com"],
      "deployment_configs": {
        "production": {
          "env_vars": {}
        }
      }
    }
  ],
  "worker_secrets": [],
  "d1_databases": [],
  "r2_buckets": [],
  "queues": [],
  "access_apps": [
    {
      "name": "Example Contact",
      "domain": "example.com/contact",
      "policies": [
        {"decision": "allow", "name": "Allow Operators"}
      ]
    }
  ],
  "resend": {
    "domains": []
  },
  "page": {
    "status": 200,
    "url": "https://example.com/contact",
    "html": "<!doctype html><form id=\"contact-form\"><input name=\"name\"><button type=\"submit\">Send</button></form>"
  }
}
JSON

cat >"${ready_spec_file}" <<JSON
{
  "name": "example-contact",
  "route": {
    "url": "https://example.com/contact",
    "submit_url": "https://example.com/api/contact",
    "method": "POST",
    "public": true
  },
  "owner": {
    "repo": "${source_dir}",
    "service": "pages",
    "project": "example-pages"
  },
  "source": {
    "frontend_files": ["${source_dir}/page.html"],
    "backend_files": ["${source_dir}/handler.ts"]
  },
  "fields": [
    {"name": "name", "required": true},
    {"name": "email", "required": true, "type": "email"},
    {"name": "company", "required": false},
    {"name": "message", "required": true, "type": "textarea"},
    {"name": "website", "required": false, "hidden": true, "honeypot": true}
  ],
  "turnstile": {
    "required": true,
    "sitekey": "0xREADY",
    "widget_name": "example-contact",
    "sitekey_binding": "TURNSTILE_SITE_KEY",
    "secret_binding": "TURNSTILE_SECRET"
  },
  "access": {
    "expected": "public"
  },
  "resend": {
    "mode": "enabled",
    "api_key_binding": "RESEND_API_KEY",
    "domain": "example.com",
    "provider_readback_required": true
  },
  "logging": {
    "sinks": [
      {"type": "d1.database", "name": "example-intake-db", "binding": "INTAKE_DB"}
    ]
  },
  "synthetic_submit": {
    "enabled": false
  }
}
JSON

cat >"${missing_spec_file}" <<JSON
{
  "name": "example-contact",
  "route": {
    "url": "https://example.com/contact",
    "submit_url": "https://example.com/api/contact",
    "method": "POST",
    "public": true
  },
  "owner": {
    "repo": "${source_dir}",
    "service": "pages",
    "project": "example-pages"
  },
  "source": {
    "frontend_files": ["${source_dir}/page.html"],
    "backend_files": ["${source_dir}/handler.ts"]
  },
  "fields": [
    {"name": "name", "required": true},
    {"name": "email", "required": true},
    {"name": "message", "required": true},
    {"name": "website", "required": false, "hidden": true, "honeypot": true}
  ],
  "turnstile": {
    "required": true,
    "sitekey": "0xREADY",
    "widget_name": "example-contact",
    "sitekey_binding": "TURNSTILE_SITE_KEY",
    "secret_binding": "TURNSTILE_SECRET"
  },
  "access": {
    "expected": "public"
  },
  "resend": {
    "mode": "enabled",
    "api_key_binding": "RESEND_API_KEY",
    "domain": "example.com",
    "provider_readback_required": true
  },
  "logging": {
    "sinks": [
      {"type": "d1.database", "name": "example-intake-db", "binding": "INTAKE_DB"}
    ]
  },
  "synthetic_submit": {
    "enabled": true,
    "test_marker": "cfctl-form-intake-contract"
  }
}
JSON

jq -e '
  .synthetic_submit.enabled == false
  and .turnstile.required == true
  and .resend.mode == "enabled"
' "${ROOT_DIR}/state/form-intake/example.json" >/dev/null || die "checked-in form-intake example must default to no synthetic submit"

output="$(
  FORM_INTAKE_EVIDENCE_FILE="${fixture_file}" \
  FORM_INTAKE_ACTION=verify \
  SPEC_FILE="${ready_spec_file}" \
  python3 "${ROOT_DIR}/scripts/cf_form_intake_lifecycle.py"
)"
artifact_path="$(printf '%s\n' "${output}" | tail -n 1)"
[[ -f "${artifact_path}" ]] || die "verify artifact was not written"

jq -e '
  .readiness.source_ready == true
  and .readiness.cloudflare_ready == true
  and .readiness.page_ready == true
  and .readiness.resend_ready == true
  and .readiness.synthetic_ready == true
  and .ready == true
  and (.drifts | length) == 0
  and .checks.synthetic_submit.mode == "disabled"
  and .checks.synthetic_submit.performed == false
  and (.plan.operations | length) == 0
' "${artifact_path}" >/dev/null || die "ready fixture did not verify"

missing_output="$(
  FORM_INTAKE_EVIDENCE_FILE="${missing_fixture_file}" \
  FORM_INTAKE_ACTION=diff \
  SPEC_FILE="${missing_spec_file}" \
  python3 "${ROOT_DIR}/scripts/cf_form_intake_lifecycle.py"
)"
missing_artifact_path="$(printf '%s\n' "${missing_output}" | tail -n 1)"
[[ -f "${missing_artifact_path}" ]] || die "missing fixture artifact was not written"

jq -e '
  .ready == false
  and .readiness.cloudflare_ready == false
  and .readiness.page_ready == false
  and .readiness.resend_ready == false
  and .readiness.synthetic_ready == false
  and (.drift_classes | index("turnstile_widget_drift")) != null
  and (.drift_classes | index("secret_binding_missing")) != null
  and (.drift_classes | index("access_blocks_public_intake")) != null
  and (.drift_classes | index("resend_domain_drift")) != null
  and (.drift_classes | index("page_field_missing")) != null
  and (.drift_classes | index("storage_sink_missing")) != null
  and (.drift_classes | index("synthetic_submit_not_executed")) != null
  and any(.plan.operations[]; .surface == "turnstile.widget" and (.preview_command | contains("cfctl apply turnstile.widget update")))
  and any(.plan.operations[]; .surface == "pages.secret" and (.preview_command | contains("cfctl apply pages.secret upsert --project example-pages --name TURNSTILE_SECRET --plan")))
  and any(.plan.operations[]; .surface == "access.app" and .blocked == "public-intake Access remediation must be reviewed as a component access.app/access.policy change")
' "${missing_artifact_path}" >/dev/null || die "missing fixture drift contract did not match"

help_output="$("${ROOT_DIR}/cfctl" --help)"
grep -Fq "cfctl form-intake init|verify|snapshot|diff|plan" <<< "${help_output}" || die "cfctl help missing form-intake command"
grep -Fq "form-intake Composite public intake readiness" <<< "${help_output}" || die "cfctl help missing form-intake summary"

set +e
apply_output="$("${ROOT_DIR}/cfctl" form-intake apply --file "${ready_spec_file}" 2>&1)"
apply_status="$?"
set -e
[[ "${apply_status}" -ne 0 ]] || die "cfctl form-intake apply must remain blocked"
grep -Fq "Unsupported form-intake action: apply" <<< "${apply_output}" || die "cfctl form-intake apply did not explain blocked action"

cfctl_output="$(
  FORM_INTAKE_EVIDENCE_FILE="${fixture_file}" \
  "${ROOT_DIR}/cfctl" form-intake plan --file "${ready_spec_file}"
)"
operation_id="$(jq -r '.summary.operation_id // empty' <<< "${cfctl_output}")"
[[ -n "${operation_id}" ]] || die "cfctl form-intake plan did not emit operation_id"
jq -e '
  .ok == true
  and .action == "form-intake"
  and .surface == "form.intake"
  and .operation == "plan"
  and .summary.plan_mode == true
  and .summary.ready == true
  and .summary.synthetic_enabled == false
' <<< "${cfctl_output}" >/dev/null || die "cfctl form-intake plan envelope did not match"

init_output="$("${ROOT_DIR}/cfctl" form-intake init --url https://example.com/contact)"
jq -e '
  .ok == true
  and .action == "form-intake"
  and .operation == "init"
  and .result.generated_spec.route.url == "https://example.com/contact"
  and .result.generated_spec.synthetic_submit.enabled == false
  and .result.generated_spec.turnstile.required == true
' <<< "${init_output}" >/dev/null || die "cfctl form-intake init envelope did not match"

cp "${ready_spec_file}" "${caller_spec_dir}/caller-relative.json"
caller_spec_physical_dir="$(cd -P "${caller_spec_dir}" && pwd)"
caller_relative_output="$(
  cd "${caller_spec_dir}"
  FORM_INTAKE_EVIDENCE_FILE="${fixture_file}" \
    "${ROOT_DIR}/cfctl" form-intake verify --file caller-relative.json
)"
jq -e \
  --arg expected_spec "${caller_spec_physical_dir}/caller-relative.json" \
  '
    .ok == true
    and .summary.spec_path == $expected_spec
    and .summary.ready == true
  ' <<< "${caller_relative_output}" >/dev/null || die "caller-relative form-intake spec path did not resolve"

standards_output="$("${ROOT_DIR}/cfctl" standards form.intake)"
jq -e '
  .ok == true
  and .action == "standards"
  and .surface == "form.intake"
  and .summary.standard_count >= 4
  and .summary.desired_state_supported == true
  and .result.runtime.backend == "form_intake_lifecycle"
' <<< "${standards_output}" >/dev/null || die "form.intake standards envelope did not match"

classify_output="$("${ROOT_DIR}/cfctl" classify form.intake plan --file "${ready_spec_file}")"
jq -e '
  .ok == true
  and .action == "classify"
  and .surface == "form.intake"
  and .operation == "plan"
  and .summary.preview_required == false
  and .summary.selector_ready == true
  and .result.public_example == "cfctl form-intake plan --file state/form-intake/<name>.json"
' <<< "${classify_output}" >/dev/null || die "form.intake classify envelope did not match"

guide_output="$("${ROOT_DIR}/cfctl" guide form.intake plan --file "${ready_spec_file}")"
jq -e '
  .ok == true
  and .action == "guide"
  and .surface == "form.intake"
  and .operation == "plan"
  and .result.commands.discovery == "cfctl form-intake verify --file '"${ready_spec_file}"'"
  and .result.commands.preview == "cfctl form-intake plan --file '"${ready_spec_file}"'"
  and .result.commands.apply_blocked == null
' <<< "${guide_output}" >/dev/null || die "form.intake guide envelope did not match"

echo "form-intake contract verification passed"

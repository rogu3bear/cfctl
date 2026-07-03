#!/usr/bin/env python3

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen


ROOT = Path(__file__).resolve().parents[1]
ACCESS_BLOCKED = "public-intake Access remediation must be reviewed as a component access.app/access.policy change"


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def operation_id() -> str:
    value = os.environ.get("CFCTL_OPERATION_ID")
    if value:
        return value
    return f"form-intake-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"


def read_json(path: Path) -> Any:
    with path.open() as handle:
        return json.load(handle)


def resolve_spec_path(raw: str | None) -> Path:
    if raw:
        path = Path(raw)
        if not path.is_absolute():
            path = Path.cwd() / path
        return path.resolve()

    spec_dir = ROOT / "state" / "form-intake"
    specs = sorted(spec_dir.glob("*.json"))
    if not specs:
        raise SystemExit("No form-intake specs found under state/form-intake")
    if len(specs) > 1:
        raise SystemExit("Multiple form-intake specs found; pass --file <spec>")
    return specs[0].resolve()


def load_spec(path: Path) -> dict[str, Any]:
    spec = read_json(path)
    if not isinstance(spec, dict):
        raise SystemExit(f"form-intake spec must be a JSON object: {path}")
    return spec


def init_spec(url: str) -> dict[str, Any]:
    parsed = urlparse(url)
    host = parsed.hostname or "example.com"
    path = parsed.path or "/"
    slug = host.replace(".", "-")
    path_slug = path.strip("/").replace("/", "-")
    if path_slug:
        slug = f"{slug}-{path_slug}"
    if not slug.endswith("intake"):
        slug = f"{slug or 'example'}-intake"
    return {
        "name": slug,
        "route": {
            "url": url,
            "submit_url": f"{parsed.scheme or 'https'}://{host}/api/intake",
            "method": "POST",
            "public": True,
        },
        "owner": {
            "repo": "/Users/star/dev/<repo>",
            "service": "pages",
            "project": "<pages-project>",
        },
        "source": {
            "frontend_files": [],
            "backend_files": [],
        },
        "fields": [
            {"name": "name", "required": True},
            {"name": "email", "required": True, "type": "email"},
            {"name": "message", "required": True, "type": "textarea"},
            {"name": "website", "required": False, "hidden": True, "honeypot": True},
        ],
        "turnstile": {
            "required": True,
            "sitekey": "<turnstile-sitekey>",
            "widget_name": slug,
            "sitekey_binding": "TURNSTILE_SITE_KEY",
            "secret_binding": "TURNSTILE_SECRET",
        },
        "access": {"expected": "public"},
        "resend": {
            "mode": "enabled",
            "api_key_binding": "RESEND_API_KEY",
            "domain": host,
            "provider_readback_required": False,
        },
        "logging": {"sinks": []},
        "synthetic_submit": {"enabled": False},
    }


def route_url(spec: dict[str, Any]) -> str:
    return str(((spec.get("route") or {}).get("url") or "")).strip()


def route_host(spec: dict[str, Any]) -> str:
    parsed = urlparse(route_url(spec))
    return parsed.hostname or ""


def route_domain_key(spec: dict[str, Any]) -> str:
    parsed = urlparse(route_url(spec))
    path = parsed.path if parsed.path and parsed.path != "/" else ""
    return f"{parsed.hostname or ''}{path}"


def owner_service(spec: dict[str, Any]) -> str:
    return str(((spec.get("owner") or {}).get("service") or "")).strip().lower()


def owner_project(spec: dict[str, Any]) -> str:
    return str(((spec.get("owner") or {}).get("project") or "")).strip()


def owner_script(spec: dict[str, Any]) -> str:
    return str(((spec.get("owner") or {}).get("script") or "")).strip()


def validate_spec(spec: dict[str, Any]) -> list[dict[str, Any]]:
    errors: list[dict[str, Any]] = []
    url = route_url(spec)
    parsed = urlparse(url)
    if not url or parsed.scheme not in {"http", "https"} or not parsed.hostname:
        errors.append({"class": "invalid_spec", "message": "route.url must be an absolute http(s) URL"})
    if str(((spec.get("route") or {}).get("method") or "POST")).upper() != "POST":
        errors.append({"class": "invalid_spec", "message": "route.method must be POST for v1"})
    if not isinstance(spec.get("fields"), list) or not spec.get("fields"):
        errors.append({"class": "invalid_spec", "message": "fields must be a non-empty list"})
    for index, field in enumerate(spec.get("fields") or []):
        if not isinstance(field, dict) or not str(field.get("name") or "").strip():
            errors.append({"class": "invalid_spec", "message": f"fields[{index}].name is required"})
    if (spec.get("turnstile") or {}).get("required", True) is True:
        turnstile = spec.get("turnstile") or {}
        for key in ("sitekey", "secret_binding"):
            if not str(turnstile.get(key) or "").strip():
                errors.append({"class": "invalid_spec", "message": f"turnstile.{key} is required when Turnstile is enabled"})
    if (spec.get("synthetic_submit") or {}).get("enabled") is True:
        synthetic = spec.get("synthetic_submit") or {}
        if not str(synthetic.get("test_marker") or "").strip():
            errors.append({"class": "invalid_spec", "message": "synthetic_submit.test_marker is required when synthetic submit is enabled"})
    return errors


def run_cfctl(args: list[str], lane: str | None = None) -> dict[str, Any]:
    env = os.environ.copy()
    if lane:
        env["CF_TOKEN_LANE"] = lane
    try:
        completed = subprocess.run(
            [str(ROOT / "cfctl"), *args],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
    except OSError as exc:
        return {"ok": False, "error": str(exc), "result": []}
    try:
        payload = json.loads(completed.stdout)
    except json.JSONDecodeError:
        payload = {"ok": False, "result": [], "stdout": completed.stdout, "stderr": completed.stderr}
    payload.setdefault("ok", completed.returncode == 0)
    return payload


def load_fixture_evidence() -> dict[str, Any] | None:
    fixture = os.environ.get("FORM_INTAKE_EVIDENCE_FILE")
    if fixture:
        return read_json(Path(fixture))
    return None


def collect_evidence(spec: dict[str, Any]) -> dict[str, Any]:
    fixture = load_fixture_evidence()
    if isinstance(fixture, dict):
        return fixture

    evidence: dict[str, Any] = {
        "turnstile_widgets": run_cfctl(["list", "turnstile.widget"]).get("result") or [],
        "access_apps": run_cfctl(["list", "access.app"]).get("result") or [],
        "pages_projects": run_cfctl(["list", "pages.project"]).get("result") or [],
        "d1_databases": run_cfctl(["list", "d1.database"]).get("result") or [],
        "r2_buckets": run_cfctl(["list", "r2.bucket"]).get("result") or [],
        "queues": run_cfctl(["list", "queue"]).get("result") or [],
        "worker_secrets": [],
        "resend": {},
    }
    script = owner_script(spec)
    if script:
        evidence["worker_secrets"] = run_cfctl(["list", "worker.secret", "--script", script]).get("result") or []
    evidence["page"] = fetch_page(route_url(spec))
    resend_file = os.environ.get("FORM_INTAKE_RESEND_EVIDENCE_FILE")
    if resend_file:
        evidence["resend"] = read_json(Path(resend_file))
    return evidence


def fetch_page(url: str) -> dict[str, Any]:
    if not url:
        return {"status": None, "html": "", "error": "missing url"}
    try:
        request = Request(url, headers={"user-agent": "cfctl-form-intake/1.0"})
        with urlopen(request, timeout=15) as response:
            body = response.read(512_000).decode("utf-8", errors="replace")
            return {"status": response.status, "url": url, "html": body}
    except (OSError, URLError) as exc:
        return {"status": None, "url": url, "html": "", "error": str(exc)}


def file_text(path: str, repo_root: str = "") -> tuple[bool, str]:
    p = Path(path)
    if not p.is_absolute() and repo_root:
        p = Path(repo_root) / p
    if not p.exists() or not p.is_file():
        return False, ""
    return True, p.read_text(errors="replace")


def has_name_attr(html: str, name: str) -> bool:
    escaped = re.escape(name)
    patterns = [
        rf"name\s*=\s*['\"]{escaped}['\"]",
        rf"name\s*=\s*{escaped}(?:\s|>|/)",
    ]
    return any(re.search(pattern, html, re.IGNORECASE) for pattern in patterns)


def source_checks(spec: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    repo_root = str(((spec.get("owner") or {}).get("repo") or "")).strip()
    source = spec.get("source") or {}
    frontend_files = [str(item) for item in source.get("frontend_files") or []]
    backend_files = [str(item) for item in source.get("backend_files") or []]
    fields = [str(field.get("name") or "") for field in spec.get("fields") or [] if isinstance(field, dict)]
    drifts: list[dict[str, Any]] = []

    loaded_frontend = [file_text(path, repo_root) for path in frontend_files]
    loaded_backend = [file_text(path, repo_root) for path in backend_files]
    missing_files = [
        *[path for path, loaded in zip(frontend_files, loaded_frontend) if not loaded[0]],
        *[path for path, loaded in zip(backend_files, loaded_backend) if not loaded[0]],
    ]
    frontend_text = "\n".join(text for ok, text in loaded_frontend if ok)
    backend_text = "\n".join(text for ok, text in loaded_backend if ok)

    if missing_files:
        drifts.append({"class": "source_file_missing", "message": "Declared source files are missing", "files": missing_files})
    field_rows = []
    for name in fields:
        in_frontend = name in frontend_text if frontend_text else False
        in_backend = name in backend_text if backend_text else False
        field_rows.append({"name": name, "frontend": in_frontend, "backend": in_backend})
        if frontend_files and not in_frontend:
            drifts.append({"class": "source_field_missing", "field": name, "side": "frontend"})
        if backend_files and not in_backend:
            drifts.append({"class": "source_field_missing", "field": name, "side": "backend"})

    checks = {
        "files": {
            "frontend": frontend_files,
            "backend": backend_files,
            "missing": missing_files,
        },
        "fields": field_rows,
        "ready": not any(item["class"].startswith("source_") for item in drifts),
    }
    return checks, drifts


def pages_project(evidence: dict[str, Any], project: str) -> dict[str, Any] | None:
    for item in evidence.get("pages_projects") or []:
        if item.get("name") == project:
            return item
    return None


def pages_env_vars(project: dict[str, Any] | None) -> dict[str, Any]:
    if not project:
        return {}
    configs = project.get("deployment_configs") or {}
    production = configs.get("production") or {}
    return production.get("env_vars") or {}


def worker_secret_names(evidence: dict[str, Any]) -> set[str]:
    names = set()
    for item in evidence.get("worker_secrets") or []:
        name = item.get("name") or item.get("secret_name")
        if name:
            names.add(str(name))
    return names


def binding_present(spec: dict[str, Any], evidence: dict[str, Any], name: str) -> bool:
    if not name:
        return True
    service = owner_service(spec)
    if service == "pages":
        return name in pages_env_vars(pages_project(evidence, owner_project(spec)))
    return name in worker_secret_names(evidence)


def resource_binding_present(spec: dict[str, Any], evidence: dict[str, Any], sink: dict[str, Any]) -> bool:
    binding = str(sink.get("binding") or "")
    if not binding:
        return True
    if owner_service(spec) != "pages":
        return True
    project = pages_project(evidence, owner_project(spec))
    if not project:
        return False
    production = ((project.get("deployment_configs") or {}).get("production") or {})
    sink_type = sink.get("type")
    binding_maps = []
    if sink_type == "d1.database":
        binding_maps = [production.get("d1_databases") or {}]
    elif sink_type == "r2.bucket":
        binding_maps = [production.get("r2_buckets") or {}]
    elif sink_type == "queue":
        binding_maps = [production.get("queues") or {}, production.get("queue_producers") or {}, production.get("queue_consumers") or {}]
    else:
        binding_maps = [production.get("kv_namespaces") or {}]
    return any(binding in item for item in binding_maps if isinstance(item, dict))


def widget_covers_host(widget: dict[str, Any], host: str) -> bool:
    # Turnstile widget domains cover the listed domain and all of its subdomains.
    if not host:
        return False
    for domain in widget.get("domains") or []:
        domain_text = str(domain)
        if host == domain_text or host.endswith("." + domain_text):
            return True
    return False


def find_turnstile_widget(spec: dict[str, Any], evidence: dict[str, Any]) -> dict[str, Any] | None:
    turnstile = spec.get("turnstile") or {}
    sitekey = str(turnstile.get("sitekey") or "")
    widget_name = str(turnstile.get("widget_name") or "")
    for widget in evidence.get("turnstile_widgets") or []:
        if sitekey and widget.get("sitekey") == sitekey:
            return widget
        if widget_name and widget.get("name") == widget_name:
            return widget
    return None


def access_apps_for_route(spec: dict[str, Any], evidence: dict[str, Any]) -> list[dict[str, Any]]:
    host = route_host(spec)
    domain_key = route_domain_key(spec)
    matches = []
    for app in evidence.get("access_apps") or []:
        app_domain = str(app.get("domain") or "")
        domains = [app_domain, *[str(item) for item in app.get("self_hosted_domains") or []]]
        if host in domains or domain_key in domains:
            matches.append(app)
    return matches


def access_decisions(app: dict[str, Any]) -> set[str]:
    decisions = set()
    for policy in app.get("policies") or []:
        decision = policy.get("decision")
        if decision:
            decisions.add(str(decision))
    for decision in app.get("policy_decisions") or []:
        decisions.add(str(decision))
    return decisions


def storage_exists(evidence: dict[str, Any], sink: dict[str, Any]) -> bool:
    sink_type = sink.get("type")
    name = str(sink.get("name") or "")
    if not name:
        return False
    if sink_type == "d1.database":
        return any(item.get("name") == name or item.get("uuid") == name for item in evidence.get("d1_databases") or [])
    if sink_type == "r2.bucket":
        return any(item.get("name") == name for item in evidence.get("r2_buckets") or [])
    if sink_type == "queue":
        return any(item.get("queue_name") == name or item.get("name") == name for item in evidence.get("queues") or [])
    return False


def cloudflare_checks(spec: dict[str, Any], evidence: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    drifts: list[dict[str, Any]] = []
    host = route_host(spec)
    turnstile = spec.get("turnstile") or {}
    turnstile_required = turnstile.get("required", True) is True
    widget = find_turnstile_widget(spec, evidence) if turnstile_required else None

    if turnstile_required:
        if not widget:
            drifts.append({"class": "turnstile_widget_drift", "message": "Turnstile widget/sitekey was not found"})
        elif host and not widget_covers_host(widget, host):
            drifts.append({"class": "turnstile_widget_drift", "message": "Turnstile widget domains do not cover route host", "host": host})
        for binding in (turnstile.get("sitekey_binding"), turnstile.get("secret_binding")):
            if binding and not binding_present(spec, evidence, str(binding)):
                drifts.append({"class": "secret_binding_missing", "binding": binding, "surface": "pages.secret" if owner_service(spec) == "pages" else "worker.secret"})

    resend = spec.get("resend") or {}
    if str(resend.get("mode") or "disabled").lower() == "enabled":
        binding = str(resend.get("api_key_binding") or "")
        if binding and not binding_present(spec, evidence, binding):
            drifts.append({"class": "secret_binding_missing", "binding": binding, "surface": "pages.secret" if owner_service(spec) == "pages" else "worker.secret"})

    access = spec.get("access") or {}
    expected = str(access.get("expected") or "public").lower()
    matched_access = access_apps_for_route(spec, evidence)
    if expected == "public":
        blocking = [
            app
            for app in matched_access
            if access_decisions(app) and not access_decisions(app).issubset({"bypass"})
        ]
        if blocking:
            drifts.append({
                "class": "access_blocks_public_intake",
                "apps": [app.get("name") or app.get("domain") for app in blocking],
            })

    sink_checks = []
    for sink in (spec.get("logging") or {}).get("sinks") or []:
        exists = storage_exists(evidence, sink)
        binding = str(sink.get("binding") or "")
        binding_ok = resource_binding_present(spec, evidence, sink)
        row = {**sink, "exists": exists, "binding_present": binding_ok}
        sink_checks.append(row)
        if not exists:
            drifts.append({"class": "storage_sink_missing", "sink": sink})
        if not binding_ok:
            drifts.append({"class": "storage_binding_missing", "binding": binding, "sink": sink})

    checks = {
        "turnstile": {
            "required": turnstile_required,
            "sitekey": turnstile.get("sitekey"),
            "widget_found": widget is not None,
            "domain_ready": (not turnstile_required) or bool(widget and widget_covers_host(widget, host)),
        },
        "access": {
            "expected": expected,
            "matched_app_count": len(matched_access),
            "public_unblocked": not any(item["class"] == "access_blocks_public_intake" for item in drifts),
        },
        "secrets": {
            "required": [item for item in [turnstile.get("sitekey_binding"), turnstile.get("secret_binding"), (spec.get("resend") or {}).get("api_key_binding")] if item],
        },
        "storage": sink_checks,
        "ready": not any(
            item["class"] in {
                "turnstile_widget_drift",
                "secret_binding_missing",
                "access_blocks_public_intake",
                "storage_sink_missing",
                "storage_binding_missing",
            }
            for item in drifts
        ),
    }
    return checks, drifts


def page_checks(spec: dict[str, Any], evidence: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    page = evidence.get("page") or {}
    html = str(page.get("html") or "")
    status = page.get("status")
    drifts: list[dict[str, Any]] = []
    if status != 200:
        drifts.append({"class": "page_fetch_failed", "status": status, "error": page.get("error")})
    if "<form" not in html.lower():
        drifts.append({"class": "page_form_missing"})
    field_rows = []
    for field in spec.get("fields") or []:
        name = str(field.get("name") or "")
        present = has_name_attr(html, name) if name else False
        field_rows.append({"name": name, "present": present})
        if not present:
            drifts.append({"class": "page_field_missing", "field": name})
    turnstile = spec.get("turnstile") or {}
    sitekey = str(turnstile.get("sitekey") or "")
    if turnstile.get("required", True) is True:
        turnstile_present = "cf-turnstile" in html or "challenges.cloudflare.com/turnstile" in html or (sitekey and sitekey in html)
        if not turnstile_present:
            drifts.append({"class": "page_turnstile_missing"})
    checks = {
        "status": status,
        "url": page.get("url") or route_url(spec),
        "form_present": "<form" in html.lower(),
        "fields": field_rows,
        "turnstile_present": not any(item["class"] == "page_turnstile_missing" for item in drifts),
        "ready": not any(item["class"].startswith("page_") for item in drifts),
    }
    return checks, drifts


def resend_checks(spec: dict[str, Any], evidence: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    resend = spec.get("resend") or {}
    mode = str(resend.get("mode") or "disabled").lower()
    drifts: list[dict[str, Any]] = []
    if mode in {"disabled", "receive_only", "receive-only"}:
        return {"mode": mode, "ready": True, "provider_readback_required": False}, []

    domain = str(resend.get("domain") or route_host(spec))
    provider_required = resend.get("provider_readback_required") is True
    domains = (evidence.get("resend") or {}).get("domains") or []
    match = None
    for item in domains:
        if item.get("name") == domain or item.get("domain") == domain:
            match = item
            break
    status = str((match or {}).get("status") or "").lower()
    ready = bool(match and status in {"verified", "active", "ready"})
    if provider_required and not ready:
        drifts.append({"class": "resend_domain_drift", "domain": domain, "status": status or None})
    return {
        "mode": mode,
        "domain": domain,
        "provider_readback_required": provider_required,
        "status": status or None,
        "ready": ready or not provider_required,
    }, drifts


def synthetic_checks(spec: dict[str, Any], evidence: dict[str, Any]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    synthetic = spec.get("synthetic_submit") or {}
    enabled = synthetic.get("enabled") is True
    if not enabled:
        return {"mode": "disabled", "enabled": False, "performed": False, "ready": True}, []
    proof = evidence.get("synthetic_submit") or {}
    performed = proof.get("performed") is True
    response_ok = proof.get("response_ok") is True
    readback_ok = proof.get("readback_ok") is True
    if performed and response_ok and readback_ok:
        return {"mode": "enabled", "enabled": True, "performed": True, "response_ok": True, "readback_ok": True, "ready": True}, []
    return (
        {"mode": "enabled", "enabled": True, "performed": performed, "response_ok": response_ok, "readback_ok": readback_ok, "ready": False},
        [{"class": "synthetic_submit_not_executed", "message": "synthetic submit is enabled but no successful bounded proof was supplied"}],
    )


def operation_for_drift(spec: dict[str, Any], drift: dict[str, Any]) -> dict[str, Any] | None:
    drift_class = drift.get("class")
    project = owner_project(spec)
    script = owner_script(spec)
    secret_surface = "pages.secret" if owner_service(spec) == "pages" else "worker.secret"
    turnstile = spec.get("turnstile") or {}
    if drift_class == "turnstile_widget_drift":
        sitekey = str(turnstile.get("sitekey") or "<sitekey>")
        return {
            "surface": "turnstile.widget",
            "operation": "update",
            "preview_command": f"cfctl apply turnstile.widget update --sitekey {sitekey} --body-file /secure/turnstile-widget.json --plan",
            "blocked": None,
        }
    if drift_class == "secret_binding_missing":
        binding = str(drift.get("binding") or "<secret>")
        if secret_surface == "pages.secret":
            return {
                "surface": "pages.secret",
                "operation": "upsert",
                "preview_command": f"cfctl apply pages.secret upsert --project {project or '<pages-project>'} --name {binding} --plan",
                "blocked": None,
            }
        return {
            "surface": "worker.secret",
            "operation": "upsert",
            "preview_command": f"cfctl apply worker.secret upsert --script {script or '<script>'} --name {binding} --plan",
            "blocked": None,
        }
    if drift_class == "access_blocks_public_intake":
        return {
            "surface": "access.app",
            "operation": "review",
            "preview_command": None,
            "blocked": ACCESS_BLOCKED,
        }
    if drift_class == "storage_sink_missing":
        sink = drift.get("sink") or {}
        surface = sink.get("type") or "storage"
        name = sink.get("name") or "<name>"
        command = None
        if surface == "d1.database":
            command = f"cfctl wrangler d1 create {name} --plan"
        elif surface == "r2.bucket":
            command = f"cfctl wrangler r2 bucket create {name} --plan"
        elif surface == "queue":
            command = f"cfctl wrangler queues create {name} --plan"
        return {"surface": surface, "operation": "create", "preview_command": command, "blocked": None}
    if drift_class == "storage_binding_missing":
        return {
            "surface": "pages.project" if owner_service(spec) == "pages" else "worker.script",
            "operation": "configure-binding",
            "preview_command": None,
            "blocked": "storage binding changes must land through the owning app deploy/config lane",
        }
    if drift_class == "resend_domain_drift":
        return {
            "surface": "sender_domain",
            "operation": "enable",
            "preview_command": f"CF_TOKEN_LANE=global cfctl apply sender_domain enable --zone {drift.get('domain') or route_host(spec)} --name {drift.get('domain') or route_host(spec)} --plan",
            "blocked": None,
        }
    if drift_class == "synthetic_submit_not_executed":
        return {
            "surface": "form.intake",
            "operation": "synthetic-submit",
            "preview_command": None,
            "blocked": "production synthetic submit requires an explicit spec and successful bounded proof evidence",
        }
    return None


def planned_operations(spec: dict[str, Any], drifts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    operations = []
    seen = set()
    for drift in drifts:
        operation = operation_for_drift(spec, drift)
        if not operation:
            continue
        key = json.dumps(operation, sort_keys=True)
        if key in seen:
            continue
        seen.add(key)
        operations.append(operation)
    return operations


def build_result(action: str, spec_path: Path | None, spec: dict[str, Any]) -> dict[str, Any]:
    validation_errors = validate_spec(spec)
    evidence = collect_evidence(spec) if action != "init" else {}
    source, source_drifts = source_checks(spec)
    cloudflare, cloudflare_drifts = cloudflare_checks(spec, evidence)
    page, page_drifts = page_checks(spec, evidence)
    resend, resend_drifts = resend_checks(spec, evidence)
    synthetic, synthetic_drifts = synthetic_checks(spec, evidence)
    drifts = [*validation_errors, *source_drifts, *cloudflare_drifts, *page_drifts, *resend_drifts, *synthetic_drifts]
    drift_classes = sorted({str(item.get("class")) for item in drifts if item.get("class")})
    operations = planned_operations(spec, drifts)
    readiness = {
        "source_ready": not validation_errors and source.get("ready") is True,
        "cloudflare_ready": cloudflare.get("ready") is True,
        "page_ready": page.get("ready") is True,
        "resend_ready": resend.get("ready") is True,
        "synthetic_ready": synthetic.get("ready") is True,
    }
    ready = all(readiness.values())
    result: dict[str, Any] = {
        "generated_at": now_iso(),
        "action": action,
        "surface": "form.intake",
        "spec_path": str(spec_path) if spec_path else None,
        "spec": spec,
        "validation_errors": validation_errors,
        "readiness": readiness,
        "ready": ready,
        "checks": {
            "source": source,
            "cloudflare": cloudflare,
            "page": page,
            "resend": resend,
            "synthetic_submit": synthetic,
        },
        "drifts": drifts,
        "drift_classes": drift_classes,
        "evidence": {
            "fixture": bool(os.environ.get("FORM_INTAKE_EVIDENCE_FILE")),
            "turnstile_widget_count": len(evidence.get("turnstile_widgets") or []),
            "access_app_count": len(evidence.get("access_apps") or []),
            "pages_project_count": len(evidence.get("pages_projects") or []),
            "page_status": (evidence.get("page") or {}).get("status"),
            "resend_domain_count": len((evidence.get("resend") or {}).get("domains") or []),
        },
        "plan": {
            "mutation_enabled": False,
            "plan_mode": action == "plan",
            "operation_id": operation_id() if action == "plan" else None,
            "operation_count": len(operations),
            "operations": operations,
            "blocked": None,
        },
    }
    if action == "diff":
        result["diff"] = {
            "drift_count": len(drifts),
            "drift_classes": drift_classes,
            "ready": readiness,
        }
    if action == "snapshot":
        result["snapshot"] = {
            "route": spec.get("route"),
            "owner": spec.get("owner"),
            "field_count": len(spec.get("fields") or []),
            "logging_sinks": (spec.get("logging") or {}).get("sinks") or [],
        }
    return result


def write_result(action: str, result: dict[str, Any]) -> Path:
    output_dir = ROOT / "var" / "inventory" / "runtime"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / (
        f"form-intake-{action}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}.json"
    )
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return output_path


def main() -> int:
    action = os.environ.get("FORM_INTAKE_ACTION", "verify")
    if action not in {"init", "verify", "snapshot", "diff", "plan"}:
        raise SystemExit(f"Unsupported form-intake action: {action}")

    if action == "init":
        url = os.environ.get("FORM_INTAKE_URL") or os.environ.get("CFCTL_URL") or "https://example.com/contact"
        result = {
            "generated_at": now_iso(),
            "action": action,
            "surface": "form.intake",
            "spec_path": None,
            "generated_spec": init_spec(url),
            "readiness": {
                "source_ready": False,
                "cloudflare_ready": False,
                "page_ready": False,
                "resend_ready": False,
                "synthetic_ready": True,
            },
            "ready": False,
            "drifts": [],
            "drift_classes": [],
            "plan": {
                "mutation_enabled": False,
                "plan_mode": False,
                "operation_id": None,
                "operation_count": 0,
                "operations": [],
                "blocked": None,
            },
        }
    else:
        spec_path = resolve_spec_path(os.environ.get("SPEC_FILE") or os.environ.get("CFCTL_FILE"))
        result = build_result(action, spec_path, load_spec(spec_path))

    output_path = write_result(action, result)
    print(f"Captured form-intake {action} evidence.")
    print(
        json.dumps(
            {
                "readiness": result.get("readiness"),
                "drift_count": len(result.get("drifts") or []),
                "operation_count": (result.get("plan") or {}).get("operation_count"),
            },
            indent=2,
            sort_keys=True,
        )
    )
    print(output_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

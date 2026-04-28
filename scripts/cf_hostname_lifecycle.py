#!/usr/bin/env python3

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import yaml


ROOT = Path(__file__).resolve().parents[1]


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def default_spec_file() -> Path:
    spec_dir = ROOT / "state" / "hostname"
    candidates = sorted([*spec_dir.glob("*.yaml"), *spec_dir.glob("*.yml")])
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise SystemExit("No hostname specs found under state/hostname")
    raise SystemExit("Multiple hostname specs found; pass --file <spec>")


def resolve_spec_path(value: str | None) -> Path:
    if value:
        path = Path(value)
        if not path.is_absolute():
            path = ROOT / path
        return path
    return default_spec_file()


def load_spec(path: Path) -> dict[str, Any]:
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        raise SystemExit(f"Hostname spec must be a mapping: {path}")
    if not data.get("zone"):
        raise SystemExit(f"Hostname spec is missing zone: {path}")
    if not isinstance(data.get("hosts"), list) or not data["hosts"]:
        raise SystemExit(f"Hostname spec is missing non-empty hosts: {path}")
    return data


def run_cfctl(args: list[str], lane: str | None = None) -> dict[str, Any]:
    env = os.environ.copy()
    if lane:
        env["CF_TOKEN_LANE"] = lane
    proc = subprocess.run(
        [str(ROOT / "cfctl"), *args],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    payload: dict[str, Any]
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = {
            "ok": False,
            "error": {
                "code": "invalid_cfctl_output",
                "message": proc.stderr.strip() or proc.stdout.strip(),
            },
            "result": None,
            "artifact_path": None,
        }
    payload["_command"] = " ".join(["cfctl", *args])
    payload["_returncode"] = proc.returncode
    return payload


def status(ok: bool, detail: str, actual: Any = None) -> dict[str, Any]:
    return {
        "ok": ok,
        "status": "ok" if ok else "drift",
        "detail": detail,
        "actual": actual,
    }


def wildcard_covers(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:])
    return pattern == host


def route_covers(pattern: str, host: str) -> bool:
    route_host = pattern.split("/", 1)[0]
    return wildcard_covers(route_host, host)


def probe_https(host: str, access_required: bool) -> dict[str, Any]:
    request = Request(f"https://{host}/", headers={"User-Agent": "cfctl-hostname-verify/1"})
    try:
        with urlopen(request, timeout=12, context=ssl.create_default_context()) as response:
            code = response.getcode()
            headers = safe_headers(response.headers.items())
    except HTTPError as error:
        code = error.code
        headers = safe_headers(error.headers.items())
    except ssl.SSLError as error:
        return status(False, "tls_probe_failed", {"error": str(error)})
    except socket.gaierror as error:
        return status(False, "dns_resolution_failed", {"error": str(error)})
    except URLError as error:
        return status(False, "http_probe_failed", {"error": str(error.reason)})
    except Exception as error:  # pragma: no cover - defensive operator detail
        return status(False, "http_probe_failed", {"error": str(error)})

    if access_required and code in {302, 401, 403}:
        return status(True, "access_challenge_or_redirect_observed", {"status_code": code, "headers": headers})
    return status(code < 500, "http_response_observed", {"status_code": code, "headers": headers})


def safe_headers(header_items: Any) -> dict[str, str]:
    sensitive = {"set-cookie", "cookie", "authorization", "cf-authorization"}
    headers: dict[str, str] = {}
    for key, value in header_items:
        lower = str(key).lower()
        headers[lower] = "<redacted>" if lower in sensitive else str(value)
    return headers


def names(items: list[dict[str, Any]], key: str) -> set[str]:
    return {str(item.get(key)) for item in items if item.get(key) is not None}


def build_checks(spec: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    zone = str(spec["zone"])
    hosts = [str(host) for host in spec["hosts"]]
    dns_spec = spec.get("dns") or {}
    worker_spec = spec.get("worker") or {}
    access_spec = spec.get("access") or {}
    cert_spec = spec.get("certificate") or {}
    storage_spec = spec.get("storage") or {}

    evidence: dict[str, Any] = {}
    evidence["dns"] = run_cfctl(["list", "dns.record", "--zone", zone], lane="global")
    evidence["worker_route"] = run_cfctl(["list", "worker.route", "--zone", zone], lane="global")
    evidence["access"] = run_cfctl(["list", "access.app"])
    evidence["worker"] = run_cfctl(["list", "worker.script"])
    evidence["d1"] = run_cfctl(["list", "d1.database"])
    evidence["r2"] = run_cfctl(["list", "r2.bucket"])
    if cert_spec.get("advanced"):
        evidence["certificate"] = run_cfctl(["list", "edge.certificate", "--zone", zone], lane="global")
    else:
        evidence["certificate"] = {"ok": True, "result": [], "artifact_path": None}

    dns_records = evidence["dns"].get("result") or []
    routes = evidence["worker_route"].get("result") or []
    access_apps = evidence["access"].get("result") or []
    workers = evidence["worker"].get("result") or []
    certificates = evidence["certificate"].get("result") or []
    d1_names = names(evidence["d1"].get("result") or [], "name")
    r2_names = names(evidence["r2"].get("result") or [], "name")

    expected_route = worker_spec.get("route")
    expected_service = worker_spec.get("service")
    expected_audience = access_spec.get("audience")
    access_required = access_spec.get("required") is True
    proxied_required = dns_spec.get("proxied_placeholder") is True

    route_matches = [
        route
        for route in routes
        if (not expected_route or route.get("pattern") == expected_route)
        and (not expected_service or (route.get("script") or route.get("service")) == expected_service)
    ]
    worker_scripts = names(workers, "id")

    checks: dict[str, Any] = {
        "zone": zone,
        "hosts": {},
        "storage": {
            "d1": status(not storage_spec.get("d1") or storage_spec["d1"] in d1_names, "d1_database_present" if storage_spec.get("d1") in d1_names else "d1_database_missing", storage_spec.get("d1")),
            "r2": status(not storage_spec.get("r2") or storage_spec["r2"] in r2_names, "r2_bucket_present" if storage_spec.get("r2") in r2_names else "r2_bucket_missing", storage_spec.get("r2")),
        },
        "worker": {
            "script": status(not expected_service or expected_service in worker_scripts, "worker_script_present" if expected_service in worker_scripts else "worker_script_missing", expected_service),
            "route": status(bool(route_matches), "worker_route_present" if route_matches else "worker_route_missing", route_matches),
        },
        "access_template": {
            "name": expected_audience,
            "ok": expected_audience in {None, "", "drive-approved", "docs-approved"},
            "status": "ok" if expected_audience in {None, "", "drive-approved", "docs-approved"} else "drift",
            "detail": "named_template_known" if expected_audience else "not_required",
        },
    }

    for host in hosts:
        host_records = [record for record in dns_records if record.get("name") == host]
        proxied_records = [record for record in host_records if record.get("proxied") is True]
        access_matches = []
        for app in access_apps:
            candidates = [str(app.get("domain") or "")]
            candidates.extend(str(item) for item in app.get("self_hosted_domains") or [])
            candidates.extend(str(item.get("uri") or "") for item in app.get("destinations") or [])
            if any(wildcard_covers(candidate, host) for candidate in candidates):
                access_matches.append(app)
        certificate_matches = [
            pack
            for pack in certificates
            if pack.get("status") == "active"
            and any(wildcard_covers(str(cert_host), host) for cert_host in pack.get("hosts") or [])
        ]
        route_host_matches = [route for route in routes if route_covers(str(route.get("pattern") or ""), host)]

        checks["hosts"][host] = {
            "dns": status(bool(proxied_records) if proxied_required else bool(host_records), "proxied_dns_record_present" if proxied_records else "dns_record_missing_or_unproxied", host_records),
            "tls": status(bool(certificate_matches) if cert_spec.get("advanced") else True, "active_certificate_present" if certificate_matches else "active_certificate_missing", certificate_matches),
            "route": status(bool(route_host_matches), "worker_route_covers_host" if route_host_matches else "worker_route_missing_for_host", route_host_matches),
            "access": status((not access_required) or bool(access_matches), "access_app_covers_host" if access_matches else "access_app_missing_for_host", access_matches),
            "app_response": probe_https(host, access_required),
        }

    return checks, evidence


def planned_operations(spec: dict[str, Any], checks: dict[str, Any]) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    zone = spec["zone"]
    worker = spec.get("worker") or {}
    access = spec.get("access") or {}
    certificate = spec.get("certificate") or {}
    storage = spec.get("storage") or {}

    if not checks["access_template"]["ok"]:
        operations.append({
            "surface": "access.template",
            "operation": "define",
            "template": access.get("audience"),
            "reason": checks["access_template"]["detail"],
            "blocked": "access templates are named patterns and must be defined before composite apply",
        })

    for host, host_checks in checks["hosts"].items():
        if not host_checks["dns"]["ok"]:
            operations.append({"surface": "dns.record", "operation": "upsert", "zone": zone, "host": host, "reason": host_checks["dns"]["detail"]})
        if not host_checks["tls"]["ok"] and certificate.get("advanced"):
            operations.append({"surface": "edge.certificate", "operation": "order", "zone": zone, "host": host, "reason": host_checks["tls"]["detail"]})
        if not host_checks["access"]["ok"] and access.get("required"):
            operations.append({"surface": "access.app", "operation": "create", "host": host, "template": access.get("audience"), "reason": host_checks["access"]["detail"]})
    if not checks["worker"]["route"]["ok"]:
        operations.append({"surface": "worker.route", "operation": "upsert", "zone": zone, "pattern": worker.get("route"), "service": worker.get("service"), "blocked": "worker.route apply is not implemented"})
    if not checks["worker"]["script"]["ok"]:
        operations.append({"surface": "worker.script", "operation": "deploy", "service": worker.get("service"), "blocked": "service implementation lives in its app repo"})
    if not checks["storage"]["d1"]["ok"]:
        operations.append({"surface": "d1.database", "operation": "create", "name": storage.get("d1"), "blocked": "d1.database apply is not implemented"})
    if not checks["storage"]["r2"]["ok"]:
        operations.append({"surface": "r2.bucket", "operation": "create", "name": storage.get("r2"), "blocked": "r2.bucket apply is not implemented"})
    return operations


def main() -> int:
    action = os.environ.get("HOSTNAME_ACTION", "verify")
    spec_path = resolve_spec_path(os.environ.get("SPEC_FILE") or os.environ.get("CFCTL_FILE"))
    spec = load_spec(spec_path)
    checks, evidence = build_checks(spec)
    operations = planned_operations(spec, checks)
    ready = not operations and all(
        host_check["app_response"]["ok"]
        for host_check in checks["hosts"].values()
    )

    result = {
        "generated_at": now_iso(),
        "action": action,
        "surface": "hostname",
        "spec_path": str(spec_path),
        "spec": spec,
        "ready": ready,
        "checks": checks,
        "evidence": {
            key: {
                "ok": value.get("ok"),
                "artifact_path": value.get("artifact_path"),
                "backend_artifact_path": value.get("backend_artifact_path"),
                "command": value.get("_command"),
                "error": value.get("error"),
            }
            for key, value in evidence.items()
        },
        "plan": {
            "mutation_enabled": False,
            "operation_count": len(operations),
            "operations": operations,
        },
    }

    if action == "apply":
        result["ready"] = False
        result["plan"]["blocked"] = "hostname composite apply is intentionally read-only in this tranche"

    output_dir = ROOT / "var" / "inventory" / "runtime"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / f"hostname-{action}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}.json"
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")

    print(f"Captured hostname {action} evidence for {spec_path.name}.")
    print(json.dumps({"ready": ready, "operation_count": len(operations)}, indent=2))
    print(output_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())

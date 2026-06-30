#!/usr/bin/env python3

from __future__ import annotations

import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
BLOCKED_PROVISION = (
    "maildesk-cf composite provision apply is blocked until every component "
    "write path is preview-gated through public cfctl surfaces"
)


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def operation_id() -> str:
    return os.environ.get("CFCTL_OPERATION_ID") or (
        f"{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}"
    )


def default_spec_file() -> Path:
    spec_dir = ROOT / "state" / "maildesk-cf"
    candidates = sorted(spec_dir.glob("*.json"))
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise SystemExit("No maildesk-cf specs found under state/maildesk-cf")
    raise SystemExit("Multiple maildesk-cf specs found; pass --file <spec>")


def resolve_spec_path(value: str | None) -> Path:
    if value:
        path = Path(value)
        if not path.is_absolute():
            path = ROOT / path
        return path
    return default_spec_file()


def load_spec(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text())
    if not isinstance(data, dict):
        raise SystemExit(f"maildesk-cf spec must be a JSON object: {path}")
    return data


def init_spec(domain: str) -> dict[str, Any]:
    return {
        "project": {
            "name": "maildesk-cf",
            "account_id_env": "CLOUDFLARE_ACCOUNT_ID",
        },
        "domains": [
            {
                "name": domain,
                "inbound_mx_provider": "cloudflare_email_routing",
                "role_aliases": [
                    "abuse",
                    "dmarc",
                    "founders",
                    "info",
                    "legal",
                    "noreply",
                    "postmaster",
                    "security",
                ],
                "personal_aliases": ["operator-a", "operator-b"],
            }
        ],
        "workers": {
            "mail_api": {"script_name": "maildesk-cf", "config": "wrangler.toml"},
            "mail_router": {
                "script_name": "maildesk-cf-router",
                "config": "wrangler.mail-router.toml",
            },
        },
        "storage": {
            "d1_database": "maildesk-cf-db",
            "d1_preview_database": "maildesk-cf-preview-db",
            "r2_raw_mail_bucket": "maildesk-cf-raw-mail",
            "r2_raw_mail_preview_bucket": "maildesk-cf-raw-mail-preview",
            "queue": "maildesk-cf-jobs",
        },
        "sender": {
            "mode": "cloudflare_first",
            "authenticated_domains": [domain],
        },
        "verification": {
            "allow_broad_live_sends": False,
            "targeted_send_required": False,
        },
    }


def domains_from_spec(spec: dict[str, Any], domain_filter: str | None) -> list[dict[str, Any]]:
    domains = spec.get("domains") or []
    if not isinstance(domains, list):
        raise SystemExit("maildesk-cf spec field domains must be a list")
    filtered = [domain for domain in domains if isinstance(domain, dict)]
    if domain_filter:
        filtered = [domain for domain in filtered if str(domain.get("name") or "") == domain_filter]
        if not filtered:
            raise SystemExit(f"Domain {domain_filter} is not present in the maildesk-cf spec")
    if not filtered:
        raise SystemExit("maildesk-cf spec has no domains to verify")
    return filtered


def worker_script(spec: dict[str, Any], key: str) -> str:
    value = (spec.get("workers") or {}).get(key) or {}
    if isinstance(value, dict):
        return str(value.get("script_name") or "")
    return str(value or "")


def worker_config(spec: dict[str, Any], key: str) -> str:
    value = (spec.get("workers") or {}).get(key) or {}
    if isinstance(value, dict):
        return str(value.get("config") or "<config>")
    return "<config>"


def expected_workers(spec: dict[str, Any]) -> dict[str, str]:
    workers = {
        "mail_api": worker_script(spec, "mail_api"),
        "mail_router": worker_script(spec, "mail_router"),
    }
    return {key: value for key, value in workers.items() if value}


def expected_storage(spec: dict[str, Any]) -> dict[str, str]:
    storage = spec.get("storage") or {}
    keys = [
        "d1_database",
        "d1_preview_database",
        "r2_raw_mail_bucket",
        "r2_raw_mail_preview_bucket",
        "queue",
    ]
    return {key: str(storage.get(key) or "") for key in keys if storage.get(key)}


def storage_preview_command(key: str, name: str) -> str | None:
    quoted_name = shlex.quote(name)
    if key in {"d1_database", "d1_preview_database"}:
        return f"cfctl wrangler d1 create {quoted_name} --plan"
    if key in {"r2_raw_mail_bucket", "r2_raw_mail_preview_bucket"}:
        return f"cfctl wrangler r2 bucket create {quoted_name} --plan"
    if key == "queue":
        return f"cfctl wrangler queues create {quoted_name} --plan"
    return None


def normalize_alias(alias: Any, domain: str) -> str:
    value = str(alias or "").strip().lower()
    if not value:
        return ""
    if "@" in value:
        return value
    return f"{value}@{domain}".lower()


def expected_aliases(domain_spec: dict[str, Any]) -> list[str]:
    domain = str(domain_spec.get("name") or "").lower()
    aliases: list[str] = []
    for key in ("role_aliases", "personal_aliases", "aliases"):
        for alias in domain_spec.get(key) or []:
            normalized = normalize_alias(alias, domain)
            if normalized and normalized not in aliases:
                aliases.append(normalized)
    return sorted(aliases)


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
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        payload = {
            "ok": False,
            "result": [],
            "artifact_path": None,
            "error": {
                "code": "invalid_cfctl_output",
                "message": proc.stderr.strip() or proc.stdout.strip(),
            },
        }
    payload["_command"] = " ".join(["cfctl", *args])
    payload["_returncode"] = proc.returncode
    return payload


def payload(items: Any, source: str = "fixture", ok: bool = True) -> dict[str, Any]:
    return {
        "ok": ok,
        "result": items if isinstance(items, list) else [],
        "artifact_path": None,
        "_source": source,
    }


def load_fixture_evidence(path: Path, domains: list[dict[str, Any]]) -> dict[str, Any]:
    raw = json.loads(path.read_text())
    domain_map = raw.get("domains") or {}
    evidence = {
        "worker.script": payload(raw.get("workers") or raw.get("worker.script") or []),
        "d1.database": payload(raw.get("d1") or raw.get("d1.database") or []),
        "r2.bucket": payload(raw.get("r2") or raw.get("r2.bucket") or []),
        "queue": payload(raw.get("queues") or raw.get("queue") or []),
        "domains": {},
        "sender": raw.get("sender") or {},
        "fixture_path": str(path),
    }
    for domain_spec in domains:
        domain = str(domain_spec.get("name") or "")
        domain_evidence = domain_map.get(domain) or {}
        evidence["domains"][domain] = {
            "email.routing_rule": payload(
                domain_evidence.get("email_routing_rules")
                or domain_evidence.get("email.routing_rule")
                or domain_evidence.get("rules")
                or []
            ),
            "email.routing": domain_evidence.get("email_routing")
            or domain_evidence.get("routing")
            or {"enabled": bool(domain_evidence.get("email_routing_enabled", True))},
            "dns.record": payload(
                domain_evidence.get("dns_records")
                or domain_evidence.get("dns.record")
                or []
            ),
        }
    return evidence


def collect_live_evidence(domains: list[dict[str, Any]]) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "worker.script": run_cfctl(["list", "worker.script"]),
        "d1.database": run_cfctl(["list", "d1.database"]),
        "r2.bucket": run_cfctl(["list", "r2.bucket"]),
        "queue": run_cfctl(["list", "queue"]),
        "domains": {},
        "sender": {"provider_readback": "not_available"},
    }
    for domain_spec in domains:
        domain = str(domain_spec.get("name") or "")
        evidence["domains"][domain] = {
            "email.routing_rule": run_cfctl(["list", "email.routing_rule", "--zone", domain], lane="global"),
            "email.routing": {},
            "dns.record": run_cfctl(["list", "dns.record", "--zone", domain], lane="global"),
        }
    return evidence


def collect_evidence(spec: dict[str, Any], domains: list[dict[str, Any]]) -> dict[str, Any]:
    fixture_path = os.environ.get("MAILDESK_CF_EVIDENCE_FILE")
    if fixture_path:
        return load_fixture_evidence(Path(fixture_path), domains)
    return collect_live_evidence(domains)


def items(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if not isinstance(value, dict):
        return []
    for key in ("result", "workers", "databases", "buckets", "queues", "rules", "records"):
        candidate = value.get(key)
        if isinstance(candidate, list):
            return [item for item in candidate if isinstance(item, dict)]
    return []


def item_names(values: list[dict[str, Any]], *fields: str) -> set[str]:
    names: set[str] = set()
    for item in values:
        for field in fields:
            value = item.get(field)
            if value is not None:
                names.add(str(value))
    return names


def status(ok: bool, detail: str, actual: Any = None) -> dict[str, Any]:
    return {
        "ok": ok,
        "status": "ok" if ok else "drift",
        "detail": detail,
        "actual": actual,
    }


def drift(
    drift_class: str,
    severity: str,
    resource: str,
    detail: str,
    expected: Any = None,
    actual: Any = None,
    command: str | None = None,
) -> dict[str, Any]:
    result = {
        "class": drift_class,
        "severity": severity,
        "resource": resource,
        "detail": detail,
        "expected": expected,
        "actual": actual,
    }
    if command:
        result["component_plan_command"] = command
    return result


def rule_recipient(rule: dict[str, Any]) -> str:
    for matcher in rule.get("matchers") or []:
        if isinstance(matcher, dict) and matcher.get("field") == "to":
            return str(matcher.get("value") or "").lower()
    return str(rule.get("recipient") or rule.get("name") or rule.get("email") or "").lower()


def collect_strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        result: list[str] = []
        for item in value:
            result.extend(collect_strings(item))
        return result
    if isinstance(value, dict):
        result = []
        for nested in value.values():
            result.extend(collect_strings(nested))
        return result
    return []


def rule_targets_worker(rule: dict[str, Any], worker: str) -> bool:
    if not worker:
        return False
    direct = [
        str(rule.get("service") or ""),
        str(rule.get("worker") or ""),
        str(rule.get("worker_name") or ""),
    ]
    direct.extend(collect_strings(rule.get("actions") or []))
    return any(worker in value for value in direct)


def dns_text(record: dict[str, Any]) -> str:
    content = record.get("content")
    if not content and isinstance(record.get("data"), dict):
        content = record["data"].get("content") or record["data"].get("value")
    return str(content or "")


def dns_name(record: dict[str, Any]) -> str:
    return str(record.get("name") or "").lower().rstrip(".")


def has_txt(records: list[dict[str, Any]], name: str, contains: str) -> bool:
    expected = name.lower().rstrip(".")
    return any(
        str(record.get("type") or "").upper() == "TXT"
        and dns_name(record) == expected
        and contains.lower() in dns_text(record).lower()
        for record in records
    )


def has_dkim_hint(records: list[dict[str, Any]], domain: str) -> bool:
    suffix = f"._domainkey.{domain}".lower()
    return any(suffix in dns_name(record) for record in records)


def worker_binding_checked(worker: dict[str, Any]) -> bool:
    return any(key in worker for key in ("bindings", "settings", "config", "metadata"))


def worker_binding_has(worker: dict[str, Any], expected: str) -> bool:
    if not expected:
        return True
    return any(expected in value for value in collect_strings(worker))


def validate_spec(spec: dict[str, Any], domains: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    if not (spec.get("project") or {}).get("name"):
        errors.append("project.name is required")
    if not expected_workers(spec):
        errors.append("workers.mail_api or workers.mail_router script_name is required")
    if not expected_storage(spec):
        errors.append("storage resources are required")
    for domain in domains:
        if not domain.get("name"):
            errors.append("each domain entry requires name")
        if not expected_aliases(domain):
            errors.append(f"domain {domain.get('name') or '<unknown>'} has no aliases")
    return errors


def routing_enabled(routing: Any) -> bool:
    if not isinstance(routing, dict):
        return False
    if "enabled" in routing:
        return bool(routing.get("enabled"))
    result = routing.get("result") if isinstance(routing.get("result"), dict) else {}
    return bool(result.get("enabled") or result.get("status") == "enabled")


def sender_domain_status(sender: dict[str, Any], domain: str) -> dict[str, Any] | None:
    domains = sender.get("domains") or sender.get("authenticated_domains") or {}
    if isinstance(domains, dict):
        value = domains.get(domain)
        return value if isinstance(value, dict) else None
    if isinstance(domains, list):
        for item in domains:
            if isinstance(item, dict) and str(item.get("domain") or item.get("name") or "") == domain:
                return item
    return None


def normalize_sender_mode(mode: str) -> str:
    normalized = (mode or "disabled").lower()
    if normalized in {"cloudflare_first", "cloudflare", "cloudflare_email_service"}:
        return "cloudflare_email_service"
    if normalized in {"resend", "disabled", "receive_only"}:
        return normalized
    return normalized


def build_checks(
    spec: dict[str, Any],
    domains: list[dict[str, Any]],
    evidence: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    drifts: list[dict[str, Any]] = []
    workers = expected_workers(spec)
    storage = expected_storage(spec)
    mail_router = workers.get("mail_router", "")

    worker_items = items(evidence.get("worker.script"))
    d1_items = items(evidence.get("d1.database"))
    r2_items = items(evidence.get("r2.bucket"))
    queue_items = items(evidence.get("queue"))
    worker_names = item_names(worker_items, "id", "name")
    d1_names = item_names(d1_items, "name")
    r2_names = item_names(r2_items, "name")
    queue_names = item_names(queue_items, "queue_name", "name")

    checks: dict[str, Any] = {
        "workers": {},
        "storage": {},
        "domains": {},
        "sender": {},
    }

    for role, script_name in workers.items():
        ok = script_name in worker_names
        checks["workers"][role] = status(
            ok,
            "worker_script_present" if ok else "worker_script_missing",
            script_name,
        )
        if not ok:
            drifts.append(
                drift(
                    "missing_resource",
                    "error",
                    f"worker.script:{script_name}",
                    "Worker script is missing",
                    script_name,
                    sorted(worker_names),
                    f"cfctl wrangler deploy --config {worker_config(spec, role)} --plan",
                )
            )

    mail_api_worker = next(
        (
            item
            for item in worker_items
            if str(item.get("id") or item.get("name") or "") == workers.get("mail_api")
        ),
        None,
    )
    if mail_api_worker and worker_binding_checked(mail_api_worker):
        for key, expected in storage.items():
            if not worker_binding_has(mail_api_worker, expected):
                drifts.append(
                    drift(
                        "wrong_binding",
                        "error",
                        f"worker.script:{workers.get('mail_api')}:{key}",
                        "Worker binding evidence does not include expected storage resource",
                        expected,
                        collect_strings(mail_api_worker),
                    )
                )

    storage_sets = {
        "d1_database": d1_names,
        "d1_preview_database": d1_names,
        "r2_raw_mail_bucket": r2_names,
        "r2_raw_mail_preview_bucket": r2_names,
        "queue": queue_names,
    }
    storage_surfaces = {
        "d1_database": "d1.database",
        "d1_preview_database": "d1.database",
        "r2_raw_mail_bucket": "r2.bucket",
        "r2_raw_mail_preview_bucket": "r2.bucket",
        "queue": "queue",
    }
    for key, expected in storage.items():
        present_names = storage_sets.get(key, set())
        ok = expected in present_names
        checks["storage"][key] = status(
            ok,
            "storage_resource_present" if ok else "storage_resource_missing",
            expected,
        )
        if not ok:
            drifts.append(
                drift(
                    "missing_resource",
                    "error",
                    f"{storage_surfaces.get(key)}:{expected}",
                    "Storage resource is missing",
                    expected,
                    sorted(present_names),
                    storage_preview_command(key, expected),
                )
            )

    for domain_spec in domains:
        domain = str(domain_spec.get("name") or "")
        domain_evidence = (evidence.get("domains") or {}).get(domain) or {}
        rule_payload = domain_evidence.get("email.routing_rule") or {}
        routing_meta = domain_evidence.get("email.routing") or {}
        rules_readable = isinstance(rule_payload, dict) and rule_payload.get("ok") is True
        routing_ok = routing_enabled(routing_meta) if routing_meta else rules_readable
        routing_detail = (
            "email_routing_enabled"
            if routing_enabled(routing_meta)
            else "email_routing_rules_readable"
            if routing_ok
            else "email_routing_not_enabled_or_unreadable"
        )
        rule_items = items(domain_evidence.get("email.routing_rule"))
        dns_items = items(domain_evidence.get("dns.record"))
        aliases = expected_aliases(domain_spec)
        domain_checks = {
            "email_routing": status(
                routing_ok,
                routing_detail,
            ),
            "aliases": {},
            "dns_authentication": {},
        }
        if not domain_checks["email_routing"]["ok"]:
            drifts.append(
                drift(
                    "missing_resource",
                    "error",
                    f"email.routing:{domain}",
                    "Cloudflare Email Routing is not enabled or was not readable",
                    "enabled",
                    domain_evidence.get("email.routing"),
                )
            )
        for alias in aliases:
            matches = [rule for rule in rule_items if rule_recipient(rule) == alias]
            worker_matches = [rule for rule in matches if rule_targets_worker(rule, mail_router)]
            ok = bool(worker_matches)
            domain_checks["aliases"][alias] = status(
                ok,
                "email_routing_alias_present" if ok else "email_routing_alias_missing_or_wrong_worker",
                matches,
            )
            if not ok:
                drifts.append(
                    drift(
                        "email_routing_alias_drift",
                        "error",
                        f"email.routing_rule:{alias}",
                        "Alias is missing or does not route to the configured mail router Worker",
                        {"recipient": alias, "worker": mail_router},
                        matches,
                        f"cfctl apply email.routing_rule upsert --zone {domain} --name {alias} --service {mail_router} --plan",
                    )
                )
        domain_checks["dns_authentication"]["spf"] = status(
            has_txt(dns_items, domain, "v=spf1"),
            "spf_txt_present" if has_txt(dns_items, domain, "v=spf1") else "spf_txt_missing",
        )
        domain_checks["dns_authentication"]["dmarc"] = status(
            has_txt(dns_items, f"_dmarc.{domain}", "v=DMARC1"),
            "dmarc_txt_present"
            if has_txt(dns_items, f"_dmarc.{domain}", "v=DMARC1")
            else "dmarc_txt_missing",
        )
        domain_checks["dns_authentication"]["dkim_hint"] = status(
            has_dkim_hint(dns_items, domain),
            "dkim_dns_hint_present" if has_dkim_hint(dns_items, domain) else "dkim_dns_hint_missing",
        )
        checks["domains"][domain] = domain_checks

    append_sender_checks(spec, domains, evidence, checks, drifts)
    return checks, drifts


def append_sender_checks(
    spec: dict[str, Any],
    domains: list[dict[str, Any]],
    evidence: dict[str, Any],
    checks: dict[str, Any],
    drifts: list[dict[str, Any]],
) -> None:
    sender_spec = spec.get("sender") or {}
    sender_evidence = evidence.get("sender") or {}
    mode = normalize_sender_mode(str(sender_spec.get("mode") or "disabled"))
    authenticated = sender_spec.get("authenticated_domains") or [
        str(domain.get("name") or "") for domain in domains
    ]
    checks["sender"]["mode"] = {
        "expected": sender_spec.get("mode"),
        "normalized": mode,
    }
    if mode not in {"cloudflare_email_service", "resend", "disabled", "receive_only"}:
        drifts.append(
            drift(
                "policy_config_drift",
                "error",
                "sender.mode",
                "Unsupported sender mode",
                ["cloudflare_email_service", "resend", "disabled"],
                sender_spec.get("mode"),
            )
        )
        return
    if mode in {"disabled", "receive_only"}:
        drifts.append(
            drift(
                "sender_adapter_receive_only",
                "error",
                "sender.mode",
                "Sender adapter is configured without outbound sending",
                "outbound sender provider",
                sender_spec.get("mode"),
            )
        )
        checks["sender"]["ready"] = False
        return

    for domain in [str(value) for value in authenticated if value]:
        domain_evidence = (evidence.get("domains") or {}).get(domain) or {}
        dns_items = items(domain_evidence.get("dns.record"))
        spf_ok = has_txt(dns_items, domain, "v=spf1")
        dmarc_ok = has_txt(dns_items, f"_dmarc.{domain}", "v=DMARC1")
        domain_status = sender_domain_status(sender_evidence, domain)
        provider_status = domain_status or {}
        provider_verified = bool(
            provider_status.get("verified")
            or str(provider_status.get("status") or "").lower() in {"verified", "active", "ready"}
        )
        domain_check = {
            "provider": mode,
            "provider_readback": provider_status if domain_status else None,
            "spf_dns": spf_ok,
            "dmarc_dns": dmarc_ok,
            "provider_verified": provider_verified,
        }
        checks["sender"][domain] = domain_check
        if not spf_ok:
            drifts.append(
                drift(
                    "dns_authentication_drift",
                    "error",
                    f"dns.record:{domain}:SPF",
                    "SPF TXT record is missing for sender authentication",
                    "TXT v=spf1",
                    [dns_name(record) for record in dns_items],
                )
            )
        if not dmarc_ok:
            drifts.append(
                drift(
                    "dns_authentication_drift",
                    "error",
                    f"dns.record:_dmarc.{domain}",
                    "DMARC TXT record is missing for sender authentication",
                    "TXT v=DMARC1",
                    [dns_name(record) for record in dns_items],
                )
            )
        if domain_status is None:
            drifts.append(
                drift(
                    "provider_status_unavailable",
                    "error",
                    f"sender_domain:{domain}",
                    "Sender-provider domain status readback is not available",
                    {"provider": mode, "domain": domain},
                    None,
                )
            )
        elif not provider_verified:
            drifts.append(
                drift(
                    "sender_domain_drift",
                    "error",
                    f"sender_domain:{domain}",
                    "Sender-provider domain is not verified",
                    "verified",
                    provider_status,
                )
            )

    verification_spec = spec.get("verification") or {}
    if verification_spec.get("targeted_send_required"):
        drifts.append(
            drift(
                "optional_live_send_not_requested",
                "warning",
                "verification.targeted_send",
                "Targeted live send proof is required by spec but was not requested",
                "targeted send receipt",
                "not_requested",
            )
        )
    else:
        drifts.append(
            drift(
                "optional_live_send_not_requested",
                "info",
                "verification.live_send",
                "Broad live-send proof was not requested and was not attempted",
                "no broad live send",
                "not_requested",
            )
        )


def evidence_summary(evidence: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for key in ("worker.script", "d1.database", "r2.bucket", "queue"):
        value = evidence.get(key) or {}
        summary[key] = {
            "ok": value.get("ok"),
            "artifact_path": value.get("artifact_path") or value.get("backend_artifact_path"),
            "command": value.get("_command"),
            "error": value.get("error"),
            "source": value.get("_source"),
        }
    summary["domains"] = {}
    for domain, domain_evidence in (evidence.get("domains") or {}).items():
        summary["domains"][domain] = {}
        for key in ("email.routing_rule", "dns.record"):
            value = domain_evidence.get(key) or {}
            summary["domains"][domain][key] = {
                "ok": value.get("ok"),
                "artifact_path": value.get("artifact_path") or value.get("backend_artifact_path"),
                "command": value.get("_command"),
                "error": value.get("error"),
                "source": value.get("_source"),
            }
        summary["domains"][domain]["email.routing"] = domain_evidence.get("email.routing")
    if evidence.get("fixture_path"):
        summary["fixture_path"] = evidence["fixture_path"]
    summary["sender"] = evidence.get("sender") or {}
    return summary


def planned_operations(drifts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    for item in drifts:
        drift_class = item["class"]
        if drift_class == "optional_live_send_not_requested" and item["severity"] == "info":
            continue
        operation = {
            "surface": item["resource"].split(":", 1)[0],
            "drift_class": drift_class,
            "reason": item["detail"],
            "blocked": None,
        }
        if item.get("component_plan_command"):
            operation["preview_command"] = item["component_plan_command"]
        elif drift_class == "missing_resource":
            operation["blocked"] = "resource creation must use the owning primitive cfctl surface or app deploy lane"
        elif drift_class == "wrong_binding":
            operation["blocked"] = "Worker bindings are owned by the app repo config and deploy lane"
        elif drift_class in {"dns_authentication_drift", "sender_domain_drift", "provider_status_unavailable"}:
            operation["blocked"] = "sender-domain authentication/provider readback is not yet a cfctl mutation surface"
        elif drift_class == "policy_config_drift":
            operation["blocked"] = "policy config is owned by the app repo"
        else:
            operation["blocked"] = "manual review required"
        operations.append(operation)
    return operations


def readiness(validation_errors: list[str], drifts: list[dict[str, Any]]) -> dict[str, bool]:
    drift_classes = {item["class"] for item in drifts if item.get("severity") != "info"}
    edge_blockers = {
        "missing_resource",
        "wrong_binding",
        "email_routing_alias_drift",
        "policy_config_drift",
    }
    mail_blockers = edge_blockers | {
        "dns_authentication_drift",
        "sender_domain_drift",
        "provider_status_unavailable",
        "sender_adapter_receive_only",
        "optional_live_send_not_requested",
    }
    template_ready = not validation_errors
    instance_ready = template_ready and "policy_config_drift" not in drift_classes
    edge_ready = instance_ready and not bool(edge_blockers & drift_classes)
    mail_ready = edge_ready and not bool(mail_blockers & drift_classes)
    return {
        "template_ready": template_ready,
        "instance_ready": instance_ready,
        "edge_ready": edge_ready,
        "mail_ready": mail_ready,
    }


def build_result(action: str, spec_path: Path | None, spec: dict[str, Any]) -> dict[str, Any]:
    domain_filter = os.environ.get("MAILDESK_CF_DOMAIN") or os.environ.get("CFCTL_DOMAIN") or None
    domains = domains_from_spec(spec, domain_filter)
    validation_errors = validate_spec(spec, domains)
    evidence = collect_evidence(spec, domains)
    checks, drifts = build_checks(spec, domains, evidence)
    operations = planned_operations(drifts)
    ready = readiness(validation_errors, drifts)
    drift_classes = sorted({item["class"] for item in drifts})
    plan_mode = action == "plan" or os.environ.get("MAILDESK_CF_PLAN") == "1"
    ack_plan = os.environ.get("MAILDESK_CF_ACK_PLAN") or ""

    result: dict[str, Any] = {
        "generated_at": now_iso(),
        "action": action,
        "surface": "maildesk-cf",
        "spec_path": str(spec_path) if spec_path else None,
        "spec": spec,
        "validation_errors": validation_errors,
        "readiness": ready,
        "ready": ready["mail_ready"],
        "checks": checks,
        "drifts": drifts,
        "drift_classes": drift_classes,
        "evidence": evidence_summary(evidence),
        "plan": {
            "mutation_enabled": False,
            "plan_mode": plan_mode,
            "operation_id": operation_id() if action in {"plan", "provision"} else None,
            "operation_count": len(operations),
            "operations": operations,
        },
    }
    if action == "diff":
        result["diff"] = {
            "drift_count": len(drifts),
            "drift_classes": drift_classes,
            "ready": ready,
        }
    if action == "snapshot":
        result["snapshot"] = {
            "domains": [str(domain.get("name") or "") for domain in domains],
            "workers": list(expected_workers(spec).values()),
            "storage": expected_storage(spec),
        }
    if action == "provision":
        if ack_plan:
            result["plan"]["acknowledged_operation_id"] = ack_plan
            result["plan"]["blocked"] = BLOCKED_PROVISION
            result["ready"] = False
            result["readiness"]["mail_ready"] = False
        elif plan_mode:
            result["plan"]["blocked"] = None
        else:
            result["plan"]["blocked"] = "Run provision with --plan first, then --ack-plan <operation-id>"
    return result


def write_result(action: str, result: dict[str, Any]) -> Path:
    output_dir = ROOT / "var" / "inventory" / "runtime"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / (
        f"maildesk-cf-{action}-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.getpid()}.json"
    )
    output_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return output_path


def main() -> int:
    action = os.environ.get("MAILDESK_CF_ACTION", "verify")
    if action not in {"init", "verify", "snapshot", "diff", "plan", "provision"}:
        raise SystemExit(f"Unsupported maildesk-cf action: {action}")

    if action == "init" and not (os.environ.get("SPEC_FILE") or os.environ.get("CFCTL_FILE")):
        domain = os.environ.get("MAILDESK_CF_DOMAIN") or os.environ.get("CFCTL_DOMAIN") or "example.com"
        spec = init_spec(domain)
        result = {
            "generated_at": now_iso(),
            "action": action,
            "surface": "maildesk-cf",
            "spec_path": None,
            "generated_spec": spec,
            "readiness": {
                "template_ready": True,
                "instance_ready": True,
                "edge_ready": False,
                "mail_ready": False,
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
            },
        }
    else:
        spec_path = resolve_spec_path(os.environ.get("SPEC_FILE") or os.environ.get("CFCTL_FILE"))
        result = build_result(action, spec_path, load_spec(spec_path))

    output_path = write_result(action, result)
    print(f"Captured maildesk-cf {action} evidence.")
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

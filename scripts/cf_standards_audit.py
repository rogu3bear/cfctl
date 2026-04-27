#!/usr/bin/env python3

import argparse
import json
import os
import re
import sys
import tomllib
from collections import Counter, defaultdict
from datetime import date, datetime
from pathlib import Path


SECRET_LIKE_KEY_RE = re.compile(
    r"(SECRET|TOKEN|PASSWORD|PRIVATE|CLIENT_SECRET|API_KEY|ACCESS_KEY)",
    re.IGNORECASE,
)
SAFE_PUBLIC_KEY_RE = re.compile(r"(PUBLIC_|SITEKEY$)", re.IGNORECASE)
PLACEHOLDER_RE = re.compile(r"__[A-Z0-9_]+__")
ZERO_SHA_RE = re.compile(r"@sha256:0{64}$")
DEFAULT_COMPATIBILITY_DATE_NOTE_AFTER_DAYS = 30
DEFAULT_COMPATIBILITY_DATE_WARNING_AFTER_DAYS = 90


def strip_jsonc_comments(text: str) -> str:
    result = []
    in_string = False
    string_char = ""
    escaped = False
    i = 0

    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if in_string:
            result.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == string_char:
                in_string = False
            i += 1
            continue

        if ch in ('"', "'"):
            in_string = True
            string_char = ch
            result.append(ch)
            i += 1
            continue

        if ch == "/" and nxt == "/":
            i += 2
            while i < len(text) and text[i] != "\n":
                i += 1
            continue

        if ch == "/" and nxt == "*":
            i += 2
            while i + 1 < len(text) and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue

        result.append(ch)
        i += 1

    return "".join(result)


def read_config(path: Path):
    raw = path.read_text(errors="ignore")
    if path.suffix == ".toml":
        return tomllib.loads(raw), "toml"
    return json.loads(strip_jsonc_comments(raw)), "jsonc"


def parse_compatibility_date(value):
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return datetime.strptime(value.strip(), "%Y-%m-%d").date()
    except ValueError:
        return None


def parse_today(value):
    parsed = parse_compatibility_date(value)
    if parsed is None:
        raise ValueError(f"expected YYYY-MM-DD date, got {value!r}")
    return parsed


def detect_features(config: dict):
    features = set()
    if "compatibility_date" in config:
        features.add("compatibility")
    if config.get("compatibility_flags"):
        features.add("compatibility_flags")
    if "upload_source_maps" in config:
        features.add("upload_source_maps")
    if "pages_build_output_dir" in config:
        features.add("pages_build_output_dir")
    if "workers_dev" in config:
        features.add("workers_dev")
    if "build" in config:
        features.add("build")
    if "assets" in config:
        features.add("assets")
    if "observability" in config:
        features.add("observability")
    if "triggers" in config:
        features.add("triggers")
    if "vars" in config:
        features.add("vars")
    if config.get("routes"):
        features.add("routes")
    if config.get("d1_databases"):
        features.add("d1")
    if config.get("containers"):
        features.add("containers")
    durable_objects = config.get("durable_objects") or {}
    if durable_objects.get("bindings"):
        features.add("do_bindings")
    if config.get("migrations"):
        features.add("migrations")
    if config.get("services"):
        features.add("services")
    if config.get("r2_buckets"):
        features.add("r2")
    return sorted(features)


def project_type(config: dict):
    if "pages_build_output_dir" in config:
        return "pages"
    worker_signals = {
        "main",
        "build",
        "assets",
        "routes",
        "workers_dev",
        "d1_databases",
        "triggers",
        "containers",
        "r2_buckets",
        "vars",
    }
    if any(key in config for key in worker_signals):
        return "worker"
    return "unknown"


def secret_like_var_keys(config: dict):
    keys = []
    for key in (config.get("vars") or {}).keys():
        if SECRET_LIKE_KEY_RE.search(key) and not SAFE_PUBLIC_KEY_RE.search(key):
            keys.append(key)
    return sorted(keys)


def placeholder_var_keys(config: dict):
    keys = []
    for key, value in (config.get("vars") or {}).items():
        if isinstance(value, str) and (
            value.startswith("replace-with-") or PLACEHOLDER_RE.search(value)
        ):
            keys.append(key)
    return sorted(keys)


def d1_missing_fields(config: dict):
    missing = []
    for item in config.get("d1_databases") or []:
        absent = [field for field in ("binding", "database_name", "database_id") if not item.get(field)]
        if absent:
            missing.append({"binding": item.get("binding"), "missing_fields": absent})
    return missing


def r2_missing_fields(config: dict):
    missing = []
    for item in config.get("r2_buckets") or []:
        absent = [field for field in ("binding", "bucket_name") if not item.get(field)]
        if absent:
            missing.append({"binding": item.get("binding"), "missing_fields": absent})
    return missing


def service_missing_fields(config: dict):
    missing = []
    for item in config.get("services") or []:
        absent = [field for field in ("binding", "service") if not item.get(field)]
        if absent:
            missing.append({"binding": item.get("binding"), "missing_fields": absent})
    return missing


def compatibility_date_findings(config: dict, kind: str, today: date, freshness_policy: dict):
    if "compatibility_date" not in config:
        return []

    value = config.get("compatibility_date")
    parsed = parse_compatibility_date(value)
    standard_surface = "worker.runtime" if kind == "worker" else "pages.project"
    note_after_days = int(
        freshness_policy.get(
            "note_after_days",
            DEFAULT_COMPATIBILITY_DATE_NOTE_AFTER_DAYS,
        )
    )
    warning_after_days = int(
        freshness_policy.get(
            "warning_after_days",
            DEFAULT_COMPATIBILITY_DATE_WARNING_AFTER_DAYS,
        )
    )

    if parsed is None:
        return [
            {
                "level": "warning",
                "code": "compatibility_date_invalid",
                "message": "compatibility_date must use YYYY-MM-DD format.",
                "standard_surface": standard_surface,
                "compatibility_date": value,
            }
        ]

    age_days = (today - parsed).days
    base = {
        "standard_surface": standard_surface,
        "compatibility_date": value,
        "age_days": age_days,
        "note_after_days": note_after_days,
        "warning_after_days": warning_after_days,
    }

    if age_days < 0:
        return [
            {
                **base,
                "level": "warning",
                "code": "compatibility_date_future",
                "message": "compatibility_date is in the future.",
            }
        ]

    if age_days > warning_after_days:
        return [
            {
                **base,
                "level": "warning",
                "code": "compatibility_date_stale",
                "message": (
                    f"compatibility_date is {age_days} days old; refresh it or "
                    "record why this runtime intentionally lags."
                ),
            }
        ]

    if age_days > note_after_days:
        return [
            {
                **base,
                "level": "note",
                "code": "compatibility_date_aging",
                "message": (
                    f"compatibility_date is {age_days} days old; confirm the "
                    "runtime date is still deliberate."
                ),
            }
        ]

    return []


def build_command(config: dict):
    build = config.get("build")
    if isinstance(build, dict):
        return build.get("command") or ""
    return ""


def container_findings(config: dict):
    findings = []
    containers = config.get("containers") or []
    for idx, item in enumerate(containers):
        image = item.get("image") or ""
        if not image:
            findings.append(
                {
                    "level": "warning",
                    "code": "container_image_missing",
                    "message": f"Container {idx} has no image reference.",
                    "standard_surface": "worker.containers",
                }
            )
            continue
        is_local_build_definition = image.startswith(".") or "Dockerfile" in image
        if "@sha256:" not in image and not is_local_build_definition:
            findings.append(
                {
                    "level": "warning",
                    "code": "container_image_not_digest_pinned",
                    "message": f"Container {idx} image is not digest pinned: {image}",
                    "standard_surface": "worker.containers",
                }
            )
        elif ZERO_SHA_RE.search(image):
            findings.append(
                {
                    "level": "warning",
                    "code": "container_image_placeholder_digest",
                    "message": f"Container {idx} image uses a placeholder zero digest: {image}",
                    "standard_surface": "worker.containers",
                }
            )
    return findings


def cron_values(config: dict):
    triggers = config.get("triggers") or {}
    crons = triggers.get("crons") or []
    return [cron for cron in crons if isinstance(cron, str)]


def file_findings(config: dict, features, today: date, compatibility_freshness_policy: dict):
    findings = []
    kind = project_type(config)
    main_path = config.get("main") or ""
    has_main_entry = isinstance(main_path, str) and main_path != ""
    is_script_entry = has_main_entry and (
        main_path.endswith(".ts")
        or main_path.endswith(".js")
        or main_path.endswith(".tsx")
        or main_path.endswith(".jsx")
    )
    active_worker = bool({"routes", "workers_dev", "triggers", "containers"} & set(features))

    if "compatibility" not in features:
        findings.append(
            {
                "level": "warning",
                "code": "compatibility_date_missing",
                "message": "compatibility_date is missing.",
                "standard_surface": "worker.runtime" if kind == "worker" else "pages.project",
            }
        )

    findings.extend(
        compatibility_date_findings(
            config,
            kind,
            today,
            compatibility_freshness_policy,
        )
    )

    if "observability" not in features and {"routes", "triggers", "containers"} & set(features):
        findings.append(
            {
                "level": "note",
                "code": "observability_missing_for_active_worker",
                "message": "This config serves traffic, runs on cron, or fronts a container but has no explicit observability block.",
                "standard_surface": "worker.observability",
            }
        )

    if "observability" not in features and active_worker:
        findings.append(
            {
                "level": "note",
                "code": "error_visibility_not_explicit",
                "message": "This active worker has no explicit observability block, so failure visibility is partly implicit.",
                "standard_surface": "worker.errors",
            }
        )

    if "workers_dev" in features and "routes" in features and config.get("workers_dev") is True:
        findings.append(
            {
                "level": "note",
                "code": "dual_exposure_workers_dev_and_routes",
                "message": "workers_dev is enabled while custom routes are also configured. Confirm that dual exposure is intentional.",
                "standard_surface": "worker.routes",
            }
        )

    if kind == "worker" and is_script_entry and "upload_source_maps" not in features:
        findings.append(
            {
                "level": "note",
                "code": "source_maps_not_explicit",
                "message": "This script-entry worker does not declare upload_source_maps. Make failure debuggability explicit.",
                "standard_surface": "worker.errors",
            }
        )

    secret_keys = secret_like_var_keys(config)
    if secret_keys:
        findings.append(
            {
                "level": "warning",
                "code": "secret_like_vars_in_plaintext",
                "message": "Secret-like keys are present in [vars]. Move these to secrets or an external sink.",
                "standard_surface": "worker.vars",
                "keys": secret_keys,
            }
        )

    placeholder_keys = placeholder_var_keys(config)
    if placeholder_keys:
        findings.append(
            {
                "level": "note",
                "code": "placeholder_vars_present",
                "message": "Placeholder values appear in [vars]. Ensure a named render or deploy step owns them.",
                "standard_surface": "worker.vars",
                "keys": placeholder_keys,
            }
        )

    cmd = build_command(config)
    if cmd and any(term in cmd for term in ("cargo install", "npm install -g", "pnpm add -g", "bun add -g")):
        findings.append(
            {
                "level": "note",
                "code": "floating_build_install",
                "message": "Build command performs a floating install. Prefer a pinned or checked-in toolchain path.",
                "standard_surface": "worker.build",
            }
        )

    for item in d1_missing_fields(config):
        findings.append(
            {
                "level": "warning",
                "code": "d1_binding_missing_fields",
                "message": "A D1 binding is missing one or more required identity fields.",
                "standard_surface": "worker.d1",
                "binding": item["binding"],
                "missing_fields": item["missing_fields"],
            }
        )

    for item in r2_missing_fields(config):
        findings.append(
            {
                "level": "warning",
                "code": "r2_binding_missing_fields",
                "message": "An R2 binding is missing one or more required fields.",
                "standard_surface": "worker.storage",
                "binding": item["binding"],
                "missing_fields": item["missing_fields"],
            }
        )

    for item in service_missing_fields(config):
        findings.append(
            {
                "level": "warning",
                "code": "service_binding_missing_fields",
                "message": "A service binding is missing one or more required fields.",
                "standard_surface": "worker.services",
                "binding": item["binding"],
                "missing_fields": item["missing_fields"],
            }
        )

    findings.extend(container_findings(config))

    if "containers" in features and "do_bindings" not in features:
        findings.append(
            {
                "level": "warning",
                "code": "container_do_binding_missing",
                "message": "Container config exists without a Durable Object binding.",
                "standard_surface": "worker.containers",
            }
        )

    if "containers" in features and "migrations" not in features:
        findings.append(
            {
                "level": "warning",
                "code": "container_migrations_missing",
                "message": "Container config exists without an explicit migrations block.",
                "standard_surface": "worker.containers",
            }
        )

    cron_placeholders = [value for value in cron_values(config) if PLACEHOLDER_RE.search(value)]
    if cron_placeholders:
        findings.append(
            {
                "level": "note",
                "code": "cron_placeholder_present",
                "message": "Cron trigger contains placeholder values. Ensure a named render step owns them.",
                "standard_surface": "worker.triggers",
                "values": cron_placeholders,
            }
        )

    return findings


def should_exclude(path: Path, exclude_tokens):
    normalized = path.as_posix()
    return any(token in normalized for token in exclude_tokens)


def discover_configs(root: Path, config_names, exclude_tokens):
    files = []
    config_name_set = set(config_names)
    for dirpath, dirnames, filenames in os.walk(root):
        current_dir = Path(dirpath)
        normalized_dir = current_dir.as_posix()

        dirnames[:] = [
            name
            for name in dirnames
            if not should_exclude(current_dir / name, exclude_tokens)
        ]

        if should_exclude(current_dir, exclude_tokens):
            continue

        for filename in filenames:
            if filename not in config_name_set:
                continue
            path = current_dir / filename
            if should_exclude(path, exclude_tokens):
                continue
            files.append(path)
    return sorted(set(files))


def standards_feature_map(standards: dict):
    mapping = defaultdict(list)
    for surface, meta in (standards.get("surfaces") or {}).items():
        for feature in meta.get("audit_features") or []:
            mapping[feature].append(surface)
    return {feature: sorted(values) for feature, values in mapping.items()}


def summarize_surfaces(standards: dict, feature_map: dict, files_json):
    per_surface_files = defaultdict(set)
    for item in files_json:
        for surface in item["standards"]:
            per_surface_files[surface].add(item["path"])

    surfaces = []
    for surface, meta in sorted((standards.get("surfaces") or {}).items()):
        features = meta.get("audit_features") or []
        if not features:
            continue
        surfaces.append(
            {
                "surface": surface,
                "stance": meta.get("stance"),
                "feature_keys": features,
                "standard_count": len(meta.get("standards") or []),
                "required_count": len([x for x in meta.get("standards") or [] if x.get("level") == "required"]),
                "matched_file_count": len(per_surface_files.get(surface) or []),
            }
        )
    return surfaces


def summarize_compatibility_date_freshness(files_json, freshness_policy: dict):
    counters = Counter()
    stale_files = []
    for item in files_json:
        for finding in item.get("findings") or []:
            code = finding.get("code")
            if not code or not code.startswith("compatibility_date_"):
                continue
            counters[code] += 1
            if code in {
                "compatibility_date_stale",
                "compatibility_date_aging",
                "compatibility_date_invalid",
                "compatibility_date_future",
            }:
                stale_files.append(
                    {
                        "path": item["path"],
                        "code": code,
                        "level": finding.get("level"),
                        "compatibility_date": finding.get("compatibility_date"),
                        "age_days": finding.get("age_days"),
                    }
                )

    return {
        "note_after_days": int(
            freshness_policy.get(
                "note_after_days",
                DEFAULT_COMPATIBILITY_DATE_NOTE_AFTER_DAYS,
            )
        ),
        "warning_after_days": int(
            freshness_policy.get(
                "warning_after_days",
                DEFAULT_COMPATIBILITY_DATE_WARNING_AFTER_DAYS,
            )
        ),
        "missing_count": counters.get("compatibility_date_missing", 0),
        "aging_count": counters.get("compatibility_date_aging", 0),
        "stale_count": counters.get("compatibility_date_stale", 0),
        "invalid_count": counters.get("compatibility_date_invalid", 0),
        "future_count": counters.get("compatibility_date_future", 0),
        "attention_file_count": len(stale_files),
        "attention_files": stale_files,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--standards-path", required=True)
    parser.add_argument("--today", help="Override today's date for deterministic checks.")
    args = parser.parse_args()

    root = Path(args.root).expanduser().resolve()
    standards_path = Path(args.standards_path).expanduser().resolve()
    today = parse_today(args.today) if args.today else date.today()

    standards = json.loads(standards_path.read_text())
    audit_meta = standards.get("audit") or {}
    config_names = audit_meta.get("config_names") or ["wrangler.toml", "wrangler.jsonc"]
    exclude_tokens = audit_meta.get("exclude_path_tokens") or []
    compatibility_freshness_policy = audit_meta.get("compatibility_date_freshness") or {}

    files = discover_configs(root, config_names, exclude_tokens)
    feature_map = standards_feature_map(standards)
    feature_counts = Counter()
    project_type_counts = Counter()
    finding_counts = Counter()
    files_json = []

    for path in files:
        config, fmt = read_config(path)
        features = detect_features(config)
        for feature in features:
            feature_counts[feature] += 1

        kind = project_type(config)
        project_type_counts[kind] += 1

        applicable_standards = set()
        for feature in features:
            applicable_standards.update(feature_map.get(feature, []))

        findings = file_findings(
            config,
            features,
            today,
            compatibility_freshness_policy,
        )
        for finding in findings:
            finding_counts[finding["level"]] += 1

        files_json.append(
            {
                "path": path.as_posix(),
                "format": fmt,
                "project_type": kind,
                "name": config.get("name"),
                "features": sorted(features),
                "standards": sorted(applicable_standards),
                "metadata": {
                    "workers_dev": config.get("workers_dev"),
                    "pages_build_output_dir": config.get("pages_build_output_dir"),
                    "route_count": len(config.get("routes") or []),
                    "d1_count": len(config.get("d1_databases") or []),
                    "container_count": len(config.get("containers") or []),
                },
                "findings": findings,
            }
        )

    uncovered_features = sorted([feature for feature in feature_counts if feature not in feature_map])
    covered_features = sorted([feature for feature in feature_counts if feature in feature_map])

    output = {
        "root": root.as_posix(),
        "standards_version": standards.get("version"),
        "config_file_count": len(files_json),
        "project_type_counts": dict(project_type_counts),
        "feature_counts": dict(sorted(feature_counts.items())),
        "compatibility_date_freshness": summarize_compatibility_date_freshness(
            files_json,
            compatibility_freshness_policy,
        ),
        "coverage": {
            "covered_features": covered_features,
            "covered_feature_count": len(covered_features),
            "uncovered_features": uncovered_features,
            "uncovered_feature_count": len(uncovered_features),
        },
        "surfaces": summarize_surfaces(standards, feature_map, files_json),
        "findings_summary": {
            "warning_count": finding_counts.get("warning", 0),
            "note_count": finding_counts.get("note", 0),
            "error_count": finding_counts.get("error", 0),
        },
        "files": files_json,
    }

    json.dump(output, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Deterministic, privacy-preserving execution-adapter choice for cfctl."""

from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


OUTCOMES = ("verified", "failed", "fallback", "abandoned")
EVIDENCE_CLASSES = (
    "source_config",
    "live_control_plane_read",
    "preview_artifact",
    "apply_artifact",
    "post_change_verification",
    "ui_before_after",
    "external_delivery",
    "payment_settlement",
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def score_adapter(adapter: dict[str, Any], weights: dict[str, int]) -> float:
    metrics = adapter["policy_metrics"]
    weighted = sum(float(metrics[name]) * float(weight) for name, weight in weights.items())
    return round(weighted / 100.0, 2)


def required_controls(catalog: dict[str, Any], adapter: dict[str, Any], risk: str) -> list[str]:
    controls = list(adapter.get("required_controls", []))
    if risk != "read":
        controls.extend(catalog["global_controls"]["mutation_controls"])
    return sorted(set(controls))


def cmd_list(args: argparse.Namespace, catalog: dict[str, Any]) -> dict[str, Any]:
    return {
        "kind": "SKILL_CATALOG",
        "schema_version": catalog["schema_version"],
        "score": catalog["score"],
        "global_controls": catalog["global_controls"],
        "adapters": catalog["adapters"],
    }


def cmd_choose(args: argparse.Namespace, catalog: dict[str, Any]) -> dict[str, Any]:
    risk = args.risk
    if risk not in catalog["risk_classes"]:
        raise ValueError(f"unsupported risk class: {risk}")

    needs = sorted(set(args.need or []))
    available = set(args.available or [])
    known_adapters = {adapter["id"] for adapter in catalog["adapters"]}
    unknown_available = sorted(available - known_adapters)
    if unknown_available:
        raise ValueError(f"unknown available adapter(s): {', '.join(unknown_available)}")

    intent_digest = sha256_text(args.intent)
    catalog_digest = sha256_text(canonical_json(catalog))
    weights = catalog["score"]["weights"]
    candidates: list[dict[str, Any]] = []

    for adapter in catalog["adapters"]:
        capability_set = set(adapter["capabilities"])
        missing = sorted(set(needs) - capability_set)
        risk_allowed = risk in adapter["allowed_risks"]
        eligible = not missing and risk_allowed
        availability_kind = adapter["availability"]["kind"]
        executable = availability_kind == "built_in" or adapter["id"] in available
        candidates.append(
            {
                "adapter_id": adapter["id"],
                "label": adapter["label"],
                "eligible": eligible,
                "executable": executable,
                "missing_capabilities": missing,
                "risk_allowed": risk_allowed,
                "score": score_adapter(adapter, weights),
                "priority": adapter["priority"],
                "metrics": {
                    "metric_class": "declared_policy",
                    "values": adapter["policy_metrics"],
                    "weights": weights,
                },
                "availability": adapter["availability"],
                "required_controls": required_controls(catalog, adapter, risk),
                "evidence_contract": adapter["evidence_contract"],
                "invocation": adapter["invocation"],
                "fallbacks": adapter["fallbacks"],
            }
        )

    ranked = sorted(
        candidates,
        key=lambda item: (
            not item["eligible"],
            not item["executable"],
            -item["score"],
            -item["priority"],
            item["adapter_id"],
        ),
    )
    eligible = [item for item in ranked if item["eligible"]]
    executable = [item for item in eligible if item["executable"]]
    chosen = executable[0] if executable else (eligible[0] if eligible else None)
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    request_contract = {
        "intent_digest": intent_digest,
        "risk": risk,
        "needs": needs,
        "available": sorted(available),
        "surface": args.surface,
        "catalog_digest": catalog_digest,
        "generated_at": now,
    }
    # Candidate ranking is deterministic; the receipt identity must be unique so
    # repeated identical choices can each carry exactly one independent outcome.
    choice_id = f"choice-{secrets.token_hex(12)}"

    if chosen is None:
        decision = {
            "status": "blocked",
            "adapter_id": None,
            "executable": False,
            "authority_granted": False,
            "preview_bypass_allowed": False,
            "external_confirmation_bypass_allowed": False,
            "reason_codes": ["no_adapter_satisfies_requirements"],
            "required_controls": [],
            "next_step": "Narrow the requirements or extend catalog/skill-choices.json with a governed adapter.",
        }
    else:
        decision = {
            "status": "selected" if chosen["executable"] else "blocked",
            "adapter_id": chosen["adapter_id"],
            "executable": chosen["executable"],
            "authority_granted": False,
            "preview_bypass_allowed": False,
            "external_confirmation_bypass_allowed": False,
            "reason_codes": [
                "requirements_satisfied",
                "highest_ranked_executable" if chosen["executable"] else "adapter_not_available_in_session",
                "authority_unchanged",
            ],
            "required_controls": chosen["required_controls"],
            "evidence_contract": chosen["evidence_contract"],
            "invocation": chosen["invocation"],
            "fallback_order": chosen["fallbacks"],
            "next_step": (
                chosen["invocation"]
                if chosen["executable"]
                else f"Make {chosen['adapter_id']} available, then rerun the same choice request."
            ),
        }

    return {
        "kind": "SKILL_CHOICE",
        "schema_version": 1,
        "choice_id": choice_id,
        "generated_at": now,
        "intent": {
            "raw": None,
            "digest": intent_digest,
            "character_count": len(args.intent),
        },
        "requirements": {
            "risk": risk,
            "needs": needs,
            "surface": args.surface,
            "available_adapters": sorted(available),
        },
        "policy": {
            "catalog_digest": catalog_digest,
            "metric_class": "declared_policy",
            "authority_granted_by_choice": False,
            "memory_is_evidence": False,
        },
        "decision": decision,
        "candidates": ranked,
    }


def iter_runtime_artifacts(runtime_dir: Path):
    if not runtime_dir.is_dir():
        return
    for path in sorted(runtime_dir.glob("*.json")):
        try:
            yield path, load_json(path)
        except (OSError, ValueError, json.JSONDecodeError):
            continue


def find_choice(runtime_dir: Path, choice_id: str) -> tuple[Path, dict[str, Any]] | None:
    for path, artifact in iter_runtime_artifacts(runtime_dir):
        if (
            artifact.get("action") == "skills"
            and artifact.get("operation") == "choose"
            and artifact.get("result", {}).get("choice_id") == choice_id
        ):
            return path, artifact
    return None


def outcome_exists(runtime_dir: Path, choice_id: str) -> bool:
    for _, artifact in iter_runtime_artifacts(runtime_dir):
        result = artifact.get("result") or {}
        if (
            artifact.get("action") == "skills"
            and artifact.get("operation") == "record"
            and result.get("kind") == "SKILL_OUTCOME"
            and result.get("choice_id") == choice_id
        ):
            return True
    return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def cmd_record(args: argparse.Namespace, catalog: dict[str, Any]) -> dict[str, Any]:
    runtime_dir = Path(args.runtime_dir).resolve()
    match = find_choice(runtime_dir, args.choice_id)
    if match is None:
        raise ValueError(f"choice artifact not found: {args.choice_id}")
    choice_path, choice = match
    if outcome_exists(runtime_dir, args.choice_id):
        raise ValueError(f"outcome already recorded for choice: {args.choice_id}")
    known_adapters = {adapter["id"] for adapter in catalog["adapters"]}
    if args.adapter not in known_adapters:
        raise ValueError(f"unknown adapter: {args.adapter}")
    if args.duration_ms < 0:
        raise ValueError("duration-ms must be non-negative")
    evidence_path = Path(args.evidence).expanduser().resolve() if args.evidence else None
    if args.outcome == "verified" and evidence_path is None:
        raise ValueError("verified outcomes require --evidence")
    if evidence_path is not None and not evidence_path.is_file():
        raise ValueError(f"evidence path not found: {evidence_path}")
    if evidence_path is not None and args.evidence_class is None:
        raise ValueError("evidence paths require --evidence-class")
    if evidence_path is None and args.evidence_class is not None:
        raise ValueError("evidence-class requires --evidence")
    if evidence_path is not None and evidence_path == choice_path.resolve():
        raise ValueError("a choice artifact cannot be its own outcome evidence")

    selected_adapter = choice.get("result", {}).get("decision", {}).get("adapter_id")
    now = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "kind": "SKILL_OUTCOME",
        "schema_version": 1,
        "recorded_at": now,
        "choice_id": args.choice_id,
        "choice_found": True,
        "choice_artifact_path": str(choice_path),
        "selected_adapter_id": selected_adapter,
        "adapter_id": args.adapter,
        "used_selected_adapter": args.adapter == selected_adapter,
        "outcome": args.outcome,
        "duration_ms": args.duration_ms,
        "evidence": (
            {
                "path": str(evidence_path),
                "class": args.evidence_class,
                "sha256": sha256_file(evidence_path),
                "size_bytes": evidence_path.stat().st_size,
            }
            if evidence_path
            else None
        ),
        "evidence_valid_at_recording": evidence_path is not None,
        "duration_source": "caller_measured",
    }


def cmd_metrics(args: argparse.Namespace, catalog: dict[str, Any]) -> dict[str, Any]:
    runtime_dir = Path(args.runtime_dir).resolve()
    aggregates: dict[str, dict[str, Any]] = {
        adapter["id"]: {
            "adapter_id": adapter["id"],
            "attempts": 0,
            "verified": 0,
            "failed": 0,
            "fallback": 0,
            "abandoned": 0,
            "invalid_evidence": 0,
            "total_duration_ms": 0,
        }
        for adapter in catalog["adapters"]
    }
    ignored_records = 0
    duplicate_choice_records = 0
    invalid_evidence_records = 0
    seen_choices: set[str] = set()
    for _, artifact in iter_runtime_artifacts(runtime_dir):
        result = artifact.get("result") or {}
        if artifact.get("action") != "skills" or artifact.get("operation") != "record":
            continue
        if result.get("kind") != "SKILL_OUTCOME":
            continue
        adapter_id = result.get("adapter_id")
        outcome = result.get("outcome")
        choice_id = result.get("choice_id")
        if adapter_id not in aggregates or outcome not in OUTCOMES:
            ignored_records += 1
            continue
        if not isinstance(choice_id, str) or not choice_id:
            ignored_records += 1
            continue
        if choice_id in seen_choices:
            ignored_records += 1
            duplicate_choice_records += 1
            continue
        seen_choices.add(choice_id)
        aggregate = aggregates[adapter_id]
        aggregate["attempts"] += 1
        if outcome == "verified":
            evidence = result.get("evidence") or {}
            evidence_path_value = evidence.get("path")
            evidence_digest = evidence.get("sha256")
            evidence_valid = False
            if isinstance(evidence_path_value, str) and isinstance(evidence_digest, str):
                evidence_path = Path(evidence_path_value)
                if evidence_path.is_file():
                    try:
                        evidence_valid = sha256_file(evidence_path) == evidence_digest
                    except OSError:
                        evidence_valid = False
            if evidence_valid:
                aggregate["verified"] += 1
            else:
                aggregate["invalid_evidence"] += 1
                invalid_evidence_records += 1
        else:
            aggregate[outcome] += 1
        duration = result.get("duration_ms")
        if isinstance(duration, int) and duration >= 0:
            aggregate["total_duration_ms"] += duration

    rows = []
    for adapter in catalog["adapters"]:
        aggregate = aggregates[adapter["id"]]
        attempts = aggregate["attempts"]
        verified = aggregate["verified"]
        total_duration = aggregate.pop("total_duration_ms")
        aggregate["observed_success_rate"] = round((verified / attempts) * 100, 2) if attempts else None
        aggregate["mean_duration_ms"] = round(total_duration / attempts, 2) if attempts else None
        aggregate["policy_score"] = score_adapter(adapter, catalog["score"]["weights"])
        rows.append(aggregate)

    return {
        "kind": "SKILL_METRICS",
        "schema_version": 1,
        "metric_class": "observed_outcomes",
        "source": str(runtime_dir),
        "ignored_records": ignored_records,
        "duplicate_choice_records": duplicate_choice_records,
        "invalid_evidence_records": invalid_evidence_records,
        "adapters": rows,
        "note": "Null observed rates mean no outcome has been recorded; policy_score is declared routing policy, not observed performance. Verified counts require evidence whose current SHA-256 still matches the recorded digest.",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cf_skill_choice.py")
    parser.add_argument("--catalog", required=True)
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("list")

    choose = subparsers.add_parser("choose")
    choose.add_argument("--intent", required=True)
    choose.add_argument("--risk", default="read")
    choose.add_argument("--need", action="append", default=[])
    choose.add_argument("--available", action="append", default=[])
    choose.add_argument("--surface")

    record = subparsers.add_parser("record")
    record.add_argument("--runtime-dir", required=True)
    record.add_argument("--choice-id", required=True)
    record.add_argument("--adapter", required=True)
    record.add_argument("--outcome", required=True, choices=OUTCOMES)
    record.add_argument("--duration-ms", required=True, type=int)
    record.add_argument("--evidence")
    record.add_argument("--evidence-class", choices=EVIDENCE_CLASSES)

    metrics = subparsers.add_parser("metrics")
    metrics.add_argument("--runtime-dir", required=True)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    try:
        catalog = load_json(Path(args.catalog))
        handlers = {
            "list": cmd_list,
            "choose": cmd_choose,
            "record": cmd_record,
            "metrics": cmd_metrics,
        }
        result = handlers[args.command](args, catalog)
        print(canonical_json({"ok": True, "result": result}))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(canonical_json({"ok": False, "error": str(exc)}))
        return 2


if __name__ == "__main__":
    sys.exit(main())

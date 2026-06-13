#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def inline_list(values: list[str]) -> str:
    if not values:
        return "-"
    return ", ".join(f"`{value}`" for value in values)


def text_list(values: list[str]) -> str:
    return ", ".join(values) if values else "-"


def operation_policy(runtime: dict, operation: str, operation_meta: dict) -> dict:
    policy = runtime.get("policy", {})
    risk = operation_meta.get("risk") or "write"
    defaults = dict(policy.get("operation_defaults", {}).get(risk, {}))
    special = dict(policy.get("special_operations", {}).get(operation, {}))
    merged = {**defaults, **special, **operation_meta}
    merged["risk"] = risk
    return merged


def selector_contract(action_meta: dict) -> str:
    required = action_meta.get("required_selectors", [])
    any_of = action_meta.get("selectors_any_of", [])
    parts = []
    if required:
        parts.append("required: " + ", ".join(required))
    if any_of:
        parts.append("one of: " + " / ".join(", ".join(group) for group in any_of))
    return "; ".join(parts) if parts else "-"


def render(root: Path) -> str:
    runtime = json.loads((root / "catalog/runtime.json").read_text())
    surfaces = json.loads((root / "catalog/surfaces.json").read_text())["surfaces"]
    desired_state = runtime.get("desired_state", {})

    rows = []
    operation_rows = []
    read_only_rows = []
    for surface_name in sorted(surfaces):
        surface = surfaces[surface_name]
        actions = surface.get("actions", {})
        read_supported = any(
            actions.get(action, {}).get("supported") is True
            for action in ("list", "get", "verify")
        )
        can_supported = actions.get("can", {}).get("supported") is True
        apply_supported = actions.get("apply", {}).get("supported") is True
        verify_supported = actions.get("verify", {}).get("supported") is True
        desired = desired_state.get(surface_name, {})
        standards_ref = surface.get("standards_ref") or "-"
        docs_topics = ", ".join(surface.get("docs_topics", [])) or "-"
        module = surface.get("module") or "-"
        rows.append(
            f"| `{surface_name}` | {yes_no(read_supported)} | "
            f"{yes_no(can_supported)} | {yes_no(apply_supported)} | "
            f"{yes_no(verify_supported)} | {yes_no(desired.get('supported', False))} | "
            f"`{standards_ref}` | `{docs_topics}` | `{module}` |"
        )

        if apply_supported:
            operations = actions.get("apply", {}).get("operations", {})
            for operation, operation_meta in sorted(operations.items()):
                policy = operation_policy(runtime, operation, operation_meta)
                confirmation = (
                    operation_meta.get("confirm") or policy.get("confirmation") or "-"
                )
                selectors = selector_contract(operation_meta)
                lanes = inline_list(policy.get("allowed_lanes", []))
                operation_rows.append(
                    f"| `{surface_name}` | `{operation}` | "
                    f"`{policy.get('risk', 'write')}` | "
                    f"{yes_no(policy.get('preview_required') is True)} | "
                    f"`{policy.get('lock_strategy', '-')}` | "
                    f"{yes_no(policy.get('verification_required') is True and verify_supported)} | "
                    f"`{confirmation}` | {lanes} | {selectors} |"
                )

        if desired.get("sync_supported") is True:
            policy = operation_policy(runtime, "sync", {"risk": "write"})
            lanes = inline_list(policy.get("allowed_lanes", []))
            selectors = text_list(desired.get("match_selectors", []))
            operation_rows.append(
                f"| `{surface_name}` | `sync` | `{policy.get('risk', 'write')}` | "
                f"{yes_no(policy.get('preview_required') is True)} | "
                f"`{policy.get('lock_strategy', '-')}` | "
                f"{yes_no(policy.get('verification_required') is True and verify_supported)} | "
                f"`-` | {lanes} | state match: {selectors} |"
            )

        if (
            read_supported
            and not apply_supported
            and desired.get("sync_supported") is not True
        ):
            public_actions = [
                action
                for action in ("list", "get", "verify", "can")
                if actions.get(action, {}).get("supported") is True
            ]
            read_only_rows.append(
                f"| `{surface_name}` | {inline_list(public_actions)} | "
                f"{selector_contract(actions.get('list', {}))} | "
                f"`{surface.get('inventory_script', '-')}` |"
            )

    lines = [
        "# Capabilities",
        "",
        "_Generated from `catalog/surfaces.json` and `catalog/runtime.json`. Edit the catalogs, not this file._",
        "",
        "`cfctl` currently exposes these Cloudflare surfaces as first-class runtime resources:",
        "",
        "This table is the operable runtime surface. The standards layer and docs bank intentionally cover more Cloudflare territory than `cfctl` can currently mutate or verify directly.",
        "",
        "| Surface | Read | Can | Apply | Verify | Desired State | Standards | Docs Topics | Module |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        *rows,
        "",
        "## Operation Contract Matrix",
        "",
        "This matrix is derived from the same catalogs used by `cfctl explain`, `cfctl classify`, `cfctl guide`, and the static verifier. It is the preflight view for deciding whether a surface is read-only, preview-gated, destructive, lane-sensitive, or desired-state-backed.",
        "",
        "| Surface | Operation | Risk | Preview | Lock | Verify After Apply | Confirmation | Allowed Lanes | Selectors |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
        *operation_rows,
        "",
        "## Read-Only Surfaces",
        "",
        "These surfaces are first-class read surfaces but do not expose `apply` or desired-state `sync` today. Mutation should not be inferred from an inventory script alone.",
        "",
        "| Surface | Public Actions | List Selectors | Inventory Backend |",
        "| --- | --- | --- | --- |",
        *read_only_rows,
        "",
        "Composite lifecycle commands:",
        "- `cfctl hostname verify --file state/hostname/<name>.yaml`",
        "- `cfctl hostname diff --file state/hostname/<name>.yaml`",
        "- `cfctl hostname plan --file state/hostname/<name>.yaml`",
        "- `cfctl hostname apply --file state/hostname/<name>.yaml` is intentionally blocked until component mutations are preview-gated.",
        "",
        "Ownership authority commands:",
        "- `cfctl ownership list`",
        "- `cfctl ownership get --resource-key cloudflare:dns.record:*`",
        "- `cfctl ownership check`",
        "",
        "Lane-aware commands:",
        "- `cfctl doctor`",
        "- `cfctl bootstrap permissions`",
        "- `cfctl lanes`",
        "- `cfctl can <surface> <operation> --all-lanes`",
        "- `cfctl classify <surface> <operation>`",
        "- `cfctl guide <surface> <operation>`",
        "",
        "State-aware commands:",
        "- `cfctl diff <surface>`",
        "- `cfctl apply <surface> sync --plan`",
        "- `cfctl apply <surface> sync --ack-plan <operation-id>`",
        "",
        "Use `cfctl explain <surface>` for the live contract of a specific surface, including selectors, supported apply operations, module bindings, standards refs, docs topics, and current permission truth.",
        "Use `cfctl classify <surface> <operation>` to see whether the operation requires preview, confirmation, or a different auth lane.",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--check", help="Path to an existing rendered file to verify")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    rendered = render(root)

    if args.check:
        target = Path(args.check)
        if target.read_text() != rendered:
            print(f"capabilities doc out of date: {target}", file=sys.stderr)
            return 1
        print("capabilities doc up to date")
        return 0

    sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

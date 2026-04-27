#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


def yes_no(value: bool) -> str:
    return "yes" if value else "no"


def render(root: Path) -> str:
    runtime = json.loads((root / "catalog/runtime.json").read_text())
    surfaces = json.loads((root / "catalog/surfaces.json").read_text())["surfaces"]
    desired_state = runtime.get("desired_state", {})

    rows = []
    for surface_name in sorted(surfaces):
      surface = surfaces[surface_name]
      actions = surface.get("actions", {})
      read_supported = any(actions.get(action, {}).get("supported") is True for action in ("list", "get", "verify"))
      apply_supported = actions.get("apply", {}).get("supported") is True
      desired = desired_state.get(surface_name, {})
      standards_ref = surface.get("standards_ref") or "-"
      docs_topics = ", ".join(surface.get("docs_topics", [])) or "-"
      module = surface.get("module") or "-"
      rows.append(
          f"| `{surface_name}` | {yes_no(read_supported)} | {yes_no(apply_supported)} | {yes_no(desired.get('supported', False))} | `{standards_ref}` | `{docs_topics}` | `{module}` |"
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
        "| Surface | Read | Apply | Desired State | Standards | Docs Topics | Module |",
        "| --- | --- | --- | --- | --- | --- | --- |",
        *rows,
        "",
        "Lane-aware commands:",
        "- `cfctl doctor`",
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

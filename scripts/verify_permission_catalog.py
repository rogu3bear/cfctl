#!/usr/bin/env python3

import argparse
import fnmatch
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "catalog" / "permissions.json"
SURFACES_PATH = ROOT / "catalog" / "surfaces.json"
RUNTIME_PATH = ROOT / "catalog" / "runtime.json"

ALLOWED_SCOPES = {"account", "zone"}
TOKEN_MINT_PERMISSION_PREFIX = "Account API Tokens"
EXPECTED_PROFILES = {
    "read",
    "dns",
    "hostname",
    "deploy",
    "security-audit",
    "full-operator",
}
EXPECTED_BOOTSTRAP_CREATOR = {
    ("Account API Tokens Read", "account"),
    ("Account API Tokens Write", "account"),
    ("Account Settings Read", "account"),
}
CLOUDFLARE_SCOPE = {
    "account": "com.cloudflare.api.account",
    "zone": "com.cloudflare.api.account.zone",
}


def load_json(path: Path) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        fail(f"missing file: {path.relative_to(ROOT)}")
    except json.JSONDecodeError as exc:
        fail(f"{path.relative_to(ROOT)} is not valid JSON: {exc}")


def fail(message: str) -> None:
    print(f"permission-catalog verification failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def require(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def require_string(value: object, path: str) -> str:
    require(isinstance(value, str) and value != "", f"{path} must be a non-empty string")
    return value


def require_int(value: object, path: str) -> int:
    require(isinstance(value, int) and value > 0, f"{path} must be a positive integer")
    return value


def require_string_list(value: object, path: str) -> list[str]:
    require(isinstance(value, list), f"{path} must be a list")
    result = []
    for index, item in enumerate(value):
        result.append(require_string(item, f"{path}[{index}]"))
    require(len(result) == len(set(result)), f"{path} must not contain duplicates")
    return result


def permission_key(permission: dict) -> tuple[str, str]:
    return (permission["name"], permission["scope"])


def sorted_permissions(permissions: list[dict]) -> list[dict]:
    return sorted(permissions, key=lambda item: (item["scope"], item["name"]))


def profile_permissions(catalog: dict, profile: str) -> list[dict]:
    selected = {
        permission_key(permission): permission
        for permission in catalog["permissions"]
        if profile in permission.get("profiles", [])
    }
    return sorted_permissions(list(selected.values()))


def shell_quote(value: object) -> str:
    # Match jq's @sh style used by cfctl for generated token commands.
    return "'" + str(value).replace("'", "'\"'\"'") + "'"


def render_permission_flags(permissions: list[dict]) -> str:
    return " ".join(
        f"--permission {shell_quote(name)}"
        for name in sorted({permission["name"] for permission in permissions})
    )


def render_resource_flags(permissions: list[dict], zone: str = "", zone_id: str = "") -> str:
    if not any(permission["scope"] == "zone" for permission in permissions):
        return ""
    if zone:
        return f" --zone {shell_quote(zone)}"
    if zone_id:
        return f" --zone-id {shell_quote(zone_id)}"
    return " --all-zones-in-account"


def render_plan_command(
    catalog: dict,
    profile: str,
    zone: str = "",
    zone_id: str = "",
    token_name: str = "",
    ttl_hours: int | None = None,
) -> str:
    profile_meta = catalog["profiles"][profile]
    permissions = profile_permissions(catalog, profile)
    if token_name == "":
        token_name = f"cfctl-{profile}-operator"
    if ttl_hours is None:
        ttl_hours = profile_meta["ttl_hours"]

    return (
        f"cfctl token mint --name {shell_quote(token_name)} "
        f"{render_permission_flags(permissions)}"
        f"{render_resource_flags(permissions, zone, zone_id)} "
        f"--ttl-hours {ttl_hours} --plan"
    )


def validate_catalog_shape(catalog: dict, surfaces: dict, runtime: dict) -> None:
    require(isinstance(catalog, dict), "catalog/permissions.json must contain an object")
    require(catalog.get("version") == 1, "catalog version must be 1")

    profiles = catalog.get("profiles")
    require(isinstance(profiles, dict) and profiles, "profiles must be a non-empty object")
    require(set(profiles) == EXPECTED_PROFILES, f"profiles must be {sorted(EXPECTED_PROFILES)}")
    default_profile = require_string(catalog.get("default_profile"), "default_profile")
    require(default_profile in profiles, "default_profile must reference a declared profile")
    require(default_profile == "read", "default_profile should stay read")

    public_verbs = set(runtime.get("public_verbs", []))
    surface_names = set(surfaces.get("surfaces", {}).keys())
    surface_aliases = public_verbs | surface_names | {"wrangler", "cloudflared", "doctor", "lanes"}

    for profile_name, profile in profiles.items():
        require(isinstance(profile, dict), f"profiles.{profile_name} must be an object")
        require_string(profile.get("summary"), f"profiles.{profile_name}.summary")
        ttl_hours = require_int(profile.get("ttl_hours"), f"profiles.{profile_name}.ttl_hours")
        risk = require_string(profile.get("risk"), f"profiles.{profile_name}.risk")
        allowed_surfaces = require_string_list(profile.get("allowed_surfaces"), f"profiles.{profile_name}.allowed_surfaces")
        require_string_list(profile.get("forbidden_permissions"), f"profiles.{profile_name}.forbidden_permissions")
        require_string_list(profile.get("verification"), f"profiles.{profile_name}.verification")

        missing_allowed_surfaces = sorted(
            surface for surface in allowed_surfaces if surface != "*" and surface not in surface_aliases
        )
        require(
            not missing_allowed_surfaces,
            f"profiles.{profile_name}.allowed_surfaces references unknown surfaces: {missing_allowed_surfaces}",
        )
        if profile_name != "full-operator":
            require("*" not in allowed_surfaces, f"profile {profile_name} must not use wildcard allowed_surfaces")

        if risk == "read":
            require(ttl_hours <= 720, f"read profile {profile_name} ttl_hours must be <= 720")
        else:
            require(ttl_hours <= 168, f"write profile {profile_name} ttl_hours must be <= 168")

    bootstrap_creator = catalog.get("bootstrap_creator")
    require(isinstance(bootstrap_creator, dict), "bootstrap_creator must be an object")
    creator_permissions = bootstrap_creator.get("permissions")
    require(isinstance(creator_permissions, list), "bootstrap_creator.permissions must be a list")
    require(
        {permission_key(validate_bootstrap_creator_permission(permission, index)) for index, permission in enumerate(creator_permissions)}
        == EXPECTED_BOOTSTRAP_CREATOR,
        "bootstrap_creator permissions must be the explicit short-lived token-mint set",
    )

    permissions = catalog.get("permissions")
    require(isinstance(permissions, list) and permissions, "permissions must be a non-empty list")
    seen = set()
    for index, permission in enumerate(permissions):
        validate_operator_permission(permission, index, profiles, surface_aliases)
        key = permission_key(permission)
        require(key not in seen, f"permissions contains duplicate entry for {key}")
        seen.add(key)
        require(
            not permission["name"].startswith(TOKEN_MINT_PERMISSION_PREFIX),
            "operator profiles must not include Account API Tokens permissions",
        )

    for profile_name in profiles:
        selected = profile_permissions(catalog, profile_name)
        require(selected, f"profile {profile_name} must select at least one permission")
        validate_profile_minimality(profile_name, profiles[profile_name], selected)
        if profile_name == "full-operator":
            require(
                not any(permission["name"].startswith(TOKEN_MINT_PERMISSION_PREFIX) for permission in selected),
                "full-operator must still exclude token-minting permissions",
            )


def validate_bootstrap_creator_permission(permission: object, index: int) -> dict:
    require(isinstance(permission, dict), f"bootstrap_creator.permissions[{index}] must be an object")
    name = require_string(permission.get("name"), f"bootstrap_creator.permissions[{index}].name")
    scope = require_string(permission.get("scope"), f"bootstrap_creator.permissions[{index}].scope")
    require(scope in ALLOWED_SCOPES, f"bootstrap_creator.permissions[{index}].scope is unsupported: {scope}")
    require_string(permission.get("reason"), f"bootstrap_creator.permissions[{index}].reason")
    return {"name": name, "scope": scope}


def validate_operator_permission(
    permission: object,
    index: int,
    profiles: dict,
    surface_aliases: set[str],
) -> None:
    require(isinstance(permission, dict), f"permissions[{index}] must be an object")
    name = require_string(permission.get("name"), f"permissions[{index}].name")
    scope = require_string(permission.get("scope"), f"permissions[{index}].scope")
    require(scope in ALLOWED_SCOPES, f"permissions[{index}] {name} has unsupported scope: {scope}")

    surfaces = require_string_list(permission.get("surfaces"), f"permissions[{index}].surfaces")
    missing_surfaces = sorted(surface for surface in surfaces if surface not in surface_aliases)
    require(not missing_surfaces, f"permissions[{index}] {name} references unknown surfaces: {missing_surfaces}")

    selected_profiles = require_string_list(permission.get("profiles"), f"permissions[{index}].profiles")
    missing_profiles = sorted(profile for profile in selected_profiles if profile not in profiles)
    require(not missing_profiles, f"permissions[{index}] {name} references unknown profiles: {missing_profiles}")


def permission_matches_any(name: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns)


def validate_profile_minimality(profile_name: str, profile: dict, permissions: list[dict]) -> None:
    allowed_surfaces = set(profile["allowed_surfaces"])
    forbidden_permissions = profile["forbidden_permissions"]
    risk = profile["risk"]

    for permission in permissions:
        name = permission["name"]
        surfaces = set(permission["surfaces"])

        if "*" not in allowed_surfaces:
            extra_surfaces = sorted(surfaces - allowed_surfaces)
            require(
                not extra_surfaces,
                f"profile {profile_name} includes {name} outside allowed_surfaces: {extra_surfaces}",
            )

        require(
            not permission_matches_any(name, forbidden_permissions),
            f"profile {profile_name} includes forbidden permission {name}",
        )

        if risk == "read":
            require(
                not permission_matches_any(name, ["* Write", "* Revoke", "* Run"]),
                f"read profile {profile_name} includes non-read permission {name}",
            )


def validate_command_fixtures(catalog: dict) -> list[dict]:
    fixtures = [
        {
            "profile": "dns",
            "zone": "example.com",
            "zone_id": "",
            "token_name": "",
            "ttl_hours": None,
            "args": ["bootstrap", "permissions", "--profile", "dns", "--zone", "example.com"],
            "expected": (
            "cfctl token mint --name 'cfctl-dns-operator' --permission 'DNS Read' "
            "--permission 'DNS Write' --permission 'Zone Read' --zone 'example.com' "
            "--ttl-hours 168 --plan"
            ),
        },
        {
            "profile": "hostname",
            "zone": "example.com",
            "zone_id": "",
            "token_name": "",
            "ttl_hours": None,
            "args": ["bootstrap", "permissions", "--profile", "hostname", "--zone", "example.com"],
            "expected": (
            "cfctl token mint --name 'cfctl-hostname-operator' "
            "--permission 'Access: Apps and Policies Read' "
            "--permission 'Access: Apps and Policies Write' --permission 'DNS Read' "
            "--permission 'DNS Write' --permission 'SSL and Certificates Read' "
            "--permission 'SSL and Certificates Write' --permission 'Workers Routes Read' "
            "--permission 'Workers Routes Write' --permission 'Workers Scripts Read' "
            "--permission 'Zone Read' --zone 'example.com' --ttl-hours 168 --plan"
            ),
        },
        {
            "profile": "deploy",
            "zone": "",
            "zone_id": "023e105f4ecef8ad9ca31a8372d0c353",
            "token_name": "",
            "ttl_hours": None,
            "args": [
                "bootstrap",
                "permissions",
                "--profile",
                "deploy",
                "--zone-id",
                "023e105f4ecef8ad9ca31a8372d0c353",
            ],
            "expected": (
            "cfctl token mint --name 'cfctl-deploy-operator' --permission 'Account Settings Read' "
            "--permission 'D1 Metadata Read' --permission 'D1 Read' --permission 'D1 Write' "
            "--permission 'Pages Read' --permission 'Pages Write' --permission 'Queues Read' "
            "--permission 'Queues Write' --permission 'Workers R2 Storage Read' "
            "--permission 'Workers R2 Storage Write' --permission 'Workers Routes Read' "
            "--permission 'Workers Routes Write' --permission 'Workers Scripts Read' "
            "--permission 'Workers Scripts Write' --permission 'Zone Read' "
            "--zone-id '023e105f4ecef8ad9ca31a8372d0c353' --ttl-hours 168 --plan"
            ),
        },
    ]

    for fixture in fixtures:
        command = render_plan_command(
            catalog,
            fixture["profile"],
            zone=fixture["zone"],
            zone_id=fixture["zone_id"],
            token_name=fixture["token_name"],
            ttl_hours=fixture["ttl_hours"],
        )
        require(
            command == fixture["expected"],
            f"{fixture['profile']} fixture drifted:\nexpected: {fixture['expected']}\nactual:   {command}",
        )

    read_command = render_plan_command(catalog, "read")
    require("--all-zones-in-account" in read_command, "read fixture must include zone resource coverage")
    require("Account API Tokens" not in read_command, "read fixture must not include token-minting permissions")
    require("--ttl-hours 720 --plan" in read_command, "read fixture must use 720-hour ttl")

    full_operator_command = render_plan_command(catalog, "full-operator")
    require("Account API Tokens" not in full_operator_command, "full-operator fixture must not include token-minting permissions")
    require("--ttl-hours 168 --plan" in full_operator_command, "full-operator fixture must use 168-hour ttl")

    return fixtures


def credentialless_cfctl_env() -> dict[str, str]:
    env = os.environ.copy()
    for key in (
        "CF_DEV_TOKEN",
        "CF_GLOBAL_TOKEN",
        "CLOUDFLARE_ACCOUNT_ID",
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_API_KEY",
        "CF_ACTIVE_AUTH_SECRET",
        "CF_ACTIVE_AUTH_SCHEME",
        "CF_ACTIVE_TOKEN_ENV",
        "CF_ACTIVE_TOKEN_LANE",
    ):
        env.pop(key, None)
    return env


def run_cfctl_json(cfctl: Path, args: list[str], env: dict[str, str]) -> dict:
    process = subprocess.run(
        [str(cfctl), *args],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(
        process.returncode == 0,
        f"cfctl {' '.join(args)} failed with exit {process.returncode}: {process.stderr.strip()}",
    )
    try:
        return json.loads(process.stdout)
    except json.JSONDecodeError as exc:
        fail(f"cfctl {' '.join(args)} did not return JSON: {exc}: {process.stdout[:500]}")


def run_cfctl_failure(cfctl: Path, args: list[str], env: dict[str, str], expected_stderr: str) -> None:
    process = subprocess.run(
        [str(cfctl), *args],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    require(process.returncode != 0, f"cfctl {' '.join(args)} unexpectedly succeeded")
    require(
        expected_stderr in process.stderr,
        f"cfctl {' '.join(args)} stderr did not include {expected_stderr!r}: {process.stderr.strip()}",
    )


def validate_cfctl_fixtures(catalog: dict, cfctl: Path) -> None:
    fixtures = validate_command_fixtures(catalog)
    cfctl = cfctl.resolve()
    require(cfctl.exists(), f"cfctl path does not exist: {cfctl}")

    with tempfile.TemporaryDirectory(prefix="cfctl-permission-catalog.") as tmp_dir:
        env = credentialless_cfctl_env()
        shared_env = Path(tmp_dir) / "empty.env"
        shared_env.write_text("")
        env["CF_SHARED_ENV_FILE"] = str(shared_env)
        env["CF_REPO_ENV_FILE"] = str(Path(tmp_dir) / "missing.env")

        for fixture in fixtures:
            payload = run_cfctl_json(cfctl, fixture["args"], env)
            plan_command = payload.get("summary", {}).get("plan_command")
            require(
                plan_command == fixture["expected"],
                (
                    f"cfctl fixture {fixture['profile']} drifted:\n"
                    f"expected: {fixture['expected']}\nactual:   {plan_command}"
                ),
            )

        read_payload = run_cfctl_json(cfctl, ["bootstrap", "verify", "--profile", "read"], env)
        require(
            read_payload.get("result", {}).get("verification", {}).get("runnable_now") is True,
            "read-profile bootstrap verification should be runnable without a zone",
        )

        run_cfctl_failure(cfctl, ["bootstrap", "permissions", "--profile"], env, "--profile requires a value")
        run_cfctl_failure(
            cfctl,
            ["bootstrap", "permissions", "--profile", "dns", "--zone", "example.com", "--zone-id", "023e105f4ecef8ad9ca31a8372d0c353"],
            env,
            "Pass only one of --zone or --zone-id",
        )
        run_cfctl_failure(
            cfctl,
            ["bootstrap", "permissions", "--profile", "dns", "--ttl-hours", "24 --reveal-token-once"],
            env,
            "--ttl-hours must be a positive integer",
        )
        env_with_bad_ttl = env.copy()
        env_with_bad_ttl["CFCTL_BOOTSTRAP_TTL_HOURS"] = "24 --reveal-token-once"
        run_cfctl_failure(
            cfctl,
            ["bootstrap", "permissions", "--profile", "dns"],
            env_with_bad_ttl,
            "--ttl-hours must be a positive integer",
        )


def extract_permission_groups(path: Path) -> list[dict]:
    payload = load_json(path)
    result = payload.get("result") if isinstance(payload, dict) else None
    if isinstance(result, dict) and isinstance(result.get("permission_groups"), list):
        return result["permission_groups"]
    if isinstance(result, list):
        return result
    if isinstance(payload, dict) and isinstance(payload.get("permission_groups"), list):
        return payload["permission_groups"]
    fail(f"{path} does not look like a permission-groups artifact")


def validate_against_permission_groups(catalog: dict, permission_groups_path: Path) -> None:
    groups = extract_permission_groups(permission_groups_path)
    available = {
        (group.get("name"), scope)
        for group in groups
        for scope in group.get("scopes", [])
    }

    required = [
        *catalog["bootstrap_creator"]["permissions"],
        *catalog["permissions"],
    ]
    missing = []
    for permission in required:
        cloudflare_scope = CLOUDFLARE_SCOPE[permission["scope"]]
        key = (permission["name"], cloudflare_scope)
        if key not in available:
            missing.append({"name": permission["name"], "scope": permission["scope"], "cloudflare_scope": cloudflare_scope})

    require(not missing, f"permission-group drift detected: {json.dumps(missing, indent=2)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate cfctl bootstrap permission catalog shape and drift.")
    parser.add_argument(
        "--permission-groups",
        type=Path,
        help="Optional cfctl token permission-groups artifact used for live drift validation.",
    )
    parser.add_argument(
        "--cfctl",
        type=Path,
        help="Optional cfctl executable used to compare command fixtures against real bootstrap output.",
    )
    args = parser.parse_args()

    catalog = load_json(CATALOG_PATH)
    surfaces = load_json(SURFACES_PATH)
    runtime = load_json(RUNTIME_PATH)

    validate_catalog_shape(catalog, surfaces, runtime)
    validate_command_fixtures(catalog)
    if args.permission_groups is not None:
        validate_against_permission_groups(catalog, args.permission_groups)
    if args.cfctl is not None:
        validate_cfctl_fixtures(catalog, args.cfctl)

    print("permission-catalog verification passed")


if __name__ == "__main__":
    main()

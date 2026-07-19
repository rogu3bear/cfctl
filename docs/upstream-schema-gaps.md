# Upstream Cloudflare OpenAPI gaps (root cause of the blocked-capability wall)

`cfctl`'s catalog is generated from Cloudflare's official OpenAPI at
`cloudflare/api-schemas` (`openapi.json`). A capability is marked `blocked`
when the schema does not carry the metadata cfctl needs to govern a mutation
**fail-closed** — required permission scope, and a bounded/known incremental
cost. cfctl will **not fabricate** either: a guessed permission or price is
worse than an honest block. Two upstream gaps, neither of which cfctl can
safely close on its own, account for **83%** of blocked capabilities.

This document exists to be filed against `cloudflare/api-schemas`. It is not a
coverage report — **`cfctl catalog coverage` owns the current numbers and
supersedes anything here whenever they disagree** (per `LAYERS.md`, catalog
outranks prose). The counts below are a frozen 2026-07-17 snapshot of
`cloudflare/api-schemas@main`, kept so the argument stays legible.

## Gap 1 — mutating operations carry no permission annotation

**1436** mutating operations declare `x-api-token-group` (the API-token
permission group required to call them). **242** mutating operations
(POST/PUT/PATCH/DELETE), spread across 95 products, declare neither
`x-api-token-group` nor `x-cfPermissionsRequired` — no permission signal at
all. A programmatic client cannot determine what token scope these operations
require, so it cannot mint a least-privilege token or fail closed correctly.

Representative cases:

- `origin-cloud-regions-create` — POST `/zones/{zone_id}/cache/origin_cloud_regions`
- `origin-cloud-regions-v2-batch-upsert` — PUT `/zones/{zone_id}/origin/cloud_regions/batch`
- `SubmitAbuseReport` — POST `/accounts/{account_id}/abuse-reports/{report_param}`

**Ask:** add `x-api-token-group` to the unannotated operations, consistent
with the 1436 mutating operations that already declare it.

## Gap 2 — no machine-readable per-operation cost signal

The schema has **no operation-level pricing extension** anywhere. The only
cost-adjacent metadata is `x-cfPlanAvailability` (652 mutating operations),
which states *which plans* may call an operation — not the **incremental
cost** of invoking it. cfctl therefore cannot bound the cost of a paid
mutation, and blocks **1336** mutating capabilities as cost-unknown rather
than risk a governed approval that hides a real charge.

Heaviest affected products: Workers AI Text Generation (59),
`dos-flowtrackd-api_other` (23), Event (21), Workers for Platforms (15),
brapi (14), Brand Protection (13), R2 Bucket (13).

**Ask:** add a machine-readable per-operation cost signal (e.g. `x-cf-pricing`
with a model such as `free` | `flat` | `usage`, plus currency and unit where
known) to paid operations, starting with those families.

## Reproduce

Both operation lists are derived, not curated — regenerate them rather than
maintaining copies here.

```sh
curl -sS -o openapi.json \
  https://raw.githubusercontent.com/cloudflare/api-schemas/main/openapi.json

# Gap 1: mutating ops missing all permission annotation
python3 - <<'EOF'
import json; s=json.load(open('openapi.json')); MUT={'post','put','patch','delete'}
miss=[ (o.get('operationId'),m,p) for p,ms in s['paths'].items() for m,o in ms.items()
       if m in MUT and isinstance(o,dict)
       and 'x-api-token-group' not in o and 'x-cfPermissionsRequired' not in o ]
print(len(miss))
for op,m,p in sorted(miss, key=lambda r: str(r[0])): print(f"{op} — {m.upper()} {p}")
EOF
```

For the live, authoritative view of what is blocked and why — including the
per-field gap counts cfctl actually enforces — use the catalog:

```sh
cfctl catalog coverage --json
cfctl catalog show <capability-id> --json
```

_Counts drift as the schema evolves._

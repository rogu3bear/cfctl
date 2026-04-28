# Live Inventory

## Full Bootstrap

Run:

```bash
./scripts/cf_agent_bootstrap.sh
```

This captures:

- auth verification
- account profile and zones
- Worker topology
- Workers AI posture
- Pages
- D1
- KV
- R2
- Queues
- Workflows
- Images
- Stream
- Calls
- Hyperdrive
- Vectorize
- AI Gateway
- Workers inventory
- Access applications
- Access drift audit
- Zero Trust inventory
- Extended Zero Trust posture
- Zero Trust fleet, DLP, and CASB posture
- Browser Isolation posture
- Turnstile
- Load balancing
- Zone security rulesets
- Zone security matrix
- WAF and bot-management posture
- API Shield posture
- GraphQL analytics capability
- Registrar and nameserver posture
- Protected surfaces
- SSL posture
- waiting rooms
- Logpush
- Token permission probes
- Open-beta products
- Containers
- mTLS certificates
- Secrets Store
- VPC services
- Pipelines
- tunnels
- email routing
- Wrangler `whoami` output

For the preferred public runtime contract on top of these inventories, use:

```bash
cfctl lanes
cfctl list surfaces
cfctl explain pages.project
cfctl list pages.project
cfctl snapshot tunnel
CF_TOKEN_LANE=global cfctl diff dns.record --zone example.com
```

## Runtime-First Reads

Use `cfctl` when you want a stable public interface:

```bash
cfctl list zone
cfctl list worker.script
cfctl list worker.route --zone example.com
cfctl list pages.project
cfctl list d1.database
cfctl list r2.bucket
cfctl list queue
cfctl list workflow
cfctl list access.app
cfctl list tunnel
```

Use backend inventory scripts when you need the broader living bank or a surface that is not yet mapped to a first-class `cfctl` read:

```bash
./scripts/cf_inventory_zones.sh
./scripts/cf_inventory_worker_topology.sh
./scripts/cf_inventory_workers_ai.sh
./scripts/cf_inventory_pages.sh
./scripts/cf_inventory_d1.sh
./scripts/cf_inventory_kv.sh
./scripts/cf_inventory_r2.sh
./scripts/cf_inventory_queues.sh
./scripts/cf_inventory_workflows.sh
./scripts/cf_inventory_images.sh
./scripts/cf_inventory_stream.sh
./scripts/cf_inventory_calls.sh
./scripts/cf_inventory_hyperdrive.sh
./scripts/cf_inventory_vectorize.sh
./scripts/cf_inventory_ai_gateway.sh
./scripts/cf_inventory_dns.sh
./scripts/cf_audit_access_apps.sh
./scripts/cf_inventory_zero_trust.sh
./scripts/cf_inventory_zero_trust_extended.sh
./scripts/cf_inventory_zero_trust_fleet.sh
./scripts/cf_inventory_browser_isolation.sh
./scripts/cf_inventory_turnstile.sh
./scripts/cf_inventory_load_balancing.sh
./scripts/cf_inventory_zone_security.sh
./scripts/cf_inventory_zone_security_matrix.sh
./scripts/cf_inventory_waf_bot_management.sh
./scripts/cf_inventory_api_shield.sh
./scripts/cf_inventory_graphql_analytics.sh
./scripts/cf_inventory_registrar.sh
./scripts/cf_inventory_protected_surfaces.sh
./scripts/cf_inventory_ssl_posture.sh
./scripts/cf_inventory_waiting_rooms.sh
./scripts/cf_inventory_logpush.sh
./scripts/cf_probe_token_permissions.sh
./scripts/cf_inventory_open_beta.sh
./scripts/cf_inventory_containers.sh
./scripts/cf_inventory_mtls_certs.sh
./scripts/cf_inventory_secrets_store.sh
./scripts/cf_inventory_vpc.sh
./scripts/cf_inventory_pipelines.sh
./scripts/cf_inventory_capability_audit.sh
```

Single zone:

```bash
ZONE_NAME=example.com ./scripts/cf_inventory_dns.sh
```

Summary-only DNS:

```bash
INCLUDE_RECORDS=0 ./scripts/cf_inventory_dns.sh
```

## Output Locations

- JSON snapshots: `var/inventory/`
- operation snapshots: `var/inventory/operations/`
- logs: `var/logs/`

These are the living bank. Agents should update them after real reads and after meaningful mutations.

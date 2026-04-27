# Tunnels

## Inventory

Read remotely-managed tunnel inventory:

```bash
./scripts/cf_inventory_tunnels.sh
```

Include remote tunnel configuration objects:

```bash
INCLUDE_CONFIG=1 ./scripts/cf_inventory_tunnels.sh
```

## Runtime

Use the wrapper so `cloudflared` runs from repo-local home state:

```bash
./scripts/cf_cloudflared.sh version
./scripts/cf_cloudflared.sh tunnel list
```

If you need to run a remotely-managed tunnel directly, provide the tunnel token through env and invoke `cloudflared` normally through the wrapper. Keep tunnel runtime secrets out of committed files and inventory snapshots.

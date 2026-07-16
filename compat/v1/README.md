# Retained cfctl v1 data

Everything below this directory is frozen, non-executable migration evidence
from the retired shell control plane. Command examples, backend paths, auth
lanes, preview semantics, and composite surfaces here describe v1 only. Do not
run them and do not treat them as current cfctl guidance.

The live v2 authorities are the Clap command tree, the managed `CapabilityV1`
catalog under `CFCTL_HOME`, typed guides, and their checked projections. Start
with:

```bash
cfctl guide --topic system
cfctl catalog search "<intent>" --json
```

The retained roots have deliberately different roles:

- `catalog/` is static reference data. Rust v2 never loads it.
- `state/` is safe desired-state and evidence input for `cfctl migrate v1`.
  The importer preserves `state` as the destination label. External v1
  workspaces with a top-level `state/` remain supported when this quarantined
  repo-local root is absent.

[`manifest.json`](manifest.json) is the machine-readable quarantine contract.
`cargo xtask verify` binds its roots, retired verb inventory, and retired
surface inventory to both the live Clap contract and the frozen catalog so
retained v1 material cannot drift back into the executable command surface.

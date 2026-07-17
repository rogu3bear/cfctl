# Legacy namespace

The retired shell and Python control plane is not operational and is not a
fallback. Its hash-bound private source archive is migration evidence only.

The small amount of checked-in v1 data retained for the compatibility window
lives under [`compat/v1/`](../compat/v1/README.md), where its non-executable
status and only permitted consumer are machine-checked. New capabilities must
be added to the Rust v2 catalog, parser, guides, tests, and agent discovery
together.

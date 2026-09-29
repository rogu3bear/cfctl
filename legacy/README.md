# Legacy namespace

The retired shell and Python control plane is not operational and is not a
fallback. Its hash-bound private source archive is migration evidence only.

The checked-in v1 data retained for the compatibility window and the
`migrate v1` command were removed on 2026-09-29; the last commit containing them
is tagged `archive/cfctl-v1-compat-20260929`. New capabilities must be added
to the Rust catalog, parser, guides, tests, and agent discovery together.

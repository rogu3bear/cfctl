# cfctl website product packet

Status: evidence-bound planning for the cfctl product site. This packet does
not change the repository's current public-domain authority.

These documents separate observed repository and market evidence from hypotheses.
They do not claim user research, production deployment, or outcome data that
does not exist.

Authority is consumer-specific:

- [`../../README.md`](../../README.md) owns product meaning;
  [`../../docs/runtime-policy.md`](../../docs/runtime-policy.md) owns runtime
  policy; and [`../../docs/v2-security.md`](../../docs/v2-security.md) owns the
  CLI credential, secret, journal, redaction, and per-capability security
  contract within the scope it declares.
- [`../SECURITY.md`](../SECURITY.md) owns the website security policy, and
  [`../site-threat-model.md`](../site-threat-model.md) owns the current site
  threat boundary and analysis.
- [`ACCEPTANCE_CRITERIA.md`](ACCEPTANCE_CRITERIA.md) owns the intended site
  outcomes and review conditions.
- Implemented site behavior lives in [`../src`](../src) and
  [`../style/main.css`](../style/main.css). Its current verification state is
  recorded against the acceptance criteria in
  [`LAUNCH_CHECKLIST.md`](LAUNCH_CHECKLIST.md); source presence alone is not
  rendered or release proof.

## Decision order

1. Repair installed credential routing drift.
2. Define the audience, outcome, risks, and measurable activation path.
3. Review the implemented Leptos surface against the acceptance criteria at
   wide and narrow viewports.
4. Close rendered, accessibility, security, and release proof gaps without
   inventing a parallel prose design authority.
5. Prepare and review the exact Cloudflare plan before approval and apply.

`RELEASE_NOTES_DRAFT.md` covers changes already merged to repository `main`; it is not evidence of a public version or website deployment.

## Evidence classes

- Observed: repository source, tests, authenticated readback, or primary source.
- Inferred: a reasoned conclusion from observed evidence.
- Proposed: a product or design choice awaiting validation.

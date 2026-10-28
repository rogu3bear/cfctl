# Audit query date contracts

Legacy user/account audit controls accept either a UTC date-only value or an
RFC3339 timestamp. Shared request validation checks date-only values as exactly
ten ASCII bytes in YYYY-MM-DD form followed by calendar validation. Timestamp
validation retains its existing RFC3339 parser. These alternatives are disjoint,
so a valid timestamp satisfies exactly one branch of the legacy union.

Audit-v2 account/organization list and history operations describe the same two
forms, although their provider schemas annotate since and before as date only.
The catalog corrects only those eight selectors, matching each exact read
operation ID/path pair, the plain string/date schema and the reviewed description
(with whitespace normalization only). Added constraints or other drift are left
unchanged. Requiredness, query serialization, pagination, permissions, risk,
response contracts and history action_time validation are preserved.

This source correction does not update an installed catalog. Qualification of
the source and publication of a PR remain separate from installation and catalog
adoption. A new strict-date backend with an old plain-date audit-v2 catalog will
reject timestamp values for those controls until the corrected catalog is
separately adopted and its eight selectors inspected. Preserve the prior runtime
and catalog for the owning rollback procedure; do not drop query bounds or
weaken oneOf to work around drift. Offline request construction proves local
validation and encoding, not provider access or retained audit-history coverage.

Provider contracts: [account logs](https://developers.cloudflare.com/api/resources/accounts/subresources/logs/subresources/audit/methods/list/),
[account history](https://developers.cloudflare.com/api/resources/accounts/subresources/logs/subresources/audit/methods/history/),
[organization logs](https://developers.cloudflare.com/api/resources/organizations/subresources/logs/subresources/audit/methods/list/).
Date formats follow the [JSON Schema date/time definitions](https://json-schema.org/draft/2020-12/json-schema-validation#section-7.3.1).

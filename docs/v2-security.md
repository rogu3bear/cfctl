# cfctl v2 security contract

- OAuth uses Authorization Code with PKCE. Refresh tokens and imported keys live only in the macOS Keychain or Linux Secret Service.
- The emergency global-key profile is never selected implicitly.
- Secret-shaped request bodies are accepted only through stdin, stored temporarily in the platform secret store, and represented in plans by a hash and opaque reference.
- Secret-producing responses require `--value-out`; the destination must not exist and is created mode `0600` on Unix. Receipts contain `[SUNK]`, not the value.
- Delegated subprocesses start with a cleared environment. cfctl restores only `PATH`, `HOME`, `NO_COLOR`, and the selected Cloudflare credential variables.
- Evidence is redacted before it is content-addressed and written atomically. Presence of evidence is not proof that an operation was performed or verified.
- Plans are one-use transactions. Their content, schema, account, targets, impact, policy, and approval are hash-bound.
- Mutation capabilities fail closed unless risk, effect, incremental cost, permissions, entitlement, operation-specific verification, and rollback or explicit irreversibility are known.
- Official product pricing indexes enrich catalog cost knowledge, but variable resource or usage pricing remains unbounded and therefore non-executable. An official pricing link is evidence, not a cost ceiling.
- Plans pin a hash of the executable capability catalog, including locally maintained adapter and safety contracts. The upstream OpenAPI hash is retained separately as source evidence.
- Each transaction stage is appended to a hash-chained journal before or after its corresponding boundary: plan, approval, consumption, adapter attempt/response, secret sink, verification attempt/response, compensation, and close. Journal drift or a missing predecessor blocks execution.
- A crash after durable consumption or an adapter-boundary attempt requires rectification; cfctl does not replay the mutation. Verification failure also enters rectification instead of being reported as success.
- Native token mint, value-roll, and revoke operations use live token-detail readbacks. Creation and rotation require the planned token to be active; revocation requires a not-found readback.
- The journal detects local file drift and inconsistent stage transitions. It is not a substitute for operating-system account integrity or a hardware-backed signature against a privileged local attacker.
- Telemetry is off. Local receipts leave the machine only through an explicit operator action such as attaching one to a pull request.

Report a suspected secret leak by preserving the operation ID and redacted receipt path, revoking the affected credential, and avoiding copies of the raw value in issues or chat.

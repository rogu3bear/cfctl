# Edge cases

## Install and credential path

| Case | Expected behavior |
|---|---|
| PATH resolves to an older `cfctl` | `doctor` identifies the mismatch; site tells the user to verify build identity before debugging credentials. |
| macOS Keychain is unavailable while fallback secrets exist | Ordinary operations remain on governed fallback without prompting; only explicit repair may inspect Keychain. |
| Selected profile has no credential | Read fails locally with a scoped next step; no broad credential suggestion. |
| Token is valid but lacks capability permission | Live read returns a redacted authorization failure and required permission lane; no automatic scope escalation. |
| Multiple accounts are possible | Import/call stays account-pinned and ambiguity fails closed. |
| Secret pasted into a command argument | Documentation rejects the pattern and uses stdin or mode-0600 file input. |

## Content and interaction

| Case | Expected behavior |
|---|---|
| JavaScript or Wasm unavailable | SSR content, commands, navigation, privacy, and security remain usable. |
| Clipboard API denied | Command stays selectable; the control reports failure without losing text. |
| Very long command or error code | Wrap inside the component or provide local horizontal scrolling without page overflow. |
| Long localization or enlarged text | Layout reflows; no fixed-height cards or clipped actions. |
| Reduced motion / high contrast | No meaning depends on animation, blur, transparency, or color alone. |
| External source link fails | Site content still explains the core contract and labels external navigation. |

## Routing and edge runtime

| Case | Expected behavior |
|---|---|
| Direct request to a nested route | Worker SSR and Router return the route; static asset matching does not swallow it. |
| Unknown route | Accessible 404 content and correct recovery links. |
| Asset hash/HTML drift | Deployment verification fails before declaring success. |
| Stale CDN response after deploy | Live read checks source/version marker and triggers rollback or cache diagnosis. |
| Hydration mismatch | Console/error proof fails release; SSR content remains the diagnostic baseline. |
| Worker exception | No credentials, environment details, or stack traces in the public response. |

## OAuth callback bridge

| Case | Expected behavior |
|---|---|
| Missing, empty, duplicated, or oversized `state` or `code` | Reject locally; never construct a success payload. |
| OAuth `error` or `error_description` is attacker-controlled | Render bounded inert text without reflecting arbitrary detail or markup. |
| Query contains control characters, whitespace, or a fake `STATE CODE` delimiter | Reject before display or copy. |
| Stylesheet, icon, telemetry, or error reporter loads before query removal | Release fails; callback must not propagate its URL as a referrer or third-party request. |
| Clipboard permission is denied or the API is unavailable | Keep the bounded payload selectable, explain manual copy, and do not claim success. |
| User navigates back, restores bfcache, backgrounds the tab, or waits past expiry | Clear the payload and require a fresh login attempt where safe reuse cannot be proven. |
| Callback response is cached | Release fails; route requires `Cache-Control: no-store` and no service-worker persistence. |
| JavaScript is disabled | Do not render query values; explain how to retry with script enabled or cancel safely. |
| Callback is embedded by another origin | Framing is denied; no UI redress path may expose or copy the value. |
| Worker/request logs include the query string | Treat as sensitive exposure and block launch until logs are disabled, redacted, or proven not to retain it. |

## Product claims

| Case | Expected behavior |
|---|---|
| Capability is cataloged but blocked | Copy says discoverable/blocked, not supported execution. |
| Mutation has no verifier or rollback | Copy surfaces the limitation and does not use “safe” or “complete.” |
| Deployment succeeds but live read fails | Launch remains incomplete. |
| Analytics sample is too small or bot-heavy | No conversion conclusion or OKR grade. |
| WebGPU visual fails or is inaccessible | Not applicable for v1; do not ship it without a validated job and fallback. |

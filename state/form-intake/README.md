# form.intake State

`form.intake` specs describe one public user-submission path end to end:
route, owner, submitted fields, honeypot fields, Turnstile, Cloudflare Access
posture, Resend mode, and storage/log readback sinks.

Use the composite command when the question is whether users can see the form,
submit it, receive a response, and leave evidence in the expected sink:

```bash
cfctl form-intake init --url https://example.com/contact
cfctl form-intake verify --file state/form-intake/example.json
cfctl form-intake snapshot --file state/form-intake/example.json
cfctl form-intake diff --file state/form-intake/example.json
cfctl form-intake plan --file state/form-intake/example.json
```

`form-intake plan` emits proposed component operations only. Real changes stay
on preview-gated component surfaces such as `turnstile.widget`, `pages.secret`,
`worker.secret`, `access.app`, `access.policy`, `sender_domain`, and storage
wrapper commands.

Production synthetic submissions are disabled by default. If a spec enables
them, it must include a test marker and the verifier must produce bounded
response plus readback evidence.

Known limitation: page checks read the raw fetched HTML without executing
JavaScript. Client-side-rendered forms (for example Leptos/WASM sites) report
`page_form_missing`/`page_field_missing` even when the form renders correctly
in a browser. Read those drift classes alongside `source_*` and Cloudflare
checks before treating a client-rendered intake as broken.

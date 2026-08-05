# Acceptance criteria

## Product and content

- Given a visitor lands on `/`, when they scan the first viewport and lifecycle region, then they can identify the audience, local-first credential promise, and that mutations produce plans before execution.
- Given any published command, when CI checks it against the exact CLI tree, then stale or nonexistent subcommands fail the build.
- Given a blocked or delegated capability is described, when the visitor reads the copy, then the site does not imply native execution or completed verification.
- Given the release version changes, when the site builds, then version-specific installation copy is updated from one owned source or the build fails.

## Routes and SSR

- Given JavaScript is disabled, when `/`, `/start`, `/security`, `/privacy`, `/terms`, or an unknown route is requested, then useful semantic HTML and correct status behavior are returned.
- Given a deep link is opened before hydration, when Workers serves it, then the Leptos router receives the request rather than returning an asset-only 404.
- Given an unknown route, when requested, then the response shows an accessible not-found path and does not expose internal runtime details.

## Interaction and accessibility

- Given keyboard-only navigation, when a user traverses the header, copy controls, and links, then focus is visible, order follows DOM meaning, and no trap exists.
- Given `prefers-reduced-motion: reduce`, when the page loads and state changes, then nonessential motion is removed and meaning is preserved.
- Given 200% zoom or a 320px viewport, when code and lifecycle content render, then the page has no horizontal overflow and actions remain reachable.
- Given copy-to-clipboard is unavailable or denied, when a copy control is used, then the command remains selectable and an honest failure state appears.

## Performance and resilience

- Given first navigation, when the server responds, then primary content does not depend on hydration.
- Given the Wasm bundle fails to load, when the user reads or follows ordinary links, then core content remains usable.
- Given a static asset hash changes, when deployed, then HTML references the new asset and stale immutable assets cannot replace current markup authority.

## Security and release

- Given a production deployment, when it is reviewed, then source SHA, target, plan, approval, apply receipt, rollback, and authenticated live readback are distinct and recorded.
- Given site analytics are absent, when launched, then no undeclared third-party tracking request is emitted.
- Given analytics are later proposed, when reviewed, then event content, retention, consent, and prohibited identifiers are documented before implementation.

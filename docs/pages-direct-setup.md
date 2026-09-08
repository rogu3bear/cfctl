# Direct-upload Pages project setup

The generated catalog exposes two bounded setup operations when the official
Pages request, permission and readback schemas support them. The existing
`pages-project-create-project` capability retains its Git-integration contract;
the broad `pages-project-update-project` capability retains its existing gates.

## Create an empty project

```sh
cfctl guide pages-project-create-direct-upload --json
cfctl call pages-project-create-direct-upload \
  --profile <scoped-profile> --account <account-id> \
  --selector account_id=<account-id> \
  --body-json '{"name":"example-site","production_branch":"main"}' --json
```

The body permits only `name` and `production_branch: "main"`. Git source,
build configuration, deployment configuration and unknown fields are refused.
The selected account must be the intended account for the scoped profile.

Preparation performs the native exact-project GET. Only HTTP 404 with the
single Pages project-not-found code `8000007` proves absence. Execution
repeats that read before consuming the reviewed plan and attempting the POST.
The verifier joins the returned project ID to a fresh exact-name GET and
requires `main`, no Git source and no configured build.

Review the returned operation ID and its plan, then use the normal exact-plan
approval and execution lifecycle:

```sh
cfctl plans show <operation-id> --json
cfctl plans approve <operation-id> --yes --json
cfctl plans run <operation-id> --json
```

Creation has no direct API-operation charge and starts no build or deployment.
Later deployment and Functions usage remain subject to the current account
plan. This capability does not change that plan. Deleting the project is a
separate reviewed operation and removes any deployments added afterward.

## Add production variables

```sh
cfctl guide pages-project-add-production-variables --json
cfctl call pages-project-add-production-variables \
  --profile <scoped-profile> --account <account-id> \
  --selector account_id=<account-id> --selector project_name=example-site \
  --body-stdin --json < /absolute/private/pages-variables.json
```

The protected input contains only this structure, with actual values supplied
privately through stdin:

```json
{
  "deployment_configs": {
    "production": {
      "env_vars": {
        "SITE_ORIGIN": {"type": "plain_text", "value": "https://example.invalid"},
        "SERVICE_KEY": {"type": "secret_text", "value": "<private-value>"}
      }
    }
  }
}
```

Every requested variable name must be absent in the native project read and
remain absent at the execution-boundary recheck. The plan binds the project
ID, full configuration commitment and exact protected-input commitment.
Existing values, preview configuration, build/Git configuration, usage model,
resource bindings, deletion through `null` and unknown fields are excluded.
Variable names use ASCII letters, digits and underscore, starting with a
letter or underscore. The body contains 1–100 variables with nonempty string
values of at most 5,120 UTF-8 bytes each.

The complete body uses the existing credential-store reference/hash lifecycle.
Plans and receipts retain names, types and commitments, and no variable
values. A secret output sink is unnecessary because this operation produces
no new secret. Pages project responses project environment variables into
name/type records so secret-shaped names do not lose their type under the
generic secret-key redactor. Provider error prose is redacted as well.

After PATCH, native GET must show the same project ID, every added name/type,
exact plain-text values and unchanged sibling configuration. Secret values
are write-only: provider acceptance plus name/type readback proves their
configuration, not their value or application usability. A subsequent
deployment and an application check establish use by the application.

The setup mutations are attempted once. A transport failure, HTTP 429 or HTTP
5xx leaves an unknown outcome for rectification and never authorizes replay.
The absence and configuration reads do not provide an atomic lock against other provider
writers; post-change verification detects an inconsistent observed result.

## Admit the first upload when `source` is omitted

An explicit `source: null` retains its existing meaning. Existing omitted-source
projects can still qualify through the exact successful `ad_hoc` deployment
corroboration described in the [capability procedures](runbooks/capability-procedures.md).

For a newly created project with no deployment yet, cfctl can instead join the
current project ID to an authenticated native direct-create verification
receipt. That receipt binds the create operation, reviewed plan and execution
pins, account, project ID/name, `main`, profile generation, catalog, build and
apply evidence. Both preparation and the execution-boundary read reload the
authenticated records. The proof is usable only within the create plan's
existing expiry window. Missing authentication, recreated IDs, changed pins,
expired proof, Git/build state or contradictory responses refuse admission.
An audit-only observation cannot qualify this join.

Project creation and variable configuration are setup evidence. A successful
upload, serving behavior and application feedback each need their own proof.

The upstream contracts are documented by Cloudflare's
[project creation API](https://developers.cloudflare.com/api/resources/pages/subresources/projects/methods/create/),
[project update API](https://developers.cloudflare.com/api/resources/pages/subresources/projects/methods/edit/),
and [Pages Functions bindings](https://developers.cloudflare.com/pages/functions/bindings/).

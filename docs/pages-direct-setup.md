# Direct-upload Pages project setup

## Deploy an immutable artifact while development advances

The optional `artifact_receipt` query selector on `wrangler.pages-deploy`
selects immutable-artifact mode. Without it, the existing clean registered
checkout HEAD/branch requirements remain unchanged. It never treats a supplied
commit string or matching archive manifest as proof of a build.

`cfctl guide pages-artifact-reproduce --json` describes the local producer.
Call it with a JSON body containing `repository`, `commit`, `tree`, `account_id`,
`project_name`, `branch`, `artifact_directory`, `artifact_manifest_sha256`, and
`esbuild_package`. Paths must be canonical absolute paths without symlinks.
The package is an existing local npm darwin-arm64 esbuild 0.28.2 tarball; this
operation does not download or install dependencies. The current recipe supports
only the exact admitted script/package/lock hashes declared in
`crates/cfctl-core/src/pages_artifact.rs`. Other recipes and platforms fail closed.

The native producer reads Git objects from the registered logical repository,
extracts declared materials privately, copies public files and invokes the
lock-integrity-verified compiler with fixed arguments and a cleared environment.
It executes no repository scripts. Every compiler input must belong to the
declared Git materials; reproduced output must equal the complete retained
manifest. The result is authenticated `local_proof` of a **fresh reproduction**,
not retrospective authentication of an earlier build. Ordinary evidence imports
cannot stamp the native producer origin. Failure issues no qualifying receipt.

Use the returned evidence content hash as `--query artifact_receipt=sha256:...`
alongside the usual artifact directory, project, branch and commit selectors.
The plan binds that receipt, logical repository, account, production target,
source tree, complete artifact and deployment producer. Current development
HEAD/dirt is not consumed as archive source; registration, affected resource
links, other repositories, credentials and live target preconditions remain
checked. Missing proof, changed inputs or private-stage drift refuse execution.
Receipt reuse requires the same native producer implementation and cfctl build.

Approval, one-use execution, exact deployment readback and uncertain-outcome
rectification retain their existing rules. Restoration still requires a separate
reviewed plan for a proven prior artifact; no automatic rollback is added.

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

### Project configuration observations

The exact `pages-project-get-project` GET now adds `configuration_metadata` to
its governed read receipt. This versioned projection retains typed deployment
booleans, preview mode and branch/path pattern records, plus D1/R2 binding
identities and variable name/type metadata for production, preview and the
returned top-level object. Missing, null, observed-empty and unknown/malformed
fields remain distinct. Variable values are never included.

This is observed provider configuration only: it does not resolve inheritance,
prove coverage of other binding types or verify effective preview isolation.
Public flag/origin comparisons are not admitted by this projection; their
expectations belong to the consuming application. The enclosing read receipt
provides account, credential, catalog, timestamp and evidence identity.

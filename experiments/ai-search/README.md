# AI Search / Firecrawl evaluation pilot

The primary workload is external research. Measure external discovery and page
reading separately from search over a collected corpus. This is a local source
pilot, with tested binding adapters and an offline capture evaluator. It is not
connected to a live account, installed into an agent, or deployed.

## Initial assessment, 2026-10-26

AI Search alone cannot replace the external research workflow. It searches data
already indexed into an instance. Its automatic website data source requires a
domain onboarded to the same Cloudflare account. Arbitrary third-party page
reading requires a separate fetch step. Browser Run offers Markdown, HTML,
structured extraction, and asynchronous site crawling and is the relevant
Cloudflare comparison for that part of Firecrawl.

The candidate architecture is:

1. An open-web discovery provider finds source URLs. No replacement for this
   component is implemented in this pilot.
2. Browser Run reads selected external URLs; compare this against Firecrawl
   scrape results first.
3. AI Search optionally indexes a selected retained corpus and retrieves cited
   chunks on later queries. Upload, retention, freshness, and sync are separate
   unimplemented stages; reading a page here does not index it.

| Workload | Cloudflare candidate | Current evidence |
| --- | --- | --- |
| Open-web discovery | Separate discovery provider required | Capability mismatch for AI Search alone |
| Read a supplied external URL | Browser Run `/markdown` | Adapter tested against injected bindings; live behavior unknown |
| Crawl a selected external site | Browser Run `/crawl` | Documented capability; no crawler implemented or run |
| Structured extraction, PDFs, difficult sites | Browser Run endpoints / additional tooling | Outside the implemented pilot; no equivalence claim |
| Search retained documents | AI Search namespace binding | Adapter tested against injected bindings; live retrieval unknown |

## Local integration

No dependency installation is needed. These modules use an existing Worker's
bindings; they expose no public HTTP endpoint or account administration API.
`wrangler.fragment.jsonc` is a fragment for a separately reviewed existing
Worker, not a deployment configuration. Browser `quickAction` requires a
compatibility date of at least `2026-03-24`. Local remote mode consumes real
account resources; the fragment intentionally does not enable it.

```ts
import { readExternal } from "./external";
import { searchCorpus } from "./search";

// In an existing authenticated, reviewed Worker flow:
const page = await readExternal(
  env.BROWSER,
  "https://developers.cloudflare.com/ai-search/",
  ["https://developers.cloudflare.com"],
);
const results = await searchCorpus(env.AI_SEARCH, "evaluation-instance", question);
```

The common result is `{ provider, hits: [{ source, text, score }] }`. This is a
small comparison boundary rather than Firecrawl's full API contract. The source
of an external read is its requested URL; redirects and canonical final URLs are
not separately observed by this adapter. AI Search item keys may be file paths;
uploads must preserve the source URL or the benchmark's expected keys must be
changed to the exact uploaded keys.

External reading validates the initial URL against selected HTTPS origins and
sends no supplied browser credentials. It does not constrain redirected
navigation or browser subresource requests, so this is not network isolation.
It asks the browser to render for up to 30 seconds and caps its returned JSON at
1 MiB. The navigation timeout is not a hard bound on all billing or
wall-clock time. Search requests use hybrid retrieval, at most ten results,
disable query rewriting, reranking, and similarity cache, and reject partial
results. The adapter never invokes generation. A namespace binding can also
administer instances; this search-only adapter does not reduce the authority of that
binding. Any deployment must review its actual permissions. Provider errors and
unsupported shapes fail; snippets are insufficient for a page-content comparison.

## Run local checks

From the repository root:

```sh
bun test experiments/ai-search/pilot.test.ts
bun experiments/ai-search/evaluate.ts experiments/ai-search/cases.json experiments/ai-search/captures.empty.json
```

`cases.json` contains six external smoke cases and two corpus cases. It is a
small documentation-based wiring set, not a representative production workload.
Before a replacement decision, add actual research tasks, a JavaScript-rendered
page, PDFs, structured data, negative/unknown queries, inaccessible pages,
freshness checks, and a bounded crawl. Version-sensitive expected text must be
reviewed when the referenced documentation changes.

`captures.empty.json` is an empty wiring example. Keep actual provider captures
in a separate ignored `*.capture.json` file and pass that file to the runner.
A capture has this shape (the placeholders below are illustrative):

```json
{
  "case_id": "external-ai-search-read",
  "provider": "cloudflare",
  "source_url": "https://developers.cloudflare.com/ai-search/",
  "response": { "success": true, "result": "ACTUAL CAPTURED MARKDOWN" },
  "latency_ms": 1234
}
```

For Cloudflare corpus cases, supply the AI Search v2 `chunks` response, optionally
wrapped in the REST envelope or a successful performed cfctl envelope. For
Firecrawl, supply the scraped page, a `data.web` search response with Markdown,
or its extracted MCP payload. Tool transport content blocks must be unwrapped
before evaluation. Attach `billed_usd` only when actual attributable billing is
available; unknown cost stays null. Fixture values and pricing estimates are
not observed billing. Captures can contain private text; keep real captures out
of Git and the public output bundle.

The runner compares top-five source documents (deduplicating chunks), reciprocal
rank, and required facts on the expected cited source. It preserves separate
external/corpus coverage and leaves unrun cases `not_run`. Captures are supplied
evidence, not authenticated live receipts. It always leaves the overall
replacement verdict inconclusive: these metrics do not establish discovery,
ingestion, extraction breadth, freshness, or operating costs.

## Live activation gates

No authenticated instance inventory or live provider integration has been
qualified for this pilot. Instance availability, account permissions and
entitlements remain unknown.

At the initial assessment, the catalog blocked `ai-search-namespace-instance-search` and
`brapi-post_Markdown`. The former lacks operation-specific risk, effect, bounded
cost, verification, rollback/irreversibility, and permission contracts; the
latter lacks risk, effect, incremental cost, verification, and rollback contracts.
The assessed Markdown catalog path was `/browser-rendering/markdown`, while the
current documentation shows `/browser-run/markdown`; compatibility must be verified in the
catalog owner before adoption. This pilot changes none of those contracts.

Next executable stages, in order:

1. Complete the relevant cfctl source contracts against the official API,
   including costs and the renamed Browser Run route, then qualify and adopt
   that candidate through the existing owner.
2. Use a profile Cloudflare accepts for the exact account and required product
   permissions; do not rotate or borrow unrelated application profiles.
3. Prepare and review exact resource and cost plans before creating an instance,
   deploying bindings, or consuming billable services. Keep the corpus private;
   enabling a public MCP endpoint changes exposure and is a separate decision.
4. Run external reads first, capture source/latency/cost and failures, then run
   the smaller corpus trial after indexing is observed complete. Run a genuine
   Firecrawl baseline under separately authorized resource and cost bounds.

This pilot has not activated a Cloudflare resource, token, public endpoint, agent
configuration or billing setting. Local Bun tests and the strict adapter type
check establish source behavior with injected bindings. The repository's full
native proof follows the supported host-target route in
[CONTRIBUTING.md](../../CONTRIBUTING.md#local-proof-and-pre-push-gate); that proof is
separate from live provider integration and installation.

## Pricing context

As documented on 2026-10-26, AI Search billing begins November 1, 2026. The
published included usage and ingestion/storage/query rates do not establish
remaining account quota or a hard spend cap. Browser Run time and any external
model use need their own cost accounting. No spend or free-tier availability
was inferred for this account.

## Official sources

- [AI Search overview](https://developers.cloudflare.com/ai-search/)
- [Website ownership constraint](https://developers.cloudflare.com/ai-search/configuration/data-source/website/)
- [Fetch and index a third-party page](https://developers.cloudflare.com/ai-search/how-to/fetch-and-index-web-pages/)
- [AI Search binding request and response](https://developers.cloudflare.com/ai-search/api/search/workers-binding/)
- [Search REST permissions](https://developers.cloudflare.com/ai-search/api/search/rest-api/)
- [AI Search limits and pricing](https://developers.cloudflare.com/ai-search/platform/limits-pricing/)
- [Browser Run Markdown](https://developers.cloudflare.com/browser-run/quick-actions/markdown-endpoint/)
- [Browser Run crawling](https://developers.cloudflare.com/browser-run/quick-actions/crawl-endpoint/)
- [Browser Run pricing](https://developers.cloudflare.com/browser-run/pricing/)
- [Firecrawl search and scraping](https://docs.firecrawl.dev/features/search)

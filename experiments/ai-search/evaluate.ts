import { normalizeCloudflare, normalizeFirecrawl, searchInput } from "./search";
import { normalizeBrowserRun } from "./external";

export type Case = { id: string; workload: "corpus" | "open_web"; operation: "search" | "read"; query: string; sources: string[]; terms: string[] };
export type Capture = {
  case_id: string;
  provider: "cloudflare" | "firecrawl";
  response: unknown;
  source_url?: string;
  latency_ms?: number;
  billed_usd?: number;
};

function canonicalSource(source: string): string {
  try {
    const url = new URL(source);
    url.hash = "";
    return url.toString().replace(/\/$/, "");
  } catch { return source; }
}

export function evaluate(cases: Case[], captures: Capture[]) {
  if (!Array.isArray(cases) || cases.length === 0 || cases.length > 100) throw new Error("expected 1..100 cases");
  const ids = new Set<string>();
  for (const item of cases) {
    if (!item.id || ids.has(item.id) || !["corpus", "open_web"].includes(item.workload) || !["search", "read"].includes(item.operation) ||
        !Array.isArray(item.sources) || item.sources.length === 0 || !item.sources.every((s) => typeof s === "string" && s.trim()) ||
        !Array.isArray(item.terms) || !item.terms.every((s) => typeof s === "string" && s.trim())) throw new Error("invalid or duplicate case");
    searchInput(item.query);
    ids.add(item.id);
  }
  if (!Array.isArray(captures) || captures.length > cases.length * 2) throw new Error("invalid capture count");
  const indexed = new Map<string, Capture>();
  for (const capture of captures) {
    if (!ids.has(capture.case_id) || !["cloudflare", "firecrawl"].includes(capture.provider)) throw new Error("unknown case or provider");
    const key = `${capture.case_id}:${capture.provider}`;
    if (indexed.has(key)) throw new Error(`duplicate capture ${key}`);
    for (const number of [capture.latency_ms, capture.billed_usd]) {
      if (number !== undefined && (typeof number !== "number" || !Number.isFinite(number) || number < 0)) throw new Error("invalid latency or cost");
    }
    indexed.set(key, capture);
  }
  const rows = cases.flatMap((item) => (["cloudflare", "firecrawl"] as const).map((provider) => {
    const capture = indexed.get(`${item.id}:${provider}`);
    const base = { case_id: item.id, workload: item.workload, operation: item.operation, provider };
    if (!capture) return { ...base, state: "not_run" };
    try {
      if (provider === "cloudflare" && item.operation === "read" && !item.sources.includes(capture.source_url ?? "")) {
        throw new Error("external read capture is not bound to its target");
      }
      const result = provider === "firecrawl" ? normalizeFirecrawl(capture.response) : item.operation === "read"
        ? normalizeBrowserRun(capture.response, capture.source_url!) : normalizeCloudflare(capture.response);
      // Compare ranked source documents, not AI Search chunks against whole pages.
      const documents = new Map<string, { source: string; text: string }>();
      for (const hit of result.hits) {
        const key = canonicalSource(hit.source);
        const existing = documents.get(key);
        if (existing) existing.text += `\n${hit.text}`;
        else documents.set(key, { source: key, text: hit.text });
      }
      const hits = [...documents.values()].slice(0, 5);
      const expected = new Set(item.sources.map(canonicalSource));
      const rank = hits.findIndex((hit) => expected.has(canonicalSource(hit.source)));
      const citedText = hits.filter((hit) => expected.has(canonicalSource(hit.source))).map((hit) => hit.text).join("\n").toLowerCase();
      return {
        ...base, state: "observed", hit_at_5: rank >= 0, reciprocal_rank_at_5: rank < 0 ? 0 : 1 / (rank + 1),
        required_terms_present: item.terms.every((term) => citedText.includes(term.toLowerCase())),
        latency_ms: capture.latency_ms ?? null, billed_usd: capture.billed_usd ?? null,
      };
    } catch {
      // Avoid echoing provider error bodies, queries, or private result content.
      return { ...base, state: "failed", reason: "provider_error_or_unsupported_response" };
    }
  }));
  return {
    schema_version: 1,
    evidence_class: "offline_capture_assessment",
    provenance: "captures are caller-supplied; this runner does not authenticate their origin or freshness",
    ranking_unit: "source_documents",
    verdict: "inconclusive",
    reason: "Retrieval metrics do not establish live ingestion, freshness, open-web discovery, or full Firecrawl replacement.",
    coverage: ["open_web", "corpus"].map((workload) => ({
      workload,
      expected: rows.filter((row) => row.workload === workload).length,
      observed: rows.filter((row) => row.workload === workload && row.state === "observed").length,
      failed: rows.filter((row) => row.workload === workload && row.state === "failed").length,
      not_run: rows.filter((row) => row.workload === workload && row.state === "not_run").length,
    })),
    rows,
  };
}

if (import.meta.main) {
  const [casesPath, capturesPath] = Bun.argv.slice(2);
  if (!casesPath || !capturesPath) {
    console.error("Usage: bun evaluate.ts <cases.json> <captures.json>");
    process.exitCode = 2;
  } else {
    try {
      for (const path of [casesPath, capturesPath]) {
        if (Bun.file(path).size > 8 * 1024 * 1024) throw new Error("input exceeds 8 MiB");
      }
      console.log(JSON.stringify(evaluate(await Bun.file(casesPath).json(), await Bun.file(capturesPath).json()), null, 2));
    } catch {
      console.error("Evaluation input is invalid, unreadable, or exceeds its bound.");
      process.exitCode = 2;
    }
  }
}

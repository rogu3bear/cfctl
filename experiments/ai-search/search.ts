/** Retrieval-only pilot. Account administration stays in cfctl. */
export type Hit = { source: string; text: string; score: number | null };
export type SearchResult = { hits: Hit[]; provider: "cloudflare" | "firecrawl" };
type ObjectValue = Record<string, unknown>;

function object(value: unknown, label: string): ObjectValue {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as ObjectValue;
}

function successful(value: unknown): ObjectValue {
  let body = object(value, "response");
  // Accept cfctl ResultEnvelopeV2 as well as a provider response or binding result.
  if ("ok" in body) {
    if (body.ok !== true || body.performed !== true) throw new Error("cfctl did not complete a live call");
    body = object(body.result, "cfctl result");
  }
  if (body.success === false || (Array.isArray(body.errors) && body.errors.length > 0)) {
    throw new Error("provider returned an error or partial results");
  }
  if ("result" in body) body = object(body.result, "provider result");
  if (body.success === false || (Array.isArray(body.errors) && body.errors.length > 0)) {
    throw new Error("provider returned an error or partial results");
  }
  return body;
}

function requiredText(value: unknown, label: string): string {
  if (typeof value !== "string" || !value.trim()) throw new Error(`${label} is missing`);
  return value;
}

export function normalizeCloudflare(value: unknown): SearchResult {
  const body = successful(value);
  if (!Array.isArray(body.chunks)) throw new Error("AI Search v2 chunks array is missing");
  const hits = body.chunks.map((value) => {
    const chunk = object(value, "chunk");
    const item = object(chunk.item, "chunk item");
    if (typeof chunk.score !== "number" || !Number.isFinite(chunk.score) || chunk.score < 0 || chunk.score > 1) {
      throw new Error("chunk score must be between zero and one");
    }
    return {
      source: requiredText(item.key, "chunk source"),
      text: requiredText(chunk.text, "chunk text"),
      score: chunk.score,
    };
  });
  return { provider: "cloudflare", hits };
}

export function normalizeFirecrawl(value: unknown): SearchResult {
  const body = successful(value);
  const data = body.data === undefined ? body : body.data;
  // Search REST v2 uses data.web; the MCP exposes web or a direct markdown page.
  let pages: unknown;
  if (Array.isArray(data)) pages = data;
  else {
    const record = object(data, "Firecrawl data");
    pages = record.web ?? ("markdown" in record ? [record] : undefined);
  }
  if (!Array.isArray(pages)) throw new Error("Firecrawl web results or scraped page are missing");
  return {
    provider: "firecrawl",
    hits: pages.map((value) => {
      const page = object(value, "Firecrawl page");
      const metadata = page.metadata === undefined ? {} : object(page.metadata, "page metadata");
      return {
        source: requiredText(page.url ?? metadata.sourceURL ?? metadata.url, "page URL"),
        // Search snippets are intentionally insufficient for a read/content benchmark.
        text: requiredText(page.markdown, "page markdown (request content scraping)"),
        score: null,
      };
    }),
  };
}

export type SearchInput = {
  query: string;
  ai_search_options: {
    retrieval: { retrieval_type: "hybrid"; max_num_results: number; context_expansion: 0; return_on_failure: false };
    query_rewrite: { enabled: false };
    reranking: { enabled: false };
    cache: { enabled: false };
  };
};
export type AiSearchNamespace = {
  get(id: string): { search(input: SearchInput): Promise<unknown> };
};

export function searchInput(query: string, limit = 5): SearchInput {
  if (!query.trim() || query.length > 4096) throw new Error("query must contain 1..4096 characters");
  if (!Number.isInteger(limit) || limit < 1 || limit > 10) throw new Error("limit must be 1..10");
  return {
    query,
    ai_search_options: {
      retrieval: { retrieval_type: "hybrid", max_num_results: limit, context_expansion: 0, return_on_failure: false },
      query_rewrite: { enabled: false },
      reranking: { enabled: false },
      cache: { enabled: false },
    },
  };
}

/** Invoke from an existing Worker with an explicitly configured namespace binding. */
export async function searchCorpus(binding: AiSearchNamespace, instance: string, query: string, limit = 5): Promise<SearchResult> {
  if (!/^[a-z0-9_-]{1,64}$/.test(instance)) throw new Error("invalid AI Search instance ID");
  const input = searchInput(query, limit);
  return normalizeCloudflare(await binding.get(instance).search(input));
}

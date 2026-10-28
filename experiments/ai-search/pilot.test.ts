import { describe, expect, test } from "bun:test";
import { normalizeCloudflare, normalizeFirecrawl, searchCorpus, searchInput } from "./search";
import { normalizeBrowserRun, readExternal } from "./external";
import { evaluate, type Case } from "./evaluate";

const chunk = (source = "https://example.com/doc", text = "required fact") => ({ item: { key: source }, text, score: 0.8 });
const cases: Case[] = [{ id: "one", workload: "corpus", operation: "search", query: "question", sources: ["https://example.com/doc"], terms: ["required fact"] }];

describe("AI Search adapter", () => {
  test("handles binding, REST, and cfctl response envelopes", () => {
    const raw = { chunks: [chunk()] };
    for (const response of [raw, { success: true, result: raw }, { ok: true, performed: true, result: { success: true, result: raw } }]) {
      expect(normalizeCloudflare(response).hits[0]?.source).toBe("https://example.com/doc");
    }
  });
  test("does not treat blocked calls, errors, partial results, or legacy shapes as empty success", () => {
    for (const response of [{ ok: false }, { ok: true, performed: false, result: {} }, { success: false }, { chunks: [], errors: ["failed"] }, { data: [] }]) {
      expect(() => normalizeCloudflare(response)).toThrow();
    }
  });
  test("preserves valid zero-result searches", () => expect(normalizeCloudflare({ chunks: [] }).hits).toEqual([]));
  test("rejects missing citations, missing text, and non-finite scores", () => {
    for (const invalid of [{ ...chunk(), score: NaN }, { ...chunk(), score: 2 }, { ...chunk(), item: {} }, { ...chunk(), text: "" }]) {
      expect(() => normalizeCloudflare({ chunks: [invalid] })).toThrow();
    }
  });
  test("uses explicit retrieval settings and avoids generation", async () => {
    let called: unknown;
    const result = await searchCorpus({ get: (id) => {
      expect(id).toBe("pilot");
      return { search: async (input) => { called = input; return { chunks: [chunk()] }; } };
    } }, "pilot", "question");
    expect(called).toEqual(searchInput("question"));
    expect(result.provider).toBe("cloudflare");
  });
  test("validates requests before touching the binding", async () => {
    const binding = { get: () => { throw new Error("binding touched"); } };
    await expect(searchCorpus(binding, "bad/instance", "q")).rejects.toThrow("invalid AI Search");
    for (const [query, limit] of [["", 5], ["q", 0], ["q", 11], ["q", 1.5], ["q".repeat(4097), 5]] as const) {
      expect(() => searchInput(query, limit)).toThrow();
    }
  });
});

describe("external reading and Firecrawl comparison", () => {
  test("normalizes Firecrawl search and scrape content", () => {
    expect(normalizeFirecrawl({ success: true, data: { web: [{ url: "https://example.com", markdown: "page" }] } }).hits).toHaveLength(1);
    expect(normalizeFirecrawl({ markdown: "page", metadata: { sourceURL: "https://example.com" } }).hits).toHaveLength(1);
  });
  test("does not substitute search snippets for retrieved content", () => {
    expect(() => normalizeFirecrawl({ data: { web: [{ url: "https://example.com", description: "snippet" }] } })).toThrow();
    expect(() => normalizeFirecrawl({ success: false, error: "no credits" })).toThrow();
  });
  test("renders an external page using only the injected browser binding", async () => {
    const result = await readExternal({ quickAction: async (action, input) => {
      expect(action).toBe("markdown");
      expect(input.url).toBe("https://example.com/doc");
      expect(input.gotoOptions.timeout).toBe(30000);
      return Response.json({ success: true, result: "page" });
    } }, "https://example.com/doc#part", ["https://example.com"]);
    expect(result.hits[0]).toEqual({ source: "https://example.com/doc", text: "page", score: null });
  });
  test("rejects unselected origins, credential URLs, and HTTP before dispatch", async () => {
    const binding = { quickAction: async () => { throw new Error("dispatched"); } };
    for (const url of ["https://other.com", "http://example.com", "https://user:password@example.com"]) {
      await expect(readExternal(binding, url, ["https://example.com"])).rejects.toThrow("explicitly selected origin");
    }
  });
  test("preserves browser failure and limits response bytes", async () => {
    for (const response of [new Response("error", { status: 403 }), Response.json({ success: false }), new Response("x".repeat(1024 * 1024 + 1))]) {
      await expect(readExternal({ quickAction: async () => response }, "https://example.com", ["https://example.com"])).rejects.toThrow();
    }
    expect(() => normalizeBrowserRun({ success: true, result: "" }, "url")).toThrow();
  });
});

describe("evaluation evidence", () => {
  test("missing trials remain not_run and cannot establish replacement", () => {
    const report = evaluate(cases, []);
    expect(report.verdict).toBe("inconclusive");
    expect(report.rows.map((r) => r.state)).toEqual(["not_run", "not_run"]);
  });
  test("scores document rank, source identity, and required facts", () => {
    const report = evaluate(cases, [{ case_id: "one", provider: "cloudflare", response: { chunks: [chunk("https://wrong.com"), chunk()] } }]);
    expect(report.rows[0]).toMatchObject({ state: "observed", hit_at_5: true, reciprocal_rank_at_5: 0.5, required_terms_present: true, billed_usd: null });
  });
  test("deduplicates chunks and ignores facts on the wrong source", () => {
    const chunks = [chunk("https://wrong.com"), chunk("https://wrong.com"), chunk("https://example.com/doc", "no matching terms")];
    const report = evaluate(cases, [{ case_id: "one", provider: "cloudflare", response: { chunks } }]);
    expect(report.rows[0]).toMatchObject({ reciprocal_rank_at_5: 0.5, required_terms_present: false });
  });
  test("invalid responses remain failed, without private error text", () => {
    const report = evaluate(cases, [{ case_id: "one", provider: "cloudflare", response: { success: false, error: "private" } }]);
    expect(report.rows[0]?.state).toBe("failed");
    expect(JSON.stringify(report)).not.toContain("private");
  });
  test("rejects duplicate captures, unknown cases, and invalid costs", () => {
    const capture = { case_id: "one", provider: "cloudflare" as const, response: { chunks: [] } };
    expect(() => evaluate(cases, [capture, capture])).toThrow();
    expect(() => evaluate(cases, [{ ...capture, case_id: "other" }])).toThrow();
    expect(() => evaluate(cases, [{ ...capture, billed_usd: -1 }])).toThrow();
    expect(() => evaluate([], [])).toThrow();
  });
  test("separates external page reads from corpus search", () => {
    const external: Case = { ...cases[0]!, workload: "open_web", operation: "read" };
    const report = evaluate([external], [{ case_id: "one", provider: "cloudflare", source_url: external.sources[0], response: { success: true, result: "required fact" } }]);
    expect(report.coverage[0]).toMatchObject({ workload: "open_web", observed: 1, not_run: 1 });
    expect(report.rows[0]).toMatchObject({ state: "observed", hit_at_5: true });
    const unbound = evaluate([external], [{ case_id: "one", provider: "cloudflare", source_url: "https://wrong.com", response: { success: true, result: "required fact" } }]);
    expect(unbound.rows[0]?.state).toBe("failed");
  });
});

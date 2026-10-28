import type { SearchResult } from "./search";

export type BrowserBinding = {
  quickAction(action: "markdown", options: { url: string; gotoOptions: { waitUntil: "networkidle2"; timeout: number } }): Promise<Response>;
};

/** Browser Run supplies external reading; AI Search only searches indexed material. */
export async function readExternal(binding: BrowserBinding, target: string, allowedOrigins: readonly string[]): Promise<SearchResult> {
  const url = new URL(target);
  if (url.protocol !== "https:" || url.username || url.password || !allowedOrigins.includes(url.origin)) {
    throw new Error("target must be HTTPS on an explicitly selected origin, without credentials");
  }
  url.hash = "";
  const response = await binding.quickAction("markdown", {
    url: url.toString(), gotoOptions: { waitUntil: "networkidle2", timeout: 30000 },
  });
  if (!response.ok || !response.body) throw new Error("Browser Run did not return a successful body");
  const reader = response.body.getReader();
  let bytes = 0;
  const decoder = new TextDecoder();
  let text = "";
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > 1024 * 1024) throw new Error("Browser Run response exceeds 1 MiB");
      text += decoder.decode(value, { stream: true });
    }
  } finally {
    await reader.cancel();
    reader.releaseLock();
  }
  text += decoder.decode();
  return normalizeBrowserRun(JSON.parse(text), url.toString());
}

export function normalizeBrowserRun(value: unknown, source: string): SearchResult {
  const body = value as { success?: unknown; result?: unknown } | null;
  if (!body || body.success !== true || typeof body.result !== "string" || !body.result.trim()) {
    throw new Error("Browser Run markdown response is missing or unsuccessful");
  }
  return { provider: "cloudflare", hits: [{ source, text: body.result, score: null }] };
}

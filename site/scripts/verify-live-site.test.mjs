import { describe, expect, test, spyOn } from "bun:test";
import {
  ROUTES,
  verifyLiveSite,
  parseCsp,
  productionOrigin,
  verifyAssetManifest,
  verifyHtmlResponse,
  verifyInlineScripts,
} from "./verify-live-site.mjs";

function htmlResponse(body = "See the boundary before you cross it.", overrides = {}) {
  return new Response(body, {
    status: overrides.status ?? 200,
    headers: {
      "cache-control": "no-cache, max-age=0, must-revalidate",
      "content-security-policy": "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'self' data:; font-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self' 'sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=' 'wasm-unsafe-eval' 'nonce-AAAAAAAAAAAAAAAAAAAAAA';",
      "content-type": "text/html; charset=utf-8",
      "cross-origin-opener-policy": "same-origin",
      "permissions-policy": "camera=(), geolocation=(), microphone=(), payment=(), usb=()",
      "referrer-policy": "strict-origin-when-cross-origin",
      "strict-transport-security": "max-age=31536000",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      ...overrides.headers,
    },
  });
}

describe("production origin", () => {
  test("accepts only a bare https origin", () => {
    expect(productionOrigin("https://cfctl.com").origin).toBe("https://cfctl.com");
    expect(() => productionOrigin("http://cfctl.com")).toThrow("https origin");
    expect(() => productionOrigin("https://cfctl.com/start")).toThrow("must not contain a path");
    expect(() => productionOrigin("https://cfctl.com/?code=secret")).toThrow("query or fragment");
  });
});

describe("HTML response contract", () => {
  test("accepts the complete ordinary-route contract", async () => {
    await expect(verifyHtmlResponse(htmlResponse(), {
      path: "/",
      status: 200,
      marker: "See the boundary before you cross it.",
    })).resolves.toBeUndefined();
  });

  test("fails closed when a security header disappears", async () => {
    const response = htmlResponse();
    response.headers.delete("content-security-policy");
    await expect(verifyHtmlResponse(response, {
      path: "/",
      status: 200,
      marker: "See the boundary before you cross it.",
    })).rejects.toThrow("content-security-policy");
  });

  test("rejects permissive first directives hidden by secure duplicates", async () => {
    const response = htmlResponse("See the boundary before you cross it.", {
      headers: {
        "content-security-policy": "default-src *; default-src 'self'; base-uri *; base-uri 'none'; object-src *; object-src 'none'; frame-ancestors *; frame-ancestors 'none'; form-action *; form-action 'none'; connect-src *; connect-src 'self'",
      },
    });
    await expect(verifyHtmlResponse(response, {
      path: "/",
      status: 200,
      marker: "See the boundary before you cross it.",
    })).rejects.toThrow("repeats the default-src directive");
  });

  test("rejects a permissive script-src that overrides default-src", async () => {
    const response = htmlResponse("See the boundary before you cross it.", {
      headers: {
        "content-security-policy": "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'self' data:; font-src 'self'; connect-src 'self'; style-src 'self'; script-src * 'unsafe-inline' 'unsafe-eval';",
      },
    });
    await expect(verifyHtmlResponse(response, {
      path: "/",
      status: 200,
      marker: "See the boundary before you cross it.",
    })).rejects.toThrow("script-src does not match the production hash-bound policy");
  });

  for (const override of [
    "script-src-elem * 'unsafe-inline'",
    "script-src-attr 'unsafe-inline'",
  ]) {
    test(`rejects browser-effective ${override.split(" ")[0]} authority`, async () => {
      const response = htmlResponse("See the boundary before you cross it.", {
        headers: {
          "content-security-policy": `${htmlResponse().headers.get("content-security-policy")} ${override};`,
        },
      });
      await expect(verifyHtmlResponse(response, {
        path: "/",
        status: 200,
        marker: "See the boundary before you cross it.",
      })).rejects.toThrow("directive outside the exact production policy");
    });
  }

  test("parses every directive once and rejects duplicates", () => {
    expect(parseCsp("default-src 'self'; base-uri 'none'").get("base-uri")).toEqual(["'none'"]);
    expect(() => parseCsp("default-src *; default-src 'self'")).toThrow("repeats the default-src directive");
  });

  test("rejects callback values rendered into SSR HTML", async () => {
    const response = htmlResponse("OAuth callback · isolated route cfctl-live-verifier-code-do-not-log", {
      headers: {
        "cache-control": "no-store, no-cache, max-age=0",
        "pragma": "no-cache",
        "referrer-policy": "no-referrer",
      },
    });
    await expect(verifyHtmlResponse(response, {
      path: "/oauth/callback/",
      status: 200,
      marker: "OAuth callback · isolated route",
      callback: true,
    })).rejects.toThrow("callback code leaked");
  });
});

describe("asset manifest contract", () => {
  test("binds every asset path to its digest", () => {
    expect(() => verifyAssetManifest({
      js: "/pkg/cfctl-site.0123456789abcdef.js",
      wasm: "/pkg/cfctl-site.1111111111111111.wasm",
      css: "/pkg/cfctl-site.2222222222222222.css",
      hashes: {
        js: "0123456789abcdef",
        wasm: "1111111111111111",
        css: "2222222222222222",
      },
    })).not.toThrow();
    expect(() => verifyAssetManifest({
      js: "/pkg/cfctl-site.js",
      wasm: "/pkg/cfctl-site.1111111111111111.wasm",
      css: "/pkg/cfctl-site.2222222222222222.css",
      hashes: {
        js: "0123456789abcdef",
        wasm: "1111111111111111",
        css: "2222222222222222",
      },
    })).toThrow("not bound to its hash");
  });
});


test("live asset readback validates actual served bytes", async () => {
  const { fingerprintAssets } = await import("./hash-assets.mjs");
  const buffers = { js: Buffer.from('new URL("cfctl-site.wasm",import.meta.url)'), wasm: Buffer.from("wasm"), css: Buffer.from("body{}") };
  const result = fingerprintAssets("cfctl-site", buffers);
  const manifest = { ...Object.fromEntries(Object.entries(result.names).map(([kind, name]) => [kind, `/pkg/${name}`])), hashes: result.hashes };
  const served = { ...buffers, js: Buffer.from(result.rewrittenJs) };
  let corrupt = false;
  const stub = spyOn(globalThis, "fetch").mockImplementation(async (value) => {
    const url = new URL(value);
    const route = ROUTES.find((route) => new URL(route.path, url.origin).pathname === url.pathname);
    if (route) return htmlResponse(route.marker, { status: route.status, headers: route.callback ? {
      "cache-control": "no-store, no-cache, max-age=0", "pragma": "no-cache", "referrer-policy": "no-referrer",
    } : {} });
    if (url.pathname === "/asset-manifest.json") return Response.json(manifest, { headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" } });
    const kind = ["js", "wasm", "css"].find((kind) => manifest[kind] === url.pathname);
    if (!kind) throw new Error("unexpected fixture fetch");
    return new Response(corrupt && kind === "wasm" ? Buffer.from("wrong") : served[kind], { headers: {
      "cache-control": "public, max-age=31536000, immutable", "x-content-type-options": "nosniff",
    } });
  });
  try {
    const proof = await verifyLiveSite("https://cfctl.example");
    expect(proof.assets).toHaveLength(3);
    corrupt = true;
    await expect(verifyLiveSite("https://cfctl.example")).rejects.toThrow("actual bytes");
  } finally { stub.mockRestore(); }
});


test("inline framework scripts must carry the exact response nonce or an admitted byte hash", async () => {
  const { createHash } = await import("node:crypto");
  const script = "initialize();";
  const hash = createHash("sha256").update(script).digest("base64");
  const sources = [`'sha256-${hash}'`, "'nonce-AAAAAAAAAAAAAAAAAAAAAA'"];
  expect(() => verifyInlineScripts(`<script type="module">${script}</script><script nonce="AAAAAAAAAAAAAAAAAAAAAA">__INCOMPLETE_CHUNKS=[];</script>`, sources)).not.toThrow();
  expect(() => verifyInlineScripts(`<script>${script}changed();</script>`, sources)).toThrow("not admitted");
  expect(() => verifyInlineScripts('<script>__INCOMPLETE_CHUNKS=[];</script>', sources)).toThrow("not admitted");
  expect(() => verifyInlineScripts('<script nonce="BBBBBBBBBBBBBBBBBBBBBB">__INCOMPLETE_CHUNKS=[];</script>', sources)).toThrow("not admitted");
  expect(() => verifyInlineScripts('<script type="application/json">{"data":true}</script>', sources)).not.toThrow();
});

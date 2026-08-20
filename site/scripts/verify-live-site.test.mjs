import { describe, expect, test } from "bun:test";
import {
  productionOrigin,
  verifyAssetManifest,
  verifyHtmlResponse,
} from "./verify-live-site.mjs";

function htmlResponse(body = "See the boundary before you cross it.", overrides = {}) {
  return new Response(body, {
    status: overrides.status ?? 200,
    headers: {
      "cache-control": "no-cache, max-age=0, must-revalidate",
      "content-security-policy": "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'none'; connect-src 'self';",
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
      js: "/pkg/site.0123456789abcdef.js",
      wasm: "/pkg/site.1111111111111111.wasm",
      css: "/pkg/site.2222222222222222.css",
      hashes: {
        js: "0123456789abcdef",
        wasm: "1111111111111111",
        css: "2222222222222222",
      },
    })).not.toThrow();
    expect(() => verifyAssetManifest({
      js: "/pkg/site.js",
      wasm: "/pkg/site.1111111111111111.wasm",
      css: "/pkg/site.2222222222222222.css",
      hashes: {
        js: "0123456789abcdef",
        wasm: "1111111111111111",
        css: "2222222222222222",
      },
    })).toThrow("not bound to its hash");
  });
});

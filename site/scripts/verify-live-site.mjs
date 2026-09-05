#!/usr/bin/env bun

import { createHash } from "node:crypto";
import { verifyAssetBytes, verifyAssetManifest } from "./asset-integrity.mjs";
export { verifyAssetManifest } from "./asset-integrity.mjs";

const CALLBACK_CODE_SENTINEL = "cfctl-live-verifier-code-do-not-log";
const CALLBACK_STATE_SENTINEL = "cfctl-live-verifier-state-do-not-log";
const REQUIRED_CSP = new Map([
  ["default-src", ["'self'"]],
  ["base-uri", ["'none'"]],
  ["object-src", ["'none'"]],
  ["frame-ancestors", ["'none'"]],
  ["form-action", ["'none'"]],
  ["img-src", ["'self'", "data:"]],
  ["font-src", ["'self'"]],
  ["connect-src", ["'self'"]],
  ["style-src", ["'self'"]],
]);
const REQUIRED_CSP_NAMES = new Set([...REQUIRED_CSP.keys(), "script-src"]);

export const ROUTES = [
  { path: "/", status: 200, marker: "See the boundary before you cross it." },
  { path: "/start", status: 200, marker: "Reach one verified read." },
  { path: "/security", status: 200, marker: "Your credential is not your consent." },
  { path: "/privacy", status: 200, marker: "The website does not build a profile of you." },
  { path: "/terms", status: 200, marker: "Review before authority. Verify after execution." },
  {
    path: `/oauth/callback/?code=${CALLBACK_CODE_SENTINEL}&state=${CALLBACK_STATE_SENTINEL}`,
    status: 200,
    marker: "OAuth callback · isolated route",
    callback: true,
  },
  {
    path: "/_cfctl-live-verifier-not-found",
    status: 404,
    marker: "This path has no governed contract.",
  },
];

function requireCondition(condition, message) {
  if (!condition) throw new Error(message);
}

function header(response, name) {
  const value = response.headers.get(name);
  requireCondition(value !== null, `${response.url || "response"} is missing ${name}`);
  return value;
}

export function productionOrigin(value) {
  const origin = new URL(value);
  requireCondition(origin.protocol === "https:", "live verification requires an https origin");
  requireCondition(origin.username === "" && origin.password === "", "origin must not contain credentials");
  requireCondition(origin.pathname === "/", "origin must not contain a path");
  requireCondition(origin.search === "" && origin.hash === "", "origin must not contain query or fragment data");
  return origin;
}

export function parseCsp(value) {
  const directives = new Map();
  for (const serialized of value.split(";")) {
    const tokens = serialized.trim().split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens.shift().toLowerCase();
    requireCondition(!directives.has(name), `CSP repeats the ${name} directive`);
    directives.set(name, tokens);
  }
  return directives;
}

export async function verifyHtmlResponse(response, route) {
  requireCondition(response.status === route.status, `${route.path} returned ${response.status}, expected ${route.status}`);
  requireCondition(response.redirected === false, `${route.path} redirected unexpectedly`);
  requireCondition(header(response, "content-type").toLowerCase().includes("text/html"), `${route.path} is not HTML`);
  requireCondition(header(response, "x-content-type-options").toLowerCase() === "nosniff", `${route.path} lacks nosniff`);
  requireCondition(header(response, "x-frame-options").toUpperCase() === "DENY", `${route.path} is frameable`);
  requireCondition(header(response, "cross-origin-opener-policy").toLowerCase() === "same-origin", `${route.path} has the wrong opener policy`);
  requireCondition(header(response, "strict-transport-security").includes("max-age=31536000"), `${route.path} lacks the one-year HSTS contract`);
  requireCondition(header(response, "permissions-policy").includes("camera=()"), `${route.path} lacks the permissions policy`);
  requireCondition(response.headers.get("set-cookie") === null, `${route.path} unexpectedly sets a cookie`);

  const csp = parseCsp(header(response, "content-security-policy"));
  requireCondition(
    csp.size === REQUIRED_CSP_NAMES.size
      && [...csp.keys()].every((name) => REQUIRED_CSP_NAMES.has(name)),
    `${route.path} CSP contains a directive outside the exact production policy`,
  );
  for (const [name, expectedSources] of REQUIRED_CSP) {
    const actualSources = csp.get(name);
    requireCondition(actualSources !== undefined, `${route.path} CSP is missing ${name}`);
    requireCondition(
      actualSources.length === expectedSources.length
        && actualSources.every((source, index) => source === expectedSources[index]),
      `${route.path} CSP ${name} is broader than ${expectedSources.join(" ")}`,
    );
  }
  const scriptSources = csp.get("script-src");
  requireCondition(scriptSources !== undefined, `${route.path} CSP is missing script-src`);
  requireCondition(
    scriptSources.length === 4
      && scriptSources[0] === "'self'"
      && /^'sha256-[A-Za-z0-9+/]{43}='$/.test(scriptSources[1])
      && scriptSources[2] === "'wasm-unsafe-eval'"
      && /^'nonce-[A-Za-z0-9_-]{22}'$/.test(scriptSources[3]),
    `${route.path} CSP script-src does not match the production hash-bound policy`,
  );

  const cacheControl = header(response, "cache-control");
  const referrerPolicy = header(response, "referrer-policy");
  if (route.callback) {
    requireCondition(cacheControl === "no-store, no-cache, max-age=0", "callback cache policy drifted");
    requireCondition(referrerPolicy === "no-referrer", "callback referrer policy drifted");
    requireCondition(header(response, "pragma") === "no-cache", "callback pragma drifted");
  } else {
    requireCondition(cacheControl === "no-cache, max-age=0, must-revalidate", `${route.path} cache policy drifted`);
    requireCondition(referrerPolicy === "strict-origin-when-cross-origin", `${route.path} referrer policy drifted`);
  }

  const body = await response.text();
  verifyInlineScripts(body, scriptSources);
  requireCondition(body.includes(route.marker), `${route.path} is missing its semantic marker`);
  if (route.callback) {
    requireCondition(!body.includes(CALLBACK_CODE_SENTINEL), "callback code leaked into SSR HTML");
    requireCondition(!body.includes(CALLBACK_STATE_SENTINEL), "callback state leaked into SSR HTML");
  }
}

export function verifyInlineScripts(html, sources) {
  for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)) {
    const attributes = match[1];
    const attribute = (name) => attributes.match(new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, "i"))?.slice(1).find((value) => value !== undefined);
    if (attribute("src") !== undefined) continue;
    const type = (attribute("type") ?? "").toLowerCase();
    if (!["", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"].includes(type)) continue;
    const hash = createHash("sha256").update(match[2]).digest("base64");
    const nonce = attribute("nonce");
    requireCondition(sources.includes(`'sha256-${hash}'`) || (nonce !== undefined && sources.includes(`'nonce-${nonce}'`)), "inline script is not admitted by the response CSP");
  }
}

async function fetchExact(url) {
  return fetch(url, {
    redirect: "manual",
    signal: AbortSignal.timeout(15_000),
    headers: { "user-agent": "cfctl-live-site-verifier/1" },
  });
}

export async function verifyLiveSite(originValue) {
  const origin = productionOrigin(originValue);
  const routeResults = [];
  for (const route of ROUTES) {
    const url = new URL(route.path, origin);
    const response = await fetchExact(url);
    await verifyHtmlResponse(response, route);
    routeResults.push({ path: url.pathname, status: route.status });
  }

  const manifestResponse = await fetchExact(new URL("/asset-manifest.json", origin));
  requireCondition(manifestResponse.status === 200, `asset manifest returned ${manifestResponse.status}`);
  requireCondition(header(manifestResponse, "cache-control") === "no-store", "asset manifest must be no-store");
  requireCondition(header(manifestResponse, "x-content-type-options").toLowerCase() === "nosniff", "asset manifest lacks nosniff");
  const manifest = await manifestResponse.json();
  verifyAssetManifest(manifest);

  const assets = [];
  for (const kind of ["js", "wasm", "css"]) {
    const response = await fetchExact(new URL(manifest[kind], origin));
    requireCondition(response.status === 200, `${manifest[kind]} returned ${response.status}`);
    requireCondition(header(response, "cache-control") === "public, max-age=31536000, immutable", `${manifest[kind]} is not immutable`);
    requireCondition(header(response, "x-content-type-options").toLowerCase() === "nosniff", `${manifest[kind]} lacks nosniff`);
    const bytes = await response.arrayBuffer();
    verifyAssetBytes(manifest, kind, bytes);
    assets.push({ kind, path: manifest[kind], bytes: bytes.byteLength });
  }

  return {
    schema_version: 1,
    origin: origin.origin,
    checked_at: new Date().toISOString(),
    routes: routeResults,
    assets,
    callback_query_values_rendered: false,
  };
}

if (import.meta.main) {
  const origin = process.argv[2];
  if (!origin || process.argv.length !== 3) {
    console.error("usage: bun ./scripts/verify-live-site.mjs https://<exact-production-origin>");
    process.exit(2);
  }
  try {
    console.log(JSON.stringify(await verifyLiveSite(origin)));
  } catch (error) {
    console.error(`[verify-live-site] ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  }
}

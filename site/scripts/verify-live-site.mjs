#!/usr/bin/env bun

const CALLBACK_CODE_SENTINEL = "cfctl-live-verifier-code-do-not-log";
const CALLBACK_STATE_SENTINEL = "cfctl-live-verifier-state-do-not-log";
const REQUIRED_CSP = [
  "default-src 'self'",
  "base-uri 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "form-action 'none'",
  "connect-src 'self'",
];

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

  const csp = header(response, "content-security-policy");
  for (const directive of REQUIRED_CSP) {
    requireCondition(csp.includes(directive), `${route.path} CSP is missing ${directive}`);
  }

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
  requireCondition(body.includes(route.marker), `${route.path} is missing its semantic marker`);
  if (route.callback) {
    requireCondition(!body.includes(CALLBACK_CODE_SENTINEL), "callback code leaked into SSR HTML");
    requireCondition(!body.includes(CALLBACK_STATE_SENTINEL), "callback state leaked into SSR HTML");
  }
}

export function verifyAssetManifest(manifest) {
  requireCondition(manifest && typeof manifest === "object", "asset manifest is not an object");
  requireCondition(manifest.hashes && typeof manifest.hashes === "object", "asset manifest lacks hashes");
  for (const kind of ["js", "wasm", "css"]) {
    const path = manifest[kind];
    const digest = manifest.hashes[kind];
    requireCondition(typeof path === "string" && path.startsWith("/pkg/"), `manifest ${kind} path is invalid`);
    requireCondition(typeof digest === "string" && /^[0-9a-f]{16}$/.test(digest), `manifest ${kind} hash is invalid`);
    requireCondition(path.includes(`.${digest}.`), `manifest ${kind} path is not bound to its hash`);
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
    requireCondition(bytes.byteLength > 0, `${manifest[kind]} is empty`);
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

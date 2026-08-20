#!/usr/bin/env bun

import { readdir, readFile } from "node:fs/promises";
import { join } from "node:path";

const root = process.cwd();
const applicationFiles = [
  "Cargo.toml",
  "wrangler.toml",
];

async function filesUnder(relative) {
  const absolute = join(root, relative);
  const entries = await readdir(absolute, { withFileTypes: true });
  const nested = await Promise.all(entries.map((entry) => {
    const path = join(relative, entry.name);
    return entry.isDirectory() ? filesUnder(path) : [path];
  }));
  return nested.flat();
}

const applicationSourceFiles = [
  ...applicationFiles,
  ...(await filesUnder("src")),
  ...(await filesUnder("style")),
  ...(await filesUnder("assets")),
];
const applicationSource = (await Promise.all(applicationSourceFiles.map((path) => readFile(join(root, path), "utf8")))).join("\n");
const verifierSource = await readFile(join(root, "scripts/verify-live-site.mjs"), "utf8");
const contractSource = `${applicationSource}\n${verifierSource}`;
const applicationSourceLower = applicationSource.toLowerCase();

for (const route of ["start", "security", "privacy", "terms", "oauth", "callback"]) {
  if (!applicationSource.includes(`StaticSegment(\"${route}\")`)) throw new Error(`missing Leptos route segment: ${route}`);
}
for (const required of ["no-store, no-cache", "no-referrer", "content-security-policy", "strict-transport-security", "form-action 'none'", "frame-ancestors 'none'", "MAX_STATE_BYTES", "MAX_CODE_BYTES", "prefers-reduced-motion", "forced-colors"]) {
  if (!contractSource.includes(required)) throw new Error(`missing site contract: ${required}`);
}
for (const forbidden of ["leptos-cf", "TodoPage", "ContactPage", "WebSocketPair", "d1_databases", "google-analytics", "segment.com", "posthog", "<form"]) {
  if (applicationSourceLower.includes(forbidden.toLowerCase())) throw new Error(`template or privacy residue remains: ${forbidden}`);
}
for (const forbidden of ["localstorage", "sessionstorage", "indexeddb", "document.cookie", "set-cookie", "analytics_engine_datasets", "kv_namespaces", "r2_buckets", "durable_objects"]) {
  if (applicationSourceLower.includes(forbidden)) throw new Error(`zero-data contract violation: ${forbidden}`);
}
if (/<script\b[^>]*\bsrc\s*=\s*["']https?:/i.test(applicationSource)) {
  throw new Error("third-party script source is not allowed");
}

const packageFiles = (await filesUnder("target/site/pkg")).filter((path) => path.endsWith(".js"));
const packageJs = (await Promise.all(packageFiles.map((path) => readFile(join(root, path), "utf8")))).join("\n");
if (/\b(?:import|fetch)\s*\(\s*["']https?:/i.test(packageJs)) {
  throw new Error("built client package contains a remote import or fetch");
}

console.log("[verify-site-contract] routes, callback bounds, zero-data/privacy posture, same-origin scripts, and accessible layout contracts are present");

#!/usr/bin/env bun

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const root = process.cwd();
const wrangler = await readFile(join(root, "wrangler.toml"), "utf8");
const shimPath = join(root, "build/_worker.js");
const manifest = JSON.parse(await readFile(join(root, "target/site/asset-manifest.json"), "utf8"));
const requireSnippet = (label, text, snippet) => { if (!text.includes(snippet)) throw new Error(`${label} is missing: ${snippet}`); };

for (const snippet of [
  'name = "cfctl-site"',
  'main = "build/_worker.js"',
  'compatibility_date = "2026-08-05"',
  "workers_dev = true",
  "upload_source_maps = false",
  "[assets]",
  'directory = "./target/site"',
  'binding = "ASSETS"',
  "[observability]",
  "enabled = false",
]) requireSnippet("wrangler.toml", wrangler, snippet);

for (const forbidden of ["d1_databases", "kv_namespaces", "r2_buckets", "analytics_engine_datasets"]) {
  if (wrangler.includes(forbidden)) throw new Error(`wrangler.toml unexpectedly contains ${forbidden}`);
}
if (!existsSync(shimPath)) throw new Error(`missing Worker shim: ${shimPath}`);
const shim = await readFile(shimPath, "utf8");
for (const snippet of ['import LeptosWorker from "./index.js";', "export default class extends LeptosWorker", '"/asset-manifest.json"', '"/favicon.svg"', '"/site.webmanifest"', '"/robots.txt"', ...[manifest.js, manifest.wasm, manifest.css].map((path) => JSON.stringify(path)), "this.env.ASSETS.fetch(request)", "super.fetch(request)"]) requireSnippet("build/_worker.js", shim, snippet);
for (const forbidden of ["STATIC_ASSET_PREFIXES", '"/pkg/"', "WebSocketPair", "REALTIME_SOCKET_PATH", ".DB", ".KV", ".R2"]) if (shim.includes(forbidden)) throw new Error(`Worker shim contains broad asset routing or template residue: ${forbidden}`);
console.log("[verify-worker-runtime] Workers Assets allowlist, SSR fallback, and zero-storage contract are aligned");

#!/usr/bin/env bun

import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

const root = process.cwd();
const wrangler = await readFile(join(root, "wrangler.toml"), "utf8");
const shimPath = join(root, "build/_worker.js");
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
for (const snippet of ['import LeptosWorker from "./index.js";', "export default class extends LeptosWorker", '"/pkg/"', '"/asset-manifest.json"', '"/favicon.svg"', '"/site.webmanifest"', '"/robots.txt"', "this.env.ASSETS.fetch(request)", "super.fetch(request)"]) requireSnippet("build/_worker.js", shim, snippet);
for (const forbidden of ["WebSocketPair", "REALTIME_SOCKET_PATH", ".DB", ".KV", ".R2"]) if (shim.includes(forbidden)) throw new Error(`Worker shim contains template residue: ${forbidden}`);
console.log("[verify-worker-runtime] Workers Assets allowlist, SSR fallback, and zero-storage contract are aligned");

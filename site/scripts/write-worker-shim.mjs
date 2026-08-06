#!/usr/bin/env bun

import { existsSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const root = process.cwd();
const workerBundle = join(root, "build/index.js");
const shimPath = join(root, "build/_worker.js");
if (!existsSync(workerBundle)) {
  console.error(`[write-worker-shim] missing Worker bundle: ${workerBundle}`);
  process.exit(1);
}

await mkdir(dirname(shimPath), { recursive: true });
await writeFile(shimPath, [
  'import LeptosWorker from "./index.js";',
  "",
  "const STATIC_ASSET_PATHS = [",
  '  "/asset-manifest.json",',
  '  "/favicon.svg",',
  '  "/site.webmanifest",',
  '  "/robots.txt",',
  "];",
  'const STATIC_ASSET_PREFIXES = ["/pkg/"];',
  "",
  "function shouldServeAsset(pathname) {",
  "  return STATIC_ASSET_PATHS.includes(pathname)",
  "    || STATIC_ASSET_PREFIXES.some((prefix) => pathname.startsWith(prefix));",
  "}",
  "",
  "export default class extends LeptosWorker {",
  "  async fetch(request) {",
  "    const url = new URL(request.url);",
  "    if (shouldServeAsset(url.pathname)) return this.env.ASSETS.fetch(request);",
  "    return super.fetch(request);",
  "  }",
  "}",
  "",
].join("\n"));

console.log("[write-worker-shim] wrote build/_worker.js");

#!/usr/bin/env bun

import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";

const root = process.cwd();
const workerBundle = join(root, "build/index.js");
const shimPath = join(root, "build/_worker.js");
const manifestPath = join(root, "target/site/asset-manifest.json");
if (!existsSync(workerBundle)) {
  console.error(`[write-worker-shim] missing Worker bundle: ${workerBundle}`);
  process.exit(1);
}
if (!existsSync(manifestPath)) {
  console.error(`[write-worker-shim] missing asset manifest: ${manifestPath}`);
  process.exit(1);
}
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const packageAssets = ["js", "wasm", "css"].map((kind) => {
  const path = manifest[kind];
  if (typeof path !== "string" || !/^\/pkg\/[^/]+\.[a-f0-9]{16}\.(?:js|wasm|css)$/.test(path)) {
    throw new Error(`asset manifest has an invalid ${kind} path`);
  }
  return path;
});

await mkdir(dirname(shimPath), { recursive: true });
await writeFile(shimPath, [
  'import LeptosWorker from "./index.js";',
  "",
  "const STATIC_ASSET_PATHS = [",
  '  "/asset-manifest.json",',
  '  "/favicon.svg",',
  '  "/site.webmanifest",',
  '  "/robots.txt",',
  ...packageAssets.map((path) => `  ${JSON.stringify(path)},`),
  "];",
  "",
  "function shouldServeAsset(pathname) {",
  "  return STATIC_ASSET_PATHS.includes(pathname);",
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

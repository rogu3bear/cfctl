#!/usr/bin/env bun

import { existsSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

function runOrThrow(command, args) {
  const result = Bun.spawnSync([command, ...args], { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" });
  if (result.exitCode !== 0) throw new Error(new TextDecoder().decode(result.stderr).trim() || `${command} failed`);
  return new TextDecoder().decode(result.stdout);
}

const metadata = JSON.parse(runOrThrow("cargo", ["metadata", "--no-deps", "--format-version", "1"]));
const workspaceRoot = metadata.workspace_root;
const rootPackage = metadata.packages.find((item) => item.manifest_path === join(workspaceRoot, "Cargo.toml"));
const leptos = rootPackage?.metadata?.leptos;
if (!leptos) throw new Error("missing package.metadata.leptos");
const outputName = leptos["output-name"];
const siteRoot = join(workspaceRoot, leptos["site-root"]);
const pkgDir = join(siteRoot, leptos["site-pkg-dir"]);
const manifestPath = join(siteRoot, "asset-manifest.json");
const hashesPath = join(workspaceRoot, "target/asset-hashes.env");
const headersPath = join(siteRoot, "_headers");
for (const path of [manifestPath, hashesPath, headersPath]) if (!existsSync(path)) throw new Error(`missing generated file: ${path}`);
const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const generatedHashes = await readFile(hashesPath, "utf8");
const headers = await readFile(headersPath, "utf8");

async function filesUnder(root, relative = "") {
  const entries = await readdir(join(root, relative), { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const path = join(relative, entry.name);
    if (entry.isDirectory()) files.push(...await filesUnder(root, path));
    else if (entry.isFile()) files.push(path);
    else throw new Error(`deployment asset is not a regular file: ${path}`);
  }
  return files;
}

for (const kind of ["js", "wasm", "css"]) {
  const href = manifest[kind];
  if (typeof href !== "string" || !href.includes(`.${manifest.hashes[kind]}.`)) throw new Error(`${kind} is not hashed`);
  if (!existsSync(join(siteRoot, href.replace(/^\//, "")))) throw new Error(`${kind} manifest target is missing`);
  if (existsSync(join(pkgDir, `${outputName}.${kind}`))) throw new Error(`unhashed ${kind} artifact remains`);
  if (!generatedHashes.includes(`"${manifest.hashes[kind]}"`)) throw new Error(`${kind} hash env is out of sync`);
}

for (const snippet of ["/pkg/*", "Cache-Control: public, max-age=31536000, immutable", "/asset-manifest.json", "Cache-Control: no-store"]) {
  if (!headers.includes(snippet)) throw new Error(`_headers is missing: ${snippet}`);
}

const expectedFiles = [
  "_headers",
  "asset-manifest.json",
  "favicon.svg",
  "robots.txt",
  "site.webmanifest",
  ...[manifest.js, manifest.wasm, manifest.css].map((path) => path.replace(/^\//, "")),
].sort();
const actualFiles = (await filesUnder(siteRoot)).sort();
if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
  const missing = expectedFiles.filter((path) => !actualFiles.includes(path));
  const unexpected = actualFiles.filter((path) => !expectedFiles.includes(path));
  throw new Error(`deployment asset allowlist drifted; missing=[${missing.join(", ")}], unexpected=[${unexpected.join(", ")}]`);
}
console.log("[verify-hashed-assets] immutable hashed assets and manifest are aligned");

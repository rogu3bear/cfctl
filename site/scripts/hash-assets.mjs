#!/usr/bin/env bun

import { createHash } from "node:crypto";
import { existsSync, readdirSync } from "node:fs";
import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";

function runOrThrow(command, args) {
  const result = Bun.spawnSync([command, ...args], { cwd: process.cwd(), stdout: "pipe", stderr: "pipe" });
  if (result.exitCode !== 0) {
    throw new Error(new TextDecoder().decode(result.stderr).trim() || `${command} failed`);
  }
  return new TextDecoder().decode(result.stdout);
}

function shortHash(buffer) {
  return createHash("sha256").update(buffer).digest("hex").slice(0, 16);
}

async function removeStale(pkgDir, outputName, extension) {
  const escaped = outputName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const pattern = new RegExp(`^${escaped}\\.[a-f0-9]{16}\\.${extension}$`);
  for (const entry of readdirSync(pkgDir)) {
    if (pattern.test(entry)) await rm(join(pkgDir, entry), { force: true });
  }
}

async function main() {
  const metadata = JSON.parse(runOrThrow("cargo", ["metadata", "--no-deps", "--format-version", "1"]));
  const workspaceRoot = metadata.workspace_root;
  const rootPackage = metadata.packages.find((item) => item.manifest_path === join(workspaceRoot, "Cargo.toml"));
  const leptos = rootPackage?.metadata?.leptos;
  if (!leptos) throw new Error("missing package.metadata.leptos");

  const outputName = leptos["output-name"];
  const siteRoot = join(workspaceRoot, leptos["site-root"]);
  const pkgDir = join(siteRoot, leptos["site-pkg-dir"]);
  await rm(join(pkgDir, `${outputName}.d.ts`), { force: true });
  await rm(join(pkgDir, `${outputName}_bg.wasm.d.ts`), { force: true });
  const paths = Object.fromEntries(["js", "wasm", "css"].map((extension) => [extension, join(pkgDir, `${outputName}.${extension}`)]));
  for (const path of Object.values(paths)) if (!existsSync(path)) throw new Error(`missing build artifact: ${path}`);
  for (const extension of Object.keys(paths)) await removeStale(pkgDir, outputName, extension);

  const buffers = Object.fromEntries(await Promise.all(Object.entries(paths).map(async ([kind, path]) => [kind, await readFile(path)])));
  const hashes = Object.fromEntries(Object.entries(buffers).map(([kind, buffer]) => [kind, shortHash(buffer)]));
  const names = Object.fromEntries(Object.keys(paths).map((kind) => [kind, `${outputName}.${hashes[kind]}.${kind}`]));
  const rewrittenJs = new TextDecoder().decode(buffers.js).replace(/new URL\("([^"]+\.wasm)",import\.meta\.url\)/, `new URL("${names.wasm}",import.meta.url)`);

  await writeFile(join(pkgDir, names.js), rewrittenJs);
  await writeFile(join(pkgDir, names.css), buffers.css);
  await rename(paths.wasm, join(pkgDir, names.wasm));
  await rm(paths.js, { force: true });
  await rm(paths.css, { force: true });

  const manifest = { js: `/pkg/${names.js}`, wasm: `/pkg/${names.wasm}`, css: `/pkg/${names.css}`, hashes };
  await writeFile(join(siteRoot, "asset-manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`);
  await writeFile(join(workspaceRoot, "target/asset-hashes.env"), [
    `export LEPTOS_EDGE_JS_HASH="${hashes.js}"`,
    `export LEPTOS_EDGE_WASM_HASH="${hashes.wasm}"`,
    `export LEPTOS_EDGE_CSS_HASH="${hashes.css}"`,
    "",
  ].join("\n"));
}

main().catch((error) => { console.error(`[hash-assets] ${error.message}`); process.exit(1); });

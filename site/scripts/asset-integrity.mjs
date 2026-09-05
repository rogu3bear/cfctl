import { createHash } from "node:crypto";

export function shortHash(bytes) {
  return createHash("sha256").update(bytes).digest("hex").slice(0, 16);
}

export function wasmImport(source) {
  const pattern = /new URL\(\s*["']([^"']+\.wasm)["']\s*,\s*import\.meta\.url\s*\)/g;
  const matches = [...source.matchAll(pattern)];
  if (matches.length !== 1) throw new Error("expected exactly one generated WASM import");
  return { pattern, target: matches[0][1] };
}

export function verifyAssetManifest(manifest, outputName = "cfctl-site") {
  if (!manifest || typeof manifest !== "object" || !manifest.hashes) throw new Error("asset manifest lacks hashes");
  for (const kind of ["js", "wasm", "css"]) {
    const digest = manifest.hashes[kind];
    if (typeof digest !== "string" || !/^[0-9a-f]{16}$/.test(digest)) throw new Error(`manifest ${kind} hash is invalid`);
    if (manifest[kind] !== `/pkg/${outputName}.${digest}.${kind}`) throw new Error(`manifest ${kind} path is not bound to its hash`);
  }
}

export function verifyAssetBytes(manifest, kind, bytes, outputName = "cfctl-site") {
  verifyAssetManifest(manifest, outputName);
  const buffer = Buffer.from(bytes);
  if (buffer.byteLength === 0 || shortHash(buffer) !== manifest.hashes[kind]) throw new Error(`${kind} actual bytes do not match manifest digest`);
  if (kind === "js") {
    const source = new TextDecoder("utf-8", { fatal: true }).decode(buffer);
    if (wasmImport(source).target !== manifest.wasm.slice("/pkg/".length)) throw new Error("JavaScript WASM import does not match manifest");
  }
}

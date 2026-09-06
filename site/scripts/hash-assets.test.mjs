import { expect, test } from "bun:test";
import { fingerprintAssets } from "./hash-assets.mjs";
import { shortHash, verifyAssetBytes } from "./asset-integrity.mjs";

const buffers = {
  js: Buffer.from('const module = new URL("cfctl-site.wasm",import.meta.url);'),
  wasm: Buffer.from("wasm-one"),
  css: Buffer.from("body{margin:0}"),
};
function manifest(result) {
  return { ...Object.fromEntries(Object.entries(result.names).map(([kind, name]) => [kind, `/pkg/${name}`])), hashes: result.hashes };
}

test("immutable JS names identify final bytes and change with WASM alone", () => {
  const first = fingerprintAssets("cfctl-site", buffers);
  const second = fingerprintAssets("cfctl-site", { ...buffers, wasm: Buffer.from("wasm-two") });
  expect(first.hashes.js).toBe(shortHash(first.rewrittenJs));
  expect(first.names.js).not.toBe(second.names.js);
  expect(first.names.wasm).not.toBe(second.names.wasm);
  expect(first.names.css).toBe(second.names.css);
  expect(fingerprintAssets("cfctl-site", buffers)).toEqual(first);
  for (const [kind, bytes] of Object.entries({ ...buffers, js: Buffer.from(first.rewrittenJs) })) {
    expect(() => verifyAssetBytes(manifest(first), kind, bytes)).not.toThrow();
    expect(() => verifyAssetBytes(manifest(first), kind, Buffer.concat([bytes, Buffer.from("changed")]))).toThrow("actual bytes");
  }
});

test("unrecognized and ambiguous generated imports fail closed", () => {
  for (const source of ["no import", 'new URL("module.wasm",other)', buffers.js.toString().repeat(2)]) {
    expect(() => fingerprintAssets("cfctl-site", { ...buffers, js: Buffer.from(source) })).toThrow("exactly one");
  }
});

test("matching JS digest cannot hide a wrong WASM reference", () => {
  const result = fingerprintAssets("cfctl-site", buffers);
  const wrong = result.rewrittenJs.replace(result.names.wasm, "different.wasm");
  const changed = manifest(result);
  changed.hashes = { ...changed.hashes, js: shortHash(wrong) };
  changed.js = `/pkg/cfctl-site.${changed.hashes.js}.js`;
  expect(() => verifyAssetBytes(changed, "js", Buffer.from(wrong))).toThrow("WASM import");
});

// Private parser input is the captured manifest, never a source directory.
// esbuild only parses: no output from this check is a transport artifact.
// https://esbuild.github.io/plugins/#resolve-callbacks
// https://esbuild.github.io/api/#log-override
const fs = require('node:fs');
const path = require('node:path').posix;
const crypto = require('node:crypto');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const esbuild = require(input.esbuild);
const files = new Map(input.files.map(file => [file.path, file]));
const edges = new Map();
const inModules = name => name.startsWith(input.module_root + '/');
const decoder = new TextDecoder('utf-8', { fatal: true });
const digest = bytes => crypto.createHash('sha256').update(bytes).digest('hex');
const types = { ESModule: 'esm', CommonJS: 'commonjs', CompiledWasm: 'compiled-wasm', Data: 'buffer', Text: 'text' };

// Closed, path-segment glob grammar matching Wrangler's globstar=true,
// extended=false behavior. Unsupported spellings fail instead of being
// interpreted by another filesystem resolver.
function globPattern(glob) {
  if (typeof glob !== 'string' || !glob || glob.length > 512 ||
      /[\\\x00-\x1f\x7f]/.test(glob)) failure();
  const segments = glob.split('/');
  if (segments.some(segment => !segment || segment === '.' || segment === '..')) failure();
  const escape = text => text.replace(/[|\\{}()[\]^$+?.=!,-]/g, '\\$&');
  let expression = '^';
  segments.forEach((segment, index) => {
    if (/^\*{2,}$/.test(segment)) {
      expression += index + 1 === segments.length ? '(?:[^/]+(?:/|$))*' : '(?:[^/]+/)*';
    } else {
      expression += segment.split(/\*+/).map(escape).join('[^/]*');
      if (index + 1 !== segments.length) expression += '/';
    }
  });
  return new RegExp(expression + '$');
}

function moduleSelection() {
  if (!Array.isArray(input.rules) || input.rules.length > 128) failure();
  const configured = [...input.rules,
    { type: 'Text', globs: ['**/*.txt', '**/*.html', '**/*.sql'] },
    { type: 'Data', globs: ['**/*.bin'] },
    { type: 'CompiledWasm', globs: ['**/*.wasm', '**/*.wasm?module'] },
  ];
  const completed = new Set();
  const rules = [];
  for (const rule of configured) {
    if (!rule || !Object.hasOwn(types, rule.type) || !Array.isArray(rule.globs) ||
        !rule.globs.length || rule.globs.length > 128 ||
        Object.keys(rule).some(key => !['type', 'globs', 'fallthrough'].includes(key)) ||
        (rule.fallthrough !== undefined && typeof rule.fallthrough !== 'boolean')) failure();
    const patterns = rule.globs.map(globPattern);
    if (completed.has(rule.type)) continue;
    rules.push({ type: types[rule.type], patterns });
    if (rule.fallthrough !== true) completed.add(rule.type);
  }
  const selected = new Map();
  for (const file of files.values()) {
    if (!inModules(file.path)) continue;
    const name = path.relative(input.module_root, file.path);
    const rule = rules.find(rule => rule.patterns.some(pattern => pattern.test(name)));
    if (file.path === input.main || (input.find_additional_modules && rule)) {
      const bytes = Buffer.from(file.content, 'base64');
      selected.set(file.path, { path: file.path,
        name: file.path === input.main ? path.basename(file.path) : name,
        type: file.path === input.main ? 'esm' : rule.type, size: bytes.length, sha256: digest(bytes) });
    }
  }
  if (new Set([...selected.values()].map(module => module.name)).size !== selected.size) failure();
  return selected;
}
const selected = moduleSelection();
const modules = [...selected.values()].filter(module => ['esm', 'commonjs'].includes(module.type))
  .map(module => module.path).sort();

function failure() { throw new Error('unclosed module input'); }
function localPath(importer, specifier) {
  if (!specifier.startsWith('./') && !specifier.startsWith('../')) failure();
  if (/[\\\x00-\x1f\x7f?#]/.test(specifier)) failure();
  const resolved = path.normalize(path.join(path.dirname(importer), specifier));
  if (!inModules(resolved) || !files.has(resolved)) failure();
  return resolved;
}

function cleanPrefix(value) {
  let cleaned = value;
  for (const prefix of ['./', '.\\', '../', '..\\']) {
    while (cleaned.startsWith(prefix)) cleaned = cleaned.slice(prefix.length);
  }
  return cleaned;
}

function sourceMap(module, contents) {
  if (!input.upload_source_maps) return null;
  let reference;
  for (const raw of contents.split('\n').reverse()) {
    const line = raw.trim();
    if (!line) continue;
    if (line.startsWith('//# sourceMappingURL=')) { reference = line.slice(21).trim(); break; }
    if (!line.startsWith('//#') && !line.startsWith('//@')) break;
  }
  if (reference === undefined) return null;
  const sourcePath = localPath(module.path, reference.startsWith('.') ? reference : './' + reference);
  const map = JSON.parse(decoder.decode(Buffer.from(files.get(sourcePath).content, 'base64')));
  // Wrangler's no-bundle source map transport reads only this JSON. Require
  // embedded source bytes whenever sources are declared; nested/external maps
  // are not part of this closed contract.
  if (!map || map.version !== 3 || map.sections !== undefined || !Array.isArray(map.sources) ||
      map.sources.some(source => typeof source !== 'string') ||
      (map.sourceRoot !== undefined && typeof map.sourceRoot !== 'string') ||
      (map.sources.length && (!Array.isArray(map.sourcesContent) ||
        map.sourcesContent.length !== map.sources.length ||
        map.sourcesContent.some(source => typeof source !== 'string')))) failure();
  map.file = module.name;
  if (map.sourceRoot) map.sourceRoot = cleanPrefix(map.sourceRoot);
  map.sources = map.sources.map(cleanPrefix);
  const emitted = Buffer.from(JSON.stringify(map));
  record(module.path, reference, sourcePath, 'source_map');
  return { path: sourcePath, name: module.name + '.map', type: 'source-map',
    size: emitted.length, sha256: digest(emitted), transformation: 'wrangler-no-bundle-source-map-v1' };
}
function record(importer, specifier, resolved, kind) {
  const edge = { importer, specifier, resolved, kind };
  edges.set(JSON.stringify(edge), edge);
}

async function main() {
  if (!modules.includes(input.main)) failure();
  const sourceMaps = [...selected.values()].map(module => sourceMap(module,
    Buffer.from(files.get(module.path).content, 'base64').toString('utf8'))).filter(Boolean);
  const result = await esbuild.build({
    entryPoints: modules,
    bundle: true,
    write: false,
    outdir: 'unused-parser-output',
    platform: 'neutral',
    format: 'esm',
    target: 'esnext',
    supported: { 'import-source': true },
    treeShaking: false,
    tsconfigRaw: {},
    metafile: true,
    logLevel: 'silent',
    logOverride: {
      'unsupported-dynamic-import': 'error',
      'unsupported-require-call': 'error',
      'ignored-dynamic-import': 'error',
      'ignored-require': 'error',
      'require-resolve-not-external': 'error',
      'empty-glob': 'error',
    },
    plugins: [{
      name: 'cfctl-frozen-module-closure',
      setup(build) {
        build.onResolve({ filter: /.*/ }, args => {
          if (args.kind === 'entry-point') {
            if (!modules.includes(args.path)) failure();
            return { path: args.path, namespace: 'admitted' };
          }
          if (/^(?:cloudflare|node):[a-zA-Z0-9_\/-]+$/.test(args.path)) {
            record(args.importer, args.path, args.path, 'platform');
            return { path: args.path, external: true };
          }
          const resolved = localPath(args.importer, args.path);
          const destination = selected.get(resolved);
          const importer = selected.get(args.importer);
          if (!destination || !importer ||
              path.normalize(path.join(path.dirname(importer.name), args.path)) !== destination.name) failure();
          record(args.importer, args.path, resolved, 'artifact');
          // Each JS file is separately parsed as an entry point. An external
          // here cannot invoke esbuild's default filesystem/package resolver.
          return { path: args.path, external: true };
        });
        build.onLoad({ filter: /.*/, namespace: 'admitted' }, args => {
          const contents = decoder.decode(Buffer.from(files.get(args.path).content, 'base64'));
          return { contents, loader: 'js' };
        });
      },
    }],
  });
  if (result.warnings.length) failure();
  const mainOutput = Object.values(result.metafile.outputs)
    .find(output => output.entryPoint === 'admitted:' + input.main);
  if (!mainOutput) failure();
  const mainInput = result.metafile.inputs['admitted:' + input.main];
  selected.get(input.main).type = mainInput?.format === 'esm' && mainOutput.exports.includes('default')
    ? 'esm' : 'commonjs';
  const ordered = [...edges.entries()].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0)
    .map(([, value]) => value);
  const uploaded = [...selected.values()].sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  process.stdout.write(JSON.stringify({ schema_version: 1, modules: uploaded,
    source_maps: sourceMaps, edges: ordered }));
}
main().catch(() => {
  // Parser errors may contain source text and values. They never become a
  // public receipt; the Rust boundary reports a fixed closed-contract error.
  process.exitCode = 1;
}).finally(() => esbuild.stop());

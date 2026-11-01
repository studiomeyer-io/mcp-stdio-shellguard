import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createHash } from 'node:crypto';

const root = process.cwd();
const pkg = JSON.parse(readFileSync(resolve(root, 'package.json'), 'utf8'));
const lock = readFileSync(resolve(root, 'package-lock.json'));
const patches = pkg.name === 'mcp-spec-migrator' || pkg.name === 'mcp-stateless-migrator'
  ? [{ name: '@ts-morph/common', version: '0.29.0', from: '^10.0.1' }]
  : pkg.name === 'mcp-stdio-shellguard'
    ? [{ name: '@typescript-eslint/typescript-estree', version: '8.72.1', from: '^10.2.2' }]
    : [];
const applied = [];
for (const patch of patches) {
  const manifestPath = resolve(root, 'node_modules', patch.name, 'package.json');
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const minimatch = JSON.parse(readFileSync(resolve(root, 'node_modules/minimatch/package.json'), 'utf8'));
  if (manifest.version !== patch.version || minimatch.version !== '11.0.3') {
    throw new Error(`Unreviewed bundle versions for ${patch.name}; review the pinned dependency tree before packing`);
  }
  const current = manifest.dependencies?.minimatch;
  if (current !== patch.from && current !== '^11.0.3') {
    throw new Error(`Unreviewed minimatch contract in ${patch.name}: ${current}`);
  }
  manifest.dependencies.minimatch = '^11.0.3';
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  applied.push({ package: patch.name, version: patch.version, dependency: 'minimatch', originalRange: patch.from, bundledRange: '^11.0.3' });
}
const metadata = {
  formatVersion: 1,
  bundledDependencies: pkg.bundledDependencies,
  lockSha256: createHash('sha256').update(lock).digest('hex'),
  manifestRangeAdjustments: applied,
  thirdPartySourceModified: false,
};
writeFileSync(resolve(root, 'dist/bundled-dependencies.json'), `${JSON.stringify(metadata, null, 2)}\n`);

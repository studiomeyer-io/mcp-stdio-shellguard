import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdirSync, mkdtempSync, rmSync, existsSync } from 'node:fs';
import { resolve, join, dirname } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { createHash } from 'node:crypto';
import { strict as assert } from 'node:assert';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
const artifactRoot = process.env.CONSUMER_ARTIFACT_DIR ? resolve(process.env.CONSUMER_ARTIFACT_DIR) : mkdtempSync(join(tmpdir(), `${pkg.name.replaceAll('/', '-')}-consumer-`));
mkdirSync(artifactRoot, { recursive: true });
const npm = process.env.npm_execpath;
if (!npm) throw new Error('Run this check using npm run test:consumer');
const npmRun = (args, cwd, label) => {
  const result = spawnSync(process.execPath, [npm, ...args], { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, timeout: 300000, env: { ...process.env, npm_config_update_notifier: 'false' } });
  writeFileSync(join(artifactRoot, `${label}.log`), `${result.stdout ?? ''}${result.stderr ?? ''}`);
  if (result.error || result.status !== 0) throw new Error(`${label} failed: ${result.error?.message ?? result.status}; see ${artifactRoot}`);
  return result.stdout;
};
const parsePack = output => JSON.parse(output.slice(output.lastIndexOf('\n[') + 1));
try {
  const hashes = [];
  let metadata;
  let tarball;
  for (const round of [1, 2]) {
    const dest = join(artifactRoot, `pack-${round}`);
    mkdirSync(dest, { recursive: true });
    metadata = parsePack(npmRun(['pack', '--json', '--pack-destination', dest], root, `pack-${round}`))[0];
    tarball = join(dest, metadata.filename);
    hashes.push(createHash('sha256').update(readFileSync(tarball)).digest('hex'));
  }
  assert.equal(hashes[0], hashes[1], 'two npm packs must produce identical artifacts');
  assert.ok(metadata.files.some(file => file.path === 'dist/bundled-dependencies.json'));
  assert.ok(metadata.bundled.length > 0);
  // Read the actual packed payload, not the potentially different producer files.
  const packed = join(artifactRoot, 'packed');
  mkdirSync(packed, { recursive: true });
  execFileSync('tar', ['-xzf', tarball, '-C', packed]);
  const packedRoot = join(packed, 'package');
  const packedPkg = JSON.parse(readFileSync(join(packedRoot, 'package.json'), 'utf8'));
  assert.equal(packedPkg.version, pkg.version, 'packed candidate version');
  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
  assert.equal(lock.version, pkg.version, 'lockfile root version');
  assert.equal(lock.packages[''].version, pkg.version, 'lockfile package version');
  const registryDescriptor = join(root, 'server.json');
  if (existsSync(registryDescriptor)) {
    const descriptor = JSON.parse(readFileSync(registryDescriptor, 'utf8'));
    assert.equal(descriptor.version, pkg.version, 'MCP registry descriptor version');
    for (const entry of descriptor.packages.filter(entry => entry.registryType === 'npm' && entry.identifier === pkg.name)) {
      assert.equal(entry.version, pkg.version, 'MCP npm descriptor version');
    }
  }
  const proofs = JSON.parse(readFileSync(join(root, 'scripts/bundled-license-proofs.json'), 'utf8'));
  assert.equal(proofs.formatVersion, 1);
  const canonical = text => text.replace(/\s+/gu, ' ').trim();
  const licenseInventory = [];
  const bundledManifests = metadata.files.filter(file => {
    if (!file.path.startsWith('node_modules/') || !file.path.endsWith('/package.json')) return false;
    const tail = file.path.slice(file.path.lastIndexOf('node_modules/') + 'node_modules/'.length).split('/');
    return tail.length === (tail[0].startsWith('@') ? 3 : 2);
  });
  for (const file of bundledManifests) {
    const folder = dirname(file.path);
    const manifest = JSON.parse(readFileSync(join(packedRoot, file.path), 'utf8'));
    const identity = `${manifest.name}@${manifest.version}`;
    const proof = proofs.packages[identity];
    assert.ok(proof, `unreviewed bundled license version: ${identity}`);
    assert.deepEqual(manifest.license, proof.license, `bundled license declaration: ${identity}`);
    assert.ok(proof.files.length > 0, `no approved complete license text: ${identity}`);
    const verified = [];
    for (const legal of proof.files) {
      const path = join(folder, legal.path);
      assert.ok(metadata.files.some(entry => entry.path === path), `bundled license missing: ${identity} ${legal.path}`);
      let content = canonical(readFileSync(join(packedRoot, path), 'utf8'));
      if (legal.kind === 'complete-upstream-readme-license-section') {
        const begin = content.indexOf(legal.sectionStart);
        const end = content.indexOf(legal.sectionEnd, begin);
        assert.ok(begin >= 0 && end >= begin, `complete README license section missing: ${identity}`);
        content = content.slice(begin, end + legal.sectionEnd.length);
      } else {
        assert.equal(legal.kind, 'complete-upstream-file', `unknown license proof kind: ${identity}`);
      }
      assert.equal(createHash('sha256').update(content).digest('hex'), legal.canonicalSha256,
        `bundled license differs from complete approved upstream text: ${identity} ${legal.path}`);
      verified.push({ path, canonicalSha256: legal.canonicalSha256, kind: legal.kind });
    }
    licenseInventory.push({ name: manifest.name, version: manifest.version, license: manifest.license,
      files: verified.map(entry => entry.path), verified, source: proof.source, integrity: proof.integrity });
  }
  const consumer = join(artifactRoot, 'consumer');
  mkdirSync(consumer, { recursive: true });
  writeFileSync(join(consumer, 'package.json'), JSON.stringify({ name: 'isolated-packed-consumer', version: '1.0.0', private: true, dependencies: { [pkg.name]: `file:${tarball}` } }));
  npmRun(['install', '--ignore-scripts', '--no-fund'], consumer, 'install');
  npmRun(['ls', '--all', '--json'], consumer, 'tree');
  const audits = {};
  for (const [mode, extra] of [['all', []], ['production', ['--omit=dev']]]) {
    let report;
    for (let attempt = 1; attempt <= 3; attempt++) {
      const result = spawnSync(process.execPath, [npm, 'audit', '--json', '--ignore-scripts', ...extra], { cwd: consumer, encoding: 'utf8', timeout: 180000, maxBuffer: 8 * 1024 * 1024 });
      writeFileSync(join(artifactRoot, `audit-${mode}-${attempt}.json`), result.stdout ?? '');
      try { report = JSON.parse(result.stdout); } catch { throw new Error('Audit returned invalid JSON'); }
      if (report.metadata?.vulnerabilities) break;
      if (!/audit endpoint returned an error|ECONNRESET|ETIMEDOUT|socket hang up/i.test(`${result.stdout}${result.stderr}`) || attempt === 3) throw new Error('Audit service unavailable or returned an unexpected error');
    }
    assert.equal(report.metadata.vulnerabilities.total, 0, `${mode} consumer vulnerabilities`);
    audits[mode] = report.metadata.vulnerabilities;
  }
  const runtime = execFileSync(process.execPath, [join(root, 'scripts/consumer-runtime.mjs'), consumer, pkg.name], { cwd: consumer, encoding: 'utf8', timeout: 60000, maxBuffer: 8 * 1024 * 1024 });
  writeFileSync(join(artifactRoot, 'runtime.log'), runtime);
  const result = { node: process.version, package: pkg.name, sha256: hashes[0], size: metadata.size, unpackedSize: metadata.unpackedSize, files: metadata.files, bundled: metadata.bundled, licenses: licenseInventory, audits, runtime: runtime.trim() };
  writeFileSync(join(artifactRoot, 'result.json'), `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify({ ...result, files: result.files.length, licenses: result.licenses.length }));
} finally {
  if (!process.env.CONSUMER_ARTIFACT_DIR) rmSync(artifactRoot, { recursive: true, force: true });
}

import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { resolve, join } from 'node:path';
import { mkdirSync, writeFileSync, readFileSync } from 'node:fs';
import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { createServer } from 'node:http';
import https from 'node:https';

const [consumer, name] = process.argv.slice(2);
const installed = resolve(consumer, 'node_modules', name);
const require = createRequire(join(installed, 'package.json'));
const candidate = JSON.parse(readFileSync(join(installed, 'package.json'), 'utf8')).version;
const fixture = resolve(consumer, 'fixture');
mkdirSync(fixture, { recursive: true });
if (name === 'mcp-spec-migrator' || name === 'mcp-stateless-migrator') {
  assert.equal(execFileSync(process.execPath, [join(installed, 'dist/cli.js'), '--version'], { cwd: consumer, encoding: 'utf8' }).trim(), candidate, 'installed CLI candidate version');
  const { Project } = require('ts-morph');
  writeFileSync(join(fixture, 'one.ts'), 'export const one = 1;');
  writeFileSync(join(fixture, 'two.tsx'), 'export const two = 2;');
  const project = new Project({ skipAddingFilesFromTsConfig: true });
  assert.equal(project.addSourceFilesAtPaths(join(fixture, '*.{ts,tsx}')).length, 2);
  const args = name === 'mcp-spec-migrator' ? ['detect', fixture, '--json'] : ['report', fixture, '--format', 'json'];
  const report = execFileSync(process.execPath, [join(installed, 'dist/cli.js'), ...args], { cwd: consumer, encoding: 'utf8' });
  assert.equal(typeof JSON.parse(report), 'object');
  console.log('installed AST/glob and actual migration CLI passed');
} else if (name === 'mcp-stdio-shellguard') {
  assert.equal(execFileSync(process.execPath, [join(installed, 'dist/cli.js'), '--version'], { cwd: consumer, encoding: 'utf8' }).trim(), candidate, 'installed CLI candidate version');
  writeFileSync(join(fixture, 'unsafe.ts'), "import { exec as run } from 'node:child_process';\nconst input: string = process.argv[2]!;\nrun(input);\n");
  writeFileSync(join(fixture, 'component.tsx'), 'export const View = () => <div />;');
  const { scanPath } = await import(pathToFileURL(join(installed, 'dist/audit/scanner.js')));
  const result = await scanPath(fixture, { severityFloor: 'LOW' });
  assert.deepEqual(result.errors, []);
  assert.equal(result.summary.filesScanned, 2);
  assert.ok(result.findings.some(finding => ['HIGH', 'CRITICAL'].includes(finding.severity)));
  const sdk = require.resolve('@modelcontextprotocol/sdk/client/index.js').replace('/dist/cjs/', '/dist/esm/');
  const { Client } = await import(pathToFileURL(sdk));
  const { StdioClientTransport } = await import(pathToFileURL(sdk.replace('/client/index.js', '/client/stdio.js')));
  const client = new Client({ name: 'packed-consumer-check', version: '1.0.0' });
  const transport = new StdioClientTransport({ command: process.execPath, args: [join(installed, 'dist/server.js')], cwd: consumer, env: { PATH: process.env.PATH }, stderr: 'pipe' });
  try {
    await client.connect(transport);
    assert.equal(client.getServerVersion().version, candidate, 'installed MCP initialize candidate version');
    const { tools } = await client.listTools();
    assert.equal(tools.length, 8);
    for (const tool of tools) assert.ok(Object.keys(tool.inputSchema.properties ?? {}).length > 0);
    const exec = tools.find(tool => tool.name === 'guard_exec');
    assert.equal(exec.inputSchema.properties.env.additionalProperties.type, 'string');
    console.log('installed TS/TSX scanner, alias detection and eight stdio schemas passed');
  } finally { await client.close(); }
} else if (name === 'mcp-personal-suite') {
  const { google } = require('googleapis');
  let requests = 0;
  const server = createServer((request, response) => {
    assert.ok(request.url.startsWith('/calendar/v3/calendars/primary/events'));
    assert.equal(request.headers.authorization, 'Bearer synthetic-consumer-token');
    requests++;
    response.setHeader('Content-Type', 'application/json');
    response.end(JSON.stringify({ items: [{ id: 'synthetic-event', summary: 'Consumer test', start: { dateTime: '2026-01-01T10:00:00Z' }, end: { dateTime: '2026-01-01T11:00:00Z' } }] }));
  });
  await new Promise(done => server.listen(0, '127.0.0.1', done));
  const address = server.address();
  const originalRefresh = google.auth.OAuth2.prototype.refreshTokenNoCache;
  const originalCalendar = google.calendar;
  const originalHttpsRequest = https.request;
  https.request = () => { throw new Error('Consumer fixture forbids external HTTPS'); };
  google.auth.OAuth2.prototype.refreshTokenNoCache = async function () { return { tokens: { access_token: 'synthetic-consumer-token', expiry_date: Date.now() + 3600000 }, res: null }; };
  const rootUrl = `http://127.0.0.1:${address.port}/`;
  google.calendar = options => {
    const api = originalCalendar.call(google, options);
    const list = api.events.list.bind(api.events);
    api.events.list = (params, requestOptions = {}) => list(params, { ...requestOptions, rootUrl });
    return api;
  };
  Object.assign(process.env, { GOOGLE_CLIENT_ID: 'synthetic', GOOGLE_CLIENT_SECRET: 'synthetic', GOOGLE_REFRESH_TOKEN: 'synthetic', PERSONAL_SUITE_CONFIG_DIR: fixture });
  delete process.env.GOOGLE_CALENDAR_CREDENTIALS;
  try {
    const { listEvents } = await import(pathToFileURL(join(installed, 'dist/modules/calendar/google-calendar.js')));
    const events = await listEvents({ maxResults: 1 });
    assert.equal(events[0].id, 'synthetic-event');
    assert.equal(events[0].summary, 'Consumer test');
    assert.equal(requests, 1);
    console.log('installed application Calendar -> Google API -> auth -> gaxios -> loopback HTTP passed');
  } finally {
    google.auth.OAuth2.prototype.refreshTokenNoCache = originalRefresh;
    google.calendar = originalCalendar;
    https.request = originalHttpsRequest;
    await new Promise(done => server.close(done));
  }
} else { throw new Error(`No runtime probe for ${name}`); }

if (name === 'mcp-spec-migrator' || name === 'mcp-personal-suite') {
  const sdk = require.resolve('@modelcontextprotocol/sdk/client/index.js').replace('/dist/cjs/', '/dist/esm/');
  const { Client } = await import(pathToFileURL(sdk));
  const { StdioClientTransport } = await import(pathToFileURL(sdk.replace('/client/index.js', '/client/stdio.js')));
  const client = new Client({ name: 'packed-version-check', version: '1.0.0' });
  const transport = new StdioClientTransport({ command: process.execPath, args: [join(installed, 'dist/server.js')], cwd: consumer, env: { PATH: process.env.PATH, PERSONAL_SUITE_CONFIG_DIR: fixture }, stderr: 'pipe' });
  try {
    await client.connect(transport);
    assert.equal(client.getServerVersion().version, candidate, 'installed MCP initialize candidate version');
    console.log(`installed MCP initialize version ${candidate} matches packed package`);
  } finally { await client.close(); }
}

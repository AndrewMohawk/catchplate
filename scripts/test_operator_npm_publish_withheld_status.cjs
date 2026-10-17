#!/usr/bin/env node
// Stock npm response-status proof only: no proxy, real registry or provider.
// Root-run recipe: mount this checkout/dependencies read-only at /app and an
// existing compatible Node binary at /node in a cached --network=none container;
// use --read-only --tmpfs /tmp:rw,nosuid,nodev,size=32m --pids-limit=64,
// --memory=512m --cpus=1, and an external 60-second container deadline.
// Run: /node /app/scripts/test_operator_npm_publish_withheld_status.cjs
// No dependency acquisition, ports, credentials, lifecycle scripts or provenance.
// Complete safe receipts go to stdout before the owned temporary files vanish.
'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const {spawn} = require('node:child_process');
const {createHash} = require('node:crypto');
const {gunzipSync} = require('node:zlib');

const ROOT = path.resolve(__dirname, '..');
const NPM = path.join(ROOT, 'examples/npm-registry/node_modules/npm');
const CLI = path.join(NPM, 'bin/npm-cli.js');
const AUTH = 'synthetic-npm-status-token-not-a-provider-credential';
const LIMIT = 65536;
const children = new Set();
const servers = new Set();
const cases = [];
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
let stage = 'containment', temporary, globalTimer, timedOut = false;
const deadline = Date.now() + 45000;

function stopChildren() {
  for (const child of children) {
    try { process.kill(-child.pid, 'SIGKILL'); } catch (_) { /* Already reaped. */ }
  }
}
function refuse(message) { throw new Error(message); }
function privateWrite(file, bytes) {
  const fd = fs.openSync(file, 'wx', 0o600);
  try { fs.writeFileSync(fd, bytes); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function syncDirectory(directory) {
  const fd = fs.openSync(directory, fs.constants.O_RDONLY | fs.constants.O_DIRECTORY);
  try { fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
}
function containment() {
  assert.equal(process.platform, 'linux');
  assert.equal(process.argv.length, 2);
  assert.deepEqual(fs.readdirSync('/sys/class/net').sort(), ['lo']);
  const interfaces = os.networkInterfaces();
  assert.deepEqual(Object.keys(interfaces).sort(), ['lo']);
  assert(interfaces.lo.length > 0 && interfaces.lo.every(value => value.internal &&
    ['127.0.0.1', '::1'].includes(value.address)));
  for (const [file, name, version] of [['package.json', 'npm', '11.8.0'],
    ['node_modules/libnpmpublish/package.json', 'libnpmpublish', '11.1.3'],
    ['node_modules/make-fetch-happen/package.json', 'make-fetch-happen', '15.0.3']]) {
    const item = JSON.parse(fs.readFileSync(path.join(NPM, file), 'utf8'));
    assert.equal(item.name, name); assert.equal(item.version, version);
  }
  assert.equal(fs.realpathSync(NPM), NPM);
}
async function npm(args, directory, config) {
  assert(!timedOut && Date.now() < deadline);
  const command = [CLI, '--userconfig', config, '--globalconfig', '/dev/null',
    '--cache', path.join(directory, 'cache'), '--loglevel=silent', '--logs-max=0',
    '--update-notifier=false', '--progress=false', ...args];
  assert(command.every(value => !value.startsWith('--fetch-retries')));
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, command, {cwd: path.join(directory, 'package'),
      env: {LANG: 'C.UTF-8'}, stdio: ['ignore', 'pipe', 'pipe'], detached: true});
    children.add(child);
    let stdout = '', stderr = '', failed = false, spawnFailed = false;
    const timer = setTimeout(() => {
      failed = true;
      try { process.kill(-child.pid, 'SIGKILL'); } catch (_) {}
    }, Math.min(12000, deadline - Date.now()));
    for (const [stream, append] of [[child.stdout, chunk => { stdout += chunk; }],
      [child.stderr, chunk => { stderr += chunk; }]]) {
      stream.setEncoding('utf8');
      stream.on('data', chunk => {
        append(chunk);
        if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > LIMIT) {
          failed = true;
          try { process.kill(-child.pid, 'SIGKILL'); } catch (_) {}
        }
      });
    }
    child.on('error', () => { spawnFailed = true; });
    child.on('close', (code, signal) => {
      clearTimeout(timer); children.delete(child);
      if (failed || spawnFailed || timedOut || signal !== null)
        return reject(new Error('bounded npm child failed'));
      resolve({code, stdout, stderr});
    });
  });
}
function tarFiles(archive) {
  const bytes = gunzipSync(archive, {maxOutputLength: LIMIT});
  assert.equal(bytes.length % 512, 0);
  const files = new Map(); let offset = 0;
  while (offset + 512 <= bytes.length) {
    const header = bytes.subarray(offset, offset + 512);
    if (header.every(value => value === 0)) {
      assert(bytes.length - offset >= 1024 && bytes.subarray(offset).every(value => value === 0));
      return files;
    }
    const field = (start, end) => header.subarray(start, end).toString('utf8').replace(/\0.*$/s, '');
    const sizeField = field(124, 136).trim();
    assert(/^[0-7]+$/.test(sizeField));
    const size = parseInt(sizeField, 8);
    assert(size > 0 && size <= LIMIT && ['0', '\0'].includes(String.fromCharCode(header[156])));
    assert.equal(field(345, 500), '');
    const name = field(0, 100);
    assert(!files.has(name) && ['package/package.json', 'package/README.md'].includes(name));
    offset += 512;
    assert(offset + size <= bytes.length);
    files.set(name, Buffer.from(bytes.subarray(offset, offset + size)));
    offset += Math.ceil(size / 512) * 512;
  }
  refuse('synthetic tar termination differs');
}
function publication(bytes, spec, registry) {
  const value = JSON.parse(bytes.toString('utf8'));
  assert.equal(value.name, spec.name); assert.equal(value._id, spec.name);
  assert.deepEqual(Object.keys(value.versions), [spec.version]);
  assert.deepEqual(value['dist-tags'], {fixture: spec.version});
  const filename = spec.name + '-' + spec.version + '.tgz';
  assert.deepEqual(Object.keys(value._attachments), [filename]);
  const attachment = value._attachments[filename];
  assert.equal(attachment.content_type, 'application/octet-stream');
  assert.equal(typeof attachment.data, 'string');
  const archive = Buffer.from(attachment.data, 'base64');
  assert.equal(archive.toString('base64'), attachment.data);
  assert(archive.length > 0 && archive.length <= LIMIT);
  assert.equal(attachment.length, archive.length);
  const manifest = value.versions[spec.version];
  assert.equal(manifest.name, spec.name); assert.equal(manifest.version, spec.version);
  assert.equal(manifest.dist.shasum, createHash('sha1').update(archive).digest('hex'));
  assert.equal(manifest.dist.integrity, 'sha512-' + createHash('sha512').update(archive).digest('base64'));
  assert.equal(manifest.dist.tarball, registry + spec.name + '/-/' + filename);
  const files = tarFiles(archive);
  assert.equal(files.size, 2);
  assert.deepEqual(files.get('package/package.json'), spec.manifest);
  assert.deepEqual(files.get('package/README.md'), spec.readme);
  return {bodySha256: digest(bytes), tarballSha256: digest(archive), tarballBytes: archive.length};
}
async function runCase(status, expectedPuts) {
  const directory = path.join(temporary, 'status-' + status);
  fs.mkdirSync(directory, {mode: 0o700});
  for (const name of ['package', 'cache', 'publications']) fs.mkdirSync(path.join(directory, name), {mode: 0o700});
  const name = 'catchplate-local-status-' + status;
  const spec = {name, version: '1.0.0', readme: Buffer.from('Synthetic local publication status proof only.\n')};
  spec.manifest = Buffer.from(JSON.stringify({name, version: spec.version,
    description: 'Synthetic local publication status proof', license: 'UNLICENSED', files: ['README.md']}) + '\n');
  privateWrite(path.join(directory, 'package/package.json'), spec.manifest);
  privateWrite(path.join(directory, 'package/README.md'), spec.readme);
  const receipts = []; let reads = 0, invalid = 0, firstBody;
  const server = http.createServer(async (request, response) => {
    try {
      assert.equal(request.socket.remoteAddress, '127.0.0.1');
      assert.equal(request.url, '/' + name);
      assert.equal(request.headers.host, '127.0.0.1:' + server.address().port);
      assert.equal(request.headers.authorization, 'Bearer ' + AUTH);
      const chunks = []; let length = 0;
      for await (const chunk of request) {
        length += chunk.length; assert(length <= LIMIT); chunks.push(chunk);
      }
      const bytes = Buffer.concat(chunks);
      if (request.method === 'GET') {
        assert.equal(bytes.length, 0); assert.equal(++reads, 1);
        response.writeHead(200, {'Content-Type': 'application/json'});
        response.end(JSON.stringify({_id: name, name, versions: {}, 'dist-tags': {}}));
        return;
      }
      assert.equal(request.method, 'PUT');
      assert.match(request.headers['content-type'], /^application\/json(?:;\s*charset=utf-8)?$/i);
      assert.equal(Number(request.headers['content-length']), bytes.length);
      assert(receipts.length < expectedPuts);
      const commitment = publication(bytes, spec, 'http://127.0.0.1:' + server.address().port + '/');
      if (firstBody) assert.deepEqual(bytes, firstBody); else firstBody = Buffer.from(bytes);
      const ordinal = receipts.length + 1;
      const file = path.join(directory, 'publications', ordinal + '.json');
      privateWrite(file, bytes); syncDirectory(path.dirname(file));
      receipts.push({ordinal, method: 'PUT', path: '/' + name, ...commitment,
        persistedBeforeResponse: true, responseStatus: status});
      response.writeHead(status, {'Content-Type': 'application/json', 'Cache-Control': 'no-store'});
      response.end(JSON.stringify({error: 'catchplate_response_withheld',
        reason: 'Synthetic publication occurred; response withheld; do not retry'}));
    } catch (_) {
      invalid++;
      if (!response.headersSent) response.writeHead(400, {'Content-Type': 'application/json'});
      response.end('{"error":"synthetic_request_refused"}');
    }
  });
  server.requestTimeout = 3000; server.headersTimeout = 3000; server.maxRequestsPerSocket = 8;
  server.on('clientError', (_, socket) => { invalid++; socket.destroy(); });
  servers.add(server);
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  try {
    const registry = 'http://127.0.0.1:' + server.address().port + '/';
    const config = path.join(directory, 'user.npmrc');
    privateWrite(config, ['registry=' + registry, '//' + new URL(registry).host + '/:_authToken=' + AUTH,
      'fetch-retry-mintimeout=10', 'fetch-retry-maxtimeout=20', ''].join('\n'));
    const configured = await npm(['config', 'get', 'fetch-retries'], directory, config);
    assert.equal(configured.code, 0); assert.equal(configured.stdout, '2\n'); assert.equal(configured.stderr, '');
    stage = 'publish-' + status;
    const result = await npm(['publish', '.', '--access=public', '--tag=fixture', '--ignore-scripts=true',
      '--provenance=false', '--audit=false', '--fund=false', '--force=false', '--dry-run=false',
      '--workspaces=false', '--json'], directory, config);
    // close event above means the child and both output streams have finished.
    assert.equal(result.code, 1);
    const output = JSON.parse(result.stdout);
    assert.equal(output.error.code, 'E' + status);
    assert.equal(invalid, 0); assert.equal(reads, 1); assert.equal(receipts.length, expectedPuts);
    const entries = fs.readdirSync(path.join(directory, 'publications')).sort();
    assert.deepEqual(entries, receipts.map(item => item.ordinal + '.json'));
    for (const receipt of receipts) assert.equal(digest(fs.readFileSync(path.join(directory,
      'publications', receipt.ordinal + '.json'))), receipt.bodySha256);
    return {status, npmExitCode: result.code, npmErrorCode: output.error.code, defaultFetchRetries: 2,
      retryCountOverridden: false, retryMinTimeoutMs: 10, retryMaxTimeoutMs: 20,
      metadataReads: reads, publicationAttempts: receipts.length, receipts};
  } finally {
    const closed = new Promise(resolve => server.close(resolve));
    server.closeAllConnections(); await closed; servers.delete(server);
  }
}
async function main() {
  try {
    containment();
    globalTimer = setTimeout(() => {
      timedOut = true; stopChildren();
      for (const server of servers) { server.closeAllConnections(); server.close(); }
    }, Math.max(1, deadline - Date.now()));
    stage = 'private-workspace';
    temporary = fs.mkdtempSync('/tmp/catchplate-npm-status-');
    assert.equal(fs.statSync(temporary).mode & 0o777, 0o700);
    cases.push(await runCase(409, 1));
    cases.push(await runCase(502, 3));
    assert(!timedOut);
    process.stdout.write(JSON.stringify({schema: 'catchplate.stockNpmWithheldStatusProof/v1', ok: true,
      syntheticOnly: true, network: 'loopback-only', actualProxyAcceptance: false,
      npmVersion: '11.8.0', libnpmpublishVersion: '11.1.3', makeFetchHappenVersion: '15.0.3',
      nodeVersion: process.version, cases}) + '\n');
  } catch (_) {
    process.stderr.write(JSON.stringify({schema: 'catchplate.stockNpmWithheldStatusProof/v1', ok: false,
      syntheticOnly: true, stage, error: 'bounded stock npm status proof failed', completedCases: cases.length}) + '\n');
    process.exitCode = 1;
  } finally {
    clearTimeout(globalTimer); stopChildren();
    for (const server of servers) { server.closeAllConnections(); server.close(); }
    if (temporary) fs.rmSync(temporary, {recursive: true, force: false});
  }
}
main();

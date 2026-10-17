#!/usr/bin/env node
// Root-reviewed wire observation only, NOT proxy acceptance. Run cached Node
// in --network=none --read-only, with fresh /tmp tmpfs and external timeout30s.
// Mount source/dependencies read-only at /app; mount the existing throwaway
// TLS leaf/key/CA and checker installation_files() project read-only at /fixture.
// Read-only /etc/hosts must map proxy.operator-basic.example.test to127.0.0.1.
// /node /app/scripts/test_operator_npm_ci_connect.cjs --proxy-cert FILE
//   --proxy-key FILE --proxy-ca FILE --project /fixture/project
// No installs/downloads/provider contact: every observed CONNECT gets fixed400.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const tls = require('node:tls');
const {spawn} = require('node:child_process');
const {createHash, X509Certificate} = require('node:crypto');
const {pathToFileURL} = require('node:url');

const ROOT = path.resolve(__dirname, '..');
const EXAMPLE = path.join(ROOT, 'examples/npm-registry');
const HOST = 'proxy.operator-basic.example.test';
const PACKAGES = ['catchplate-fixture-publish', '@catchplate-fixture/publish'];
const NAMES = new Set(['host', 'proxy-authorization', 'proxy-connection', 'connection',
  'user-agent', 'content-length', 'transfer-encoding', 'content-encoding']);
const RESPONSE = 'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n';
const digest = raw => createHash('sha256').update(raw).digest('hex');
let stage = 'containment', temporary, server, child, childClosed = true, expired = false, fatal = false;
let connections = 0, timer, emergency, npmDiagnostic = null, fatalCause = null;
const sockets = new Set(), heads = [];

function stop() {
  if (child && !childClosed) { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }
  for (const socket of sockets) socket.destroy();
}
function file(selected, maximum) {
  assert(path.isAbsolute(selected) && path.resolve(selected) === selected && fs.realpathSync(selected) === selected);
  const info = fs.lstatSync(selected);
  assert(info.isFile() && info.size > 0 && info.size <= maximum);
  const raw = fs.readFileSync(selected); assert.equal(raw.length, info.size); return raw;
}
function write(selected, raw) { fs.writeFileSync(selected, raw, {flag: 'wx', mode: 0o600}); }
function fault(cause) { fatal = true; fatalCause ??= cause; }
function classify(raw, receivedBytes) {
  const ascii = raw.every(value => value < 128);
  let utf8 = true;
  try { new TextDecoder('utf-8', {fatal: true}).decode(raw); } catch { utf8 = false; }
  const lines = raw.toString('latin1').split('\r\n');
  const parts = lines.shift().split(' '), names = [], seen = new Set();
  let duplicates = false, malformedHeader = false, hostKnown = false, hostCount = 0;
  let contentEncoding = 'absent', contentLength = 'absent';
  for (const line of lines) {
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon <= 0) { malformedHeader = true; names.push('other'); continue; }
    const name = line.slice(0, colon).toLowerCase();
    if (seen.has(name)) duplicates = true;
    seen.add(name); names.push(NAMES.has(name) ? name : 'other');
    if (name === 'host') { hostCount++; hostKnown = line.slice(colon + 1).trim() === 'registry.npmjs.org:443'; }
    if (name === 'content-encoding') {
      const selected = line.slice(colon + 1).trim();
      contentEncoding = ['identity', 'gzip'].includes(selected) ? selected : 'other';
    }
    // Noncanonical/non-numeric values are conservatively not classified zero.
    if (name === 'content-length') contentLength = /^0+$/.test(line.slice(colon + 1).trim()) ? 'zero' : 'nonzero';
  }
  return {method: parts[0] === 'CONNECT' ? 'CONNECT' : 'other',
    version: ['HTTP/1.0', 'HTTP/1.1'].includes(parts[2]) ? parts[2] : 'other',
    exactRequestLine: parts.length === 3 && parts.every(Boolean),
    targetKnown: parts[1] === 'registry.npmjs.org:443', literalHostKnown: hostCount === 1 && hostKnown,
    headerNames: names, headerBytes: raw.length, totalBytes: receivedBytes, ascii, utf8,
    duplicateKeys: duplicates, malformedHeader, transferEncodingPresent: seen.has('transfer-encoding'),
    contentEncodingPresent: seen.has('content-encoding'), contentEncoding, contentLength};
}
async function run() {
  assert.equal(process.platform, 'linux'); assert.equal(process.version, 'v25.5.0');
  assert.deepEqual(fs.readdirSync('/sys/class/net').sort(), ['lo']);
  const interfaces = os.networkInterfaces(); assert.deepEqual(Object.keys(interfaces), ['lo']);
  assert(interfaces.lo.every(value => value.internal && ['127.0.0.1', '::1'].includes(value.address)));
  const argv = process.argv.slice(2), flags = ['--proxy-cert', '--proxy-key', '--proxy-ca', '--project'];
  assert.equal(argv.length, 8); assert.deepEqual(argv.filter((_, index) => index % 2 === 0), flags);
  const [certPath, keyPath, caPath, projectPath] = argv.filter((_, index) => index % 2 === 1);
  const hosts = fs.readFileSync('/etc/hosts', 'utf8').split('\n').map(line => line.split('#')[0].trim().split(/\s+/))
    .filter(fields => fields.slice(1).includes(HOST));
  assert.equal(hosts.length, 1); assert.equal(hosts[0][0], '127.0.0.1');
  const core = await import(pathToFileURL(path.join(EXAMPLE, 'core.mjs')));
  const {processDiagnostic} = await import(pathToFileURL(path.join(EXAMPLE, 'diagnostics.mjs')));
  const versions = {};
  for (const [relative, expected] of [['npm', '11.8.0'], ['npm/node_modules/pacote', '21.0.4'],
    ['npm/node_modules/npm-registry-fetch', '19.1.1'], ['npm/node_modules/@npmcli/arborist', '9.1.10']]) {
    const raw = file(path.join(EXAMPLE, 'node_modules', relative, 'package.json'), 65536);
    const item = JSON.parse(raw); assert.equal(item.version, expected);
    versions[relative] = {version: item.version, packageJsonSha256: digest(raw)};
  }
  stage = 'inputs';
  const cert = file(certPath, 65536), key = file(keyPath, 65536), ca = file(caPath, 65536);
  assert.equal(new X509Certificate(cert).checkHost(HOST), HOST);
  assert(new X509Certificate(cert).verify(new X509Certificate(ca).publicKey));
  assert.equal(fs.realpathSync(projectPath), projectPath);
  assert.deepEqual(fs.readdirSync(projectPath).sort(), ['package-lock.json', 'package.json']);
  const manifest = file(path.join(projectPath, 'package.json'), 65536);
  const lock = file(path.join(projectPath, 'package-lock.json'), 4 * 1024 * 1024);
  const parsed = JSON.parse(manifest), locked = JSON.parse(lock);
  assert.deepEqual(parsed, {name: 'catchplate-fixture-consumer', version: '1.0.0', private: true,
    dependencies: {[PACKAGES[0]]: '1.0.2'}});
  assert.deepEqual(Object.keys(locked.packages).sort(), ['', ...PACKAGES.map(name => 'node_modules/' + name)].sort());
  for (const [name, version] of [[PACKAGES[0], '1.0.2'], [PACKAGES[1], '3.0.0']]) {
    const entry = locked.packages['node_modules/' + name];
    assert.equal(entry.version, version);
    assert.equal(entry.resolved, 'https://registry.npmjs.org/' + name + '/-/' + name.split('/').at(-1) + '-' + version + '.tgz');
    assert.deepEqual(entry.dependencies || {}, name === PACKAGES[0] ? {[PACKAGES[1]]: '3.0.0'} : {});
  }
  temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'catchplate-npm-ci-connect-'));
  assert.equal(fs.statSync(temporary).mode & 0o777, 0o700);
  const paths = {root: temporary, project: path.join(temporary, 'project'), cache: path.join(temporary, 'cache'),
    trust: path.join(temporary, 'trust.pem'), npmrc: path.join(temporary, 'user.npmrc'),
    globalrc: path.join(temporary, 'global.npmrc'), npmCli: path.join(EXAMPLE, 'node_modules/npm/bin/npm-cli.js')};
  fs.mkdirSync(paths.project, {mode: 0o700}); fs.mkdirSync(paths.cache, {mode: 0o700});
  write(path.join(paths.project, 'package.json'), manifest); write(path.join(paths.project, 'package-lock.json'), lock);
  write(paths.trust, ca); write(paths.globalrc, '');
  stage = 'listener';
  server = tls.createServer({cert, key, minVersion: 'TLSv1.2'}, socket => {
    let buffered = Buffer.alloc(0), done = false;
    socket.setTimeout(4000, () => { fault('head_timeout'); socket.destroy(); });
    socket.on('error', () => { fault(done ? 'post_response_socket_error' : 'head_socket_error'); });
    socket.on('data', chunk => {
      if (done) { fault('post_response_data'); socket.destroy(); return; }
      buffered = Buffer.concat([buffered, chunk]);
      if (buffered.length > 32768) { fault('head_oversize'); socket.destroy(); return; }
      const end = buffered.indexOf('\r\n\r\n');
      if (end < 0) return;
      done = true;
      if (heads.length >= 3) { fault('head_limit'); stop(); return; }
      heads.push(classify(buffered.subarray(0, end + 4), buffered.length));
      buffered.fill(0); buffered = Buffer.alloc(0);
      socket.end(RESPONSE);
    });
  });
  server.on('connection', socket => {
    sockets.add(socket); socket.once('close', () => sockets.delete(socket));
    socket.on('error', () => {});
    if (++connections > 3) { fault('connection_limit'); stop(); }
  });
  server.on('tlsClientError', () => { fault('tls_client_error'); });
  await new Promise((accept, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', accept); });
  const config = core.configuration({CATCHPLATE_PROXY_URL: 'https://' + HOST + ':' + server.address().port,
    CATCHPLATE_APP_ID: '00000000-0000-4000-8000-000000000001', CATCHPLATE_PROXY_TOKEN: 'A'.repeat(43),
    CATCHPLATE_CA_FILE: caPath, CATCHPLATE_NPM_PACKAGE: PACKAGES[0], CATCHPLATE_NPM_VERSION: '1.0.2',
    CATCHPLATE_NPM_PROJECT: projectPath, CATCHPLATE_NPM_OUTPUT: paths.project}, 'ci');
  core.reviewedProject(config, manifest, lock);
  write(paths.npmrc, core.npmConfiguration(config));
  stage = 'stock_ci';
  const result = await new Promise((accept, reject) => {
    child = spawn(process.execPath, core.npmArguments(config, paths), {cwd: paths.project,
      env: core.childEnvironment(config, paths), detached: true, stdio: ['ignore', 'pipe', 'pipe']});
    childClosed = false;
    let stdout = '', stderr = '', error;
    child.on('error', value => { error = value; });
    for (const [stream, append] of [[child.stdout, value => {stdout += value;}], [child.stderr, value => {stderr += value;}]]) {
      stream.setEncoding('utf8'); stream.on('data', value => {
        append(value); if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > 65536) {fault('output_limit'); stop();}
      });
    }
    child.once('close', (status, signal) => { childClosed = true; accept({status, signal, error, stdout, stderr}); });
  });
  stage = 'result_process';
  const diagnostic = processDiagnostic('npm', result);
  npmDiagnostic = diagnostic;
  assert(!expired && !fatal && childClosed && result.status === 1 && result.signal === null && !result.error);
  stage = 'result_response';
  assert.equal(diagnostic.npmCode, 'E400'); assert(heads.length >= 1 && heads.length <= 3);
  assert.equal(connections, heads.length);
  stage = 'result_lock';
  assert(fs.readFileSync(path.join(paths.project, 'package-lock.json')).equals(lock));
  stage = 'result_source';
  assert(file(path.join(projectPath, 'package.json'), 65536).equals(manifest));
  assert(file(path.join(projectPath, 'package-lock.json'), 4 * 1024 * 1024).equals(lock));
  return {schema: 'catchplate.privateNpmCiConnectProbe/v1', ok: true, syntheticOnly: true,
    proxyAcceptance: false, stockNpmVersion: '11.8.0', nodeVersion: process.version, versions,
    inputManifestSha256: digest(manifest), inputLockSha256: digest(lock), sourcePreserved: true,
    fixedResponseStatus: 400, npmDiagnostic: diagnostic, connections, requests: heads};
}
async function main() {
  let receipt;
  timer = setTimeout(() => {expired = true; stop();}, 25000);
  emergency = setTimeout(() => {process.stdout.write(JSON.stringify({schema: 'catchplate.privateNpmCiConnectProbe/v1',
    ok: false, syntheticOnly: true, proxyAcceptance: false, stage: 'deadline', cleanup: false}) + '\n'); process.exit(1);}, 28000);
  try { receipt = await run(); }
  catch { receipt = {schema: 'catchplate.privateNpmCiConnectProbe/v1', ok: false, syntheticOnly: true,
    proxyAcceptance: false, stage, connections, requests: heads, npmDiagnostic,
    probeState: {expired, childClosed, fatal, fatalCause}}; }
  finally {
    stop();
    try {
      if (server?.listening) await new Promise(resolve => server.close(resolve));
      if (temporary) fs.rmSync(temporary, {recursive: true, force: false});
      receipt.cleanup = childClosed;
    } catch { receipt.cleanup = false; receipt.ok = false; }
    clearTimeout(timer); clearTimeout(emergency);
  }
  if (!receipt.cleanup) receipt.ok = false;
  process.stdout.write(JSON.stringify(receipt) + '\n'); process.exitCode = receipt.ok ? 0 : 1;
}
if (require.main === module) main();

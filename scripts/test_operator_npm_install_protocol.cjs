#!/usr/bin/env node
// Source-only preparation. Root runs /node /app/scripts/test_operator_npm_install_protocol.cjs
// in the reviewed cached container: network=none, read-only checkout/dependencies,
// /node=existing Node25.5.0, private /tmp32MiB, no capabilities/ports/credentials.
// 60s internal deadline; runner owns a 90s external deadline and exact cleanup.
// Stock-client wire observation ONLY, not publication or actual proxy acceptance.
'use strict';
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const {spawn} = require('node:child_process');
const {createHash} = require('node:crypto');
const {gzipSync, gunzipSync} = require('node:zlib');
const NPM = path.resolve(__dirname, '../examples/npm-registry/node_modules/npm');
const TOP = 'serverware-protocol-top', LEAF = '@serverware-protocol/leaf', VERSION = '1.0.0';
const BULK = '/-/npm/v1/security/advisories/bulk';
const TOKEN = 'synthetic-install-protocol-token-not-a-provider-credential';
const LIMIT = 65536, children = new Set(), wire = [], phases = [], sourcePins = {};
const deadline = Date.now() + 60000;
const hash = (bytes, algorithm = 'sha256', encoding = 'hex') => createHash(algorithm).update(bytes).digest(encoding);
const expectedAudit = {[TOP]: [VERSION], [LEAF]: [VERSION]};
let temporary, server, registry, active = 'setup', invalid = 0, timer, timedOut = false;
const packages = [
  {name: TOP, metadataPath: '/' + TOP, tarballPath: '/' + TOP + '/-/' + TOP + '-1.0.0.tgz',
    manifest: {name: TOP, version: VERSION, main: 'index.cjs', dependencies: {[LEAF]: VERSION}},
    code: "'use strict';\nmodule.exports = 'top:' + require('@serverware-protocol/leaf');\n"},
  {name: LEAF, metadataPath: '/@serverware-protocol%2fleaf', tarballPath: '/@serverware-protocol/leaf/-/leaf-1.0.0.tgz',
    manifest: {name: LEAF, version: VERSION, main: 'index.cjs'},
    code: "'use strict';\nmodule.exports = 'synthetic-leaf-v1';\n"},
];
function write(file, bytes) { fs.writeFileSync(file, bytes, {flag: 'wx', mode: 0o600}); }
function killChildren() { for (const child of children) { try { process.kill(-child.pid, 'SIGKILL'); } catch (_) {} } }
function preflight() {
  assert.equal(process.platform, 'linux'); assert.equal(process.version, 'v25.5.0'); assert.equal(process.argv.length, 2);
  assert.deepEqual(fs.readdirSync('/sys/class/net').sort(), ['lo']);
  const interfaces = os.networkInterfaces(); assert.deepEqual(Object.keys(interfaces).sort(), ['lo']);
  assert(interfaces.lo.length && interfaces.lo.every(item => item.internal && ['127.0.0.1', '::1'].includes(item.address)));
  assert.equal(fs.realpathSync(NPM), NPM);
  for (const [file, name, version] of [['package.json', 'npm', '11.21.1'],
    ['node_modules/@npmcli/arborist/package.json', '@npmcli/arborist', '9.9.3'],
    ['node_modules/pacote/package.json', 'pacote', '21.5.1'],
    ['node_modules/npm-registry-fetch/package.json', 'npm-registry-fetch', '19.1.1'],
    ['node_modules/make-fetch-happen/package.json', 'make-fetch-happen', '15.0.6']]) {
    const bytes = fs.readFileSync(path.join(NPM, file)), value = JSON.parse(bytes);
    assert.equal(value.name, name); assert.equal(value.version, version);
    sourcePins[file] = {name, version, sha256: hash(bytes)};
  }
  for (const file of ['bin/npm-cli.js', 'lib/commands/install.js', 'lib/commands/ci.js', 'lib/utils/reify-output.js',
    'node_modules/@npmcli/arborist/lib/audit-report.js', 'node_modules/npm-registry-fetch/lib/index.js',
    'node_modules/pacote/lib/registry.js', 'node_modules/pacote/lib/remote.js'])
    sourcePins[file] = {sha256: hash(fs.readFileSync(path.join(NPM, file)))};
}
function archive(files) {
  const chunks = [];
  for (const [name, data] of files) {
    const bytes = Buffer.from(data), header = Buffer.alloc(512);
    header.write('package/' + name, 0, 100, 'ascii'); header.write('0000644\0', 100, 8, 'ascii');
    header.write('0000000\0', 108, 8, 'ascii'); header.write('0000000\0', 116, 8, 'ascii');
    header.write(bytes.length.toString(8).padStart(11, '0') + '\0', 124, 12, 'ascii');
    header.write('00000000000\0', 136, 12, 'ascii'); header.fill(32, 148, 156); header[156] = 48;
    header.write('ustar\0', 257, 6, 'ascii'); header.write('00', 263, 2, 'ascii');
    header.write(header.reduce((sum, value) => sum + value, 0).toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
    chunks.push(header, bytes, Buffer.alloc((512 - bytes.length % 512) % 512));
  }
  return gzipSync(Buffer.concat([...chunks, Buffer.alloc(1024)]));
}
async function child(args, cwd) {
  assert(!timedOut && Date.now() < deadline);
  return new Promise((resolve, reject) => {
    const processChild = spawn(process.execPath, args, {cwd, env: {LANG: 'C.UTF-8'},
      stdio: ['ignore', 'pipe', 'pipe'], detached: true});
    children.add(processChild); let stdout = '', stderr = '', failed = false;
    const stop = () => { failed = true; try { process.kill(-processChild.pid, 'SIGKILL'); } catch (_) {} };
    const childTimer = setTimeout(stop, Math.min(15000, deadline - Date.now()));
    for (const [stream, append] of [[processChild.stdout, value => { stdout += value; }],
      [processChild.stderr, value => { stderr += value; }]]) {
      stream.setEncoding('utf8'); stream.on('data', value => { append(value);
        if (Buffer.byteLength(stdout) + Buffer.byteLength(stderr) > LIMIT) stop(); });
    }
    processChild.on('error', stop);
    processChild.on('close', (code, signal) => {
      clearTimeout(childTimer); children.delete(processChild);
      if (failed || timedOut || signal !== null) return reject(new Error('bounded child refused'));
      resolve({code, stdout, stderr});
    });
  });
}
function npmArgs(config, cache, args) {
  assert(args.every(value => !/^--(?:no-)?audit(?:=|$)/.test(value)));
  return [path.join(NPM, 'bin/npm-cli.js'), '--userconfig', config, '--globalconfig', '/dev/null',
    '--cache', cache, '--loglevel=error', '--logs-max=0', '--update-notifier=false', '--progress=false', ...args];
}
function startRegistry() {
  server = http.createServer(async (request, response) => {
    // Record each arrival before admission; only bounded public shapes are emitted.
    const record = {ordinal: wire.length + 1, phase: active, method: request.method,
      path: typeof request.url === 'string' && request.url.length <= 256 ? request.url : 'invalid',
      headerNames: [...new Set(request.rawHeaders.filter((_, index) => index % 2 === 0).map(value => value.toLowerCase()))].sort(),
      contentEncoding: request.headers['content-encoding'] || null,
      transferEncoding: request.headers['transfer-encoding'] || null,
      contentLength: request.headers['content-length'] === undefined ? null : Number(request.headers['content-length'])};
    wire.push(record);
    try {
      assert(wire.length <= 24 && ['install', 'ci', 'audit-negative'].includes(active));
      assert.equal(request.socket.remoteAddress, '127.0.0.1');
      assert.equal(request.headers.host, new URL(registry).host);
      assert.equal(request.headers.authorization, 'Bearer ' + TOKEN);
      assert(['GET', 'POST'].includes(request.method));
      assert(record.contentEncoding === null || record.contentEncoding === 'gzip');
      assert(record.transferEncoding === null || record.transferEncoding === 'chunked');
      assert(record.contentLength === null || Number.isSafeInteger(record.contentLength) && record.contentLength >= 0 && record.contentLength <= LIMIT);
      assert(record.transferEncoding === null || record.contentLength === null);
      const chunks = []; let count = 0;
      for await (const chunk of request) { count += chunk.length; assert(count <= LIMIT); chunks.push(chunk); }
      const bytes = Buffer.concat(chunks); record.bodyBytes = bytes.length; record.bodySha256 = hash(bytes);
      if (record.contentLength !== null) assert.equal(record.contentLength, bytes.length);
      let body, media = 'application/json', status = 200;
      if (request.method === 'POST') {
        assert.equal(request.url, BULK); assert.equal(record.contentEncoding, 'gzip');
        assert.match(request.headers['content-type'], /^application\/json(?:;\s*charset=utf-8)?$/i);
        const decoded = gunzipSync(bytes, {maxOutputLength: LIMIT});
        const audit = JSON.parse(decoded); assert.deepEqual(audit, expectedAudit);
        record.kind = 'audit-bulk'; record.decodedBodySha256 = hash(decoded); record.auditPackages = audit;
        status = active === 'audit-negative' ? 400 : 200;
        body = Buffer.from(status === 200 ? '{}' : '{"error":"synthetic_audit_refused"}');
      } else {
        assert.equal(bytes.length, 0); assert.equal(record.contentEncoding, null);
        const pkg = packages.find(item => request.url === item.metadataPath || request.url === item.tarballPath);
        assert(pkg);
        if (request.url === pkg.metadataPath) {
          record.kind = 'metadata'; record.package = pkg.name;
          body = Buffer.from(JSON.stringify({_id: pkg.name, name: pkg.name, 'dist-tags': {latest: VERSION},
            versions: {[VERSION]: {...pkg.manifest, dist: {tarball: registry.slice(0, -1) + pkg.tarballPath,
              integrity: pkg.integrity, shasum: hash(pkg.tarball, 'sha1')}}}}));
        } else { record.kind = 'tarball'; record.package = pkg.name; body = pkg.tarball; media = 'application/octet-stream'; }
      }
      record.responseStatus = status; record.responseBytes = body.length; record.responseSha256 = hash(body);
      response.writeHead(status, {'Content-Type': media, 'Content-Length': body.length, 'Cache-Control': 'no-store'});
      response.end(body);
    } catch (_) {
      invalid++; record.refused = true;
      if (!response.headersSent) response.writeHead(400, {'Content-Type': 'application/json'});
      response.end('{"error":"synthetic_request_refused"}');
    }
  });
  server.requestTimeout = 3000; server.headersTimeout = 3000;
  server.on('clientError', (_, socket) => { invalid++; socket.destroy(); });
  return new Promise((resolve, reject) => { server.once('error', reject);
    server.listen(0, '127.0.0.1', () => { registry = 'http://127.0.0.1:' + server.address().port + '/'; resolve(); }); });
}
function installed(project) {
  for (const pkg of packages) {
    const directory = path.join(project, 'node_modules', pkg.name);
    assert.deepEqual(fs.readdirSync(directory).sort(), ['index.cjs', 'package.json']);
    assert.equal(fs.readFileSync(path.join(directory, 'index.cjs'), 'utf8'), pkg.code);
    assert.equal(fs.readFileSync(path.join(directory, 'package.json'), 'utf8'), pkg.manifestBytes);
    assert(!fs.lstatSync(directory).isSymbolicLink());
  }
  const lock = JSON.parse(fs.readFileSync(path.join(project, 'package-lock.json')));
  assert.equal(lock.lockfileVersion, 3);
  assert.deepEqual(Object.keys(lock.packages).sort(), ['', ...packages.map(pkg => 'node_modules/' + pkg.name)].sort());
  for (const pkg of packages) {
    const entry = lock.packages['node_modules/' + pkg.name];
    assert.equal(entry.version, VERSION); assert.equal(entry.integrity, pkg.integrity);
    assert.equal(entry.resolved, registry.slice(0, -1) + pkg.tarballPath);
  }
}
function auditSucceeded(summary, observations) {
  assert.equal(summary.audited, 3); assert(summary.audit && typeof summary.audit === 'object');
  assert.equal(summary.audit.dependencies.total, 2);
  assert.deepEqual(summary.audit.vulnerabilities, {info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0});
  const audits = observations.filter(item => item.kind === 'audit-bulk'); assert.equal(audits.length, 1);
  assert.equal(audits[0].responseStatus, 200); assert.deepEqual(audits[0].auditPackages, expectedAudit);
}
async function phase(name, project, config) {
  active = name; const start = wire.length, cache = path.join(temporary, name + '-cache');
  fs.mkdirSync(cache, {mode: 0o700}); assert.deepEqual(fs.readdirSync(cache), []);
  const auditConfig = await child(npmArgs(config, cache, ['config', 'get', 'audit']), project);
  assert.equal(auditConfig.code, 0); assert.equal(auditConfig.stdout, 'true\n'); assert.equal(auditConfig.stderr, '');
  const result = await child(npmArgs(config, cache, [name === 'ci' ? 'ci' : 'install', '--ignore-scripts=true',
    '--fund=false', '--workspaces=false', '--json']), project);
  assert.equal(result.code, 0); assert.equal(result.stderr, '');
  const summary = JSON.parse(result.stdout), observations = wire.slice(start);
  assert.equal(invalid, 0); assert.equal(summary.added, 2);
  for (const pkg of packages) {
    const tarballs = observations.filter(item => item.kind === 'tarball' && item.package === pkg.name);
    assert.equal(tarballs.length, 1); assert.equal(tarballs[0].responseSha256, hash(pkg.tarball));
    assert.equal(observations.filter(item => item.kind === 'metadata' && item.package === pkg.name).length, name === 'ci' ? 0 : 1);
  }
  installed(project);
  const consumption = await child(['-e', "require('node:assert/strict').equal(require('serverware-protocol-top'), 'top:synthetic-leaf-v1'); process.stdout.write('fixed-export-ok\\n');"], project);
  assert.equal(consumption.code, 0); assert.equal(consumption.stdout, 'fixed-export-ok\n'); assert.equal(consumption.stderr, '');
  if (name === 'audit-negative') {
    assert.equal(summary.audited, 0); assert(!Object.hasOwn(summary, 'audit') || summary.audit === null);
    const audits = observations.filter(item => item.kind === 'audit-bulk'); assert.equal(audits.length, 1);
    assert.equal(audits[0].responseStatus, 400); assert.deepEqual(audits[0].auditPackages, expectedAudit);
    assert.throws(() => auditSucceeded(summary, observations));
  } else auditSucceeded(summary, observations);
  return {name, npmExitCode: result.code, defaultAuditEnabled: true, auditOptionOverridden: false,
    coldCache: true, added: summary.added, audited: summary.audited, audit: summary.audit || null,
    harmlessExportConsumed: true, expectedNegative: name === 'audit-negative',
    successClassifierAccepted: name !== 'audit-negative', observations};
}
async function main() {
  try {
    preflight(); timer = setTimeout(() => { timedOut = true; killChildren(); server?.closeAllConnections(); }, 60000);
    temporary = fs.mkdtempSync('/tmp/serverware-npm-install-'); assert.equal(fs.statSync(temporary).mode & 0o777, 0o700);
    for (const pkg of packages) {
      pkg.manifestBytes = JSON.stringify(pkg.manifest) + '\n';
      pkg.tarball = archive([['package.json', pkg.manifestBytes], ['index.cjs', pkg.code]]);
      pkg.integrity = 'sha512-' + hash(pkg.tarball, 'sha512', 'base64');
    }
    await startRegistry();
    const config = path.join(temporary, 'user.npmrc');
    write(config, 'registry=' + registry + '\n//' + new URL(registry).host + '/:_authToken=' + TOKEN + '\n');
    const manifest = JSON.stringify({name: 'serverware-protocol-consumer', private: true, version: VERSION,
      dependencies: {[TOP]: VERSION}}) + '\n';
    const project = path.join(temporary, 'project'); fs.mkdirSync(project, {mode: 0o700}); write(path.join(project, 'package.json'), manifest);
    phases.push(await phase('install', project, config));
    const lock = fs.readFileSync(path.join(project, 'package-lock.json'));
    write(path.join(project, 'node_modules/.serverware-ci-sentinel'), 'owned ci removal marker\n');
    phases.push(await phase('ci', project, config));
    assert(!fs.existsSync(path.join(project, 'node_modules/.serverware-ci-sentinel')));
    assert.deepEqual(fs.readFileSync(path.join(project, 'package-lock.json')), lock);
    assert.equal(fs.readFileSync(path.join(project, 'package.json'), 'utf8'), manifest);
    const negative = path.join(temporary, 'negative'); fs.mkdirSync(negative, {mode: 0o700}); write(path.join(negative, 'package.json'), manifest);
    phases.push(await phase('audit-negative', negative, config)); assert(!timedOut && invalid === 0);
    process.stdout.write(JSON.stringify({schema: 'serverware.stockNpmInstallProtocolProof/v1', ok: true,
      syntheticOnly: true, network: 'loopback-only', actualProxyAcceptance: false, publicationAcceptance: false,
      nodeVersion: process.version, sourcePins, lockSha256BeforeCi: hash(lock),
      lockSha256AfterCi: hash(fs.readFileSync(path.join(project, 'package-lock.json'))),
      ciRemovedOldNodeModules: true, packages: packages.map(pkg => ({name: pkg.name, version: VERSION,
        tarballSha256: hash(pkg.tarball), integrity: pkg.integrity, manifestSha256: hash(pkg.manifestBytes), codeSha256: hash(pkg.code)})), phases}) + '\n');
  } catch (_) {
    process.stderr.write(JSON.stringify({schema: 'serverware.stockNpmInstallProtocolProof/v1', ok: false,
      syntheticOnly: true, phase: active, error: 'bounded stock npm protocol proof failed',
      completedPhases: phases.length, arrivals: wire.length, refused: invalid}) + '\n'); process.exitCode = 1;
  } finally {
    clearTimeout(timer); killChildren();
    if (server) { const closed = new Promise(resolve => server.close(resolve)); server.closeAllConnections(); await closed; }
    if (temporary) fs.rmSync(temporary, {recursive: true, force: false});
  }
}
main();

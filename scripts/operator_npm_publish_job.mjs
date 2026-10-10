// Stock npm publish through its ordinary proxy/auth/CA configuration only.
// No transport replacement, force, dry-run, automatic command retry or install.
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';

const assert = value => { if (!value) throw new Error('synthetic npm publish assertion'); };
const hash = (algorithm, bytes, encoding = 'hex') => createHash(algorithm).update(bytes).digest(encoding);
const phases = ['prerequisite', 'unscoped', 'scoped', 'wrong_package', 'outside_window', 'wrong_placeholder', 'revoked_app'];
const safeCodes = new Set(['E400', 'E403', 'E404', 'E407', 'E409', 'E502', 'ECONNRESET', 'ECONNREFUSED',
  'EPROXY', 'ENEEDAUTH', 'EACCES', 'ENOENT', 'EINVAL', 'ENOTFOUND', 'ETIMEDOUT', 'ERR_SYSTEM_ERROR',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'ERR_TLS_CERT_ALTNAME_INVALID']);
const code = value => typeof value === 'string' && safeCodes.has(value) ? value : 'unrecognized';
const extraCa = '/client-trust/requests-ca.pem';
let phase = 'unknown', stage = 'input', errorCode = 'unrecognized', processExitCode = null;
let stdoutBytes = 0, stderrBytes = 0, result, timer;
try {
  const bytes = readFileSync(0); assert(bytes.length <= 4096);
  const input = JSON.parse(bytes);
  assert(Object.keys(input).sort().join(',') === 'applicationId,package,phase,runId,tarballSha256,token,version'
    && process.version === 'v25.5.0' && phases.includes(input.phase)
    && /^[0-9a-f-]{36}$/.test(input.applicationId) && /^[A-Za-z0-9_-]{43}$/.test(input.token)
    && /^operator-check-[0-9a-f]{32}$/.test(input.runId)
    && /^sha256:[0-9a-f]{64}$/.test(input.tarballSha256) && process.env.NODE_EXTRA_CA_CERTS === extraCa);
  phase = input.phase; stage = 'identity';
  for (const [file, name, version] of [['/npm/package.json', 'npm', '11.8.0'],
    ['/npm/node_modules/pacote/package.json', 'pacote', '21.0.4'],
    ['/npm/node_modules/npm-registry-fetch/package.json', 'npm-registry-fetch', '19.1.1']]) {
    const value = JSON.parse(readFileSync(file)); assert(value.name === name && value.version === version);
  }
  stage = 'trust';
  assert(readFileSync(extraCa, 'ascii') === readFileSync('/client-trust/outer-ca.pem', 'ascii')
    + readFileSync('/client-trust/inner-ca.pem', 'ascii'));
  timer = setTimeout(() => process.exit(70), 20000);
  stage = 'package';
  const tarballPath = '/client-packages/' + phase + '.tgz';
  const payload = readFileSync(tarballPath);
  assert(payload.length > 0 && payload.length < 32768 && 'sha256:' + hash('sha256', payload) === input.tarballSha256);
  stage = 'workspace';
  const root = mkdtempSync('/client-work/npm-publish-' + phase + '-');
  assert((statSync(root).mode & 0o777) === 0o700);
  const clientHome = root + '/home', cache = root + '/cache';
  mkdirSync(clientHome, { mode: 0o700 }); mkdirSync(cache, { mode: 0o700 });
  const config = root + '/user.npmrc';
  const placeholder = phase === 'wrong_placeholder' ? 'serverware-wrong-placeholder-v1' : 'serverware-npm-placeholder-v1';
  writeFileSync(config, [
    'registry=https://registry.npmjs.org/', '//registry.npmjs.org/:_authToken=' + placeholder,
    'https-proxy=https://' + input.applicationId + ':${SERVERWARE_PROXY_TOKEN}@proxy.operator-basic.example.test:8443',
    'cache=${SERVERWARE_NPM_CACHE}', 'noproxy=', 'strict-ssl=true', 'fetch-retries=0', 'fetch-timeout=10000',
    'update-notifier=false', 'progress=false', 'logs-max=0', 'loglevel=silent', '',
  ].join('\n'), { flag: 'wx', mode: 0o600 });
  stage = 'npm_spawn';
  const invocation = spawnSync('/node', ['/npm/bin/npm-cli.js', '--userconfig', config,
    '--globalconfig', '/dev/null', 'publish', tarballPath, '--access=public', '--tag=fixture',
    '--ignore-scripts=true', '--provenance=false', '--force=false', '--dry-run=false', '--workspaces=false', '--json'], {
    cwd: root, env: { LANG: 'C.UTF-8', PATH: '/usr/bin:/bin', HOME: clientHome, NODE_EXTRA_CA_CERTS: extraCa,
      SERVERWARE_PROXY_TOKEN: input.token, SERVERWARE_NPM_CACHE: cache },
    timeout: 15000, killSignal: 'SIGKILL', maxBuffer: 262144, encoding: 'utf8',
  });
  stage = 'npm_process';
  processExitCode = Number.isInteger(invocation.status) && invocation.status >= 0 && invocation.status <= 255 ? invocation.status : null;
  stdoutBytes = typeof invocation.stdout === 'string' ? Buffer.byteLength(invocation.stdout) : 0;
  stderrBytes = typeof invocation.stderr === 'string' ? Buffer.byteLength(invocation.stderr) : 0;
  errorCode = code(invocation.error?.code);
  assert(!invocation.error && invocation.signal === null && stderrBytes <= 8192);
  stage = 'npm_json';
  const value = JSON.parse(invocation.stdout);
  errorCode = code(value.error?.code);
  if (!['unscoped', 'scoped'].includes(phase)) {
    stage = 'npm_denial';
    assert(invocation.status !== 0 && ['E403', 'E407', 'ECONNRESET', 'ECONNREFUSED'].includes(errorCode));
    result = { ok: true, refused: true, errorCode };
  } else {
    stage = 'npm_process';
    assert(invocation.status === 0);
    stage = 'npm_receipt';
    assert(invocation.stderr === '' && value.name === input.package
      && value.version === input.version && value.id === input.package + '@' + input.version
      && value.integrity === 'sha512-' + hash('sha512', payload, 'base64')
      && value.shasum === hash('sha1', payload) && value.size === payload.length);
    result = { ok: true, package: value.name, version: value.version, tarballSha256: input.tarballSha256,
      tarballIntegrity: value.integrity, tarballShasum: value.shasum, attachmentBytes: payload.length };
  }
} catch (error) {
  if (errorCode === 'unrecognized') errorCode = code(error?.code);
  result = { ok: false, error: 'stock npm publish operation failed', stage, errorCode,
    processExitCode, stdoutBytes, stderrBytes };
} finally {
  clearTimeout(timer);
}
process.stdout.write(JSON.stringify({ schema: 'serverware.privateNpmPublishClient/v1', phase,
  npmVersion: '11.8.0', pacoteVersion: '21.0.4', registryFetchVersion: '19.1.1', strictSSL: true,
  extraCaPreservesDefaultRoots: true, configuredRetries: 0, isolatedCache: true,
  requestRewrite: false, force: false, dryRun: false, provenance: false, ...result }) + '\n');
process.exitCode = result.ok ? 0 : 1;

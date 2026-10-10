// Stock npm view and pacote manifest, with configuration only. No request,
// response, agent or header replacement. The parent supplies private proxy
// credentials on stdin; neither argv nor public receipts contain them.
import { readFileSync, writeFileSync, mkdtempSync, mkdirSync, statSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import { spawnSync } from 'node:child_process';

const load = createRequire(import.meta.url);
const pacote = load('/npm/node_modules/pacote/lib/index.js');
const require = (value) => { if (!value) throw new Error('synthetic npm assertion'); };
const sha = (value) => 'sha256:' + createHash('sha256').update(value).digest('hex');
const packages = ['serverware-fixture-metadata', '@serverware-fixture/metadata'];
const phases = ['wrong_app', 'wrong_package_denied', 'wrong_dummy', 'npm_unscoped', 'npm_scoped',
  'pacote_unscoped', 'pacote_scoped', 'not_found', 'wrong_package', 'reflection'];
const registry = 'https://registry.npmjs.org';
const proxyHost = 'proxy.operator-basic.example.test:8443';
const extraCa = '/client-trust/requests-ca.pem';
const inputBytes = readFileSync(0);
require(inputBytes.length <= 4096);
const input = JSON.parse(inputBytes);
require(process.version === 'v25.5.0' && phases.includes(input.phase)
  && /^[0-9a-f-]{36}$/.test(input.applicationId) && /^[A-Za-z0-9_-]{43}$/.test(input.token)
  && /^operator-check-[0-9a-f]{32}$/.test(input.runId)
  && process.env.NODE_EXTRA_CA_CERTS === extraCa);
for (const [file, name, version] of [['/npm/package.json', 'npm', '11.8.0'],
  ['/npm/node_modules/pacote/package.json', 'pacote', '21.0.4'],
  ['/npm/node_modules/npm-registry-fetch/package.json', 'npm-registry-fetch', '19.1.1']]) {
  const identity = JSON.parse(readFileSync(file));
  require(identity.name === name && identity.version === version);
}
require(readFileSync(extraCa, 'ascii') === readFileSync('/client-trust/outer-ca.pem', 'ascii')
  + readFileSync('/client-trust/inner-ca.pem', 'ascii'));
const deadline = setTimeout(() => process.exit(70), 20000);
const scoped = input.phase.endsWith('_scoped') || input.phase === 'reflection';
const packageName = input.phase === 'wrong_package_denied' ? 'serverware-fixture-denied' : packages[scoped ? 1 : 0];
const client = input.phase.startsWith('pacote_') ? 'pacote' : 'npm';
const expectedVersion = client === 'pacote' ? '1.0.0' : '2.0.0';
const shouldFail = !['npm_unscoped', 'npm_scoped', 'pacote_unscoped', 'pacote_scoped'].includes(input.phase);
const taskRoot = mkdtempSync('/client-work/npm-metadata-' + input.phase + '-');
require((statSync(taskRoot).mode & 0o777) === 0o700);
const cache = taskRoot + '/cache'; mkdirSync(cache, { mode: 0o700 });
const dummy = input.phase === 'wrong_dummy' ? 'serverware-wrong-placeholder-v1' : 'serverware-npm-placeholder-v1';
let result;

function verifyMetadata(value) {
  require(value && typeof value === 'object' && !Array.isArray(value)
    && value.name === packageName && value.version === expectedVersion
    && value.description === 'Complete synthetic metadata \u2603' && value.license === 'MIT'
    && value.dependencies?.['serverware-fixture-dependency'] === '^1.0.0'
    && value.optionalDependencies?.['serverware-fixture-optional'] === '2.0.0'
    && value.engines?.node === '>=20'
    && JSON.stringify(value.fixtureExtra) === JSON.stringify({ preserved: [true, null, 7] }));
  const inert = Buffer.from(packageName + '@' + expectedVersion + ': synthetic bytes, no tarball served');
  const tarball = registry + '/' + packageName + '/-/metadata-' + expectedVersion + '.tgz';
  const integrity = 'sha512-' + createHash('sha512').update(inert).digest('base64');
  require(value.dist?.tarball === tarball && value.dist?.integrity === integrity
    && value.dist?.shasum === createHash('sha1').update(inert).digest('hex')
    && value.dist?.fileCount === 1 && value.dist?.unpackedSize === inert.length);
  if (client === 'npm') {
    require(JSON.stringify(value.versions) === JSON.stringify(['1.0.0', '2.0.0'])
      && value['dist-tags']?.latest === '2.0.0'
      && JSON.stringify(value.fixtureRootExtra) === JSON.stringify({ preserved: [false, 'metadata only'] }));
  } else {
    require(value._resolved === tarball && value._integrity === integrity);
  }
  return { name: value.name, version: value.version, dependenciesVerified: true,
    distVerified: true, extraFieldsVerified: true, selectedMetadataSha256: sha(JSON.stringify(value)) };
}

try {
  if (client === 'npm') {
    // Same ordinary npmrc interpolation as the documented UI flow. A fresh
    // working directory/config/cache and empty global config exclude user state.
    const config = taskRoot + '/user.npmrc';
    const text = [
      'registry=' + registry + '/',
      '//registry.npmjs.org/:_authToken=' + dummy,
      'https-proxy=https://' + input.applicationId + ':${SERVERWARE_PROXY_TOKEN}@' + proxyHost,
      'cache=${SERVERWARE_NPM_CACHE}', 'noproxy=', 'strict-ssl=true', 'fetch-retries=0',
      'fetch-timeout=10000', 'update-notifier=false', 'progress=false', 'logs-max=0', 'loglevel=silent', '',
    ].join('\n');
    writeFileSync(config, text, { flag: 'wx', mode: 0o600 });
    const invocation = spawnSync('/node', ['/npm/bin/npm-cli.js', '--userconfig', config,
      '--globalconfig', '/dev/null', 'view', packageName, '--json'], {
      cwd: taskRoot, env: { LANG: 'C.UTF-8', PATH: '/usr/bin:/bin', NODE_EXTRA_CA_CERTS: extraCa,
        SERVERWARE_PROXY_TOKEN: input.token, SERVERWARE_NPM_CACHE: cache },
      timeout: 15000, killSignal: 'SIGKILL', maxBuffer: 1048576, encoding: 'utf8',
    });
    require(!invocation.error && invocation.signal === null && invocation.stderr.length <= 8192);
    const value = JSON.parse(invocation.stdout);
    if (shouldFail) {
      require(invocation.status !== 0 && typeof value.error?.code === 'string');
      const code = value.error.code;
      if (input.phase === 'not_found') require(code === 'E404');
      else if (['wrong_package', 'reflection'].includes(input.phase)) require(code === 'E502');
      else if (input.phase !== 'wrong_app') require(code === 'E403');
      require(['E403', 'E404', 'E407', 'E502', 'ECONNRESET', 'ECONNREFUSED'].includes(code));
      result = { ok: true, refused: true, errorCode: code };
    } else {
      require(invocation.status === 0 && invocation.stderr === '');
      result = { ok: true, metadata: verifyMetadata(value) };
    }
  } else {
    const value = await pacote.manifest(packageName + '@1.0.0', {
      registry: registry + '/', proxy: 'https://' + input.applicationId + ':' + input.token + '@' + proxyHost,
      strictSSL: true, noProxy: '', retry: { retries: 0 }, timeout: 10000, cache,
      '//registry.npmjs.org/:_authToken': dummy,
    });
    result = { ok: true, metadata: verifyMetadata(value) };
  }
} catch {
  // npm/SDK errors may include proxy credentials. Never stringify or persist them.
  result = { ok: false, error: 'stock npm metadata operation failed' };
} finally {
  clearTimeout(deadline);
}
process.stdout.write(JSON.stringify({ schema: 'serverware.privateNpmMetadataClient/v1',
  phase: input.phase, client, npmVersion: '11.8.0', pacoteVersion: '21.0.4',
  registryFetchVersion: '19.1.1', strictSSL: true, extraCaPreservesDefaultRoots: true,
  configuredRetries: 0, isolatedCache: true, requestRewrite: false, ...result }) + '\n');
process.exitCode = result.ok ? 0 : 1;

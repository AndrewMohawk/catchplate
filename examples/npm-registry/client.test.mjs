// Offline source/example checks: no actual SDK, process, network or filesystem I/O.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { configuration, npmConfiguration, childEnvironment, pacoteOptions, npmArguments,
  reviewedTarball, reviewedManifest, failure, PUBLIC_NPM_DUMMY, VERSIONS } from './core.mjs';
import { verifyVersions, trustedPem, invokeWorker } from './client.mjs';
import { perform } from './worker.mjs';

const bytes = Buffer.from('inert reviewed fixture bytes, not an archive');
const env = {
  SERVERWARE_PROXY_URL: 'https://proxy.example.invalid:8443',
  SERVERWARE_APP_ID: '01234567-89ab-4cde-8fab-0123456789ab',
  SERVERWARE_PROXY_TOKEN: 'private_application_token_canary',
  SERVERWARE_CA_FILE: '/trusted/inner.pem', SERVERWARE_PROXY_CA_FILE: '/trusted/outer.pem',
  SERVERWARE_NPM_PACKAGE: '@example/metadata', SERVERWARE_NPM_VERSION: '1.2.3',
  SERVERWARE_NPM_TAG: 'preview', SERVERWARE_NPM_TARBALL: '/reviewed/package.tgz',
  SERVERWARE_NPM_TARBALL_SHA256: createHash('sha256').update(bytes).digest('hex'),
  SERVERWARE_NPM_PUBLISH_CONFIRM: 'publish-publicly',
};
const paths = { root: '/private/task', cache: '/private/task/cache',
  trust: '/private/task/trust.pem', tarball: '/private/task/reviewed-package.tgz',
  npmCli: '/example/node_modules/npm/bin/npm-cli.js', npmrc: '/private/task/user.npmrc',
  globalrc: '/private/task/global.npmrc' };
const metadata = { name: env.SERVERWARE_NPM_PACKAGE, version: '1.2.3', description: 'not printed' };
const receipt = { ...metadata, id: metadata.name + '@1.2.3', size: bytes.length,
  integrity: 'sha512-' + createHash('sha512').update(bytes).digest('base64'),
  shasum: createHash('sha1').update(bytes).digest('hex') };
const noCall = () => assert.fail('unexpected effect');

test('default is read-only; names, proxy identity and explicit write admission are closed', () => {
  assert.equal(configuration(env).operation, 'view');
  assert.equal(configuration({ ...env, SERVERWARE_NPM_PACKAGE: 'metadata' }).packageName, 'metadata');
  for (const name of ['https://evil.invalid/a', 'file:a', 'foo@latest', 'Foo', '@scope/name/other', 'a\n']) {
    assert.throws(() => configuration({ ...env, SERVERWARE_NPM_PACKAGE: name }));
  }
  for (const url of ['http://proxy.invalid', 'https://u:p@proxy.invalid', 'https://proxy.invalid/path', 'https://proxy.invalid/?x']) {
    assert.throws(() => configuration({ ...env, SERVERWARE_PROXY_URL: url }));
  }
  assert.throws(() => configuration(env, 'install'));
  assert.throws(() => configuration({ ...env, NODE_TLS_REJECT_UNAUTHORIZED: '0' }));
  for (const key of ['SERVERWARE_NPM_TAG', 'SERVERWARE_NPM_TARBALL', 'SERVERWARE_NPM_TARBALL_SHA256', 'SERVERWARE_NPM_PUBLISH_CONFIRM']) {
    assert.throws(() => configuration({ ...env, [key]: undefined }, 'publish'));
  }
  assert.throws(() => configuration({ ...env, SERVERWARE_NPM_VERSION: '^1.0.0' }, 'manifest'));
});

test('npmrc has public dummy and literal token interpolation; clean child trust/env preserve no ambient secrets', () => {
  const config = configuration(env);
  const text = npmConfiguration(config);
  assert.ok(text.includes(PUBLIC_NPM_DUMMY));
  assert.ok(text.includes(':${SERVERWARE_PROXY_TOKEN}@proxy.example.invalid:8443'));
  assert.ok(!text.includes(config.token));
  assert.ok(text.includes('strict-ssl=true\nfetch-retries=0\nfetch-timeout=10000'));
  assert.ok(!text.includes('cafile'));
  const child = childEnvironment(config, paths);
  assert.equal(child.NODE_EXTRA_CA_CERTS, paths.trust);
  for (const key of ['HOME', 'NPM_TOKEN', 'NODE_OPTIONS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'HTTPS_PROXY', 'NO_PROXY', 'npm_config_registry']) {
    assert.ok(!Object.hasOwn(child, key));
  }
  assert.equal(child.SERVERWARE_PROXY_TOKEN, config.token);
});

test('pacote uses normal HTTPS proxy, exact dummy, strict TLS and zero retries', () => {
  const config = configuration(env, 'manifest');
  const options = pacoteOptions(config, paths.cache);
  assert.equal(options.registry, 'https://registry.npmjs.org/');
  assert.equal(new URL(options.proxy).username, config.applicationId);
  assert.equal(new URL(options.proxy).password, config.token);
  assert.deepEqual(options.retry, { retries: 0 });
  assert.equal(options.strictSSL, true);
  assert.equal(options.noProxy, '');
  assert.equal(options.timeout, 10000);
  assert.equal(options.tufCache, paths.cache + '/tuf');
  assert.equal(options['//registry.npmjs.org/:_authToken'], PUBLIC_NPM_DUMMY);
  assert.equal(options.ca, undefined);
});

test('tarball review is exact and publishConfig cannot override stock configuration', () => {
  const config = configuration(env, 'publish');
  assert.equal(reviewedTarball(config, bytes), bytes);
  assert.throws(() => reviewedTarball(config, Buffer.from('different')));
  assert.throws(() => reviewedTarball(config, Buffer.alloc(8 * 1024 * 1024 + 1)));
  reviewedManifest(config, metadata);
  for (const value of [{ ...metadata, name: 'other' }, { ...metadata, version: '2.0.0' },
    { ...metadata, publishConfig: {} }, { ...metadata, private: true }]) {
    assert.throws(() => reviewedManifest(config, value));
  }
});

test('CLI arguments preserve stock publish prerequisite and explicit public tag without secret argv', () => {
  const config = configuration(env, 'publish');
  const args = npmArguments(config, paths);
  for (const flag of ['--access=public', '--tag=preview', '--ignore-scripts=true', '--provenance=false',
    '--force=false', '--dry-run=false', '--workspaces=false', '--json']) assert.ok(args.includes(flag));
  assert.ok(!JSON.stringify(args).includes(config.token));
  assert.deepEqual(npmArguments(configuration(env), paths).slice(-3), ['view', '@example/metadata', '--json']);
});

test('default view invokes the stock CLI once with bounded output/time and prints only selected metadata', async () => {
  let calls = 0;
  const result = await perform(configuration(env), paths, { pacote: { manifest: noCall }, readFile: noCall,
    node: '/node', env: {}, spawn(node, args, options) {
      calls++;
      assert.equal(node, '/node');
      assert.equal(options.timeout, 12000);
      assert.equal(options.killSignal, 'SIGKILL');
      assert.equal(options.maxBuffer, 2097152);
      assert.equal(options.cwd, paths.root);
      return { status: 0, signal: null, stderr: '', stdout: JSON.stringify(metadata) };
    } });
  assert.equal(calls, 1);
  assert.deepEqual(result, { ok: true, operation: 'view', package: metadata.name, version: '1.2.3', tarballFetched: false });
});

test('manifest uses only the stock metadata API, never tarball or CLI methods', async () => {
  const result = await perform(configuration(env, 'manifest'), paths, { spawn: noCall, readFile: noCall,
    pacote: { async manifest(spec, options) {
      assert.equal(spec, '@example/metadata@1.2.3');
      assert.equal(options.strictSSL, true);
      return metadata;
    }, extract: noCall, tarball: noCall } });
  assert.equal(result.tarballFetched, false);
});

test('publish reviews local file before one stock command and validates the returned archive receipt', async () => {
  const order = [];
  const config = configuration(env, 'publish');
  const dependencies = { node: '/node', env: {}, readFile(path) { assert.equal(path, paths.tarball); return bytes; },
    pacote: { async manifest(path, options) {
      order.push('review'); assert.equal(path, paths.tarball);
      assert.deepEqual(options, { cache: paths.cache, tufCache: paths.cache + '/tuf', offline: true, ignoreScripts: true }); return metadata;
    } }, spawn() { order.push('publish'); return { status: 0, signal: null, stderr: '', stdout: JSON.stringify(receipt) }; } };
  const result = await perform(config, paths, dependencies);
  assert.deepEqual(order, ['review', 'publish']);
  assert.equal(result.npmReportedSuccess, true);
  await assert.rejects(perform(config, paths, { ...dependencies,
    pacote: { async manifest() { return { ...metadata, publishConfig: { registry: 'https://evil.invalid' } }; } }, spawn: noCall }));
  await assert.rejects(perform(config, paths, { ...dependencies,
    spawn() { return { status: 0, signal: null, stderr: '', stdout: JSON.stringify({ ...receipt, integrity: 'wrong' }) }; } }));
});

test('errors are neither printed nor retried, and an uncertain write has a fixed warning', async () => {
  let calls = 0;
  await assert.rejects(perform(configuration(env), paths, { pacote: {}, spawn() {
    calls++; return { status: 1, signal: null, stdout: env.SERVERWARE_PROXY_TOKEN, stderr: env.SERVERWARE_PROXY_TOKEN };
  } }));
  assert.equal(calls, 1);
  const safe = JSON.stringify(failure('publish'));
  assert.ok(!safe.includes(env.SERVERWARE_PROXY_TOKEN));
  assert.ok(safe.includes('do not automatically retry'));
});

test('version guards cover direct and npm-bundled libraries; malformed trust is refused', () => {
  let reads = 0;
  const read = file => { reads++; const name = file.split('/').at(-2); return JSON.stringify({ name, version: VERSIONS[name] }); };
  verifyVersions(read);
  assert.equal(reads, 5);
  assert.throws(() => verifyVersions(file => JSON.stringify({ name: file.split('/').at(-2), version: '0.0.0' })));
  for (const text of ['', 'not a certificate', '-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----',
    '-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----']) {
    assert.throws(() => trustedPem(Buffer.from(text)));
  }
});

test('launcher uses a separate process group and bounded captured pipes (mock only)', async () => {
  const fake = new EventEmitter();
  fake.stdout = new EventEmitter(); fake.stderr = new EventEmitter();
  fake.stdout.setEncoding = fake.stderr.setEncoding = () => {};
  const pending = invokeWorker('/node', ['/example/worker.mjs', 'view'], { env: { SAFE: 'only' } }, (node, args, options) => {
    assert.equal(options.detached, true);
    assert.deepEqual(options.stdio, ['ignore', 'pipe', 'pipe']);
    assert.deepEqual(options.env, { SAFE: 'only' });
    queueMicrotask(() => { fake.stdout.emit('data', '{"ok":true}'); fake.emit('close', 0, null); });
    return fake;
  });
  assert.deepEqual(await pending, { status: 0, signal: null, stdout: '{"ok":true}', stderr: '' });
});

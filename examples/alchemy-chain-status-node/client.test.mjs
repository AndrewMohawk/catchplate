// Inert configuration/launcher tests. No SDK import, child execution or network.
import assert from 'node:assert/strict';
import { rootCertificates } from 'node:tls';
import test from 'node:test';
import { certificate, childEnvironment, configuration, DEADLINE_MS, failure, run, summary } from './client.mjs';
import { agentOptions, installTransport, perform, PUBLIC_ALCHEMY_DUMMY, sdkSettings } from './request.mjs';

const ENV = { SERVERWARE_PROXY_URL: 'https://proxy.example.test:8443',
  SERVERWARE_APP_ID: '11111111-2222-4333-8444-555555555555',
  SERVERWARE_PROXY_TOKEN: 'synthetic_app_token', SERVERWARE_CA_FILE: '/synthetic/inner.pem',
  SERVERWARE_ALCHEMY_CHAIN: 'eth-mainnet' };
const PEM = Buffer.from(rootCertificates[0]);
const SUCCESS = { ok: true, operation: 'chain-status', chain: 'eth-mainnet', chainId: '0x1', blockNumber: '0x123' };

test('only two fixed chains and an HTTPS credential-free proxy are configured', () => {
  assert.equal(configuration(ENV).chain, 'eth-mainnet');
  assert.equal(configuration({ ...ENV, SERVERWARE_ALCHEMY_CHAIN: 'eth-sepolia' }).chain, 'eth-sepolia');
  for (const patch of [
    { SERVERWARE_ALCHEMY_CHAIN: 'arbitrary' }, { SERVERWARE_ALCHEMY_CHAIN: 'eth-mainnet/key' },
    { SERVERWARE_PROXY_URL: 'http://proxy.example.test' },
    { SERVERWARE_PROXY_URL: 'https://user:secret@proxy.example.test' },
    { SERVERWARE_PROXY_URL: 'https://proxy.example.test/path' },
    { SERVERWARE_PROXY_URL: 'https://proxy.example.test/?key=value' },
    { SERVERWARE_APP_ID: 'not-an-app-id' }, { SERVERWARE_PROXY_TOKEN: 'token\r\nvalue' },
    { SERVERWARE_CA_FILE: 'relative.pem' }, { NODE_OPTIONS: '--inspect' },
    { NODE_DEBUG: 'https' }, { NODE_DEBUG_NATIVE: '*' }, { NODE_TLS_REJECT_UNAUTHORIZED: '0' },
  ]) assert.throws(() => configuration({ ...ENV, ...patch }));
});

test('child environment is an allowlist, never a proxy URL or provider secret', () => {
  const ambient = { ...ENV, HTTPS_PROXY: 'http://bad', NO_PROXY: '*', HOME: '/ambient',
    ALCHEMY_API_KEY: 'provider_secret_canary', NODE_EXTRA_CA_CERTS: '/ambient.pem' };
  assert.deepEqual(childEnvironment(configuration(ambient)), ENV);
  const outer = childEnvironment(configuration({ ...ambient, SERVERWARE_PROXY_CA_FILE: '/synthetic/outer.pem' }));
  assert.equal(outer.NODE_EXTRA_CA_CERTS, '/synthetic/outer.pem');
  assert.equal(outer.SERVERWARE_PROXY_CA_FILE, '/synthetic/outer.pem');
  assert.equal(JSON.stringify(outer).includes('provider_secret_canary'), false);
  assert.equal(JSON.stringify(outer).includes('@proxy'), false);
});

test('SDK settings use supported keyless and one-attempt overrides', async () => {
  const options = sdkSettings(configuration(ENV));
  assert.equal(options.url, 'https://eth-mainnet.g.alchemy.com/v2');
  assert.equal(options.apiKey, PUBLIC_ALCHEMY_DUMMY);
  assert.equal(options.batchRequests, false);
  assert.equal(options.maxRetries, 1);
  assert.equal(options.connectionInfoOverrides.throttleLimit, 1);
  assert.equal(await options.connectionInfoOverrides.throttleCallback(0, 'not used'), false);
  assert.equal(options.connectionInfoOverrides.timeout, 15000);
  assert.equal(options.connectionInfoOverrides.allowGzip, false);
  assert.deepEqual(options.connectionInfoOverrides.headers, {
    Authorization: 'Bearer serverware-alchemy-placeholder-v1', Accept: 'application/json',
    'Alchemy-Ethers-Sdk-Version': '3.6.5',
  });
});

test('agent routes via Basic CONNECT while its ca is inner-only', () => {
  const config = configuration({ ...ENV, SERVERWARE_PROXY_CA_FILE: '/synthetic/outer.pem' });
  const paths = [];
  const options = agentOptions(config, (path) => { paths.push(path); return PEM; });
  assert.deepEqual(paths, ['/synthetic/inner.pem']);
  assert.equal(options.rejectUnauthorized, true);
  assert.equal(options.ca, PEM);
  assert.deepEqual(Object.keys(options.proxyEnv).sort(), ['HTTPS_PROXY', 'NO_PROXY']);
  const proxy = new URL(options.proxyEnv.HTTPS_PROXY);
  assert.equal(proxy.protocol, 'https:');
  assert.equal(proxy.username, ENV.SERVERWARE_APP_ID);
  assert.equal(proxy.password, ENV.SERVERWARE_PROXY_TOKEN);
  assert.equal(proxy.hostname, 'proxy.example.test');
  assert.equal(options.proxyEnv.NO_PROXY, '');
  assert.equal(options.keepAlive, false);
});

test('process-scoped documented agent configuration restores and destroys', () => {
  const previous = {};
  let destroyed = 0;
  class Agent { constructor(options) { this.options = options; } destroy() { destroyed++; } }
  const module = { globalAgent: previous, Agent };
  const transport = installTransport(configuration(ENV), { module, readCertificate: () => PEM });
  assert.equal(module.globalAgent, transport.agent);
  transport.close();
  assert.equal(module.globalAgent, previous);
  assert.equal(destroyed, 1);
});

test('two ordinary SDK sends are sequential and output is bounded public data', async () => {
  const calls = [];
  const sdk = { config: { async getProvider() { return { async send(method, params) {
    calls.push([method, params]); return calls.length === 1 ? '0x1' : '0x123';
  } }; } } };
  assert.deepEqual(await perform(configuration(ENV), sdk), SUCCESS);
  assert.deepEqual(calls, [['eth_chainId', []], ['eth_blockNumber', []]]);
});

test('first-call errors and wrong chains never issue the second call', async () => {
  for (const result of ['0xaa36a7', new Error('private_error_canary')]) {
    const calls = [];
    const sdk = { config: { async getProvider() { return { async send(method) {
      calls.push(method); if (result instanceof Error) throw result; return result;
    } }; } } };
    await assert.rejects(perform(configuration(ENV), sdk));
    assert.deepEqual(calls, ['eth_chainId']);
  }
});

test('parent rejects unbounded, noncanonical or additional child fields', () => {
  assert.deepEqual(summary(SUCCESS, 'eth-mainnet'), SUCCESS);
  for (const value of [null, [], { ...SUCCESS, extra: 'canary' }, { ...SUCCESS, ok: false },
    { ...SUCCESS, chainId: '0x2' }, { ...SUCCESS, blockNumber: '0x01' },
    { ...SUCCESS, blockNumber: '0x' + 'f'.repeat(65) }, { ...SUCCESS, blockNumber: 123 }]) {
    assert.throws(() => summary(value, 'eth-mainnet'));
  }
});

test('launcher runs one bounded child without inherited options or credential argv', () => {
  const calls = [];
  const spawn = (...args) => { calls.push(args); return { status: 0, signal: null,
    stdout: JSON.stringify(SUCCESS), stderr: 'private_stderr_canary' }; };
  assert.deepEqual(run(ENV, { spawn, readFile: () => PEM }), SUCCESS);
  assert.equal(calls.length, 1);
  const [command, args, options] = calls[0];
  assert.equal(command, process.execPath);
  assert.equal(args.length, 1);
  assert.ok(args[0].endsWith('/request.mjs'));
  assert.equal(JSON.stringify(args).includes(ENV.SERVERWARE_PROXY_TOKEN), false);
  assert.deepEqual(options.env, ENV);
  assert.equal(options.timeout, DEADLINE_MS);
  assert.equal(options.killSignal, 'SIGKILL');
  assert.equal(options.maxBuffer, 65536);
  assert.deepEqual(options.stdio, ['ignore', 'pipe', 'pipe']);
});

test('launch failures are never replayed and diagnostics contain no SDK data', () => {
  for (const failed of [{ status: 1, signal: null }, { status: null, signal: 'SIGKILL' },
    { status: 0, signal: null, stdout: '{malformed' },
    { status: 0, signal: null, stdout: JSON.stringify({ ...SUCCESS, error: 'private_canary' }) },
    { error: new Error('private_canary'), status: null, signal: null }]) {
    let calls = 0;
    assert.throws(() => run(ENV, { readFile: () => PEM,
      spawn: () => { calls++; return { stderr: 'private_canary', ...failed }; } }));
    assert.equal(calls, 1);
  }
  assert.equal(JSON.stringify(failure(new Error('private_canary'))).includes('private_canary'), false);
});

test('CA input is bounded PEM certificates, not keys or arbitrary content', () => {
  assert.equal(certificate('/not read', () => PEM), PEM);
  for (const bytes of [Buffer.alloc(0), Buffer.alloc(262145), Buffer.from('not a certificate'),
    Buffer.concat([PEM, Buffer.from('\nPRIVATE KEY canary')]),
    Buffer.from('-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----')]) {
    assert.throws(() => certificate('/not read', () => bytes));
  }
});

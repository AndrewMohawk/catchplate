// Inert configuration/launcher tests. No SDK import, child execution or network.
import assert from 'node:assert/strict';
import { rootCertificates } from 'node:tls';
import test from 'node:test';
import { certificate, childEnvironment, configuration, DEADLINE_MS, failure, run, summary } from './client.mjs';
import { agentOptions, boundedDispatcher, createSdk, installTransport, perform, PUBLIC_ALCHEMY_DUMMY,
  REQUEST_TIMEOUT_MS, RESPONSE_LIMIT, sdkSettings } from './request.mjs';

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

test('SDK settings require an explicit dispatcher and keyless one-attempt transport', () => {
  const config = configuration(ENV), dispatcher = { dispatch() {} }, fetch = () => {};
  const options = sdkSettings(config, dispatcher, fetch);
  assert.equal(options.batch, false);
  assert.equal(options.retryCount, 0);
  assert.equal(options.timeout, REQUEST_TIMEOUT_MS);
  assert.equal(options.maxResponseBodySize, RESPONSE_LIMIT);
  assert.deepEqual(options.methods, { include: ['eth_chainId', 'eth_blockNumber'] });
  assert.equal(options.fetchFn, fetch);
  assert.equal(options.fetchOptions.dispatcher, dispatcher);
  assert.equal(options.fetchOptions.redirect, 'error');
  assert.deepEqual(options.fetchOptions.headers, {
    Authorization: 'Bearer serverware-alchemy-placeholder-v1', Accept: 'application/json',
    'Accept-Encoding': 'identity',
  });
  assert.equal(options.fetchOptions.headers.Authorization, 'Bearer ' + PUBLIC_ALCHEMY_DUMMY);
  for (const args of [[config], [config, {}], [config, dispatcher], [config, null, fetch]]) {
    assert.throws(() => sdkSettings(...args));
  }
  const transport = {}, client = {};
  assert.equal(createSdk(config, dispatcher, {
    fetch,
    http(url, selected) { assert.equal(url, 'https://eth-mainnet.g.alchemy.com/v2');
      assert.deepEqual(selected, options); return transport; },
    createPublicClient(selected) { assert.deepEqual(selected, { cacheTime: 0, ccipRead: false, transport }); return client; },
  }), client);
});

test('agent routes only via Basic CONNECT with explicit separate TLS roots', () => {
  const config = configuration({ ...ENV, SERVERWARE_PROXY_CA_FILE: '/synthetic/outer.pem' });
  const inner = Buffer.from(PEM), outer = Buffer.from(PEM);
  const paths = [];
  const options = agentOptions(config, (path) => { paths.push(path); return path === config.caFile ? inner : outer; });
  assert.deepEqual(paths, ['/synthetic/inner.pem', '/synthetic/outer.pem']);
  assert.equal(options.uri, ENV.SERVERWARE_PROXY_URL);
  assert.equal(options.token, 'Basic ' + Buffer.from(ENV.SERVERWARE_APP_ID + ':' + ENV.SERVERWARE_PROXY_TOKEN).toString('base64'));
  assert.deepEqual(options.requestTls, { ca: inner, rejectUnauthorized: true,
    servername: 'eth-mainnet.g.alchemy.com', allowH2: false, maxCachedSessions: 0 });
  assert.deepEqual(options.proxyTls, { ca: [...rootCertificates, outer], rejectUnauthorized: true,
    allowH2: false, maxCachedSessions: 0 });
  assert.equal(options.proxyTls.ca.includes(inner), false);
  assert.equal(options.connections, 1); assert.equal(options.pipelining, 0);
  assert.equal(options.allowH2, false); assert.equal(options.proxyTunnel, true);
  assert.equal(options.maxResponseSize, RESPONSE_LIMIT); assert.equal(options.maxHeaderSize, 16384);
  for (const key of ['connectTimeout', 'headersTimeout', 'bodyTimeout']) assert.equal(options[key], REQUEST_TIMEOUT_MS);
  assert.deepEqual(agentOptions(configuration(ENV), () => inner).proxyTls.ca, [...rootCertificates]);
});

test('dedicated supported ProxyAgent is destroyed without changing global dispatchers', async () => {
  let destroyed = 0;
  const interceptor = () => {}, dispatcher = { dispatch() {} };
  const interceptors = { responseError(options) {
    assert.deepEqual(options, { maxSize: RESPONSE_LIMIT }); return interceptor;
  } };
  class ProxyAgent {
    constructor(options) { this.options = options; }
    compose(selected) { assert.equal(selected, interceptor); return dispatcher; }
    async destroy() { destroyed++; }
  }
  const transport = installTransport(configuration(ENV), { ProxyAgent, interceptors, readCertificate: () => PEM });
  assert.ok(transport.agent instanceof ProxyAgent);
  assert.equal(transport.agent.options.uri, ENV.SERVERWARE_PROXY_URL);
  assert.equal(transport.dispatcher, dispatcher);
  await transport.close();
  assert.equal(destroyed, 1);
});

test('HTTP error guard uses one supported interceptor with a positive bounded body limit', () => {
  const calls = [], interceptor = () => {}, dispatcher = { dispatch() {} };
  const agent = { compose(value) { calls.push(['compose', value]); return dispatcher; } };
  const interceptors = { responseError(options) { calls.push(['responseError', options]); return interceptor; } };
  assert.equal(Number.isSafeInteger(RESPONSE_LIMIT) && RESPONSE_LIMIT > 0, true);
  assert.equal(boundedDispatcher(agent, interceptors), dispatcher);
  assert.deepEqual(calls, [['responseError', { maxSize: 65536 }], ['compose', interceptor]]);
});

test('two ordinary SDK sends are sequential and output is bounded public data', async () => {
  const calls = [];
  const sdk = { async request(request, options) {
    calls.push([request, options]); return calls.length === 1 ? '0x1' : '0x123';
  } };
  assert.deepEqual(await perform(configuration(ENV), sdk), SUCCESS);
  assert.deepEqual(calls, [
    [{ method: 'eth_chainId', params: [] }, { retryCount: 0, dedupe: false }],
    [{ method: 'eth_blockNumber', params: [] }, { retryCount: 0, dedupe: false }],
  ]);
});

test('first-call errors and wrong chains never issue the second call', async () => {
  for (const result of ['0xaa36a7', new Error('private_error_canary')]) {
    const calls = [];
    const sdk = { async request({ method }) {
      calls.push(method); if (result instanceof Error) throw result; return result;
    } };
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

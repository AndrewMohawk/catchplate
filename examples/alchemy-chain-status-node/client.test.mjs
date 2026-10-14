// Inert configuration/launcher tests. No SDK import, child execution or network.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { rootCertificates } from 'node:tls';
import test from 'node:test';
import { certificate, childEnvironment, configuration, DEADLINE_MS, failure, loadClientConfig, parseArguments, run, summary } from './client.mjs';
import { agentOptions, boundedDispatcher, createSdk, installTransport, perform, PUBLIC_ALCHEMY_DUMMY,
  REQUEST_TIMEOUT_MS, RESPONSE_LIMIT, sdkSettings } from './request.mjs';

const ENV = { SERVERWARE_PROXY_URL: 'https://proxy.example.test:8443',
  SERVERWARE_APP_ID: '11111111-2222-4333-8444-555555555555',
  SERVERWARE_PROXY_TOKEN: 'synthetic_app_token', SERVERWARE_CA_FILE: '/synthetic/inner.pem',
  SERVERWARE_ALCHEMY_CHAIN: 'eth-mainnet' };
const PEM = Buffer.from(rootCertificates[0]);
const SUCCESS = { ok: true, operation: 'chain-status', chain: 'eth-mainnet', chainId: '0x1', blockNumber: '0x123' };
const NOW = 1_791_996_000_000;
const downloaded = () => ({ application_id: ENV.SERVERWARE_APP_ID,
  access_rule_id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', proxy_url: ENV.SERVERWARE_PROXY_URL,
  proxy_authentication: 'basic_and_bearer_v1', proxy_username: ENV.SERVERWARE_APP_ID,
  proxy_password: 'downloaded_synthetic_token', token_expires_at_epoch_ms: NOW + 60000,
  ca_file: './serverware-ca.pem', proxy_ca_file: null, chain: 'eth-mainnet',
  upstream_url: 'https://eth-mainnet.g.alchemy.com/v2', methods: ['POST'],
  operation_bundle: 'alchemy_chain_status_read_v1', rpc_methods: ['eth_chainId', 'eth_blockNumber'],
  credential_input: 'replace_exact', response_mode: 'alchemy_rpc_read_json_v1' });
function configFile(t) {
  const directory = mkdtempSync(join(tmpdir(), 'serverware-alchemy-config-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'serverware-client.private.json');
  return { directory, path, write(value) { writeFileSync(path, JSON.stringify(value), { mode: 0o600 }); return path; } };
}

test('downloaded config imports only connection and exact chain; relative CA paths use the file directory', t => {
  const file = configFile(t), value = downloaded();
  value.request_body = { method: 'eth_sendRawTransaction', params: ['never-import'] };
  value.request_headers = { Authorization: 'never-import' };
  value.client_recipe = { command: 'never-execute', environment: { NODE_OPTIONS: 'never-import' } };
  const ambient = { ...ENV, SERVERWARE_ALCHEMY_CHAIN: 'eth-sepolia', SERVERWARE_PROXY_CA_FILE: '/stale.pem' };
  const config = loadClientConfig(file.write(value), ambient, NOW);
  assert.deepEqual(config, { proxyUrl: value.proxy_url, applicationId: value.application_id,
    token: value.proxy_password, chain: 'eth-mainnet', caFile: join(file.directory, 'serverware-ca.pem'), proxyCaFile: null });
  assert.equal(ambient.SERVERWARE_PROXY_CA_FILE, '/stale.pem');
  value.proxy_ca_file = './outer.pem';
  assert.equal(loadClientConfig(file.write(value), {}, NOW).proxyCaFile, join(file.directory, 'outer.pem'));
  delete value.proxy_ca_file;
  assert.equal(loadClientConfig(file.write(value), ambient, NOW).proxyCaFile, null);
  value.chain = 'eth-sepolia'; value.upstream_url = 'https://eth-sepolia.g.alchemy.com/v2';
  assert.equal(loadClientConfig(file.write(value), {}, NOW).chain, 'eth-sepolia');
});

test('downloaded config rejects mismatched identity, expired token and broadened RPC scope', t => {
  const file = configFile(t);
  for (const patch of [{ application_id: 'bad' }, { access_rule_id: 'bad' }, { proxy_username: 'other' },
    { proxy_authentication: 'bearer' }, { proxy_password: 'bad token' }, { proxy_url: 'http://proxy.test' },
    { token_expires_at_epoch_ms: NOW }, { token_expires_at_epoch_ms: String(NOW + 60000) },
    { token_expires_at_epoch_ms: Number.MAX_SAFE_INTEGER + 1 }, { ca_file: '' }, { proxy_ca_file: '' },
    { operation_bundle: 'generic' }, { chain: 'other' }, { methods: ['GET'] }, { methods: ['POST', 'POST'] },
    { upstream_url: 'https://eth-mainnet.g.alchemy.com/v2/private-key' },
    { upstream_url: 'https://eth-sepolia.g.alchemy.com/v2' }, { credential_input: 'inject' },
    { response_mode: 'passthrough' }, { rpc_methods: ['eth_sendRawTransaction'] }])
    assert.throws(() => loadClientConfig(file.write({ ...downloaded(), ...patch }), {}, NOW));
  file.write(downloaded());
  assert.throws(() => loadClientConfig(file.path, { NODE_TLS_REJECT_UNAUTHORIZED: '0' }, NOW));
  assert.throws(() => loadClientConfig(file.path, {}, NaN));
});

test('downloaded config is bounded regular JSON with fixed errors', t => {
  const file = configFile(t), json = JSON.stringify(downloaded());
  writeFileSync(file.path, json.padEnd(65536, ' '));
  assert.equal(loadClientConfig(file.path, {}, NOW).chain, 'eth-mainnet');
  for (const raw of ['', json.padEnd(65537, ' '), '{"secret":"private-canary"', 'null', '[]']) {
    writeFileSync(file.path, raw);
    assert.throws(() => loadClientConfig(file.path, {}, NOW), { message: 'Alchemy example configuration or response refused' });
  }
  assert.throws(() => loadClientConfig(file.directory, {}, NOW));
  file.write(downloaded()); const link = join(file.directory, 'link.json'); symlinkSync(file.path, link);
  assert.throws(() => loadClientConfig(link, {}, NOW));
});

test('config CLI preserves environment invocation and feeds only fixed settings to one inert child', t => {
  assert.deepEqual(parseArguments([]), { help: false, configPath: null });
  assert.deepEqual(parseArguments(['--config', './private.json']), { help: false, configPath: './private.json' });
  assert.equal(parseArguments(['--help']).help, true);
  for (const args of [['--config'], ['--config', ''], ['--config', '--help'], ['--config', 'a', '--config', 'b'],
    ['--help', 'extra'], ['--write'], ['send-transaction']]) assert.throws(() => parseArguments(args));
  const file = configFile(t), value = { ...downloaded(), token_expires_at_epoch_ms: Date.now() + 60000 };
  let calls = 0;
  assert.deepEqual(run({}, { configPath: file.write(value), readFile: () => PEM, spawn(command, args, options) {
    calls++; assert.equal(options.env.SERVERWARE_ALCHEMY_CHAIN, 'eth-mainnet');
    assert.equal(options.env.SERVERWARE_PROXY_TOKEN, value.proxy_password);
    assert.equal(args.length, 1); assert.ok(args[0].endsWith('/request.mjs'));
    return { status: 0, signal: null, stdout: JSON.stringify(SUCCESS) };
  } }), SUCCESS);
  assert.equal(calls, 1);
});

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

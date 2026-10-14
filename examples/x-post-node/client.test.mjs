import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { configuration, createSdk, failure, installTransport, loadClientConfig, onePostInterceptor, parseArguments,
  perform, postText, proxyOptions, PUBLIC_X_DUMMY, X_ORIGIN } from './client.mjs';

const env = () => ({ SERVERWARE_PROXY_URL: 'https://proxy.example.test',
  SERVERWARE_APP_ID: '11111111-2222-4333-8444-555555555555',
  SERVERWARE_PROXY_TOKEN: 'synthetic_app_token', SERVERWARE_CA_FILE: '/trusted/inner.pem',
  SERVERWARE_X_POST_TEXT: 'An explicit synthetic post.', SERVERWARE_X_POST_CONFIRM: 'post-once' });
const pem = value => Buffer.from('-----BEGIN CERTIFICATE-----\n' + value + '\n-----END CERTIFICATE-----');
const request = () => ({ origin: X_ORIGIN, path: '/2/tweets', method: 'POST', body: '{"text":"test"}' });
const NOW = 1_791_996_000_000;
const downloaded = () => ({ application_id: env().SERVERWARE_APP_ID,
  access_rule_id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', proxy_url: env().SERVERWARE_PROXY_URL,
  proxy_authentication: 'basic_and_bearer_v1', proxy_username: env().SERVERWARE_APP_ID,
  proxy_password: 'downloaded_synthetic_token', token_expires_at_epoch_ms: NOW + 60000,
  ca_file: './serverware-ca.pem', proxy_ca_file: null, upstream_url: X_ORIGIN + '/2/tweets', methods: ['POST'],
  operation_bundle: 'x_text_post_v1', credential_input: 'replace_exact', response_mode: 'x_post_json_v1',
  client_recipe: { required_local_environment: ['SERVERWARE_X_POST_TEXT', 'SERVERWARE_X_POST_CONFIRM'],
    confirmation_value: 'post-once', automatic_retries: 0, sdk_auth_token: PUBLIC_X_DUMMY } });
function configFile(t) {
  const directory = mkdtempSync(join(tmpdir(), 'serverware-x-post-config-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'serverware-client.private.json');
  return { directory, path, write(value) { writeFileSync(path, JSON.stringify(value), { mode: 0o600 }); return path; } };
}

test('downloaded config imports connection only; post content and confirmation remain local', t => {
  const file = configFile(t), value = downloaded();
  value.text = 'never-import'; value.request_body = { text: 'never-import' };
  value.request_headers = { Authorization: 'never-import' }; value.command = 'never-execute';
  value.SERVERWARE_X_POST_TEXT = 'never-import'; value.SERVERWARE_X_POST_CONFIRM = 'post-once';
  value.environment = { SERVERWARE_X_POST_TEXT: 'never-import', SERVERWARE_X_POST_CONFIRM: 'post-once' };
  value.client_recipe.environment = value.environment;
  const path = file.write(value);
  for (const local of [{}, { SERVERWARE_X_POST_TEXT: 'local' }, { SERVERWARE_X_POST_CONFIRM: 'post-once' },
    { SERVERWARE_X_POST_TEXT: 'local', SERVERWARE_X_POST_CONFIRM: 'yes' }])
    assert.throws(() => loadClientConfig(path, local, NOW));
  const ambient = { ...env(), SERVERWARE_PROXY_CA_FILE: '/stale.pem' };
  assert.deepEqual(loadClientConfig(path, ambient, NOW), {
    proxyUrl: value.proxy_url, applicationId: value.application_id, token: value.proxy_password,
    caFile: join(file.directory, 'serverware-ca.pem'), proxyCaFile: null, text: env().SERVERWARE_X_POST_TEXT });
  assert.equal(ambient.SERVERWARE_PROXY_CA_FILE, '/stale.pem');
  value.proxy_ca_file = './outer.pem';
  assert.equal(loadClientConfig(file.write(value), env(), NOW).proxyCaFile, join(file.directory, 'outer.pem'));
  delete value.proxy_ca_file;
  assert.equal(loadClientConfig(file.write(value), ambient, NOW).proxyCaFile, null);
});

test('downloaded config rejects mismatched identity, expired token and non-post scope', t => {
  const file = configFile(t);
  for (const patch of [{ application_id: 'bad' }, { access_rule_id: 'bad' }, { proxy_username: 'other' },
    { proxy_authentication: 'bearer' }, { proxy_password: 'bad token' }, { proxy_url: 'http://proxy.test' },
    { token_expires_at_epoch_ms: NOW }, { token_expires_at_epoch_ms: String(NOW + 60000) },
    { token_expires_at_epoch_ms: Number.MAX_SAFE_INTEGER + 1 }, { ca_file: '' }, { proxy_ca_file: '' },
    { operation_bundle: 'x_username_read_v1' }, { methods: ['GET'] }, { methods: ['POST', 'POST'] },
    { upstream_url: 'https://api.twitter.com/2/tweets' }, { upstream_url: X_ORIGIN + '/2/tweets?query=1' },
    { credential_input: 'inject' }, { response_mode: 'passthrough' }])
    assert.throws(() => loadClientConfig(file.write({ ...downloaded(), ...patch }), env(), NOW));
  file.write(downloaded());
  assert.throws(() => loadClientConfig(file.path, { ...env(), NODE_TLS_REJECT_UNAUTHORIZED: '0' }, NOW));
  assert.throws(() => loadClientConfig(file.path, env(), NaN));
});

test('downloaded config is bounded regular JSON and errors omit private content', t => {
  const file = configFile(t), json = JSON.stringify(downloaded());
  writeFileSync(file.path, json.padEnd(65536, ' '));
  assert.equal(loadClientConfig(file.path, env(), NOW).text, env().SERVERWARE_X_POST_TEXT);
  for (const raw of ['', json.padEnd(65537, ' '), '{"secret":"private-canary"', 'null', '[]']) {
    writeFileSync(file.path, raw);
    assert.throws(() => loadClientConfig(file.path, env(), NOW), { message: 'X posting configuration or response refused' });
  }
  assert.throws(() => loadClientConfig(file.directory, env(), NOW));
  file.write(downloaded()); const link = join(file.directory, 'link.json'); symlinkSync(file.path, link);
  assert.throws(() => loadClientConfig(link, env(), NOW));
});

test('config CLI preserves environment invocation and cannot supply posting confirmation or text', () => {
  assert.deepEqual(parseArguments([]), { help: false, configPath: null });
  assert.deepEqual(parseArguments(['--config', './private.json']), { help: false, configPath: './private.json' });
  assert.equal(parseArguments(['--help']).help, true);
  for (const args of [['--config'], ['--config', ''], ['--config', '--help'], ['--config', 'a', '--config', 'b'],
    ['--help', 'extra'], ['--confirm', 'post-once'], ['--text', 'post']]) assert.throws(() => parseArguments(args));
});

test('posting requires exact confirmation and bounded text without rewriting', () => {
  for (const patch of [{ SERVERWARE_X_POST_CONFIRM: undefined }, { SERVERWARE_X_POST_CONFIRM: 'yes' },
    { SERVERWARE_X_POST_TEXT: '' }, { SERVERWARE_X_POST_TEXT: 'x\0y' },
    { SERVERWARE_X_POST_TEXT: '\ud800' }, { SERVERWARE_X_POST_TEXT: '\udc00' },
    { SERVERWARE_X_POST_TEXT: 'x'.repeat(16385) }, { SERVERWARE_X_POST_TEXT: '€'.repeat(5462) },
    { SERVERWARE_X_POST_TEXT: '\t'.repeat(16384) }]) assert.throws(() => configuration({ ...env(), ...patch }));
  for (const text of ['  unchanged\n\t\r ', '🙂'.repeat(4096), 'x'.repeat(16384), 'é'.repeat(8192), 'x'.repeat(281)]) {
    assert.equal(postText(text), text);
    assert.equal(configuration({ ...env(), SERVERWARE_X_POST_TEXT: text }).text, text);
  }
});

test('explicit HTTPS proxy, application login and safe startup settings only', () => {
  for (const patch of [{ SERVERWARE_PROXY_URL: 'http://proxy.example.test' },
    { SERVERWARE_PROXY_URL: 'https://user:password@proxy.example.test' },
    { SERVERWARE_PROXY_URL: 'https://proxy.example.test/path' },
    { SERVERWARE_PROXY_URL: 'https://proxy.example.test?query=1' },
    { SERVERWARE_PROXY_TOKEN: 'secret\nvalue' }, { SERVERWARE_APP_ID: 'bad' },
    { SERVERWARE_CA_FILE: 'relative.pem' }, { SERVERWARE_PROXY_CA_FILE: 'relative.pem' },
    { NODE_TLS_REJECT_UNAUTHORIZED: '0' }, { NODE_OPTIONS: '--require other.js' },
    { NODE_DEBUG: 'http' }, { NODE_DEBUG_NATIVE: 'tls' }, { SSLKEYLOGFILE: '/tmp/secrets' }])
    assert.throws(() => configuration({ ...env(), ...patch }));
  const config = configuration({ ...env(), X_API_BEARER_TOKEN: 'provider_canary',
    X_ACCESS_TOKEN: 'provider_canary', HTTPS_PROXY: 'http://bypass.invalid', NO_PROXY: '*' });
  assert(!JSON.stringify(config).includes('provider_canary'));
  assert(!JSON.stringify(config).includes('bypass.invalid'));
});

test('Basic CONNECT credential is separate from URL and both verified TLS legs', () => {
  const config = configuration({ ...env(), SERVERWARE_PROXY_CA_FILE: '/trusted/outer.pem' });
  const options = proxyOptions(config, pem);
  assert.equal(options.uri, 'https://proxy.example.test');
  assert.equal(options.token, 'Basic ' + Buffer.from(config.applicationId + ':' + config.token).toString('base64'));
  assert.deepEqual(options.requestTls, { ca: pem('/trusted/inner.pem'), rejectUnauthorized: true });
  assert.deepEqual(options.proxyTls, { ca: pem('/trusted/outer.pem'), rejectUnauthorized: true });
  assert.deepEqual(proxyOptions(configuration(env()), pem).proxyTls, { rejectUnauthorized: true });
  for (const bytes of [Buffer.from('not PEM'), Buffer.alloc(262145), Buffer.from('-----BEGIN CERTIFICATE----- PRIVATE KEY')])
    assert.throws(() => proxyOptions(config, () => bytes));
});

test('stock SDK receives only public user-context dummy and retries disabled', () => {
  let actual;
  createSdk(class { constructor(options) { actual = options; } });
  assert.deepEqual(actual, { baseUrl: X_ORIGIN, accessToken: PUBLIC_X_DUMMY, retry: false, timeout: 30000 });
  assert(!Object.hasOwn(actual, 'bearerToken'));
  assert(!JSON.stringify(actual).includes(env().SERVERWARE_PROXY_TOKEN));
});

test('one-dispatch guard preserves request/handler behavior and observes final status', () => {
  const state = {}; const options = request(); const controller = {}; const headers = {};
  let sent = 0; let response = 0;
  const handler = { onResponseStart(...args) {
    assert.equal(this, handler); response++; assert.deepEqual(args, [controller, response === 1 ? 103 : 201, headers]);
    return 'unchanged';
  } };
  const dispatch = onePostInterceptor(state)((actual, wrapped) => {
    sent++; assert.equal(actual, options);
    assert.equal(wrapped.onResponseStart(controller, 103, headers), 'unchanged');
    assert.equal(state.httpStatus, undefined);
    assert.equal(wrapped.onResponseStart(controller, 201, headers), 'unchanged');
    return true;
  });
  assert.equal(dispatch(options, handler), true); assert.equal(state.httpStatus, 201);
  assert.throws(() => dispatch(options, handler)); assert.equal(sent, 1);
});

test('wrong origin/method/path/redirect cannot be dispatched or retried', () => {
  for (const patch of [{ origin: 'https://api.twitter.com' }, { origin: 'http://api.x.com' },
    { origin: 'https://api.x.com:444' }, { origin: 'https://user:secret@api.x.com' },
    { path: '/2/tweets?x=1' }, { path: '/2/tweets/' }, { path: '/2/users/me' }, { method: 'GET' }]) {
    const dispatch = onePostInterceptor({})(() => assert.fail('forbidden dispatch'));
    assert.throws(() => dispatch({ ...request(), ...patch }, {}));
    assert.throws(() => dispatch(request(), {}));
  }
});

test('transport restores previous dispatcher even when proxy destruction fails', async () => {
  const previous = {}; let current = previous; const error = new Error('fixed synthetic failure');
  class ProxyAgent {
    constructor(options) { this.options = options; }
    compose(interceptor) { this.interceptor = interceptor; return this; }
    async destroy() { this.destroyed = true; throw error; }
  }
  const transport = installTransport(configuration(env()), {}, { ProxyAgent, readFile: pem,
    getGlobalDispatcher: () => current, setGlobalDispatcher: value => { current = value; } });
  assert.equal(current, transport.dispatcher);
  await assert.rejects(transport.close(), value => value === error);
  assert.equal(current, previous); assert.equal(transport.proxy.destroyed, true);
});

test('one stock create call uses only exact text and prints no text or response extras', async () => {
  const config = configuration(env()); const state = {}; const calls = [];
  const sdk = { posts: { async create(...args) {
    calls.push(args); state.httpStatus = 201;
    return { data: { id: '123', text: 'private_response_canary', extra: 'private_response_canary' } };
  } } };
  assert.deepEqual(await perform(config, sdk, state), { status: 201, id: '123' });
  assert.deepEqual(calls, [[{ text: config.text }]]);
  await assert.rejects(perform(config, sdk, state)); assert.equal(calls.length, 1);
});

test('201 and nonempty decimal ID required; malformed results never replay', async () => {
  for (const [status, value] of [[200, { data: { id: '123' } }], [202, { data: { id: '123' } }],
    [201, {}], [201, { data: { id: '' } }], [201, { data: { id: 123 } }],
    [201, { data: { id: '1'.repeat(21) } }], [201, { data: { id: 'bad' } }],
    [201, { data: { id: '123' }, errors: [{ detail: 'secret_canary' }] }]]) {
    const state = {}; let calls = 0;
    await assert.rejects(perform(configuration(env()), { posts: { async create() {
      calls++; state.httpStatus = status; return value;
    } } }, state));
    assert.equal(calls, 1); assert.equal(failure(null, state).outcome, 'unknown');
  }
  for (const id of ['0', '01', '9'.repeat(20)]) {
    const state = {};
    assert.deepEqual(await perform(configuration(env()), { posts: { async create() {
      state.httpStatus = 201; return { data: { id } };
    } } }, state), { status: 201, id });
  }
});

test('withheld409/network/provider errors preserve uncertainty and redact all details', async () => {
  for (const status of [0, 409, 429, 500]) {
    const state = {}; let calls = 0;
    const error = Object.assign(new Error('provider_secret_canary'), { status, data: { text: env().SERVERWARE_X_POST_TEXT } });
    await assert.rejects(perform(configuration(env()), { posts: { async create() { calls++; throw error; } } }, state), value => value === error);
    const result = failure(error, state);
    assert.equal(result.outcome, 'unknown'); assert.equal(result.mayHaveBeenPosted, true);
    assert.equal(result.automaticRetryAllowed, false); assert.equal(calls, 1);
    assert.equal(result.httpStatus, status || null);
    assert(!JSON.stringify(result).includes('provider_secret_canary'));
    assert(!JSON.stringify(result).includes(env().SERVERWARE_X_POST_TEXT));
  }
  assert.equal(failure(new Error('private_config_canary')).outcome, 'not_attempted');
  assert.equal(failure(null).mayHaveBeenPosted, false);
});

test('copied dependency lock preserves exact reviewed dependency identities', () => {
  const lock = JSON.parse(readFileSync(new URL('./package-lock.json', import.meta.url)));
  assert.equal(lock.packages[''].name, 'serverware-x-post-example');
  assert.deepEqual(lock.packages[''].dependencies, { '@xdevplatform/xdk': '0.6.6', undici: '8.11.2' });
  for (const [name, version, integrity] of [
    ['@xdevplatform/xdk', '0.6.6', 'sha512-ced4iHSz08eQe1L0N3UWVvJyfGnmGU0CRjecoXpr27dVIyQvc637Pxm3cdP4G85PwhHn5IGVJ1DJF2YD9zWfAg=='],
    ['undici', '8.11.2', 'sha512-u4UB2/IrKdU6lFxumHmmo1a3fCQO5tzQllRorfoRS63txhrB7xTpSn1PftwC4qEHkOaqP95fCWW4lJzwErwzhQ=='],
  ]) {
    const record = lock.packages['node_modules/' + name];
    assert.equal(record.version, version); assert.equal(record.integrity, integrity);
    assert(record.resolved.startsWith('https://registry.npmjs.org/'));
  }
});

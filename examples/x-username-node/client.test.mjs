// Prepared pure tests: no dependency installation, socket, proxy or provider.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { configuration, createSdk, failure, installTransport, loadClientConfig, oneLookupInterceptor, parseArguments,
  perform, proxyOptions, PUBLIC_X_DUMMY, X_ORIGIN } from './client.mjs';

const env = () => ({ SERVERWARE_PROXY_URL: 'https://proxy.example.test',
  SERVERWARE_APP_ID: '11111111-2222-4333-8444-555555555555',
  SERVERWARE_PROXY_TOKEN: 'synthetic_app_token', SERVERWARE_CA_FILE: '/trusted/inner.pem',
  SERVERWARE_X_USERNAME: 'fixture_user' });
const pem = (value) => Buffer.from('-----BEGIN CERTIFICATE-----\n' + value + '\n-----END CERTIFICATE-----');
const request = () => ({ origin: X_ORIGIN, path: '/2/users/by/username/fixture_user', method: 'GET', body: null });
const NOW = 1_791_996_000_000;
const downloaded = () => ({ application_id: env().SERVERWARE_APP_ID,
  access_rule_id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', proxy_url: env().SERVERWARE_PROXY_URL,
  proxy_authentication: 'basic_and_bearer_v1', proxy_username: env().SERVERWARE_APP_ID,
  proxy_password: 'downloaded_synthetic_token', token_expires_at_epoch_ms: NOW + 60000,
  ca_file: './serverware-ca.pem', username: 'saved_user',
  upstream_url: X_ORIGIN + '/2/users/by/username/saved_user', methods: ['GET'],
  operation_bundle: 'x_username_read_v1', credential_input: 'replace_exact', response_mode: 'x_app_read_json_v1' });
function configFile(t) {
  const directory = mkdtempSync(join(tmpdir(), 'serverware-x-read-config-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'serverware-client.private.json');
  return { directory, path, write(value) { writeFileSync(path, JSON.stringify(value), { mode: 0o600 }); return path; } };
}

test('downloaded config imports only connection and exact username, resolving CA paths beside JSON', t => {
  const file = configFile(t), value = downloaded();
  value.request_headers = { Authorization: 'never-import' }; value.request_body = 'never-import';
  value.client_recipe = { command: 'never-execute', environment: { SERVERWARE_X_USERNAME: 'other' } };
  const ambient = { ...env(), SERVERWARE_PROXY_CA_FILE: '/stale.pem' };
  assert.deepEqual(loadClientConfig(file.write(value), ambient, NOW), {
    proxyUrl: value.proxy_url, applicationId: value.application_id, token: value.proxy_password,
    username: 'saved_user', caFile: join(file.directory, 'serverware-ca.pem'), proxyCaFile: null });
  assert.equal(ambient.SERVERWARE_PROXY_CA_FILE, '/stale.pem');
  value.proxy_ca_file = './outer.pem';
  assert.equal(loadClientConfig(file.write(value), {}, NOW).proxyCaFile, join(file.directory, 'outer.pem'));
  value.proxy_ca_file = null;
  assert.equal(loadClientConfig(file.write(value), ambient, NOW).proxyCaFile, null);
});

test('downloaded config rejects mismatched identity, expired tokens and other X operations', t => {
  const file = configFile(t);
  for (const patch of [{ application_id: 'bad' }, { access_rule_id: 'bad' }, { proxy_username: 'other' },
    { proxy_authentication: 'bearer' }, { proxy_password: 'bad token' }, { proxy_url: 'http://proxy.test' },
    { token_expires_at_epoch_ms: NOW }, { token_expires_at_epoch_ms: String(NOW + 60000) },
    { token_expires_at_epoch_ms: Number.MAX_SAFE_INTEGER + 1 }, { ca_file: '' }, { proxy_ca_file: '' },
    { operation_bundle: 'x_text_post_v1' }, { username: 'Other' }, { username: 'other' },
    { methods: ['POST'] }, { methods: ['GET', 'GET'] }, { upstream_url: X_ORIGIN + '/2/users/me' },
    { upstream_url: downloaded().upstream_url + '?user.fields=id' },
    { credential_input: 'inject' }, { response_mode: 'passthrough' }])
    assert.throws(() => loadClientConfig(file.write({ ...downloaded(), ...patch }), {}, NOW));
  file.write(downloaded());
  assert.throws(() => loadClientConfig(file.path, { NODE_OPTIONS: '--require unsafe' }, NOW));
  assert.throws(() => loadClientConfig(file.path, {}, NaN));
});

test('downloaded config is bounded regular JSON and errors omit private content', t => {
  const file = configFile(t), json = JSON.stringify(downloaded());
  writeFileSync(file.path, json.padEnd(65536, ' '));
  assert.equal(loadClientConfig(file.path, {}, NOW).username, 'saved_user');
  for (const raw of ['', json.padEnd(65537, ' '), '{"secret":"private-canary"', 'null', '[]']) {
    writeFileSync(file.path, raw);
    assert.throws(() => loadClientConfig(file.path, {}, NOW), { message: 'X example configuration or request refused' });
  }
  assert.throws(() => loadClientConfig(file.directory, {}, NOW));
  file.write(downloaded()); const link = join(file.directory, 'link.json'); symlinkSync(file.path, link);
  assert.throws(() => loadClientConfig(link, {}, NOW));
});

test('config CLI preserves environment invocation and admits no operation or extra arguments', () => {
  assert.deepEqual(parseArguments([]), { help: false, configPath: null });
  assert.deepEqual(parseArguments(['--config', './private.json']), { help: false, configPath: './private.json' });
  assert.equal(parseArguments(['--help']).help, true);
  for (const args of [['--config'], ['--config', ''], ['--config', '--help'], ['--config', 'a', '--config', 'b'],
    ['--help', 'extra'], ['--write'], ['post']]) assert.throws(() => parseArguments(args));
});

test('exact lowercase username and explicit HTTPS proxy only', () => {
  for (const patch of [
    { SERVERWARE_PROXY_URL: 'http://proxy.example.test' },
    { SERVERWARE_PROXY_URL: 'https://user:password@proxy.example.test' },
    { SERVERWARE_PROXY_URL: 'https://proxy.example.test/path' },
    { SERVERWARE_PROXY_URL: 'https://proxy.example.test?query=1' },
    { SERVERWARE_X_USERNAME: 'Uppercase' }, { SERVERWARE_X_USERNAME: 'bad/name' },
    { SERVERWARE_X_USERNAME: 'a'.repeat(16) }, { SERVERWARE_X_USERNAME: '' },
    { SERVERWARE_PROXY_TOKEN: 'secret\nvalue' }, { SERVERWARE_APP_ID: 'bad' },
    { SERVERWARE_CA_FILE: '' }, { NODE_TLS_REJECT_UNAUTHORIZED: '0' }, { NODE_OPTIONS: '--require other.js' },
  ]) assert.throws(() => configuration({ ...env(), ...patch }));
  const config = configuration({ ...env(), X_API_BEARER_TOKEN: 'must_not_use',
    HTTPS_PROXY: 'http://bypass.invalid', NO_PROXY: '*' });
  assert.equal(config.username, 'fixture_user');
  assert.equal(JSON.stringify(config).includes('must_not_use'), false);
  assert.equal(JSON.stringify(config).includes('bypass'), false);
});

test('application identity is outer Basic; inner and outer trust stay separate', () => {
  const config = configuration({ ...env(), SERVERWARE_PROXY_CA_FILE: '/trusted/outer.pem' });
  const options = proxyOptions(config, pem);
  assert.equal(options.token, 'Basic ' + Buffer.from(config.applicationId + ':' + config.token).toString('base64'));
  assert.deepEqual(options.requestTls, { ca: pem('/trusted/inner.pem'), rejectUnauthorized: true });
  assert.deepEqual(options.proxyTls, { ca: pem('/trusted/outer.pem'), rejectUnauthorized: true });
  assert.deepEqual(proxyOptions(configuration(env()), pem).proxyTls, { rejectUnauthorized: true });
  assert.throws(() => proxyOptions(config, () => Buffer.from('not a CA')));
});

test('stock SDK gets dummy, fixed origin, explicit retry false and timeout', () => {
  let actual;
  class Client { constructor(options) { actual = options; } }
  createSdk(Client);
  assert.deepEqual(actual, { baseUrl: X_ORIGIN, bearerToken: PUBLIC_X_DUMMY, retry: false, timeout: 30000 });
  assert.equal(JSON.stringify(actual).includes(env().SERVERWARE_PROXY_TOKEN), false);
});

test('guard passes request untouched once and rejects redirect/repeat dispatches', () => {
  const config = configuration(env());
  const seen = [];
  const dispatch = oneLookupInterceptor(config)((...args) => { seen.push(args); return true; });
  const options = { ...request(), headers: { authorization: 'Bearer ' + PUBLIC_X_DUMMY } };
  const handler = {};
  assert.equal(dispatch(options, handler), true);
  assert.equal(seen[0][0], options);
  assert.equal(seen[0][1], handler);
  assert.throws(() => dispatch(options, handler));
  assert.equal(seen.length, 1);
  for (const patch of [{ origin: 'https://api.twitter.com' }, { origin: 'http://api.x.com' },
    { origin: 'https://api.x.com:444' }, { origin: 'https://u:p@api.x.com' },
    { path: '/2/users/by/username/other' }, { path: request().path + '?user.fields=id' },
    { method: 'POST' }, { body: '{}' }]) {
    const guarded = oneLookupInterceptor(config)(() => assert.fail('forbidden dispatch'));
    assert.throws(() => guarded({ ...request(), ...patch }, {}));
    assert.throws(() => guarded(request(), {}), 'refusal also consumes the local one-attempt budget');
  }
});

test('documented dispatcher setup restores prior dispatcher and destroys proxy', async () => {
  const previous = {};
  let current = previous;
  class ProxyAgent {
    constructor(options) { this.options = options; }
    compose(interceptor) { this.interceptor = interceptor; return this; }
    async destroy() { this.destroyed = true; }
  }
  const transport = installTransport(configuration(env()), { ProxyAgent, readFile: pem,
    getGlobalDispatcher: () => current, setGlobalDispatcher: (value) => { current = value; } });
  assert.equal(current, transport.dispatcher);
  await transport.close();
  assert.equal(current, previous);
  assert.equal(transport.proxy.destroyed, true);
});

test('one actual SDK-method call, no query options, bounded signal and narrow output', async () => {
  const calls = [];
  const result = await perform(configuration(env()), { users: { async getByUsername(...args) {
    calls.push(args); return { data: { id: '123', username: 'Fixture_User', name: 'not printed' } };
  } } });
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'fixture_user');
  assert.deepEqual(Object.keys(calls[0][1]), ['requestOptions']);
  assert.ok(calls[0][1].requestOptions.signal instanceof AbortSignal);
  assert.deepEqual(result, { operation: 'lookup-username', id: '123', username: 'Fixture_User' });
});

test('provider errors or mismatched data are not successful lookups; errors stay fixed', async () => {
  for (const response of [{ errors: [{ detail: 'secret_canary' }] },
    { data: { id: '123', username: 'other' } }, { data: { id: 'bad', username: 'fixture_user' } },
    { data: { id: '123', username: 'fixture_user' }, errors: [{ detail: 'secret_canary' }] }]) {
    await assert.rejects(perform(configuration(env()), { users: { getByUsername: async () => response } }));
  }
  let calls = 0;
  const error = Object.assign(new Error('secret_canary'), { status: 429, request: { secret: 'secret_canary' } });
  await assert.rejects(perform(configuration(env()), { users: { getByUsername: async () => { calls++; throw error; } } }));
  assert.equal(calls, 1);
  assert.equal(failure(error).httpStatus, 429);
  assert.equal(JSON.stringify(failure(error)).includes('secret_canary'), false);
});

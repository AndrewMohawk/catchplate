// Prepared pure tests: no dependency installation, socket, proxy or provider.
import assert from 'node:assert/strict';
import test from 'node:test';
import { configuration, createSdk, failure, installTransport, oneLookupInterceptor,
  perform, proxyOptions, PUBLIC_X_DUMMY, X_ORIGIN } from './client.mjs';

const env = () => ({ SERVERWARE_PROXY_URL: 'https://proxy.example.test',
  SERVERWARE_APP_ID: '11111111-2222-4333-8444-555555555555',
  SERVERWARE_PROXY_TOKEN: 'synthetic_app_token', SERVERWARE_CA_FILE: '/trusted/inner.pem',
  SERVERWARE_X_USERNAME: 'fixture_user' });
const pem = (value) => Buffer.from('-----BEGIN CERTIFICATE-----\n' + value + '\n-----END CERTIFICATE-----');
const request = () => ({ origin: X_ORIGIN, path: '/2/users/by/username/fixture_user', method: 'GET', body: null });

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

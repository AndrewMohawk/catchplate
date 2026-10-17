// Prepared OFFLINE SDK serialization tests. Real XDK + native fetch + Undici
// MockAgent; no real proxy, TLS, credential release, provider or deployment proof.
import assert from 'node:assert/strict';
import dns from 'node:dns';
import net from 'node:net';
import test from 'node:test';
import { MockAgent, getGlobalDispatcher, setGlobalDispatcher } from 'undici';
import { configuration, createSdk, failure, oneLookupInterceptor, perform,
  PUBLIC_X_DUMMY, X_ORIGIN } from './client.mjs';

const ENV = { CATCHPLATE_PROXY_URL: 'https://proxy.example.test',
  CATCHPLATE_APP_ID: '11111111-2222-4333-8444-555555555555',
  CATCHPLATE_PROXY_TOKEN: 'synthetic_app_token', CATCHPLATE_CA_FILE: '/synthetic/inner.pem',
  CATCHPLATE_X_USERNAME: 'fixture_user' };
const PATH = '/2/users/by/username/fixture_user';
const EXPECTED_HEADERS = { authorization: 'Bearer ' + PUBLIC_X_DUMMY,
  accept: 'application/json', 'content-type': 'application/json',
  'user-agent': 'xdk-typescript/0.6.6', 'accept-language': '*', 'sec-fetch-mode': 'cors' };

async function fixture(t, status, response, extraHeaders = {}) {
  const forbidden = () => { throw new Error('Offline SDK fixture forbids real networking'); };
  t.mock.method(net.Socket.prototype, 'connect', forbidden);
  t.mock.method(dns, 'lookup', forbidden);
  const previous = getGlobalDispatcher();
  const mock = new MockAgent();
  mock.disableNetConnect();
  const config = configuration(ENV);
  const calls = [];
  const observed = (dispatch) => (options, handler) => {
    calls.push(options);
    return dispatch(options, handler);
  };
  setGlobalDispatcher(mock.compose(observed, oneLookupInterceptor(config)));
  t.after(async () => {
    setGlobalDispatcher(previous);
    await mock.close();
  });
  mock.get(X_ORIGIN).intercept({ method: 'GET', path: PATH, headers: EXPECTED_HEADERS })
    .reply(status, response, { headers: { 'content-type': 'application/json', ...extraHeaders } });
  const { Client } = await import('@xdevplatform/xdk');
  const sdk = createSdk(Client);
  assert.ok(sdk instanceof Client);
  return { config, sdk, mock, calls };
}

test('real pinned SDK serializes the bodyless lookup and actual JSON headers', { timeout: 5000 }, async (t) => {
  const f = await fixture(t, 200, { data: { id: '123', username: 'fixture_user', name: 'not printed' } });
  assert.deepEqual(await perform(f.config, f.sdk), { operation: 'lookup-username', id: '123', username: 'fixture_user' });
  f.mock.assertNoPendingInterceptors();
  assert.equal(f.calls.length, 1);
  assert.equal(f.calls[0].path, PATH);
  assert.equal(f.calls[0].body == null, true);
  const inner = JSON.stringify(f.calls[0].headers);
  for (const privateValue of [ENV.CATCHPLATE_APP_ID, ENV.CATCHPLATE_PROXY_TOKEN, 'proxy-authorization']) {
    assert.equal(inner.includes(privateValue), false);
  }
});

test('actual SDK HTTP error is fixed in output and is not retried', { timeout: 5000 }, async (t) => {
  const f = await fixture(t, 429, { detail: 'secret_response_canary' });
  let error;
  try { await perform(f.config, f.sdk); } catch (caught) { error = caught; }
  assert.ok(error);
  assert.equal(failure(error).httpStatus, 429);
  assert.equal(JSON.stringify(failure(error)).includes('secret_response_canary'), false);
  f.mock.assertNoPendingInterceptors();
  assert.equal(f.calls.length, 1);
});

test('redirect cannot dispatch to a different username or origin', { timeout: 5000 }, async (t) => {
  const f = await fixture(t, 302, {}, { location: 'https://api.x.com/2/users/by/username/other' });
  await assert.rejects(perform(f.config, f.sdk));
  f.mock.assertNoPendingInterceptors();
  assert.equal(f.calls.length, 1, 'guard rejects the second dispatch before the mock transport');
});

test('HTTP200 provider error envelope is not lookup success', { timeout: 5000 }, async (t) => {
  const f = await fixture(t, 200, { errors: [{ detail: 'not printed' }] });
  await assert.rejects(perform(f.config, f.sdk));
  f.mock.assertNoPendingInterceptors();
  assert.equal(f.calls.length, 1);
});

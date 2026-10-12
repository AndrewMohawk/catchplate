// Real pinned SDK, native fetch and MockAgent only. Networking is prohibited.
import assert from 'node:assert/strict';
import dns from 'node:dns';
import net from 'node:net';
import test from 'node:test';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';
import { configuration, createSdk, failure, onePostInterceptor, perform, PUBLIC_X_DUMMY, X_ORIGIN } from './client.mjs';

// Repository-only offline fallback reads the identical installed username cache.
// The actual CLI has no fallback and resolves only its own pinned dependencies.
let dependencies = createRequire(new URL('./package.json', import.meta.url));
try { dependencies.resolve('@xdevplatform/xdk'); dependencies.resolve('undici'); }
catch (error) {
  assert.equal(error.code, 'MODULE_NOT_FOUND');
  dependencies = createRequire(new URL('../x-username-node/package.json', import.meta.url));
}
const { MockAgent, getGlobalDispatcher, setGlobalDispatcher } = await import(pathToFileURL(dependencies.resolve('undici')));
assert.equal(dependencies('undici/package.json').version, '8.11.2');
// The SDK export map does not expose package.json; version is independently
// checked through its exact generated wire User-Agent below.
const ENV = { SERVERWARE_PROXY_URL: 'https://proxy.example.test',
  SERVERWARE_APP_ID: '11111111-2222-4333-8444-555555555555',
  SERVERWARE_PROXY_TOKEN: 'synthetic_app_token', SERVERWARE_CA_FILE: '/synthetic/inner.pem',
  SERVERWARE_X_POST_TEXT: 'Keep Unicode 🙂 and\n\ttabs\r unchanged.', SERVERWARE_X_POST_CONFIRM: 'post-once' };
const HEADERS = { authorization: 'Bearer ' + PUBLIC_X_DUMMY, accept: 'application/json',
  'content-type': 'application/json', 'user-agent': 'xdk-typescript/0.6.6',
  'accept-language': '*', 'sec-fetch-mode': 'cors' };

async function fixture(t, status, response, extraHeaders = {}, env = ENV) {
  const forbidden = () => { throw new Error('Offline posting test forbids real networking'); };
  t.mock.method(net.Socket.prototype, 'connect', forbidden); t.mock.method(dns, 'lookup', forbidden);
  const previous = getGlobalDispatcher(); const mock = new MockAgent(); mock.disableNetConnect();
  const state = {}; const calls = []; const bodies = []; const config = configuration(env);
  const observe = dispatch => (options, handler) => { calls.push(options); return dispatch(options, handler); };
  setGlobalDispatcher(mock.compose(observe, onePostInterceptor(state)));
  t.after(async () => { setGlobalDispatcher(previous); await mock.close(); });
  mock.get(X_ORIGIN).intercept({ method: 'POST', path: '/2/tweets', headers: HEADERS })
    .reply(async options => {
      // Terminal mock receiver reads native fetch's original body stream. No
      // dispatcher or SDK request is rewritten to manufacture compatibility.
      const parts = []; let length = 0;
      const chunks = typeof options.body === 'string' || ArrayBuffer.isView(options.body)
        ? [options.body] : options.body;
      for await (const chunk of chunks) {
        const bytes = Buffer.from(chunk); length += bytes.length;
        assert(length <= 32768); parts.push(bytes);
      }
      const bytes = Buffer.concat(parts);
      assert.deepEqual(bytes, Buffer.from(JSON.stringify({ text: config.text })));
      bodies.push(bytes);
      return { statusCode: status, data: response,
        responseOptions: { headers: { 'content-type': 'application/json', ...extraHeaders } } };
    });
  const { Client } = await import(pathToFileURL(dependencies.resolve('@xdevplatform/xdk')));
  const sdk = createSdk(Client); assert(sdk instanceof Client);
  return { config, sdk, mock, calls, bodies, state };
}

test('stock posts.create serializes exact text-only JSON and user-context dummy once', { timeout: 5000 }, async t => {
  const f = await fixture(t, 201, { data: { id: '1234567890', text: 'not printed' } });
  assert.deepEqual(await perform(f.config, f.sdk, f.state), { status: 201, id: '1234567890' });
  f.mock.assertNoPendingInterceptors(); assert.equal(f.calls.length, 1); assert.equal(f.state.httpStatus, 201);
  assert.equal(f.bodies.length, 1);
  for (const value of [ENV.SERVERWARE_APP_ID, ENV.SERVERWARE_PROXY_TOKEN, 'proxy-authorization'])
    assert(!JSON.stringify(f.calls[0].headers).includes(value));
});

test('stock SDK preserves a text longer than 280 codepoints without a client length rewrite', { timeout: 5000 }, async t => {
  const f = await fixture(t, 201, { data: { id: '123' } }, {}, { ...ENV, SERVERWARE_X_POST_TEXT: 'x'.repeat(1000) });
  await perform(f.config, f.sdk, f.state); f.mock.assertNoPendingInterceptors(); assert.equal(f.calls.length, 1);
});

for (const status of [409, 429, 503]) test(`actual SDK HTTP${status} is uncertain and never retried`, { timeout: 5000 }, async t => {
  const f = await fixture(t, status, { detail: 'private_response_canary' });
  let error;
  try { await perform(f.config, f.sdk, f.state); } catch (caught) { error = caught; }
  assert(error); const result = failure(error, f.state);
  assert.equal(result.httpStatus, status); assert.equal(result.outcome, 'unknown');
  assert.equal(result.mayHaveBeenPosted, true); assert.equal(result.automaticRetryAllowed, false);
  assert(!JSON.stringify(result).includes('private_response_canary'));
  f.mock.assertNoPendingInterceptors(); assert.equal(f.calls.length, 1);
});

test('HTTP200 with a plausible post ID is not confirmed creation', { timeout: 5000 }, async t => {
  const f = await fixture(t, 200, { data: { id: '123' } });
  await assert.rejects(perform(f.config, f.sdk, f.state));
  assert.equal(failure(null, f.state).outcome, 'unknown');
  f.mock.assertNoPendingInterceptors(); assert.equal(f.calls.length, 1);
});

test('307 redirect cannot replay the POST, even to the same URL', { timeout: 5000 }, async t => {
  const f = await fixture(t, 307, {}, { location: X_ORIGIN + '/2/tweets' });
  await assert.rejects(perform(f.config, f.sdk, f.state));
  f.mock.assertNoPendingInterceptors(); assert.equal(f.calls.length, 1);
});

test('201 malformed JSON is uncertain, not success', { timeout: 5000 }, async t => {
  const f = await fixture(t, 201, '{invalid private_response_canary');
  await assert.rejects(perform(f.config, f.sdk, f.state));
  assert.equal(failure(null, f.state).mayHaveBeenPosted, true);
  f.mock.assertNoPendingInterceptors(); assert.equal(f.calls.length, 1);
});

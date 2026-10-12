import assert from 'node:assert/strict';
import test from 'node:test';
import { Readable } from 'node:stream';
import { spawnSync } from 'node:child_process';
import { configuration, proxyOptions, createTransport, perform, FAILURE } from './client.mjs';

const env = { SERVERWARE_PROXY_URL: 'https://proxy.example:443',
  SERVERWARE_APP_ID: '11111111-2222-4333-8444-555555555555',
  SERVERWARE_PROXY_TOKEN: Buffer.alloc(32, 7).toString('base64url'),
  SERVERWARE_CA_FILE: '/private/inner.pem', SERVERWARE_PROXY_CA_FILE: '/private/outer.pem' };
const certificate = name => Buffer.from('-----BEGIN CERTIFICATE-----\nsynthetic-' + name);
const readFile = path => certificate(path);
class Proxy { constructor(options) { this.options = options; } async destroy() {} }
const url = 'https://gmail.googleapis.com/gmail/v1/users/me/messages?maxResults=5&labelIds=INBOX';
const options = { method: 'GET', headers: { authorization: 'Bearer serverware-gmail-placeholder-v1' } };
function response(body = '{}', statusCode = 200, headers = {}) {
  return { statusCode, headers, body: Readable.from([Buffer.from(body)]) };
}

test('configuration is application-only; refuses ambient diagnostic/credential controls and malformed input', () => {
  assert.equal(configuration(env).applicationId, env.SERVERWARE_APP_ID);
  for (const override of [
    { SERVERWARE_PROXY_URL: 'http://proxy.example' }, { SERVERWARE_PROXY_URL: 'https://user:secret@proxy.example' },
    { SERVERWARE_PROXY_URL: 'https://proxy.example/path' }, { SERVERWARE_PROXY_URL: 'https://proxy.example/?secret=x' },
    { SERVERWARE_PROXY_URL: 'https://gmail.googleapis.com' }, { SERVERWARE_PROXY_URL: 'https://127.0.0.1' },
    { SERVERWARE_PROXY_URL: 'https://proxy.example:' }, { SERVERWARE_PROXY_URL: 'https://proxy.example:65536' },
    { SERVERWARE_APP_ID: 'bad' }, { SERVERWARE_PROXY_TOKEN: 'provider-token' },
    { SERVERWARE_PROXY_TOKEN: 'B'.repeat(43) }, { SERVERWARE_CA_FILE: '' },
    { NODE_TLS_REJECT_UNAUTHORIZED: '0' }, { DEBUG: '*' }, { NODE_DEBUG: 'http' },
    { NODE_OPTIONS: '--require hook' }, { GOOGLE_APPLICATION_CREDENTIALS: '/private/provider.json' },
  ]) assert.throws(() => configuration({ ...env, ...override }));
});

test('separate CA roots; Basic app identity is CONNECT-only and never URL userinfo', () => {
  const config = configuration(env);
  const options = proxyOptions(config, readFile);
  assert.equal(options.uri, env.SERVERWARE_PROXY_URL);
  assert.equal(options.token, 'Basic ' + Buffer.from(env.SERVERWARE_APP_ID + ':' + env.SERVERWARE_PROXY_TOKEN).toString('base64'));
  assert.equal(options.proxyTls.rejectUnauthorized, true);
  assert.equal(options.requestTls.rejectUnauthorized, true);
  assert.deepEqual(options.requestTls.ca, certificate('/private/inner.pem'));
  assert.deepEqual(options.proxyTls.ca.at(-1), certificate('/private/outer.pem'));
  assert.ok(!options.proxyTls.ca.some(ca => Buffer.from(ca).equals(options.requestTls.ca)));
  assert.equal(options.connections, 1);
  assert.equal(options.pipelining, 0);
  assert.throws(() => proxyOptions(config, () => Buffer.alloc(1024 * 1024 + 1)));
});

test('bounded transport preserves SDK headers/query and never supplies app auth to Gmail', async () => {
  let seen;
  const transport = createTransport(configuration(env), { ProxyAgent: Proxy, readFile,
    request: async (target, init) => { seen = { target, init }; return response('{"messages":[]}'); } });
  const headers = { ...options.headers, 'user-agent': 'official-client', 'x-goog-api-client': 'official-version', 'accept-encoding': 'gzip' };
  assert.deepEqual(await (await transport.fetchImplementation(url, { ...options, headers })).json(), { messages: [] });
  assert.equal(String(seen.target), url);
  assert.deepEqual(seen.init.headers, headers);
  assert.equal(seen.init.maxRedirections, 0);
  assert.equal(seen.init.dispatcher, transport.proxy);
  assert.equal(seen.init.headersTimeout, 30000);
  assert.ok(seen.init.signal instanceof AbortSignal);
  assert.ok(!JSON.stringify(seen.init.headers).includes(env.SERVERWARE_PROXY_TOKEN));
});

test('target/method/header/budget controls stop before dispatch', async () => {
  let calls = 0;
  const transport = createTransport(configuration(env), { ProxyAgent: Proxy, readFile,
    request: async () => { calls++; return response(); } });
  for (const [target, init] of [
    ['https://other.example/', options], [url, { ...options, method: 'POST' }],
    [url, { ...options, body: '' }], [url, { ...options, headers: { authorization: 'Bearer real-token' } }],
    [url, { ...options, headers: { ...options.headers, 'x-goog-user-project': 'billing' } }],
    ['https://gmail.googleapis.com/gmail/v1/users/other/messages', options],
  ]) await assert.rejects(transport.fetchImplementation(target, init));
  assert.equal(calls, 0);
  for (let i = 0; i < 12; i++) await transport.fetchImplementation(url, options);
  await assert.rejects(transport.fetchImplementation(url, options));
  assert.equal(calls, 12);
});

test('response bounds, redirects, compressed response and cancellation fail closed', async () => {
  for (const makeResponse of [() => response('x'.repeat(1024 * 1024 + 1)),
    () => response('x'.repeat(65537), 403), () => response('', 302, { location: 'https://other.example/' }),
    () => response('{}', 200, { 'content-encoding': 'gzip' })]) {
    const reply = makeResponse();
    let calls = 0;
    const transport = createTransport(configuration(env), { ProxyAgent: Proxy, readFile,
      request: async () => { calls++; return reply; } });
    await assert.rejects(transport.fetchImplementation(url, options));
    assert.equal(calls, 1);
    assert.equal(reply.body.destroyed, true);
  }
  const transport = createTransport(configuration(env), { ProxyAgent: Proxy, readFile,
    request: async () => { throw new Error('must not dispatch'); } });
  await assert.rejects(transport.fetchImplementation(url, { ...options, signal: AbortSignal.abort() }));
});

function sdkFor(pages, detail = id => ({ id })) {
  const seen = { lists: [], details: [] };
  const sdk = { users: { messages: {
    async list(params) { seen.lists.push(params); return { status: 200, data: pages[seen.lists.length - 1] }; },
    async get(params) { seen.details.push(params); return { status: 200, data: detail(params.id) }; },
  } } };
  return { sdk, seen };
}

test('two-page bounded metadata job; no message content in counts', async () => {
  const { sdk, seen } = sdkFor([{ messages: [{ id: 'msg_1' }], nextPageToken: 'next+page /=' },
    { messages: [{ id: 'msg-2' }], nextPageToken: 'third-page' }]);
  assert.deepEqual(await perform(sdk), { pages: 2, messages_read: 2, more_pages: true });
  assert.deepEqual(seen.lists, [{ userId: 'me', maxResults: 5, labelIds: ['INBOX'] },
    { userId: 'me', maxResults: 5, labelIds: ['INBOX'], pageToken: 'next+page /=' }]);
  assert.deepEqual(seen.details.map(row => row.metadataHeaders), [['From', 'Subject', 'Date'], ['From', 'Subject', 'Date']]);
  assert.ok(seen.details.every(row => row.format === 'metadata' && row.userId === 'me'));
  assert.deepEqual(await perform(sdkFor([{}]).sdk), { pages: 1, messages_read: 0, more_pages: false });
});

test('validate whole page before detail calls; reject invalid/duplicate IDs and pagination', async () => {
  for (const page of [
    { messages: [{ id: 'valid' }, { id: '../bad' }] }, { messages: [{ id: 'same' }, { id: 'same' }] },
    { messages: Array.from({ length: 6 }, (_, i) => ({ id: 'm' + i })) }, { messages: {} },
    { messages: [{ id: 'good' }], nextPageToken: 'bad\\page' },
    { nextPageToken: 'a'.repeat(4097) }, { nextPageToken: null }, { nextPageToken: '\u0080' }, [],
  ]) {
    const { sdk, seen } = sdkFor([page]);
    await assert.rejects(perform(sdk), { message: FAILURE });
    assert.equal(seen.details.length, 0);
  }
  await assert.rejects(perform(sdkFor([{ nextPageToken: 'same' }, { nextPageToken: 'same' }]).sdk));
  await assert.rejects(perform(sdkFor([{ messages: [{ id: 'm' }], nextPageToken: 'p' }, { messages: [{ id: 'm' }] }]).sdk));
  await assert.rejects(perform(sdkFor([{ messages: [{ id: 'm' }] }], () => ({ id: 'other' })).sdk));
});

test('CLI configuration failure prints only a fixed error, never input credentials', () => {
  const result = spawnSync(process.execPath, ['client.mjs'], { cwd: new URL('.', import.meta.url),
    env: { SERVERWARE_PROXY_TOKEN: 'DO_NOT_PRINT_SECRET' }, encoding: 'utf8', timeout: 5000 });
  assert.equal(result.status, 1);
  assert.equal(result.stdout, '');
  assert.equal(result.stderr, FAILURE + '\n');
});

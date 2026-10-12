// Actual generated SDK + Gaxios + Undici.request; only dispatch is intercepted.
// No provider, real proxy, credentials, or TLS acceptance claim.
import assert from 'node:assert/strict';
import test from 'node:test';
import net from 'node:net';
import dns from 'node:dns';
import { gmail, auth } from '@googleapis/gmail';
import { MockAgent, ProxyAgent, request } from 'undici';
import { configuration, createClient, perform } from './client.mjs';

const env = { SERVERWARE_PROXY_URL: 'https://proxy.example:443',
  SERVERWARE_APP_ID: '11111111-2222-4333-8444-555555555555',
  SERVERWARE_PROXY_TOKEN: Buffer.alloc(32, 7).toString('base64url'),
  SERVERWARE_CA_FILE: '/inner.pem', SERVERWARE_PROXY_CA_FILE: '/outer.pem' };
const readFile = path => Buffer.from('-----BEGIN CERTIFICATE-----\nsynthetic-' + path);
const LIST = '/gmail/v1/users/me/messages?maxResults=5&labelIds=INBOX';
const DETAIL = id => '/gmail/v1/users/me/messages/' + id + '?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date';

async function fixture(work) {
  const mock = new MockAgent();
  mock.disableNetConnect();
  const pool = mock.get('https://gmail.googleapis.com');
  const requests = [];
  const client = createClient(configuration(env), { gmail, auth, ProxyAgent, readFile,
    request: (url, options) => {
      // Only the network dispatcher is replaced; actual SDK serialization and
      // Undici.request are unchanged. The real proxy never opens a connection.
      requests.push({ url: String(url), options });
      return request(url, { ...options, dispatcher: mock });
    } });
  const originalConnect = net.Socket.prototype.connect;
  const originalLookup = dns.lookup;
  net.Socket.prototype.connect = () => { throw new Error('Unexpected socket'); };
  dns.lookup = () => { throw new Error('Unexpected DNS'); };
  try { await work({ client, pool, requests, mock }); }
  finally {
    net.Socket.prototype.connect = originalConnect;
    dns.lookup = originalLookup;
    await client.proxy.destroy();
    await mock.close();
  }
}

test('real SDK ordered queries, preserved headers, pagination and returned-ID metadata', async () => {
  await fixture(async ({ client, pool, requests, mock }) => {
    const replies = [
      [LIST, { messages: [{ id: 'msg_1' }], nextPageToken: 'next+page /=' }],
      [DETAIL('msg_1'), { id: 'msg_1', snippet: 'PRIVATE MAIL NOT OUTPUT' }],
      [LIST + '&pageToken=next%2Bpage%20%2F%3D', { messages: [{ id: 'msg-2' }] }],
      [DETAIL('msg-2'), { id: 'msg-2' }],
    ];
    for (const [path, body] of replies) pool.intercept({ method: 'GET', path }).reply(200, body,
      { headers: { 'content-type': 'application/json' } });
    assert.deepEqual(await perform(client.sdk), { pages: 2, messages_read: 2, more_pages: false });
    assert.deepEqual(requests.map(row => new URL(row.url).pathname + new URL(row.url).search), replies.map(row => row[0]));
    for (const { options } of requests) {
      assert.deepEqual(options.headers, {
        accept: 'application/json', 'accept-encoding': 'gzip', authorization: 'Bearer serverware-gmail-placeholder-v1',
        'user-agent': 'google-api-nodejs-client/9.2.0 (gzip)',
        'x-goog-api-client': 'gdcl/9.2.0 gl-node/' + process.versions.node,
      });
      assert.ok(!JSON.stringify(options.headers).includes(env.SERVERWARE_PROXY_TOKEN));
      assert.equal(options.maxRedirections, 0);
      assert.equal(options.dispatcher, client.proxy);
    }
    mock.assertNoPendingInterceptors();
  });
});

test('SDK 401/403/429/503 and redirect each stop after one dispatch; no OAuth refresh or retry', async () => {
  for (const status of [401, 403, 429, 503, 302]) await fixture(async ({ client, pool, requests }) => {
    pool.intercept({ path: LIST, method: 'GET' }).reply(status, { error: 'synthetic' },
      { headers: { 'content-type': 'application/json', location: 'https://other.example/' } });
    await assert.rejects(perform(client.sdk));
    assert.equal(requests.length, 1);
  });
});

test('SDK malformed JSON and wrong returned ID fail without more requests', async () => {
  await fixture(async ({ client, pool, requests }) => {
    pool.intercept({ path: LIST, method: 'GET' }).reply(200, 'not JSON', { headers: { 'content-type': 'application/json' } });
    await assert.rejects(perform(client.sdk));
    assert.equal(requests.length, 1);
  });
  await fixture(async ({ client, pool, requests }) => {
    pool.intercept({ path: LIST, method: 'GET' }).reply(200, { messages: [{ id: 'm' }] });
    pool.intercept({ path: DETAIL('m'), method: 'GET' }).reply(200, { id: 'other' });
    await assert.rejects(perform(client.sdk));
    assert.equal(requests.length, 2);
  });
});

test('ambient proxy and universe variables cannot redirect or bypass explicit dispatcher', async () => {
  const values = { HTTPS_PROXY: 'deliberately malformed unused proxy', NO_PROXY: '*',
    GOOGLE_CLOUD_UNIVERSE_DOMAIN: 'other.example' };
  const before = Object.fromEntries(Object.keys(values).map(name => [name, process.env[name]]));
  Object.assign(process.env, values);
  try {
    await fixture(async ({ client, pool, requests }) => {
      pool.intercept({ path: LIST, method: 'GET' }).reply(200, {});
      assert.deepEqual(await perform(client.sdk), { pages: 1, messages_read: 0, more_pages: false });
      assert.equal(requests.length, 1);
      assert.equal(new URL(requests[0].url).origin, 'https://gmail.googleapis.com');
      assert.equal(requests[0].options.dispatcher, client.proxy);
    });
  } finally {
    for (const [name, value] of Object.entries(before)) {
      if (value === undefined) delete process.env[name]; else process.env[name] = value;
    }
  }
});

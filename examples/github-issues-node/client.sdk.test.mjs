// Offline SDK serialization/pagination proof only: no GitHub, proxy, TLS or
// credential-release acceptance. Octokit is real; the fetch boundary supplies
// synthetic Responses and ProxyAgent is an explicitly inert configuration stub.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import net from 'node:net';
import dns from 'node:dns';
import test from 'node:test';
import { Octokit } from '@octokit/rest';
import { PUBLIC_GITHUB_DUMMY, configuration, createClient, failure, perform } from './client.mjs';

const BASE = 'https://api.github.com/repos/fixture-owner/fixture.repo/issues';
const FIRST = BASE + '?per_page=100';
const SECOND = BASE + '?per_page=100&page=2';
const ENV = Object.freeze({
  SERVERWARE_PROXY_URL: 'https://proxy.example.test:443',
  SERVERWARE_APP_ID: '11111111-2222-4333-8444-555555555555',
  SERVERWARE_PROXY_TOKEN: 'synthetic_proxy_identity_canary',
  SERVERWARE_CA_FILE: '/synthetic/inner.pem',
  SERVERWARE_GITHUB_OWNER: 'fixture-owner',
  SERVERWARE_GITHUB_REPO: 'fixture.repo',
});
const PEM = Buffer.from('-----BEGIN CERTIFICATE-----\nSYNTHETIC-NOT-A-REAL-CA\n-----END CERTIFICATE-----');
const TIMEOUT = { timeout: 5000 };

class InertProxyAgent {
  constructor(options) { this.options = options; this.closed = false; }
  async destroy() { this.closed = true; }
}

function fixture(t, operation, overrides, responder) {
  const forbidden = () => { throw new Error('offline SDK test forbids sockets and ambient fetch'); };
  t.mock.method(net.Socket.prototype, 'connect', forbidden);
  t.mock.method(dns, 'lookup', forbidden);
  t.mock.method(globalThis, 'fetch', forbidden);
  const config = configuration({ ...ENV, ...overrides }, operation);
  const calls = [];
  const client = createClient(config, {
    Octokit,
    ProxyAgent: InertProxyAgent,
    readFile(path) { assert.equal(path, ENV.SERVERWARE_CA_FILE); return PEM; },
    async fetch(url, options) {
      assert.ok(calls.length < 20, 'finite intercepted request budget');
      const call = { url, options };
      calls.push(call);
      return responder(call, calls.length);
    },
  });
  t.after(async () => { await client.proxy.destroy(); assert.equal(client.proxy.closed, true); });
  assert.ok(client.sdk instanceof Octokit);
  assert.deepEqual(client.proxy.options, {
    uri: ENV.SERVERWARE_PROXY_URL,
    token: 'Basic ' + Buffer.from(ENV.SERVERWARE_APP_ID + ':' + ENV.SERVERWARE_PROXY_TOKEN).toString('base64'),
    proxyTls: { rejectUnauthorized: true },
    requestTls: { ca: PEM, rejectUnauthorized: true },
    connections: 1,
  });
  return { ...client, config, calls };
}

function response(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status, headers: { 'content-type': 'application/json; charset=utf-8', ...headers },
  });
}

function assertRequest(call, client, { method = 'GET', url = FIRST, body } = {}) {
  assert.equal(call.url, url);
  assert.equal(call.options.method, method);
  assert.equal(call.options.body, body);
  assert.equal(call.options.dispatcher, client.proxy);
  assert.equal(call.options.redirect, 'error');
  assert.ok(call.options.signal instanceof AbortSignal);
  assert.equal(call.options.signal.aborted, false);
  const headers = call.options.headers;
  assert.deepEqual(Object.keys(headers).sort(),
    (method === 'GET' ? ['accept', 'authorization', 'user-agent']
      : ['accept', 'authorization', 'content-type', 'user-agent']).sort());
  assert.equal(headers.accept, 'application/vnd.github.v3+json');
  assert.equal(headers.authorization, 'token ' + PUBLIC_GITHUB_DUMMY);
  assert.match(headers['user-agent'], /^octokit-rest\.js\/22\.0\.1 octokit-core\.js\/[0-9.]+ Node\.js\//);
  if (method === 'POST') assert.equal(headers['content-type'], 'application/json; charset=utf-8');
  const inner = JSON.stringify({ url: call.url, headers, body: call.options.body });
  for (const privateValue of [ENV.SERVERWARE_APP_ID, ENV.SERVERWARE_PROXY_TOKEN,
    client.proxy.options.token, 'proxy-authorization', 'x-serverware-agent']) {
    assert.equal(inner.includes(privateValue), false, 'proxy identity must stay outside inner request');
  }
}

test('real pinned Octokit follows two stock pages with exact inner requests', TIMEOUT, async (t) => {
  const manifest = JSON.parse(readFileSync(new URL('./node_modules/@octokit/rest/package.json', import.meta.url)));
  const lock = JSON.parse(readFileSync(new URL('./package-lock.json', import.meta.url)));
  assert.equal(manifest.version, '22.0.1');
  assert.equal(lock.packages['node_modules/@octokit/rest'].version, '22.0.1');
  const client = fixture(t, 'list', {}, ({ url }, count) => {
    assert.equal(url, count === 1 ? FIRST : SECOND);
    assert.ok(count <= 2, 'pagination must stop when next link ends');
    return count === 1
      ? response([{ number: 11, title: 'First', body: 'not projected' }], 200,
        { link: '<' + SECOND + '>; rel="next", <' + SECOND + '>; rel="last"' })
      : response([{ number: 12, title: 'Second', body: 'also not projected' }]);
  });
  const result = await perform(client.config, client.sdk);
  assert.deepEqual(result, { operation: 'list', issueCount: 2,
    issues: [{ number: 11, title: 'First' }, { number: 12, title: 'Second' }] });
  assert.equal(client.calls.length, 2);
  assertRequest(client.calls[0], client);
  assertRequest(client.calls[1], client, { url: SECOND });
});

test('real SDK serializes each explicit issue/comment exactly once at intercepted fetch', TIMEOUT, async (t) => {
  for (const operation of ['create-issue', 'create-comment']) {
    await t.test(operation, async (sub) => {
      const title = 'Synthetic "issue"';
      const body = 'Synthetic snowman ☃\nSecond line';
      const client = fixture(sub, operation, {
        SERVERWARE_ISSUE_TITLE: title, SERVERWARE_ISSUE_BODY: body,
        SERVERWARE_ISSUE_NUMBER: '11', SERVERWARE_COMMENT_BODY: body,
      }, () => response(operation === 'create-issue' ? { number: 11 } : { id: 101 }, 201));
      const result = await perform(client.config, client.sdk);
      assert.equal(client.calls.length, 1);
      assertRequest(client.calls[0], client, { method: 'POST',
        url: operation === 'create-issue' ? BASE : BASE + '/11/comments',
        body: JSON.stringify(operation === 'create-issue' ? { title, body } : { body }) });
      assert.deepEqual(result, operation === 'create-issue'
        ? { operation, issueNumber: 11 } : { operation, issueNumber: 11, commentId: 101 });
    });
  }
});

test('real pagination cannot send a cross-origin or different-repository next page', TIMEOUT, async (t) => {
  for (const target of ['https://other.example/repos/fixture-owner/fixture.repo/issues?page=2',
    'https://api.github.com/repos/other/fixture.repo/issues?page=2',
    'https://api.github.com/repositories/123/issues?page=2']) {
    await t.test(target.includes('other.example') ? 'origin' : target.includes('/other/') ? 'repository' : 'numeric path', async (sub) => {
      const client = fixture(sub, 'list', {}, () => response([{ number: 11, title: 'First' }], 200,
        { link: '<' + target + '>; rel="next"' }));
      await assert.rejects(perform(client.config, client.sdk));
      assert.equal(client.calls.length, 1, 'invalid next page must not reach fetch');
      assertRequest(client.calls[0], client);
    });
  }
});

test('real SDK HTTP and transport errors are not retried and public failures stay fixed', TIMEOUT, async (t) => {
  for (const operation of ['list', 'create-issue', 'create-comment']) {
    for (const status of [403, 429, 503, null]) {
      await t.test(operation + ':' + (status ?? 'transport'), async (sub) => {
        const canary = 'synthetic-sdk-error-private-canary';
        const sentinel = new Error(canary);
        const client = fixture(sub, operation, {
          SERVERWARE_ISSUE_TITLE: 'Title', SERVERWARE_ISSUE_BODY: 'Body',
          SERVERWARE_ISSUE_NUMBER: '11', SERVERWARE_COMMENT_BODY: 'Comment',
        }, () => {
          if (status === null) throw sentinel;
          return response({ message: canary }, status, { 'retry-after': '1' });
        });
        let caught;
        await assert.rejects(perform(client.config, client.sdk), (error) => {
          caught = error;
          assert.equal(error.status, status ?? 500);
          if (status === null) assert.equal(error.cause, sentinel);
          return true;
        });
        assert.equal(client.calls.length, 1, 'SDK must not retry this operation');
        const result = failure(caught, operation);
        assert.equal(result.ok, false);
        assert.equal(result.httpStatus, status ?? 500);
        assert.deepEqual(Object.keys(result).sort(),
          (operation === 'list' ? ['ok', 'operation', 'httpStatus', 'error']
            : ['ok', 'operation', 'httpStatus', 'error', 'warning']).sort());
        if (operation !== 'list') assert.match(result.warning, /Inspect GitHub/);
        for (const privateValue of [canary, ENV.SERVERWARE_APP_ID, ENV.SERVERWARE_PROXY_TOKEN, PUBLIC_GITHUB_DUMMY]) {
          assert.equal(JSON.stringify(result).includes(privateValue), false);
        }
      });
    }
  }
});

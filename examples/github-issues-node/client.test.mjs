// No dependency installation, socket, provider or proxy is needed for these tests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { PUBLIC_GITHUB_DUMMY, configuration, createClient, failure, perform, proxyOptions } from './client.mjs';

const env = () => ({
  SERVERWARE_PROXY_URL: 'https://proxy.example.test:443',
  SERVERWARE_APP_ID: '11111111-2222-4333-8444-555555555555',
  SERVERWARE_PROXY_TOKEN: 'synthetic_app_token',
  SERVERWARE_CA_FILE: '/trusted/inner.pem',
  SERVERWARE_GITHUB_OWNER: 'example-owner',
  SERVERWARE_GITHUB_REPO: 'example.repo',
});
const pem = (label) => Buffer.from('-----BEGIN CERTIFICATE-----\n' + label + '\n-----END CERTIFICATE-----');

test('read-only default ignores ambient provider tokens and stale write content', () => {
  const config = configuration({ ...env(), GITHUB_TOKEN: 'never_use', GH_TOKEN: 'also_never_use',
    SERVERWARE_ISSUE_TITLE: 'stale', SERVERWARE_ISSUE_BODY: 'stale' });
  assert.equal(config.operation, 'list');
  assert.equal(config.body, undefined);
  assert.equal(JSON.stringify(config).includes('never_use'), false);
});

test('closed operations, exact repository and HTTPS identity validation', () => {
  for (const patch of [
    { SERVERWARE_PROXY_URL: 'http://proxy.example.test' },
    { SERVERWARE_PROXY_URL: 'https://user:password@proxy.example.test' },
    { SERVERWARE_PROXY_URL: 'https://proxy.example.test/path' },
    { SERVERWARE_PROXY_URL: 'https://proxy.example.test?query=1' },
    { SERVERWARE_APP_ID: '' }, { SERVERWARE_PROXY_TOKEN: 'bad\nvalue' },
    { SERVERWARE_GITHUB_OWNER: '../other' }, { SERVERWARE_GITHUB_REPO: '..' },
    { SERVERWARE_CA_FILE: '' }, { NODE_TLS_REJECT_UNAUTHORIZED: '0' },
  ]) assert.throws(() => configuration({ ...env(), ...patch }));
  assert.throws(() => configuration(env(), 'delete'));
});

test('explicit writes require bodies and appropriate identity before SDK creation', () => {
  assert.throws(() => configuration(env(), 'create-issue'));
  assert.throws(() => configuration({ ...env(), SERVERWARE_ISSUE_TITLE: 'Title' }, 'create-issue'));
  assert.throws(() => configuration({ ...env(), SERVERWARE_ISSUE_NUMBER: '1', SERVERWARE_COMMENT_BODY: '  ' }, 'create-comment'));
  assert.throws(() => configuration({ ...env(), SERVERWARE_ISSUE_NUMBER: '01', SERVERWARE_COMMENT_BODY: 'Body' }, 'create-comment'));
  assert.throws(() => configuration({ ...env(), SERVERWARE_ISSUE_TITLE: 'Title', SERVERWARE_ISSUE_BODY: 'x'.repeat(61441) }, 'create-issue'));
  assert.throws(() => configuration({ ...env(), SERVERWARE_ISSUE_TITLE: 'Title', SERVERWARE_ISSUE_BODY: '\t'.repeat(40000) + 'body' }, 'create-issue'));
});

test('proxy credentials and two CA trust domains stay separate', () => {
  const seen = [];
  const options = proxyOptions(configuration({ ...env(), SERVERWARE_PROXY_CA_FILE: '/trusted/outer.pem' }),
    (path) => { seen.push(path); return pem(path); });
  assert.equal(options.token, 'Basic ' + Buffer.from(env().SERVERWARE_APP_ID + ':synthetic_app_token').toString('base64'));
  assert.deepEqual(seen, ['/trusted/outer.pem', '/trusted/inner.pem']);
  assert.deepEqual(options.proxyTls, { ca: pem('/trusted/outer.pem'), rejectUnauthorized: true });
  assert.deepEqual(options.requestTls, { ca: pem('/trusted/inner.pem'), rejectUnauthorized: true });
  assert.deepEqual(proxyOptions(configuration(env()), () => pem('inner')).proxyTls, { rejectUnauthorized: true });
  assert.throws(() => proxyOptions(configuration(env()), () => Buffer.from('not a certificate')));
});

test('SDK uses only public dummy and unchanged requests through explicit dispatcher', async () => {
  let sdkOptions;
  class ProxyAgent { constructor(options) { this.options = options; } destroy() {} }
  class Octokit { constructor(options) { sdkOptions = options; } }
  const sent = [];
  const response = { status: 200 };
  const { proxy } = createClient(configuration(env()), { Octokit, ProxyAgent,
    fetch: async (url, options) => { sent.push({ url, options }); return response; }, readFile: () => pem('inner') });
  assert.equal(sdkOptions.auth, PUBLIC_GITHUB_DUMMY);
  const url = 'https://api.github.com/repos/example-owner/example.repo/issues?per_page=100&page=2';
  const headers = { authorization: 'token ' + PUBLIC_GITHUB_DUMMY };
  assert.equal(await sdkOptions.request.fetch(url, { method: 'GET', headers }), response);
  assert.equal(sent[0].url, url);
  assert.equal(sent[0].options.headers, headers);
  assert.equal(sent[0].options.dispatcher, proxy);
  assert.equal(sent[0].options.redirect, 'error');
  for (const bad of ['https://other.example/repos/example-owner/example.repo/issues',
    'https://api.github.com/repos/other/example.repo/issues',
    'https://api.github.com/repositories/123/issues',
    'http://api.github.com/repos/example-owner/example.repo/issues']) {
    assert.throws(() => sdkOptions.request.fetch(bad, { method: 'GET' }));
  }
  assert.equal(sent.length, 1);
  for (let index = 1; index < 20; index++) await sdkOptions.request.fetch(url, { method: 'GET' });
  assert.throws(() => sdkOptions.request.fetch(url, { method: 'GET' }));
  assert.equal(sent.length, 20);
});

test('stock pagination helper receives exact repository, with no writes', async () => {
  const listForRepo = () => assert.fail('pagination helper owns individual requests');
  const result = await perform(configuration(env()), {
    rest: { issues: { listForRepo, create: () => assert.fail('write'), createComment: () => assert.fail('write') } },
    paginate: async (method, options) => {
      assert.equal(method, listForRepo);
      assert.deepEqual(options, { owner: 'example-owner', repo: 'example.repo', per_page: 100 });
      return [{ number: 1, title: 'First', body: 'not printed' }, { number: 2, title: 'Second' }];
    },
  });
  assert.deepEqual(result, { operation: 'list', issueCount: 2,
    issues: [{ number: 1, title: 'First' }, { number: 2, title: 'Second' }] });
});

test('each explicit creation makes exactly one ordinary SDK call', async () => {
  const calls = [];
  const sdk = { rest: { issues: {
    create: async (payload) => { calls.push(payload); return { status: 201, data: { number: 7 } }; },
    createComment: async (payload) => { calls.push(payload); return { status: 201, data: { id: 8 } }; },
  } } };
  await perform(configuration({ ...env(), SERVERWARE_ISSUE_TITLE: 'Explicit title', SERVERWARE_ISSUE_BODY: 'Explicit body' }, 'create-issue'), sdk);
  await perform(configuration({ ...env(), SERVERWARE_ISSUE_NUMBER: '7', SERVERWARE_COMMENT_BODY: 'Explicit comment' }, 'create-comment'), sdk);
  assert.deepEqual(calls, [
    { owner: 'example-owner', repo: 'example.repo', title: 'Explicit title', body: 'Explicit body' },
    { owner: 'example-owner', repo: 'example.repo', issue_number: 7, body: 'Explicit comment' },
  ]);
});

test('uncertain write has no retry and fixed diagnostics cannot reflect SDK secrets', async () => {
  let calls = 0;
  const error = Object.assign(new Error('secret_canary'), { status: 503, request: { token: 'secret_canary' } });
  const config = configuration({ ...env(), SERVERWARE_ISSUE_TITLE: 'Title', SERVERWARE_ISSUE_BODY: 'Body' }, 'create-issue');
  await assert.rejects(perform(config, { rest: { issues: { create: async () => { calls++; throw error; } } } }));
  assert.equal(calls, 1);
  const result = failure(error, config.operation);
  assert.equal(result.httpStatus, 503);
  assert.match(result.warning, /Inspect GitHub/);
  assert.equal(JSON.stringify(result).includes('secret_canary'), false);
});

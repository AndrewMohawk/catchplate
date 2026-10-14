// No dependency installation, socket, provider or proxy is needed for these tests.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { PUBLIC_GITHUB_DUMMY, configuration, createClient, failure, loadClientConfig, parseArguments, perform, proxyOptions } from './client.mjs';

const env = () => ({
  SERVERWARE_PROXY_URL: 'https://proxy.example.test:443',
  SERVERWARE_APP_ID: '11111111-2222-4333-8444-555555555555',
  SERVERWARE_PROXY_TOKEN: 'synthetic_app_token',
  SERVERWARE_CA_FILE: '/trusted/inner.pem',
  SERVERWARE_GITHUB_OWNER: 'example-owner',
  SERVERWARE_GITHUB_REPO: 'example.repo',
});
const pem = (label) => Buffer.from('-----BEGIN CERTIFICATE-----\n' + label + '\n-----END CERTIFICATE-----');
const NOW = 1_791_996_000_000;
const downloaded = () => ({
  application_id: env().SERVERWARE_APP_ID,
  access_rule_id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee',
  proxy_url: env().SERVERWARE_PROXY_URL,
  proxy_authentication: 'basic_and_bearer_v1',
  proxy_username: env().SERVERWARE_APP_ID,
  proxy_password: 'downloaded_synthetic_token',
  token_expires_at_epoch_ms: NOW + 60_000,
  ca_file: './serverware-ca.pem',
  repository: { owner: 'downloaded-owner', name: 'downloaded.repo' },
  upstream_url: 'https://api.github.com/repos/downloaded-owner/downloaded.repo/issues',
  operation_bundle: 'github_issues_read_v1', methods: ['GET'],
  client_recipe: { proxy_ca_file: null },
});
function configFile(t) {
  const directory = mkdtempSync(join(tmpdir(), 'serverware-github-config-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  const path = join(directory, 'serverware-client.private.json');
  return { directory, path, write(value) { writeFileSync(path, JSON.stringify(value), { mode: 0o600 }); return path; } };
}

test('downloaded console config overrides ambient connection scope and resolves CA paths', (t) => {
  const fixture = configFile(t), value = downloaded();
  value.client_recipe.environment = { SERVERWARE_PROXY_TOKEN: 'never-import', SERVERWARE_ISSUE_BODY: 'never-import' };
  value.client_recipe.entrypoint = 'never-execute';
  value.request_headers = { Authorization: 'never-import' };
  const ambient = { ...env(), SERVERWARE_PROXY_CA_FILE: '/stale/outer.pem', GITHUB_TOKEN: 'never-import' };
  const config = loadClientConfig(fixture.write(value), ambient, undefined, NOW);
  assert.deepEqual(config, { operation: 'list', proxyUrl: value.proxy_url,
    applicationId: value.application_id, token: value.proxy_password,
    owner: value.repository.owner, repo: value.repository.name,
    caFile: join(fixture.directory, 'serverware-ca.pem'), proxyCaFile: null });
  assert.equal(ambient.SERVERWARE_PROXY_CA_FILE, '/stale/outer.pem');
  value.client_recipe.proxy_ca_file = './outer.pem';
  assert.equal(loadClientConfig(fixture.write(value), ambient, 'list', NOW).proxyCaFile, join(fixture.directory, 'outer.pem'));
  delete value.client_recipe;
  assert.equal(loadClientConfig(fixture.write(value), ambient, 'list', NOW).proxyCaFile, null);
});

test('config CLI defaults to reads; writes remain explicit and local-content only', (t) => {
  const fixture = configFile(t), value = downloaded();
  const local = { SERVERWARE_ISSUE_TITLE: 'Local title', SERVERWARE_ISSUE_BODY: 'Local body' };
  assert.throws(() => loadClientConfig(fixture.write(value), local, 'create-issue', NOW));
  value.operation_bundle = 'github_issues_write_v1'; value.methods = ['GET', 'POST'];
  value.operation = 'create-issue'; value.environment = local; value.body = 'Never imported';
  assert.equal(loadClientConfig(fixture.write(value), {}, undefined, NOW).operation, 'list');
  assert.throws(() => loadClientConfig(fixture.path, {}, 'create-issue', NOW));
  assert.equal(loadClientConfig(fixture.path, local, 'create-issue', NOW).body, 'Local body');
  assert.deepEqual(parseArguments([]), { help: false, operation: 'list', configPath: null });
  assert.deepEqual(parseArguments(['--config', fixture.path]), { help: false, operation: 'list', configPath: fixture.path });
  assert.deepEqual(parseArguments(['--config', fixture.path, 'list']), { help: false, operation: 'list', configPath: fixture.path });
  assert.equal(parseArguments(['create-comment', '--config', fixture.path]).operation, 'create-comment');
  assert.equal(parseArguments(['create-issue']).operation, 'create-issue');
  assert.equal(parseArguments(['--help']).help, true);
  for (const args of [['--config'], ['--config', ''], ['--config', '--help'], ['--config', 'one', '--config', 'two'],
    ['list', 'create-issue'], ['--help', 'list'], ['--unknown'], ['delete']]) assert.throws(() => parseArguments(args));
});

test('downloaded config refuses expired tokens and mismatched identity, scope or bundle', (t) => {
  const fixture = configFile(t);
  const invalid = [
    { application_id: 'invalid' }, { access_rule_id: 'invalid' }, { proxy_username: 'different' },
    { proxy_authentication: 'bearer' }, { proxy_password: 'bad token' },
    { proxy_url: 'http://proxy.example.test' }, { ca_file: '' },
    { token_expires_at_epoch_ms: NOW }, { token_expires_at_epoch_ms: Number.MAX_SAFE_INTEGER + 1 },
    { token_expires_at_epoch_ms: String(NOW + 60_000) },
    { operation_bundle: 'github_issues_other_v1' }, { methods: ['GET', 'POST'] }, { methods: ['POST'] },
    { methods: ['GET', 'GET'] }, { methods: 'GET' },
    { upstream_url: 'https://api.github.com/repos/other/downloaded.repo/issues' },
    { upstream_url: 'https://api.github.com/repos/downloaded-owner/downloaded.repo/issues?query=1' },
    { repository: { owner: '../other', name: 'downloaded.repo' } }, { repository: null },
    { client_recipe: { proxy_ca_file: '' } }, { client_recipe: [] },
  ];
  for (const changes of invalid) assert.throws(() => loadClientConfig(fixture.write({ ...downloaded(), ...changes }), env(), 'list', NOW));
  fixture.write(downloaded());
  assert.throws(() => loadClientConfig(fixture.path, { ...env(), NODE_TLS_REJECT_UNAUTHORIZED: '0' }, 'list', NOW));
  assert.throws(() => loadClientConfig(fixture.path, env(), 'list', NaN));
});

test('config input is bounded regular JSON and errors never include private bytes or paths', (t) => {
  const fixture = configFile(t), json = JSON.stringify(downloaded());
  writeFileSync(fixture.path, json.padEnd(64 * 1024, ' '));
  assert.equal(loadClientConfig(fixture.path, {}, 'list', NOW).operation, 'list');
  for (const raw of [json.padEnd(64 * 1024 + 1, ' '), '{"private":"secret-canary"', 'null', '[]']) {
    writeFileSync(fixture.path, raw);
    assert.throws(() => loadClientConfig(fixture.path, {}, 'list', NOW), { message: 'Example configuration or operation refused' });
  }
  assert.throws(() => loadClientConfig(fixture.directory, {}, 'list', NOW), { message: 'Example configuration or operation refused' });
  fixture.write(downloaded());
  const link = join(fixture.directory, 'private-link.json'); symlinkSync(fixture.path, link);
  assert.throws(() => loadClientConfig(link, {}, 'list', NOW), { message: 'Example configuration or operation refused' });
});

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

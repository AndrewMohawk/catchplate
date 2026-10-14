#!/usr/bin/env node
'use strict';
// Pure state-machine controls plus rendered, deny-all synthetic HTTP fixtures.
// The separate guided checker proves the same lost-ACK flow against the real
// backend. This file never contacts a deployment, provider, proxy or CA.
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const {fixture, ready, view, credential, application, rule, IDS} = require('./test_operator_catalog_browser.cjs');
const {context: catalogContext, rawCatalog} = require('./test_operator_npm_ui.cjs');
const {MUTATION_REVIEW_KEY: KEY, MUTATION_REVIEW_VALUE: VALUE, acknowledgeMutationReview,
  withoutMutationReview} = require('./operator_mutation_recovery_test_helpers.cjs');
const CORE = readFileSync(resolve(__dirname, '../serverware/operator_demo_web/workspace_core.js'), 'utf8');
const ORIGIN = 'https://operator-catalog.example.test';
const CATALOG = '/api/operator-demo/catalog', CREATE = '/api/operator-demo/credentials';
const SECRET = 'synthetic-recovery-secret-NEVER-PERSIST';
const hash = 'sha256:' + 'a'.repeat(64);
const clone = value => JSON.parse(JSON.stringify(value));
const response = (value, status = 200) => ({ok: status >= 200 && status < 300, status,
  headers: {get: () => 'application/json'}, json: async () => clone(value)});
const catalog = () => ({revision: 1, policy: {policy_hash: hash, loaded_policy_hash: hash, sequence: 1, activation: 'active'},
  credentials: [credential()], applications: [application()], access_rules: []});
function deferred() { let resolve; const promise = new Promise(done => { resolve = done; }); return {promise, resolve}; }
function inert({storage = new Map(), fault = null, realCatalog = false} = {}) {
  const nodes = new Map(), events = new Map(), calls = [], writes = [];
  const node = id => {
    if (!nodes.has(id)) nodes.set(id, {hidden: true, disabled: true, textContent: '', events: {},
      addEventListener(name, callback) { this.events[name] = callback; }, querySelectorAll: () => []});
    return nodes.get(id);
  };
  const ctx = realCatalog ? catalogContext().value : vm.createContext({});
  Object.assign(ctx, {AbortSignal, URL, Set, Map, JSON, Number, Object, Array, Error,
    document: {getElementById: node},
    clearTimeout() {}, setTimeout: () => 1, window: {addEventListener(name, callback) { events.set(name, callback); }},
    sessionStorage: {getItem(key) { if (fault === 'get') throw new Error('synthetic storage read refusal'); return storage.get(key) ?? null; },
      setItem(key, value) { writes.push(['set', key, value]); if (fault === 'set') throw new Error('synthetic storage write refusal');
        if (fault !== 'silent-set') storage.set(key, value); },
      removeItem(key) { writes.push(['remove', key]); if (fault === 'remove') throw new Error('synthetic storage removal refusal');
        if (fault !== 'silent-remove') storage.delete(key); }},
    fetch: async (path, options) => { calls.push({path, options}); return ctx.respond(path, options); }});
  if (!realCatalog) vm.runInContext(CORE + '\nprojectCatalog = value => value;', ctx, {timeout: 1000});
  ctx.respond = () => response(catalog());
  const workspace = vm.runInContext('createOperatorWorkspace()', ctx);
  return {workspace, ctx, node, events, storage, writes, calls, click: () => node('mutation-review-confirm').events.click()};
}
const pure = [];
function test(name, run) { pure.push([name, run]); }
test('warning is fixed, retained before dispatch, and removed after confirmed response plus catalog', async () => {
  const f = inert(); await f.workspace.refresh();
  f.ctx.respond = (path, options) => {
    if (options.method === 'POST') {
      assert.equal(f.storage.get(KEY), VALUE); assert.equal(JSON.parse(options.body).secret, SECRET);
      return response({accepted: true});
    }
    return response(catalog());
  };
  const body = {secret: SECRET}; let accepted = 0;
  assert.equal(await f.workspace.mutate('credentials', body, 'status', () => accepted++), true);
  assert.equal(accepted, 1); assert.equal(body.secret, ''); assert.equal(f.storage.size, 0);
  assert.deepEqual(f.writes, [['set', KEY, VALUE], ['remove', KEY]]);
});
test('lost reply survives a new workspace and needs a fresh catalog plus explicit acknowledgement', async () => {
  const f = inert(); await f.workspace.refresh();
  f.ctx.respond = (path, options) => options.method === 'POST' ? Promise.reject(new Error('lost reply')) : response(catalog());
  assert.equal(await f.workspace.mutate('credentials', {secret: SECRET}, 'status', () => assert.fail('no reply')), false);
  const next = inert({storage: f.storage}); assert(next.workspace.state.uncertain); assert(next.node('mutation-review-confirm').disabled);
  next.click(); assert.equal(next.storage.get(KEY), VALUE);
  await next.workspace.refresh(); assert.equal(next.workspace.state.uncertain, true); assert.equal(next.node('mutation-review-confirm').disabled, false);
  next.click(); assert.equal(next.workspace.state.uncertain, false); assert.equal(next.storage.size, 0);
  assert.equal(next.calls.length, 1); assert(next.calls.every(item => !item.options.method));
});
for (const fault of ['get', 'set', 'silent-set']) test(fault + ' persistence failure refuses POST and private callback', async () => {
  const f = inert({fault}); await f.workspace.refresh();
  const body = {secret: SECRET};
  assert.equal(await f.workspace.mutate('credentials', body, 'status', () => assert.fail('no private reply')), false);
  assert(f.workspace.state.uncertain); assert(f.node('mutation-review-confirm').disabled);
  assert(f.calls.every(item => !item.options.method)); assert(!JSON.stringify([...f.storage]).includes(SECRET));
  if (fault !== 'get') assert.equal(body.secret, '');
});
for (const fault of ['remove', 'silent-remove']) test(fault + ' cleanup failure retains a blocked warning', async () => {
  const f = inert({fault, storage: new Map([[KEY, VALUE]])}); await f.workspace.refresh(); f.click();
  assert(f.workspace.state.uncertain); assert(f.node('mutation-review-confirm').disabled); assert.equal(f.storage.get(KEY), VALUE);
});
test('malformed or externally changed marker is not overwritten, interpreted or cleared', async () => {
  const f = inert({storage: new Map([[KEY, 'unrecognized']])}); await f.workspace.refresh(); f.click();
  assert(f.workspace.state.uncertain); assert(f.node('mutation-review-confirm').disabled); assert.equal(f.writes.length, 0);
  assert(!f.node('mutation-review-text').textContent.includes('unrecognized'));
  const changed = inert(); await changed.workspace.refresh(); changed.storage.set(KEY, 'changed');
  await changed.workspace.mutate('credentials', {}, 'status', () => {});
  assert(changed.workspace.state.uncertain); assert(changed.calls.every(item => !item.options.method)); assert.equal(changed.storage.get(KEY), 'changed');
});
test('provider reference and independent consent hold cannot be cleared by generic acknowledgement', async () => {
  const provider = 'serverware.operator.google.configuration.operation.v2';
  const f = inert({storage: new Map([[provider, 'public-provider-reference']])}); await f.workspace.refresh();
  f.workspace.setConsentHold(true, 'provider-owner'); f.workspace.requireReview('Provider result requires review');
  await f.workspace.refresh(); f.click();
  assert(f.workspace.state.uncertain); assert(f.workspace.state.consentHold); assert(f.node('mutation-review-confirm').disabled);
  assert.equal(f.storage.get(provider), 'public-provider-reference'); assert.equal(f.storage.get(KEY), VALUE);
  f.workspace.setConsentHold(false, 'provider-owner'); f.click();
  assert.equal(f.workspace.state.uncertain, false); assert.equal(f.storage.get(KEY), undefined);
  assert.equal(f.storage.get(provider), 'public-provider-reference');
});
test('post-response ordinary review survives reload and needs a newer catalog than the earlier success', async () => {
  const f = inert(); await f.workspace.refresh();
  await f.workspace.mutate('credentials', {}, 'status', () => {});
  f.workspace.requireReview('Caller could not confirm the exact refreshed resource');
  assert(f.node('mutation-review-confirm').disabled); f.click(); assert(f.workspace.state.uncertain);
  const next = inert({storage: f.storage}); await next.workspace.refresh(); next.click();
  assert.equal(next.workspace.state.uncertain, false);
});
test('acknowledged save with failed catalog refresh retains review instead of implying rollback', async () => {
  const f = inert(); await f.workspace.refresh();
  f.ctx.respond = (path, options) => response({}, options.method === 'POST' ? 200 : 503);
  await f.workspace.mutate('credentials', {}, 'status', () => {});
  assert(f.workspace.state.uncertain); assert(f.node('mutation-review-confirm').disabled); assert.equal(f.storage.get(KEY), VALUE);
});
for (const event of ['pagehide', 'authenticationLost']) test(event + ' invalidates late mutation callbacks and retains review', async () => {
  const f = inert(); await f.workspace.refresh(); const reply = deferred(); let callbacks = 0;
  f.ctx.respond = (path, options) => options.method === 'POST' ? reply.promise : response(catalog());
  const pending = f.workspace.mutate('applications', {}, 'status', () => callbacks++);
  if (event === 'pagehide') f.events.get('pagehide')(); else f.workspace.authenticationLost();
  reply.resolve(response({client_token: 'synthetic-private-one-time-token'})); await pending;
  assert.equal(callbacks, 0); assert(f.workspace.state.uncertain); assert.equal(f.storage.get(KEY), VALUE);
  assert(!JSON.stringify([...f.storage]).includes('synthetic-private'));
});
for (const realCatalog of [false, true]) test((realCatalog ? 'real catalog projection with backend-shaped metadata' : 'minimal catalog state machine') +
  ': all four default paths reject empty success and mismatched catalog, accept exact receipt/current-resource joins', async () => {
  for (const path of ['credentials/revoke', 'applications/revoke', 'access-rules', 'access-rules/revoke'])
    for (const mode of ['empty', 'mismatch', 'valid']) {
    const before = realCatalog ? rawCatalog({credentials: [credential({version: 1, credential_generation: 1})],
      rules: [], capability: null, allowed: ['https://api.example.test']}) : catalog();
    const creating = path === 'access-rules';
    if (realCatalog) Object.assign(before.applications[0], {version: 2, client_renewal: null,
      token_rotated_at: '2026-10-08T11:30:00Z'});
    const savedRule = () => rule({...realCatalog && {version: 1}, credential_input: 'insert'});
    if (path === 'applications/revoke' || path === 'access-rules/revoke') before.access_rules = [savedRule()];
    const after = clone(before); after.revision++;
    const collection = path.startsWith('credentials') ? 'credentials' : path.startsWith('applications') ? 'applications' : 'access_rules';
    const key = {credentials: 'credential', applications: 'application', access_rules: 'access_rule'}[collection];
    if (creating) after.access_rules = [savedRule()]; else {
      after[collection][0].status = 'revoked';
      if (realCatalog) { after[collection][0].version++; after[collection][0].revoked_at = '2026-10-08T12:00:00Z'; }
    }
    if (realCatalog && path === 'credentials/revoke') after.credentials[0].credential_generation = null;
    if (path === 'applications/revoke') {
      after.access_rules[0].status = 'revoked';
      after.applications[0].token_status = 'revoked';
    }
    if (collection !== 'credentials') {
      after.policy.policy_hash = 'sha256:' + 'b'.repeat(64); after.policy.loaded_policy_hash = after.policy.policy_hash; after.policy.sequence++;
    }
    const body = creating ? Object.fromEntries(Object.entries(savedRule()).filter(([name]) =>
      !['id', 'status', 'route_id', 'enforcement', 'created_at', 'version'].includes(name))) : {id: before[collection][0].id};
    const result = {[key]: clone(after[collection][0]), revision: after.revision, policy: clone(after.policy)};
    if (path === 'applications/revoke') result.affected_rule_ids = [IDS.rule];
    const f = inert({realCatalog}); f.ctx.respond = () => response(before); assert.equal(await f.workspace.refresh(), true);
    if (realCatalog) assert.equal(Object.hasOwn(f.workspace.state.catalog[collection][0] || {}, 'version'), false,
      'the actual public projection, not an identity stub, omits backend record versions');
    f.ctx.respond = (requestPath, options) => response(options.method === 'POST' ? mode === 'empty' ? {} : result : mode === 'mismatch' ? before : after);
    const accepted = await f.workspace.mutate(path, body, 'status');
    assert.equal(accepted, mode === 'valid'); assert.equal(f.workspace.state.uncertain, mode !== 'valid');
    assert.equal(f.storage.has(KEY), mode !== 'valid'); assert.equal(f.calls.filter(item => item.options.method === 'POST').length, 1);
  }
});
test('real catalog projection accepts revoked AWS session crossing expiry without losing exact expiry binding', async () => {
  const before = rawCatalog({credentials: [credential({version: 1, auth_type: 'aws_sigv4_v1', header_name: null,
    connection_type: 'aws_sigv4_v1', provider_id: 'aws', credential_kind: 'session', expires_at: '2026-10-08T12:00:01Z',
    expired: false, signing_available: false, credential_generation: 1})], rules: [], capability: null});
  const after = clone(before); after.revision++; Object.assign(after.credentials[0], {
    version: 2, status: 'revoked', revoked_at: '2026-10-08T12:00:00Z', credential_generation: null, expired: true});
  for (const differentExpiry of [false, true]) {
    const f = inert({realCatalog: true}); f.ctx.respond = () => response(before); assert.equal(await f.workspace.refresh(), true);
    const result = {credential: {...after.credentials[0], expired: false}, revision: after.revision, policy: clone(after.policy)};
    if (differentExpiry) result.credential.expires_at = '2026-10-08T12:00:02Z';
    f.ctx.respond = (path, options) => response(options.method === 'POST' ? result : after);
    assert.equal(await f.workspace.mutate('credentials/revoke', {id: IDS.credential}, 'status'), !differentExpiry);
    assert.equal(f.workspace.state.uncertain, differentExpiry);
    assert.equal(f.storage.has(KEY), differentExpiry);
  }
});

async function marker(page) { return page.evaluate(key => sessionStorage.getItem(key), KEY); }
async function privacy(page) {
  const storage = await page.evaluate(() => ({local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  assert.deepEqual(storage.local, []); assert.deepEqual(withoutMutationReview(storage.session), []);
  assert(!JSON.stringify(storage).includes(SECRET));
}
async function credentialForm(page) {
  await ready(page); await view(page, 'credentials'); await page.locator('#credential-add').click();
  await page.locator('#connect-use-key').click(); await page.locator('#connect-credential-name').fill('Recovery test key');
  await page.locator('#connect-credential-secret').fill(SECRET);
}
async function held(page) {
  await page.locator('#mutation-review').waitFor({state: 'visible'});
  assert.equal(await marker(page), VALUE);
  for (const id of ['credential-fields', 'application-fields', 'access-rule-fields'])
    assert(await page.locator('#' + id).evaluate(node => node.disabled), id + ' must remain blocked');
  await privacy(page);
}
const browserTests = [
  ['lost committed credential reply survives reload; acknowledgement does not duplicate it', browser => fixture(browser,
    {fault: 'lost-after-commit'}, async (page, state, {context}) => {
      await context.route(ORIGIN + CREATE, async route => { assert.equal(await marker(page), VALUE); await route.fallback(); });
      await credentialForm(page); await page.locator('#connect-credential-next').click(); await held(page);
      assert.equal(state.credentials.length, 1); assert.equal(state.posts.length, 1);
      state.catalogStatus = 503; await page.reload({waitUntil: 'networkidle'}); await held(page);
      assert(await page.locator('#mutation-review-confirm').isDisabled());
      await page.locator('#mutation-review-confirm').dispatchEvent('click'); assert.equal(await marker(page), VALUE);
      state.catalogStatus = 200; await view(page, 'credentials'); await page.locator('#credentials-refresh').click();
      await page.waitForFunction(() => !document.getElementById('mutation-review-confirm').disabled); await held(page);
      await acknowledgeMutationReview(page); await ready(page); await privacy(page);
      assert.equal(state.posts.length, 1); assert.equal(state.credentials.length, 1);
      await page.reload({waitUntil: 'networkidle'}); await ready(page); assert.equal(await marker(page), null);
    })],
  ['full reload while a committed response is held never dispatches a replacement write', browser => fixture(browser,
    {}, async (page, state, {context}) => {
      const arrived = deferred(), release = deferred();
      await context.route(ORIGIN + CREATE, async route => {
        assert.equal(await marker(page), VALUE); const body = route.request().postDataJSON();
        assert.equal(body.secret, SECRET); assert.equal(body.expected_revision, state.revision);
        state.posts.push({name: 'credentials', body}); state.credentials.push(credential({name: body.name})); state.revision++;
        state.expectedFailures.add(CREATE); arrived.resolve(); await release.promise;
        await route.abort('failed').catch(() => {}); // Reload may have already cancelled this exact intercepted request.
      });
      await credentialForm(page); await page.locator('#connect-credential-next').click(); await arrived.promise;
      await page.reload({waitUntil: 'domcontentloaded'}); release.resolve(); await page.waitForLoadState('networkidle');
      await held(page); await acknowledgeMutationReview(page); await ready(page);
      assert.equal(state.posts.length, 1); assert.equal(state.credentials.length, 1); await privacy(page);
    })],
  ...['set', 'silent-set'].map(fault => [fault + ' storage failure blocks rendered save before any POST', browser => fixture(browser,
    {}, async (page, state) => {
      await credentialForm(page);
      await page.evaluate(([key, fault]) => {
        const original = Storage.prototype.setItem;
        Storage.prototype.setItem = function(name, value) {
          if (this === sessionStorage && name === key) { if (fault === 'set') throw new Error('synthetic refusal'); return; }
          return original.call(this, name, value);
        };
      }, [KEY, fault]);
      await page.locator('#connect-credential-next').click(); await page.locator('#mutation-review').waitFor({state: 'visible'});
      assert(await page.locator('#mutation-review-confirm').isDisabled()); assert.equal(state.posts.length, 0);
      assert.equal(await page.locator('#connect-credential-secret').inputValue(), ''); await privacy(page);
    })]),
  ['late successful client creation after pagehide never restores its one-time token', browser => fixture(browser,
    {}, async (page, state, {context}) => {
      const arrived = deferred(), release = deferred();
      await context.route(ORIGIN + '/api/operator-demo/applications', async route => {
        assert.equal(await marker(page), VALUE); arrived.resolve(); await release.promise; await route.fallback();
      });
      await ready(page); await view(page, 'applications'); await page.locator('#application-name').fill('Recovery client');
      await page.locator('#application-create').click(); await arrived.promise;
      await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pagehide', {persisted: true})));
      release.resolve(); await page.waitForFunction(() => !document.getElementById('mutation-review-confirm').disabled);
      await held(page); assert.equal(await page.locator('#client-token').inputValue(), '');
      assert(await page.locator('#one-time-access').isHidden()); assert.equal(state.posts.length, 1); assert.equal(state.applications.length, 1);
      await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true})));
      await held(page); assert.equal(await page.locator('#client-token').inputValue(), '');
    })],
  ['normal completed save removes warning and reload needs no recovery', browser => fixture(browser,
    {}, async (page, state) => {
      await credentialForm(page); await page.locator('#connect-credential-next').click(); await ready(page);
      assert.equal(await marker(page), null); await page.reload({waitUntil: 'networkidle'}); await ready(page);
      assert(await page.locator('#mutation-review').isHidden()); assert.equal(state.posts.length, 1); await privacy(page);
    })],
];
async function main() {
  const args = process.argv.slice(2); assert(args.length === 0 || args.length === 1 && args[0] === '--self-test');
  for (const [name, run] of pure) { await run(); console.log('PASS ' + name); }
  if (args[0] === '--self-test') { console.log(JSON.stringify({ok: true, groups: pure.length, browser: false,
    network: false, scope: 'pure ordinary mutation recovery and exact receipt controls'})); return; }
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  let deadline;
  try {
    await Promise.race([(async () => { for (const [name, run] of browserTests) { await run(browser); console.log('PASS ' + name); } })(),
      new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('mutation recovery fixture deadline')), 90000); })]);
    console.log(JSON.stringify({ok: true, pureGroups: pure.length, browserGroups: browserTests.length,
      scope: 'pure state-machine and intercepted synthetic browser fixtures', liveRequests: 0, realBackendVerified: false}));
  } finally { clearTimeout(deadline); await browser.close(); }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });
module.exports = {main};

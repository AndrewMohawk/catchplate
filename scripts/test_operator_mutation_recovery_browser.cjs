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
const CORE = readFileSync(resolve(__dirname, '../catchplate/operator_demo_web/workspace_core.js'), 'utf8');
const APPLICATIONS = readFileSync(resolve(__dirname, '../catchplate/operator_demo_web/workspace_applications.js'), 'utf8');
const HTML = readFileSync(resolve(__dirname, '../catchplate/operator_demo_web/index.html'), 'utf8');
const APP = readFileSync(resolve(__dirname, '../catchplate/operator_demo_web/app.js'), 'utf8');
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
function inert({storage = new Map(), fault = null, realCatalog = false, migrate = false} = {}) {
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
    sessionStorage: {get length() { return storage.size; }, key(index) { return [...storage.keys()][index] ?? null; },
      getItem(key) { if (fault === 'get') throw new Error('synthetic storage read refusal'); return storage.get(key) ?? null; },
      setItem(key, value) { writes.push(['set', key, value]); if (fault === 'set') throw new Error('synthetic storage write refusal');
        if (fault !== 'silent-set') storage.set(key, value); },
      removeItem(key) { writes.push(['remove', key]); if (fault === 'remove') throw new Error('synthetic storage removal refusal');
        if (fault !== 'silent-remove') storage.delete(key); }},
    fetch: async (path, options) => { calls.push({path, options}); return ctx.respond(path, options); }});
  if (!realCatalog) vm.runInContext(CORE + '\nprojectCatalog = value => value;', ctx, {timeout: 1000});
  ctx.respond = () => response(catalog());
  const workspace = vm.runInContext(migrate ? 'createOperatorWorkspace(migrateLegacyOperatorBrowserState())' : 'createOperatorWorkspace()', ctx);
  return {workspace, ctx, node, events, storage, writes, calls, click: () => node('mutation-review-confirm').events.click()};
}
const pure = [];
function test(name, run) { pure.push([name, run]); }
test('current recovery copy uses Catchplate and requires a fresh handoff without weakening legacy guards', () => {
  assert.doesNotMatch(HTML, /serverware/i);
  assert.doesNotMatch(APP, /serverware/i);
  assert(HTML.includes('Returning from a previous installation?'));
  assert(HTML.includes('fresh private client configuration and verify the current Catchplate CA'));
  assert(HTML.includes('Do not reuse an old CA as a fallback or disable TLS verification.'));
  assert(APP.includes('A recovery marker from the previous installation could not be transferred safely. Changes are blocked;'));
  assert(APP.includes('Unresolved operations still need review; no request was retried.'));
});
test('rename transfers only the twelve recognized public recovery marker types, without requests', () => {
  const id = IDS.application, ref = JSON.stringify({operation_id: id, kind: 'prepare'});
  const entries = [['operator.mutation.review.v1', VALUE], ['operator.upstreams.operation.v1', ref],
    ['operator.google.configuration.operation.v2', ref], ['operator.notifications.operation.v1', JSON.stringify({
      operation_id: id, kind: 'save', slot: 'audit_log.webhook', expected_revision: 0})],
    ['operator.x.configuration.operation.v1', id], ['operator.x.account.operation.v1', id], ['googleReauthorization.operation', id],
    ...['hostApprovalDecisionUncertain.', 'nativeJitReviewUncertain.', 'approvalDecisionUncertain.',
      'ecrPublicationDecisionUncertain.', 'ecrPublicationRetirementUncertain.'].map(prefix => [prefix + id, id])];
  const storage = new Map(entries.map(([suffix, raw]) => ['serverware.' + suffix, raw]));
  storage.set('unrelated', SECRET); storage.set('serverware.sandbox.client.v1', 'not-operator-recovery');
  const f = inert({storage, migrate: true});
  assert.equal(f.workspace.state.browserRecoveryBlocked, false); assert(f.workspace.state.uncertain);
  for (const [suffix, raw] of entries) {
    assert.equal(storage.get('catchplate.' + suffix), raw); assert(!storage.has('serverware.' + suffix));
  }
  assert.equal(storage.get('unrelated'), SECRET); assert.equal(storage.get('serverware.sandbox.client.v1'), 'not-operator-recovery');
  assert.equal(f.calls.length, 0); assert(!JSON.stringify(f.writes).includes(SECRET));
  assert.deepEqual(clone(f.ctx.migrateLegacyOperatorBrowserState()), {migrated: 0, blocked: false});
});
test('rename conflicts or malformed old markers preserve both sides and refuse new mutations', async () => {
  const id = IDS.application;
  for (const entries of [
    [['serverware.operator.mutation.review.v1', VALUE], [KEY, 'conflicting']],
    [['serverware.googleReauthorization.operation', SECRET]],
    [['serverware.hostApprovalDecisionUncertain.' + id, 'invalid']],
    [['serverware.hostApprovalDecisionUncertain.not-a-uuid', id]],
    [['serverware.operator.notifications.operation.v1', JSON.stringify({operation_id: id, secret: SECRET})]]
  ]) {
    const f = inert({storage: new Map(entries), migrate: true});
    assert(f.workspace.state.browserRecoveryBlocked); assert(f.workspace.state.uncertain);
    await f.workspace.refresh(); f.click();
    assert(f.node('mutation-review-confirm').disabled);
    assert.equal(await f.workspace.mutate('credentials', {secret: SECRET}, 'status', () => assert.fail('no save')), false);
    assert.deepEqual([...f.storage], entries); assert.equal(f.writes.length, 0);
    assert(f.calls.every(item => !item.options.method)); assert(!f.node('mutation-review-text').textContent.includes(SECRET));
  }
});
test('rename failures never remove the last verified legacy recovery copy', () => {
  const old = 'serverware.operator.mutation.review.v1';
  for (const fault of ['get', 'set', 'silent-set', 'remove', 'silent-remove']) {
    const f = inert({storage: new Map([[old, VALUE]]), fault, migrate: true});
    assert(f.workspace.state.browserRecoveryBlocked); assert(f.workspace.state.uncertain);
    assert.equal(f.storage.get(old), VALUE); assert.equal(f.calls.length, 0);
    if (fault === 'remove' || fault === 'silent-remove') assert.equal(f.storage.get(KEY), VALUE);
    else assert(!f.storage.has(KEY));
  }
});
test('same-origin renamed warning remains unresolved after reload and retires only after explicit review', async () => {
  const old = 'serverware.operator.mutation.review.v1';
  const f = inert({storage: new Map([[old, VALUE], [KEY, VALUE]]), migrate: true});
  assert(!f.storage.has(old)); assert(f.workspace.state.uncertain);
  const next = inert({storage: f.storage, migrate: true}); assert(next.workspace.state.uncertain);
  await next.workspace.refresh(); next.click(); assert(!next.workspace.state.uncertain); assert.equal(next.storage.size, 0);
  const last = inert({storage: next.storage, migrate: true}); assert(!last.workspace.state.uncertain); assert.equal(last.calls.length, 0);
  const newOrigin = inert({migrate: true}); assert(!newOrigin.workspace.state.uncertain);
  assert.equal(newOrigin.storage.size, 0); assert.equal(newOrigin.calls.length, 0);
});
test('old and new channels invalidate tokens with public IDs only, no forwarding, and close on lifecycle', () => {
  const opened = [], received = [], sent = [];
  class Channel {
    constructor(name) { this.name = name; opened.push(this); }
    addEventListener(name, callback) { assert.equal(name, 'message'); this.receive = callback; }
    postMessage(value) { sent.push([this.name, clone(value)]); }
    close() { this.closed = true; }
  }
  const ctx = vm.createContext({BroadcastChannel: Channel}); vm.runInContext(APPLICATIONS, ctx);
  const notifier = ctx.createApplicationTokenInvalidations(id => received.push(id));
  notifier.connect(); notifier.connect();
  assert.deepEqual(opened.map(value => value.name), ['catchplate-operator-catalog-v1', 'serverware-operator-catalog-v1']);
  notifier.send(IDS.application); assert.equal(sent.length, 2);
  for (const [, value] of sent) assert.deepEqual(value, {kind: 'application-token-invalidated', application_id: IDS.application});
  for (const channel of opened) channel.receive({data: {kind: 'application-token-invalidated', application_id: IDS.application}});
  assert.deepEqual(received, [IDS.application, IDS.application]); assert.equal(sent.length, 2, 'received messages are never forwarded');
  notifier.send(SECRET); opened[0].receive({data: {kind: 'application-token-invalidated', application_id: SECRET}});
  assert.equal(sent.length, 2); assert.equal(received.length, 2);
  notifier.close(); assert(opened.every(value => value.closed)); notifier.connect(); assert.equal(opened.length, 4);
});
test('a failed legacy notifier does not block the new notifier or retry a mutation', () => {
  const sent = [];
  class Channel {
    constructor(name) { if (name === 'serverware-operator-catalog-v1') throw new Error('unavailable'); }
    addEventListener() {} postMessage(value) { sent.push(clone(value)); } close() {}
  }
  const ctx = vm.createContext({BroadcastChannel: Channel}); vm.runInContext(APPLICATIONS, ctx);
  const notifier = ctx.createApplicationTokenInvalidations(() => assert.fail('no received message'));
  notifier.connect(); notifier.send(IDS.application); notifier.close(); assert.equal(sent.length, 1);
});
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
  assert.equal(f.node('mutation-review-resource').href, '#credentials');
  assert.equal(f.node('mutation-review-resource').textContent, 'Review Credentials');
  assert.equal(f.node('mutation-review-resource').hidden, false);
  assert.doesNotMatch(f.node('mutation-review-text').textContent, /lost one-time token/i);
  const next = inert({storage: f.storage}); assert(next.workspace.state.uncertain); assert(next.node('mutation-review-confirm').disabled);
  assert(next.node('mutation-review-resource').hidden, 'reload does not invent or persist the prior action context');
  next.click(); assert.equal(next.storage.get(KEY), VALUE);
  await next.workspace.refresh(); assert.equal(next.workspace.state.uncertain, true); assert.equal(next.node('mutation-review-confirm').disabled, false);
  next.click(); assert.equal(next.workspace.state.uncertain, false); assert.equal(next.storage.size, 0);
  assert.equal(next.calls.length, 1); assert(next.calls.every(item => !item.options.method));
});
test('action guidance stays in memory and refresh never acknowledges or resends a mutation', async () => {
  for (const [path, view, token] of [['credentials/replace-key', 'credentials', false],
    ['applications', 'applications', true], ['applications/rotate-token', 'applications', true],
    ['applications/renewal/enroll', 'applications', false], ['access-rules/common-app', 'access-rules', false]]) {
    const f = inert(); await f.workspace.refresh();
    const destinations = [];
    f.workspace.subscribe(() => { if (f.workspace.state.uncertain) destinations.push(f.node('mutation-review-resource').href); });
    f.ctx.respond = (requestPath, options) => options.method === 'POST' ? Promise.reject(new Error(SECRET)) : response(catalog());
    await f.workspace.mutate(path, {secret: SECRET, name: SECRET}, 'status', () => assert.fail('no reply'));
    assert.equal(f.node('mutation-review-resource').href, '#' + view);
    assert.equal(/lost one-time token/i.test(f.node('mutation-review-text').textContent), token);
    assert(!f.node('mutation-review-text').textContent.includes(SECRET));
    await f.node('mutation-review-refresh').events.click();
    assert(destinations.length > 0 && destinations.every(value => value === '#' + view),
      'review destination is current before Overview or any other subscriber renders');
    assert(f.workspace.state.uncertain); assert.equal(f.calls.filter(item => item.options.method === 'POST').length, 1);
    assert.deepEqual([...f.storage], [[KEY, VALUE]], 'only the unchanged constant marker is persisted');
    f.click(); assert.equal(f.workspace.state.uncertain, false); assert(f.node('mutation-review-resource').hidden);
  }
});
test('closed API error headers add safe guidance with status binding and generic fallback', async () => {
  const f = inert();
  const message = (status, code = null, fields = null) => f.ctx.operatorApiErrorMessage({status,
    headers: {get: name => name === 'X-Catchplate-Error-Code' ? code : fields}});
  const expected = {invalid_input: [422, /form fields/], unsupported_policy: [422, /not supported/],
    catalog_changed: [409, /Saved state changed since/], credential_in_use: [409, /active permissions/],
    provider_disconnect_required: [409, /provider disconnect/], approval_required: [409, /human approval/],
    already_configured: [409, /already matches/], capacity_reached: [409, /resource limit/],
    resource_not_found: [404, /no longer available/], github_app_verification_failed: [503, /GitHub App verification/],
    mutation_outcome_unknown: [503, /save outcome could not be confirmed/]};
  for (const [code, [status, pattern]] of Object.entries(expected)) {
    assert.match(message(status, code), pattern);
    assert.equal(message(400, code), message(400), 'mismatched status never selects a specialized message');
  }
  assert.match(message(422, 'invalid_input', 'scope,secret'), /Check: Operation limits, Provider key or token\./);
  for (const fields of ['', SECRET, 'secret,' + SECRET, 'secret,secret', '__proto__', 'name,'.repeat(9), 'x'.repeat(513)])
    assert.equal(message(422, 'invalid_input', fields), message(422));
  for (const code of [SECRET, '__proto__', 'INVALID_INPUT', 'invalid_input ']) assert.equal(message(422, code), message(422));
  assert.equal(message(409, 'credential_in_use', 'secret'), message(409));
  await f.workspace.refresh();
  f.ctx.respond = (path, options) => options.method === 'POST' ? {ok: false, status: 422,
    headers: {get: name => name === 'X-Catchplate-Error-Code' ? 'invalid_input' : 'secret'},
    json: () => assert.fail('error body is not parsed or rendered')} : response(catalog());
  await f.workspace.mutate('credentials', {secret: SECRET}, 'status', () => assert.fail('no success'));
  assert(f.workspace.state.uncertain, 'recognized local validation still retains the existing review hold');
  assert.match(f.node('status').textContent, /Provider key or token/);
  assert.equal(f.calls.filter(item => item.options.method === 'POST').length, 1);
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
  const provider = 'catchplate.operator.google.configuration.operation.v2';
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
  await ready(page); await view(page, 'credentials'); await page.locator('#credentials [data-credential-provider="manual"]').click();
  await page.locator('#connect-credential-name').fill('Recovery test key');
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
      assert.equal(await page.locator('#mutation-review-resource').getAttribute('href'), '#credentials');
      assert.doesNotMatch(await page.locator('#mutation-review-text').innerText(), /lost one-time token/i);
      await page.locator('#mutation-review-resource').click(); await page.locator('#credentials').waitFor({state: 'visible'});
      await page.locator('#mutation-review-refresh').click(); await held(page);
      assert.equal(state.posts.length, 1, 'review navigation and refresh do not resend or acknowledge');
      state.catalogStatus = 503; await page.reload({waitUntil: 'networkidle'}); await held(page);
      assert(await page.locator('#mutation-review-resource').isHidden());
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

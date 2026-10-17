#!/usr/bin/env node
// Actual UI helpers/controllers, inert DOM and synthetic HTTP only.
// This does not prove durable quota enforcement, rendering or provider behavior.
'use strict';
const assert = require('node:assert/strict');
const {mutationReviewStorage} = require('./operator_mutation_recovery_test_helpers.cjs');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const {context, rawCatalog, IDS, clone} = require('./test_operator_npm_ui.cjs');
const {credential, rule} = require('./test_operator_catalog_browser.cjs');
const SHA = 'sha256:' + 'a'.repeat(64);
const quota = () => ({schema: 'catchplate.operatorXPostAttemptQuota/v1', field: 'daily_post_attempt_limit',
  period: 'utc_day', scope: 'verified_x_account', unit: 'posting_attempt', minimum: 1, maximum: 1000000000});
const capability = (limited = true) => ({schema: 'catchplate.operatorXPost/v1', connection_type: 'x_user_oauth_v1',
  create_rule_path: '/api/operator-demo/access-rules/x-post', api_origin: 'https://api.x.com', destination_allowed: true,
  operation_bundles: ['x_text_post_v1'], sdk_auth_token: 'catchplate-x-post-placeholder-v1',
  placeholder: 'Bearer catchplate-x-post-placeholder-v1', response_mode: 'x_post_json_v1', source_pair_required: true,
  daily_quota_available: limited, ...(limited ? {daily_quota: quota()} : {})});
const account = () => credential({auth_type: 'x_oauth', connection_type: 'x_user_oauth_v1', provider_id: 'x',
  provider_account: '@fixture_user', provider_subject: '123456789', oauth_client_id: 'fixture-client',
  permission_preset: 'x_text_post_v1', scopes: ['offline.access', 'tweet.read', 'tweet.write', 'users.read'], credential_generation: 1});
const postRule = (changes = {}) => rule({name: 'Publish text · @fixture_user', operation_bundle: 'x_text_post_v1',
  methods: ['POST'], upstream_url: 'https://api.x.com/2/tweets', request_fields: [], response_fields: [], query_keys: [],
  allowed_headers: ['accept', 'accept-language', 'content-type', 'sec-fetch-mode', 'user-agent'], response_mode: 'x_post_json_v1',
  credential_input: 'replace_exact', placeholder: 'Bearer catchplate-x-post-placeholder-v1', ...changes});
function catalog(cap = capability(), rules = []) {
  const value = rawCatalog({credentials: [account()], rules, capability: null, allowed: ['https://api.x.com']});
  value.capabilities.x_post = cap; return value;
}
function fixture({raw = catalog(), pending = false, failure = null, receiptLimit = undefined} = {}) {
  const f = context();
  for (const name of ['workspace_x_accounts.js', 'workspace_x_post.js'])
    vm.runInContext(readFileSync(resolve(__dirname, '../catchplate/operator_demo_web', name), 'utf8'), f.value, {timeout: 2000});
  const calls = [];
  Object.assign(f.value, {sessionStorage: mutationReviewStorage(), AbortSignal: {timeout: () => undefined}, clearTimeout() {}, setTimeout: () => 0, fetch: async (path, init) => {
    assert.equal(init.credentials, 'same-origin'); assert.equal(init.redirect, 'error'); assert.equal(init.cache, 'no-store');
    const call = {path, method: init.method || 'GET', body: init.body ? JSON.parse(init.body) : null}; calls.push(call);
    let result = raw, status = 200;
    if (call.method === 'POST') {
      assert.equal(path, '/api/operator-demo/access-rules/x-post');
      if (failure === 'lost') throw new Error('synthetic unavailable response');
      if (failure) return {ok: false, status: failure, headers: {get: () => 'application/json'}, json: async () => ({})};
      raw.revision++; raw.policy.policy_hash = SHA; raw.policy.activation = pending ? 'pending' : 'active';
      if (!pending) raw.policy.loaded_policy_hash = SHA;
      const limit = Object.hasOwn(call.body, 'daily_post_attempt_limit') ? {daily_post_attempt_limit: call.body.daily_post_attempt_limit} : {};
      raw.access_rules = [postRule({...limit, enforcement: pending ? 'pending' : 'active'})];
      raw.applications[0].active_rule_count = 1; raw.credentials[0].active_rule_count = 1;
      raw.applications[0].access_status = pending ? 'pending' : 'active';
      if (pending) raw.capabilities.x_post = null;
      result = {revision: raw.revision, policy: {policy_hash: SHA}, access_rule: clone(raw.access_rules[0])};
      if (receiptLimit !== undefined) result.access_rule.daily_post_attempt_limit = receiptLimit;
      status = 201;
    } else assert.equal(path, '/api/operator-demo/catalog');
    return {ok: true, status, headers: {get: () => 'application/json'}, json: async () => clone(result)};
  }});
  const workspace = f.run('createOperatorWorkspace()');
  workspace.state.catalog = f.run('projectCatalog(input)', raw); f.value.workspace = workspace;
  const node = id => f.dom.getElementById(id);
  const event = async (id, type = 'click') => {
    const target = node(id); await target.events[type]({preventDefault() {}, currentTarget: target});
  };
  const start = () => f.run('createConnectView(workspace, {mount(){},tokenFor(){return null;}}, {mount(){},select(){}})');
  const refresh = () => { workspace.state.catalog = f.run('projectCatalog(input)', raw); workspace.emit(); };
  return {...f, raw, workspace, calls, node, event, start, refresh};
}
async function pair(f) {
  f.start(); await f.event('connect-use-saved'); f.node('connect-credential-choice').value = IDS.credential;
  await f.event('connect-credential-form', 'submit'); f.node('connect-application-choice').value = IDS.application;
  await f.event('connect-application-form', 'submit');
}
async function limit(f, text = '42') {
  f.node('connect-x-post-quota').value = 'daily'; await f.event('connect-x-post-quota', 'change');
  f.node('connect-x-post-limit').value = text; await f.event('connect-x-post-limit', 'input');
}
const tests = [
  ['exact paired descriptor admits legacy and bounded capabilities only', () => {
    const f = fixture();
    for (const value of [capability(), capability(false)]) assert.deepEqual(clone(f.run('projectXPostCapability(input)', value)), value);
    for (const value of [{...capability(), daily_quota: {...quota(), maximum: 1000000}},
      {...capability(), daily_quota: {...quota(), scope: 'application'}}, {...capability(), daily_quota: {...quota(), period: 'rolling_day'}},
      {...capability(), daily_quota: {...quota(), extra: true}}, {...capability(), daily_quota_available: false},
      {...capability(false), daily_quota_available: true}, {...capability(), extra: true}])
      assert.equal(f.run('projectXPostCapability(input)', value), null);
  }],
  ['saved quota projection preserves exact integer or omission and rejects cross-provider fields', () => {
    const f = fixture();
    for (const changes of [{}, {daily_post_attempt_limit: 1}, {daily_post_attempt_limit: 1000000000}]) {
      const value = f.run('projectCatalog(input)', catalog(capability(), [postRule(changes)]));
      assert.equal(value.access_rules[0].daily_post_attempt_limit, changes.daily_post_attempt_limit);
      const payload = clone(f.run('xPostRulePayload(input)', value.access_rules[0]));
      assert.equal(Object.hasOwn(payload, 'daily_post_attempt_limit'), Object.hasOwn(changes, 'daily_post_attempt_limit'));
    }
    for (const limit of [null, false, true, 0, -1, 1.5, '5', 1000000001])
      assert.throws(() => f.run('projectCatalog(input)', catalog(capability(), [postRule({daily_post_attempt_limit: limit})])));
    const other = rawCatalog(); other.access_rules[0].daily_post_attempt_limit = 5;
    assert.throws(() => f.run('projectCatalog(input)', other));
  }],
  ['positive decimal grammar rejects blank, fractions, exponent and absent support', () => {
    const f = fixture();
    const parse = (mode, text, cap = capability()) => f.run('xPostQuotaInput(input.mode,input.text,input.catalog,input.credential)',
      {mode, text, catalog: catalog(cap), credential: account()});
    assert.deepEqual(clone(parse('none', '42')), {});
    for (const text of ['1', '42', '1000000000']) assert.deepEqual(clone(parse('daily', text)), {daily_post_attempt_limit: Number(text)});
    for (const text of ['', '0', '-1', '01', ' 1', '1 ', '1.0', '1e2', '+1', '1000000001', '∞', null, 5]) assert.throws(() => parse('daily', text));
    for (const cap of [null, capability(false), {...capability(), destination_allowed: false}]) assert.throws(() => parse('daily', '42', cap));
    assert.throws(() => parse('', '42'));
  }],
  ['default none performs no mutation and emits unchanged legacy grant DTO', async () => {
    const f = fixture(); await pair(f);
    assert.equal(f.node('connect-x-post-quota').value, 'none'); assert.equal(f.node('connect-x-post-limit-group').hidden, true);
    assert.equal(f.node('connect-x-post-quota-group').hidden, false); assert.equal(f.calls.length, 0);
    await f.event('connect-access-form', 'submit');
    assert.equal(f.node('connect-review-step').hidden, false, f.node('connect-status').textContent);
    assert.equal(f.node('connect-grant').disabled, false, f.node('connect-review-context').textContent);
    await f.event('connect-grant');
    const posts = f.calls.filter(call => call.method === 'POST'); assert.equal(posts.length, 1);
    assert.deepEqual(posts[0].body, {name: 'Publish text · @fixture_user', application_id: IDS.application, credential_id: IDS.credential,
      operation_bundle: 'x_text_post_v1', expected_revision: 1, expected_policy_hash: 'sha256:' + '0'.repeat(63) + '1'});
  }],
  ['optional limit requires explicit valid input and reviews shared uncertain-attempt semantics', async () => {
    const f = fixture(); await pair(f); await limit(f, '');
    assert.equal(f.node('connect-review').disabled, true); assert.match(f.node('connect-x-post-quota-status').textContent, /whole number/);
    await f.event('connect-access-form', 'submit'); assert.equal(f.calls.length, 0);
    await limit(f); assert.equal(f.node('connect-review').disabled, false); await f.event('connect-access-form', 'submit');
    const text = f.node('connect-review-details').descendants().map(node => node.textContent).join(' ');
    assert.match(text, /42 posting attempts per UTC day across all apps using this X account/); assert.match(text, /Uncertain attempts still count/);
    assert.match(text, /even across OAuth clients/); assert.doesNotMatch(text, /remaining|resets at|successful posts today/i);
    await f.event('connect-grant'); assert.equal(f.calls.filter(call => call.method === 'POST').length, 1);
    assert.equal(f.calls.find(call => call.method === 'POST').body.daily_post_attempt_limit, 42);
  }],
  ['withdrawn quota capability preserves selected limit and never grants unlimited fallback', async () => {
    const f = fixture(); await pair(f); await limit(f); f.raw.capabilities.x_post = capability(false); f.refresh();
    assert.equal(f.node('connect-x-post-quota-group').hidden, false); assert.equal(f.node('connect-x-post-quota').value, 'daily');
    assert.equal(f.node('connect-x-post-quota').disabled, true); assert.equal(f.node('connect-review').disabled, true);
    assert.match(f.node('connect-x-post-quota-status').textContent, /no unlimited fallback/);
    await f.event('connect-access-form', 'submit'); await f.event('connect-grant'); assert.equal(f.calls.length, 0);
    f.raw.capabilities.x_post = capability(); f.refresh(); assert.equal(f.node('connect-review').disabled, false);
    assert.equal(f.node('connect-x-post-limit').value, '42');
  }],
  ['legacy and bounded saved grants stay readable while only advertised support permits setup', () => {
    const f = fixture();
    for (const cap of [null, capability(false)]) {
      const value = f.run('projectCatalog(input)', catalog(cap, [postRule({daily_post_attempt_limit: 42})]));
      assert.equal(value.access_rules[0].daily_post_attempt_limit, 42);
      assert.equal(f.run('operatorRuleSupported(input.access_rules[0],input)', value), false);
    }
    const value = f.run('projectCatalog(input)', catalog(capability(false), [postRule()]));
    assert.equal(f.run('operatorRuleSupported(input.access_rules[0],input)', value), true);
    assert.match(f.run('xPostQuotaSummary(input)', value.access_rules[0]), /No daily posting-attempt limit is set on this permission/);
  }],
  ['saved bounded grant recovers pending-null capability using reads without replay', async () => {
    const f = fixture({pending: true}); await pair(f); await limit(f); await f.event('connect-access-form', 'submit'); await f.event('connect-grant');
    assert.equal(f.workspace.state.uncertain, false); assert.equal(f.node('connect-setup-step').hidden, false);
    assert.equal(f.workspace.state.catalog.capabilities.x_post, null); assert.match(f.node('connect-activation').textContent, /Waiting for the proxy/);
    await f.workspace.refresh(); assert.equal(f.calls.filter(call => call.method === 'POST').length, 1);
    f.raw.capabilities.x_post = capability(); f.raw.policy.activation = 'active'; f.raw.policy.loaded_policy_hash = SHA;
    f.raw.access_rules[0].enforcement = 'active'; f.raw.applications[0].access_status = 'active'; await f.workspace.refresh();
    assert.match(f.node('connect-activation').textContent, /Rule active in the proxy/); assert.equal(f.calls.filter(call => call.method === 'POST').length, 1);
  }],
  ['review changes, capability loss and generation drift prevent stale grant', async () => {
    for (const drift of ['capability', 'generation', 'limit']) {
      const f = fixture(); await pair(f); await limit(f); await f.event('connect-access-form', 'submit');
      if (drift === 'capability') f.raw.capabilities.x_post = capability(false);
      if (drift === 'generation') f.raw.credentials[0].credential_generation++;
      if (drift === 'limit') { f.node('connect-x-post-limit').value = '43'; await f.event('connect-x-post-limit', 'input'); }
      f.refresh(); await f.event('connect-grant'); assert.equal(f.calls.length, 0);
    }
  }],
  ['uncertain or mismatched quota receipts never replay the mutation', async () => {
    for (const options of [{failure: 409}, {failure: 503}, {failure: 'lost'}, {receiptLimit: 43}]) {
      const f = fixture(options); await pair(f); await limit(f); await f.event('connect-access-form', 'submit'); await f.event('connect-grant');
      assert.equal(f.workspace.state.uncertain, true); await f.event('connect-grant');
      assert.equal(f.calls.filter(call => call.method === 'POST').length, 1);
    }
  }],
  ['legacy deployment hides quota input and changes no existing permission', async () => {
    const f = fixture({raw: catalog(capability(false))}); await pair(f);
    assert.equal(f.node('connect-x-post-quota-group').hidden, true); assert.equal(f.node('connect-x-post-quota').value, 'none');
    assert.match(f.node('connect-x-post-summary').textContent, /does not advertise daily limits/); assert.equal(f.calls.length, 0);
  }]
];
(async () => {
  assert.equal(process.argv.length, 2); assert.equal(tests.length, 11);
  for (const [name, test] of tests) { await test(); console.log('PASS ' + name); }
  console.log(JSON.stringify({ok: true, groups: tests.length, browser: false, network: false,
    scope: 'shared X posting-attempt quota UI contracts; no backend or enforcement acceptance'}));
})().catch(error => { console.error(error.stack); process.exitCode = 1; });

#!/usr/bin/env node
'use strict';
// Actual UI helpers, draft/review and download handlers with inert public
// fixtures. No browser, provider, proxy, stored credential or application I/O.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const ROOT = resolve(__dirname, '..');
const fixture = JSON.parse(execFileSync('python3', ['-B', '-c', [
  'import json', 'from types import SimpleNamespace', 'from unittest.mock import patch',
  'from serverware import operator_catalog_gmail as gmail', 'from serverware.operator_demo_portal import SCRIPT_FILES',
  'profile=SimpleNamespace(permission_preset="gmail_readonly", api_origins=[gmail.ORIGIN], scopes=[gmail.READ_SCOPE])',
  'with patch("serverware.operator_catalog_google.validate_profile_binding", return_value=profile):',
  ' print(json.dumps({"descriptor":gmail.capabilities(SimpleNamespace(in_transaction=True))[0],"scripts":SCRIPT_FILES}))',
].join('\n')], {cwd: ROOT, encoding: 'utf8', timeout: 5000}));
const copy = value => JSON.parse(JSON.stringify(value));
const context = vm.createContext({URL, URLSearchParams, module: {exports: {}}, location: {origin: 'https://operator.example.test'}});
for (const file of fixture.scripts) vm.runInContext(readFileSync(resolve(ROOT, 'serverware/operator_demo_web', file), 'utf8'), context, {timeout: 1000});
const recent = days => ({mode: 'recent_internal_date_v1', max_age_days: days});
const unrestricted = {mode: 'unrestricted'};
const old = copy(fixture.descriptor); delete old.age_policy_options;
let groups = 0;
function test(body) { body(); groups++; }

test(() => {
  assert.deepEqual(copy(context.operatorGmailDescriptor(true)), fixture.descriptor, 'actual backend descriptor matches exactly');
  assert.deepEqual(copy(context.operatorGmailDescriptor()), old);
  for (const descriptor of [old, fixture.descriptor]) assert.deepEqual(copy(context.projectOperationBundles([descriptor], true)), [descriptor]);
  assert.equal(context.gmailRecentAvailable({capabilities: {operation_bundles: [old]}}), false);
  assert(context.gmailRecentAvailable({capabilities: {operation_bundles: [fixture.descriptor]}}));
  for (const options of [[], null, [{mode: 'unrestricted'}], [...fixture.descriptor.age_policy_options].reverse(),
    [unrestricted, {...fixture.descriptor.age_policy_options[1], max_list_results: 33}],
    [unrestricted, {...fixture.descriptor.age_policy_options[1], extra: true}]])
    assert.throws(() => context.projectOperationBundles([{...old, age_policy_options: options}], true));
  assert.throws(() => context.projectOperationBundles([fixture.descriptor], false));
});
test(() => {
  assert.deepEqual(copy(context.gmailAgePolicy()), unrestricted);
  for (const days of [1, 30, 3650]) assert.deepEqual(copy(context.gmailAgePolicy(recent(days))), recent(days));
  for (const days of [0, -1, 3651, 1.5, '30', true, null, NaN, Infinity]) assert.throws(() => context.gmailAgePolicy(recent(days)));
  for (const policy of [null, [], {}, {mode: 'future'}, {...unrestricted, max_age_days: 30}, {...recent(30), extra: true}])
    assert.throws(() => context.gmailAgePolicy(policy));
  const input = recent(30), output = context.gmailAgePolicy(input); output.max_age_days = 1; assert.equal(input.max_age_days, 30);
});
const credential = {id: '11111111-1111-4111-8111-111111111111', status: 'active', auth_type: 'google_oauth',
  header_name: 'Authorization', permission_preset: 'gmail_readonly'};
const app = {id: '22222222-2222-4222-8222-222222222222', status: 'active', proxy_authentication: 'basic_and_bearer_v1'};
const catalog = {revision: 1, policy: {policy_hash: 'synthetic-policy'}, credentials: [credential], applications: [app],
  allowed_upstreams: ['https://gmail.googleapis.com'], capabilities: {google_oauth: {}, operation_bundles: [fixture.descriptor],
    credential_input_modes: ['insert', 'replace_exact'], application_proxy_authentication: {
      schema: 'serverware.operatorProxyAuthentication/v1', modes: ['bearer', 'basic_and_bearer_v1'], path: '/api/operator-demo/applications/proxy-authentication'}}};
const makeRule = policy => ({...context.gmailRuleFields(policy), name: 'Read Gmail', application_id: app.id, credential_id: credential.id,
  credential_input: 'replace_exact', placeholder: 'Bearer serverware-gmail-placeholder-v1'});
test(() => {
  for (const policy of [unrestricted, recent(1), recent(3650)]) {
    const rule = makeRule(policy);
    assert(context.gmailRuleValid(rule, credential)); assert(context.operatorRuleSupported(rule, catalog));
    assert.deepEqual(copy(context.gmailRulePayload(rule).age_policy), policy);
    const before = copy(rule); context.gmailRulePayload(rule).age_policy.max_age_days = 300; assert.deepEqual(copy(rule), before);
  }
  const legacy = makeRule(unrestricted); delete legacy.query_mode;
  legacy.allowed_headers = ['accept', 'accept-encoding', 'user-agent', 'x-goog-api-client'];
  assert(context.gmailRuleValid(legacy, credential));
  assert(!context.gmailRuleValid({...legacy, age_policy: recent(30)}, credential));
  const missing = makeRule(unrestricted); delete missing.age_policy; assert(!context.gmailRuleValid(missing, credential));
  const oldCatalog = {...catalog, capabilities: {...catalog.capabilities, operation_bundles: [old]}};
  assert(context.operatorRuleSupported(makeRule(unrestricted), oldCatalog));
  assert(!context.operatorRuleSupported(makeRule(recent(30)), oldCatalog));
});
test(() => {
  const rule = makeRule(recent(30)), changed = {...rule, age_policy: recent(31)};
  assert(!context.operatorExact(context.gmailRulePayload(rule), context.gmailRulePayload(changed)), 'receipt comparison binds exact days');
  const summary = context.operatorRuleRestrictions(rule).map(row => row.join(': ')).join('\n');
  assert.match(summary, /last 30 days/); assert.match(summary, /internalDate/); assert.match(summary, /1–32/);
  assert.match(summary, /whole page/); assert(!summary.includes('Unrestricted'));
  assert.match(context.gmailAgePolicySummary(unrestricted), /Unrestricted/);
});
const connect = readFileSync(resolve(ROOT, 'serverware/operator_demo_web/workspace_connect.js'), 'utf8');
function functionSource(name, endMarker) {
  const start = connect.indexOf('  function ' + name + '('), end = connect.indexOf(endMarker, start);
  assert(start > 0 && end > start); return connect.slice(start, end).trim();
}
for (const [name, next] of [['gmailAgeInput', 'gmailAgeProblem'], ['gmailAgeProblem', 'gmailSdkRule'],
  ['gmailSdkRule', 'gmailSdkProblem'], ['gmailSdkProblem', 'confirmCheckpoint'], ['reviewCurrent', 'renderReview']])
  vm.runInContext(functionSource(name, '\n  function ' + next + '('), context, {timeout: 1000});
const draftSource = functionSource('draftRule', "\n  element('connect-access-form').addEventListener");
const values = {'connect-operation': 'gmail_read_v1', 'connect-gmail-client': 'sdk', 'connect-gmail-age-policy': 'unrestricted',
  'connect-gmail-age-days': '30', 'connect-credential-input': 'insert', 'gmail-proxy-ca-path': ''};
Object.assign(context, {document: {getElementById: id => ({value: values[id] ?? ''})},
  credential: () => credential, application: () => app, catalog: () => catalog, activePair: () => true,
  selectedApplication: app.id, selectedCredential: credential.id, supported: rule => context.operatorRuleSupported(rule, catalog)});
const draft = () => vm.runInContext('(' + draftSource + ')()', context, {timeout: 1000});
test(() => {
  for (const client of ['sdk', 'custom']) {
    values['connect-gmail-client'] = client; values['connect-gmail-age-policy'] = 'unrestricted';
    assert.deepEqual(copy(draft().age_policy), unrestricted);
    values['connect-gmail-age-policy'] = 'recent_internal_date_v1'; values['connect-gmail-age-days'] = '30';
    assert.deepEqual(copy(draft().age_policy), recent(30));
    for (const value of ['', '0', '3651', '1.5', 'bad']) { values['connect-gmail-age-days'] = value; assert.throws(draft); }
    values['connect-gmail-age-days'] = '30';
    catalog.capabilities.operation_bundles = [old]; assert.throws(draft);
    catalog.capabilities.operation_bundles = [fixture.descriptor];
  }
});
test(() => {
  values['connect-gmail-client'] = 'sdk'; values['connect-gmail-age-days'] = '30';
  context.review = {rule: draft(), gmailClient: 'sdk', revision: catalog.revision, policyHash: catalog.policy.policy_hash};
  assert(context.reviewCurrent()); values['connect-gmail-age-days'] = '31'; assert(!context.reviewCurrent());
  // Existing selected grants have no draft client marker; their exact saved
  // policy is reused, never replaced with the unrelated form selection.
  context.review = {rule: makeRule(unrestricted), existing: true, revision: catalog.revision, policyHash: catalog.policy.policy_hash};
  assert(context.reviewCurrent()); assert.deepEqual(copy(context.review.rule.age_policy), unrestricted);
  assert(connect.includes("[['connect-gmail-age-policy', 'change'], ['connect-gmail-age-days', 'input']]"));
});
const handoff = readFileSync(resolve(ROOT, 'serverware/operator_demo_web/workspace_proxy_audit.js'), 'utf8');
const start = handoff.indexOf('    if (isGmailRule(rule)) {', handoff.indexOf("element('download-config').addEventListener"));
const end = handoff.indexOf('    if (isGithubRule(rule)) {', start); assert(start > 0 && end > start);
test(() => {
  const now = Date.now();
  context.catalog = catalog; context.application = app; context.token = Buffer.alloc(32, 85).toString('base64url');
  context.gmailSdkOptions = () => ({proxyUrl: 'https://proxy.example.test', applicationId: app.id,
    accessRuleId: '33333333-3333-4333-8333-333333333333', tokenExpiresAtEpochMs: now + 86400000});
  for (const policy of [unrestricted, recent(1), recent(3650)]) for (const input of ['insert', 'replace_exact']) {
    context.rule = {...makeRule(policy), credential_input: input};
    if (input === 'insert') delete context.rule.placeholder;
    context.config = {note: ''};
    const config = vm.runInContext('(() => {' + handoff.slice(start, end) + '; return config;})()', context, {timeout: 1000});
    assert(config); assert.deepEqual(copy(config.age_policy), policy);
    if (policy.mode !== 'unrestricted') { assert.match(config.note, /whole page/); assert(!config.note.includes('No age restriction')); }
    if (input === 'replace_exact') { assert(config.client_recipe); assert(!Object.hasOwn(config.client_recipe, 'age_policy')); }
  }
  assert(handoff.includes("? '?maxResults=32' : ''"), 'restricted custom HTTP list example includes explicit bounded size');
});
test(() => {
  const html = readFileSync(resolve(ROOT, 'serverware/operator_demo_web/index.html'), 'utf8');
  assert.match(html, /id="connect-gmail-age-policy" required disabled><option value="unrestricted" selected>All mail/);
  assert.match(html, /id="connect-gmail-age-days" type="number" min="1" max="3650" step="1"/);
  assert(connect.includes("gmail && (gmailRecentAvailable(catalog()) || recentAge)"));
  assert(connect.includes('Boolean(gmailAgeProblemText)'));
});
console.log(JSON.stringify({ok: true, groups, scope: 'actual backend descriptor and isolated UI draft/review/download functions',
  browser: false, providerRequests: 0, applicationRequests: 0}));

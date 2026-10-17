#!/usr/bin/env node
// Intercepted UI protocol fixtures only. No real consent, callback, exchange,
// adoption, provider request or proxy dispatch is exercised. The real renderer
// consumes synthetic public DTOs; backend transaction/runtime proof is separate.
const assert = require('node:assert/strict');
const {withoutMutationReview} = require('./operator_mutation_recovery_test_helpers.cjs');
const {createHash} = require('node:crypto');
const {execFileSync} = require('node:child_process');
const {readFileSync} = require('node:fs');
const {readFile, mkdtemp, stat} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {runInNewContext} = require('node:vm');
const {fixture: baseFixture, ready, view, credential, application, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {publicCatalog, google} = require('./test_operator_ordinary_modes_browser.cjs');
const pure = require('../catchplate/operator_demo_web/workspace_google_reauthorization.js');
const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const CATALOG = ORIGIN + '/api/operator-demo/catalog';
const PATH = '/api/operator-demo/oauth/google/reauthorize';
const STORAGE = 'catchplate.googleReauthorization.operation';
const OPERATION = '77777777-7777-4777-8777-777777777777';
const ORIGINAL = '88888888-8888-4888-8888-888888888888';
const OTHER = '99999999-9999-4999-8999-999999999999';
const SECOND_RULE = '55555555-5555-4555-8555-555555555555';
const STATIC = '66666666-6666-4666-8666-666666666666';
const INITIAL_OPERATION = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SCOPES = ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'];
const PRIVATE = ['synthetic-provider-secret-NEVER-PERSIST', 'synthetic-refresh-token-NEVER-PERSIST', 'synthetic-provider-error-NEVER-DISPLAY'];
const STATE = 'synthetic-reauthorization-state-' + 'a'.repeat(43);
const CAPABILITY = {schema: 'catchplate.operatorGoogleReauthorizationCapability/v1', path: PATH,
  status_path_prefix: PATH + '/', review_path_suffix: '/review', preserves_assignments: true, existing_account_only: true};
const GOOGLE_CAPABILITY = {schema: 'catchplate.operatorGoogleCapability/v1', profile: 'operator-google-v1', provider_id: 'google',
  permission_preset: 'gmail_readonly', scopes: SCOPES, api_origins: ['https://gmail.googleapis.com'],
  authorization_origin: 'https://accounts.google.com', authorization_path: '/o/oauth2/v2/auth',
  redirect_uri: ORIGIN + '/api/oauth/callback/google', start_path: '/api/operator-demo/oauth/google/start',
  intents_path: '/api/operator-demo/oauth/google/intents'};
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const clone = value => JSON.parse(JSON.stringify(value));
const account = (changes = {}) => google({name: 'Shared Google account', ...changes});
const gmailRule = (changes = {}) => rule({name: 'Read saved Gmail endpoint',
  upstream_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages', ...changes});
const supplied = (options = {}) => ({credentials: [account(), account({id: OTHER, provider_subject: 'other-google-subject',
    provider_account: 'other-fixture@example.test'}), credential({id: STATIC, name: 'Static control'})],
  applications: [application(), application({id: IDS.other, name: 'Mail indexing worker'})],
  rules: [gmailRule(), gmailRule({id: SECOND_RULE, route_id: 'operator.' + SECOND_RULE, name: 'Read a saved message',
    application_id: IDS.other, upstream_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages/abc123'})],
  responseModes: ['projected_json'], credentialInputModes: ['insert'], ...options});
function review(state, changes = {}) {
  const key = state.credentials.find(item => item.id === IDS.credential);
  const assigned = state.rules.filter(item => item.credential_id === key.id && item.status === 'active');
  return {schema: 'catchplate.operatorGoogleReauthorizationReview/v1', credential_id: key.id, name: key.name,
    provider_id: 'google', provider_subject: key.provider_subject, provider_account: key.provider_account,
    oauth_client_id: key.oauth_client_id, scopes: [...SCOPES], original_oauth_intent_id: ORIGINAL,
    expected_revision: state.revision, expected_policy_hash: state.active, expected_credential_generation: 7,
    affected_rule_ids: assigned.map(item => item.id).sort(), application_ids: [...new Set(assigned.map(item => item.application_id))].sort(),
    eligible: true, ...changes};
}
function operation(reviewed, changes = {}) {
  return {schema: 'catchplate.operatorGoogleReauthorization/v1', operation_id: OPERATION, credential_id: reviewed.credential_id,
    name: reviewed.name, provider_id: 'google', provider_account: reviewed.provider_account, scopes: [...SCOPES],
    status: 'awaiting_consent', reason: null, created_at: new Date(NOW).toISOString(), expires_at_epoch: NOW / 1000 + 600,
    expected_revision: reviewed.expected_revision, expected_policy_hash: reviewed.expected_policy_hash,
    expected_credential_generation: reviewed.expected_credential_generation, affected_rule_ids: [...reviewed.affected_rule_ids],
    application_ids: [...reviewed.application_ids], receipt: null, ...changes};
}
function adopted(reviewed, changes = {}) {
  const item = operation(reviewed, {status: 'adopted'});
  item.receipt = {schema: 'catchplate.operatorGoogleReauthorizationReceipt/v1', operation_id: item.operation_id,
    credential_id: item.credential_id, previous_credential_generation: reviewed.expected_credential_generation,
    credential_generation: reviewed.expected_credential_generation + 1, original_oauth_intent_id: reviewed.original_oauth_intent_id,
    revision: reviewed.expected_revision, policy_hash: reviewed.expected_policy_hash, affected_rule_ids: [...reviewed.affected_rule_ids],
    application_ids: [...reviewed.application_ids], adopted_at: new Date(NOW).toISOString()};
  return {...item, ...changes};
}
function startReceipt(item) {
  const query = new URLSearchParams({response_type: 'code', client_id: account().oauth_client_id,
    redirect_uri: GOOGLE_CAPABILITY.redirect_uri, scope: SCOPES.join(' '), state: STATE,
    code_challenge: 'c'.repeat(43), code_challenge_method: 'S256', access_type: 'offline', prompt: 'consent', include_granted_scopes: 'true'});
  return {provider: 'google', authorizationUrl: GOOGLE_CAPABILITY.authorization_origin + GOOGLE_CAPABILITY.authorization_path + '?' + query,
    state: STATE, expiresAtEpoch: item.expires_at_epoch, redirectUri: GOOGLE_CAPABILITY.redirect_uri,
    scopes: [...SCOPES], operatorGoogleReauthorization: clone(item)};
}
const INPUTS = ['scripts/test_operator_google_reauthorization_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
  'scripts/test_operator_ordinary_modes_browser.cjs', 'catchplate/operator_demo_portal.py',
  ...['index.html', 'style.css', 'app.js', 'workspace_core.js', 'workspace_github.js', 'workspace_google.js', 'workspace_google_reauthorization.js',
    'workspace_resources.js', 'workspace_applications.js', 'workspace_proxy_audit.js', 'workspace_connect.js'].map(name => 'catchplate/operator_demo_web/' + name)];
let artifacts;
let activeGroup = 0;
const checkpointStates = new WeakMap();
async function hashes() { return Object.fromEntries(await Promise.all(INPUTS.map(async path =>
  [path, createHash('sha256').update(await readFile(join(ROOT, path))).digest('hex')]))); }
async function screenshot(page, name) {
  await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true, mask: [page.locator('#client-token')]});
}
const panel = page => page.locator('#google-reauthorization-panel');
const action = (page, id = IDS.credential) => page.locator('#credentials-list [data-resource-id="' + id + '"] [data-action="reauthorize-google"]');
async function noMaterial(page) {
  const surfaces = await page.evaluate(() => ({html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].map(node => node.value), local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  for (const value of [...PRIVATE, STATE]) assert(!JSON.stringify(surfaces).includes(value), 'provider material, OAuth state and raw errors never persist');
  assert.deepEqual(surfaces.local, []);
  assert(withoutMutationReview(surfaces.session).every(([key, value]) => key === STORAGE && UUID.test(value)), 'only a public exact recovery UUID or shared review marker may persist');
  assert(!JSON.stringify(surfaces.session).includes('accounts.google.com'));
}
async function refreshCatalog(page) {
  const response = page.waitForResponse(item => item.url() === CATALOG && item.request().method() === 'GET');
  await page.locator('#credentials-refresh').click(); await (await response).finished(); await page.waitForLoadState('networkidle');
}
async function fixture(browser, options, exercise) {
  return baseFixture(browser, supplied(options), async (page, state, controls) => {
    state.allowedUpstreams = ['https://gmail.googleapis.com'];
    const observed = {posts: [], reads: [], navigations: 0, returns: 0, oldConsentReads: 0, initialIntents: [],
      capability: Object.hasOwn(options, 'capability') ? options.capability : clone(CAPABILITY),
      reviewChanges: {}, catalogTransform: null, operationTransform: null, current: null, catalogStatus: 200, statusCode: 200};
    checkpointStates.set(page, {state, observed});
    const answer = (route, value, status = 200) => route.fulfill({status, contentType: 'application/json', body: JSON.stringify(value)});
    let catalogReads = 0; let releaseOld; let oldArrived;
    const oldArrival = new Promise(resolve => { oldArrived = resolve; });
    const oldGate = options.deferOldConsent ? new Promise(resolve => { releaseOld = resolve; }) : Promise.resolve();
    await controls.context.route(CATALOG, async route => {
      const request = route.request();
      try {
        assert.equal(request.url(), CATALOG); assert.equal(request.method(), 'GET'); assert(!request.postDataBuffer()?.length);
        if (observed.returns) assert.equal(new URL(page.url()).search, '', 'return marker cleared before catalog API');
        assert(++catalogReads <= 50); state.catalogCalls++;
        if (observed.catalogStatus !== 200) { state.expectedFailures.add('/api/operator-demo/catalog'); return await answer(route, {detail: PRIVATE[2]}, observed.catalogStatus); }
        let value = publicCatalog(state); value.capabilities.oauth = true; value.capabilities.google_oauth = clone(GOOGLE_CAPABILITY);
        value.capabilities.credential_types.push('google_oauth');
        if (observed.capability !== undefined) value.capabilities.google_reauthorization = observed.capability;
        if (observed.catalogTransform) value = observed.catalogTransform(value);
        await answer(route, value);
      } catch (_) { state.errors.push('reauthorization catalog boundary refused'); await route.abort(); }
    });
    await controls.context.route(ORIGIN + GOOGLE_CAPABILITY.intents_path, async route => {
      try {
        assert.equal(route.request().url(), ORIGIN + GOOGLE_CAPABILITY.intents_path);
        assert.equal(route.request().method(), 'GET'); assert(!route.request().postDataBuffer()?.length);
        assert(++observed.oldConsentReads <= 12); oldArrived(); await oldGate;
        await answer(route, {apiVersion: 'catchplate.operatorGoogleConsent/v1', intents: observed.initialIntents, limits: {active: 32, retained: 1024},
          productionReady: false, protectedActivationSupported: false});
      } catch (_) { state.errors.push('old consent observation boundary refused'); await route.abort(); }
    });
    await controls.context.route(ORIGIN + PATH + '**', async route => {
      const request = route.request(); const url = new URL(request.url());
      try {
        assert.equal(url.origin, ORIGIN); assert.equal(url.search, ''); assert(observed.reads.length < 24);
        if (request.method() === 'GET') {
          if (observed.returns) assert.equal(new URL(page.url()).search, '', 'return marker cleared before status API');
          assert(!request.postDataBuffer()?.length); observed.reads.push(url.pathname);
          if (url.pathname === PATH + '/' + IDS.credential + '/review') {
            // Active attempts are not an invitation to obtain new eligibility.
            assert(!observed.current || ['adopted', 'denied', 'expired', 'failed'].includes(observed.current.status));
            let result = review(state, observed.reviewChanges); if (options.reviewTransform) result = options.reviewTransform(result);
            return await answer(route, result);
          }
          assert(observed.current && url.pathname === PATH + '/' + observed.current.operation_id, 'recover only the exact public operation locator');
          if (observed.statusCode !== 200) { state.expectedFailures.add(url.pathname); return await answer(route, {detail: PRIVATE[2]}, observed.statusCode); }
          const item = observed.operationTransform ? observed.operationTransform(clone(observed.current)) : observed.current;
          return await answer(route, item);
        }
        assert.equal(url.pathname, PATH); assert.equal(request.method(), 'POST'); assert.deepEqual(observed.capability, CAPABILITY);
        const bytes = request.postDataBuffer(); assert(bytes && bytes.length <= 8192); assert.equal(observed.posts.length, 0, 'never replay a reauthorization POST');
        assert(request.headers()['content-type']?.startsWith('application/json')); const body = JSON.parse(bytes.toString());
        assert.deepEqual(Object.keys(body).sort(), ['affected_rule_ids', 'credential_id', 'expected_credential_generation', 'expected_policy_hash', 'expected_revision', 'operation_id']);
        assert(UUID.test(body.operation_id)); const selected = review(state, observed.reviewChanges);
        for (const key of ['credential_id', 'expected_revision', 'expected_policy_hash', 'expected_credential_generation', 'affected_rule_ids'])
          assert.deepEqual(body[key], selected[key]);
        assert(selected.eligible);
        assert.equal(await page.evaluate(key => sessionStorage.getItem(key), STORAGE), body.operation_id, 'public recovery UUID is fixed before POST');
        observed.posts.push(clone(body)); observed.current = operation(selected, {operation_id: body.operation_id});
        if (options.afterStart) options.afterStart(observed, state);
        if (options.startFault === 'lost') { state.expectedFailures.add(PATH); return await route.abort('failed'); }
        if (options.startFault === '409') { state.expectedFailures.add(PATH); return await answer(route, {detail: PRIVATE[2]}, 409); }
        const result = startReceipt(observed.current);
        if (options.startFault === 'wrong-client') result.authorizationUrl = result.authorizationUrl.replace(account().oauth_client_id, 'other-client.apps.googleusercontent.com');
        await answer(route, result);
      } catch (_) { state.errors.push('reauthorization exact DTO/CAS/locator boundary refused'); await route.abort(); }
    });
    await controls.context.route('https://accounts.google.com/**', async route => {
      try {
        const request = route.request(); assert.equal(observed.posts.length, 1);
        assert.equal(request.url(), startReceipt(observed.current).authorizationUrl); assert.equal(request.method(), 'GET');
        assert(!request.postDataBuffer()?.length && request.isNavigationRequest()); assert.equal(request.frame(), page.mainFrame());
        assert.equal(++observed.navigations, 1);
        await route.fulfill({status: 200, contentType: 'text/html', body: '<link rel="icon" href="data:,"><h1>Synthetic reauthorization destination</h1>'});
      } catch (_) { state.errors.push('reauthorization navigation boundary refused'); await route.abort(); }
    });
    async function landing(id = observed.current?.operation_id || OPERATION, extra = '', initial = false) {
      const target = ORIGIN + '/?' + (initial ? 'operator_google_intent=' : 'operator_google_reauthorization=') +
        id + extra + (initial ? '#connect' : '#credentials');
      const document = execFileSync('python3', ['-B', '-c', 'from catchplate.operator_demo_portal import render; print(render())'],
        {cwd: ROOT, encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024});
      await controls.context.route(target.split('#')[0], async route => {
        assert(++observed.returns <= 2); assert.equal(route.request().url(), target.split('#')[0]);
        assert.equal(route.request().method(), 'GET'); assert(!route.request().postDataBuffer()?.length);
        await route.fulfill({status: 200, contentType: 'text/html', body: document});
      }, {times: 1});
      await page.goto(target, {waitUntil: 'networkidle'}); assert.equal(new URL(page.url()).search, '', 'marker removed before API observation');
      await page.locator(initial ? '#google-consent-panel' : '#google-reauthorization-panel').waitFor({state: 'visible'});
      await page.locator(initial ? '#google-consent-leave:enabled' : '#google-reauthorization-leave:enabled').waitFor({state: 'visible'});
    }
    try {
      await ready(page); await view(page, 'credentials');
      if (options.deferOldConsent) {
        const refreshed = page.waitForResponse(item => item.url() === CATALOG);
        await page.locator('#credentials-refresh').click(); await (await refreshed).finished(); await oldArrival;
        await action(page).waitFor({state: 'visible'});
      } else { await refreshCatalog(page); await ready(page); }
      const preserved = clone({credentials: state.credentials, applications: state.applications, rules: state.rules, revision: state.revision,
        sequence: state.sequence, active: state.active, loaded: state.loaded});
      await exercise(page, state, observed, {...controls, landing, initialLanding: id => landing(id, '', true), releaseOld: () => releaseOld?.()});
      assert(observed.posts.length <= 1 && observed.navigations <= 1);
      assert.deepEqual(state.posts.map(item => item.name), options.allowApplicationCreation ? ['applications'] : [],
        'reauthorization never creates credentials/apps/rules, rotates tokens, revokes or starts initial consent');
      if (!options.allowApplicationCreation && !options.allowCatalogDrift) assert.deepEqual({credentials: state.credentials, applications: state.applications,
        rules: state.rules, revision: state.revision, sequence: state.sequence, active: state.active, loaded: state.loaded}, preserved);
      if (new URL(page.url()).origin === ORIGIN) await noMaterial(page);
    } finally { releaseOld?.(); checkpointStates.delete(page); }
  });
}
async function open(page) {
  await action(page).click(); await panel(page).waitFor({state: 'visible'});
  await page.locator('#google-reauthorization-leave:enabled').waitFor({state: 'visible'});
}
async function checkStatus(page, pattern) {
  try {
    await page.locator('#google-reauthorization-status').filter({hasText: pattern}).waitFor({state: 'visible'});
    await page.locator('#google-reauthorization-leave:enabled').waitFor({state: 'visible'});
  } catch (_) {
    // Fixed categories and bounded counters only: never status text, URLs,
    // account identity, operation UUID, OAuth state, request bodies or tokens.
    const ui = await page.evaluate(() => {
      const text = document.querySelector('#google-reauthorization-status')?.textContent || '';
      const prefixes = [['Checking the exact account', 'checking'], ['Waiting for Google consent.', 'awaiting-consent'],
        ['Saved reauthorization status or the current account could not be verified.', 'unverified'],
        ['The start response or current operation was not confirmed.', 'start-unconfirmed'],
        ['Reauthorization saved for the same account.', 'adopted-confirmed'], ['A replacement receipt exists,', 'adopted-unconfirmed'],
        ['Reauthorization prepared;', 'prepared'], ['Confirming the Google exchange.', 'exchanging'],
        ['A replacement is retained but not active.', 'candidate-held'], ['Reauthorization needs server-side review.', 'review-required'],
        ['Google consent was declined.', 'denied'], ['This consent attempt expired.', 'expired'],
        ['Reauthorization did not complete.', 'failed'], ['Reauthorization is unavailable', 'capability-unavailable'],
        ['Invalid return reference.', 'invalid-return'], ['The operation outcome is unconfirmed.', 'operation-unconfirmed']];
      return {status: prefixes.find(([prefix]) => text.startsWith(prefix))?.[1] || 'other',
        operatorOrigin: location.origin === 'https://operator-catalog.example.test',
        panelVisible: document.querySelector('#google-reauthorization-panel')?.hidden === false,
        leaveEnabled: document.querySelector('#google-reauthorization-leave')?.disabled === false,
        mutationReviewVisible: document.querySelector('#mutation-review')?.hidden === false,
        catalogUnavailable: document.querySelector('#load-error')?.hidden === false};
    }).catch(() => ({status: 'document-unavailable'}));
    const checkpoint = checkpointStates.get(page);
    const counts = checkpoint ? {posts: checkpoint.observed.posts.length,
      reviewReads: checkpoint.observed.reads.filter(path => path.endsWith('/review')).length,
      operationReads: checkpoint.observed.reads.filter(path => !path.endsWith('/review')).length,
      initialConsentReads: checkpoint.observed.oldConsentReads, catalogReads: checkpoint.state.catalogCalls,
      navigations: checkpoint.observed.navigations, returns: checkpoint.observed.returns} : {};
    console.log(JSON.stringify({phase: 'reauthorization-status-checkpoint-failed', group: activeGroup, ui, counts}));
    throw new Error('Reauthorization status checkpoint failed; see fixed-category diagnostic');
  }
}
async function start(page, observed, navigation) {
  try {
    if (navigation) await Promise.all([page.waitForURL(startReceipt({expires_at_epoch: NOW / 1000 + 600}).authorizationUrl,
      {timeout: 5000, waitUntil: 'domcontentloaded'}),
      page.locator('#google-reauthorization-start').click()]);
    else {
      await page.locator('#google-reauthorization-start').click();
      await checkStatus(page, /^The start response or current operation was not confirmed\./);
    }
  } catch (_) {
    const state = await page.evaluate(() => ({operatorOrigin: location.origin === 'https://operator-catalog.example.test',
      leaveEnabled: !document.querySelector('#google-reauthorization-leave')?.disabled,
      reviewVisible: document.querySelector('#mutation-review')?.hidden === false})).catch(() => ({documentAvailable: false}));
    console.log(JSON.stringify({phase: 'reauthorization-checkpoint-failed', expectedNavigation: navigation,
      posts: observed.posts.length, reads: observed.reads.length, navigations: observed.navigations, state}));
    throw new Error('Reauthorization completion checkpoint failed; sanitized counts only');
  }
}
function pureChecks() {
  const state = {...supplied(), revision: 1, active: 'sha256:' + '0'.repeat(63) + '1'};
  const reviewed = review(state); const item = operation(reviewed); const complete = adopted(reviewed);
  assert.deepEqual(pure.projectGoogleReauthorizationReview(reviewed), reviewed);
  assert.equal(pure.projectGoogleReauthorizationReview({...reviewed, eligible: false}).eligible, false);
  assert.deepEqual(pure.projectGoogleReauthorizationOperation(complete), complete);
  assert.equal(pure.validateGoogleReauthorizationStart(startReceipt(item), GOOGLE_CAPABILITY, reviewed, OPERATION, NOW).operation.operation_id, OPERATION);
  for (const change of [{eligible: 'true'}, {expected_credential_generation: 0}, {affected_rule_ids: [IDS.rule, IDS.rule]},
    {scopes: ['openid']}, {original_oauth_intent_id: null}])
    assert.throws(() => pure.projectGoogleReauthorizationReview({...reviewed, ...change}));
  for (const change of [{status: 'healthy'}, {reason: PRIVATE[2]}, {receipt: {}}, {expected_revision: 0},
    {application_ids: [IDS.other, IDS.application]}])
    assert.throws(() => pure.projectGoogleReauthorizationOperation({...item, ...change}));
  for (const change of [{operation_id: OTHER}, {credential_id: OTHER}, {credential_generation: 10},
    {revision: 2}, {policy_hash: 'sha256:' + 'f'.repeat(64)}, {affected_rule_ids: []}])
    assert.throws(() => pure.projectGoogleReauthorizationOperation({...complete, receipt: {...complete.receipt, ...change}}));
  for (const change of [{state: 'wrong'}, {authorizationUrl: startReceipt(item).authorizationUrl.replace('accounts.google.com', 'evil.example.test')},
    {operatorGoogleReauthorization: {...item, operation_id: OTHER}},
    {authorizationUrl: startReceipt(item).authorizationUrl.replace(account().oauth_client_id, 'wrong-client.apps.googleusercontent.com')}])
    assert.throws(() => pure.validateGoogleReauthorizationStart({...startReceipt(item), ...change}, GOOGLE_CAPABILITY, reviewed, OPERATION, NOW));
  const publicItem = pure.projectGoogleReauthorizationOperation({...complete, access_token: PRIVATE[0], refresh_token: PRIVATE[1]});
  for (const value of PRIVATE) assert(!JSON.stringify(publicItem).includes(value));
  const catalog = {credentials: state.credentials, applications: state.applications, access_rules: state.rules};
  assert(pure.googleReauthorizationAccountMatches(reviewed, catalog));
  for (const value of [{...reviewed, credential_id: OTHER}, {...reviewed, provider_subject: 'wrong-subject'},
    {...reviewed, oauth_client_id: 'wrong.apps.googleusercontent.com'}, {...reviewed, affected_rule_ids: []}])
    assert.equal(pure.googleReauthorizationAccountMatches(value, catalog), false);
  assert.deepEqual(pure.googleReauthorizationReturnHint(ORIGIN + '/?operator_google_reauthorization=' + OPERATION + '#credentials'),
    {present: true, id: OPERATION, clean: '/#credentials'});
  for (const query of ['operator_google_reauthorization=bad', 'operator_google_reauthorization=' + OPERATION + '&code=synthetic',
    'operator_google_reauthorization=' + OPERATION + '&operator_google_reauthorization=' + OTHER])
    assert.deepEqual(pure.googleReauthorizationReturnHint(ORIGIN + '/?' + query + '#credentials'),
      {present: true, id: null, clean: '/#credentials'});
  // Actual shared coordinator, without network or a browser. A second owner
  // releasing its observation must never clear another owner's active hold.
  const core = ['workspace_core.js', 'workspace_github.js']
    .map(name => readFileSync(join(ROOT, 'catchplate/operator_demo_web', name), 'utf8')).join('\n');
  const workspace = runInNewContext(core + '\ncreateOperatorWorkspace()', {
    document: {getElementById: () => ({addEventListener() {}, querySelectorAll: () => []})},
    window: {addEventListener() {}}, clearTimeout, setTimeout,
  }, {timeout: 1000});
  workspace.setConsentHold(true, 'google-reauthorization'); workspace.setConsentHold(false, 'google-consent');
  assert.equal(workspace.state.busy, true);
  workspace.setConsentHold(true, 'google-consent'); workspace.setConsentHold(false, 'google-reauthorization');
  assert.equal(workspace.state.busy, true);
  workspace.setConsentHold(false, 'google-consent'); assert.equal(workspace.state.busy, false);
  workspace.state.busy = true; workspace.setConsentHold(true, 'google-reauthorization');
  workspace.setConsentHold(false, 'google-reauthorization'); assert.equal(workspace.state.busy, true);
  workspace.state.busy = false; workspace.state.uncertain = true; workspace.setConsentHold(true, 'google-reauthorization');
  workspace.setConsentHold(false, 'google-reauthorization'); assert.equal(workspace.state.uncertain, true);
  return {ok: true, groups: 1, scope: 'real public validators and independent consent-owner/write holds; no provider or runtime proof'};
}
const tests = [
  ['missing and malformed capability do not expose account maintenance', async browser => {
    for (const capability of [undefined, null, {...CAPABILITY, path: '/api/operator-demo/oauth/google/start'}, {...CAPABILITY, preserves_assignments: false}])
      await fixture(browser, {capability}, async (page, state, observed) => {
        assert.equal(await action(page).count(), 0); assert(await page.locator('#credential-add').isEnabled());
        assert.equal(observed.reads.length, 0); assert.equal(observed.posts.length, 0); assert.equal(observed.navigations, 0);
      });
  }],
  ['exact active account review shows its assigned apps and rules without recreating them', browser => fixture(browser, {}, async (page, state, observed) => {
    await open(page); const text = await page.locator('#google-reauthorization-review').innerText();
    assert.match(text, /ordinary-fixture@example.test/); assert(!text.includes('other-fixture@example.test'));
    assert.match(text, /Current reviewed credential version\s+7/); assert.match(text, /Assigned clients \(2\)/);
    for (const row of [...state.applications, ...state.rules]) assert(text.includes(row.name));
    assert.match(await panel(page).innerText(), /not Disconnect|does not disconnect/i);
    assert.match(await panel(page).innerText(), /not a Gmail request test/i);
    assert(await page.locator('#google-reauthorization-start').isEnabled());
    assert.equal(await action(page, STATIC).count(), 0); assert.equal(observed.posts.length, 0);
    assert.deepEqual(observed.reads, [PATH + '/' + IDS.credential + '/review']);
    await screenshot(page, 'same-account-review-desktop');
  })],
  ['cancelled confirmation sends nothing and preserves the explicit review', browser => fixture(browser, {}, async (page, state, observed) => {
    await open(page); state.cancelNextDialog = true; await page.locator('#google-reauthorization-start').click();
    assert.match(state.dialogs.at(-1), /ordinary-fixture@example.test.*stored credential version 7/);
    assert.equal(observed.posts.length, 0); assert(await page.locator('#google-reauthorization-start').isEnabled());
    assert.equal(await page.evaluate(key => sessionStorage.getItem(key), STORAGE), null);
  })],
  ['one explicit POST has a prior public operation UUID and one validated navigation', browser => fixture(browser, {}, async (page, state, observed) => {
    await open(page); await noMaterial(page); await start(page, observed, true);
    assert.equal(observed.posts.length, 1); assert.equal(observed.navigations, 1);
    assert.equal(observed.posts[0].credential_id, IDS.credential);
    assert.deepEqual(observed.posts[0].affected_rule_ids, [IDS.rule, SECOND_RULE].sort());
    assert.deepEqual(observed.reads, [PATH + '/' + IDS.credential + '/review', PATH + '/' + observed.posts[0].operation_id]);
    assert.equal(state.revision, 1); assert.equal(state.posts.length, 0);
  })],
  ['lost start uses exact GET recovery and keeps shared uncertainty until informed review', browser => fixture(browser, {startFault: 'lost'}, async (page, state, observed) => {
    await open(page); await start(page, observed, false); assert.equal(observed.posts.length, 1); assert.equal(observed.navigations, 0);
    const id = observed.posts[0].operation_id; assert.equal(await page.evaluate(key => sessionStorage.getItem(key), STORAGE), id);
    await page.locator('#google-reauthorization-refresh').click(); await checkStatus(page, /^Waiting for Google consent\./);
    assert(observed.reads.slice(1).every(path => path === PATH + '/' + id));
    assert(await page.locator('#google-reauthorization-start').isHidden()); assert(await page.locator('#credential-add').isDisabled());
    await page.locator('#google-reauthorization-leave').click(); assert(await panel(page).isHidden());
    assert(await page.locator('#credential-add').isDisabled()); assert(await page.locator('#mutation-review').isVisible());
    assert.equal(await page.evaluate(key => sessionStorage.getItem(key), STORAGE), id, 'leave does not erase an uncertain recovery locator');
    await refreshCatalog(page); await page.locator('#mutation-review-confirm').click(); await ready(page);
    assert.equal(observed.posts.length, 1); assert.match(state.dialogs.at(-1), /does not cancel.*disconnect.*retry/is);
  })],
  ['reload recovers the exact operation while an explicit initial-consent return retains precedence', async browser => {
    await fixture(browser, {startFault: 'lost'}, async (page, state, observed) => {
      await open(page); await start(page, observed, false); const id = observed.posts[0].operation_id;
      const priorReads = observed.reads.length; const priorInitialConsentReads = observed.oldConsentReads;
      // open() already selected #credentials; goto of that same hash-bearing URL
      // may be same-document navigation and cannot prove session restoration.
      const response = await page.reload({waitUntil: 'networkidle'});
      assert(response && response.status() === 200 && response.request().isNavigationRequest(), 'a new main document is required');
      await checkStatus(page, /^Waiting for Google consent\./);
      assert(observed.reads.length > priorReads, 'the new document performs fresh exact-operation recovery');
      assert.equal(observed.oldConsentReads, priorInitialConsentReads, 'unselected initial consent does not start a competing recovery read');
      assert(observed.reads.slice(1).every(path => path === PATH + '/' + id));
      assert.equal(observed.posts.length, 1); assert.equal(observed.navigations, 0); assert(await page.locator('#credential-add').isDisabled());
    });
    await fixture(browser, {}, async (page, state, observed, controls) => {
      observed.current = operation(review(state));
      observed.initialIntents = [{id: INITIAL_OPERATION, name: 'Earlier Google connection', provider_id: 'google',
        permission_preset: 'gmail_readonly', scopes: [...SCOPES], created_at: new Date(NOW).toISOString(),
        expires_at_epoch: NOW / 1000 + 600, status: 'awaiting_consent'}];
      // Seed only the documented public recovery locator from a prior document.
      // The preceding context proves its real one-POST write before navigation.
      await page.evaluate(([key, value]) => sessionStorage.setItem(key, value), [STORAGE, OPERATION]);
      await controls.initialLanding(INITIAL_OPERATION);
      assert(await page.locator('#google-consent-panel').isVisible()); assert(await panel(page).isHidden());
      assert.match(await page.locator('#google-consent-status').innerText(), /^Waiting for Google consent/);
      assert.equal(new URL(page.url()).search, ''); assert.equal(observed.reads.length, 0, 'explicit initial return suppresses automatic reauthorization reads');
      assert.equal(await page.evaluate(key => sessionStorage.getItem(key), STORAGE), OPERATION);
      assert(await page.locator('#credential-add').isDisabled()); assert.equal(observed.posts.length, 0);
      await page.locator('#google-consent-leave').click(); await ready(page); await view(page, 'credentials');
      await open(page); await checkStatus(page, /^Waiting for Google consent\./);
      assert.deepEqual(observed.reads, [PATH + '/' + OPERATION]); assert(await page.locator('#google-reauthorization-start').isHidden());
      assert.equal(observed.posts.length, 0); assert.equal(observed.navigations, 0);
      assert.equal(await page.evaluate(key => sessionStorage.getItem(key), STORAGE), OPERATION);
    });
  }],
  ['untrusted start link and mismatched saved operation refuse navigation and require review', async browser => {
    for (const options of [{startFault: 'wrong-client'}, {afterStart(observed) { observed.operationTransform = item => ({...item, expected_credential_generation: 8}); }}])
      await fixture(browser, options, async (page, state, observed) => {
        await open(page); await start(page, observed, false);
        assert.equal(observed.posts.length, 1); assert.equal(observed.navigations, 0);
        assert(await page.locator('#mutation-review').isVisible()); assert(await page.locator('#credential-add').isDisabled());
        assert(await page.locator('#google-reauthorization-start').isHidden());
      });
  }],
  ['adopted exact receipt joins fresh identity and permits a later legitimate refresh generation', async browser => {
    for (const generation of [8, 12]) await fixture(browser, {}, async (page, state, observed, controls) => {
      observed.current = adopted(review(state)); observed.current.access_token = PRIVATE[0];
      observed.reviewChanges = {expected_credential_generation: generation, eligible: generation === 8};
      await controls.landing(); await checkStatus(page, /^Reauthorization saved for the same account\./);
      assert.match(await page.locator('#google-reauthorization-status').innerText(), /permissions and application tokens were preserved.*not been tested/is);
      assert(observed.reads.includes(PATH + '/' + OPERATION)); assert(observed.reads.includes(PATH + '/' + IDS.credential + '/review'));
      assert(await page.locator('#credential-add').isEnabled()); assert.equal(observed.posts.length, 0);
      if (generation === 8) await screenshot(page, 'same-account-adopted-desktop');
      await page.locator('#google-reauthorization-leave').click(); assert.equal(await page.evaluate(key => sessionStorage.getItem(key), STORAGE), null);
    });
  }],
  ['old active account and non-adopted statuses never prove replacement success', async browser => {
    const labels = {prepared: /prepared.*no saved authorization link is replayed/is, awaiting_consent: /Waiting for Google consent/,
      exchanging: /Confirming the Google exchange/, candidate_held: /retained but not active/, review_required: /needs server-side review/};
    for (const [status, label] of Object.entries(labels)) await fixture(browser, {}, async (page, state, observed, controls) => {
      observed.current = operation(review(state), {status}); await controls.landing(); await checkStatus(page, label);
      assert(!await page.locator('#google-reauthorization-status').innerText().then(text => text.includes('saved for the same account')));
      assert(await page.locator('#credential-add').isDisabled()); assert(await page.locator('#google-reauthorization-start').isHidden());
      assert(observed.reads.every(path => path === PATH + '/' + OPERATION), 'pending recovery must not request a new eligibility review');
      if (status === 'candidate_held') { await page.setViewportSize({width: 390, height: 844}); await screenshot(page, 'candidate-held-mobile');
        assert(await page.locator('#google-reauthorization-refresh').isVisible()); assert(await page.locator('#google-reauthorization-leave').isVisible());
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)); }
      assert.equal(observed.posts.length, 0);
    });
  }],
  ['adoption requires original intent, advanced generation and matching current account metadata', async browser => {
    for (const changes of [{expected_credential_generation: 7}, {expected_credential_generation: 8, original_oauth_intent_id: OTHER},
      {expected_credential_generation: 8, provider_subject: 'different-subject'}, {expected_credential_generation: 8, application_ids: []}])
      await fixture(browser, {}, async (page, state, observed, controls) => {
        observed.current = adopted(review(state)); observed.reviewChanges = changes;
        await controls.landing(); await checkStatus(page, /could not be verified/);
        assert(await page.locator('#credential-add').isDisabled()); assert(await page.locator('#google-reauthorization-start').isHidden());
        assert.equal(observed.posts.length, 0);
      });
  }],
  ['malformed, ineligible and stale initial review cannot start a new operation', async browser => {
    for (const changes of [{eligible: false}, {expected_revision: 2}, {provider_account: 'different@example.test'}, {scopes: ['openid']}])
      await fixture(browser, {reviewTransform: value => ({...value, ...changes})}, async (page, state, observed) => {
        await open(page); assert(await page.locator('#google-reauthorization-start').isDisabled());
        assert.equal(observed.posts.length, 0); assert.equal(observed.navigations, 0);
        assert(await page.locator('#credential-add').isEnabled(), 'unstarted review does not permanently hold unrelated writes');
      });
  }],
  ['catalog drift invalidates the review without silently rebasing or submitting', browser => fixture(browser, {allowCatalogDrift: true}, async (page, state, observed) => {
    await open(page); assert(await page.locator('#google-reauthorization-start').isEnabled()); state.revision++;
    await refreshCatalog(page); assert(await page.locator('#google-reauthorization-start').isDisabled());
    assert.match(await page.locator('#google-reauthorization-status').innerText(), /changed.*fresh review/);
    assert.equal(observed.posts.length, 0);
    await page.locator('#google-reauthorization-refresh').click(); await page.locator('#google-reauthorization-start:enabled').waitFor({state: 'visible'});
    assert.equal(observed.posts.length, 0, 'a deliberate fresh review is not consent submission');
  })],
  ['denied expired and failed are distinct terminal observations without health or rollback claims', async browser => {
    for (const [status, reason, label] of [['denied', 'consent_denied', /consent was declined/], ['expired', null, /attempt expired/],
      ['failed', 'exchange_failed', /did not complete.*do not assume provider-side rollback/is]])
      await fixture(browser, {}, async (page, state, observed, controls) => {
        observed.current = operation(review(state), {status, reason, private_error: PRIVATE[2],
          ...(status === 'expired' ? {expires_at_epoch: NOW / 1000 - 1} : {})});
        await controls.landing(); await checkStatus(page, label); assert(await page.locator('#credential-add').isEnabled());
        assert(await page.locator('#google-reauthorization-start').isHidden()); assert.equal(observed.posts.length, 0);
        assert(!await page.locator('#google-reauthorization-status').innerText().then(text => /healthy|provider.*revoked/i.test(text)));
      });
  }],
  ['held one-time application token blocks provider navigation and survives account review', browser => fixture(browser,
    {applications: [application()], rules: [gmailRule()], allowApplicationCreation: true}, async (page, state, observed) => {
      await view(page, 'applications'); await page.locator('#application-name').fill('Save before consent');
      await page.locator('#application-create').click(); await page.locator('#one-time-access').waitFor({state: 'visible'});
      await ready(page); const token = await page.locator('#client-token').inputValue(); assert(token.length >= 32);
      await view(page, 'credentials'); await open(page); assert(await page.locator('#google-reauthorization-token-warning').isVisible());
      assert(await page.locator('#google-reauthorization-start').isDisabled()); assert.equal(await page.locator('#client-token').inputValue(), token);
      assert.equal(observed.posts.length, 0); assert.equal(observed.navigations, 0);
      await view(page, 'applications'); await page.locator('#dismiss-token').click(); assert.equal(await page.locator('#client-token').inputValue(), '');
      await view(page, 'credentials'); assert(await page.locator('#google-reauthorization-start').isEnabled());
      assert.equal(observed.posts.length, 0, 'token acknowledgement never automatically continues to Google');
    })],
  ['a late initial-consent observation cannot release the selected reauthorization hold', browser => fixture(browser,
    {deferOldConsent: true, startFault: 'lost'}, async (page, state, observed, controls) => {
      await open(page); await start(page, observed, false); assert(await page.locator('#credential-add').isDisabled());
      const priorCatalogReads = state.catalogCalls;
      const completed = page.waitForResponse(item => item.url() === ORIGIN + GOOGLE_CAPABILITY.intents_path);
      controls.releaseOld(); await (await completed).finished(); await page.waitForLoadState('networkidle');
      assert.equal(state.catalogCalls, priorCatalogReads, 'a late unselected consent read cannot supersede selected recovery with another catalog refresh');
      // Clear only generic mutation uncertainty while the reauthorization hold
      // remains: its review-confirm control is intentionally ineffective.
      assert(await page.locator('#credential-add').isDisabled()); assert(await page.locator('#mutation-review-confirm').isDisabled());
      await page.locator('#mutation-review-confirm').dispatchEvent('click');
      assert(await page.locator('#mutation-review').isVisible()); assert(await page.locator('#credential-add').isDisabled());
      await page.locator('#google-reauthorization-leave').click(); assert(await page.locator('#credential-add').isDisabled());
      await refreshCatalog(page); await page.locator('#mutation-review-confirm').click(); await ready(page);
      assert.equal(observed.posts.length, 1); assert.equal(observed.navigations, 0);
    })],
  ['capability withdrawal preserves recovery and requires explicit exit rather than clearing a pending attempt', browser => fixture(browser, {}, async (page, state, observed, controls) => {
    observed.current = operation(review(state)); await controls.landing(); await checkStatus(page, /Waiting for Google consent/);
    observed.capability = null; await refreshCatalog(page); assert(await page.locator('#google-reauthorization-refresh').isDisabled());
    assert(await page.locator('#credential-add').isDisabled());
    assert.equal(await page.locator('#google-reauthorization-status').innerText(),
      'Reauthorization is unavailable in this deployment. No request will be retried.');
    await page.locator('#google-reauthorization-leave').click(); await ready(page); assert.equal(observed.posts.length, 0);
    assert(await panel(page).isHidden());
  })],
  ['unavailable exact operation after lost start is not permission to retry', async browser => {
    for (const statusCode of [404, 503]) await fixture(browser, {startFault: 'lost', afterStart(observed) { observed.statusCode = statusCode; }},
      async (page, state, observed) => {
        await open(page); await start(page, observed, false); await page.locator('#google-reauthorization-refresh').click();
        await checkStatus(page, /could not be verified/); assert.equal(observed.posts.length, 1); assert.equal(observed.navigations, 0);
        assert(observed.reads.slice(1).every(path => path === PATH + '/' + observed.posts[0].operation_id));
        assert(await page.locator('#google-reauthorization-start').isHidden()); assert(await page.locator('#credential-add').isDisabled());
      });
  }],
  ['invalid callback marker is removed without status lookup or a new start', browser => fixture(browser, {}, async (page, state, observed, controls) => {
    await controls.landing(OPERATION, '&code=' + PRIVATE[0]); await checkStatus(page, /Invalid return reference/);
    assert.equal(observed.reads.length, 0); assert.equal(observed.posts.length, 0); assert.equal(new URL(page.url()).search, '');
    assert(await page.locator('#google-reauthorization-start').isHidden());
  })],
];
function selection(argv) {
  if (!argv.length) return {from: 1, pure: true};
  if (argv.length === 2 && argv[0] === '--from-group' && /^(?:[1-9]|1[0-8])$/.test(argv[1]))
    return {from: Number(argv[1]), pure: false};
  throw new Error('Usage: test_operator_google_reauthorization_browser.cjs [--from-group 1..18]');
}
async function main() {
  const selected = selection(process.argv.slice(2)); const before = await hashes();
  if (selected.pure) console.log(JSON.stringify(pureChecks()));
  const artifactRoot = '/srv/catchplate-fast/projects/catchplate-operator-artifacts';
  assert((await stat(artifactRoot)).isDirectory()); artifacts = await mkdtemp(join(artifactRoot, 'google-reauthorization-synthetic-'));
  console.log(JSON.stringify({phase: 'prepared', sourceHashes: before, artifacts, selection: selected,
    renderedGroups: tests.length - selected.from + 1, scope: 'synthetic intercepted UI; no provider, callback, adoption or dispatch acceptance'}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  let expired = false;
  const deadline = setTimeout(() => { expired = true; browser.close().catch(() => {}); }, 150000);
  try {
    for (let index = selected.from - 1; index < tests.length; index++) {
      activeGroup = index + 1;
      assert(!expired, 'absolute suite deadline'); const [name, execute] = tests[index];
      await execute(browser); console.log(JSON.stringify({ok: true, group: index + 1, name}));
    }
  } finally { clearTimeout(deadline); await browser.close(); }
  assert(!expired); assert.deepEqual(await hashes(), before, 'all fixture and rendered source inputs remain frozen');
  console.log(JSON.stringify({ok: true, renderedGroups: tests.length - selected.from + 1, pureGroups: selected.pure ? 1 : 0, artifacts,
    boundary: 'No real OAuth, credential adoption, provider/runtime health, proxy dispatch, downloads or live deployment tested'}));
}
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = {main, selection};

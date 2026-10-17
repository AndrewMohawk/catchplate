#!/usr/bin/env node
// Synthetic rendered catalog/DTO acceptance only. No consent, provider, proxy,
// CA download, generated command or backend process is contacted or executed.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFile, mkdtemp, stat} = require('node:fs/promises');
const {readFileSync} = require('node:fs');
const {join, resolve} = require('node:path');
const vm = require('node:vm');
const {ready, view, openRestrictions, credential, application, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture, publicCatalog, google, digest, pair, step, review, grant, downloadedConfig} = require('./test_operator_ordinary_modes_browser.cjs');
const {clientCredentialInput, credentialHeaderTarget} = require('../catchplate/operator_demo_web/app.js');
const {projectGoogleCapability} = require('../catchplate/operator_demo_web/workspace_google.js');
const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const GMAIL = 'https://gmail.googleapis.com';
const PATH = '/gmail/v1/users/me/messages';
const BUNDLE = 'gmail_read_v1';
const MODE = 'gmail_read_json_v1';
const QUERY = ['alt', 'format', 'includeSpamTrash', 'labelIds', 'maxResults', 'metadataHeaders', 'pageToken', 'prettyPrint', 'q'];
const HEADERS = ['accept', 'user-agent', 'x-goog-api-client'];
const LEGACY_HEADERS = ['accept', 'accept-encoding', 'user-agent', 'x-goog-api-client'];
const SCOPES = ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'];
const PRIVATE = ['synthetic-gmail-provider-private-never-render', 'synthetic-gmail-refresh-private-never-render'];
const DUMMY = "Bearer GMAIL-DUMMY-'literal'-$value";
const descriptor = () => ({operation_bundle: BUNDLE, create_path: '/api/operator-demo/access-rules/gmail-read',
  credential_type: 'google_oauth', permission_preset: 'gmail_readonly', api_origin: GMAIL, methods: ['GET'],
  paths: [PATH, PATH + '/{message_id}'], query_mode: 'orderedFormV1', age_policy: {mode: 'unrestricted'}, response_mode: MODE,
  response_contract: {mode: 'gmailReadJsonV1', body_presence: 'required', content_types: ['application/json'],
    success_status_codes: [200], error_status_codes: [400, 401, 403, 404, 429, 500, 502, 503, 504],
    max_body_bytes: 1048576, max_error_body_bytes: 65536, unlisted_header_policy: 'discardUnselectedV1'}});
const googleCapability = () => ({schema: 'catchplate.operatorGoogleCapability/v1', profile: 'operator-google-v1', provider_id: 'google',
  permission_preset: 'gmail_readonly', scopes: [...SCOPES], api_origins: [GMAIL], authorization_origin: 'https://accounts.google.com',
  authorization_path: '/o/oauth2/v2/auth', redirect_uri: ORIGIN + '/api/oauth/callback/google',
  start_path: '/api/operator-demo/oauth/google/start', intents_path: '/api/operator-demo/oauth/google/intents'});
const bundleRule = (changes = {}) => rule({name: 'Read Gmail', upstream_url: GMAIL + PATH, methods: ['GET'],
  request_fields: [], response_fields: [], query_keys: [...QUERY], allowed_headers: [...HEADERS], response_mode: MODE,
  credential_input: 'insert', operation_bundle: BUNDLE, age_policy: {mode: 'unrestricted'}, query_mode: 'orderedFormV1', ...changes});
const options = (changes = {}) => ({credentials: [google({secret: PRIVATE[0], refresh_token: PRIVATE[1]})], applications: [application()],
  responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'], requestBodyModes: ['preserve_json_v1'],
  credentialInputModes: ['insert', 'replace_exact'], allowedUpstreams: [GMAIL], ...changes});
function catalog(state) {
  const value = publicCatalog(state);
  value.capabilities.oauth = state.googleEnabled;
  value.capabilities.google_oauth = state.googleEnabled ? googleCapability() : null;
  value.capabilities.credential_types = state.googleEnabled ? ['bearer', 'header', 'google_oauth'] : ['bearer', 'header'];
  if (state.bundles !== undefined) value.capabilities.operation_bundles = state.bundles;
  return state.gmailTransform ? state.gmailTransform(value) : value;
}
// Independent API oracle: derive server fields, never echo arbitrary editor
// fields into a response and never accept query_mode from the browser.
function admit(state, body) {
  const keys = ['name', 'application_id', 'credential_id', 'operation_bundle', 'age_policy', 'credential_input', 'expected_revision', 'expected_policy_hash'];
  assert.deepEqual(Object.keys(body).sort(), [...keys, ...(body.credential_input === 'replace_exact' ? ['placeholder'] : [])].sort());
  assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
  assert.equal(body.name, 'Read Gmail'); assert.equal(body.operation_bundle, BUNDLE); assert.deepEqual(body.age_policy, {mode: 'unrestricted'});
  assert(state.googleEnabled && state.bundles?.some(value => JSON.stringify(value) === JSON.stringify(descriptor())));
  const account = state.credentials.find(value => value.id === body.credential_id && value.status === 'active');
  assert.equal(account?.auth_type, 'google_oauth'); assert.deepEqual(account.scopes, SCOPES);
  assert(state.applications.some(value => value.id === body.application_id && value.status === 'active'));
  assert(state.credentialInputModes.includes(body.credential_input));
  if (body.credential_input === 'replace_exact') assert(typeof body.placeholder === 'string' && /^[\x20-\x7e]{1,1024}$/.test(body.placeholder) && body.placeholder === body.placeholder.trim());
  const id = state.rules.length ? '55555555-5555-4555-8555-555555555555' : IDS.rule;
  assert(!state.rules.some(value => value.id === id));
  const payload = Object.fromEntries(Object.entries(body).filter(([key]) => !key.startsWith('expected_')));
  const saved = bundleRule({...payload, id, route_id: 'operator.' + id});
  state.rules.push(saved); state.revision++; state.active = digest(++state.sequence);
  if (state.autoLoad) state.loaded = state.active;
  return {access_rule: catalog(state).access_rules.find(value => value.id === id), revision: state.revision,
    policy: catalog(state).policy};
}
async function fixture(browser, config, exercise) {
  return ordinaryFixture(browser, config, async (page, state, controls) => {
    state.googleEnabled = config.googleEnabled !== false;
    state.bundles = Object.hasOwn(config, 'bundles') ? config.bundles : [descriptor()];
    state.gmailTransform = config.gmailTransform;
    const observed = {posts: [], reads: 0, requests: 0};
    const handler = async route => {
      const request = route.request(); const url = new URL(request.url());
      try {
        assert.equal(url.origin, ORIGIN); assert(!url.search); assert(++observed.requests <= 100);
        const bytes = request.postDataBuffer(); let result;
        if (url.pathname === '/api/operator-demo/oauth/google/intents') {
          assert.equal(request.method(), 'GET'); assert(!bytes?.length); assert(state.googleEnabled);
          result = {apiVersion: 'catchplate.operatorGoogleConsent/v1', intents: [], limits: {active: 32, retained: 1024},
            productionReady: false, protectedActivationSupported: false};
        } else if (url.pathname === '/api/operator-demo/catalog') {
          assert.equal(request.method(), 'GET'); assert(!bytes?.length); observed.reads++; state.catalogCalls++;
          if (state.gmailCatalogFailure) {
            state.expectedFailures.add(url.pathname); return await route.fulfill({status: 503, contentType: 'application/json', body: '{}'});
          }
          result = catalog(state);
        } else {
          assert.equal(url.pathname, '/api/operator-demo/access-rules/gmail-read'); assert.equal(request.method(), 'POST');
          assert(bytes && bytes.length <= 4096 && observed.posts.length < 2); assert(request.headers()['content-type']?.startsWith('application/json'));
          const body = JSON.parse(bytes.toString()); observed.posts.push(body); result = admit(state, body);
          if (config.failCatalogAfterSave) state.gmailCatalogFailure = true;
          if (config.loseReceipt) { state.expectedFailures.add(url.pathname); return await route.abort('failed'); }
        }
        await route.fulfill({status: request.method() === 'POST' ? 201 : 200, contentType: 'application/json', body: JSON.stringify(result)});
      } catch (error) { state.errors.push('Gmail fixture contract: ' + error.message); await route.abort(); }
    };
    await controls.context.route('**/api/operator-demo/catalog', handler);
    await controls.context.route('**/api/operator-demo/access-rules/gmail-read', handler);
    await controls.context.route('**/api/operator-demo/oauth/google/intents', handler);
    await page.reload({waitUntil: 'domcontentloaded'});
    await exercise(page, state, observed, controls);
    for (const secret of PRIVATE) assert(!(await page.locator('html').innerHTML()).includes(secret));
    assert(observed.posts.length <= 1, 'one explicit grant; no automatic retry');
  });
}
async function refresh(page, state) {
  const before = state.catalogCalls;
  const response = page.waitForResponse(value => value.url() === ORIGIN + '/api/operator-demo/catalog' && value.request().method() === 'GET');
  await page.locator('#connect-status-refresh').click();
  await (await response).finished();
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
  await page.waitForFunction(() => document.querySelector('#load-error').hidden);
  assert(state.catalogCalls > before);
}
async function commandReady(page) { await page.waitForFunction(() => !document.querySelector('#copy-command').disabled); }
async function bundleForm(page) {
  await pair(page); assert.equal(await page.locator('#connect-operation').inputValue(), BUNDLE);
  // These retained controls exercise custom HTTP insertion/replacement, not
  // the official SDK's separately gated Basic-login and fixed-dummy contract.
  await page.locator('#connect-gmail-client').selectOption('custom');
  for (const id of ['connect-path', 'connect-response-mode', 'connect-query-keys', 'connect-request-body-mode']) {
    assert(await page.locator('#' + id).isHidden()); assert(await page.locator('#' + id).isDisabled());
  }
  assert.match(await page.locator('#connect-gmail-summary').innerText(), /Read Gmail.*pagination.*individual.*No age restriction/is);
}
const SOURCE_FILES = ['scripts/test_operator_gmail_bundle_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
  'scripts/test_operator_ordinary_modes_browser.cjs', 'catchplate/operator_demo_portal.py', ...['index.html', 'style.css', 'app.js',
    'workspace_core.js', 'workspace_github.js', 'workspace_google.js', 'workspace_resources.js', 'workspace_applications.js', 'workspace_proxy_audit.js',
    'workspace_connect.js'].map(name => 'catchplate/operator_demo_web/' + name)];
let artifacts;
async function hashes() { return Object.fromEntries(await Promise.all(SOURCE_FILES.map(async path =>
  [path, createHash('sha256').update(await readFile(join(ROOT, path))).digest('hex')]))); }
async function screenshot(page, name) { await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true, mask: [page.locator('#client-token')]}); }
function pureChecks() {
  const source = ['workspace_core.js', 'workspace_github.js']
    .map(name => readFileSync(join(ROOT, 'catchplate/operator_demo_web', name), 'utf8')).join('\n');
  const state = {credentials: [google({secret: PRIVATE[0]})], applications: [application()], rules: [bundleRule()],
    responseModes: ['projected_json'], credentialInputModes: ['insert', 'replace_exact'], requestBodyModes: ['preserve_json_v1'],
    revision: 1, sequence: 1, active: digest(1), loaded: digest(1), allowedUpstreams: [GMAIL], googleEnabled: true, bundles: [descriptor()]};
  const project = input => JSON.parse(JSON.stringify(vm.runInNewContext(source + '\nprojectCatalog(input);',
    {input, clientCredentialInput, credentialHeaderTarget, projectGoogleCapability, location: {origin: ORIGIN}}, {timeout: 1000})));
  const valid = project(catalog(state)); assert.equal(valid.access_rules[0].operation_bundle, BUNDLE);
  assert.deepEqual(valid.access_rules[0].age_policy, {mode: 'unrestricted'}); assert.equal(valid.access_rules[0].query_mode, 'orderedFormV1');
  assert(!JSON.stringify(valid).includes(PRIVATE[0]));
  const legacy = catalog(state); delete legacy.access_rules[0].query_mode; legacy.access_rules[0].allowed_headers = [...LEGACY_HEADERS];
  assert(!Object.hasOwn(project(legacy).access_rules[0], 'query_mode'));
  const mismatchedLegacy = catalog(state); delete mismatchedLegacy.access_rules[0].query_mode; assert.throws(() => project(mismatchedLegacy));
  for (const change of [{operation_bundle: null}, {operation_bundle: 'future'}, {age_policy: {mode: 'last_30_days'}},
    {age_policy: {mode: 'unrestricted', secret: PRIVATE[0]}}, {query_mode: null}, {query_mode: 'future'},
    {methods: ['POST']}, {query_keys: []}, {allowed_headers: ['accept']}, {allowed_headers: LEGACY_HEADERS}, {request_fields: ['body']}, {response_fields: ['id']},
    {request_body_mode: 'preserve_json_v1'}, {response_mode: 'unfiltered_json_or_empty_v2'}, {upstream_url: GMAIL + '/gmail/v1/users/other/messages'}]) {
    const value = catalog(state); Object.assign(value.access_rules[0], change); assert.throws(() => project(value));
  }
  const mixed = catalog(state); delete mixed.access_rules[0].operation_bundle; assert.throws(() => project(mixed));
  const wrongAccount = catalog(state); wrongAccount.credentials = [credential()]; assert.throws(() => project(wrongAccount));
  for (const bundles of [null, [{}], [descriptor(), descriptor()], [{...descriptor(), create_path: '/other'}],
    [{...descriptor(), response_contract: {...descriptor().response_contract, body_presence: 'optional'}}]]) {
    const value = catalog(state); value.capabilities.operation_bundles = bundles; assert.throws(() => project(value));
  }
  return {ok: true, pureGroups: 1, scope: 'strict bundle/capability projection and legacy absence; no runtime'};
}
const tests = [
  ['fresh Google journey needs no path, method, query or response decisions and grants only after review', browser => fixture(browser, options(), async (page, state, observed) => {
    await bundleForm(page); assert.equal(state.posts.length, 0); assert.equal(observed.posts.length, 0);
    await screenshot(page, 'gmail-permission-desktop'); await review(page);
    assert.match(await page.locator('#connect-review-details').innerText(), /Read Gmail.*pagination.*individual.*Unrestricted/is);
    assert.equal(observed.posts.length, 0); await screenshot(page, 'gmail-review-desktop');
    await grant(page); await commandReady(page); assert.equal(observed.posts.length, 1); assert.equal(state.posts.length, 0);
    assert.deepEqual(observed.posts[0], {name: 'Read Gmail', application_id: IDS.application, credential_id: IDS.credential,
      operation_bundle: BUNDLE, age_policy: {mode: 'unrestricted'}, credential_input: 'insert', expected_revision: 1, expected_policy_hash: digest(1)});
    assert.equal(state.rules[0].query_mode, 'orderedFormV1');
    await view(page, 'access-rules');
    const card = await page.locator('#access-rules-list [data-resource-id="' + IDS.rule + '"]').innerText();
    assert.match(card, /Read Gmail.*List messages.*pagination.*individual.*Unrestricted/is);
    assert.match(card, /1 MiB.*64 KiB.*No empty 204/is);
  })],
  ['pending exact policy blocks setup until activation; list and actual-ID read commands are separate', browser => fixture(browser, options({autoLoad: false}), async (page, state) => {
    await bundleForm(page); await review(page); await grant(page); assert(await page.locator('#connect-setup-slot').isHidden());
    assert.match(await page.locator('#connect-activation').innerText(), /Waiting/);
    state.loaded = state.active; await refresh(page, state); await commandReady(page);
    assert((await page.locator('#client-command').innerText()).endsWith("'" + GMAIL + PATH + "'"));
    await page.locator('#gmail-client-operation').selectOption('message'); assert(await page.locator('#copy-command').isDisabled());
    await page.locator('#gmail-message-id').fill('../profile'); assert(await page.locator('#copy-command').isDisabled());
    await page.locator('#gmail-message-id').fill('18c4a7e8fa3a1234'); await commandReady(page);
    const command = await page.locator('#client-command').innerText(); assert(command.includes(GMAIL + PATH + '/18c4a7e8fa3a1234'));
    assert(command.includes('Proxy-Authorization: Bearer $CATCHPLATE_PROXY_TOKEN')); assert(!/--data|--insecure|--compressed/.test(command));
    await screenshot(page, 'gmail-message-template-desktop'); await page.setViewportSize({width: 390, height: 844});
    await screenshot(page, 'gmail-message-template-mobile'); assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
  })],
  ['new app one-time token feeds private bundle export without provider material or implicit rotation', browser => fixture(browser, options({applications: []}), async (page, state, observed) => {
    await ready(page); await view(page, 'connect'); await page.locator('#connect-use-saved').click();
    await page.locator('#connect-credential-choice').selectOption(IDS.credential); await page.locator('#connect-credential-next').click(); await step(page, 'application');
    await page.locator('#connect-application-name').fill('Inbox worker'); await page.locator('#connect-application-next').click(); await step(page, 'access');
    assert.equal(await page.locator('#connect-operation').inputValue(), BUNDLE); assert(await page.locator('#connect-path').isHidden());
    assert(await page.locator('#connect-response-mode').isDisabled());
    const token = await page.locator('#client-token').inputValue(); assert(token.startsWith('synthetic_application_'));
    await page.locator('#connect-gmail-client').selectOption('custom');
    await page.locator('#connect-credential-input').selectOption('replace_exact'); await page.locator('#connect-placeholder').fill(DUMMY);
    await review(page); await grant(page); await commandReady(page);
    assert.equal(observed.posts[0].placeholder, DUMMY); assert.equal(state.posts.length, 1); assert.equal(state.posts[0].name, 'applications');
    const config = await downloadedConfig(page); assert.equal(config.operation_bundle, BUNDLE); assert.equal(config.response_mode, MODE);
    assert.deepEqual(config.age_policy, {mode: 'unrestricted'}); assert.equal(config.query_mode, 'orderedFormV1');
    assert.equal(config.operations[0].url, GMAIL + PATH); assert.equal(config.operations[1].url_template, GMAIL + PATH + '/{message_id}');
    assert.equal(config.proxy_authorization, 'Bearer ' + token); assert.equal(config.request_headers.Authorization, DUMMY);
    for (const value of PRIVATE) assert(!JSON.stringify(config).includes(value));
    await page.locator('#copy-command').click(); const copied = await page.evaluate(() => navigator.clipboard.readText());
    assert(copied.includes("GMAIL-DUMMY-'\\''literal'\\''-$value")); assert(!copied.includes(token));
  })],
  ['saved legacy exact Google rule remains literal and reusable without a new grant', browser => fixture(browser, options({rules: [rule({upstream_url: GMAIL + PATH, response_mode: 'unfiltered_json_or_empty_v2', response_fields: []})]}), async (page, state, observed) => {
    await pair(page); await page.locator('#connect-rule-choice').selectOption(IDS.rule); await review(page);
    assert(!/Read Gmail ·/.test(await page.locator('#connect-review-details').innerText())); await grant(page); await commandReady(page);
    assert(await page.locator('#gmail-client-controls').isHidden()); assert(!Object.hasOwn(state.rules[0], 'operation_bundle'));
    assert.equal(observed.posts.length, 0); assert.equal(state.posts.length, 0);
  })],
  ['deliberate advanced exact draft survives Read Gmail and back without changing its restrictions', browser => fixture(browser, options(), async page => {
    await bundleForm(page); await page.locator('#connect-operation').selectOption('exact');
    await page.locator('#connect-path').fill('/gmail/v1/users/me/profile'); await openRestrictions(page, 'connect');
    await page.locator('#connect-rule-name').fill('Keep my exact rule'); await page.locator('#connect-response-mode').selectOption('projected_json');
    await page.locator('#connect-response-fields').fill('emailAddress');
    await page.locator('#connect-operation').selectOption(BUNDLE); await review(page); await page.locator('#connect-back').click();
    await page.locator('#connect-operation').selectOption('exact');
    assert.equal(await page.locator('#connect-path').inputValue(), '/gmail/v1/users/me/profile');
    assert.equal(await page.locator('#connect-rule-name').inputValue(), 'Keep my exact rule');
    assert.equal(await page.locator('#connect-response-mode').inputValue(), 'projected_json');
    assert.equal(await page.locator('#connect-response-fields').inputValue(), 'emailAddress');
  })],
  ['withdrawn bundle retains the selected draft and blocks review without silent endpoint fallback', browser => fixture(browser, options(), async (page, state, observed) => {
    await bundleForm(page); state.bundles = []; await refresh(page, state);
    assert.equal(await page.locator('#connect-operation').inputValue(), BUNDLE); assert(await page.locator('#connect-review').isDisabled());
    assert.match(await page.locator('#connect-gmail-summary').innerText(), /no longer advertised/);
    await page.locator('#connect-operation').selectOption('exact'); assert(await page.locator('#connect-path').isVisible());
    assert.equal(observed.posts.length, 0);
  })],
  ['saved bundle capability withdrawal blocks command copy/export but keeps catalog readable', browser => fixture(browser, options({rules: [bundleRule()]}), async (page, state) => {
    await ready(page); await view(page, 'proxy'); await commandReady(page); state.bundles = []; await view(page, 'connect'); await refresh(page, state);
    await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
    assert(await page.locator('#load-error').isHidden());
  })],
  ['disabled Google profile never advertises Read Gmail or enables provider connection', browser => fixture(browser, options({googleEnabled: false, bundles: []}), async page => {
    await ready(page); assert(await page.locator('#connect-google').isDisabled()); await pair(page);
    assert.equal(await page.locator('#connect-operation option[value="gmail_read_v1"]').count(), 0);
    assert.equal(await page.locator('#connect-operation').inputValue(), 'exact'); assert(await page.locator('#connect-path').isVisible());
  })],
  ['missing bundle capability preserves legacy-only Google setup', browser => fixture(browser, options({bundles: undefined}), async page => {
    await pair(page); assert.equal(await page.locator('#connect-operation').inputValue(), 'exact');
    assert.equal(await page.locator('#connect-operation option[value="gmail_read_v1"]').count(), 0);
  })],
  ['malformed saved bundle blocks whole catalog instead of silently dropping fields', browser => fixture(browser, options({rules: [bundleRule({age_policy: {mode: 'last_30_days'}})]}), async page => {
    await page.locator('#load-error').waitFor({state: 'visible'});
    // Playwright's native-control disabled matcher excludes FIELDSET itself;
    // inspect its DOM property and prove inherited disabling on real controls.
    assert.equal(await page.locator('#credential-fields').evaluate(node => node.disabled), true);
    assert.equal(await page.locator('#credential-secret').count(), 0); assert(await page.locator('#credential-add').isDisabled());
    await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled());
  })],
  ['malformed advertised response contract cannot authorize bundle creation', browser => fixture(browser, options({bundles: [{...descriptor(), response_contract: {...descriptor().response_contract, body_presence: 'optional'}}]}), async page => {
    await page.locator('#load-error').waitFor({state: 'visible'}); assert(await page.locator('#connect-use-saved').isDisabled());
  })],
  ['lost committed grant response becomes uncertainty with no automatic retry or ready setup', browser => fixture(browser, options({loseReceipt: true}), async (page, state, observed) => {
    await bundleForm(page); await review(page); await page.locator('#connect-grant').click();
    await page.locator('#mutation-review').waitFor({state: 'visible'}); await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
    assert.equal(observed.posts.length, 1); assert.equal(state.rules.length, 1); assert(await page.locator('#connect-grant').isDisabled());
    assert(await page.locator('#connect-setup-step').isHidden()); await refresh(page, state); assert.equal(observed.posts.length, 1);
  })],
  ['successful receipt requires fresh exact catalog join before setup and never resubmits', browser => fixture(browser, options({failCatalogAfterSave: true}), async (page, state, observed) => {
    await bundleForm(page); await review(page); await page.locator('#connect-grant').click(); await page.locator('#load-error').waitFor({state: 'visible'});
    assert(await page.locator('#connect-grant').isDisabled()); assert(await page.locator('#connect-setup-step').isHidden()); assert.equal(observed.posts.length, 1);
    state.gmailCatalogFailure = false; await refresh(page, state); await step(page, 'setup'); await commandReady(page); assert.equal(observed.posts.length, 1);
  })],
  ['selected account becoming unavailable prevents reviewed grant', browser => fixture(browser, options(), async (page, state, observed) => {
    await bundleForm(page); await review(page); state.credentials = []; state.revision++; await refresh(page, state);
    assert(await page.locator('#connect-grant').isDisabled()); assert.match(await page.locator('#connect-review-context').innerText(), /unavailable/);
    assert.equal(observed.posts.length, 0);
  })],
  ['stale review revision prevents grant until deliberate re-review', browser => fixture(browser, options(), async (page, state, observed) => {
    await bundleForm(page); await review(page); state.revision++; await refresh(page, state); assert(await page.locator('#connect-grant').isDisabled());
    assert.equal(observed.posts.length, 0); await page.locator('#connect-back').click(); await review(page); await grant(page);
    assert.equal(observed.posts[0].expected_revision, 2);
  })],
  ['retained pre-query bundle stays canonical and never claims an automatic upgrade', browser => {
    const retained = bundleRule({allowed_headers: [...LEGACY_HEADERS]}); delete retained.query_mode;
    return fixture(browser, options({rules: [retained]}), async (page, state, observed) => {
      await pair(page); await page.locator('#connect-rule-choice').selectOption(IDS.rule); await review(page);
      assert.match(await page.locator('#connect-review-details').innerText(), /legacy canonical.*no automatic upgrade/is);
      await grant(page); await commandReady(page); assert.match(await page.locator('#client-guidance').innerText(), /legacy canonical/);
      assert(!Object.hasOwn(state.rules[0], 'query_mode')); assert.equal(observed.posts.length, 0);
    });
  }],
  ['static credential keeps generic setup even with Google bundle advertised', browser => fixture(browser, options({credentials: [credential()]}), async (page, state, observed) => {
    await pair(page); assert(await page.locator('#connect-operation-group').isHidden());
    assert.equal(await page.locator('#connect-operation').inputValue(), 'exact'); assert(await page.locator('#connect-path').isVisible());
    assert.equal(observed.posts.length, 0); assert.equal(state.posts.length, 0);
  })],
];
async function main() {
  const args = process.argv.slice(2);
  assert(args.length === 0 || args.length === 2 && args[0] === '--from-group' && /^(?:[1-9]|1[0-7])$/.test(args[1]), 'Only no arguments or --from-group N (1..17) accepted');
  const first = args.length ? Number(args[1]) : 1; const selected = tests.slice(first - 1);
  const before = await hashes(); console.log(JSON.stringify({phase: 'source-before', hashes: before}));
  console.log(JSON.stringify({firstGroup: first, lastGroup: tests.length, renderedGroups: selected.length, pureGroups: args.length ? 0 : 1}));
  if (!args.length) console.log(JSON.stringify(pureChecks()));
  const directory = '/srv/catchplate-fast/projects/catchplate-operator-artifacts'; assert((await stat(directory)).isDirectory());
  artifacts = await mkdtemp(join(directory, 'gmail-bundle-synthetic-')); console.log(JSON.stringify({artifactDirectory: artifacts}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']}); let deadline;
  try {
    await Promise.race([(async () => { for (const [name, run] of selected) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, renderedGroups: selected.length, pureGroups: args.length ? 0 : 1, providerRequests: 0, proxyRequests: 0,
        actualConsent: false, backendAcceptance: false, nativeHttpDownloads: 0, generatedCommandsExecuted: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('Gmail bundle fixture deadline')), 150000); })]);
  } finally {
    clearTimeout(deadline); try { await browser.close(); }
    finally { const after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after})); assert.deepEqual(after, before); }
  }
}
module.exports = {fixture, options, bundleRule};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

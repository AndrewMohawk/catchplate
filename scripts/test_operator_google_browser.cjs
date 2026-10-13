#!/usr/bin/env node
// Public Google account presentation only. No consent, cleanup, provider request,
// live proxy, generated command execution, or native HTTP download is exercised.
// Secret-like fixture extras test allowlisted display; they do not assert that a
// real backend would return provider secrets in its public catalog.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFileSync} = require('node:fs');
const {readFile, mkdtemp, stat} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {runInNewContext} = require('node:vm');
const {fixture, ready, view, credential, application, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {publicCatalog} = require('./test_operator_ordinary_modes_browser.cjs');

const ROOT = resolve(__dirname, '..');
const SCOPES = ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'];
const ACCOUNT = 'operator-fixture@example.test';
const SUBJECT = 'synthetic-google-subject';
const CLIENT = 'synthetic-client.apps.googleusercontent.com';
const DUMMY = "Bearer GOOGLE-DUMMY-'literal'-$value";
const PRIVATE = ['synthetic-google-access-private-NEVER-RENDER', 'synthetic-google-refresh-private-NEVER-RENDER',
  'synthetic-google-client-secret-NEVER-RENDER', 'synthetic-google-ciphertext-NEVER-RENDER'];
const STATIC_ID = '66666666-6666-4666-8666-666666666666';
const FORMER_RULE_ID = '77777777-7777-4777-8777-777777777777';
const ACTIVE_CARD_TEST = 'Google card shows account, friendly permission and app names with one optional Details disclosure';
const QUARANTINED_CARD_TEST = 'quarantine stays visibly unusable while former assignments and technical metadata stay in Details';
const UNKNOWN_PRESET_TEST = 'malformed public Google metadata: unknown permission preset';
const SETUP_SUMMARY_TEST = 'Connect keeps Google account details optional and ordinary selection and review labels concise';
const DUPLICATE_NAMES_TEST = 'Connect disambiguates duplicate names and preserves exact selected account application and rule across refresh';
const SECOND_GOOGLE_ID = '11111111-2222-4222-8222-222222222222';
const SECOND_STATIC_ID = '66666666-7777-4777-8777-777777777777';
const SECOND_APPLICATION_ID = '22222222-3333-4333-8333-333333333333';
const SECOND_RULE_ID = '44444444-5555-4555-8555-555555555555';
const MIMIC_APPLICATION_ID = '88888888-8888-4888-8888-888888888888';
const ACTION_RULE_ID = '99999999-9999-4999-8999-999999999999';
const SECOND_ACCOUNT = 'other-operator@example.test';
const ACTIVITY_SCHEMA = 'serverware.operatorAccountActivity/v1';
const ACTIVITY_ERROR = 'synthetic-raw-provider-error-NEVER-DISPLAY';
const RESPONSE_EVENT = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const SUCCESS_EVENT = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const FAILURE_EVENT = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const capabilities = {responseModes: ['projected_json', 'unfiltered_json'], credentialInputModes: ['insert', 'replace_exact']};
const digest = n => 'sha256:' + n.toString(16).padStart(64, '0');
const google = (changes = {}) => credential({name: 'Saved test Google account', auth_type: 'google_oauth', header_name: 'Authorization',
  provider_account: ACCOUNT, provider_subject: SUBJECT, oauth_client_id: CLIENT, permission_preset: 'gmail_readonly', scopes: [...SCOPES], ...changes});
const quarantine = (changes = {}) => google({status: 'quarantined', quarantined_at: new Date(NOW).toISOString(),
  quarantine_reason: 'operator_google_cleanup_fence', provider_revocation_status: 'not_proven', ...changes});
const googleRule = (mode = 'replace_exact', changes = {}) => rule({name: 'Read Gmail profile',
  upstream_url: 'https://gmail.googleapis.com/gmail/v1/users/me/profile', response_mode: 'unfiltered_json', response_fields: [],
  credential_input: mode, ...(mode === 'replace_exact' ? {placeholder: DUMMY} : {}), ...changes});
const supplied = (changes = {}) => ({...capabilities, credentials: [google()], applications: [application()], ...changes});
const accountCard = page => page.locator('#credentials-list [data-resource-id="' + IDS.credential + '"][data-credential-type="google_oauth"]');
const clone = value => JSON.parse(JSON.stringify(value));
const activityAccount = (changes = {}) => ({credential_id: IDS.credential, last_successful_response: null,
  last_refresh_success: null, last_refresh_failure: null, last_refresh_outcome: 'unobserved', ...changes});
const activityEvent = (changes = {}) => ({event_id: SUCCESS_EVENT, recorded_at_epoch_ms: NOW - 60000, credential_version: 2, ...changes});
const responseEvent = (changes = {}) => activityEvent({event_id: RESPONSE_EVENT, application_id: IDS.application, rule_id: IDS.rule, ...changes});
const activity = (changes = {}) => ({schema: ACTIVITY_SCHEMA, status: 'available', observed_at_epoch_ms: NOW,
  chain_verification: 'not_checked', window: {row_limit: 256, event_byte_limit: 16384, byte_limit: 2097152,
    rows_scanned: 0, bytes_read: 0, has_older_rows: false, byte_budget_exhausted: false,
    oversized_events: 0, invalid_events: 0, unmatched_responses: 0, incomplete: false},
  accounts: [activityAccount()], ...changes});
const observedActivity = (accounts, changes = {}) => activity({accounts,
  window: {...activity().window, rows_scanned: 8, bytes_read: 2048}, ...changes});
const INPUTS = ['scripts/test_operator_google_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
  'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py',
  ...['index.html', 'style.css', 'app.js', 'workspace_core.js', 'workspace_github.js', 'workspace_applications.js', 'workspace_resources.js',
    'workspace_proxy_audit.js', 'workspace_connect.js', 'workspace_google.js'].map(name => 'serverware/operator_demo_web/' + name)];
let artifacts;

async function hashes() { return Object.fromEntries(await Promise.all(INPUTS.map(async name =>
  [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')]))); }
async function screenshot(page, name) {
  if (!artifacts) return;
  await page.evaluate(() => window.scrollTo({top: 0, left: 0, behavior: 'instant'}));
  await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true});
}
async function privateAbsent(page) {
  const surfaces = await page.evaluate(() => [document.documentElement.outerHTML,
    ...[...document.querySelectorAll('input,textarea')].map(item => item.value)].join('\n'));
  for (const value of PRIVATE) assert(!surfaces.includes(value), 'provider-private fixture extra must not enter DOM, source or form values');
}
async function refresh(page) {
  const response = page.waitForResponse(value => new URL(value.url()).pathname === '/api/operator-demo/catalog');
  await page.locator('#connect-status-refresh').click(); await response; await page.waitForLoadState('networkidle');
}
async function activityRefresh(page) {
  const endpoint = 'https://operator-catalog.example.test/api/operator-demo/catalog';
  // Await the actual replacement of resource cards after this GET, including
  // unavailable fallback where the visible words may match the old document.
  await page.evaluate(() => {
    window.__activityRendered = false;
    const observer = new MutationObserver(() => { window.__activityRendered = true; observer.disconnect(); });
    observer.observe(document.querySelector('#credentials-list'), {childList: true});
  });
  const response = page.waitForResponse(value => value.url() === endpoint && value.request().method() === 'GET');
  await page.locator('#connect-status-refresh').click(); await (await response).finished();
  await page.waitForFunction(() => window.__activityRendered === true);
  await page.evaluate(() => { delete window.__activityRendered; });
}
async function activityFixture(browser, options, exercise) {
  return fixture(browser, supplied(options), async (page, state, controls) => {
    const endpoint = 'https://operator-catalog.example.test/api/operator-demo/catalog';
    state.activityObservation = options.activityObservation;
    let calls = 0;
    // A top-level public observation is not a credential or a new API authority.
    // Override only this exact synthetic GET; the existing deny-all HTTP and
    // WebSocket guards, service-worker block and context cleanup remain active.
    await controls.context.route(endpoint, async route => {
      const request = route.request();
      state.requests.push({path: '/api/operator-demo/catalog', query: '', method: request.method()});
      if (++calls > 12 || state.requests.length > 150 || request.url() !== endpoint || request.method() !== 'GET' || request.postDataBuffer()?.length) {
        state.unexpected.push('account activity catalog boundary refused'); await route.abort(); return;
      }
      state.catalogCalls++;
      const value = publicCatalog(state);
      if (state.activityObservation !== undefined) value.observed_activity = state.activityObservation;
      await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(value)});
    });
    await activityRefresh(page);
    await exercise(page, state, controls);
    assert(calls >= 1); assert.equal(state.posts.length, 0, 'activity observation never causes a catalog mutation');
    await privateAbsent(page);
  });
}
async function useGoogle(page) {
  await ready(page); await view(page, 'connect'); await page.locator('#connect-use-saved').click();
  await page.locator('#connect-credential-choice').selectOption(IDS.credential);
  await page.locator('#connect-credential-next').click(); await page.locator('#connect-application-step').waitFor({state: 'visible'});
  await page.locator('#connect-application-choice').selectOption(IDS.application); await page.locator('#connect-application-next').click();
  await page.locator('#connect-access-step').waitFor({state: 'visible'});
}
async function reviewSaved(page) {
  await page.locator('#connect-rule-choice').selectOption(IDS.rule); await page.locator('#connect-review').click();
  await page.locator('#connect-review-step').waitFor({state: 'visible'});
}
async function configured(page) {
  await page.locator('#connect-grant').click(); await page.locator('#connect-setup-slot').waitFor({state: 'visible'});
  await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  assert.equal(await page.locator('#proxy-rule').inputValue(), IDS.rule);
  assert.match(await page.locator('#connect-provider-status').innerText(), /saved metadata only.*has not tested consent, token refresh or a Google request.*connection remains disabled/is);
}
function quarantineState(state) {
  state.credentials[0] = quarantine(); for (const value of state.rules) if (value.credential_id === IDS.credential) value.status = 'revoked';
  state.revision++; state.active = state.loaded = digest(++state.sequence);
}
async function unavailable(page, state) {
  await page.locator('#load-error').waitFor({state: 'visible'});
  assert(await page.locator('#credential-add').isDisabled()); assert(await page.locator('#application-create').isDisabled());
  assert(await page.locator('#rule-save').isDisabled()); assert(await page.locator('#connect-credential-next').isDisabled());
  await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
  assert.equal(state.posts.length, 0); await privateAbsent(page);
}
function generatorChecks() {
  const {credentialHeaderTarget, clientCredentialInput, buildCurlCommand} = require('../serverware/operator_demo_web/app.js');
  assert.equal(credentialHeaderTarget(google()), 'Authorization');
  assert.equal(clientCredentialInput({credentialInput: 'insert', credential: google()}), null);
  assert.deepEqual(clientCredentialInput({credentialInput: 'replace_exact', placeholder: DUMMY, credential: google()}), {name: 'Authorization', value: DUMMY});
  for (const header_name of ['X-API-Key', 'authorization', 'Proxy-Authorization']) assert.throws(() => credentialHeaderTarget(google({header_name})));
  const command = buildCurlCommand({proxyUrl: 'https://proxy.example.test', upstreamUrl: googleRule().upstream_url, method: 'GET',
    credentialInput: 'replace_exact', placeholder: DUMMY, credential: google({access_token: PRIVATE[0], refresh_token: PRIVATE[1]})});
  assert(command.includes("Authorization: Bearer GOOGLE-DUMMY-'\\''literal'\\''-$value"));
  assert(command.includes('Proxy-Authorization: Bearer $SERVERWARE_PROXY_TOKEN')); assert(command.includes('--cacert'));
  for (const value of PRIVATE) assert(!command.includes(value));
  const resources = readFileSync(join(ROOT, 'serverware/operator_demo_web/workspace_resources.js'), 'utf8');
  const permission = input => runInNewContext(resources + '\noperatorGooglePermission(input)', {input}, {timeout: 1000});
  assert.equal(permission(google()), 'Read Gmail');
  for (const permission_preset of ['gmail_full_access', '', null, undefined])
    assert.equal(permission(google({permission_preset})), 'Unsupported permission preset');
  const connect = readFileSync(join(ROOT, 'serverware/operator_demo_web/workspace_connect.js'), 'utf8');
  const labels = (input, reserved = []) => JSON.parse(JSON.stringify(runInNewContext(connect + '\noperatorConnectResourceChoices(input, reserved)', {input, reserved}, {timeout: 1000})));
  assert.deepEqual(labels([application()]), [{id: IDS.application, name: 'Reporting application'}]);
  const duplicateApps = [application({name: 'Same name'}), application({id: SECOND_APPLICATION_ID, name: 'Same  name'})];
  const names = labels(duplicateApps); assert.notEqual(names[0].name, names[1].name);
  assert.deepEqual(labels([...duplicateApps].reverse()), [...names].reverse(), 'disambiguation depends on exact IDs, not list order');
  assert(names.every(item => item.name.startsWith('Same name · ') && !item.name.includes(item.id)), 'only the necessary unique ID prefix is displayed');
  const accounts = labels([google(), google({id: SECOND_GOOGLE_ID, provider_account: SECOND_ACCOUNT, provider_subject: 'other-subject'})]);
  assert(accounts[0].name.includes(ACCOUNT) && accounts[1].name.includes(SECOND_ACCOUNT));
  assert(accounts.every(item => !item.name.includes(item.id)), 'account email disambiguates before adding an ID');
  const sameAccountLabel = labels([google(), google({id: SECOND_GOOGLE_ID})]);
  assert.notEqual(sameAccountLabel[0].name, sameAccountLabel[1].name, 'identical account labels still retain distinct display identities');
  const mimics = [...duplicateApps, application({id: IDS.other, name: names[0].name}),
    application({id: MIMIC_APPLICATION_ID, name: '[' + IDS.application + '] Same name'})];
  const resolved = labels(mimics);
  assert.equal(new Set(resolved.map(item => item.name)).size, mimics.length, 'literal names cannot imitate generated short or full-ID labels');
  assert.deepEqual(resolved.map(item => item.id), mimics.map(item => item.id));
  assert.deepEqual(labels([...mimics].reverse()), [...resolved].reverse());
  for (const name of ['Choose a saved credential', 'Create a new client', 'Grant a new permission']) {
    const result = labels([application({name})], ['  ' + name.replaceAll(' ', '  ') + '  ']);
    assert.equal(result[0].id, IDS.application); assert.notEqual(result[0].name, name, 'saved resources cannot impersonate an action choice');
  }
  return {ok: true, groups: 1, scope: 'pure Google header target, safe commands, permission labels and exact-ID display disambiguation; commands never executed'};
}

const malformedActivity = [
  ['unknown schema', value => { value.schema += '/unknown'; }],
  ['unknown status', value => { value.status = 'healthy'; }],
  ['claimed verified chain', value => { value.chain_verification = 'verified'; }],
  ['fractional observation time', value => { value.observed_at_epoch_ms += 0.5; }],
  ['wrong row bound', value => { value.window.row_limit = 257; }],
  ['wrong event byte bound', value => { value.window.event_byte_limit++; }],
  ['wrong total byte bound', value => { value.window.byte_limit++; }],
  ['excess rows', value => { value.window.rows_scanned = 257; }],
  ['excess bytes', value => { value.window.bytes_read = 2097153; }],
  ['nonboolean coverage', value => { value.window.incomplete = 'false'; }],
  ['counter greater than rows', value => { value.window.invalid_events = 9; }],
  ...['has_older_rows', 'byte_budget_exhausted', 'oversized_events', 'invalid_events', 'unmatched_responses'].map(key =>
    ['unacknowledged omission ' + key, value => { value.window[key] = key.endsWith('rows') || key === 'byte_budget_exhausted' ? true : 1; }]),
  ['missing account', value => { value.accounts = []; }],
  ['duplicate account', value => { value.accounts.push(clone(value.accounts[0])); }],
  ['foreign credential', value => { value.accounts[0].credential_id = SECOND_GOOGLE_ID; }],
  ['invalid event ID', value => { value.accounts[0].last_successful_response.event_id = 'not-an-event'; }],
  ['future response', value => { value.accounts[0].last_successful_response.recorded_at_epoch_ms = NOW + 1; }],
  ['zero version', value => { value.accounts[0].last_successful_response.credential_version = 0; }],
  ['missing application', value => { value.accounts[0].last_successful_response.application_id = SECOND_APPLICATION_ID; }],
  ['missing rule', value => { value.accounts[0].last_successful_response.rule_id = SECOND_RULE_ID; }],
  ['success without success event', value => { value.accounts[0].last_refresh_success = null; }],
  ['unobserved with a refresh event', value => { value.accounts[0].last_refresh_outcome = 'unobserved'; }],
  ['failure without failure event', value => { value.accounts[0].last_refresh_outcome = 'failure'; }],
  ['success older than failure', value => { value.accounts[0].last_refresh_failure = activityEvent({event_id: FAILURE_EVENT, recorded_at_epoch_ms: NOW - 1}); }],
  ['missing required event slot', value => { delete value.accounts[0].last_refresh_failure; }],
  ['observation without scanned rows', value => { value.window.rows_scanned = 0; }],
  ['unavailable with account evidence', value => { value.status = 'unavailable'; value.window.incomplete = true; }],
];
function activityProjectionChecks() {
  const core = ['workspace_core.js', 'workspace_github.js']
    .map(name => readFileSync(join(ROOT, 'serverware/operator_demo_web', name), 'utf8')).join('\n');
  const {clientCredentialInput, credentialHeaderTarget} = require('../serverware/operator_demo_web/app.js');
  const state = {credentials: [google()], applications: [application()], rules: [googleRule()], revision: 1,
    sequence: 1, active: digest(1), loaded: digest(1), responseModes: capabilities.responseModes,
    credentialInputModes: capabilities.credentialInputModes};
  const project = (value, changes = {}) => {
    const input = publicCatalog({...state, ...changes}); if (value !== undefined) input.observed_activity = value;
    return clone(runInNewContext(core + '\nprojectCatalog(input)',
      {input, clientCredentialInput, credentialHeaderTarget}, {timeout: 1000}));
  };
  const valid = observedActivity([activityAccount({last_successful_response: responseEvent(),
    last_refresh_success: activityEvent(), last_refresh_outcome: 'success'})]);
  assert.deepEqual(project(valid).observed_activity, valid);
  for (const value of [undefined, null, {}, ...malformedActivity.map(([, change]) => { const item = clone(valid); change(item); return item; })]) {
    const result = project(value); assert.equal(result.observed_activity, null);
    assert.equal(result.credentials[0].id, IDS.credential); assert.equal(result.access_rules[0].id, IDS.rule);
    assert.equal(result.capabilities.oauth, false, 'malformed observations do not create authority or invalidate the catalog');
  }
  const extras = clone(valid); extras.raw_error = ACTIVITY_ERROR; extras.window.raw_error = ACTIVITY_ERROR;
  extras.accounts[0].refresh_token = PRIVATE[1]; extras.accounts[0].last_successful_response.error = ACTIVITY_ERROR;
  extras.accounts[0].last_refresh_success.access_token = PRIVATE[0];
  assert.deepEqual(project(extras).observed_activity, valid, 'only explicit public evidence survives projection');
  const tied = clone(valid); tied.accounts[0].last_refresh_failure = activityEvent({event_id: FAILURE_EVENT});
  for (const last_refresh_outcome of ['success', 'failure']) {
    tied.accounts[0].last_refresh_outcome = last_refresh_outcome;
    assert.equal(project(tied).observed_activity.accounts[0].last_refresh_outcome, last_refresh_outcome,
      'equal storage timestamps retain backend row-order outcome, not a client timestamp guess');
  }
  const unavailable = activity({status: 'unavailable', accounts: [], window: {...activity().window, incomplete: true}});
  assert.deepEqual(project(unavailable).observed_activity, unavailable);
  const staticEvidence = observedActivity([activityAccount({last_successful_response: responseEvent({event_id: digest(9)})})]);
  assert.deepEqual(project(staticEvidence, {credentials: [credential()], rules: [rule()]}).observed_activity, staticEvidence);
  assert.equal(project(valid, {credentials: [credential()], rules: [rule()]}).observed_activity, null, 'static keys cannot inherit Google refresh evidence');
  const misbound = clone(valid);
  assert.equal(project(misbound, {credentials: [google(), google({id: SECOND_GOOGLE_ID})],
    rules: [googleRule('insert', {credential_id: SECOND_GOOGLE_ID})]}).observed_activity, null);
  const withTwoAccounts = clone(valid); withTwoAccounts.accounts.push(activityAccount({credential_id: SECOND_GOOGLE_ID}));
  assert.equal(project(withTwoAccounts, {credentials: [google(), google({id: SECOND_GOOGLE_ID})],
    rules: [googleRule('insert', {credential_id: SECOND_GOOGLE_ID})]}).observed_activity, null,
    'even a retained rule and application must belong to the exact observed credential');
  return {ok: true, groups: 1, malformedVariants: malformedActivity.length + 3,
    scope: 'pure actual catalog projection; activity-only failure, exact joins and sanitized historical evidence, not audit verification'};
}

const malformed = [
  ['missing account', {provider_account: undefined}], ['empty account', {provider_account: ''}],
  ['control character in account', {provider_account: ACCOUNT + '\n'}], ['missing subject', {provider_subject: undefined}],
  ['missing OAuth client ID', {oauth_client_id: undefined}], ['unrecognized OAuth client ID', {oauth_client_id: 'not-a-google-client'}],
  ['nonarray scopes', {scopes: 'openid'}], ['changed permission scope', {scopes: ['email', 'https://www.googleapis.com/auth/gmail.modify', 'openid']}],
  ['duplicate scope', {scopes: ['email', 'email', 'openid']}], ['unknown permission preset', {permission_preset: 'gmail_full_access'}],
  ['wrong provider header', {header_name: 'X-API-Key'}], ['ordinary revoked Google status', {status: 'revoked'}],
  ['missing quarantine timestamp', {...quarantine(), quarantined_at: undefined}],
  ['invalid quarantine timestamp', {...quarantine(), quarantined_at: 'not-a-date'}],
  ['missing quarantine reason', {...quarantine(), quarantine_reason: undefined}],
  ['false provider-revocation success', {...quarantine(), provider_revocation_status: 'revoked'}],
];

const tests = [
  [ACTIVE_CARD_TEST, browser => fixture(browser,
    supplied({credentials: [google(), credential({id: STATIC_ID, name: 'Separate static key'})],
      applications: [application(), application({id: IDS.other, name: 'Former worker'})],
      rules: [googleRule(), googleRule('insert', {id: FORMER_RULE_ID, route_id: 'operator.' + FORMER_RULE_ID,
        application_id: IDS.other, status: 'revoked'})]}), async (page, state) => {
      await ready(page); await view(page, 'credentials'); const card = accountCard(page); await card.waitFor({state: 'visible'});
      const details = card.locator('[data-google-identity]'); assert.equal(await card.locator('details').count(), 1);
      assert.equal(await details.locator('summary').innerText(), 'Details'); assert(!await details.evaluate(item => item.open));
      const text = await card.innerText(); for (const value of [ACCOUNT, 'Read Gmail', 'Assigned clients', 'Reporting application']) assert(text.includes(value));
      for (const value of ['gmail_readonly', ...SCOPES, SUBJECT, CLIENT, IDS.credential, IDS.application, IDS.other, 'Former worker'])
        assert(!text.includes(value), 'technical or former-assignment detail must not appear on the compact card');
      assert.equal(await card.locator('[data-google-account-notice]').innerText(), 'Historical observations do not confirm current account health or proxy activation.');
      assert.equal(await card.locator('[data-action="revoke-credential"]').count(), 0);
      const staticCard = page.locator('#credentials-list [data-resource-id="' + STATIC_ID + '"]');
      assert.match(await staticCard.innerText(), /Authentication\s+Bearer token/); assert((await staticCard.innerText()).includes(STATIC_ID));
      assert(!await staticCard.locator('[data-action="revoke-credential"]').isDisabled());
      assert(await page.locator('#credential-google-connect').isDisabled()); await screenshot(page, 'google-account-desktop');
      await details.locator('summary').click(); assert(await details.evaluate(item => item.open));
      const detailText = await details.innerText();
      for (const value of ['gmail_readonly', ...SCOPES, SUBJECT, CLIENT, IDS.credential, IDS.application, IDS.other, 'Former worker'])
        assert(detailText.includes(value), 'Details retains exact metadata and assignment identities');
      assert.match(detailText, /saved active assignments\s+reporting application/i);
      assert.match(detailText, /former assignments\s+former worker/i);
      await details.locator('summary').click(); assert(!await details.evaluate(item => item.open));
      assert(!(await card.innerText()).includes(SUBJECT));
      await page.setViewportSize({width: 390, height: 844});
      assert(await details.locator('summary').isVisible());
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'compact account view fits mobile width');
      await screenshot(page, 'google-account-mobile');
      await view(page, 'connect'); assert(await page.locator('#connect-google').isDisabled());
      await page.locator('#connect-use-saved').click();
      assert((await page.locator('#connect-credential-choice option[value="' + IDS.credential + '"]').innerText()).includes(ACCOUNT));
      await page.locator('#connect-credential-choice').selectOption(IDS.credential);
      assert((await page.locator('#connect-google-account-summary').innerText()).includes(ACCOUNT));
      assert.equal(state.posts.length, 0);
    })],
  [SETUP_SUMMARY_TEST, browser => fixture(browser, supplied({rules: [googleRule()]}), async (page, state) => {
    await ready(page); await view(page, 'connect'); await page.locator('#connect-use-saved').click();
    const option = page.locator('#connect-credential-choice option[value="' + IDS.credential + '"]');
    assert((await option.innerText()).includes(ACCOUNT)); assert(!(await option.innerText()).includes(IDS.credential));
    await page.locator('#connect-credential-choice').selectOption(IDS.credential);
    const summary = page.locator('#connect-google-account-summary');
    const card = summary.locator('[data-resource-id="' + IDS.credential + '"]');
    const details = card.locator('[data-google-identity]');
    assert.equal(await summary.locator('details').count(), 1); assert(!await details.evaluate(item => item.open));
    const compact = await summary.innerText();
    for (const value of [ACCOUNT, 'Read Gmail', 'Assigned clients', 'Reporting application']) assert(compact.includes(value));
    for (const value of ['gmail_readonly', ...SCOPES, SUBJECT, CLIENT, IDS.credential, IDS.application]) assert(!compact.includes(value));
    assert(compact.includes('Historical observations do not confirm current account health or proxy activation.'));
    await details.locator('summary').click();
    for (const value of ['gmail_readonly', ...SCOPES, SUBJECT, CLIENT, IDS.credential, IDS.application]) assert((await details.innerText()).includes(value));
    await refresh(page); assert(await details.evaluate(item => item.open), 'refresh preserves an explicit Details choice for the same account');
    await details.locator('summary').click();
    await page.locator('#connect-credential-next').click(); await page.locator('#connect-application-step').waitFor({state: 'visible'});
    assert.equal(await page.locator('#connect-application-choice option[value="' + IDS.application + '"]').innerText(), 'Reporting application');
    await page.locator('#connect-application-choice').selectOption(IDS.application); await page.locator('#connect-application-next').click();
    await page.locator('#connect-access-step').waitFor({state: 'visible'});
    assert.equal(await page.locator('#connect-rule-choice option[value="' + IDS.rule + '"]').innerText(), 'Read Gmail profile');
    await reviewSaved(page);
    const review = await page.locator('#connect-review-context').innerText();
    assert(review.includes('Reporting application') && review.includes(ACCOUNT));
    for (const id of [IDS.credential, IDS.application, IDS.rule]) assert(!review.includes(id));
    assert(!await details.evaluate(item => item.open)); await screenshot(page, 'google-connect-summary-desktop');
    await page.setViewportSize({width: 390, height: 844}); await details.locator('summary').click();
    assert(await details.evaluate(item => item.open)); await details.locator('summary').click();
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1));
    await screenshot(page, 'google-connect-summary-mobile');
    await configured(page); assert.equal(await card.count(), 1);
    assert(!await page.locator('#one-time-access').isVisible(), 'using a saved application never retrieves or rotates its token');
    assert.equal(state.posts.length, 0); await privateAbsent(page);
  })],
  [DUPLICATE_NAMES_TEST, browser => fixture(browser, supplied({
    credentials: [google({name: 'Shared mailbox'}), google({id: SECOND_GOOGLE_ID, name: 'Shared mailbox',
      provider_account: SECOND_ACCOUNT, provider_subject: 'other-subject'}),
      credential({id: STATIC_ID, name: 'Shared key'}), credential({id: SECOND_STATIC_ID, name: 'Shared key'})],
    applications: [application({name: 'Inbox worker'}), application({id: SECOND_APPLICATION_ID, name: 'Inbox worker'}),
      application({id: IDS.other, name: 'Create a new client'}),
      application({id: MIMIC_APPLICATION_ID, name: 'Inbox worker · 22222222-2'})],
    rules: [googleRule('insert', {application_id: SECOND_APPLICATION_ID, credential_id: SECOND_GOOGLE_ID}),
      googleRule('replace_exact', {id: SECOND_RULE_ID, route_id: 'operator.' + SECOND_RULE_ID,
        application_id: SECOND_APPLICATION_ID, credential_id: SECOND_GOOGLE_ID, placeholder: 'Bearer OTHER_DUMMY',
        upstream_url: 'https://gmail.googleapis.com/gmail/v1/users/me/messages'}),
      googleRule('insert', {id: ACTION_RULE_ID, route_id: 'operator.' + ACTION_RULE_ID, name: 'Grant a new permission',
        application_id: SECOND_APPLICATION_ID, credential_id: SECOND_GOOGLE_ID,
        upstream_url: 'https://gmail.googleapis.com/gmail/v1/users/me/labels'}),
      googleRule('insert', {id: FORMER_RULE_ID, route_id: 'operator.' + FORMER_RULE_ID})]
  }), async (page, state) => {
    await ready(page); await view(page, 'connect'); await page.locator('#connect-use-saved').click();
    const label = (control, id) => page.locator('#' + control + ' option[value="' + id + '"]').innerText();
    const firstAccount = await label('connect-credential-choice', IDS.credential);
    const secondAccount = await label('connect-credential-choice', SECOND_GOOGLE_ID);
    assert(firstAccount.includes(ACCOUNT) && secondAccount.includes(SECOND_ACCOUNT)); assert.notEqual(firstAccount, secondAccount);
    assert(!firstAccount.includes(IDS.credential) && !secondAccount.includes(SECOND_GOOGLE_ID));
    const firstKey = await label('connect-credential-choice', STATIC_ID); const secondKey = await label('connect-credential-choice', SECOND_STATIC_ID);
    assert.notEqual(firstKey, secondKey); assert(firstKey.startsWith('Shared key · ') && secondKey.startsWith('Shared key · '));
    await page.locator('#connect-credential-choice').selectOption(SECOND_GOOGLE_ID);
    assert.equal(await page.locator('#connect-google-account-summary [data-resource-id="' + SECOND_GOOGLE_ID + '"]').count(), 1);
    assert((await page.locator('#connect-google-account-summary').innerText()).includes(SECOND_ACCOUNT));
    await page.locator('#connect-credential-next').click(); await page.locator('#connect-application-step').waitFor({state: 'visible'});
    const firstApp = await label('connect-application-choice', IDS.application); const secondApp = await label('connect-application-choice', SECOND_APPLICATION_ID);
    assert.notEqual(firstApp, secondApp); assert(firstApp.startsWith('[' + IDS.application + '] Inbox worker') && secondApp.startsWith('Inbox worker · '));
    assert.notEqual(await label('connect-application-choice', IDS.other), await label('connect-application-choice', 'new'));
    const appLabels = await page.locator('#connect-application-choice option').allTextContents();
    assert.equal(new Set(appLabels).size, appLabels.length, 'literal short-label mimic and action-like name remain visibly distinct');
    await page.locator('#connect-application-choice').selectOption(SECOND_APPLICATION_ID); await page.locator('#connect-application-next').click();
    await page.locator('#connect-access-step').waitFor({state: 'visible'});
    const firstRule = await label('connect-rule-choice', IDS.rule); const secondRule = await label('connect-rule-choice', SECOND_RULE_ID);
    assert.notEqual(firstRule, secondRule); assert(firstRule.startsWith('Read Gmail profile · ') && secondRule.startsWith('Read Gmail profile · '));
    assert.notEqual(await label('connect-rule-choice', ACTION_RULE_ID), await label('connect-rule-choice', 'new'));
    assert.equal(await page.locator('#connect-rule-choice option[value="' + FORMER_RULE_ID + '"]').count(), 0, 'other account/app permissions are not selected by name');
    await page.locator('#connect-rule-choice').selectOption(SECOND_RULE_ID);
    state.credentials.reverse(); state.applications.reverse(); state.rules.reverse(); state.revision++; await refresh(page);
    assert.equal(await page.locator('#connect-credential-choice').inputValue(), SECOND_GOOGLE_ID);
    assert.equal(await page.locator('#connect-application-choice').inputValue(), SECOND_APPLICATION_ID);
    assert.equal(await page.locator('#connect-rule-choice').inputValue(), SECOND_RULE_ID);
    assert.equal(await label('connect-application-choice', SECOND_APPLICATION_ID), secondApp);
    assert.equal(await label('connect-rule-choice', SECOND_RULE_ID), secondRule);
    await page.locator('#connect-review').click(); await page.locator('#connect-review-step').waitFor({state: 'visible'});
    const review = await page.locator('#connect-review-context').innerText();
    assert(review.includes(secondApp) && review.includes(SECOND_ACCOUNT)); assert(!review.includes(firstApp) && !review.includes(ACCOUNT));
    await page.locator('#connect-grant').click(); await page.locator('#connect-setup-slot').waitFor({state: 'visible'});
    await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
    assert.equal(await page.locator('#proxy-application').inputValue(), SECOND_APPLICATION_ID);
    assert.equal(await page.locator('#proxy-rule').inputValue(), SECOND_RULE_ID);
    assert((await page.locator('#client-command').innerText()).includes('Authorization: Bearer OTHER_DUMMY'));
    assert(!await page.locator('#one-time-access').isVisible()); assert.equal(state.posts.length, 0);
  })],
  ['Google replacement uses the fixed Authorization header and full Bearer dummy hint in both editors', browser => fixture(browser, supplied(), async (page, state) => {
    await ready(page); await view(page, 'access-rules'); await page.locator('#rule-credential-input').selectOption('replace_exact');
    assert.equal(await page.locator('#rule-credential-header').innerText(), 'Authorization');
    assert.equal(await page.locator('#rule-placeholder').getAttribute('placeholder'), 'Bearer SERVERWARE_DUMMY');
    await useGoogle(page); await page.locator('#connect-credential-input').selectOption('replace_exact');
    assert.equal(await page.locator('#connect-header-target').innerText(), 'Authorization');
    assert.equal(await page.locator('#connect-placeholder').getAttribute('placeholder'), 'Bearer SERVERWARE_DUMMY');
    assert.equal(state.posts.length, 0);
  })],
  ...['insert', 'replace_exact'].map(mode => ['active saved Google ' + mode + ' rule produces a separate application-auth connection template', browser => fixture(browser,
    supplied({rules: [googleRule(mode)]}), async (page, state) => {
      await useGoogle(page); await reviewSaved(page); await configured(page);
      const command = await page.locator('#client-command').innerText();
      assert(command.includes('Proxy-Authorization: Bearer $SERVERWARE_PROXY_TOKEN'));
      assert.equal(command.includes("--header 'Authorization:"), mode === 'replace_exact');
      if (mode === 'replace_exact') assert(command.includes("Authorization: Bearer GOOGLE-DUMMY-'\\''literal'\\''-$value"));
      assert(await page.locator('#download-config').isDisabled(), 'existing application token is not retrieved');
      assert.equal(state.posts.length, 0); await privateAbsent(page);
    })]),
  ['secret-like extra API fields never enter DOM, embedded page source or private client configuration', browser => fixture(browser,
    supplied({applications: [], credentials: [google({access_token: PRIVATE[0], refresh_token: PRIVATE[1], client_secret: PRIVATE[2],
      encrypted_value: PRIVATE[3], secret: PRIVATE[0], metadata: {refresh_token: PRIVATE[1]}})]}), async (page, state) => {
      await ready(page); await view(page, 'credentials'); await privateAbsent(page); await view(page, 'applications');
      await page.locator('#application-name').fill('Synthetic Google client'); await page.locator('#application-token-ttl').selectOption('3600');
      await page.locator('#application-create').click(); await ready(page);
      await page.locator('#one-time-access').waitFor({state: 'visible'}); const held = await page.locator('#client-token').inputValue();
      assert(held.startsWith('synthetic_application_'));
      // Supply a public saved-rule observation, not a mock Google rule admission.
      state.rules.push(googleRule()); state.revision++; state.active = state.loaded = digest(++state.sequence);
      await view(page, 'connect'); await refresh(page); await useGoogle(page); await reviewSaved(page); await configured(page); await privateAbsent(page);
      const pending = page.waitForEvent('download'); await page.locator('#download-config').click(); const download = await pending;
      assert(download.url().startsWith('blob:'), 'native HTTP downloads are prohibited');
      const stream = await download.createReadStream(); const chunks = []; let bytes = 0;
      for await (const chunk of stream) { bytes += chunk.length; assert(bytes <= 16384); chunks.push(chunk); }
      const contents = Buffer.concat(chunks).toString(); const config = JSON.parse(contents);
      assert.equal(config.proxy_authorization, 'Bearer ' + held); assert.deepEqual(config.request_headers, {Authorization: DUMMY});
      assert.equal(config.credential_input, 'replace_exact'); for (const value of PRIVATE) assert(!contents.includes(value));
      assert(!contents.includes(SUBJECT) && !contents.includes(CLIENT), 'client setup does not need provider account identifiers');
      await download.delete(); assert.deepEqual(state.posts.map(item => item.name), ['applications']);
    })],
  [QUARANTINED_CARD_TEST, browser => fixture(browser,
    supplied({credentials: [quarantine()], rules: [googleRule('replace_exact', {status: 'revoked'})]}), async (page, state) => {
      await ready(page); await view(page, 'credentials'); const card = accountCard(page);
      assert.match(await card.locator('.badge').innerText(), /quarantined.*unusable/i);
      assert.equal(await card.locator('[data-google-account-notice]').innerText(), 'Unavailable for use. Google revocation is not proven.');
      const text = await card.innerText(); assert.match(text, /assigned apps\s+none/i); assert(text.includes('Read Gmail'));
      for (const value of ['Former assignments', 'Reporting application', 'gmail_readonly', SUBJECT, CLIENT, IDS.application]) assert(!text.includes(value));
      assert.equal(await card.locator('[data-action]').count(), 0); assert.equal(await card.locator('details').count(), 1);
      const details = card.locator('[data-google-identity]'); assert(!await details.evaluate(item => item.open));
      await details.locator('summary').click(); assert.match(await details.innerText(), /provider revocation\s+not proven/i);
      assert.match(await details.innerText(), /historical observations do not establish current account health, application-token validity or policy activation/i);
      assert.match(await details.innerText(), /former assignments\s+reporting application/i); assert((await details.innerText()).includes(IDS.application));
      await details.locator('summary').click(); assert(!await details.evaluate(item => item.open));
      await screenshot(page, 'google-quarantine-desktop'); await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'compact quarantine view fits mobile width');
      await screenshot(page, 'google-quarantine-mobile');
      await view(page, 'access-rules'); assert(await page.locator('#rule-save').isDisabled());
      assert.equal(await page.locator('#rule-credential-id option[value="' + IDS.credential + '"]').count(), 0);
      await view(page, 'connect'); assert.equal(await page.locator('#connect-credential-choice option[value="' + IDS.credential + '"]').count(), 0);
      await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
      assert.equal(state.posts.length, 0);
    })],
  ['quarantining the selected account at step one preserves the unavailable choice and cannot resubmit it', browser => fixture(browser,
    supplied({credentials: [google(), credential({id: STATIC_ID})]}), async (page, state) => {
      await ready(page); await page.locator('#connect-use-saved').click();
      await page.locator('#connect-credential-choice').selectOption(IDS.credential); quarantineState(state); await refresh(page);
      assert.equal(await page.locator('#connect-credential-choice').inputValue(), IDS.credential);
      assert(await page.locator('#connect-credential-choice option:checked').evaluate(item => item.disabled));
      assert(await page.locator('#connect-credential-next').isDisabled());
      assert.match(await page.locator('#connect-google-account-summary').innerText(), /quarantined.*unavailable/is); assert.equal(state.posts.length, 0);
    })],
  ...['review', 'setup'].map(stage => ['quarantine during selected Google ' + stage + ' disables the exact workflow without switching accounts', browser => fixture(browser,
    supplied({credentials: [google(), credential({id: STATIC_ID})], rules: [googleRule()]}), async (page, state) => {
      await useGoogle(page); await reviewSaved(page); if (stage === 'setup') await configured(page);
      quarantineState(state); await refresh(page);
      assert.match(await page.locator('#connect-google-account-summary').innerText(), /quarantined.*not proven/is);
      if (stage === 'review') assert(await page.locator('#connect-grant').isDisabled());
      else {
        assert(!await page.locator('#connect-setup-slot').isVisible());
        assert.match(await page.locator('#connect-provider-status').innerText(), /quarantined and unavailable.*provider revocation is not proven.*does not start consent or cleanup/is);
      }
      assert.equal(state.posts.length, 0);
    })]),
  ['quarantined Google account with a contradictory active assignment fails the whole catalog closed', browser => fixture(browser,
    supplied({credentials: [quarantine()], rules: [googleRule()]}), unavailable)],
  ['a false public zero count cannot conceal an active rule referencing a quarantined Google account', browser => fixture(browser,
    supplied({credentials: [quarantine()], rules: [googleRule('replace_exact', {status: 'revoked'})]}), async (page, state, {context}) => {
      await ready(page); // Nearby control: quarantined account with only revoked references is accepted.
      const endpoint = 'https://operator-catalog.example.test/api/operator-demo/catalog'; let calls = 0;
      const observed = {schema: 'serverware.operatorCatalog/v1', mode: 'operator-development', productionReady: false,
        hardwareVerified: false, revision: 2, policy: {policy_hash: digest(1), loaded_policy_hash: digest(1), sequence: 1, activation: 'active'},
        proxy_url: 'https://proxy.example.test', allowed_upstreams: ['https://gmail.googleapis.com'],
        credentials: [quarantine({active_rule_count: 0})], applications: [application({active_rule_count: 1, access_status: 'active'})],
        access_rules: [googleRule()], capabilities: {credential_types: ['bearer', 'header'], oauth: false,
          response_modes: capabilities.responseModes, credential_input_modes: capabilities.credentialInputModes,
          token_lifetime_seconds: {min: 3600, max: 7776000, default: 2592000}},
        limits: Object.fromEntries(['credentials', 'applications', 'access_rules'].map(name => [name,
          {active: name === 'credentials' ? 0 : 1, retained: 1, active_max: 32, retained_max: 1024}]))};
      // One exact synthetic GET response is overridden; no fallback, redirects,
      // route.fetch, browser navigation, or additional network admission exists.
      await context.route(endpoint, async route => {
        const request = route.request(); state.requests.push({path: '/api/operator-demo/catalog', query: '', method: request.method()});
        if (++calls !== 1 || state.requests.length > 150 || request.url() !== endpoint || request.method() !== 'GET' || request.postDataBuffer()?.length) {
          state.unexpected.push('contradictory catalog override boundary refused'); await route.abort(); return;
        }
        state.catalogCalls++; await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(observed)});
      });
      await refresh(page); await unavailable(page, state); assert.equal(calls, 1);
    })],
  ...malformed.map(([name, changes]) => ['malformed public Google metadata: ' + name, browser => fixture(browser,
    supplied({credentials: [google(changes)]}), async (page, state) => {
      await unavailable(page, state);
      if (name === 'unknown permission preset') assert.equal(await accountCard(page).count(), 0, 'unknown preset is rejected before any account card is rendered');
    })]),
];

async function activityCard(page, status, id = IDS.credential) {
  await ready(page); await view(page, 'credentials');
  const card = page.locator('#credentials-list [data-resource-id="' + id + '"]');
  const summary = card.locator('p[data-account-activity]');
  assert.equal(await summary.getAttribute('data-activity-status'), status);
  assert(!await page.locator('#load-error').isVisible());
  assert(!await page.locator('#credential-add').isDisabled()); assert(!await page.locator('#application-create').isDisabled());
  return {card, summary, details: card.locator('details')};
}
async function activityDetails(details) {
  assert(!await details.evaluate(node => node.open)); await details.locator('summary').click();
  const evidence = details.locator('[data-account-activity-details]'); assert(await evidence.isVisible());
  const text = await evidence.innerText();
  for (const phrase of ['audit storage/receiver times, not provider event times', 'no matching event does not mean never used',
    'audit chain has not been verified', 'does not prove delivery to the client or completion of its job',
    'do not establish current account health, application-token validity or policy activation']) assert(text.includes(phrase));
  return text;
}
const activityTests = [
  ['activity: missing additive evidence is unavailable without disabling valid saved resources', browser => activityFixture(browser,
    {rules: [googleRule()]}, async page => {
      const {card, summary, details} = await activityCard(page, 'unavailable'); assert.equal(await summary.innerText(), 'Activity unavailable.');
      assert.equal(await card.locator('details').count(), 1); await activityDetails(details);
      await view(page, 'proxy'); assert(!await page.locator('#copy-command').isDisabled(), 'missing observations do not revoke current independent rule authority');
      assert(await page.locator('#download-config').isDisabled(), 'historical activity never retrieves the app token');
    })],
  ['activity: explicit unavailable reports no successful-use inference', browser => activityFixture(browser,
    {activityObservation: activity({status: 'unavailable', accounts: [], window: {...activity().window, incomplete: true}})}, async page => {
      const {summary, details} = await activityCard(page, 'unavailable'); assert.equal(await summary.innerText(), 'Activity unavailable.');
      const text = await activityDetails(details); assert.match(text, /coverage\s+incomplete evidence/i); assert.match(text, /audit-chain verification\s+not checked/i);
      assert(!text.includes('Refresh success recorded')); await screenshot(page, 'activity-unavailable-desktop');
    })],
  ['activity: unobserved is a bounded scan and the same optional Details appears in Connect', browser => activityFixture(browser,
    {activityObservation: activity()}, async page => {
      const {summary, details} = await activityCard(page, 'unobserved');
      assert.equal(await summary.innerText(), 'No matching activity in the scanned audit window.');
      const text = await activityDetails(details); assert.match(text, /0 of at most 256 recent rows; 0 of at most 2097152 bytes/);
      assert.match(text, /no omissions reported inside this bounded scan/i);
      await view(page, 'connect'); await page.locator('#connect-use-saved').click();
      await page.locator('#connect-credential-choice').selectOption(IDS.credential);
      const selected = page.locator('#connect-google-account-summary');
      assert.equal(await selected.locator('[data-account-activity]').getAttribute('data-activity-status'), 'unobserved');
      await activityDetails(selected.locator('details')); await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1));
      await screenshot(page, 'activity-connect-details-mobile');
      await activityRefresh(page); assert.equal(await page.locator('#connect-credential-choice').inputValue(), IDS.credential);
      assert(await selected.locator('details').evaluate(node => node.open), 'refresh preserves the operator disclosure choice for this exact account');
    })],
  ['activity: incomplete evidence retains a historical response while exposing scan omissions', browser => activityFixture(browser,
    {rules: [googleRule()], activityObservation: observedActivity([activityAccount({last_successful_response: responseEvent()})],
      {window: {...activity().window, rows_scanned: 8, bytes_read: 2048, has_older_rows: true,
        byte_budget_exhausted: true, oversized_events: 1, invalid_events: 1, unmatched_responses: 1, incomplete: true}})}, async page => {
      const {summary, details} = await activityCard(page, 'incomplete');
      assert.match(await summary.innerText(), /proxy recorded a successful response.*evidence incomplete/is);
      const text = await activityDetails(details);
      for (const value of [RESPONSE_EVENT, 'Reporting application', IDS.application, IDS.rule, 'credential version 2']) assert(text.includes(value));
      assert.match(text, /older rows outside scan\s+yes/i); assert.match(text, /byte budget exhausted\s+yes/i);
      assert(text.includes('1 oversized; 1 invalid; 1 unmatched responses')); await screenshot(page, 'activity-incomplete-desktop');
    })],
  ['activity: refresh success cannot renew an expired application token or enable client setup', browser => activityFixture(browser,
    {applications: [application({token_status: 'expired', token_expires_at_epoch_ms: NOW - 1})], rules: [googleRule()],
      activityObservation: observedActivity([activityAccount({last_refresh_success: activityEvent(), last_refresh_outcome: 'success'})])}, async page => {
      const {summary} = await activityCard(page, 'observed'); assert.match(await summary.innerText(), /^Refresh success recorded /);
      assert(!/healthy|reconnect|token valid|policy active/i.test(await summary.innerText()));
      await view(page, 'applications'); assert.match(await page.locator('#applications-list [data-resource-id="' + IDS.application + '"]').innerText(), /token expired/i);
      await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
      assert.match(await page.locator('#client-command').innerText(), /application token is expired, revoked or cannot be verified/i);
      assert.match(await page.locator('#client-guidance').innerText(), /no token has been renewed automatically/i); await screenshot(page, 'activity-expired-app-desktop');
    })],
  ['activity: latest refresh failure is historical evidence not a reconnect diagnosis', browser => activityFixture(browser,
    {activityObservation: observedActivity([activityAccount({last_refresh_success: activityEvent({recorded_at_epoch_ms: NOW - 120000}),
      last_refresh_failure: activityEvent({event_id: FAILURE_EVENT}), last_refresh_outcome: 'failure'})])}, async page => {
      const {card, summary, details} = await activityCard(page, 'observed'); assert.match(await summary.innerText(), /^Refresh failure recorded /);
      assert(!/reconnect|consent required|healthy|revoked/i.test(await summary.innerText()));
      assert.equal(await card.locator('[data-action]').count(), 0); assert(await page.locator('#credential-google-connect').isDisabled());
      const text = await activityDetails(details); assert(text.includes(SUCCESS_EVENT) && text.includes(FAILURE_EVENT));
      assert.match(text, /last recorded refresh success/i); assert.match(text, /last recorded refresh failure/i);
    })],
  ['activity: quarantine remains unusable despite earlier successful response and refresh', browser => activityFixture(browser,
    {credentials: [quarantine()], rules: [googleRule('insert', {status: 'revoked'})],
      activityObservation: observedActivity([activityAccount({last_successful_response: responseEvent(),
        last_refresh_success: activityEvent(), last_refresh_outcome: 'success'})])}, async page => {
      const {card, summary, details} = await activityCard(page, 'observed');
      assert.match(await card.locator('.badge').innerText(), /quarantined.*unusable/i); assert.match(await summary.innerText(), /^Historical activity only:/);
      assert.equal(await card.locator('[data-google-account-notice]').innerText(), 'Unavailable for use. Google revocation is not proven.');
      await activityDetails(details); await view(page, 'connect'); assert(await page.locator('#connect-use-saved').isDisabled());
      assert.equal(await page.locator('#connect-credential-choice option[value="' + IDS.credential + '"]').count(), 0);
      await view(page, 'access-rules'); assert(await page.locator('#rule-save').isDisabled());
      await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
    })],
  ['activity: arbitrary errors and private extras stay absent while public labels remain escaped text', browser => {
    const label = '<img data-activity-injected src=x onerror="window.activityExecuted=true">';
    const appName = '<svg data-activity-injected onload="window.activityExecuted=true">';
    const evidence = observedActivity([activityAccount({last_successful_response: {...responseEvent(), error: ACTIVITY_ERROR},
      last_refresh_success: {...activityEvent(), access_token: PRIVATE[0]}, last_refresh_outcome: 'success', raw_error: ACTIVITY_ERROR})]);
    evidence.raw_error = ACTIVITY_ERROR; evidence.refresh_token = PRIVATE[1];
    return activityFixture(browser, {credentials: [google({provider_account: label})], applications: [application({name: appName})],
      rules: [googleRule()], activityObservation: evidence}, async page => {
      const {card, details} = await activityCard(page, 'observed'); assert((await card.innerText()).includes(label));
      assert((await activityDetails(details)).includes(appName)); assert.equal(await page.locator('[data-activity-injected]').count(), 0);
      assert.equal(await page.evaluate(() => window.activityExecuted), undefined);
      assert(!(await page.content()).includes(ACTIVITY_ERROR)); await privateAbsent(page);
    });
  }],
  ['activity: malformed observations fail only their own display and never replace the selected saved identity', browser => activityFixture(browser,
    {rules: [googleRule()], activityObservation: activity()}, async (page, state) => {
      await view(page, 'connect'); await page.locator('#connect-use-saved').click(); await page.locator('#connect-credential-choice').selectOption(IDS.credential);
      for (const name of ['unknown schema', 'future response', 'foreign credential', 'missing rule', 'success older than failure', 'excess rows']) {
        state.activityObservation = observedActivity([activityAccount({last_successful_response: responseEvent(),
          last_refresh_success: activityEvent(), last_refresh_outcome: 'success'})]);
        malformedActivity.find(([label]) => label === name)[1](state.activityObservation);
        await activityRefresh(page); const {summary} = await activityCard(page, 'unavailable');
        assert.equal(await summary.innerText(), 'Activity unavailable.', name);
        await view(page, 'connect'); assert.equal(await page.locator('#connect-credential-choice').inputValue(), IDS.credential);
        assert(!await page.locator('#connect-credential-next').isDisabled());
      }
      await view(page, 'proxy'); assert(!await page.locator('#copy-command').isDisabled());
    })],
  ['activity: evidence is bound to exact account rule and application rather than a matching label', browser => activityFixture(browser,
    {credentials: [google(), google({id: SECOND_GOOGLE_ID, provider_subject: 'different-subject'})],
      applications: [application(), application({id: SECOND_APPLICATION_ID, name: 'Other worker'})],
      rules: [googleRule('insert', {credential_id: SECOND_GOOGLE_ID, application_id: SECOND_APPLICATION_ID})],
      activityObservation: observedActivity([activityAccount(), activityAccount({credential_id: SECOND_GOOGLE_ID,
        last_successful_response: responseEvent({application_id: SECOND_APPLICATION_ID})})])}, async page => {
      const first = await activityCard(page, 'unobserved'); assert.equal(await first.summary.innerText(), 'No matching activity in the scanned audit window.');
      const second = await activityCard(page, 'observed', SECOND_GOOGLE_ID); assert.match(await second.summary.innerText(), /^Proxy recorded a successful response /);
      const text = await activityDetails(second.details); assert(text.includes(SECOND_APPLICATION_ID) && text.includes('Other worker'));
      assert(!text.includes('(' + IDS.application + ')'));
      await view(page, 'connect'); await page.locator('#connect-use-saved').click(); await page.locator('#connect-credential-choice').selectOption(IDS.credential);
      assert.equal(await page.locator('#connect-google-account-summary [data-account-activity]').getAttribute('data-activity-status'), 'unobserved');
      await page.locator('#connect-credential-choice').selectOption(SECOND_GOOGLE_ID);
      assert.equal(await page.locator('#connect-google-account-summary [data-account-activity]').getAttribute('data-activity-status'), 'observed');
    })],
  ['activity: static keys show joined response evidence without invented Google refresh fields', browser => activityFixture(browser,
    {credentials: [credential()], rules: [rule()], activityObservation: observedActivity([activityAccount({last_successful_response: responseEvent({event_id: digest(9)})})])}, async page => {
      const {card, summary, details} = await activityCard(page, 'observed'); assert.match(await summary.innerText(), /^Proxy recorded a successful response /);
      assert(!/refresh/i.test(await summary.innerText())); assert.equal(await card.locator('details').count(), 1);
      assert.equal(await details.locator('summary').innerText(), 'Activity details');
      const text = await activityDetails(details); assert(text.includes(digest(9))); assert(text.includes('Reporting application'));
      assert(!/last recorded refresh/i.test(text)); assert.equal(await card.locator('[data-action="revoke-credential"]').count(), 1);
      assert(await card.locator('[data-action="revoke-credential"]').isDisabled(), 'existing active-rule revoke guard remains unchanged');
      await screenshot(page, 'activity-static-key-desktop');
    })],
];

async function main() {
  const args = process.argv.slice(2);
  assert(args.length === 0 || (args.length === 1 && ['--cards-only', '--setup-only', '--activity-only'].includes(args[0])),
    'Google presentation tests accept only --cards-only, --setup-only, --activity-only or no arguments');
  const cardTests = new Set([ACTIVE_CARD_TEST, QUARANTINED_CARD_TEST, UNKNOWN_PRESET_TEST]);
  const setupTests = new Set([SETUP_SUMMARY_TEST, DUPLICATE_NAMES_TEST,
    'quarantining the selected account at step one preserves the unavailable choice and cannot resubmit it',
    'quarantine during selected Google review disables the exact workflow without switching accounts',
    'quarantine during selected Google setup disables the exact workflow without switching accounts']);
  const selection = args[0]?.slice(2) || 'all';
  const selected = selection === 'all' ? [...tests, ...activityTests] : selection === 'activity-only' ? activityTests :
    tests.filter(([name]) => (selection === 'cards-only' ? cardTests : setupTests).has(name));
  assert.equal(activityTests.length, 11, 'activity selection remains exactly eleven focused rendered groups');
  if (selection !== 'all') assert.equal(selected.length, selection === 'cards-only' ? 3 : selection === 'setup-only' ? 5 : 11, 'focused selection remains exact');
  const before = await hashes(); console.log(JSON.stringify({phase: 'source-before', hashes: before}));
  if (selection !== 'activity-only') console.log(JSON.stringify(generatorChecks()));
  if (selection === 'all' || selection === 'activity-only') console.log(JSON.stringify(activityProjectionChecks()));
  const artifactRoot = '/srv/catchplate-fast/projects/serverware-operator-artifacts';
  assert((await stat(artifactRoot)).isDirectory()); artifacts = await mkdtemp(join(artifactRoot, 'google-browser-synthetic-'));
  console.log(JSON.stringify({artifactDirectory: artifacts, scope: 'public-account synthetic screenshots only'}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']}); let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of selected) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: selected.length, totalGroups: tests.length + activityTests.length, selection,
        scope: 'intercepted Google public-account presentation fixtures only',
        consentTested: false, cleanupTested: false, otherBrowserSuitesExecuted: false, liveRequests: 0,
        generatedCommandsExecuted: false, auditVerificationTested: false, productionAcceptance: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('Google presentation fixture absolute deadline')), 120000); })]);
  } finally {
    clearTimeout(deadline); try { await browser.close(); }
    finally { const after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after})); assert.deepEqual(after, before, 'sources remained frozen'); }
  }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

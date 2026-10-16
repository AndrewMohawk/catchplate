#!/usr/bin/env node
// Synthetic UI protocol acceptance only: intercepted public catalog/intents,
// exact CAS start receipt and a fake Google navigation document. No actual
// callback, OAuth exchange, provider API, proxy or native download is contacted.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFile, mkdtemp, stat} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {fixture: baseFixture, ready, view, credential, application, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {publicCatalog, google} = require('./test_operator_ordinary_modes_browser.cjs');
const pure = require('../serverware/operator_demo_web/workspace_google.js');
const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const INTENT = '77777777-7777-4777-8777-777777777777';
const OTHER = '88888888-8888-4888-8888-888888888888';
const SCOPES = ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'];
const PRIVATE = ['synthetic-google-provider-secret-never-render', 'synthetic-refresh-token-never-render'];
const STATE = 'synthetic-state-' + 'a'.repeat(43);
const capability = () => ({schema: 'serverware.operatorGoogleCapability/v1', profile: 'operator-google-v1', provider_id: 'google',
  permission_preset: 'gmail_readonly', scopes: [...SCOPES], api_origins: ['https://gmail.googleapis.com'],
  authorization_origin: 'https://accounts.google.com', authorization_path: '/o/oauth2/v2/auth', redirect_uri: ORIGIN + '/api/oauth/callback/google',
  start_path: '/api/operator-demo/oauth/google/start', intents_path: '/api/operator-demo/oauth/google/intents'});
// Independent public contract, matching the existing Gmail bundle fixture
// oracle, not imported from the product's eligibility helper.
const gmailDescriptor = () => ({operation_bundle: 'gmail_read_v1', create_path: '/api/operator-demo/access-rules/gmail-read',
  credential_type: 'google_oauth', permission_preset: 'gmail_readonly', api_origin: 'https://gmail.googleapis.com', methods: ['GET'],
  paths: ['/gmail/v1/users/me/messages', '/gmail/v1/users/me/messages/{message_id}'], query_mode: 'orderedFormV1',
  age_policy: {mode: 'unrestricted'}, response_mode: 'gmail_read_json_v1',
  response_contract: {mode: 'gmailReadJsonV1', body_presence: 'required', content_types: ['application/json'],
    success_status_codes: [200], error_status_codes: [400, 401, 403, 404, 429, 500, 502, 503, 504],
    max_body_bytes: 1048576, max_error_body_bytes: 65536, unlisted_header_policy: 'discardUnselectedV1'}});
const intent = (changes = {}) => ({id: INTENT, name: 'My Gmail account', provider_id: 'google', permission_preset: 'gmail_readonly',
  scopes: [...SCOPES], created_at: new Date(NOW).toISOString(), expires_at_epoch: NOW / 1000 + 600, status: 'awaiting_consent', ...changes});
const status = intents => ({apiVersion: 'serverware.operatorGoogleConsent/v1', intents, limits: {active: 32, retained: 1024},
  productionReady: false, protectedActivationSupported: false});
function startReceipt(name = 'My Gmail account') {
  const query = new URLSearchParams({response_type: 'code', client_id: 'synthetic-client.apps.googleusercontent.com',
    redirect_uri: capability().redirect_uri, scope: SCOPES.join(' '), state: STATE, code_challenge: 'c'.repeat(43),
    code_challenge_method: 'S256', access_type: 'offline', prompt: 'consent', include_granted_scopes: 'true'});
  return {provider: 'google', authorizationUrl: capability().authorization_origin + capability().authorization_path + '?' + query,
    state: STATE, expiresAtEpoch: NOW / 1000 + 600, redirectUri: capability().redirect_uri, scopes: [...SCOPES],
    operatorGoogleIntent: intent({name})};
}
const SOURCE_FILES = ['scripts/test_operator_google_connect_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
  'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py',
  ...['index.html', 'style.css', 'app.js', 'workspace_core.js', 'workspace_github.js', 'workspace_google.js', 'workspace_resources.js',
    'workspace_applications.js', 'workspace_proxy_audit.js', 'workspace_connect.js'].map(name => 'serverware/operator_demo_web/' + name)];
let artifacts;
async function hashes() { return Object.fromEntries(await Promise.all(SOURCE_FILES.map(async path =>
  [path, createHash('sha256').update(await readFile(join(ROOT, path))).digest('hex')]))); }
async function screenshot(page, name) { await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true, mask: [page.locator('#client-token')]}); }
function pureChecks() {
  const caps = {oauth: true, google_oauth: capability(), credential_types: ['bearer', 'header', 'google_oauth']};
  assert.deepEqual(pure.projectGoogleCapability(caps, ORIGIN), capability());
  assert.equal(pure.projectGoogleCapability({oauth: false, google_oauth: null}, ORIGIN), null);
  for (const change of [{authorization_origin: 'https://evil.example.test'}, {start_path: '/api/oauth/start'},
    {redirect_uri: 'https://elsewhere.example.test/api/oauth/callback/google'}, {scopes: ['openid']}, {secret: PRIVATE[0]}])
    assert.throws(() => pure.projectGoogleCapability({...caps, google_oauth: {...capability(), ...change}}, ORIGIN));
  assert.throws(() => pure.projectGoogleCapability({...caps, oauth: false}, ORIGIN));
  const receipt = startReceipt(); assert.equal(pure.validateGoogleStart(receipt, capability(), receipt.operatorGoogleIntent.name, NOW).intent.id, INTENT);
  for (const change of [{state: 'wrong'}, {redirectUri: 'https://evil.example.test'}, {expiresAtEpoch: NOW / 1000},
    {authorizationUrl: receipt.authorizationUrl.replace('accounts.google.com', 'evil.example.test')},
    {authorizationUrl: receipt.authorizationUrl + '&state=duplicate'}, {scopes: ['openid']}])
    assert.throws(() => pure.validateGoogleStart({...receipt, ...change}, capability(), receipt.operatorGoogleIntent.name, NOW));
  const projected = pure.projectGoogleIntents(status([intent({secret: PRIVATE[0], refresh_token: PRIVATE[1]})]));
  for (const value of PRIVATE) assert(!JSON.stringify(projected).includes(value));
  assert.throws(() => pure.projectGoogleIntents(status([intent(), intent()])));
  assert.throws(() => pure.projectGoogleIntents(status([intent({status: 'connected'})])));
  assert.throws(() => pure.projectGoogleIntents(status([intent({status: 'failed', reason: 'private-provider-error'})])));
  const connected = intent({status: 'connected', credential_id: IDS.credential});
  assert.equal(pure.googleConnectedAccount(connected, {credentials: [google()]}).id, IDS.credential);
  for (const record of [google({id: OTHER}), google({status: 'quarantined'}), credential(), google({scopes: ['openid']})])
    assert.equal(pure.googleConnectedAccount(connected, {credentials: [record]}), null);
  assert.deepEqual(pure.googleReturnHint(ORIGIN + '/?operator_google_intent=' + INTENT + '#connect'), {present: true, id: INTENT, clean: '/#connect'});
  for (const query of ['operator_google_intent=bad', 'operator_google_intent=' + INTENT + '&code=never-retain',
    'operator_google_intent=' + INTENT + '&operator_google_intent=' + OTHER])
    assert.deepEqual(pure.googleReturnHint(ORIGIN + '/?' + query + '#connect'), {present: true, id: null, clean: '/#connect'});
  return {ok: true, groups: 1, scope: 'pure capability, navigation, intent and exact-account joins'};
}
async function fixture(browser, options, exercise) {
  return baseFixture(browser, {credentials: options.credentials || [], applications: options.applications || [],
    responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'], credentialInputModes: ['insert', 'replace_exact']},
  async (page, state, controls) => {
    state.allowedUpstreams = ['https://gmail.googleapis.com']; state.requestBodyModes = ['preserve_json_v1'];
    const observations = {posts: [], gets: 0, navigations: 0, returns: 0, enabled: options.enabled !== false,
      bundles: Object.hasOwn(options, 'gmailBundles') ? options.gmailBundles : [gmailDescriptor()],
      intents: options.intents || [], catalogFailure: false, statusFailure: false, catalogTransform: null};
    const answer = (route, value, code = 200) => route.fulfill({status: code, contentType: 'application/json', body: JSON.stringify(value)});
    await controls.context.route(ORIGIN + '/api/operator-demo/catalog', async route => {
      const request = route.request(); state.requests.push({path: '/api/operator-demo/catalog', method: request.method(), query: ''});
      try {
        assert.equal(request.url(), ORIGIN + '/api/operator-demo/catalog'); assert.equal(request.method(), 'GET');
        assert(!request.postDataBuffer()?.length); assert(state.requests.length < 150); state.catalogCalls++;
        if (observations.catalogFailure) { state.expectedFailures.add('/api/operator-demo/catalog'); return await answer(route, {detail: PRIVATE[0]}, 503); }
        let value = publicCatalog(state); value.capabilities.oauth = observations.enabled;
        value.capabilities.google_oauth = observations.enabled ? capability() : null;
        if (observations.enabled) value.capabilities.credential_types.push('google_oauth');
        if (observations.enabled && observations.bundles !== undefined) value.capabilities.operation_bundles = observations.bundles;
        if (observations.catalogTransform) value = observations.catalogTransform(value);
        await answer(route, value);
      } catch (error) { state.errors.push('Google catalog fixture: ' + error.message); await route.abort(); }
    });
    await controls.context.route(ORIGIN + '/api/operator-demo/oauth/google/*', async route => {
      const request = route.request(); const path = new URL(request.url()).pathname;
      try {
        assert.equal(request.url(), ORIGIN + path); assert(observations.gets + observations.posts.length < 30);
        if (path.endsWith('/intents')) {
          assert.equal(path, capability().intents_path); assert.equal(request.method(), 'GET'); assert(!request.postDataBuffer()?.length); observations.gets++;
          if (observations.statusFailure) { state.expectedFailures.add(path); return await answer(route, {detail: PRIVATE[0]}, 503); }
          return await answer(route, options.badStatus ? {...status(observations.intents), apiVersion: 'unknown'} : status(observations.intents));
        }
        assert.equal(path, capability().start_path); assert.equal(request.method(), 'POST'); assert(observations.enabled);
        const bytes = request.postDataBuffer(); assert(bytes && bytes.length <= 2048); assert.equal(observations.posts.length, 0, 'no consent retry');
        assert(request.headers()['content-type'].startsWith('application/json'));
        const body = JSON.parse(bytes.toString());
        assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'name', 'permission_preset']);
        assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
        assert.equal(body.permission_preset, 'gmail_readonly'); assert(body.name.length > 0 && body.name.length <= 128 && body.name === body.name.trim());
        observations.posts.push(body); state.revision += 2;
        let result = startReceipt(body.name); observations.intents.push(result.operatorGoogleIntent);
        if (options.afterStart) options.afterStart(observations, state, result);
        if (options.startFault === 'lost') { state.expectedFailures.add(path); return await route.abort('failed'); }
        if (options.startFault === 'invalid') result.authorizationUrl = 'https://evil.example.test/never-contact';
        return await answer(route, result);
      } catch (error) { state.errors.push('Google endpoint fixture: ' + error.message); await route.abort(); }
    });
    await controls.context.route('https://accounts.google.com/**', async route => {
      const request = route.request();
      try {
        assert.equal(observations.posts.length, 1);
        assert.equal(request.url(), startReceipt(observations.posts[0]?.name).authorizationUrl);
        assert.equal(request.method(), 'GET'); assert(!request.postDataBuffer()?.length); assert(request.isNavigationRequest());
        assert.equal(request.frame(), page.mainFrame()); assert.equal(++observations.navigations, 1);
        // This is an inert intercepted document, not Google's consent page.
        await route.fulfill({status: 200, contentType: 'text/html', body: '<link rel="icon" href="data:,"><h1>Synthetic consent destination</h1>'});
      } catch (error) { state.errors.push('Google navigation fixture: ' + error.message); await route.abort(); }
    });
    const returnToWorkspace = async (id = INTENT, queryExtra = '') => {
      const target = ORIGIN + '/?operator_google_intent=' + id + queryExtra + '#connect';
      // Exact marker landing renders the same frozen portal. No callback
      // endpoint, redirects, route.fetch, network continuation or cookies.
      // Use the immutable original portal rather than the current provider page.
      const {execFileSync} = require('node:child_process');
      const portal = execFileSync('python3', ['-B', '-c', 'from serverware.operator_demo_portal import render; print(render())'],
        {cwd: ROOT, encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024});
      await controls.context.route(target.split('#')[0], async route => {
        assert(++observations.returns <= 2);
        assert.equal(route.request().url(), target.split('#')[0]); assert.equal(route.request().method(), 'GET');
        assert(!route.request().postDataBuffer()?.length);
        await route.fulfill({status: 200, contentType: 'text/html', body: portal});
      }, {times: 1});
      await page.goto(target, {waitUntil: 'networkidle'});
      assert.equal(new URL(page.url()).search, '', 'return marker removed immediately');
    };
    await ready(page); await view(page, 'connect');
    await page.locator('#connect-status-refresh').click(); await page.waitForLoadState('networkidle');
    await exercise(page, state, observations, {...controls, returnToWorkspace});
    assert(observations.posts.length <= 1); assert(observations.navigations <= 1);
  });
}
async function open(page) {
  await page.locator('#connect-google').click(); await page.locator('#google-consent-panel').waitFor({state: 'visible'});
  await exclusiveGoogle(page);
  await page.waitForLoadState('networkidle');
}
async function managementGoogle(page) {
  await view(page, 'credentials');
  const disclosure = page.locator('#credential-google-connect').locator('xpath=ancestor::details[1]');
  if (!await disclosure.evaluate(node => node.open)) await disclosure.locator(':scope > summary').click();
  await page.locator('#credential-google-connect').click();
  await page.locator('#google-consent-panel').waitFor({state: 'visible'}); await exclusiveGoogle(page);
  await page.waitForLoadState('networkidle');
}
async function exclusiveGoogle(page, expectedForms = 1) {
  assert(await page.locator('#connect').isVisible()); assert(await page.locator('#google-consent-panel').isVisible());
  assert(await page.locator('#connect-method-choice').isHidden()); assert(await page.locator('#connect-credential-form').isHidden());
  assert(await page.locator('#connect-google').isHidden()); assert(await page.locator('#connect-method-change').isHidden());
  assert.equal(await page.locator('#google-consent-panel').count(), 1);
  assert.equal(await page.locator('#connect-credential-step form:visible').count(), expectedForms);
  assert.equal(await page.locator('form form').count(), 0, 'forms remain siblings, never nested');
}
async function start(page, state, observed, outcome) {
  assert(['navigate', 'uncertain', 'unreconciled'].includes(outcome));
  await page.locator('#google-account-name').fill('My Gmail account');
  try {
    if (outcome === 'navigate') {
      // Arm the next-document event before the click. The old document's
      // already-fired networkidle event does not await an async submit handler.
      await Promise.all([
        page.waitForURL(startReceipt().authorizationUrl, {timeout: 5000, waitUntil: 'domcontentloaded'}),
        page.locator('#google-consent-start').click(),
      ]);
    } else {
      await page.locator('#google-consent-start').click();
      const text = outcome === 'uncertain' ? /^Consent may have started, but no exact receipt was confirmed\./ :
        /^The exact consent attempt could not be reconciled\. No navigation or retry occurred\./;
      await page.locator('#google-consent-status').filter({hasText: text}).waitFor({state: 'visible', timeout: 5000});
      if (outcome === 'uncertain') await page.locator('#mutation-review').waitFor({state: 'visible', timeout: 5000});
      await page.locator('#google-consent-leave:enabled').waitFor({state: 'visible', timeout: 5000});
    }
  } catch (_) {
    // Never print the navigation exception: it can contain the OAuth URL/state.
    const ui = await page.evaluate(() => {
      const status = document.querySelector('#google-consent-status')?.textContent || '';
      const phases = [['Saving...', 'saving'], ['Checking saved consent', 'checking'],
        ['The exact consent attempt could not be reconciled.', 'reconciliation-refused'],
        ['Consent may have started,', 'unconfirmed'], ['Waiting for Google consent', 'awaiting-consent'],
        ['Saved Google connection status is unavailable.', 'status-unavailable']];
      const review = document.querySelector('#mutation-review'); const leave = document.querySelector('#google-consent-leave');
      return {phase: phases.find(([prefix]) => status.startsWith(prefix))?.[1] || 'other',
        uncertaintyReviewVisible: Boolean(review && !review.hidden), leaveEnabled: Boolean(leave && !leave.disabled),
        startDisabled: document.querySelector('#google-consent-start')?.matches(':disabled') ?? null,
        operatorOrigin: location.origin === 'https://operator-catalog.example.test'};
    }).catch(() => ({phase: 'document-unavailable'}));
    console.log(JSON.stringify({phase: 'consent-checkpoint-failed', expected: outcome, ui,
      startPosts: observed.posts.length, intentReads: observed.gets, catalogReads: state.catalogCalls,
      syntheticNavigations: observed.navigations, fixtureErrorCount: state.errors.length, unexpectedRequestCount: state.unexpected.length}));
    throw new Error('Consent completion checkpoint failed; see sanitized diagnostic receipt');
  }
}
async function absent(page) {
  const surfaces = await page.evaluate(() => [document.documentElement.outerHTML, ...[...document.querySelectorAll('input,textarea')].map(node => node.value),
    ...Object.values(localStorage), ...Object.values(sessionStorage)].join('\n'));
  for (const value of [...PRIVATE, STATE]) assert(!surfaces.includes(value), 'OAuth private/transient material not retained in UI/storage');
}
const tests = [
  ['disabled profile makes no consent request and does not block static configuration', browser => fixture(browser, {enabled: false}, async (page, state, observed) => {
    await ready(page); assert(await page.locator('#connect-method-choice').isVisible());
    assert.equal(await page.locator('#connect-credential-step form:visible').count(), 0);
    assert(await page.locator('#connect-google').isDisabled()); await view(page, 'credentials');
    assert(await page.locator('#credential-google-connect').isDisabled()); assert.equal(observed.gets, 0); assert.equal(observed.posts.length, 0);
  })],
  ['advertised profile uses exact CAS/preset and a single strictly validated Google navigation', browser => fixture(browser, {}, async (page, state, observed) => {
    await open(page); assert.equal(await page.locator('#google-start-form input').count(), 1);
    await screenshot(page, 'google-connect-desktop'); await start(page, state, observed, 'navigate');
    assert.equal(observed.posts.length, 1); assert.equal(observed.navigations, 1); assert.equal(state.revision, 3);
    assert.equal(new URL(page.url()).origin, 'https://accounts.google.com'); assert.equal(state.posts.length, 0);
  })],
  ['return reconciles exact saved account before explicit app selection, never creates an app or rule', browser => fixture(browser,
    {credentials: [google()], intents: [intent({status: 'connected', credential_id: IDS.credential, secret: PRIVATE[0]})]}, async (page, state, observed, controls) => {
      await controls.returnToWorkspace(); await page.locator('#google-consent-use').waitFor({state: 'visible'});
      await exclusiveGoogle(page, 0);
      assert.match(await page.locator('#google-consent-account').innerText(), /ordinary-fixture@example.test.*Read Gmail.*health.*not been checked/);
      assert(await page.locator('#google-consent-use').isEnabled(), 'the exact advertised Gmail bundle permits explicit reuse');
      await absent(page); await page.setViewportSize({width: 390, height: 844}); await screenshot(page, 'google-return-mobile');
      await page.locator('#google-consent-use').click(); await page.locator('#connect-application-step').waitFor({state: 'visible'});
      assert(await page.locator('#google-consent-panel').isHidden()); assert(await page.locator('#connect-credential-form').isHidden());
      assert.equal(await page.locator('#connect-credential-choice').inputValue(), IDS.credential);
      assert.equal(state.posts.length, 0); assert.equal(observed.posts.length, 0);
    })],
  ['missing or withdrawn Gmail access keeps the saved account visible and blocks rendered and dispatched use', async browser => {
    for (const kind of ['missing', 'withdrawn']) await fixture(browser,
      {credentials: [google()], gmailBundles: kind === 'missing' ? undefined : [gmailDescriptor()],
        intents: [intent({status: 'connected', credential_id: IDS.credential})]}, async (page, state, observed, controls) => {
        const saved = JSON.stringify({credentials: state.credentials, applications: state.applications, rules: state.rules, revision: state.revision});
        await controls.returnToWorkspace(); await page.locator('#google-consent-use').waitFor({state: 'visible'});
        if (kind === 'withdrawn') {
          assert(await page.locator('#google-consent-use').isEnabled());
          observed.bundles = [];
          await page.locator('#google-consent-refresh').click(); await page.waitForLoadState('networkidle');
        }
        await page.locator('#google-consent-use:disabled').waitFor({state: 'visible'});
        const account = await page.locator('#google-consent-account').innerText();
        assert.match(account, /ordinary-fixture@example.test.*This credential is saved, but this instance does not offer supported Gmail client access/);
        assert.match(account, /Saving the credential alone does not grant client access/);
        assert(await page.locator('#connect-application-step').isHidden());
        await page.locator('#google-consent-use').dispatchEvent('click');
        assert(await page.locator('#google-consent-use').isDisabled());
        assert(await page.locator('#google-consent-account').isVisible());
        assert(await page.locator('#google-consent-panel').isVisible());
        assert(await page.locator('#connect-application-step').isHidden());
        assert.equal(await page.locator('#client-token').inputValue(), '');
        assert(await page.locator('#one-time-access').isHidden());
        assert.equal(state.posts.length, 0); assert.equal(observed.posts.length, 0); assert.equal(observed.navigations, 0);
        assert.equal(JSON.stringify({credentials: state.credentials, applications: state.applications, rules: state.rules, revision: state.revision}), saved);
        await absent(page);
      });
  }],
  ...['missing', 'quarantined', 'wrong-id'].map(kind => ['connected receipt refuses ' + kind + ' account', browser => fixture(browser,
    {credentials: kind === 'missing' ? [] : [kind === 'quarantined' ? google({status: 'quarantined', quarantined_at: new Date(NOW).toISOString(),
      quarantine_reason: 'operator_google_cleanup_fence', provider_revocation_status: 'not_proven'}) : google({id: OTHER})],
      intents: [intent({status: 'connected', credential_id: IDS.credential})]}, async (page, state, observed, controls) => {
      await controls.returnToWorkspace(); assert(await page.locator('#google-consent-use').isHidden());
      assert.match(await page.locator('#google-consent-status').innerText(), /missing or unavailable/); assert.equal(observed.posts.length, 0);
    })]),
  ['actor-unowned return reference cannot select an account by name', browser => fixture(browser,
    {credentials: [google()], intents: [intent({id: OTHER, status: 'connected', credential_id: IDS.credential})]}, async (page, state, observed, controls) => {
      await controls.returnToWorkspace(); assert.match(await page.locator('#google-consent-status').innerText(), /not found/);
      assert(await page.locator('#google-consent-use').isHidden()); assert(await page.locator('#application-create').isDisabled());
      await page.locator('#google-consent-leave').click(); await ready(page); assert.equal(observed.posts.length, 0);
    })],
  ...['awaiting_consent', 'exchanging'].map(statusValue => ['selected ' + statusValue + ' holds writes but explicit exit preserves server intent', browser => fixture(browser,
    {intents: [intent({status: statusValue, expires_at_epoch: statusValue === 'exchanging' ? NOW / 1000 - 10 : NOW / 1000 + 600})]}, async (page, state, observed, controls) => {
      await controls.returnToWorkspace(); assert(await page.locator('#application-create').isDisabled()); assert(await page.locator('#credential-add').isDisabled());
      await exclusiveGoogle(page, 0); await view(page, 'overview'); assert(await page.locator('#google-consent-panel').isHidden());
      await view(page, 'connect'); await exclusiveGoogle(page, 0);
      await page.locator('#google-consent-leave').click(); await ready(page); assert.equal(observed.intents[0].status, statusValue);
      assert(await page.locator('#connect-method-choice').isVisible()); assert(await page.locator('#google-consent-panel').isHidden());
      assert.equal(observed.posts.length, 0); assert.equal(state.posts.length, 0);
    })]),
  ['unrelated historical exchanging intent does not permanently freeze the workspace', browser => fixture(browser,
    {intents: [intent({status: 'exchanging', expires_at_epoch: NOW / 1000 - 60})]}, async (page, state, observed) => {
      await ready(page); assert(!await page.locator('#application-create').isDisabled()); await open(page);
      await page.locator('#google-consent-history summary').click(); assert.match(await page.locator('#google-consent-history').innerText(), /still being confirmed/);
      assert.equal(observed.posts.length, 0);
    })],
  ...['consent_denied', 'expired'].map(reason => ['terminal ' + reason + ' is honest and never restarts consent', browser => fixture(browser,
    {intents: [intent({status: reason === 'expired' ? 'expired' : 'failed', reason})]}, async (page, state, observed, controls) => {
      await controls.returnToWorkspace(); assert(await page.locator('#google-consent-use').isHidden());
      assert.match(await page.locator('#google-consent-status').innerText(), reason === 'expired' ? /expired/ : /declined/);
      assert(await page.locator('#google-consent-start').isDisabled()); assert.equal(observed.posts.length, 0);
    })]),
  ...['lost', 'invalid'].map(startFault => ['uncertain ' + startFault + ' start never navigates/retries and exit retains generic uncertainty', browser => fixture(browser,
    {startFault}, async (page, state, observed) => {
      await open(page); await start(page, state, observed, 'uncertain'); assert.equal(observed.posts.length, 1); assert.equal(observed.navigations, 0);
      assert(await page.locator('#google-consent-start').isDisabled()); await absent(page);
      await page.locator('#google-consent-leave').click(); assert(await page.locator('#application-create').isDisabled());
      assert(await page.locator('#mutation-review').isVisible()); assert.equal(observed.posts.length, 1);
      await page.locator('#mutation-review-confirm').click(); await ready(page);
    })]),
  ['failed fresh catalog after successful POST cannot navigate or submit again', browser => fixture(browser,
    {afterStart: observed => { observed.catalogFailure = true; }}, async (page, state, observed) => {
      await open(page); await start(page, state, observed, 'unreconciled'); assert.equal(observed.posts.length, 1); assert.equal(observed.navigations, 0);
      assert(await page.locator('#google-consent-start').isDisabled()); assert(await page.locator('#load-error').isVisible()); await absent(page);
    })],
  ['capability withdrawal after start blocks navigation without fallback', browser => fixture(browser,
    {afterStart: observed => { observed.enabled = false; }}, async (page, state, observed) => {
      await open(page); await start(page, state, observed, 'unreconciled'); assert.equal(observed.posts.length, 1); assert.equal(observed.navigations, 0);
      assert(await page.locator('#connect-google').isDisabled()); assert(await page.locator('#google-consent-use').isHidden());
    })],
  ['unacknowledged one-time app token blocks consent until the existing saved-and-clear action', browser => fixture(browser, {}, async (page, state, observed) => {
    await view(page, 'applications'); await page.locator('#application-name').fill('Synthetic application'); await page.locator('#application-create').click();
    await page.locator('#one-time-access').waitFor({state: 'visible'}); const token = await page.locator('#client-token').inputValue();
    await view(page, 'connect'); await open(page); assert(await page.locator('#google-consent-start').isDisabled());
    assert.equal(await page.locator('#client-token').inputValue(), token); assert(await page.locator('#google-token-warning').isVisible());
    await view(page, 'applications'); await page.locator('#dismiss-token').click();
    assert.equal(await page.locator('#client-token').inputValue(), ''); assert(!await page.locator('#google-consent-start').isDisabled());
    await view(page, 'connect'); await exclusiveGoogle(page);
    assert.equal(observed.posts.length, 0);
  })],
  ['unexpected return parameters are removed, rejected and never treated as connected', browser => fixture(browser,
    {credentials: [google()], intents: [intent({status: 'connected', credential_id: IDS.credential})]}, async (page, state, observed, controls) => {
      await controls.returnToWorkspace(INTENT, '&code=synthetic-never-retain'); assert(await page.locator('#google-consent-use').isHidden());
      assert(!page.url().includes('code=')); assert.equal(observed.posts.length, 0);
    })],
  ['malformed public intent response fails closed without retaining private extras', browser => fixture(browser, {badStatus: true}, async (page, state, observed) => {
    await open(page); assert(await page.locator('#google-consent-start').isDisabled()); await absent(page); assert.equal(observed.posts.length, 0);
  })],
  ['management Google action reuses the one Connect panel and Leave restores the untouched application draft', browser => fixture(browser,
    {credentials: [credential()], applications: [application()]}, async (page, state, observed) => {
      await page.locator('#connect-use-saved').click(); await page.locator('#connect-credential-choice').selectOption(IDS.credential);
      await page.locator('#connect-credential-next').click(); await page.locator('#connect-application-step').waitFor({state: 'visible'});
      await page.locator('#connect-application-name').fill('Keep this application draft');
      await page.locator('#connect-token-ttl').selectOption('3600');
      assert.equal(await page.locator('#connect-title').innerText(), 'Set up access');
      await managementGoogle(page);
      assert.equal(await page.locator('#connect-title').innerText(), 'Add credential');
      assert(await page.locator('#credential-google-connect').isHidden());
      await page.locator('#google-consent-leave').click(); await page.locator('#connect-application-step').waitFor({state: 'visible'});
      assert.equal(await page.locator('#connect-title').innerText(), 'Set up access');
      assert.equal(await page.locator('#connect-application-name').inputValue(), 'Keep this application draft');
      assert.equal(await page.locator('#connect-token-ttl').inputValue(), '3600');
      assert.equal(await page.locator('#connect-credential-choice').inputValue(), IDS.credential);
      assert.equal(await page.locator('#connect-credential-secret').inputValue(), '');
      assert.equal(state.posts.length, 0); assert.equal(observed.posts.length, 0);
    })],
  ['management Google entry and Leave restore the exact save-only receipt without creating access', browser => fixture(browser, {}, async (page, state, observed) => {
    await view(page, 'credentials'); await page.locator('#credentials [data-credential-provider="manual"]').click();
    await page.locator('#connect-credential-name').fill('Saved before Google');
    await page.locator('#connect-credential-secret').fill('synthetic-layout-save-only-key');
    await page.locator('#connect-credential-next').click(); await page.locator('#connect-credential-saved').waitFor({state: 'visible'});
    await ready(page); assert.equal(await page.locator('#connect-title').innerText(), 'Add credential');
    const receipt = await page.locator('#connect-credential-saved-summary').innerText();
    assert.match(receipt, /Saved before Google/);
    const resources = JSON.stringify({credentials: state.credentials, applications: state.applications, rules: state.rules, revision: state.revision});
    await managementGoogle(page); assert(await page.locator('#connect-credential-saved').isHidden());
    assert.equal(await page.locator('#connect-credential-secret').inputValue(), '');
    await page.locator('#google-consent-leave').click(); await page.locator('#connect-credential-saved').waitFor({state: 'visible'});
    assert.equal(await page.locator('#connect-title').innerText(), 'Add credential');
    assert.equal(await page.locator('#connect-credential-saved-summary').innerText(), receipt);
    assert(await page.locator('#connect-application-step').isHidden());
    assert.equal(await page.locator('#connect-credential-secret').inputValue(), '');
    assert.deepEqual(state.posts.map(item => item.name), ['credentials']); assert.equal(observed.posts.length, 0);
    assert.equal(state.applications.length, 0); assert.equal(state.rules.length, 0);
    assert.equal(await page.locator('#client-token').inputValue(), '');
    assert.equal(JSON.stringify({credentials: state.credentials, applications: state.applications, rules: state.rules, revision: state.revision}), resources);
    await page.locator('#connect-saved-use').click(); await page.locator('#connect-application-step').waitFor({state: 'visible'});
    assert.equal(await page.locator('#connect-title').innerText(), 'Set up access');
    assert.equal(await page.locator('#connect-credential-choice').inputValue(), IDS.credential);
    assert.equal(state.posts.length, 1); assert.equal(observed.posts.length, 0);
  })],
  ['changing to Google and leaving preserves the non-secret API-key draft while clearing its secret', browser => fixture(browser, {}, async (page, state, observed) => {
    await page.locator('#connect-use-key').click(); await page.locator('#connect-credential-name').fill('Keep this API-key draft');
    await page.locator('#connect-credential-secret').fill('synthetic-layout-key-draft');
    await page.locator('#connect-method-change').click(); await open(page);
    assert(await page.locator('#connect-credential-secret').isDisabled());
    assert.equal(await page.locator('#connect-credential-secret').inputValue(), '');
    await page.locator('#google-consent-leave').click(); await page.locator('#connect-use-key').click();
    assert.equal(await page.locator('#connect-credential-name').inputValue(), 'Keep this API-key draft');
    assert.equal(await page.locator('#connect-credential-secret').inputValue(), '');
    assert(await page.locator('#google-consent-panel').isHidden()); assert.equal(state.posts.length, 0); assert.equal(observed.posts.length, 0);
  })],
];
async function main() {
  const args = process.argv.slice(2);
  assert(args.length === 0 || args.length === 2 && args[0] === '--from-group' && /^(?:[1-9]|1[0-9]|2[0-3])$/.test(args[1]),
    'Only no arguments or exact --from-group N (1..23) are accepted');
  const firstGroup = args.length ? Number(args[1]) : 1; const selected = tests.slice(firstGroup - 1);
  const runPure = args.length === 0;
  const before = await hashes(); console.log(JSON.stringify({phase: 'source-before', hashes: before}));
  console.log(JSON.stringify({phase: 'selection', firstGroup, lastGroup: tests.length, renderedGroups: selected.length, pureGroups: runPure ? 1 : 0}));
  if (runPure) console.log(JSON.stringify(pureChecks()));
  const artifactRoot = '/srv/catchplate-fast/projects/serverware-operator-artifacts'; assert((await stat(artifactRoot)).isDirectory());
  artifacts = await mkdtemp(join(artifactRoot, 'google-connect-synthetic-')); console.log(JSON.stringify({artifactDirectory: artifacts}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']}); let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of selected) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, firstGroup, lastGroup: tests.length, renderedGroups: selected.length, pureGroups: runPure ? 1 : 0, actualConsent: false,
        actualCallback: false, providerRequests: 0, proxyRequests: 0, nativeDownloads: 0, otherSuitesExecuted: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('Google connect fixture absolute deadline')), 150000); })]);
  } finally {
    clearTimeout(deadline); try { await browser.close(); }
    finally { const after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after})); assert.deepEqual(after, before); }
  }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

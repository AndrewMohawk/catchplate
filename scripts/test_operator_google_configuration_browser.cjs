#!/usr/bin/env node
// Actual rendered assets, intercepted synthetic HTTP only. Never accepts a
// target URL, continues/fetches a request, restarts a process, contacts Google,
// starts consent or proves the connected configuration API/SQLite boundary.
const assert = require('node:assert/strict');
const {withoutMutationReview} = require('./operator_mutation_recovery_test_helpers.cjs');
const {createHash} = require('node:crypto');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {fixture: ordinaryFixture} = require('./test_operator_ordinary_modes_browser.cjs');
const {ready, view: navigateView, NOW} = require('./test_operator_catalog_browser.cjs');
const view = (page, name) => navigateView(page, name === 'proxy' ? 'proxy-operator-settings' : name);

const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const PATH = '/api/operator-demo/oauth/google/configuration/v2';
const STORAGE = 'catchplate.operator.google.configuration.operation.v2';
const PLAYWRIGHT = '/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright';
const CLIENT = '123-synthetic-configuration.apps.googleusercontent.com';
const SECRET = 'synthetic-Google-application-secret-NEVER-RETAIN';
const PRIVATE = 'synthetic-private-provider-error-path-NEVER-RENDER';
const OWNER = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const OTHER_POLICY = 'sha256:' + 'f'.repeat(64);
const GMAIL = 'https://gmail.googleapis.com';
const SCOPES = ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'];
const OLD = {allowed_upstreams: ['https://demo-upstream:8443'], fixture_cidrs: ['172.31.252.2/32']};
const TARGET = {...OLD, allowed_upstreams: [...OLD.allowed_upstreams, GMAIL]};
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const clone = value => JSON.parse(JSON.stringify(value));
const sorted = value => Array.isArray(value) ? value.map(sorted) : value && typeof value === 'object' ?
  Object.fromEntries(Object.keys(value).sort().map(key => [key, sorted(value[key])])) : value;
const digest = value => 'sha256:' + createHash('sha256').update(JSON.stringify(sorted(value))).digest('hex');
const node = (page, name) => page.locator('#google-configuration-' + name);

function profile() {
  return {schema: 'catchplate.operatorGoogleProfile/v1', profile: 'operator-google-v1', provider_id: 'google',
    client_id: CLIENT, redirect_uri: ORIGIN + '/api/oauth/callback/google', permission_preset: 'gmail_readonly',
    scopes: [...SCOPES], api_origins: [GMAIL], authorization_url: 'https://accounts.google.com/o/oauth2/v2/auth',
    token_url: 'https://oauth2.googleapis.com/token', revocation_url: 'https://oauth2.googleapis.com/revoke',
    identity_url: 'https://openidconnect.googleapis.com/v1/userinfo'};
}
function capability() {
  const value = profile();
  return {schema: 'catchplate.operatorGoogleCapability/v1', ...Object.fromEntries(
    ['profile', 'provider_id', 'permission_preset', 'scopes', 'api_origins', 'redirect_uri'].map(key => [key, value[key]])),
    authorization_origin: 'https://accounts.google.com', authorization_path: '/o/oauth2/v2/auth',
    start_path: '/api/operator-demo/oauth/google/start', intents_path: '/api/operator-demo/oauth/google/intents'};
}
function review(state) {
  return {schema: 'catchplate.operatorGoogleManagedSetupReview/v2', expected_revision: state.revision,
    expected_policy_hash: state.active, expected_settings_digest: digest(state.settings), old_settings: clone(state.settings),
    target_settings: clone(TARGET), public_url: ORIGIN, redirect_uri: profile().redirect_uri,
    provider_id: 'google', permission_preset: 'gmail_readonly', scopes: [...SCOPES], eligible: true};
}
function operation(state, input) {
  return {schema: 'catchplate.operatorGoogleManagedSetup/v2', operation_id: input.operation_id, client_id: CLIENT,
    old_settings: clone(state.settings), target_settings: clone(TARGET), expected_settings_digest: digest(state.settings),
    public_url: ORIGIN, redirect_uri: profile().redirect_uri, profile_binding: profile(), profile_binding_digest: digest(profile()),
    reviewed_revision: state.revision, staged_revision: state.revision + 1, policy_hash: state.active,
    created_at: new Date(NOW).toISOString(), setup_contract: 'catchplate.operatorGoogleManagedSetupBinding/v2',
    custody_ref: {owner_id: OWNER, config_version: 1, key_source: 'operator-provider-key-v1'}, secret_present: true,
    status: 'pending', revision: ++state.revision, completed_at: null, activation_receipt: null};
}
function terminal(state, observed, status) {
  const value = {...clone(observed.operation), status, revision: ++state.revision,
    completed_at: new Date(NOW + 1000).toISOString(), activation_receipt: null};
  if (status === 'activated') {
    value.activation_receipt = {schema: 'catchplate.operatorGoogleSetupActivation/v1', operation_id: value.operation_id,
      activated_revision: value.revision, policy_hash: value.policy_hash, profile_binding_digest: value.profile_binding_digest,
      settings_digest: digest(value.target_settings), activated_at: value.completed_at};
    state.settings = clone(TARGET); state.allowedUpstreams = [...TARGET.allowed_upstreams];
  }
  observed.operation = value;
  return value;
}
function discovery(state, observed) {
  const current = observed.operation && observed.operation.status !== 'cancelled' ? observed.operation : null;
  const phase = current?.status || 'unconfigured';
  const blocked = phase === 'pending' ? 'pending_configuration' : phase === 'activated' ? 'already_configured' : observed.blockedReason;
  return {schema: 'catchplate.operatorGoogleConfiguration/v2', state: phase, revision: state.revision, policy_hash: state.active,
    effective_settings: clone(state.settings), effective_settings_digest: digest(state.settings), public_url: ORIGIN,
    redirect_uri: profile().redirect_uri, permission_preset: 'gmail_readonly', scopes: [...SCOPES], blocked_reason: blocked,
    review: phase === 'unconfigured' && blocked === null ? review(state) : null,
    operation: current && observed.owned ? clone(current) : null,
    readiness: {pair_ready: observed.pairReady, consent_ready: phase === 'activated' && observed.pairReady,
      loaded_policy_hash: observed.pairReady ? state.active : null}};
}
async function noMaterial(page, {draft = false} = {}) {
  const surfaces = await page.evaluate(() => ({html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].map(item => ({id: item.id, value: item.value})),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  assert(!JSON.stringify(surfaces).includes(PRIVATE), 'raw server errors never enter the UI or browser storage');
  assert(!surfaces.html.includes(SECRET), 'secret is never an HTML attribute or text node');
  for (const item of surfaces.fields) if (!(draft && item.id === 'google-configuration-client-secret'))
    assert(!item.value.includes(SECRET), 'secret clears from every field after leaving the draft');
  assert.deepEqual(surfaces.local, [], 'no localStorage persistence');
  const references = withoutMutationReview(surfaces.session);
  for (const [key, encoded] of references) {
    assert.equal(key, STORAGE); const value = JSON.parse(encoded);
    assert.deepEqual(Object.keys(value).sort(), ['kind', 'operation_id']);
    assert(UUID.test(value.operation_id) && ['prepare', 'cancel'].includes(value.kind));
    assert(!encoded.includes(CLIENT) && !encoded.includes(SECRET) && !encoded.includes(PRIVATE));
  }
  return references.length ? JSON.parse(references[0][1]) : null;
}
async function screenshot(page, directory, name) {
  await noMaterial(page);
  await page.screenshot({path: join(directory, name + '.png'), fullPage: true,
    mask: [node(page, 'client-secret'), page.locator('#client-token'), page.locator('#connect-credential-secret')]});
}
async function fixture(browser, options, exercise) {
  activeVariant = options.external ? 'external-profile' : options.unsupported ? 'unsupported-profile' : 'managed-profile';
  activeStep = 'fixture-shell-start';
  return ordinaryFixture(browser, {credentials: [], applications: [], rules: [], allowedUpstreams: [...OLD.allowed_upstreams],
    responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'], requestBodyModes: ['preserve_json_v1'],
    credentialInputModes: ['insert', 'replace_exact']}, async (page, state, controls) => {
    activeStep = 'fixture-install-overrides';
    state.settings = clone(options.external ? TARGET : OLD);
    if (options.external) state.allowedUpstreams = [...TARGET.allowed_upstreams];
    const observed = {requests: [], prepares: [], cancels: [], operation: null, owned: true, pairReady: true,
      blockedReason: null, statusCode: 200, reviewStatus: 200, intentsReads: 0, discoveryTransform: null, operationTransform: null};
    page.on('console', message => {
      if ([SECRET, PRIVATE].some(value => message.text().includes(value)))
        state.errors.push('Google configuration secret or raw error escaped through browser console');
    });
    const resources = clone({credentials: state.credentials, applications: state.applications, rules: state.rules});
    let releasePrepare; let arrivedPrepare;
    const prepareArrival = new Promise(resolve => { arrivedPrepare = resolve; });
    const prepareGate = options.deferPrepare ? new Promise(resolve => { releasePrepare = resolve; }) : Promise.resolve();
    const answer = (route, body, status = 200) => route.fulfill({status, contentType: 'application/json',
      headers: {'Cache-Control': 'no-store'}, body: JSON.stringify(body)});
    state.catalogTransform = value => {
      const enabled = options.external || observed.operation?.status === 'activated';
      value.capabilities.oauth = Boolean(enabled); value.capabilities.google_oauth = enabled ? capability() : null;
      if (enabled) value.capabilities.credential_types.push('google_oauth');
      return value;
    };
    const handler = async route => {
      const request = route.request(); const url = new URL(request.url()); const bytes = request.postDataBuffer();
      try {
        assert.equal(url.origin, ORIGIN); assert.equal(url.search, ''); assert(observed.requests.length < 50);
        observed.requests.push({method: request.method(), path: url.pathname});
        if (request.method() === 'GET') {
          assert(!bytes?.length);
          if (url.pathname === PATH) {
            if (options.unsupported || options.external) {
              state.expectedFailures.add(PATH);
              return await answer(route, {detail: 'Managed Google configuration is not supported by this deployment'}, 404);
            }
            if (observed.reviewStatus !== 200) {
              state.expectedFailures.add(PATH); return await answer(route, {detail: PRIVATE}, observed.reviewStatus);
            }
            let value = discovery(state, observed);
            if (observed.discoveryTransform) value = observed.discoveryTransform(value);
            return await answer(route, value);
          }
          const id = url.pathname.slice(PATH.length + 1);
          assert(UUID.test(id) && id === (observed.operation?.operation_id || observed.prepares[0]?.operation_id));
          if (!observed.owned || !observed.operation || observed.statusCode !== 200) {
            const status = observed.statusCode === 200 ? 404 : observed.statusCode;
            state.expectedFailures.add(url.pathname); return await answer(route, {detail: PRIVATE}, status);
          }
          const result = observed.operationTransform ? observed.operationTransform(clone(observed.operation)) : observed.operation;
          return await answer(route, result);
        }
        assert.equal(request.method(), 'POST'); assert(bytes && bytes.length <= (url.pathname === PATH ? 8192 : 2048));
        assert(request.headers()['content-type']?.startsWith('application/json'));
        const body = JSON.parse(bytes.toString()); const stored = await noMaterial(page);
        assert(stored && UUID.test(body.operation_id) && stored.operation_id === body.operation_id,
          'public locator must be durable before dispatch');
        assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
        if (url.pathname === PATH) {
          assert.equal(stored.kind, 'prepare'); assert.equal(observed.prepares.length, 0, 'never automatically replay Prepare');
          assert.deepEqual(Object.keys(body).sort(), ['client_id', 'client_secret', 'expected_policy_hash', 'expected_revision',
            'expected_settings_digest', 'operation_id']);
          assert.equal(body.client_id, CLIENT); assert.equal(body.client_secret, SECRET);
          assert.equal(body.expected_settings_digest, digest(state.settings));
          assert.equal(await node(page, 'client-secret').inputValue(), '', 'clear secret before awaiting HTTP');
          observed.prepares.push(Object.fromEntries(Object.entries(body).filter(([key]) => key !== 'client_secret')));
          if (options.prepareStatus) {
            arrivedPrepare(); state.expectedFailures.add(PATH);
            return await answer(route, {detail: options.prepareStatus === 422 ? 'invalid operator catalog input' : PRIVATE}, options.prepareStatus);
          }
          observed.operation = operation(state, body); arrivedPrepare(); await prepareGate;
          if (options.failDiscoveryAfterPrepare) observed.reviewStatus = 503;
          if (options.lostPrepare) { state.expectedFailures.add(PATH); return await route.abort('failed'); }
          const value = options.badPrepared ? {...clone(observed.operation), secret: PRIVATE} : observed.operation;
          return await answer(route, value, 201);
        }
        assert.equal(url.pathname, PATH + '/cancel'); assert.equal(stored.kind, 'cancel'); assert.equal(observed.cancels.length, 0);
        assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'operation_id']);
        assert.equal(body.operation_id, observed.operation.operation_id); assert.equal(observed.operation.status, 'pending');
        observed.cancels.push(clone(body));
        if (!options.unknownCancel) terminal(state, observed, 'cancelled');
        if (options.lostCancel || options.unknownCancel) { state.expectedFailures.add(url.pathname); return await route.abort('failed'); }
        return await answer(route, observed.operation);
      } catch (_) { state.errors.push('Google configuration fixture DTO/CAS/secret/locator boundary refused'); await route.abort(); }
    };
    await controls.context.route(ORIGIN + PATH, handler);
    await controls.context.route(ORIGIN + PATH + '/**', handler);
    // MAIN's optional X panel performs one read-only feature discovery when
    // Proxy opens. Model the default-disabled route, never an X save or action.
    let xDiscoveryReads = 0;
    await controls.context.route(ORIGIN + '/api/operator-demo/oauth/x/configuration/v1', async route => {
      try {
        const request = route.request();
        assert.equal(request.method(), 'GET'); assert(!request.postDataBuffer()?.length);
        assert.equal(request.url(), ORIGIN + '/api/operator-demo/oauth/x/configuration/v1'); assert(++xDiscoveryReads <= 8);
        state.expectedFailures.add('/api/operator-demo/oauth/x/configuration/v1');
        await answer(route, {detail: 'X configuration is not supported by this deployment'}, 404);
      } catch (_) { state.errors.push('Google fixture attempted a non-observation X request'); await route.abort(); }
    });
    await controls.context.route(ORIGIN + '/api/operator-demo/oauth/google/intents', async route => {
      try {
        assert.equal(route.request().method(), 'GET'); assert(!route.request().postDataBuffer()?.length);
        assert.equal(route.request().url(), ORIGIN + '/api/operator-demo/oauth/google/intents'); assert(++observed.intentsReads <= 12);
        await answer(route, {apiVersion: 'catchplate.operatorGoogleConsent/v1', intents: [],
          limits: {active: 32, retained: 1024}, productionReady: false, protectedActivationSupported: false});
      } catch (_) { state.errors.push('Google configuration attempted a non-observation consent request'); await route.abort(); }
    });
    try {
      activeStep = 'fixture-assets-reload'; await page.reload({waitUntil: 'networkidle'});
      activeStep = 'fixture-catalog-admission'; await ready(page);
      activeStep = 'fixture-shell-assertions';
      assert.equal(await page.title(), 'Overview - Catchplate operator workspace'); assert.equal(new URL(page.url()).origin, ORIGIN);
      await exercise(page, state, observed, {...controls, prepareArrival, releasePrepare: () => releasePrepare?.()});
      activeStep = 'fixture-final-material';
      await noMaterial(page);
      activeStep = 'fixture-final-write-origins';
      assert.deepEqual(state.posts, [], 'configuration never writes credentials, accounts, applications, rules, tokens or notifications');
      assert.deepEqual({credentials: state.credentials, applications: state.applications, rules: state.rules}, resources);
      assert.equal(new URL(page.url()).origin, ORIGIN, 'no provider or restart navigation');
    } finally { releasePrepare?.(); }
  });
}

let activeGroup = 0;
let activeStep = 'not-started';
let activeVariant = 'not-started';
function safeFrames(error) {
  // Do not emit error.message, raw stack lines, URL paths or assertion values.
  // Only an exact local harness filename and bounded source coordinates leave
  // this parser, even when the first stack line contains a synthetic secret.
  const frames = [];
  try {
    if (typeof error?.stack !== 'string') return frames;
    const names = ['test_operator_google_configuration_browser.cjs',
      'test_operator_ordinary_modes_browser.cjs', 'test_operator_catalog_browser.cjs'];
    for (const line of error.stack.slice(0, 32768).split('\n').slice(1, 65)) {
      for (const name of names) {
        const prefix = join(ROOT, 'scripts', name) + ':';
        const offset = line.indexOf(prefix); if (offset < 0) continue;
        const suffix = line.slice(offset + prefix.length);
        const match = /^(\d{1,6}):(\d{1,6})\)?\s*$/.exec(suffix);
        if (!match || Number(match[1]) < 1 || Number(match[2]) < 1) continue;
        frames.push({file: 'scripts/' + name, line: Number(match[1]), column: Number(match[2])});
        if (frames.length === 8) return frames;
      }
    }
  } catch (_) { /* Fixed empty projection if an unusual error object refuses inspection. */ }
  return frames;
}
async function settled(page) {
  // A fulfilled synthetic request may begin after the document's existing
  // network-idle milestone. The controller disables Review synchronously for
  // its operation, then reenables it only after DTO projection/catalog refresh
  // or the fixed error path and finally cleanup. Wait for that actual UI state.
  const idle = () => document.readyState === 'complete' &&
    document.querySelector('#google-configuration-review')?.disabled === false;
  await page.waitForFunction(idle);
  await page.waitForLoadState('networkidle');
  await page.waitForFunction(idle);
}
async function reloadUnresolved(page) {
  // The stored locator intentionally holds ordinary writes after reload until
  // an explicit Check recovers the receipt. The inherited ready() waits for
  // those writes to be enabled, which would incorrectly wait through this hold.
  await view(page, 'overview');
  const loaded = page.waitForResponse(response => response.url() === ORIGIN + '/api/operator-demo/catalog');
  await page.reload({waitUntil: 'networkidle'});
  const response = await loaded; assert.equal(response.status(), 200); await response.finished();
  assert.equal(new URL(page.url()).hash, '#overview');
  await page.locator('#mutation-review').waitFor({state: 'visible'});
  const hint = page.locator('#google-configuration-recovery-hint');
  assert(await hint.isVisible(), 'Overview explains the Google-only hold before navigation');
  assert.match(await hint.innerText(), /Google.*Proxy setup.*Google provider settings.*Check operation result/);
  const recovery = page.locator('#google-configuration-recovery-link');
  assert.equal(await recovery.getAttribute('href'), '#google-configuration-panel');
  await recovery.click();
  await page.waitForFunction(() => location.hash === '#google-configuration-panel' && !document.querySelector('#proxy').hidden);
  await page.waitForFunction(() => !document.querySelector('#google-configuration-check').disabled &&
    document.querySelector('#credential-fields').disabled && document.querySelector('#load-error').hidden);
  assert.equal((await page.locator('#proxy-url').innerText()).trim(), 'https://proxy.example.test');
  assert(await page.locator('#credential-add').isDisabled(), 'the held fieldset disables its actual Save control');
  await noMaterial(page);
}
async function inspect(page) {
  activeStep = 'explicit-review'; await view(page, 'proxy'); await node(page, 'review').click(); await settled(page);
}
async function draft(page) {
  await inspect(page); await node(page, 'form').waitFor({state: 'visible'});
  assert.equal(await node(page, 'client-secret').getAttribute('type'), 'password');
  await node(page, 'client-id').fill(CLIENT); await node(page, 'client-secret').fill(SECRET);
  assert(!await node(page, 'prepare').isDisabled()); await noMaterial(page, {draft: true});
}
async function prepare(page) {
  await draft(page); activeStep = 'explicit-prepare'; await node(page, 'prepare').click(); await settled(page);
  assert.equal(await node(page, 'client-secret').inputValue(), ''); await noMaterial(page);
}
async function check(page) {
  activeStep = 'explicit-status-check'; await node(page, 'check').click(); await settled(page); await noMaterial(page);
}
async function refreshCatalog(page) {
  const loaded = page.waitForResponse(response => response.url() === ORIGIN + '/api/operator-demo/catalog');
  await page.locator('#proxy-settings-refresh').click(); await (await loaded).finished(); await settled(page);
}
const tests = [
  ['opening settings is inert; unsupported and externally configured profiles preserve static UI', async browser => {
    for (const options of [{unsupported: true}, {external: true}]) await fixture(browser, options, async (page, state, observed) => {
      activeStep = 'compatibility-open-proxy';
      await view(page, 'proxy'); assert.equal(observed.requests.length, 0);
      activeStep = 'compatibility-initial-controls';
      assert(await node(page, 'form').isHidden()); assert(await node(page, 'prepare').isDisabled());
      activeStep = 'compatibility-review-unsupported';
      await node(page, 'review').click(); await settled(page);
      activeStep = 'compatibility-refused-controls';
      assert(await node(page, 'form').isHidden()); assert(await node(page, 'prepare').isDisabled());
      assert.match(await node(page, 'status').innerText(), /not supported|unavailable|deployment/i);
      assert.equal(observed.prepares.length + observed.cancels.length, 0);
      activeStep = 'compatibility-static-controls';
      await view(page, 'credentials'); assert(!await page.locator('#credential-add').isDisabled());
    });
  }],
  ['review presents exact callback and Gmail addition; Prepare is write-only and never hot applies', (browser, directory) => fixture(browser, {}, async (page, state, observed) => {
    await inspect(page);
    assert.equal((await node(page, 'callback').innerText()).trim(), profile().redirect_uri);
    await node(page, 'scopes').locator('..').locator(':scope > summary').click();
    assert(await node(page, 'scopes').isVisible());
    assert.equal((await node(page, 'scopes').innerText()).trim(), SCOPES.join('\n'));
    assert.equal((await node(page, 'added-upstream').innerText()).trim(), GMAIL);
    assert.match(await node(page, 'panel').innerText(), /restart/i); assert.equal(await page.locator('form form').count(), 0);
    await screenshot(page, directory, 'google-configuration-review-desktop');
    await node(page, 'client-id').fill(CLIENT); await node(page, 'client-secret').fill(SECRET);
    await node(page, 'prepare').click(); await settled(page);
    assert.equal(observed.prepares.length, 1); assert.equal(await node(page, 'client-secret').inputValue(), '');
    assert.deepEqual(state.settings, OLD); assert.deepEqual(state.allowedUpstreams, OLD.allowed_upstreams);
    assert.match(await node(page, 'operation-status').innerText(), /prepared|pending/i);
    assert.match(await node(page, 'operation-status').innerText(), /restart/i);
    assert(await node(page, 'prepare').isDisabled()); assert(!await node(page, 'cancel').isDisabled());
    assert.deepEqual(await noMaterial(page), {operation_id: observed.operation.operation_id, kind: 'prepare'});
    await page.setViewportSize({width: 390, height: 844});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    assert(await node(page, 'check').isVisible()); assert(await node(page, 'cancel').isVisible());
    await screenshot(page, directory, 'google-configuration-pending-mobile');
  })],
  ['draft secrets clear on navigation, pagehide and reload without any POST', browser => fixture(browser, {}, async (page, state, observed) => {
    await draft(page); await view(page, 'credentials'); assert.equal(await node(page, 'client-secret').inputValue(), '');
    await draft(page);
    await page.evaluate(() => dispatchEvent(new Event('pagehide'))); assert.equal(await node(page, 'client-secret').inputValue(), '');
    await draft(page); await page.reload({waitUntil: 'networkidle'}); await ready(page);
    await view(page, 'proxy'); assert.equal(await node(page, 'client-secret').inputValue(), '');
    assert.equal(observed.prepares.length + observed.cancels.length, 0); assert.equal(await noMaterial(page), null);
  })],
  ['secret is already cleared while a submitted Prepare response is outstanding', browser => fixture(browser, {deferPrepare: true}, async (page, state, observed, controls) => {
    await draft(page); activeStep = 'deferred-prepare'; await node(page, 'prepare').click(); await controls.prepareArrival;
    assert.equal(observed.prepares.length, 1); assert.equal(await node(page, 'client-secret').inputValue(), '');
    await noMaterial(page); await view(page, 'credentials'); await noMaterial(page);
    controls.releasePrepare(); await settled(page); await view(page, 'proxy');
    assert.equal(observed.prepares.length, 1); assert.equal(await node(page, 'client-secret').inputValue(), '');
  })],
  ['storage failure clears the secret and prevents dispatch', browser => fixture(browser, {}, async (page, state, observed) => {
    await draft(page);
    await page.evaluate(({key, detail}) => {
      const original = Storage.prototype.setItem;
      Storage.prototype.setItem = function (name, value) {
        if (this === sessionStorage && name === key) throw new Error(detail);
        return original.call(this, name, value);
      };
    }, {key: STORAGE, detail: PRIVATE});
    await node(page, 'prepare').click(); await settled(page);
    assert.equal(observed.prepares.length, 0); assert.equal(await node(page, 'client-secret').inputValue(), '');
    assert.match(await node(page, 'status').innerText(), /storage|reference|not sent|not submitted|not saved/i);
    assert.equal(await noMaterial(page), null);
  })],
  ['a failed fresh review clears an existing draft secret without persisting or submitting it', browser => fixture(browser, {}, async (page, state, observed) => {
    await draft(page); observed.reviewStatus = 503; await node(page, 'review').click(); await settled(page);
    assert.equal(await node(page, 'client-secret').inputValue(), ''); assert.equal(observed.prepares.length, 0);
    assert(await node(page, 'prepare').isDisabled()); assert.equal(await noMaterial(page), null);
  })],
  ['lost Prepare response retains one exact locator and reload is GET-only recovery', browser => fixture(browser, {lostPrepare: true}, async (page, state, observed) => {
    await prepare(page); assert.match(await node(page, 'operation-status').innerText(), /unconfirmed|unknown/i);
    const reference = await noMaterial(page); assert.equal(reference.operation_id, observed.operation.operation_id);
    const beforeReload = observed.requests.length;
    await reloadUnresolved(page);
    assert.equal(observed.requests.length, beforeReload, 'reload does not replay or automatically inspect a saved operation');
    assert.deepEqual(await noMaterial(page), reference); assert(await node(page, 'prepare').isDisabled());
    await check(page); assert.match(await node(page, 'operation-status').innerText(), /prepared|pending/i);
    assert.equal(observed.prepares.length, 1); assert.equal(observed.cancels.length, 0);
    assert(observed.requests.slice(beforeReload).every(item => item.method === 'GET'));
  })],
  ['ambiguous 409, 503 or 404 plus missing receipt never authorizes a second POST', async browser => {
    for (const status of [409, 503, 404]) await fixture(browser, {prepareStatus: status}, async (page, state, observed) => {
      await prepare(page); const reference = await noMaterial(page); assert(reference && reference.kind === 'prepare');
      await check(page); assert.equal(observed.prepares.length, 1); assert.equal(observed.cancels.length, 0);
      assert.deepEqual(await noMaterial(page), reference); assert(await node(page, 'prepare').isDisabled());
      assert(await node(page, 'cancel').isDisabled());
      await reloadUnresolved(page);
      await check(page); assert.equal(observed.prepares.length, 1); assert.deepEqual(await noMaterial(page), reference);
    });
  }],
  ['known precommit 422 clears only the rejected reference and never retries', browser => fixture(browser, {prepareStatus: 422}, async (page, state, observed) => {
    await prepare(page); assert.equal(observed.prepares.length, 1); assert.equal(await noMaterial(page), null);
    assert.match(await node(page, 'status').innerText(), /before|invalid|rejected/i);
    assert(await node(page, 'prepare').isDisabled()); assert.equal(await node(page, 'client-secret').inputValue(), '');
    await page.reload({waitUntil: 'networkidle'}); await ready(page); assert.equal(observed.prepares.length, 1);
  })],
  ['malformed discovery closes controls without exposing extra fields or treating booleans as readiness', async browser => {
    const changes = [value => ({...value, secret: PRIVATE}), value => ({...value, redirect_uri: 'https://elsewhere.example.test/callback'}),
      value => ({...value, readiness: {...value.readiness, pair_ready: 1}}),
      value => ({...value, readiness: {...value.readiness, consent_ready: true}}),
      value => ({...value, review: {...value.review, expected_policy_hash: OTHER_POLICY}})];
    for (const transform of changes) await fixture(browser, {}, async (page, state, observed) => {
      observed.discoveryTransform = transform; await inspect(page);
      assert(await node(page, 'form').isHidden()); assert(await node(page, 'prepare').isDisabled());
      assert.equal(observed.prepares.length + observed.cancels.length, 0); await noMaterial(page);
    });
  }],
  ['malformed success receipt remains uncertain until a separate exact GET', browser => fixture(browser, {badPrepared: true}, async (page, state, observed) => {
    await prepare(page); const reference = await noMaterial(page);
    assert.equal(reference.operation_id, observed.operation.operation_id);
    assert.match(await node(page, 'operation-status').innerText(), /unconfirmed|unknown/i);
    assert(await node(page, 'prepare').isDisabled()); await check(page);
    assert.match(await node(page, 'operation-status').innerText(), /prepared|pending/i); assert.equal(observed.prepares.length, 1);
  })],
  ['a valid Prepare receipt followed by failed discovery cannot authorize a second Prepare', browser => fixture(browser, {failDiscoveryAfterPrepare: true}, async (page, state, observed) => {
    await prepare(page); const reference = await noMaterial(page);
    assert.equal(reference.operation_id, observed.operation.operation_id);
    assert.equal(observed.prepares.length, 1);
    assert.match(await node(page, 'operation-status').innerText(), /prepared|pending/i);
    assert(await node(page, 'form').isHidden()); assert(await node(page, 'prepare').isDisabled());
    await node(page, 'review').click(); await settled(page);
    assert.equal(observed.prepares.length, 1); assert(await node(page, 'prepare').isDisabled());
    assert.deepEqual(await noMaterial(page), reference);
    observed.reviewStatus = 200; await check(page);
    assert.match(await node(page, 'discovery-state').innerText(), /^A Google provider configuration is pending\./);
    assert(await node(page, 'prepare').isDisabled()); assert.equal(observed.prepares.length, 1);
  })],
  ['pending, activated-not-ready and consent-ready remain separate without starting consent', (browser, directory) => fixture(browser, {}, async (page, state, observed) => {
    await prepare(page); assert.match(await node(page, 'operation-status').innerText(), /prepared|pending/i);
    assert.match(await node(page, 'discovery-state').innerText(), /^A Google provider configuration is pending\./);
    assert(await node(page, 'connect-link').isHidden());
    terminal(state, observed, 'activated'); observed.pairReady = false; state.loaded = null;
    await check(page); assert.match(await node(page, 'operation-status').innerText(), /activated|activation/i);
    assert.equal(await node(page, 'discovery-state').innerText(),
      'Activated, but the exact app/proxy pair is not confirmed ready. Refresh this review before connecting an account.');
    assert(await node(page, 'connect-link').isHidden());
    assert(await node(page, 'cancel').isDisabled()); assert(await node(page, 'prepare').isDisabled());
    observed.pairReady = true; state.loaded = state.active; await check(page);
    assert.equal(await node(page, 'discovery-state').innerText(),
      'Activated. The exact app/proxy pair was ready at the last check. Account consent is separate and is checked again when started.');
    assert(await node(page, 'connect-link').isVisible());
    assert.equal(await node(page, 'connect-link').locator('a').getAttribute('href'), '#credentials');
    await screenshot(page, directory, 'google-configuration-activated-ready-desktop');
    await page.setViewportSize({width: 390, height: 844});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await screenshot(page, directory, 'google-configuration-activated-ready-mobile');
    assert.equal(observed.prepares.length, 1); assert.equal(observed.cancels.length, 0);
  })],
  ['cancellation refreshes CAS and sends its own closed DTO without changing effective settings', browser => fixture(browser, {}, async (page, state, observed) => {
    await prepare(page); const initialRevision = observed.operation.revision;
    state.revision++; const freshRevision = state.revision; assert(freshRevision > initialRevision);
    const before = observed.requests.length; await node(page, 'cancel').click(); await settled(page);
    assert.equal(observed.cancels.length, 1); assert.equal(observed.cancels[0].expected_revision, freshRevision);
    assert(observed.requests.slice(before).some(item => item.method === 'GET'), 'cancel rechecks current discovery before dispatch');
    assert.match(await node(page, 'operation-status').innerText(), /cancelled/i);
    assert.deepEqual(state.settings, OLD); assert(await node(page, 'cancel').isDisabled());
    assert.equal(observed.prepares.length, 1); await noMaterial(page);
  })],
  ['uncertain cancellation is recovered by GET and cannot be automatically replayed', async browser => {
    for (const options of [{lostCancel: true}, {unknownCancel: true}]) await fixture(browser, options, async (page, state, observed) => {
      await prepare(page); await node(page, 'cancel').click(); await settled(page);
      const reference = await noMaterial(page); assert.equal(reference.kind, 'cancel');
      await check(page); assert.equal(observed.cancels.length, 1); assert.equal(observed.prepares.length, 1);
      assert(await node(page, 'cancel').isDisabled());
      if (options.unknownCancel) assert(await node(page, 'prepare').isDisabled());
      await reloadUnresolved(page); await check(page);
      assert.equal(observed.cancels.length, 1); assert.equal(observed.prepares.length, 1);
    });
  }],
  ['catalog drift invalidates review, while another actor cannot obtain a cancellation reference', browser => fixture(browser, {}, async (page, state, observed) => {
    await draft(page); state.revision++; await refreshCatalog(page);
    assert(await node(page, 'prepare').isDisabled()); assert.equal(observed.prepares.length, 0);
    await view(page, 'credentials'); await noMaterial(page); await view(page, 'proxy');
    observed.operation = operation(state, {operation_id: '11111111-2222-4333-8444-555555555555'}); observed.owned = false;
    await node(page, 'review').click(); await settled(page);
    assert(await node(page, 'prepare').isDisabled()); assert(await node(page, 'cancel').isDisabled());
    assert.equal(await noMaterial(page), null); assert.equal(observed.prepares.length + observed.cancels.length, 0);
  })],
  ['Overview recovery retires a verified terminal reference only after confirmation and stays resolved after reload', async (browser, directory) => {
    for (const status of ['cancelled', 'activated']) await fixture(browser, {}, async (page, state, observed) => {
      await prepare(page); const reference = await noMaterial(page);
      assert.deepEqual(reference, {operation_id: observed.operation.operation_id, kind: 'prepare'});
      assert.equal(observed.prepares.length, 1);
      await view(page, 'overview'); const beforeReload = observed.requests.length;
      activeStep = 'retained-reference-overview-reload';
      const loaded = page.waitForResponse(response => response.url() === ORIGIN + '/api/operator-demo/catalog');
      await page.reload({waitUntil: 'networkidle'});
      const response = await loaded; assert.equal(response.status(), 200); await response.finished();
      await page.waitForFunction(() => document.querySelector('#load-error').hidden &&
        document.querySelector('#credential-fields').disabled);
      // The provider owner holds the workspace until its exact operation is
      // checked. The shared acknowledgement must not bypass that hold.
      assert(await page.locator('#mutation-review-confirm').isDisabled());
      assert.equal(await page.title(), 'Overview - Catchplate operator workspace');
      assert(await page.locator('#overview').isVisible()); assert(await page.locator('#proxy').isHidden());
      assert(await page.locator('#mutation-review').isVisible());
      assert(await node(page, 'recovery-hint').isVisible());
      assert.match(await node(page, 'recovery-hint').innerText(), /Google provider configuration needs a status check/);
      assert.equal(await node(page, 'recovery-link').getAttribute('href'), '#google-configuration-panel');
      assert.equal(await node(page, 'recovery-link').innerText(), 'Check Google configuration result');
      assert.deepEqual(await noMaterial(page), reference);
      assert.equal(observed.requests.length, beforeReload, 'restoring the reference never auto-checks or resubmits');
      // Recovery uses the provider-specific Check, not a generic acknowledgement.
      assert(await page.locator('#credential-fields').evaluate(fieldset => fieldset.disabled === true));
      assert(await page.locator('#credential-add').isDisabled());
      assert(await page.locator('#mutation-review').isVisible());
      assert.equal(observed.requests.length, beforeReload);
      await screenshot(page, directory, 'google-recovery-' + status + '-overview-desktop');
      await page.setViewportSize({width: 390, height: 844});
      assert(await node(page, 'recovery-link').isVisible());
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      activeStep = 'retained-reference-fixed-recovery-link';
      await node(page, 'recovery-link').click(); await page.locator('#proxy').waitFor({state: 'visible'});
      assert.equal(new URL(page.url()).hash, '#google-configuration-panel');
      assert.equal(await page.locator('nav a[href="#proxy"]').getAttribute('aria-current'), 'page');
      assert.equal(await page.locator('.page:visible').count(), 1);
      assert(await node(page, 'panel').isVisible()); assert(!await node(page, 'check').isDisabled());
      await node(page, 'operation-reference').locator('..').locator(':scope > summary').click();
      assert(await node(page, 'operation-reference').isVisible());
      assert.equal(await node(page, 'operation-reference').innerText(), reference.operation_id);
      assert.equal(observed.requests.length, beforeReload, 'the fixed navigation link itself performs no recovery request');
      terminal(state, observed, status);
      activeStep = 'retained-reference-exact-terminal-check';
      await check(page);
      assert.deepEqual(observed.requests.slice(beforeReload), [
        {method: 'GET', path: PATH + '/' + reference.operation_id},
        {method: 'GET', path: PATH},
      ], 'one exact status GET followed by the existing read-only discovery refresh');
      assert.equal(observed.prepares.length, 1); assert.equal(observed.cancels.length, 0);
      assert.match(await node(page, 'operation-status').innerText(), status === 'cancelled' ? /Cancelled/ : /Activation is recorded/);
      assert(await node(page, 'recovery-hint').isHidden(), 'only the resolved Google hint retires');
      assert(await page.locator('#mutation-review').isVisible(), 'terminal receipt does not acknowledge the shared review');
      assert(await page.locator('#credential-fields').evaluate(fieldset => fieldset.disabled === true));
      assert(await page.locator('#credential-add').isDisabled());
      assert(!await page.locator('#mutation-review-confirm').isDisabled());
      assert.deepEqual(await noMaterial(page), reference);
      const afterCheck = observed.requests.length;
      activeStep = 'retained-reference-explicit-shared-confirmation';
      await page.locator('#mutation-review-confirm').click(); await ready(page);
      assert(await page.locator('#mutation-review').isHidden());
      assert(await node(page, 'recovery-hint').isHidden());
      await view(page, 'credentials'); assert(!await page.locator('#credential-add').isDisabled(),
        'successful explicit confirmation proves the Google hold was released');
      assert.equal(observed.requests.length, afterCheck, 'confirmation is local, not a replay or second recovery request');
      assert.equal(observed.prepares.length, 1); assert.equal(observed.cancels.length, 0);
      assert.equal(await noMaterial(page), null, 'explicit acknowledgement retires only the verified terminal locator');
      await view(page, 'overview');
      activeStep = 'completed-google-recovery-second-overview-reload';
      await page.reload({waitUntil: 'networkidle'}); await ready(page);
      assert.equal(await page.title(), 'Overview - Catchplate operator workspace');
      assert(await page.locator('#mutation-review').isHidden());
      assert.equal(await node(page, 'recovery-hint').count(), 0, 'completed recovery must not become a fresh hold');
      assert(await page.locator('#credential-fields').evaluate(fieldset => fieldset.disabled === false));
      assert(!await page.locator('#credential-add').isDisabled());
      assert.equal(await noMaterial(page), null); assert.equal(observed.requests.length, afterCheck);
      assert.equal(observed.prepares.length, 1); assert.equal(observed.cancels.length, 0);
      await screenshot(page, directory, 'completed-google-' + status + '-overview-mobile');
      if (status === 'activated') {
        await view(page, 'proxy'); await node(page, 'review').click(); await settled(page);
        assert.match(await node(page, 'operation-status').innerText(), /Activation is recorded/);
        assert.equal(await noMaterial(page), null, 'reviewing saved settings must not re-create persistent recovery');
      }
    });
  }],
];

async function hashes() {
  const assets = await readdir(join(ROOT, 'catchplate/operator_demo_web'));
  const files = ['scripts/test_operator_google_configuration_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
    'scripts/test_operator_ordinary_modes_browser.cjs', 'catchplate/operator_demo_portal.py',
    ...assets.filter(name => /\.(?:js|css|html)$/.test(name)).sort().map(name => 'catchplate/operator_demo_web/' + name)];
  return Object.fromEntries(await Promise.all(files.map(async name =>
    [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
function selectedGroups(args) {
  if (args.length === 0) return tests.map((_, index) => index + 1);
  assert.equal(args.length, 2, 'Only the bounded --groups selector is accepted');
  assert.equal(args[0], '--groups', 'Only the bounded --groups selector is accepted');
  assert(typeof args[1] === 'string' && args[1].length <= 47 && /^[1-9]\d?(?:,[1-9]\d?)*$/.test(args[1]),
    'Group selector requires canonical comma-separated group numbers');
  const values = args[1].split(',').map(Number);
  assert(values.length <= tests.length && new Set(values).size === values.length &&
    values.every(value => value <= tests.length), 'Group selector is bounded to the fixed suite');
  return values;
}
async function runSuite(browser, groups = selectedGroups([])) {
  const selected = tests.map(([name, test], index) => ({group: index + 1, name, test})).filter(item => groups.includes(item.group));
  const before = await hashes(); const directory = await mkdtemp('/tmp/catchplate-google-configuration-browser-');
  console.log(JSON.stringify({phase: 'source-before', hashes: before, artifactDirectory: directory,
    tests: selected.map(({group, name}) => ({group, name})), totalGroups: tests.length,
    scope: 'intercepted synthetic API, actual rendered assets'}));
  const contexts = new Set(); let finished = false; let timeout; let passed = 0;
  const bounded = {async newContext(...args) {
    assert(!finished); const context = await browser.newContext(...args);
    if (finished) { await context.close(); throw new Error('Suite already finished'); }
    contexts.add(context); context.on('close', () => contexts.delete(context)); return context;
  }};
  try {
    await Promise.race([(async () => {
      for (const {group, name, test} of selected) {
        activeGroup = group; activeStep = 'fixture-start'; activeVariant = 'not-started'; await test(bounded, directory);
        passed++; console.log('PASS ' + name);
      }
    })(), new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('Bounded synthetic browser suite expired')), 180000); })]);
    const result = {ok: true, renderedGroups: selected.length, totalGroups: tests.length,
      selectedGroups: selected.map(item => item.group), passed, artifactDirectory: directory,
      backendAcceptance: false, realSQLiteVerified: false, providerRequests: 0, consentStarts: 0,
      proxyRequests: 0, externalRequests: 0, restarted: false, deploymentFilesChanged: false};
    console.log(JSON.stringify(result)); return result;
  } catch (error) {
    console.log(JSON.stringify({phase: 'fixed-failure-checkpoint', group: activeGroup, variant: activeVariant,
      step: activeStep, passed, frames: safeFrames(error), rawErrorSuppressed: true, syntheticOnly: true}));
    throw new Error('Google configuration rendered regression refused; fixed checkpoint retained');
  } finally {
    finished = true; clearTimeout(timeout);
    try { await Promise.all([...contexts].map(context => context.close())); }
    finally {
      const after = await hashes(); assert.deepEqual(after, before, 'source changed during rendered suite');
      console.log(JSON.stringify({phase: 'source-after', hashes: after, sameSource: true, passed}));
    }
  }
}
async function run(page) { return runSuite(page.context().browser()); }
async function main() {
  const groups = selectedGroups(process.argv.slice(2));
  assert.equal(process.version, 'v25.5.0', 'use the fixed cached Node runner');
  assert.equal(require(PLAYWRIGHT + '/package.json').version, '1.58.2', 'fixed cached Playwright version');
  const {chromium} = require(PLAYWRIGHT);
  const browser = await chromium.launch({headless: true, timeout: 20000, args: ['--no-sandbox', '--disable-background-networking']});
  try {
    assert.equal(browser.version(), '145.0.7632.6', 'fixed cached Chromium revision1208');
    await runSuite(browser, groups);
  } finally { await browser.close(); }
}
module.exports = {run, profile, review, operation, terminal, discovery, digest, OLD, TARGET, selectedGroups, safeFrames};
if (require.main === module) main().catch(() => {
  console.error('Google configuration browser regression refused; raw errors and request bodies suppressed'); process.exitCode = 1;
});

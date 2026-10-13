#!/usr/bin/env node
// Rendered production assets with independent synthetic DTOs only. Every
// request is fulfilled or refused; no real consent, account, grant, cleanup,
// provider post, SDK, proxy or recipe is executed. Quota screenshots contain
// only synthetic public data; private inputs and app-token fields are masked.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {execFileSync} = require('node:child_process');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {resolve, join} = require('node:path');
const {ready, view, credential, application, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture, publicCatalog, pair, review, grant, digest} = require('./test_operator_ordinary_modes_browser.cjs');
const {ORIGIN, API} = require('./operator_x_browser_fixture.cjs');
const ROOT = resolve(__dirname, '..');
const BASE = '/api/operator-demo/oauth/x';
const CONFIG = BASE + '/configuration/v1';
const START = BASE + '/start';
const DISCONNECT = BASE + '/disconnect';
const GRANT = '/api/operator-demo/access-rules/x-post';
const STORAGE = 'serverware.operator.x.account.operation.v1';
const BUNDLE = 'x_text_post_v1';
const SCOPES = ['offline.access', 'tweet.read', 'tweet.write', 'users.read'];
const NONCE = 's'.repeat(43);
const CHALLENGE = 'c'.repeat(43);
const SECRET = 'synthetic-provider-private-NEVER-RENDER';
const CLIENT = 'synthetic-X-client';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const clone = value => JSON.parse(JSON.stringify(value));
const oauthCapability = () => ({schema: 'serverware.operatorXOAuth/v1', connection_type: 'x_user_oauth_v1',
  auth_type: 'x_oauth', permission_preset: BUNDLE, start_path: START, operation_path_prefix: BASE + '/operations/',
  disconnect_review_path_template: BASE + '/accounts/{credential_id}/disconnect-review', disconnect_path: DISCONNECT,
  source_pair_required: true, automatic_refresh: true, daily_quota_available: false});
const quotaCapability = () => ({schema: 'serverware.operatorXPostAttemptQuota/v1', field: 'daily_post_attempt_limit',
  period: 'utc_day', scope: 'verified_x_account', unit: 'posting_attempt', minimum: 1, maximum: 1000000000});
const postCapability = (quotaReady = false) => ({schema: 'serverware.operatorXPost/v1', connection_type: 'x_user_oauth_v1',
  create_rule_path: GRANT, api_origin: API, destination_allowed: true, operation_bundles: [BUNDLE],
  sdk_auth_token: 'serverware-x-post-placeholder-v1', placeholder: 'Bearer serverware-x-post-placeholder-v1',
  response_mode: 'x_post_json_v1', source_pair_required: true, daily_quota_available: quotaReady,
  ...(quotaReady ? {daily_quota: quotaCapability()} : {})});
const account = (changes = {}) => credential({name: 'My X account', auth_type: 'x_oauth',
  connection_type: 'x_user_oauth_v1', provider_id: 'x', provider_subject: '123456', provider_account: '@fixture_user',
  oauth_client_id: CLIENT, permission_preset: BUNDLE, scopes: [...SCOPES], credential_generation: 1, ...changes});
const postRule = (changes = {}) => rule({name: 'Publish text · @fixture_user', operation_bundle: BUNDLE,
  upstream_url: API + '/2/tweets', methods: ['POST'], request_fields: [], response_fields: [], query_keys: [],
  allowed_headers: ['accept', 'accept-language', 'content-type', 'sec-fetch-mode', 'user-agent'],
  response_mode: 'x_post_json_v1', credential_input: 'replace_exact', placeholder: 'Bearer serverware-x-post-placeholder-v1', ...changes});
function configuration(state) {
  const profile = {schema: 'serverware.operatorXOAuthProfile/v1', profile: 'operator-x-oauth-v1', provider_id: 'x',
    client_id: CLIENT, redirect_uri: ORIGIN + '/api/oauth/callback/x', client_auth_method: 'client_secret_basic',
    permission_preset: BUNDLE, scopes: [...SCOPES], api_origins: [API], authorization_url: 'https://x.com/i/oauth2/authorize',
    token_url: API + '/2/oauth2/token', revocation_url: API + '/2/oauth2/revoke', identity_url: API + '/2/users/me'};
  return {schema: 'serverware.operatorXConfiguration/v1', state: 'configured', revision: state.revision,
    policy_hash: state.active, redirect_uri: profile.redirect_uri, permission_preset: BUNDLE, scopes: [...SCOPES],
    configuration: {config_version: 1, profile_binding_digest: digest(22), public_profile: profile, client_secret_configured: true},
    operation: null, review: null, blocked_reason: 'already_configured', consent_ready: false};
}
function catalog(state) {
  const result = publicCatalog(state);
  result.capabilities.x_oauth = state.gateReady ? oauthCapability() : null;
  result.capabilities.x_post = state.gateReady ? postCapability(state.quotaReady) : null;
  result.capabilities.application_proxy_authentication = {schema: 'serverware.operatorProxyAuthentication/v1',
    modes: ['bearer', 'basic_and_bearer_v1'], path: '/api/operator-demo/applications/proxy-authentication'};
  return result;
}
function operation(id, kind, status, changes = {}) {
  return {schema: 'serverware.operatorXAccountOperation/v1', operation_id: id, kind, status,
    credential_id: status === 'consent_pending' ? null : IDS.credential, reason: null,
    created_at: new Date(NOW).toISOString(), expires_at_epoch_ms: kind === 'consent' ? NOW + 600000 : null, ...changes};
}
function cas(state, body) {
  assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
}
async function privacy(page, id = null) {
  const result = await page.evaluate(() => ({dom: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].map(item => item.value),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  for (const value of [SECRET, NONCE, CHALLENGE, 'https://x.com/i/oauth2/authorize?'])
    assert(!JSON.stringify(result).includes(value), 'private/transient consent material escaped to DOM or storage');
  assert.deepEqual(result.local, []);
  assert.deepEqual(result.session, id ? [[STORAGE, id]] : []);
}
async function responsive(page) {
  for (const viewport of [{width: 1280, height: 960}, {width: 390, height: 844}]) {
    await page.setViewportSize(viewport);
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'viewport overflow');
    assert.equal(await page.locator('.page:visible').count(), 1);
  }
}
async function quotaScreenshots(page, artifacts, name, selectors) {
  await privacy(page);
  for (const viewport of [{width: 1280, height: 960}, {width: 390, height: 844}]) {
    await page.setViewportSize(viewport);
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'quota viewport overflow');
    for (const selector of selectors) {
      const control = page.locator(selector); assert(await control.isVisible(), selector + ' visible');
      const box = await control.boundingBox();
      assert(box && box.width > 0 && box.height > 0 && box.x >= -1 && box.x + box.width <= viewport.width + 1,
        selector + ' fits viewport');
    }
    const path = join(artifacts.directory, name + '-' + viewport.width + '.png');
    await page.screenshot({path, fullPage: true,
      mask: [page.locator('input[type="password"]'), page.locator('#client-token')]});
    artifacts.paths.push(path);
  }
}
async function fixture(browser, options, exercise) {
  return ordinaryFixture(browser, {credentials: options.empty ? [] : [account()],
    applications: [application({proxy_authentication: 'basic_and_bearer_v1'})], rules: options.rules || [],
    allowedUpstreams: [API], responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'],
    credentialInputModes: ['insert', 'replace_exact'], requestBodyModes: ['preserve_json_v1']}, async (page, state, controls) => {
    state.gateReady = options.gateReady !== false;
    state.quotaReady = options.quotaReady === true;
    const observed = {starts: [], grants: [], disconnects: [], reads: [], consentNavigations: 0};
    const operations = new Map();
    const answer = (route, value, status = 200) => route.fulfill({status, contentType: 'application/json',
      headers: {'Cache-Control': 'no-store'}, body: JSON.stringify(value)});
    const document = execFileSync('python3', ['-B', '-c', 'from serverware.operator_demo_portal import render; print(render())'],
      {cwd: ROOT, encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024});
    const handler = async route => {
      const request = route.request(), url = new URL(request.url()), bytes = request.postDataBuffer();
      try {
        assert.equal(url.origin, ORIGIN); assert(!url.search); assert(observed.reads.length < 64);
        if (request.method() === 'GET') {
          assert(!bytes?.length); observed.reads.push(url.pathname);
          if (url.pathname === '/api/operator-demo/catalog') return await answer(route, catalog(state));
          if (url.pathname === CONFIG) return await answer(route, configuration(state));
          if (url.pathname.startsWith(BASE + '/operations/')) {
            const id = url.pathname.slice((BASE + '/operations/').length); assert(UUID.test(id));
            if (!operations.has(id) || options.missingStatus) {
              state.expectedFailures.add(url.pathname); return await answer(route, {detail: SECRET}, 404);
            }
            return await answer(route, operations.get(id));
          }
          assert.equal(url.pathname, BASE + '/accounts/' + IDS.credential + '/disconnect-review');
          return await answer(route, {schema: 'serverware.operatorXDisconnectReview/v1', credential_id: IDS.credential,
            expected_credential_generation: state.credentials[0].credential_generation, expected_revision: state.revision,
            expected_policy_hash: state.active, review_digest: digest(88), affected_credential_ids: [IDS.credential],
            affected_rule_ids: state.rules.filter(item => item.status === 'active').map(item => item.id).sort()});
        }
        assert.equal(request.method(), 'POST'); assert(bytes?.length && bytes.length <= 4096);
        assert(request.headers()['content-type']?.startsWith('application/json'));
        const body = JSON.parse(bytes.toString()); cas(state, body);
        if (url.pathname === START) {
          assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'name', 'operation_id']);
          assert.equal(body.name, 'My X account'); assert(UUID.test(body.operation_id)); assert.equal(observed.starts.length, 0);
          assert.equal(await page.evaluate(key => sessionStorage.getItem(key), STORAGE), body.operation_id);
          observed.starts.push(clone(body)); state.revision++;
          operations.set(body.operation_id, operation(body.operation_id, 'consent', 'consent_pending'));
          if (options.lostStart) { state.expectedFailures.add(START); return await route.abort('failed'); }
          const authorization = new URL('https://x.com/i/oauth2/authorize');
          for (const [key, value] of Object.entries({response_type: 'code', client_id: CLIENT,
            redirect_uri: ORIGIN + '/api/oauth/callback/x', scope: SCOPES.join(' '), state: NONCE,
            code_challenge: CHALLENGE, code_challenge_method: 'S256'})) authorization.searchParams.set(key, value);
          return await answer(route, {schema: 'serverware.operatorXConsent/v1', operation_id: body.operation_id,
            status: 'consent_pending', authorization_url: authorization.href, state: NONCE,
            expires_at_epoch_ms: NOW + 600000, profile_binding_digest: digest(22)}, 201);
        }
        if (url.pathname === GRANT) {
          // Independent oracle: only the explicitly selected fixture may add
          // this field. In particular, no limit is omission, never null or 0.
          const limited = Object.hasOwn(options, 'expectedLimit');
          assert.deepEqual(Object.keys(body).sort(), ['application_id', 'credential_id', 'expected_policy_hash',
            'expected_revision', 'name', 'operation_bundle', ...(limited ? ['daily_post_attempt_limit'] : [])].sort());
          if (limited) {
            assert(state.quotaReady); assert(Number.isSafeInteger(body.daily_post_attempt_limit));
            assert(body.daily_post_attempt_limit >= 1 && body.daily_post_attempt_limit <= 1000000000);
            assert.equal(body.daily_post_attempt_limit, options.expectedLimit);
          }
          assert.equal(body.application_id, IDS.application); assert.equal(body.credential_id, IDS.credential);
          assert.equal(body.operation_bundle, BUNDLE); assert.equal(body.name, 'Publish text · @fixture_user');
          assert(state.gateReady); assert.equal(observed.grants.length, 0); observed.grants.push(clone(body));
          state.rules.push(postRule(limited ? {daily_post_attempt_limit: options.expectedLimit} : {}));
          state.revision++; state.active = digest(++state.sequence); state.loaded = state.active;
          const result = catalog(state); return await answer(route, {access_rule: result.access_rules[0], revision: result.revision, policy: result.policy}, 201);
        }
        assert.equal(url.pathname, DISCONNECT); assert.equal(observed.disconnects.length, 0);
        assert.deepEqual(Object.keys(body).sort(), ['credential_id', 'expected_credential_generation', 'expected_policy_hash', 'expected_revision', 'operation_id', 'review_digest']);
        assert(UUID.test(body.operation_id)); assert.equal(body.credential_id, IDS.credential);
        assert.equal(body.expected_credential_generation, 1); assert.equal(body.review_digest, digest(88));
        observed.disconnects.push(clone(body)); state.revision++; state.active = digest(++state.sequence); state.loaded = state.active;
        for (const item of state.rules) item.status = 'revoked';
        state.credentials[0] = account(options.uncertainDisconnect ? {status: 'quarantined', quarantined_at: new Date(NOW).toISOString(),
          quarantine_reason: 'operator_x_cleanup_fence', provider_revocation_status: 'not_proven'} : {status: 'revoked', credential_generation: null});
        const result = operation(body.operation_id, 'disconnect', options.uncertainDisconnect ? 'uncertain' : 'disconnected',
          {reason: options.uncertainDisconnect ? 'cleanup_unconfirmed' : null});
        operations.set(body.operation_id, result); return await answer(route, result);
      } catch (error) { state.errors.push('X account fixture: ' + error.message); await route.abort(); }
    };
    for (const path of ['/api/operator-demo/catalog', CONFIG, START, GRANT, DISCONNECT,
      BASE + '/operations/*', BASE + '/accounts/*/disconnect-review']) await controls.context.route(ORIGIN + path, handler);
    await controls.context.route(ORIGIN + '/?serverware_x_operation=*', async route => {
      const url = new URL(route.request().url());
      assert.equal(route.request().method(), 'GET'); assert.equal([...url.searchParams].length, 1);
      assert(operations.has(url.searchParams.get('serverware_x_operation')));
      await route.fulfill({status: 200, contentType: 'text/html', body: document});
    });
    await controls.context.route('https://x.com/**', async route => {
      const request = route.request(), url = new URL(request.url());
      try {
        assert.equal(request.method(), 'GET'); assert(!request.postDataBuffer()?.length);
        if (url.pathname === '/favicon.ico' && !url.search) return await route.fulfill({status: 204, body: ''});
        assert.equal(url.pathname, '/i/oauth2/authorize'); assert.equal([...url.searchParams].length, 7);
        assert.deepEqual(Object.fromEntries(url.searchParams), {response_type: 'code', client_id: CLIENT,
          redirect_uri: ORIGIN + '/api/oauth/callback/x', scope: SCOPES.join(' '), state: NONCE,
          code_challenge: CHALLENGE, code_challenge_method: 'S256'});
        assert.equal(++observed.consentNavigations, 1);
        await route.fulfill({status: 200, contentType: 'text/html', body: '<!doctype html><title>Synthetic consent interception</title><p>No provider request occurred.</p>'});
      } catch (_) { state.errors.push('X consent navigation refused'); await route.abort(); }
    });
    page.on('download', () => state.errors.push('unexpected download'));
    await page.reload({waitUntil: 'networkidle'}); await ready(page);
    await exercise(page, state, observed, operations);
    assert.deepEqual(state.posts, [], 'no generic mutation fallback');
    for (const item of state.consoleErrors) assert(state.expectedFailures.has(new URL(item.url).pathname), 'unanticipated console error');
  });
}
async function refresh(page) {
  // Reads do not set workspace.busy, so an enabled refresh button is not a
  // completion signal. Join this GET's actual body; callers checking changed
  // controls must additionally wait for the corresponding rendered state.
  const received = page.waitForResponse(response => response.url() === ORIGIN + '/api/operator-demo/catalog'
    && response.request().method() === 'GET');
  await page.locator('#connect-status-refresh').click();
  const response = await received; assert.equal(response.status(), 200); await response.finished();
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
  return response.json();
}
async function begin(page) {
  await view(page, 'credentials'); await page.locator('#x-account-name').fill('My X account');
  await page.locator('#x-account-start').click();
}
const tests = [
  ['consent URL then public-UUID-only callback recovery, desktop/mobile', browser => fixture(browser, {empty: true}, async (page, state, seen, operations) => {
    await begin(page); await page.waitForURL('https://x.com/i/oauth2/authorize?**');
    assert.equal(await page.title(), 'Synthetic consent interception'); assert.equal(seen.starts.length, 1);
    const id = seen.starts[0].operation_id;
    state.credentials.push(account()); state.revision++;
    operations.set(id, operation(id, 'consent', 'connected'));
    await page.goto(ORIGIN + '/?serverware_x_operation=' + id + '#credentials', {waitUntil: 'networkidle'});
    assert.equal(new URL(page.url()).search, ''); await privacy(page, id);
    await page.locator('#x-account-check').click();
    await page.waitForFunction(() => !document.querySelector('#x-account-acknowledge').disabled);
    assert.match(await page.locator('#x-account-status').innerText(), /connected.*No posting permission was granted/);
    assert.equal(state.rules.length, 0); assert.equal(seen.grants.length, 0); await responsive(page);
    await page.locator('#x-account-acknowledge').click(); await privacy(page);
    assert.equal(seen.starts.length, 1); assert.equal(seen.consentNavigations, 1);
  })],
  ['lost consent reply is GET-only recoverable and never replayed', browser => fixture(browser, {empty: true, lostStart: true}, async (page, state, seen) => {
    await begin(page); await page.waitForFunction(() => document.querySelector('#x-account-status').textContent.includes('could not be confirmed'));
    assert.equal(seen.starts.length, 1); const id = seen.starts[0].operation_id; await privacy(page, id);
    assert(await page.locator('#x-account-start').isDisabled()); await page.locator('#x-account-check').click();
    await page.waitForFunction(() => document.querySelector('#x-account-status').textContent.includes('consent pending'));
    await page.reload({waitUntil: 'networkidle'}); await view(page, 'credentials');
    await page.locator('#x-account-check').click(); await page.waitForFunction(() => !document.querySelector('#x-account-check').disabled);
    await privacy(page, id); assert.equal(seen.starts.length, 1); assert.equal(seen.consentNavigations, 0);
  })],
  ['fixed text-post grant has no arbitrary endpoint, content, or daily quota fields', browser => fixture(browser, {}, async (page, state, seen) => {
    await pair(page); assert.equal(await page.locator('#connect-operation').inputValue(), BUNDLE);
    for (const id of ['connect-path', 'connect-response-fields', 'connect-request-fields', 'connect-query-keys', 'connect-credential-input']) {
      assert(await page.locator('#' + id).isHidden()); assert(await page.locator('#' + id).isDisabled());
    }
    assert.match(await page.locator('#connect-x-post-summary').innerText(), /does not advertise daily limits/);
    assert(await page.locator('#connect-x-post-quota-group').isHidden());
    await review(page); assert.match(await page.locator('#connect-review-details').innerText(), /No daily posting-attempt limit is set/);
    await responsive(page); await grant(page); assert.equal(seen.grants.length, 1);
    assert.deepEqual(state.rules[0], postRule());
    const recipe = await page.locator('#client-command').innerText(); assert(recipe.includes('SERVERWARE_X_POST_CONFIRM=post-once'));
    assert(!recipe.includes(SECRET)); assert(!recipe.includes('fixture_user')); await privacy(page);
  })],
  ['advertised quota defaults to no limit and omits the field, desktop/mobile', (browser, artifacts) => fixture(browser,
    {quotaReady: true}, async (page, state, seen) => {
      await pair(page);
      assert(await page.locator('#connect-x-post-quota-group').isVisible());
      assert.equal(await page.locator('#connect-x-post-quota').inputValue(), 'none');
      assert(await page.locator('#connect-x-post-limit-group').isHidden());
      assert(await page.locator('#connect-x-post-limit').isDisabled());
      assert.equal(seen.grants.length, 0);
      await quotaScreenshots(page, artifacts, 'x-quota-no-limit-form',
        ['#connect-x-post-quota', 'label[for="connect-x-post-quota"]', '#connect-review']);
      await review(page);
      assert.match(await page.locator('#connect-review-details').innerText(), /No daily posting-attempt limit is set/);
      await quotaScreenshots(page, artifacts, 'x-quota-no-limit-review', ['#connect-review-details', '#connect-grant']);
      await grant(page); assert.equal(seen.grants.length, 1);
      assert(!Object.hasOwn(seen.grants[0], 'daily_post_attempt_limit'));
      assert(!Object.hasOwn(state.rules[0], 'daily_post_attempt_limit'));
      await refresh(page); assert.equal(seen.grants.length, 1); await privacy(page);
    })],
  ['explicit shared limit is reviewed and submitted exactly once, desktop/mobile', (browser, artifacts) => fixture(browser,
    {quotaReady: true, expectedLimit: 42}, async (page, state, seen) => {
      await pair(page); await page.locator('#connect-x-post-quota').selectOption('daily');
      await page.locator('#connect-x-post-limit').fill('42');
      assert(!(await page.locator('#connect-review').isDisabled()));
      const description = await page.locator('#connect-x-post-quota-group').innerText();
      assert.match(description, /even across OAuth clients/); assert.match(description, /Uncertain attempts still count/);
      assert.match(description, /Usage and reset observations are not available/);
      await quotaScreenshots(page, artifacts, 'x-quota-limited-form', ['#connect-x-post-quota',
        '#connect-x-post-limit', 'label[for="connect-x-post-limit"]', '#connect-review']);
      await review(page); const text = await page.locator('#connect-review-details').innerText();
      assert.match(text, /42 posting attempts per UTC day across all apps/);
      assert.match(text, /Uncertain attempts still count/); assert.equal(seen.grants.length, 0);
      await quotaScreenshots(page, artifacts, 'x-quota-limited-review', ['#connect-review-details', '#connect-grant']);
      await grant(page); assert.equal(seen.grants.length, 1);
      assert.equal(seen.grants[0].daily_post_attempt_limit, 42);
      assert.equal(state.rules[0].daily_post_attempt_limit, 42);
      assert.match(await page.locator('#client-guidance').innerText(), /42 posting attempts per UTC day/);
      await refresh(page); assert.equal(seen.grants.length, 1); await privacy(page);
    })],
  ['invalid limits cannot reach review while the exact upper bound can', browser => fixture(browser,
    {quotaReady: true}, async (page, state, seen) => {
      await pair(page); await page.locator('#connect-x-post-quota').selectOption('daily');
      for (const value of ['', '0', '-1', '1.5', '01', '1000000001']) {
        await page.locator('#connect-x-post-limit').fill(value);
        assert(await page.locator('#connect-review').isDisabled(), 'invalid limit blocks review');
        assert.match(await page.locator('#connect-x-post-quota-status').innerText(), /whole number/);
        assert(await page.locator('#connect-review-step').isHidden()); assert.equal(seen.grants.length, 0);
      }
      await page.locator('#connect-x-post-limit').fill('1000000000'); await review(page);
      assert.match(await page.locator('#connect-review-details').innerText(), /1000000000 posting attempts/);
      assert.equal(seen.grants.length, 0); assert.equal(state.rules.length, 0); await privacy(page);
    })],
  ['withdrawn quota capability invalidates review without unlimited fallback', browser => fixture(browser,
    {quotaReady: true}, async (page, state, seen) => {
      await pair(page); await page.locator('#connect-x-post-quota').selectOption('daily');
      await page.locator('#connect-x-post-limit').fill('42'); await review(page);
      state.quotaReady = false; const refreshed = await refresh(page);
      assert.equal(refreshed.capabilities.x_post.daily_quota_available, false);
      assert(!Object.hasOwn(refreshed.capabilities.x_post, 'daily_quota'));
      await page.waitForFunction(() => document.querySelector('#connect-grant').disabled
        && document.querySelector('#connect-review-context').textContent.includes('No grant was sent.'));
      assert(await page.locator('#connect-grant').isDisabled());
      await page.locator('#connect-back').click();
      await page.locator('#connect-access-step').waitFor({state: 'visible'});
      assert.equal(await page.locator('#connect-x-post-quota').inputValue(), 'daily');
      assert.equal(await page.locator('#connect-x-post-limit').inputValue(), '42');
      assert(await page.locator('#connect-x-post-quota').isDisabled());
      assert(await page.locator('#connect-review').isDisabled());
      assert.match(await page.locator('#connect-x-post-quota-status').innerText(), /no unlimited fallback/);
      assert.equal(seen.grants.length, 0); assert.equal(state.rules.length, 0); await privacy(page);
    })],
  ['unavailable gate blocks new posting without generic fallback', browser => fixture(browser, {gateReady: false}, async (page, state, seen) => {
    await pair(page); assert.equal(await page.locator('#connect-operation option:not([disabled])').count(), 0);
    assert.match(await page.locator('#connect-x-post-summary').innerText(), /Posting is unavailable/);
    assert(await page.locator('#connect-review').isDisabled()); assert.equal(seen.grants.length, 0); await privacy(page);
  })],
  ['gate-unavailable disconnect reviews exact scope and remains usable on mobile', browser => fixture(browser, {gateReady: false, rules: [postRule()]}, async (page, state, seen) => {
    await view(page, 'credentials'); assert(await page.locator('#x-account-start').isDisabled());
    await page.locator('[data-action="disconnect-x"]').click();
    await page.locator('#x-disconnect-review').waitFor({state: 'visible'});
    const text = await page.locator('#x-disconnect-details').innerText();
    assert(text.includes(IDS.credential) && text.includes(IDS.rule) && text.includes('@fixture_user'));
    await responsive(page); assert(!(await page.locator('#x-disconnect-submit').isDisabled()));
    await page.locator('#x-disconnect-submit').click();
    await page.waitForFunction(() => document.querySelector('#x-account-status').textContent.includes('disconnected'));
    assert.equal(seen.disconnects.length, 1); assert.equal(state.credentials[0].status, 'revoked');
    assert.equal(state.rules[0].status, 'revoked'); assert.equal(state.applications[0].status, 'active');
    const id = seen.disconnects[0].operation_id; await privacy(page, id); await page.locator('#x-account-check').click();
    await page.waitForFunction(() => !document.querySelector('#x-account-acknowledge').disabled);
    await page.locator('#x-account-acknowledge').click(); await privacy(page); assert.equal(seen.disconnects.length, 1);
  })],
  ['uncertain cleanup retains operation and cannot replay disconnect', browser => fixture(browser, {gateReady: false, uncertainDisconnect: true}, async (page, state, seen) => {
    await view(page, 'credentials'); await page.locator('[data-action="disconnect-x"]').click();
    await page.locator('#x-disconnect-review').waitFor({state: 'visible'}); await page.locator('#x-disconnect-submit').click();
    await page.waitForFunction(() => document.querySelector('#x-account-status').textContent.includes('uncertain'));
    assert.equal(seen.disconnects.length, 1); const id = seen.disconnects[0].operation_id;
    assert(await page.locator('#x-account-acknowledge').isHidden()); await privacy(page, id);
    await page.reload({waitUntil: 'networkidle'}); await view(page, 'credentials'); await page.locator('#x-account-check').click();
    await page.waitForFunction(() => !document.querySelector('#x-account-check').disabled);
    assert(await page.locator('[data-action="disconnect-x"]').isDisabled()); await privacy(page, id);
    assert.equal(seen.disconnects.length, 1); assert.equal(state.credentials[0].status, 'quarantined');
  })],
];
async function hashes() {
  const names = ['scripts/test_operator_x_accounts_browser.cjs', 'scripts/operator_x_browser_fixture.cjs',
    'scripts/test_operator_catalog_browser.cjs', 'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py',
    ...(await readdir(join(ROOT, 'serverware/operator_demo_web'))).filter(name => /\.(html|js|css)$/.test(name)).sort().map(name => 'serverware/operator_demo_web/' + name)];
  return Object.fromEntries(await Promise.all(names.map(async name => [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
async function runSuite(browser) {
  const before = await hashes(); const contexts = new Set(); let timer; let finished = false; let passed = 0;
  const artifacts = {directory: await mkdtemp('/tmp/serverware-x-quota-browser-'), paths: []};
  console.log(JSON.stringify({phase: 'source-before', hashes: before, artifactDirectory: artifacts.directory}));
  const bounded = {async newContext(...args) { assert(!finished); const context = await browser.newContext(...args);
    if (finished) { await context.close(); throw new Error('suite finished'); }
    contexts.add(context); context.on('close', () => contexts.delete(context)); return context; }};
  try {
    await Promise.race([(async () => { for (const [name, test] of tests) { await test(bounded, artifacts); passed++; console.log('PASS ' + name); } })(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('X accounts browser deadline')), 120000); })]);
    return {ok: true, groups: passed, backendAcceptance: false, providerRequests: 0, proxyRequests: 0,
      screenshots: artifacts.paths.length, screenshotPaths: artifacts.paths, artifactDirectory: artifacts.directory,
      recipeExecuted: false, sameSource: true, sourceHashes: before};
  } finally { finished = true; clearTimeout(timer); await Promise.all([...contexts].map(context => context.close()));
    assert.deepEqual(await hashes(), before, 'consumed frontend/fixture source changed during test'); }
}
async function run(page) { return runSuite(page.context().browser()); }
async function main() {
  assert.equal(process.argv.length, 2, 'No live-target arguments accepted');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  try { console.log(JSON.stringify(await runSuite(browser))); } finally { await browser.close(); }
}
module.exports = {run, runSuite};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

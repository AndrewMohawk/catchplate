'use strict';
// Bounded intercepted UI fixture. No live app, provider, proxy or CA requests.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {readFileSync, mkdtempSync} = require('node:fs');
const {resolve, join} = require('node:path');
const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://common-apps.example.test';
const IDS = ['11111111-1111-4111-8111-111111111111', '22222222-2222-4222-8222-222222222222', '33333333-3333-4333-8333-333333333333'];
const SECRET = 'synthetic-provider-key-not-real';
const TOKEN = 'synthetic-proxy-token-not-real-0123456789';
const HASH = n => 'sha256:' + n.toString(16).padStart(64, '0');
async function run(browserPage) {
  const source = JSON.parse(execFileSync('python3', ['-B', '-c',
    'import json; from serverware import operator_common_apps as a, operator_demo as d; from serverware.operator_demo_portal import render; d.settings=lambda: {"allowed_upstreams": ["https://slack.com"]}; print(json.dumps({"capability":a.capability(),"html":render()}))'],
    {cwd: ROOT, encoding: 'utf8', timeout: 5000, maxBuffer: 2 * 1024 * 1024}));
  const browser = browserPage.context().browser();
  const context = await browser.newContext({viewport: {width: 1280, height: 960}, acceptDownloads: true, serviceWorkers: 'block'});
  const directory = mkdtempSync('/tmp/serverware-common-apps-ui-');
  const state = {revision: 1, sequence: 1, credentials: [], applications: [], access_rules: [], requests: [], errors: [], posts: []};
  const policy = () => ({policy_hash: HASH(state.sequence), loaded_policy_hash: HASH(state.sequence), sequence: state.sequence, activation: 'active'});
  const catalog = () => ({schema: 'serverware.operatorCatalog/v1', mode: 'operator-development', productionReady: false, hardwareVerified: false,
    revision: state.revision, policy: policy(), proxy_url: 'https://proxy.example.test', allowed_upstreams: ['https://slack.com'],
    credentials: state.credentials.map(item => ({...item, active_rule_count: state.access_rules.length})),
    applications: state.applications.map(item => ({...item, active_rule_count: state.access_rules.length, access_status: state.access_rules.length ? 'active' : 'unassigned'})),
    access_rules: state.access_rules, limits: Object.fromEntries(['credentials', 'applications', 'access_rules'].map(key =>
      [key, {active: state[key].length, retained: state[key].length, active_max: 32, retained_max: 1024}])),
    capabilities: {credential_types: ['bearer', 'header'], response_modes: ['unfiltered_json_or_empty_v2'],
      request_body_modes: ['preserve_json_v1'], credential_input_modes: ['insert', 'replace_exact'], oauth: false,
      token_lifetime_seconds: {min: 3600, max: 7776000, default: 2592000}, common_apps: source.capability,
      application_proxy_authentication: {schema: 'serverware.operatorProxyAuthentication/v1', path: '/api/operator-demo/applications/proxy-authentication', modes: ['bearer', 'basic_and_bearer_v1']},
      host_approvals: {schema: 'serverware.operatorHostApprovals/v1', mode: 'host_trusted_v1', available: true,
        operation_bundles: [], generic_rules: true, setting_path: '/api/operator-demo/access-rules/approval'}}});
  await context.route('**/*', async route => {
    const request = route.request(), url = new URL(request.url());
    state.requests.push([request.method(), url.pathname]);
    const answer = (body, status = 200) => route.fulfill({status, contentType: 'application/json', body: JSON.stringify(body)});
    try {
      assert.equal(url.origin, ORIGIN); assert(state.requests.length < 50);
      if (request.method() === 'GET' && url.pathname === '/') return route.fulfill({status: 200, contentType: 'text/html', body: source.html});
      if (request.method() === 'GET' && url.pathname === '/api/operator-demo/catalog') return answer(catalog());
      if (request.method() === 'GET' && url.pathname === '/api/operator-demo/oauth/x/configuration/v1') return answer({detail: 'not configured'}, 404);
      if (request.method() === 'GET' && url.pathname === '/favicon.ico') return route.fulfill({status: 204, body: ''});
      assert.equal(request.method(), 'POST'); assert(state.posts.length < 4);
      const body = request.postDataJSON(); assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, HASH(state.sequence));
      state.posts.push({path: url.pathname, body: {...body, ...(body.secret ? {secret: '[redacted]'} : {})}});
      let item, key, extra = {};
      if (url.pathname === '/api/operator-demo/credentials') {
        assert.equal(body.app_preset, 'slack'); assert.equal(body.secret, SECRET);
        item = {id: IDS[0], name: body.name, app_preset: body.app_preset, auth_type: body.auth_type, header_name: body.header_name,
          status: 'active', created_at: new Date().toISOString(), active_rule_count: 0, credential_generation: 1};
        state.credentials.push(item); key = 'credential';
      } else if (url.pathname === '/api/operator-demo/applications') {
        item = {id: IDS[1], name: body.name, status: 'active', created_at: new Date().toISOString(), principal_id: 'agent:operator-demo:' + IDS[1],
          proxy_authentication: body.proxy_authentication, token_expires_at_epoch_ms: Date.now() + body.token_lifetime_seconds * 1000,
          token_generation: 1, token_status: 'valid', access_status: 'unassigned', active_rule_count: 0};
        state.applications.push(item); key = 'application'; extra.client_token = TOKEN;
      } else {
        assert.equal(url.pathname, '/api/operator-demo/access-rules/common-app');
        assert.equal(body.operation, 'post_message'); assert.deepEqual(body.scope, {channel: 'C0123456789'}); assert.equal(body.approval_mode, 'host_review_v1');
        const preset = source.capability.presets.find(item => item.id === 'slack'), operation = preset.operations[0];
        item = {id: IDS[2], name: body.name, status: 'active', created_at: new Date().toISOString(), route_id: 'operator.' + IDS[2],
          application_id: body.application_id, credential_id: body.credential_id, app_preset: body.app_preset,
          app_operation: body.operation, scope: body.scope, upstream_url: operation.origin + operation.path_template,
          methods: operation.methods, request_fields: operation.request_fields, response_fields: [], query_keys: operation.query_keys,
          allowed_headers: operation.allowed_headers, response_mode: operation.response_mode, credential_input: operation.credential_input,
          placeholder: operation.placeholder, approval_mode: body.approval_mode, enforcement: 'active'};
        state.access_rules.push(item); key = 'access_rule'; state.sequence++;
      }
      state.revision++; return answer({[key]: item, revision: state.revision, policy: policy(), ...extra});
    } catch (error) { state.errors.push(error.message); return route.abort(); }
  });
  const page = await context.newPage(); page.setDefaultTimeout(5000);
  page.on('pageerror', error => state.errors.push(error.message));
  page.on('console', message => { if (message.type() === 'error' && !message.text().includes('404')) state.errors.push(message.text()); });
  try {
    await page.goto(ORIGIN, {waitUntil: 'networkidle'});
    await page.locator('#overview-connect-service').click();
    assert.equal(await page.locator('[data-common-app]').count(), 12);
    await page.locator('#connect-common-category').selectOption('ai'); assert.equal(await page.locator('[data-common-app]').count(), 4);
    await page.locator('#connect-common-search').fill('claude'); assert.equal(await page.locator('[data-common-app]').count(), 1);
    await page.locator('#connect-common-search').fill(''); await page.locator('#connect-common-category').selectOption('all');
    await page.screenshot({path: join(directory, 'apps-desktop.png'), fullPage: true});
    await page.setViewportSize({width: 390, height: 844});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.screenshot({path: join(directory, 'apps-mobile.png'), fullPage: true});
    await page.locator('[data-common-app="gitlab"]').click();
    assert((await page.locator('#connect-common-key-note').textContent()).includes('https://gitlab.com'));
    assert((await page.locator('#connect-common-key-note').textContent()).includes('controlled restart'));
    await page.locator('#connect-method-change').click(); await page.locator('[data-common-app="slack"]').click();
    await page.locator('#connect-credential-name').fill('Deployment bot'); await page.locator('#connect-credential-secret').fill(SECRET);
    await page.locator('#connect-credential-next').click(); await page.locator('#connect-application-step').waitFor({state: 'visible'});
    assert.equal(await page.locator('#connect-credential-secret').inputValue(), '');
    await page.locator('#connect-application-name').fill('Release job'); await page.locator('#connect-application-next').click();
    await page.locator('#connect-access-step').waitFor({state: 'visible'});
    await page.locator('#connect-common-scope-channel').fill('C0123456789');
    assert(!await page.locator('#connect-approval-required').isDisabled()); await page.locator('#connect-approval-required').check();
    await page.locator('#connect-review').click(); await page.locator('#connect-review-step').waitFor({state: 'visible'});
    assert((await page.locator('#connect-review-step').textContent()).includes('C0123456789'));
    await page.locator('#connect-grant').click(); await page.locator('#connect-setup-step').waitFor({state: 'visible'});
    assert((await page.locator('#client-command').textContent()).includes('"channel":"C0123456789"'));
    const downloaded = page.waitForEvent('download'); await page.locator('#download-config').click();
    const download = await downloaded; const config = JSON.parse(readFileSync(await download.path(), 'utf8'));
    assert.equal(config.app_preset, 'slack'); assert.equal(config.app_operation, 'post_message');
    assert.deepEqual(config.scope, {channel: 'C0123456789'}); assert.equal(config.request_body.channel, 'C0123456789');
    assert.equal(config.proxy_password, TOKEN); assert.equal(config.request_headers.Authorization, 'Bearer serverware-slack-placeholder-v1');
    assert(!JSON.stringify(config).includes(SECRET)); assert.deepEqual(config.request_query, {});
    assert(config.note.includes('never automatic write intent')); assert.equal(state.posts.length, 3);
    await page.screenshot({path: join(directory, 'setup-mobile.png'), fullPage: true});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    assert.deepEqual(state.errors, []);
    return {ok: true, scope: 'intercepted synthetic desktop/mobile setup and private-config download',
      providers: 12, posts: state.posts.length, providerRequests: 0, screenshots: directory};
  } catch (error) {
    await page.screenshot({path: join(directory, 'failure.png'), fullPage: true});
    throw new Error(error.message + '\n' + JSON.stringify({errors: state.errors, screenshots: directory,
      status: await page.locator('#connect-status').textContent(), load: await page.locator('#load-error-text').textContent()}));
  } finally { await context.close(); }
}
module.exports = {run};

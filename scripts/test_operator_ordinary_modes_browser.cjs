#!/usr/bin/env node
// Additive ordinary-client UI acceptance only. Reuses the existing intercepted
// browser fixture without running its suite. Two exact synthetic API handlers
// extend its old-mode DTO oracle; no live target, provider or command is used.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFileSync} = require('node:fs');
const {readFile, mkdtemp, stat} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const vm = require('node:vm');
const {fixture: legacyFixture, ready, view, openRestrictions, credential, application, rule, IDS, NOW, UPSTREAM} = require('./test_operator_catalog_browser.cjs');
const {clientCredentialInput, credentialHeaderTarget} = require('../catchplate/operator_demo_web/app.js');

const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const REQUEST_MODE = 'preserve_json_v1';
const RESPONSE_MODE = 'unfiltered_json_or_empty_v1';
const RESPONSES = ['projected_json', 'unfiltered_json', RESPONSE_MODE];
// Additive fixture admission only; the original suite's advertised defaults stay unchanged.
const KNOWN_RESPONSES = [...RESPONSES, 'unfiltered_json_or_empty_v2'];
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const PRIVATE = ['synthetic-ordinary-provider-secret-NEVER-RENDER', 'synthetic-refresh-private-NEVER-RENDER'];
const DUMMY = "Bearer ORDINARY-DUMMY-'literal'-$value";
const capabilities = {requestBodyModes: [REQUEST_MODE], responseModes: RESPONSES, credentialInputModes: ['insert', 'replace_exact']};
const supplied = (changes = {}) => ({...capabilities, credentials: [credential()], applications: [application()], ...changes});
const preservedRule = (changes = {}) => rule({request_body_mode: REQUEST_MODE, request_fields: [],
  response_mode: RESPONSE_MODE, response_fields: [], credential_input: 'replace_exact', placeholder: DUMMY, ...changes});
const google = (changes = {}) => credential({auth_type: 'google_oauth', header_name: 'Authorization',
  provider_account: 'ordinary-fixture@example.test', provider_subject: 'synthetic-google-subject',
  oauth_client_id: 'synthetic-client.apps.googleusercontent.com', permission_preset: 'gmail_readonly',
  scopes: ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'], ...changes});
const digest = number => 'sha256:' + number.toString(16).padStart(64, '0');
const clone = value => JSON.parse(JSON.stringify(value));
const SOURCE_FILES = ['scripts/test_operator_ordinary_modes_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
  'catchplate/operator_demo_portal.py', ...['index.html', 'style.css', 'app.js', 'workspace_core.js', 'workspace_github.js',
    'workspace_applications.js', 'workspace_resources.js', 'workspace_proxy_audit.js', 'workspace_connect.js']
    .map(name => 'catchplate/operator_demo_web/' + name)];
let artifacts;

function policy(state) {
  return {policy_hash: state.active, loaded_policy_hash: state.loaded, sequence: state.sequence,
    activation: state.activationOverride ?? (state.active === state.loaded ? 'active' : 'pending')};
}
function publicCatalog(state) {
  const activeRules = state.rules.filter(item => item.status === 'active');
  const loaded = policy(state).activation === 'active' && state.active === state.loaded;
  const value = {schema: 'catchplate.operatorCatalog/v1', mode: 'operator-development', productionReady: false,
    hardwareVerified: false, revision: state.revision, policy: policy(state), proxy_url: 'https://proxy.example.test',
    allowed_upstreams: state.allowedUpstreams || [UPSTREAM], credentials: state.credentials.map(item => ({...item,
      active_rule_count: activeRules.filter(saved => saved.credential_id === item.id).length})),
    applications: state.applications.map(item => {
      const count = activeRules.filter(saved => saved.application_id === item.id).length;
      return {...item, active_rule_count: count, access_status: item.status === 'revoked' ? loaded ? 'revoked' : 'pending' :
        count === 0 ? 'unassigned' : loaded && item.token_status === 'valid' ? 'active' : 'pending'};
    }), access_rules: state.rules.map(item => ({...item, enforcement: loaded ? item.status === 'revoked' ? 'revoked' : 'active' : 'pending'})),
    capabilities: {credential_types: ['bearer', 'header'], request_body_modes: state.requestBodyModes,
      response_modes: state.responseModes, credential_input_modes: state.credentialInputModes, oauth: false,
      token_lifetime_seconds: {min: 3600, max: 7776000, default: 2592000}}};
  value.limits = Object.fromEntries(['credentials', 'applications', 'access_rules'].map(key => [key,
    {active: value[key].filter(item => item.status === 'active').length, retained: value[key].length, active_max: 32, retained_max: 1024}]));
  return value;
}

// This is an independent bounded payload oracle, not a backend acceptance test.
function admitRule(state, body) {
  const required = ['name', 'application_id', 'credential_id', 'upstream_url', 'methods', 'request_fields', 'response_fields',
    'query_keys', 'allowed_headers', 'response_mode', 'credential_input', 'expected_revision', 'expected_policy_hash'];
  assert(required.every(key => Object.hasOwn(body, key)));
  assert(Object.keys(body).every(key => required.includes(key) || ['request_body_mode', 'placeholder'].includes(key)));
  assert.equal(body.expected_revision, state.revision, 'reviewed catalog revision');
  assert.equal(body.expected_policy_hash, state.active, 'reviewed policy hash');
  assert(typeof body.name === 'string' && body.name.length >= 1 && body.name.length <= 128 && body.name === body.name.trim());
  const selectedCredential = state.credentials.find(item => item.id === body.credential_id && item.status === 'active');
  assert(selectedCredential && state.applications.some(item => item.id === body.application_id && item.status === 'active'));
  const target = new URL(body.upstream_url);
  assert((state.allowedUpstreams || [UPSTREAM]).includes(target.origin)); assert(!target.username && !target.password && !target.hash && !target.search);
  assert(Array.isArray(body.methods) && body.methods.length >= 1 && body.methods.length <= 6 && new Set(body.methods).size === body.methods.length);
  assert(body.methods.every(method => METHODS.includes(method)));
  for (const name of ['request_fields', 'response_fields', 'query_keys', 'allowed_headers']) {
    assert(Array.isArray(body[name]) && body[name].length <= (name === 'allowed_headers' ? 32 : 64));
    assert(body[name].every(value => typeof value === 'string' && value.length >= 1 && value.length <= 256 && /^[\x21-\x7e]+$/.test(value)));
    assert.equal(new Set(body[name]).size, body[name].length);
  }
  if (Object.hasOwn(body, 'request_body_mode')) {
    assert.equal(body.request_body_mode, REQUEST_MODE); assert(Array.isArray(state.requestBodyModes) && state.requestBodyModes.includes(REQUEST_MODE));
    assert.deepEqual(body.request_fields, []); assert.notEqual(selectedCredential.auth_type, 'google_oauth');
  }
  assert(KNOWN_RESPONSES.includes(body.response_mode) && Array.isArray(state.responseModes) && state.responseModes.includes(body.response_mode));
  assert.equal(body.response_fields.length > 0, body.response_mode === 'projected_json');
  assert(['insert', 'replace_exact'].includes(body.credential_input) && Array.isArray(state.credentialInputModes) && state.credentialInputModes.includes(body.credential_input));
  if (body.credential_input === 'insert') assert(!Object.hasOwn(body, 'placeholder'));
  else assert(typeof body.placeholder === 'string' && /^[\x20-\x7e]{1,1024}$/.test(body.placeholder) && body.placeholder === body.placeholder.trim());
  if (selectedCredential.auth_type === 'google_oauth') {
    assert.deepEqual(body.methods, ['GET']); assert.deepEqual(body.request_fields, []);
    assert(!Object.hasOwn(body, 'request_body_mode'));
    assert.equal(target.origin, 'https://gmail.googleapis.com');
    assert(/^\/gmail\/v1\/users\/me\/(?:profile|history|(?:messages|threads|labels)(?:\/[A-Za-z0-9_-]+)?)$/.test(target.pathname));
  }
  const payload = Object.fromEntries(Object.entries(body).filter(([key]) => !key.startsWith('expected_')));
  const id = state.rules.length ? '55555555-5555-4555-8555-555555555555' : IDS.rule;
  assert(!state.rules.some(item => item.id === id), 'bounded fixture has at most two distinct rules');
  const saved = rule({...payload, id, route_id: 'operator.' + id});
  state.rules.push(saved); state.revision++; state.active = digest(++state.sequence);
  if (state.autoLoad) state.loaded = state.active;
  return {access_rule: publicCatalog(state).access_rules.find(item => item.id === id), revision: state.revision, policy: policy(state)};
}

async function fixture(browser, options, exercise) {
  return legacyFixture(browser, options, async (page, state, controls) => {
    state.requestBodyModes = options.requestBodyModes === undefined ? undefined : clone(options.requestBodyModes);
    if (options.allowedUpstreams) state.allowedUpstreams = clone(options.allowedUpstreams);
    // Do not call route.fetch/continue: these handlers can only fulfill synthetic
    // JSON or deny. The underlying fixture still denies every other request and
    // every WebSocket, blocks service workers and closes this dedicated context.
    const handler = async route => {
      const request = route.request(); const url = new URL(request.url());
      state.requests.push({path: url.pathname, query: url.search, method: request.method()});
      try {
        assert.equal(url.origin, ORIGIN); assert(!url.search); assert(state.requests.length <= 150);
        const bytes = request.postDataBuffer(); let result; let status = 200;
        if (url.pathname === '/api/operator-demo/catalog') {
          assert.equal(request.method(), 'GET'); assert(!bytes?.length); state.catalogCalls++;
          result = publicCatalog(state); if (state.catalogTransform) result = state.catalogTransform(result);
        } else {
          assert.equal(url.pathname, '/api/operator-demo/access-rules'); assert.equal(request.method(), 'POST');
          assert(bytes && bytes.length <= 32768 && state.posts.length < 16);
          assert(request.headers()['content-type']?.startsWith('application/json'));
          const body = JSON.parse(bytes.toString()); state.posts.push({name: 'access-rules', body});
          result = admitRule(state, body); status = 201;
        }
        await route.fulfill({status, contentType: 'application/json', body: JSON.stringify(result)});
      } catch (error) { state.errors.push('ordinary fixture contract: ' + error.message); await route.abort(); }
    };
    await controls.context.route('**/api/operator-demo/catalog', handler);
    await controls.context.route('**/api/operator-demo/access-rules', handler);
    await page.reload({waitUntil: 'networkidle'});
    await exercise(page, state, controls);
  });
}

async function hashes() { return Object.fromEntries(await Promise.all(SOURCE_FILES.map(async name =>
  [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')]))); }
async function screenshot(page, name) { if (artifacts) await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true}); }
async function privateAbsent(page) {
  const surfaces = await page.evaluate(() => [document.documentElement.outerHTML,
    ...[...document.querySelectorAll('input,textarea')].map(item => item.value),
    ...Object.values(localStorage), ...Object.values(sessionStorage)].join('\n'));
  for (const value of PRIVATE) assert(!surfaces.includes(value), 'provider-private data must not enter DOM, inputs or browser storage');
}
async function idle(page) { await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled); }
async function step(page, name) { await page.locator('#connect-' + name + '-step').waitFor({state: 'visible'}); await idle(page); }
async function pair(page) {
  await ready(page); await view(page, 'connect'); await page.locator('#connect-use-saved').click();
  await page.locator('#connect-credential-choice').selectOption(IDS.credential);
  await page.locator('#connect-credential-next').click(); await step(page, 'application');
  await page.locator('#connect-application-choice').selectOption(IDS.application);
  await page.locator('#connect-application-next').click(); await step(page, 'access');
}
async function direct(page) {
  await ready(page); await view(page, 'access-rules');
  await openRestrictions(page, 'rule');
  await page.locator('#rule-name').fill('Ordinary JSON operation'); await page.locator('#rule-path').fill('/v1/status');
}
async function draft(page) {
  await pair(page); await page.locator('#connect-rule-choice').selectOption('new');
  await openRestrictions(page, 'connect');
  await page.locator('#connect-rule-name').fill('Ordinary JSON operation'); await page.locator('#connect-origin').selectOption(UPSTREAM);
  await page.locator('#connect-path').fill('/v1/status');
}
async function method(page, prefix, value) {
  for (const name of METHODS) await page.locator(`input[name="${prefix}-method"][value="${name}"]`).setChecked(name === value);
}
async function review(page) { await page.locator('#connect-review').click(); await step(page, 'review'); }
async function grant(page) { await page.locator('#connect-grant').click(); await step(page, 'setup'); }
async function refresh(page, id = 'connect-status-refresh') {
  const response = page.waitForResponse(value => new URL(value.url()).pathname === '/api/operator-demo/catalog');
  await page.locator('#' + id).click(); await response; await page.waitForLoadState('networkidle'); await idle(page);
}
async function command(page) {
  await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  const text = await page.locator('#client-command').innerText();
  assert(text.includes('Proxy-Authorization: Bearer $CATCHPLATE_PROXY_TOKEN') && text.includes('--cacert'));
  assert(!/--insecure|--proxy-insecure|--data|--json/.test(text), 'example stays a connection template, never sends fabricated endpoint data');
  for (const value of PRIVATE) assert(!text.includes(value));
  return text;
}
async function disabledClient(page) {
  await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled());
  assert(await page.locator('#download-config').isDisabled());
}
async function requestFields(page, prefix, visible) {
  assert.equal(await page.locator('#' + prefix + '-request-fields-group').isVisible(), visible);
  if (!visible) assert(await page.locator('#' + prefix + '-request-fields').isDisabled());
}
async function maybeSubmit(page, id) { const button = page.locator('#' + id); if (!await button.isDisabled()) await button.click(); }
async function downloadedConfig(page) {
  const pending = page.waitForEvent('download'); await page.locator('#download-config').click(); const download = await pending;
  assert(download.url().startsWith('blob:'), 'native HTTP/CA downloads are prohibited');
  const stream = await download.createReadStream(); const chunks = []; let bytes = 0;
  try {
    for await (const chunk of stream) { bytes += chunk.length; assert(bytes <= 16384); chunks.push(chunk); }
    const text = Buffer.concat(chunks).toString(); for (const value of PRIVATE) assert(!text.includes(value));
    return JSON.parse(text);
  } finally { await download.delete(); }
}

function projectionChecks() {
  const source = ['workspace_core.js', 'workspace_github.js']
    .map(name => readFileSync(join(ROOT, 'catchplate/operator_demo_web', name), 'utf8')).join('\n');
  const state = {credentials: [credential({secret: PRIVATE[0], refresh_token: PRIVATE[1]})], applications: [application()],
    rules: [rule(), preservedRule({id: '55555555-5555-4555-8555-555555555555'})], requestBodyModes: [REQUEST_MODE],
    responseModes: RESPONSES, credentialInputModes: ['insert', 'replace_exact'], revision: 1, sequence: 1, active: digest(1), loaded: digest(1)};
  const project = input => vm.runInNewContext(source + '\nprojectCatalog(input);',
    {input, clientCredentialInput, credentialHeaderTarget}, {timeout: 1000});
  const projected = project(publicCatalog(state));
  assert(!Object.hasOwn(projected.access_rules[0], 'request_body_mode'), 'legacy absence is retained, not rewritten');
  assert(Object.hasOwn(projected.access_rules[1], 'request_body_mode')); assert.equal(projected.access_rules[1].request_body_mode, REQUEST_MODE);
  for (const value of PRIVATE) assert(!JSON.stringify(projected).includes(value));
  for (const changes of [{request_body_mode: null}, {request_body_mode: 'future_mode'}, {request_fields: ['message']},
    {response_mode: 'future_response'}, {response_fields: ['secret']}]) {
    const input = publicCatalog(state); Object.assign(input.access_rules[1], changes); assert.throws(() => project(input));
  }
  const googleInput = publicCatalog(state); googleInput.credentials = [google()];
  assert.throws(() => project(googleInput), 'Google cannot inherit JSON preservation from a saved contradictory rule');
  const legacyHeader = publicCatalog(state); legacyHeader.credentials = [credential({auth_type: 'header', header_name: 'Content-Type'})];
  legacyHeader.access_rules = [rule({credential_input: 'insert'})];
  assert(!Object.hasOwn(project(legacyHeader).access_rules[0], 'request_body_mode'));
  legacyHeader.access_rules[0].credential_input = 'replace_exact'; legacyHeader.access_rules[0].placeholder = DUMMY;
  assert.throws(() => project(legacyHeader), 'legacy insertion does not widen the replacement header contract');
  return {ok: true, groups: 1, scope: 'pure public projection: absence, additive modes, malformed metadata and secret omission'};
}

const tests = [
  ['direct new-rule defaults preserve JSON and admit empty204 without either field list', browser => fixture(browser, supplied(), async (page, state) => {
    await direct(page); assert.equal(await page.locator('#rule-request-body-mode').inputValue(), REQUEST_MODE);
    assert.equal(await page.locator('#rule-response-mode').inputValue(), RESPONSE_MODE);
    await requestFields(page, 'rule', false); assert(await page.locator('#rule-response-fields').isDisabled());
    assert(!await page.locator('#rule-response-fields-group').isVisible());
    await method(page, 'rule', 'POST'); await page.locator('#rule-credential-input').selectOption('replace_exact');
    await page.locator('#rule-placeholder').fill(DUMMY); await screenshot(page, 'direct-default-new-modes-desktop');
    await page.locator('#rule-save').click(); await ready(page);
    assert.equal(state.posts.length, 1); const body = state.posts[0].body;
    assert.equal(body.request_body_mode, REQUEST_MODE); assert.equal(body.response_mode, RESPONSE_MODE);
    assert.deepEqual(body.request_fields, []); assert.deepEqual(body.response_fields, []);
    assert.deepEqual(body.methods, ['POST']); assert.deepEqual(body.query_keys, []);
    assert.deepEqual(body.allowed_headers, ['accept', 'user-agent']); assert.equal(body.placeholder, DUMMY);
    const summary = await page.locator('#access-rules-list').innerText(); assert.match(summary, /JSON/i); assert.match(summary, /204/);
    await view(page, 'proxy'); const text = await command(page); assert(text.includes("Authorization: Bearer ORDINARY-DUMMY-'\\''literal'\\''-$value"));
    assert.match(await page.locator('#client-guidance').innerText(), /204/); assert.equal(state.posts.length, 1);
  })],
  ['guided empty workspace keeps provider secret separate and downloads exact additive client metadata', browser => fixture(browser, capabilities, async (page, state) => {
    await ready(page); await view(page, 'connect'); await page.locator('#connect-use-key').click();
    await page.locator('#connect-credential-name').fill('Reusable static key');
    await page.locator('#connect-credential-secret').fill(PRIVATE[0]); await page.locator('#connect-credential-next').click(); await step(page, 'application');
    assert.equal(await page.locator('#connect-credential-secret').inputValue(), ''); await privateAbsent(page);
    await page.locator('#connect-application-name').fill('Ordinary JSON client'); await page.locator('#connect-token-ttl').selectOption('3600');
    await page.locator('#connect-application-next').click(); await step(page, 'access'); const held = await page.locator('#client-token').inputValue();
    assert(held.startsWith('synthetic_application_')); assert.equal(state.rules.length, 0);
    await openRestrictions(page, 'connect');
    await page.locator('#connect-rule-name').fill('Ordinary JSON operation'); await page.locator('#connect-path').fill('/v1/status');
    assert.equal(await page.locator('#connect-request-body-mode').inputValue(), REQUEST_MODE);
    assert.equal(await page.locator('#connect-response-mode').inputValue(), RESPONSE_MODE); await requestFields(page, 'connect', false);
    assert(await page.locator('#connect-response-fields').isDisabled()); await method(page, 'connect', 'POST');
    await page.locator('#connect-credential-input').selectOption('replace_exact'); await page.locator('#connect-placeholder').fill(DUMMY);
    await screenshot(page, 'guided-default-new-modes-desktop'); await review(page);
    const summary = await page.locator('#connect-review-details').innerText(); assert.match(summary, /JSON/); assert.match(summary, /204/); assert.match(summary, /POST/);
    assert.equal(state.posts.length, 2); await screenshot(page, 'guided-effective-review-desktop');
    await grant(page); await page.locator('#connect-setup-slot').waitFor({state: 'visible'}); await command(page); await privateAbsent(page);
    assert.deepEqual(state.posts.map(item => item.name), ['credentials', 'applications', 'access-rules']);
    const body = state.posts[2].body; assert.equal(body.request_body_mode, REQUEST_MODE); assert.equal(body.response_mode, RESPONSE_MODE);
    assert.deepEqual(body.request_fields, []); assert.deepEqual(body.response_fields, []);
    const config = await downloadedConfig(page); assert.equal(config.request_body_mode, REQUEST_MODE); assert.equal(config.response_mode, RESPONSE_MODE);
    assert.equal(config.proxy_authorization, 'Bearer ' + held); assert.deepEqual(config.request_headers, {Authorization: DUMMY});
    await screenshot(page, 'guided-setup-desktop'); await page.setViewportSize({width: 390, height: 844});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)); await screenshot(page, 'guided-setup-mobile');
  })],
  ...['rule', 'connect'].map(prefix => [prefix + ' explicit legacy request fields are not silently discarded by preserving mode', browser => fixture(browser, supplied(), async (page, state) => {
    if (prefix === 'rule') await direct(page); else await draft(page);
    await page.locator('#' + prefix + '-request-body-mode').selectOption('legacy_fields'); await requestFields(page, prefix, true);
    await page.locator('#' + prefix + '-request-fields').fill('message\nrecipient');
    await page.locator('#' + prefix + '-request-body-mode').selectOption(REQUEST_MODE); await requestFields(page, prefix, true);
    assert.equal(await page.locator('#' + prefix + '-request-fields').inputValue(), 'message\nrecipient');
    await maybeSubmit(page, prefix === 'rule' ? 'rule-save' : 'connect-review'); assert.equal(state.posts.length, 0);
    if (prefix === 'connect') await step(page, 'access');
    await page.locator('#' + prefix + '-request-fields').fill(''); await requestFields(page, prefix, false);
    if (prefix === 'rule') { await page.locator('#rule-save').click(); await ready(page); } else { await review(page); await grant(page); }
    assert.equal(state.posts.length, 1); assert.equal(state.posts[0].body.request_body_mode, REQUEST_MODE); assert.deepEqual(state.posts[0].body.request_fields, []);
  })]),
  ...['rule', 'connect'].map(prefix => [prefix + ' explicit field-constrained request and response remain opt-in legacy payloads', browser => fixture(browser, supplied(), async (page, state) => {
    if (prefix === 'rule') await direct(page); else await draft(page);
    await page.locator('#' + prefix + '-request-body-mode').selectOption('legacy_fields');
    await page.locator('#' + prefix + '-request-fields').fill('message'); await page.locator('#' + prefix + '-response-mode').selectOption('projected_json');
    assert(await page.locator('#' + prefix + '-response-fields').evaluate(node => node.required));
    await maybeSubmit(page, prefix === 'rule' ? 'rule-save' : 'connect-review'); assert.equal(state.posts.length, 0);
    await page.locator('#' + prefix + '-response-fields').fill('result.id');
    if (prefix === 'rule') { await page.locator('#rule-save').click(); await ready(page); } else { await review(page); await grant(page); }
    const body = state.posts[0].body; assert(!Object.hasOwn(body, 'request_body_mode')); assert.deepEqual(body.request_fields, ['message']);
    assert.equal(body.response_mode, 'projected_json'); assert.deepEqual(body.response_fields, ['result.id']);
  })]),
  ['old saved no-body and selected-field rules stay unchanged beside a newly preserved rule', browser => fixture(browser,
    supplied({rules: [rule({request_fields: ['message'], credential_input: 'insert', response_mode: 'unfiltered_json', response_fields: []})]}), async (page, state) => {
      const before = JSON.stringify(state.rules[0]); await direct(page); await page.locator('#rule-save').click(); await ready(page);
      assert.equal(JSON.stringify(state.rules[0]), before); assert(!Object.hasOwn(state.rules[0], 'request_body_mode'));
      assert.equal(state.rules[1].request_body_mode, REQUEST_MODE); assert.equal(state.posts.length, 1);
      await view(page, 'proxy'); await command(page); assert.match(await page.locator('#client-guidance').innerText(), /message/);
      await page.locator('#proxy-rule').selectOption(state.rules[1].id); await command(page);
      assert.match(await page.locator('#client-guidance').innerText(), /204/); assert.equal(JSON.stringify(state.rules[0]), before);
    })],
  ...['insert', 'replace_exact'].map(mode => ['legacy custom Content-Type ' + mode + ' keeps insertion distinct from stricter replacement', browser => fixture(browser,
    supplied({credentials: [credential({auth_type: 'header', header_name: 'Content-Type'})],
      rules: [rule({credential_input: mode, ...(mode === 'replace_exact' ? {placeholder: DUMMY} : {})})]}), async (page, state) => {
      if (mode === 'insert') {
        await ready(page); await view(page, 'access-rules'); assert.match(await page.locator('#access-rules-list').innerText(), /No body/);
        await view(page, 'proxy'); const text = await command(page); assert(!text.includes('--header \'Content-Type:'));
        assert(!Object.hasOwn(state.rules[0], 'request_body_mode')); assert(!await page.locator('#load-error').isVisible());
      } else {
        await page.locator('#load-error').waitFor({state: 'visible'}); assert(await page.locator('#rule-save').isDisabled()); await disabledClient(page);
      }
      assert.equal(state.posts.length, 0);
    })]),
  ...[{name: 'missing', value: undefined}, {name: 'empty', value: []}, {name: 'unknown-only', value: ['future_mode']}].map(capability =>
    [capability.name + ' initial request capability retains explicit legacy absence, never claims preservation', browser => fixture(browser,
      supplied({requestBodyModes: capability.value, responseModes: ['projected_json', 'unfiltered_json']}), async (page, state) => {
        await direct(page); assert.equal(await page.locator('#rule-request-body-mode').inputValue(), 'legacy_fields');
        assert.equal(await page.locator('#rule-request-body-mode option[value="' + REQUEST_MODE + '"]:not(:disabled)').count(), 0);
        assert.equal(await page.locator('#rule-response-mode').inputValue(), 'unfiltered_json'); await requestFields(page, 'rule', true);
        await page.locator('#rule-save').click(); await ready(page); assert(!Object.hasOwn(state.posts[0].body, 'request_body_mode'));
        assert.deepEqual(state.posts[0].body.request_fields, []); assert.equal(state.posts[0].body.response_mode, 'unfiltered_json');
        await draft(page); assert.equal(await page.locator('#connect-request-body-mode').inputValue(), 'legacy_fields');
        assert.equal(state.posts.length, 1);
      })]),
  ['withdrawing capabilities does not change a reviewed choice into a broader or legacy rule', browser => fixture(browser, supplied(), async (page, state) => {
    await draft(page); await review(page); state.requestBodyModes = []; state.responseModes = ['projected_json', 'unfiltered_json'];
    await refresh(page); assert(await page.locator('#connect-grant').isDisabled()); await page.locator('#connect-back').click(); await step(page, 'access');
    assert.equal(await page.locator('#connect-request-body-mode').inputValue(), REQUEST_MODE);
    assert.equal(await page.locator('#connect-response-mode').inputValue(), RESPONSE_MODE);
    for (const id of ['connect-request-body-mode', 'connect-response-mode']) assert(await page.locator('#' + id + ' option:checked').evaluate(node => node.disabled));
    await maybeSubmit(page, 'connect-review'); await step(page, 'access'); assert.equal(state.posts.length, 0);
  })],
  ['unadvertised saved preservation cannot be copied or downloaded despite active matching policy hashes', browser => fixture(browser,
    supplied({requestBodyModes: [], rules: [preservedRule()]}), async (page, state) => {
      await ready(page); await disabledClient(page); assert.equal(state.posts.length, 0);
    })],
  ...[{name: 'missing', value: undefined}, {name: 'empty', value: []}, {name: 'unknown-only', value: ['future_response']}].map(capability =>
    [capability.name + ' response capability disables access-rule creation and existing client actions', browser => fixture(browser,
      supplied({responseModes: capability.value, rules: [preservedRule()]}), async (page, state) => {
        await ready(page); await view(page, 'access-rules'); assert(await page.locator('#rule-save').isDisabled());
        await pair(page); assert(await page.locator('#connect-review').isDisabled()); await disabledClient(page); assert.equal(state.posts.length, 0);
      })]),
  ['DOM-tampered unsupported request and response choices cannot reach publication', browser => fixture(browser, supplied(), async (page, state) => {
    await direct(page);
    for (const [id, value] of [['rule-request-body-mode', 'future_mode'], ['rule-response-mode', 'future_response']]) {
      await page.locator('#' + id).evaluate((select, value) => {
        const option = document.createElement('option'); option.value = value; option.textContent = 'synthetic unsupported option';
        select.append(option); select.value = value; select.dispatchEvent(new Event('change', {bubbles: true}));
      }, value);
      await maybeSubmit(page, 'rule-save'); assert.equal(state.posts.length, 0);
      await page.locator('#' + id).selectOption(id.includes('request') ? REQUEST_MODE : RESPONSE_MODE);
    }
  })],
  ['Google keeps the exact GET/no-body choice and cannot silently inherit a prior preservation draft', browser => fixture(browser,
    supplied({credentials: [credential(), google({id: '66666666-6666-4666-8666-666666666666'})]}), async (page, state) => {
      await direct(page); await page.locator('#rule-credential-id').selectOption('66666666-6666-4666-8666-666666666666');
      await maybeSubmit(page, 'rule-save'); assert.equal(state.posts.length, 0, 'previous static preservation choice must require correction');
      await page.locator('#rule-request-body-mode').selectOption('legacy_fields');
      assert.equal(await page.locator('#rule-request-body-mode option[value="' + REQUEST_MODE + '"]:not(:disabled)').count(), 0);
      await method(page, 'rule', 'POST'); await maybeSubmit(page, 'rule-save'); assert.equal(state.posts.length, 0);
      await pair(page); await page.locator('#connect-back').click(); await step(page, 'application');
      await page.locator('#connect-back').click(); await step(page, 'credential');
      await page.locator('#connect-credential-choice').selectOption('66666666-6666-4666-8666-666666666666');
      await page.locator('#connect-credential-next').click(); await step(page, 'application');
      await page.locator('#connect-application-next').click(); await step(page, 'access');
      assert.equal(await page.locator('#connect-request-body-mode option[value="' + REQUEST_MODE + '"]:not(:disabled)').count(), 0);
      assert(await page.locator('#connect-google').isDisabled()); assert.equal(state.posts.length, 0);
      assert(!state.requests.some(item => /oauth|google/.test(item.path)));
    })],
  ['saved Google GET rule remains legacy bodyless despite advertised new request capabilities', browser => fixture(browser,
    supplied({credentials: [google()], rules: [rule({upstream_url: 'https://gmail.googleapis.com/gmail/v1/users/me/profile',
      credential_input: 'insert', response_mode: 'unfiltered_json', response_fields: []})]}), async (page, state) => {
      // This saved public observation is presentation only. The fake deployment
      // allowlist does not claim to admit a real Google rule or provider request.
      const before = JSON.stringify(state.rules); await ready(page); await view(page, 'proxy'); await command(page);
      assert.match(await page.locator('#client-guidance').innerText(), /Request bodies are forbidden/);
      assert(!Object.hasOwn(state.rules[0], 'request_body_mode')); assert.equal(JSON.stringify(state.rules), before);
      await view(page, 'credentials'); assert(await page.locator('#credential-google-connect').isDisabled());
      assert.equal(state.posts.length, 0);
    })],
  ...[
    {name: 'explicit null request mode', changes: {request_body_mode: null}},
    {name: 'preservation with nonempty request fields', changes: {request_fields: ['message']}},
    {name: 'empty204 response with projected fields', changes: {response_fields: ['id']}},
  ].map(test => [test.name + ' rejects the catalog and disables writes, copy and download', browser => fixture(browser,
    supplied({rules: [preservedRule(test.changes)]}), async (page, state) => {
      await page.locator('#load-error').waitFor({state: 'visible'}); assert(await page.locator('#rule-save').isDisabled());
      assert(await page.locator('#connect-credential-next').isDisabled()); await disabledClient(page); assert.equal(state.posts.length, 0);
    })]),
  ['new-mode activation pending is not ready setup even when committed and loaded hashes match', browser => fixture(browser,
    supplied({activationOverride: 'pending'}), async (page, state) => {
      await draft(page); await review(page); await grant(page); assert.equal(state.active, state.loaded);
      assert(!await page.locator('#connect-setup-slot').isVisible()); assert(await page.locator('#copy-command').isDisabled());
      assert(await page.locator('#download-config').isDisabled()); state.activationOverride = 'active'; await refresh(page);
      await page.locator('#connect-setup-slot').waitFor({state: 'visible'}); await command(page); assert.equal(state.posts.length, 1);
    })],
  ['public saved new modes omit provider-secret extras from summaries, forms and client examples', browser => fixture(browser,
    supplied({credentials: [credential({secret: PRIVATE[0], refresh_token: PRIVATE[1]})],
      rules: [preservedRule({secret: PRIVATE[0], provider_secret: PRIVATE[1]})]}), async (page, state) => {
      await ready(page); await view(page, 'credentials'); await privateAbsent(page); await view(page, 'access-rules'); await privateAbsent(page);
      await view(page, 'proxy'); await command(page); await privateAbsent(page); assert.equal(state.posts.length, 0);
      assert(await page.locator('#download-config').isDisabled(), 'an existing app token is never retrieved implicitly');
    })],
];

async function main() {
  assert.equal(process.argv.length, 2, 'ordinary-mode fixtures accept no live target, credentials or runtime options');
  const before = await hashes(); console.log(JSON.stringify({phase: 'source-before', hashes: before}));
  console.log(JSON.stringify(projectionChecks()));
  const artifactRoot = '/srv/catchplate-fast/projects/catchplate-operator-artifacts';
  assert((await stat(artifactRoot)).isDirectory()); artifacts = await mkdtemp(join(artifactRoot, 'ordinary-modes-browser-synthetic-'));
  console.log(JSON.stringify({artifactDirectory: artifacts, scope: 'synthetic screenshots only'}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of tests) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: tests.length, pureGroups: 1, scope: 'intercepted additive ordinary-client UI fixtures only',
        otherBrowserSuitesExecuted: false, liveRequests: 0, providerRequests: 0, nativeCaDownloadExecuted: false,
        generatedCommandsExecuted: false, runtimeGateAcceptance: false, productionAcceptance: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('ordinary-mode fixture deadline')), 150000); })]);
  } finally {
    clearTimeout(deadline);
    try { await browser.close(); }
    finally { const after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after})); assert.deepEqual(after, before, 'sources remained frozen'); }
  }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });
module.exports = {fixture, publicCatalog, supplied, google, preservedRule, policy, digest, clone,
  pair, direct, draft, method, review, grant, refresh, command, disabledClient, downloadedConfig, step, privateAbsent, PRIVATE, DUMMY};

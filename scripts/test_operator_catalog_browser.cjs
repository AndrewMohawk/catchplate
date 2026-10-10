#!/usr/bin/env node
// Intercepted synthetic catalog fixtures only. Never contacts an app, provider,
// proxy, SSO endpoint or CA server; native HTTP downloads are not exercised.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {mkdtemp, stat} = require('node:fs/promises');
const {join, resolve} = require('node:path');

const ROOT = resolve(__dirname, '..');
let artifactDirectory;
const ORIGIN = 'https://operator-catalog.example.test';
const NOW = Date.parse('2026-10-08T12:00:00Z');
const UPSTREAM = 'https://api.example.test';
const SECRET = 'synthetic-provider-value-not-a-real-credential';
const IDS = {credential: '11111111-1111-4111-8111-111111111111', application: '22222222-2222-4222-8222-222222222222',
  other: '33333333-3333-4333-8333-333333333333', rule: '44444444-4444-4444-8444-444444444444'};
const VIEWS = ['overview', 'credentials', 'applications', 'access-rules', 'proxy', 'audit'];
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const LIMITS = {credentials: 16384, 'credentials/revoke': 1024, applications: 2048,
  'applications/revoke': 1024, 'applications/rotate-token': 2048, 'access-rules': 32768, 'access-rules/revoke': 1024};
const digest = number => 'sha256:' + number.toString(16).padStart(64, '0');
const token = (id, generation = 1) => 'synthetic_application_' + id.replaceAll('-', '') + '_generation_' + generation;
const copy = value => JSON.parse(JSON.stringify(value));
const credential = (changes = {}) => ({id: IDS.credential, name: 'Shared provider key', status: 'active',
  auth_type: 'bearer', header_name: 'Authorization', active_rule_count: 0, created_at: new Date(NOW).toISOString(), ...changes});
const application = (changes = {}) => ({id: IDS.application, name: 'Reporting application', status: 'active',
  principal_id: 'agent:operator-demo:' + (changes.id || IDS.application), token_expires_at_epoch_ms: NOW + 86400000,
  token_generation: 1, token_status: 'valid', access_status: 'unassigned', active_rule_count: 0,
  created_at: new Date(NOW).toISOString(), ...changes});
const rule = (changes = {}) => ({id: IDS.rule, name: 'Read status', status: 'active', application_id: IDS.application,
  credential_id: IDS.credential, route_id: 'operator.' + IDS.rule, upstream_url: UPSTREAM + '/v1/status', methods: ['GET'],
  request_fields: [], response_fields: ['id', 'status'], query_keys: [], allowed_headers: ['accept', 'user-agent'],
  response_mode: 'projected_json', enforcement: 'active', created_at: new Date(NOW).toISOString(), ...changes});

function generatorChecks() {
  const {buildCurlCommand} = require('../serverware/operator_demo_web/app.js');
  const inputs = {proxyUrl: 'https://proxy.example.test', upstreamUrl: UPSTREAM + '/v1/status', method: 'GET', caPath: './serverware-ca.pem'};
  for (const method of METHODS) assert(buildCurlCommand({...inputs, method}).includes("--request '" + method + "'"));
  for (const method of ['HEAD', 'TRACE', 'CONNECT', 'get', 'GET\nPOST']) assert.throws(() => buildCurlCommand({...inputs, method}));
  for (const key of ['proxyUrl', 'upstreamUrl']) for (const value of ['http://example.test', 'https://user:pass@example.test', 'https://example.test/#fragment'])
    assert.throws(() => buildCurlCommand({...inputs, [key]: value}));
  const command = buildCurlCommand({...inputs, caPath: "./certificate's $(never-executed).pem", providerSecret: SECRET, clientToken: token(IDS.application)});
  assert(command.includes("--cacert './certificate'\\''s $(never-executed).pem'"), 'shell quoting keeps the complete CA path literal');
  assert(command.includes('--proxy-header "Proxy-Authorization: Bearer $SERVERWARE_PROXY_TOKEN"'));
  assert(!command.includes(SECRET) && !command.includes(token(IDS.application)), 'unknown credential fields do not enter public examples');
  for (const forbidden of ['--insecure', '--proxy-insecure', ' -k ']) assert(!command.includes(forbidden));
  assert(command.includes('--cacert ') && command.includes("--noproxy ''"));
  assert(command.includes("--header 'Accept: application/json'") && command.includes("--header 'User-Agent:'"));
  const restricted = buildCurlCommand({...inputs, allowedHeaders: []});
  assert(restricted.includes("--header 'Accept:'") && !restricted.includes('Accept: application/json'));
  return {ok: true, scope: 'pure exported client command generator; no browser or requests', groups: 8};
}

function policy(state) {
  return {policy_hash: state.active, loaded_policy_hash: state.loaded, sequence: state.sequence,
    activation: state.activationOverride ?? (state.active === state.loaded ? 'active' : 'pending')};
}
function catalog(state) {
  const activeRules = state.rules.filter(item => item.status === 'active');
  const loaded = state.active === state.loaded && policy(state).activation === 'active';
  const value = {schema: 'serverware.operatorCatalog/v1', mode: 'operator-development', productionReady: false,
    hardwareVerified: false, revision: state.revision, policy: policy(state), proxy_url: 'https://proxy.example.test',
    allowed_upstreams: state.allowedUpstreams, credentials: state.credentials.map(item => ({...item,
      active_rule_count: activeRules.filter(itemRule => itemRule.credential_id === item.id).length})),
    applications: state.applications.map(item => {
      const count = activeRules.filter(itemRule => itemRule.application_id === item.id).length;
      return {...item, active_rule_count: count, access_status: item.status === 'revoked' ? loaded ? 'revoked' : 'pending' :
        count === 0 ? 'unassigned' : loaded && item.token_status === 'valid' ? 'active' : 'pending'};
    }), access_rules: state.rules.map(item => ({...item, enforcement: loaded ? item.status === 'revoked' ? 'revoked' : 'active' : 'pending'})),
    capabilities: {credential_types: ['bearer', 'header'], response_modes: state.responseModes,
      credential_input_modes: state.credentialInputModes, oauth: false,
      token_lifetime_seconds: {min: 3600, max: 7776000, default: 2592000}}};
  value.limits = Object.fromEntries(['credentials', 'applications', 'access_rules'].map(key => [key,
    {active: value[key].filter(item => item.status === 'active').length, retained: value[key].length, active_max: 32, retained_max: 1024}]));
  return value;
}
function mutation(state, name, body) {
  assert.equal(body.expected_revision, state.revision, 'mutation uses reviewed catalog revision');
  assert.equal(body.expected_policy_hash, state.active, 'mutation uses reviewed policy hash');
  const payload = Object.fromEntries(Object.entries(body).filter(([key]) => !key.startsWith('expected_')));
  let selected; let collection; let clientToken; let authorityChanged = false;
  if (name === 'credentials') {
    assert.deepEqual(Object.keys(payload).sort(), ['auth_type', 'header_name', 'name', 'secret']);
    selected = credential({name: payload.name, auth_type: payload.auth_type, header_name: payload.header_name});
    state.credentials.push(selected); collection = 'credentials';
  } else if (name === 'applications') {
    assert.deepEqual(Object.keys(payload).sort(), ['name', 'token_lifetime_seconds']);
    assert(Number.isInteger(payload.token_lifetime_seconds) && payload.token_lifetime_seconds >= 3600 && payload.token_lifetime_seconds <= 7776000);
    const id = state.applications.length ? IDS.other : IDS.application;
    selected = application({id, name: payload.name, token_expires_at_epoch_ms: NOW + payload.token_lifetime_seconds * 1000});
    state.applications.push(selected); collection = 'applications'; clientToken = token(id);
  } else if (name === 'access-rules') {
    assert(!Object.hasOwn(payload, 'secret') && !Object.hasOwn(payload, 'client_token'));
    const credentialInput = Object.hasOwn(payload, 'credential_input') ? payload.credential_input : 'insert';
    assert(['insert', 'replace_exact'].includes(credentialInput), 'supported credential input mode');
    if (credentialInput === 'insert') assert(!Object.hasOwn(payload, 'placeholder'), 'insertion omits placeholder');
    else {
      assert(state.credentialInputModes?.includes('replace_exact'), 'exact replacement must be explicitly advertised');
      assert(typeof payload.placeholder === 'string' && /^[\x20-\x7e]{1,1024}$/.test(payload.placeholder) &&
        payload.placeholder === payload.placeholder.trim(), 'replacement requires a bounded exact printable header value');
    }
    const responseMode = payload.response_mode || 'projected_json';
    assert(['projected_json', 'unfiltered_json'].includes(responseMode), 'supported response mode');
    if (responseMode === 'unfiltered_json') {
      assert(state.responseModes?.includes('unfiltered_json'), 'simple response mode must be explicitly advertised');
      assert.deepEqual(payload.response_fields || [], []);
    } else assert(Array.isArray(payload.response_fields) && payload.response_fields.length > 0, 'projected response retains explicit fields');
    assert(state.credentials.some(item => item.id === payload.credential_id && item.status === 'active'));
    assert(state.applications.some(item => item.id === payload.application_id && item.status === 'active'));
    const id = state.rules.length ? '55555555-5555-4555-8555-555555555555' : IDS.rule;
    selected = rule({...payload, credential_input: credentialInput, id, route_id: 'operator.' + id});
    state.rules.push(selected); collection = 'access_rules'; authorityChanged = true;
  } else {
    collection = name.split('/')[0].replace('-', '_');
    const items = collection === 'access_rules' ? state.rules : state[collection];
    selected = items.find(item => item.id === payload.id);
    assert(selected && selected.status === 'active', 'mutation targets an active fixture resource');
    if (name === 'applications/rotate-token') {
      assert.deepEqual(Object.keys(payload).sort(), ['id', 'token_lifetime_seconds']);
      selected.token_generation++; selected.token_status = 'valid';
      selected.token_expires_at_epoch_ms = NOW + payload.token_lifetime_seconds * 1000;
      clientToken = token(selected.id, selected.token_generation);
      authorityChanged = state.rules.some(item => item.application_id === selected.id && item.status === 'active');
    } else {
      assert.deepEqual(Object.keys(payload), ['id']); selected.status = 'revoked';
      if (collection === 'credentials') assert(!state.rules.some(item => item.credential_id === selected.id && item.status === 'active'));
      if (collection === 'applications') {
        selected.token_status = 'revoked';
        for (const item of state.rules) if (item.application_id === selected.id && item.status === 'active') { item.status = 'revoked'; authorityChanged = true; }
      }
      if (collection === 'access_rules') authorityChanged = true;
    }
  }
  state.revision++;
  if (authorityChanged) { state.active = digest(++state.sequence); if (state.autoLoad) state.loaded = state.active; }
  const key = {credentials: 'credential', applications: 'application', access_rules: 'access_rule'}[collection];
  const published = catalog(state)[collection].find(item => item.id === selected.id);
  return {[key]: published, revision: state.revision, policy: policy(state), ...(clientToken ? {client_token: clientToken} : {})};
}

async function fixture(browser, options, exercise) {
  const state = {credentials: copy(options.credentials || []), applications: copy(options.applications || []), rules: copy(options.rules || []),
    allowedUpstreams: copy(options.allowedUpstreams || [UPSTREAM]),
    responseModes: Object.hasOwn(options, 'responseModes') ? options.responseModes : ['projected_json'],
    credentialInputModes: Object.hasOwn(options, 'credentialInputModes') ? options.credentialInputModes : ['insert'],
    activationOverride: options.activationOverride,
    revision: 1, sequence: 1, active: digest(1), loaded: options.pending ? digest(0) : digest(1), autoLoad: options.autoLoad !== false,
    posts: [], requests: [], errors: [], unexpected: [], consoleErrors: [], expectedFailures: new Set(), dialogs: [], catalogCalls: 0,
    catalogStatus: 200, cancelNextDialog: false, fault: options.fault, faultUsed: false};
  const context = await browser.newContext({viewport: {width: 1280, height: 960}, serviceWorkers: 'block',
    permissions: ['clipboard-read', 'clipboard-write']});
  const document = execFileSync('python3', ['-B', '-c', 'from serverware.operator_demo_portal import render; print(render())'],
    {cwd: ROOT, encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024});
  const answer = (route, body, status = 200) => route.fulfill({status, contentType: 'application/json', body: JSON.stringify(body)});
  await context.route('**/*', async route => {
    const request = route.request(); const url = new URL(request.url());
    state.requests.push({path: url.pathname, query: url.search, method: request.method()});
    const refuse = async label => { state.unexpected.push(label); await route.abort(); };
    try {
      if (state.requests.length > 150 || url.origin !== ORIGIN) return await refuse('request origin/count refused');
      const bytes = request.postDataBuffer();
      if (request.method() === 'GET' && bytes?.length) return await refuse('GET body refused');
      if (request.method() === 'GET' && url.pathname === '/' && !url.search)
        return await route.fulfill({status: 200, contentType: 'text/html', body: document});
      if (request.method() === 'GET' && url.pathname === '/favicon.ico') return await route.fulfill({status: 204, body: ''});
      if (request.method() === 'GET' && url.pathname === '/api/operator-demo/catalog' && !url.search) {
        state.catalogCalls++;
        if (state.catalogStatus !== 200) { state.expectedFailures.add(url.pathname); return await answer(route, {detail: 'synthetic access refusal'}, state.catalogStatus); }
        return await answer(route, options.invalidCatalog ? {...catalog(state), productionReady: true} : catalog(state));
      }
      if (request.method() === 'GET' && url.pathname === '/api/audit/search') {
        assert.equal(url.searchParams.get('limit'), '20'); assert.equal(url.searchParams.get('scanLimit'), '5000');
        assert([...url.searchParams.keys()].every(key => ['limit', 'scanLimit', 'q', 'eventType', 'cursor'].includes(key)));
        return await answer(route, {ok: true, complete: true, has_more: false, next_cursor: null, items: [
          {id: 'fixture-audit', created_at: new Date(NOW).toISOString(), event_type: url.searchParams.get('eventType') || 'operator_catalog.credential.created', event: {syntheticOnly: true}}]});
      }
      if (request.method() === 'GET' && url.pathname === '/api/audit/verify' && !url.search)
        return await answer(route, {ok: true, complete: true, backend: 'sqlite'});
      const name = url.pathname.startsWith('/api/operator-demo/') ? url.pathname.slice('/api/operator-demo/'.length) : '';
      if (request.method() !== 'POST' || !Object.hasOwn(LIMITS, name) || url.search || !bytes || bytes.length > LIMITS[name] || state.posts.length >= 16)
        return await refuse('unknown or unbounded operation');
      assert(request.headers()['content-type']?.startsWith('application/json'));
      const body = JSON.parse(bytes.toString()); state.posts.push({name, body});
      if (state.fault && !state.faultUsed) {
        state.faultUsed = true; state.expectedFailures.add(url.pathname);
        if (state.fault === 'lost-after-commit') { mutation(state, name, body); return await route.abort('failed'); }
        return await answer(route, {detail: SECRET}, Number(state.fault));
      }
      return await answer(route, mutation(state, name, body), name.includes('/') ? 200 : 201);
    } catch (error) { state.errors.push('fixture contract: ' + error.message); await route.abort(); }
  });
  await context.routeWebSocket('**/*', socket => { state.unexpected.push('WebSocket refused'); socket.close(); });
  function instrument(page) {
    page.setDefaultTimeout(5000);
    page.on('pageerror', error => state.errors.push(error.message));
    page.on('console', message => { if (message.type() === 'error') state.consoleErrors.push({message: message.text(), url: message.location().url}); });
    page.on('dialog', async dialog => { state.dialogs.push(dialog.message()); if (state.cancelNextDialog) { state.cancelNextDialog = false; await dialog.dismiss(); } else await dialog.accept(); });
  }
  const page = await context.newPage(); instrument(page);
  await page.clock.install({time: new Date(NOW)}); await page.clock.pauseAt(new Date(NOW));
  const openPage = async () => { const next = await context.newPage(); instrument(next); await next.goto(ORIGIN, {waitUntil: 'networkidle'}); await ready(next); return next; };
  try {
    await page.goto(ORIGIN, {waitUntil: 'networkidle'});
    await exercise(page, state, {context, openPage});
    assert.deepEqual(state.errors, []); assert.deepEqual(state.unexpected, []);
    for (const entry of state.consoleErrors) assert(entry.url && state.expectedFailures.has(new URL(entry.url).pathname), 'unexpected browser console error');
    assert(state.requests.every(item => item.method === 'GET' || item.method === 'POST' && Object.hasOwn(LIMITS, item.path.slice('/api/operator-demo/'.length))));
  } finally { await context.close(); }
}
async function ready(page) { await page.waitForFunction(() => !document.querySelector('#credential-fields').disabled); }
async function view(page, name) {
  await page.locator(`nav a[href="#${name}"]`).click(); await page.locator('#' + name).waitFor({state: 'visible'});
  assert.equal(await page.locator('.page:visible').count(), 1); assert.equal(await page.locator(`nav a[href="#${name}"]`).getAttribute('aria-current'), 'page');
}
async function openRestrictions(page, prefix) {
  const details = page.locator('#' + prefix + '-restrictions');
  if (!await details.evaluate(node => node.open)) await details.locator(':scope > summary').click();
}
async function noToken(page) {
  await page.waitForFunction(() => document.querySelector('#client-token').value === '' && document.querySelector('#one-time-access').hidden);
  for (const id of ['copy-token', 'reveal-token', 'dismiss-token', 'download-config']) assert(await page.locator('#' + id).isDisabled(), id);
}
async function addCredential(page, custom = false) {
  await ready(page); await view(page, 'credentials'); await page.locator('#credential-name').fill('Shared provider key');
  if (custom) { await page.locator('#credential-auth-type').selectOption('header'); await page.locator('#credential-header-name').fill('X-API-Key'); }
  await page.locator('#credential-secret').fill(SECRET); await page.locator('#credential-save').click();
}
async function addApplication(page, lifetime = '3600') {
  await ready(page); await view(page, 'applications'); await page.locator('#application-name').fill('Reporting application');
  await page.locator('#application-token-ttl').selectOption(lifetime); await page.locator('#application-create').click();
}
const card = (page, id = IDS.application) => page.locator(`#applications-list [data-resource-id="${id}"]`);
async function heldToken(page, value = token(IDS.application)) {
  await page.locator('#one-time-access').waitFor({state: 'visible'}); assert.equal(await page.locator('#client-token').inputValue(), value);
}
async function settled(page) { await page.waitForFunction(() => !document.querySelector('#application-fields').disabled); }
async function saveRule(page, name = 'Read status') {
  await view(page, 'access-rules'); await openRestrictions(page, 'rule'); await page.locator('#rule-name').fill(name);
  await page.locator('#rule-path').fill('/v1/status'); await page.locator('#rule-response-fields').fill('id\nstatus');
  await page.locator('#rule-save').click(); await ready(page);
}

const tests = [
  ['overview guided-entry labels track credential, application and access progress before client setup', browser => fixture(browser, {}, async (page, state) => {
    await ready(page); await view(page, 'overview');
    assert.equal(await page.locator('#overview-next-action').getAttribute('href'), '#connect');
    assert.equal(await page.locator('#overview-next-action').innerText(), 'Connect your first app');
    await addCredential(page); await ready(page); await view(page, 'overview');
    assert.equal(await page.locator('#overview-next-action').getAttribute('href'), '#connect');
    assert.equal(await page.locator('#overview-next-action').innerText(), 'Connect an app with a saved account or key');
    await addApplication(page); await heldToken(page); await settled(page); await view(page, 'overview');
    assert.equal(await page.locator('#overview-next-action').getAttribute('href'), '#connect');
    assert.equal(await page.locator('#overview-next-action').innerText(), 'Choose permitted access for your app');
    await saveRule(page); await view(page, 'overview');
    assert.equal(await page.locator('#overview-next-action').getAttribute('href'), '#proxy');
    assert.equal(await page.locator('#overview-next-action').innerText(), 'Configure your app and send a scoped test request');
    await view(page, 'proxy'); assert(!(await page.locator('#copy-command').isDisabled()));
    assert(!(await page.locator('#download-config').isDisabled()));
    await view(page, 'applications'); await heldToken(page);
    assert.deepEqual(state.posts.map(item => item.name), ['credentials', 'applications', 'access-rules']);
  })],
  ['credential form stores a bearer key without an endpoint, rule, response schema or application', browser => fixture(browser, {}, async (page, state) => {
    await addCredential(page); await ready(page);
    assert.deepEqual(state.posts, [{name: 'credentials', body: {name: 'Shared provider key', auth_type: 'bearer', header_name: 'Authorization', secret: SECRET,
      expected_revision: 1, expected_policy_hash: digest(1)}}]);
    assert.equal(await page.locator('#credential-secret').inputValue(), ''); assert(!await page.locator('#credential-form input[type="url"]').count());
    assert.equal(await page.locator('#credential-form textarea').count(), 0); assert.equal(state.applications.length, 0); assert.equal(state.rules.length, 0);
    assert.equal(state.active, digest(1)); assert(!(await page.locator('body').innerText()).includes(SECRET));
    assert(await page.locator('#credential-google-connect').isDisabled()); await noToken(page);
  })],
  ['custom-header credential has only independent credential fields', browser => fixture(browser, {}, async (page, state) => {
    await addCredential(page, true); await ready(page); assert.equal(state.posts.length, 1);
    assert.equal(state.posts[0].body.auth_type, 'header'); assert.equal(state.posts[0].body.header_name, 'X-API-Key');
    assert.equal(state.rules.length, 0); assert.equal(state.applications.length, 0);
  })],
  ['application creation chooses expiry and discloses its token once without granting a rule', browser => fixture(browser, {}, async (page, state) => {
    await addApplication(page, '604800'); await heldToken(page); await settled(page);
    assert.deepEqual(state.posts[0], {name: 'applications', body: {name: 'Reporting application', token_lifetime_seconds: 604800,
      expected_revision: 1, expected_policy_hash: digest(1)}});
    assert.equal(state.applications[0].token_expires_at_epoch_ms, NOW + 604800000); assert.equal(state.rules.length, 0);
    assert.equal(await page.locator('#client-token').getAttribute('type'), 'password');
    await page.locator('#copy-token').click();
    await page.waitForFunction(() => document.querySelector('#token-status').textContent.startsWith('Copied.'));
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), token(IDS.application));
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
    await page.reload({waitUntil: 'networkidle'}); await ready(page); await noToken(page);
  })],
  ['two access rules reference one saved credential without resubmitting it', browser => fixture(browser, {credentials: [credential()],
    applications: [application(), application({id: IDS.other, name: 'Second application'})]}, async (page, state) => {
    await ready(page); await view(page, 'access-rules');
    assert.deepEqual(await page.locator('input[name="rule-method"]').evaluateAll(items => items.map(item => item.value)), METHODS);
    for (const [id, name] of [[IDS.application, 'First access'], [IDS.other, 'Second access']]) {
      await openRestrictions(page, 'rule');
      await page.locator('#rule-name').fill(name); await page.locator('#rule-application-id').selectOption(id);
      await page.locator('#rule-credential-id').selectOption(IDS.credential); await page.locator('#rule-path').fill('/v1/status');
      await page.locator('#rule-response-fields').fill('id\nstatus'); await page.locator('#rule-save').click(); await ready(page);
    }
    assert.equal(state.credentials.length, 1); assert.equal(state.rules.length, 2);
    assert.deepEqual(state.posts.map(item => item.body.credential_id), [IDS.credential, IDS.credential]);
    assert.deepEqual(state.posts.map(item => item.body.application_id), [IDS.application, IDS.other]);
    assert(!JSON.stringify(state.posts).includes(SECRET)); assert(state.posts.every(item => !Object.hasOwn(item.body, 'secret')));
    await view(page, 'credentials'); assert(await page.locator('[data-action="revoke-credential"]').isDisabled());
  })],
  ['rotation replaces held token with an explicitly expiring new generation', browser => fixture(browser, {}, async (page, state) => {
    await addApplication(page); await heldToken(page); await settled(page);
    await card(page).locator('.application-rotate-ttl').selectOption('86400');
    await card(page).locator('[data-action="rotate-application"]').click(); await heldToken(page, token(IDS.application, 2)); await settled(page);
    assert.deepEqual(state.posts[1], {name: 'applications/rotate-token', body: {id: IDS.application, token_lifetime_seconds: 86400,
      expected_revision: 2, expected_policy_hash: digest(1)}});
    assert.equal(state.applications[0].token_expires_at_epoch_ms, NOW + 86400000);
    assert(!await page.locator('body').innerText().then(value => value.includes(token(IDS.application))));
  })],
  ['revoking one application clears its token and retains its shared credential and other application', browser => fixture(browser, {
    credentials: [credential()]}, async (page, state) => {
    await addApplication(page); await heldToken(page); await settled(page);
    state.applications.push(application({id: IDS.other, name: 'Other application'}));
    state.rules.push(rule(), rule({id: '55555555-5555-4555-8555-555555555555', application_id: IDS.other}));
    await page.locator('#applications-refresh').click(); await settled(page);
    await card(page).locator('[data-action="revoke-application"]').click(); await noToken(page); await settled(page);
    assert.equal(state.credentials[0].status, 'active'); assert.equal(state.applications.find(item => item.id === IDS.other).status, 'active');
    assert.equal(state.rules.find(item => item.application_id === IDS.other).status, 'active');
    assert.equal(state.posts.at(-1).name, 'applications/revoke'); assert.equal(state.posts.at(-1).body.id, IDS.application);
  })],
  ...['rotate-application', 'revoke-application'].map(action => ['cross-tab ' + action + ' invalidates an already held token', browser => fixture(browser, {}, async (page, state, {openPage}) => {
    await addApplication(page); await heldToken(page); await settled(page);
    const other = await openPage(); await view(other, 'applications');
    await card(other).locator('[data-action="' + action + '"]').click(); await noToken(page); await settled(other);
    assert.equal(await page.locator('#client-token').inputValue(), '');
    assert.equal(state.posts.length, 2); assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
  })]),
  ['persisted page lifecycle clears old material and allows explicit rotation after restoration', browser => fixture(browser, {}, async (page, state) => {
    await addApplication(page); await heldToken(page); await settled(page);
    await page.evaluate(() => {
      dispatchEvent(new PageTransitionEvent('pagehide', {persisted: true}));
      dispatchEvent(new PageTransitionEvent('pageshow', {persisted: true}));
    });
    await noToken(page); await settled(page);
    await card(page).locator('[data-action="rotate-application"]').click();
    await heldToken(page, token(IDS.application, 2)); await settled(page); assert.equal(state.posts.length, 2);
  })],
  ...['409', '422', '503', 'lost-after-commit'].map(fault => ['uncertain ' + fault + ' mutation blocks all writes until explicit state review', browser => fixture(browser, {fault}, async (page, state) => {
    await addCredential(page); await page.locator('#mutation-review').waitFor({state: 'visible'});
    await page.waitForFunction(() => !document.querySelector('#mutation-review-confirm').disabled);
    assert.equal(state.posts.length, 1); assert.equal(await page.locator('#credential-secret').inputValue(), '');
    for (const id of ['credential-fields', 'application-fields', 'access-rule-fields']) assert(await page.locator('#' + id).evaluate(node => node.disabled), id + ' remains disabled');
    assert(!(await page.locator('body').innerText()).includes(SECRET));
    await page.clock.runFor(10000); assert.equal(state.posts.length, 1, 'no automatic mutation replay');
    await page.locator('#mutation-review-confirm').click(); await ready(page); assert.equal(state.posts.length, 1);
    if (fault === 'lost-after-commit') assert.equal(state.credentials.length, 1, 'uncertain commit is reconciled without duplication');
  })]),
  ['uncertain rotation clears the old token and does not retry', browser => fixture(browser, {}, async (page, state) => {
    await addApplication(page); await heldToken(page); await settled(page); state.fault = 'lost-after-commit';
    await card(page).locator('[data-action="rotate-application"]').click(); await noToken(page);
    await page.locator('#mutation-review').waitFor({state: 'visible'}); await page.clock.runFor(10000);
    assert.equal(state.posts.length, 2); assert.equal(state.applications[0].token_generation, 2);
  })],
  ['session loss and newer catalog generations clear held client material', browser => fixture(browser, {}, async (page, state) => {
    await addApplication(page); await heldToken(page); await settled(page);
    state.applications[0].token_generation++; await page.locator('#applications-refresh').click(); await noToken(page);
    await settled(page); await card(page).locator('[data-action="rotate-application"]').click(); await heldToken(page, token(IDS.application, 3)); await settled(page);
    state.catalogStatus = 401; await page.locator('#applications-refresh').click(); await page.locator('#load-error').waitFor({state: 'visible'}); await noToken(page);
    assert(await page.locator('#credential-fields').evaluate(node => node.disabled));
    assert.equal(await page.locator('#applications-list [data-action]:enabled').count(), 0, 'unavailable catalog has no visually enabled application mutation');
  })],
  ['token expiry invalidates an open-page token without renewal', browser => fixture(browser, {}, async (page, state) => {
    await addApplication(page); await heldToken(page); await settled(page);
    await page.clock.runFor(3600001); await noToken(page); assert.equal(state.posts.length, 1);
  })],
  ['proxy setup respects loaded policy, CA link and placeholder-only command', browser => fixture(browser, {
    credentials: [credential()], applications: [application()], rules: [rule()], pending: true}, async (page, state) => {
    await ready(page); await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled());
    assert.equal(await page.locator('#ca-download').getAttribute('href'), '/ca.pem');
    assert.equal(await page.locator('#ca-download').getAttribute('download'), 'serverware-ca.pem');
    state.loaded = state.active; await page.locator('#proxy-refresh').click();
    await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
    const command = await page.locator('#client-command').innerText();
    assert(command.includes('--proxy') && command.includes('--cacert') && command.includes('$SERVERWARE_PROXY_TOKEN') && command.includes('/v1/status'));
    assert(!command.includes('--insecure') && !command.includes(SECRET)); assert(await page.locator('#download-config').isDisabled());
    await page.locator('#copy-command').click();
    await page.waitForFunction(() => document.querySelector('#client-copy-status').textContent.startsWith('Copied.'));
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), command);
    assert(!state.requests.some(item => item.path === '/ca.pem'), 'native HTTP CA download is deliberately not invoked');
  })],
  ['all six workspaces, audit filter and mobile controls are rendered and usable', browser => fixture(browser, {
    credentials: [credential()], applications: [application()], rules: [rule()]}, async (page, state) => {
    await ready(page);
    const artifactRoot = '/srv/catchplate-fast/projects/serverware-operator-artifacts';
    assert((await stat(artifactRoot)).isDirectory());
    artifactDirectory = await mkdtemp(join(artifactRoot, 'catalog-browser-synthetic-'));
    for (const size of [{width: 1280, height: 960}, {width: 390, height: 844}]) {
      await page.setViewportSize(size);
      for (const name of VIEWS) {
        await view(page, name);
        if (name === 'audit') await page.waitForFunction(() => document.querySelectorAll('#audit-list .event-card').length === 1);
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), name + ' horizontal overflow');
        const screenshot = join(artifactDirectory, `${size.width === 390 ? 'mobile' : 'desktop'}-${name}-synthetic.png`);
        await page.screenshot({path: screenshot, fullPage: true}); assert((await stat(screenshot)).size > 0);
      }
    }
    await page.waitForFunction(() => document.querySelectorAll('#audit-list .event-card').length === 1);
    await page.locator('#audit-filter').selectOption('data_plane.response.released');
    await page.waitForFunction(() => document.querySelector('#audit-list').textContent.includes('data_plane.response.released'));
    await page.locator('#audit-verify').click(); await page.waitForFunction(() => document.querySelector('#audit-verification').textContent.includes('consistent'));
    await view(page, 'applications'); assert(await card(page).locator('[data-action="rotate-application"]').isVisible());
    assert(await card(page).locator('[data-action="revoke-application"]').isVisible());
    assert.equal(state.posts.length, 0);
  })],
  ['incorrect runtime catalog disables mutation and client actions', browser => fixture(browser, {invalidCatalog: true}, async page => {
    await page.locator('#load-error').waitFor({state: 'visible'}); assert(await page.locator('#credential-fields').evaluate(node => node.disabled));
    assert(await page.locator('#application-fields').evaluate(node => node.disabled)); await noToken(page);
  })],
  ['explicit rule then credential revocation retains the separate application', browser => fixture(browser, {
    credentials: [credential()], applications: [application()], rules: [rule()]}, async (page, state) => {
    await ready(page); await view(page, 'access-rules');
    state.cancelNextDialog = true; await page.locator('[data-action="revoke-rule"]').click(); assert.equal(state.posts.length, 0);
    await page.locator('[data-action="revoke-rule"]').click(); await ready(page);
    assert.equal(state.rules[0].status, 'revoked'); assert.equal(state.credentials[0].status, 'active'); assert.equal(state.applications[0].status, 'active');
    await view(page, 'credentials'); await page.locator('[data-action="revoke-credential"]').click(); await ready(page);
    assert.equal(state.credentials[0].status, 'revoked'); assert.equal(state.applications[0].status, 'active');
    assert.deepEqual(state.posts.map(item => item.name), ['access-rules/revoke', 'credentials/revoke']);
  })],
];

async function main() {
  const args = process.argv.slice(2);
  const pureResult = generatorChecks();
  if (args.length === 1 && args[0] === '--self-test') { console.log(JSON.stringify(pureResult)); return; }
  const from = args.length === 0 ? 1 : args.length === 2 && args[0] === '--from-group' ? Number(args[1]) : NaN;
  assert(Number.isSafeInteger(from) && from >= 1 && from <= tests.length, 'usage: test_operator_catalog_browser.cjs [--self-test | --from-group N]');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of tests.slice(from - 1)) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: tests.length - from + 1, totalGroups: tests.length, firstGroup: from, scope: 'intercepted synthetic catalog browser fixtures only',
        liveRequests: 0, nativeCaDownloadExecuted: false, productionAcceptance: false, screenshotDirectory: artifactDirectory}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('catalog browser fixture deadline')), 150000); })]);
  } finally { clearTimeout(deadline); await browser.close(); }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });
module.exports = {main, fixture, ready, view, openRestrictions, saveRule, credential, application, rule, IDS, NOW, UPSTREAM};

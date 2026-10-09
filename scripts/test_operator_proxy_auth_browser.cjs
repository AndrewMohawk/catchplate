#!/usr/bin/env node
// Intercepted UI contract fixtures only. No proxy handshake, provider, live API,
// TLS trust or generated command is exercised. Backend/Rust acceptance is separate.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {execFileSync} = require('node:child_process');
const {readFileSync} = require('node:fs');
const {readFile, mkdtemp, stat} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {runInNewContext} = require('node:vm');
const {fixture: baseFixture, ready, view, credential, application, rule, IDS, NOW, UPSTREAM} = require('./test_operator_catalog_browser.cjs');
const {publicCatalog} = require('./test_operator_ordinary_modes_browser.cjs');

const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const CATALOG = ORIGIN + '/api/operator-demo/catalog';
const CREATE = '/api/operator-demo/applications';
const CHANGE = CREATE + '/proxy-authentication';
const BASIC = 'basic_and_bearer_v1';
const CAPABILITY = {schema: 'serverware.operatorProxyAuthentication/v1', modes: ['bearer', BASIC], path: CHANGE};
const PRIVATE = 'synthetic-provider-private-NEVER-RENDER';
const RAW_ERROR = 'synthetic-private-backend-error-NEVER-RENDER';
const DUMMY = "Bearer DUMMY-'literal'-$value";
const SECOND_RULE = '55555555-5555-4555-8555-555555555555';
const FORMER_RULE = '66666666-6666-4666-8666-666666666666';
const OTHER_RULE = '77777777-7777-4777-8777-777777777777';
const clone = value => JSON.parse(JSON.stringify(value));
const digest = value => 'sha256:' + value.toString(16).padStart(64, '0');
const token = id => 'synthetic_application_' + id.replaceAll('-', '') + '_generation_1';
const app = (changes = {}) => application({version: 1, ...changes});
const supplied = (changes = {}) => ({credentials: [credential({secret: PRIVATE})], applications: [app()],
  rules: [rule()], credentialInputModes: ['insert', 'replace_exact'], ...changes});
const card = (page, id = IDS.application) => page.locator('#applications-list [data-resource-id="' + id + '"]');
const action = (page, id = IDS.application) => card(page, id).locator('[data-action="change-proxy-authentication"]');
const INPUTS = ['scripts/test_operator_proxy_auth_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
  'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py',
  ...['index.html', 'style.css', 'app.js', 'workspace_core.js', 'workspace_resources.js', 'workspace_applications.js',
    'workspace_proxy_audit.js', 'workspace_connect.js', 'workspace_google.js'].map(name => 'serverware/operator_demo_web/' + name)];
let artifacts;
let contexts = 0;
async function hashes() { return Object.fromEntries(await Promise.all(INPUTS.map(async name =>
  [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')]))); }
async function screenshot(page, name) {
  await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true, mask: [page.locator('#client-token')]});
}
async function privateAbsent(page) {
  const surfaces = await page.evaluate(() => ({html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].filter(node => node.id !== 'client-token').map(node => node.value),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage),
    command: document.querySelector('#client-command').textContent}));
  const serialized = JSON.stringify(surfaces);
  for (const value of [PRIVATE, RAW_ERROR, token(IDS.application), token(IDS.other)])
    assert(!serialized.includes(value), 'provider material, application token and raw errors stay out of public surfaces/storage');
}
function catalog(state) {
  const value = publicCatalog(state);
  if (state.proxyCapability !== undefined) value.capabilities.application_proxy_authentication = state.proxyCapability;
  if (state.applicationOverride) value.applications = value.applications.map(item => item.id === state.applicationOverride.id ? clone(state.applicationOverride) : item);
  return value;
}
function exactCAS(state, body) {
  assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
}
function createApplication(state, body) {
  const fields = ['expected_policy_hash', 'expected_revision', 'name', 'token_lifetime_seconds'];
  if (Object.hasOwn(body, 'proxy_authentication')) fields.push('proxy_authentication');
  assert.deepEqual(Object.keys(body).sort(), fields.sort()); exactCAS(state, body);
  assert(typeof body.name === 'string' && body.name.length >= 1 && body.name.length <= 128 && body.name === body.name.trim());
  assert(Number.isSafeInteger(body.token_lifetime_seconds) && body.token_lifetime_seconds >= 3600 && body.token_lifetime_seconds <= 7776000);
  if (Object.hasOwn(body, 'proxy_authentication')) assert(['bearer', BASIC].includes(body.proxy_authentication));
  const id = state.applications.length ? IDS.other : IDS.application;
  assert(!state.applications.some(item => item.id === id));
  const selected = app({id, name: body.name, token_expires_at_epoch_ms: NOW + body.token_lifetime_seconds * 1000,
    proxy_authentication: body.proxy_authentication || 'bearer'});
  state.applications.push(selected); state.revision++;
  return {application: catalog(state).applications.find(item => item.id === id), revision: state.revision,
    policy: catalog(state).policy, client_token: token(id)};
}
function changeApplication(state, body) {
  assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'id', 'proxy_authentication']);
  exactCAS(state, body); assert(['bearer', BASIC].includes(body.proxy_authentication));
  const selected = state.applications.find(item => item.id === body.id);
  assert(selected?.status === 'active'); assert.notEqual(selected.proxy_authentication || 'bearer', body.proxy_authentication);
  const rules = state.rules.filter(item => item.application_id === selected.id && item.status === 'active');
  selected.proxy_authentication = body.proxy_authentication; selected.version++; state.revision++;
  if (rules.length) { state.active = digest(++state.sequence); if (state.autoLoad) state.loaded = state.active; }
  return {application: catalog(state).applications.find(item => item.id === selected.id), revision: state.revision,
    policy: catalog(state).policy, ...(rules.length ? {affected_rule_ids: rules.map(item => item.id)} : {})};
}
async function fixture(browser, options, exercise) {
  contexts++;
  return baseFixture(browser, supplied(options), async (page, state, controls) => {
    state.proxyCapability = Object.hasOwn(options, 'capability') ? options.capability : clone(CAPABILITY);
    state.authPosts = []; state.creates = []; let reads = 0; let signal; let release;
    const arrival = new Promise(resolve => { signal = resolve; });
    const responseGate = options.deferResponse ? new Promise(resolve => { release = resolve; }) : Promise.resolve();
    const answer = (route, value, status = 200) => route.fulfill({status, contentType: 'application/json', body: JSON.stringify(value)});
    await controls.context.route(CATALOG, async route => {
      const request = route.request();
      if (++reads > 30 || request.url() !== CATALOG || request.method() !== 'GET' || request.postDataBuffer()?.length) {
        state.unexpected.push('proxy-auth catalog boundary refused'); await route.abort(); return;
      }
      state.catalogCalls++;
      if (state.catalogStatus !== 200) {
        state.expectedFailures.add('/api/operator-demo/catalog'); await answer(route, {detail: RAW_ERROR}, state.catalogStatus); return;
      }
      await answer(route, catalog(state));
    });
    for (const path of [CREATE, CHANGE]) await controls.context.route(ORIGIN + path, async route => {
      const request = route.request(); const bytes = request.postDataBuffer();
      try {
        assert.equal(request.url(), ORIGIN + path); assert.equal(request.method(), 'POST');
        assert(bytes && bytes.length <= 2048); assert(request.headers()['content-type']?.startsWith('application/json'));
        const body = JSON.parse(bytes.toString());
        if (path === CREATE) {
          assert.equal(state.creates.length, 0, 'one explicit application creation maximum');
          state.creates.push(clone(body)); await answer(route, createApplication(state, body), 201); return;
        }
        assert.equal(state.authPosts.length, 0, 'never retry the mode mutation');
        // Validate the exact public DTO/CAS even when an injected fault prevents commit.
        assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'id', 'proxy_authentication']);
        exactCAS(state, body); assert(['bearer', BASIC].includes(body.proxy_authentication));
        assert(state.applications.some(item => item.id === body.id && item.status === 'active'));
        state.authPosts.push(clone(body)); signal(); await responseGate;
        const before = catalog(state).applications.find(item => item.id === body.id);
        if (options.fault === '409') { state.expectedFailures.add(CHANGE); await answer(route, {detail: RAW_ERROR}, 409); return; }
        if (options.fault === 'lost-before-commit') { state.expectedFailures.add(CHANGE); await route.abort('failed'); return; }
        const result = changeApplication(state, body);
        if (options.fault === 'lost-after-commit') { state.expectedFailures.add(CHANGE); await route.abort('failed'); return; }
        if (options.fault === 'stale-catalog') state.applicationOverride = before;
        if (options.fault === 'catalog-failure') state.catalogStatus = 503;
        if (options.fault === 'malformed-receipt') result.application.token_generation++;
        await answer(route, result);
      } catch (_) { state.errors.push('proxy-auth fixture DTO/CAS boundary failed'); signal(); await route.abort(); }
    });
    try {
      await page.reload({waitUntil: 'networkidle'});
      if (!options.invalidApplication) await ready(page);
      await exercise(page, state, {arrival, release: () => release?.()});
      assert.deepEqual(state.posts, [], 'no accidental key/rule creation, revoke, rotation or unrelated write');
      assert(state.authPosts.length <= 1 && state.creates.length <= 1); assert(reads >= 1); await privateAbsent(page);
    } finally { release?.(); }
  });
}
async function refresh(page) {
  await page.evaluate(() => {
    window.__proxyAuthRendered = false;
    const observer = new MutationObserver(() => { window.__proxyAuthRendered = true; observer.disconnect(); });
    observer.observe(document.querySelector('#applications-list'), {childList: true});
  });
  const response = page.waitForResponse(value => value.url() === CATALOG && value.request().method() === 'GET');
  await page.locator('#applications-refresh').click(); await (await response).finished();
  await page.waitForFunction(() => window.__proxyAuthRendered === true);
  await page.evaluate(() => { delete window.__proxyAuthRendered; });
}
async function create(page, guided = false) {
  if (guided) {
    await view(page, 'connect'); await page.locator('#connect-use-saved').click();
    await page.locator('#connect-credential-choice').selectOption(IDS.credential);
    await page.locator('#connect-credential-next').click(); await page.locator('#connect-application-step').waitFor({state: 'visible'});
    await page.locator('#connect-application-choice').selectOption('new');
    await page.locator('#connect-application-name').fill('Standard client'); await page.locator('#connect-token-ttl').selectOption('3600');
    await page.locator('#connect-application-next').click(); await page.locator('#connect-access-step').waitFor({state: 'visible'});
  } else {
    await view(page, 'applications'); await page.locator('#application-name').fill('Standard client');
    await page.locator('#application-token-ttl').selectOption('3600'); await page.locator('#application-create').click();
  }
  await page.locator('#one-time-access').waitFor({state: 'visible'});
  await page.waitForFunction(() => !document.querySelector('#application-fields').disabled);
}
async function settledChange(page) {
  await page.waitForFunction(() => !document.querySelector('#application-fields').disabled &&
    !document.querySelector('#application-action-status').textContent.startsWith('Saving'));
}
async function uncertain(page, freshRequired = false) {
  await page.locator('#mutation-review').waitFor({state: 'visible'});
  if (freshRequired) assert(await page.locator('#mutation-review-confirm').isDisabled());
  else await page.waitForFunction(() => !document.querySelector('#mutation-review-confirm').disabled);
  assert.match(await page.locator('#mutation-review-text').innerText(), /no automatic retry/i);
  for (const id of ['application-create', 'credential-save', 'rule-save']) assert(await page.locator('#' + id).isDisabled());
  assert(await action(page).isDisabled()); await privateAbsent(page);
}
const argsFor = command => JSON.parse(execFileSync('python3', ['-B', '-c',
  'import json, shlex, sys; print(json.dumps(shlex.split(sys.stdin.read())))'],
{input: command.replace(/\\\r?\n/g, ''), encoding: 'utf8', timeout: 5000, maxBuffer: 65536}));
const values = (args, flag) => args.flatMap((value, index) => value === flag ? [args[index + 1]] : []);
function checkCommand(command, basic, id = IDS.application) {
  const args = argsFor(command);
  assert.equal(args.includes('--proxy-basic'), basic);
  assert.deepEqual(values(args, '--proxy-user'), basic ? [id + ':$SERVERWARE_PROXY_TOKEN'] : []);
  assert.deepEqual(values(args, '--proxy-header'), basic ? [] : ['Proxy-Authorization: Bearer $SERVERWARE_PROXY_TOKEN']);
  assert(!values(args, '--header').some(value => /^proxy-authorization:/i.test(value)));
  assert(!args.includes('--insecure') && !args.includes('--proxy-insecure'));
  for (const value of [PRIVATE, token(id)]) assert(!command.includes(value));
  assert(!/https:\/\/[^\s]*@/.test(command), 'no token-bearing URL'); return args;
}
function projectionChecks() {
  const source = readFileSync(join(ROOT, 'serverware/operator_demo_web/workspace_core.js'), 'utf8');
  const {buildCurlCommand, clientCredentialInput, credentialHeaderTarget} = require('../serverware/operator_demo_web/app.js');
  const project = (capability, application = app()) => {
    const state = {...supplied({applications: [application]}), revision: 1, sequence: 1, active: digest(1), loaded: digest(1),
      responseModes: ['projected_json'], proxyCapability: capability};
    return clone(runInNewContext(source + '\nprojectCatalog(input)', {input: catalog(state), clientCredentialInput, credentialHeaderTarget}, {timeout: 1000}));
  };
  assert.deepEqual(project(CAPABILITY).capabilities.application_proxy_authentication, CAPABILITY);
  for (const capability of [undefined, null, {}, {...CAPABILITY, schema: 'future'}, {...CAPABILITY, path: CREATE},
    {...CAPABILITY, modes: [BASIC]}, {...CAPABILITY, modes: ['bearer', BASIC, 'future']}, {...CAPABILITY, extra: true}]) {
    const result = project(capability); assert.equal(result.capabilities.application_proxy_authentication, null);
    assert.equal(result.applications[0].id, IDS.application);
  }
  assert.equal(project(CAPABILITY, app({proxy_authentication: BASIC})).applications[0].proxy_authentication, BASIC);
  for (const mode of [null, '', 'future', 0, []]) {
    const result = project(CAPABILITY, app({proxy_authentication: mode}));
    assert.equal(result.applications[0].proxy_authentication, null, 'invalid explicit mode is never downgraded to legacy Bearer');
    assert.equal(runInNewContext(source + '\napplicationProxyAuthenticationSupported(input, input.applications[0])',
      {input: result}, {timeout: 1000}), false, 'only this application login is refused; the catalog stays readable');
  }
  const base = {proxyUrl: 'https://proxy.example.test', upstreamUrl: UPSTREAM + '/v1/status', method: 'GET', caPath: "./ca's $(literal).pem"};
  checkCommand(buildCurlCommand(base), false);
  const basic = buildCurlCommand({...base, proxyAuthentication: BASIC, applicationId: IDS.application,
    credentialInput: 'replace_exact', placeholder: DUMMY, credential: credential(), clientToken: token(IDS.application), providerSecret: PRIVATE});
  const args = checkCommand(basic, true); assert(values(args, '--header').includes('Authorization: ' + DUMMY));
  assert(values(args, '--cacert').includes(base.caPath));
  for (const applicationId of [undefined, '', 'not-a-uuid', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', IDS.application + ':password', '$(command)'])
    assert.throws(() => buildCurlCommand({...base, proxyAuthentication: BASIC, applicationId}));
  for (const proxyAuthentication of [null, '', 'basic', 'future']) assert.throws(() => buildCurlCommand({...base, proxyAuthentication, applicationId: IDS.application}));
  return {ok: true, groups: 1, scope: 'real public projection and pure command generation only; no shell command/proxy execution'};
}

const tests = [
  ['valid advertised capability opts new direct and guided applications into standard login without granting access', async browser => {
    for (const guided of [false, true]) await fixture(browser, {applications: [], rules: []}, async (page, state) => {
      await create(page, guided);
      assert.deepEqual(state.creates, [{name: 'Standard client', token_lifetime_seconds: 3600, proxy_authentication: BASIC,
        expected_revision: 1, expected_policy_hash: digest(1)}]);
      assert.equal(state.authPosts.length, 0); assert.equal(state.rules.length, 0); assert.equal(state.sequence, 1);
      assert.equal(await page.locator('#client-token').inputValue(), token(IDS.application));
      assert.equal(state.applications[0].token_expires_at_epoch_ms, NOW + 3600000);
    });
  }],
  ['missing and malformed advertised capabilities retain legacy create bodies and never expose upgrade actions', async browser => {
    for (const capability of [undefined, {...CAPABILITY, path: CREATE}]) await fixture(browser, {capability, applications: [], rules: []}, async (page, state) => {
      await create(page); assert(!Object.hasOwn(state.creates[0], 'proxy_authentication'));
      assert.equal(state.applications[0].proxy_authentication, 'bearer'); assert.equal(await action(page).count(), 0);
      assert(!await page.locator('#load-error').isVisible()); assert.equal(state.authPosts.length, 0);
    });
  }],
  ['explicit existing-application review identifies exact affected rules and cancel preserves unsaved input', browser => fixture(browser,
    {applications: [app(), app({id: IDS.other, name: 'Unrelated worker'})], rules: [rule(), rule({id: SECOND_RULE, name: 'Read metrics'}),
      rule({id: FORMER_RULE, name: 'Former permission', status: 'revoked'}), rule({id: OTHER_RULE, application_id: IDS.other, name: 'Other permission'})]},
    async (page, state) => {
      await view(page, 'applications'); await page.locator('#application-name').fill('Unsubmitted application draft');
      await page.locator('#application-token-ttl').selectOption('604800'); const before = JSON.stringify(catalog(state));
      state.cancelNextDialog = true; await action(page).click();
      assert.equal(state.dialogs.length, 1); const review = state.dialogs[0];
      assert(review.includes(IDS.application)); assert(review.includes('Reporting application'));
      assert(review.includes('Read status') && review.includes('Read metrics')); assert.match(review, /Affected active access rules \(2\):/);
      assert(!review.includes('Former permission') && !review.includes('Other permission') && !review.includes(IDS.other));
      assert.match(review, /token.*expir.*unchanged|unchanged.*token.*expir/is); assert.match(review, /policy|loads|activation/i);
      assert.equal(state.authPosts.length, 0); assert.equal(JSON.stringify(catalog(state)), before);
      assert.equal(await page.locator('#application-name').inputValue(), 'Unsubmitted application draft');
      assert.equal(await page.locator('#application-token-ttl').inputValue(), '604800');
    })],
  ['assigned app mode change preserves identity token and rules and waits for matching loaded policy', browser => fixture(browser,
    {autoLoad: false}, async (page, state) => {
      await view(page, 'applications'); const original = clone(state.applications[0]); const rules = clone(state.rules);
      await action(page).click(); await settledChange(page);
      assert.deepEqual(state.authPosts, [{id: IDS.application, proxy_authentication: BASIC, expected_revision: 1, expected_policy_hash: digest(1)}]);
      assert.deepEqual(state.applications[0], {...original, version: 2, proxy_authentication: BASIC}); assert.deepEqual(state.rules, rules);
      assert.equal(state.sequence, 2); assert.equal(state.loaded, digest(1));
      await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
      assert.match(await page.locator('#client-proxy-login-status').innerText(), /pending|wait|not.*confirmed/i);
      state.loaded = state.active; await view(page, 'applications'); await refresh(page); await view(page, 'proxy');
      await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
      checkCommand(await page.locator('#client-command').innerText(), true); assert.equal(state.authPosts.length, 1);
    })],
  ['disabling standard login is an explicit scoped mutation and preserves the existing one-time token and expiry', browser => fixture(browser,
    {applications: [], rules: []}, async (page, state) => {
      await create(page); const held = await page.locator('#client-token').inputValue(); const original = clone(state.applications[0]);
      const policy = clone(catalog(state).policy); await action(page).click(); await settledChange(page);
      assert.deepEqual(state.authPosts, [{id: IDS.application, proxy_authentication: 'bearer', expected_revision: 2, expected_policy_hash: digest(1)}]);
      assert.deepEqual(state.applications[0], {...original, version: 2, proxy_authentication: 'bearer'});
      assert.deepEqual(catalog(state).policy, policy); assert.equal(await page.locator('#client-token').inputValue(), held);
      assert.equal(state.rules.length, 0); assert.equal(state.creates.length, 1);
    })],
  ['capability withdrawal preserves saved modes but refuses upgrade and unconfirmed standard client actions', browser => fixture(browser,
    {applications: [app({proxy_authentication: BASIC})]}, async (page, state) => {
      await view(page, 'proxy'); checkCommand(await page.locator('#client-command').innerText(), true);
      state.proxyCapability = undefined; await view(page, 'applications'); await refresh(page);
      assert.equal(await action(page).count(), 0); assert.equal(state.applications[0].proxy_authentication, BASIC);
      await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
      assert(!await page.locator('#load-error').isVisible()); assert.equal(state.authPosts.length, 0);
    })],
  ['revoked apps and malformed explicit mode never expose usable standard client configuration', async browser => {
    await fixture(browser, {applications: [app({status: 'revoked', token_status: 'revoked', proxy_authentication: BASIC})],
      rules: [rule({status: 'revoked'})]}, async (page, state) => {
      await view(page, 'applications'); assert.equal(await action(page).count(), 0); await view(page, 'proxy');
      assert(await page.locator('#copy-command').isDisabled()); assert.equal(state.authPosts.length, 0);
    });
    await fixture(browser, {applications: [app({proxy_authentication: null})]}, async (page, state) => {
      await view(page, 'applications'); assert(!await page.locator('#load-error').isVisible());
      assert(!await page.locator('#application-create').isDisabled()); assert.equal(await action(page).count(), 0);
      await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled());
      assert(await page.locator('#download-config').isDisabled()); assert(await page.locator('#client-proxy-login').isHidden());
      assert.match(await page.locator('#client-command').innerText(), /unavailable or unsupported/i);
      assert.equal(state.authPosts.length, 0); assert.equal(state.creates.length, 0);
    });
  }],
  ['write in flight blocks repeated actions and only one explicit mode POST is sent', browser => fixture(browser,
    {deferResponse: true}, async (page, state, controls) => {
      await view(page, 'applications'); await action(page).click(); await controls.arrival;
      assert(await action(page).isDisabled()); assert(await page.locator('#application-create').isDisabled());
      await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled());
      await page.clock.runFor(4000); assert.equal(state.authPosts.length, 1);
      controls.release(); await view(page, 'applications'); await settledChange(page); assert.equal(state.authPosts.length, 1);
    })],
  ['conflict and lost mode responses require shared review and never rotate renew retry or assume rollback', async browser => {
    for (const fault of ['409', 'lost-before-commit', 'lost-after-commit']) await fixture(browser, {fault}, async (page, state) => {
      await view(page, 'applications'); const original = clone(state.applications[0]); await action(page).click(); await uncertain(page);
      assert.equal(state.authPosts.length, 1); assert.equal(state.applications[0].token_generation, original.token_generation);
      assert.equal(state.applications[0].token_expires_at_epoch_ms, original.token_expires_at_epoch_ms);
      await page.clock.runFor(6000); assert.equal(state.authPosts.length, 1);
      await page.locator('#mutation-review-confirm').click(); await page.locator('#mutation-review').waitFor({state: 'hidden'});
      assert(!await action(page).isDisabled()); assert.equal(state.authPosts.length, 1);
    });
  }],
  ['acknowledged but stale failed or malformed reconciliation requires fresh review without replay', async browser => {
    for (const fault of ['stale-catalog', 'catalog-failure', 'malformed-receipt']) await fixture(browser, {fault}, async (page, state) => {
      await view(page, 'applications'); await action(page).click(); await uncertain(page, fault !== 'malformed-receipt');
      assert.equal(state.authPosts.length, 1); assert.equal(state.applications[0].proxy_authentication, BASIC);
      const notice = await page.locator('#mutation-review-text').innerText();
      if (fault === 'malformed-receipt') assert.match(notice, /receipt could not be confirmed.*no token was renewed.*no automatic retry/is);
      else assert.match(notice, /do not assume rollback/i);
      await page.clock.runFor(6000); assert.equal(state.authPosts.length, 1);
      state.applicationOverride = null; state.catalogStatus = 200; await refresh(page);
      assert(await action(page).isDisabled()); assert(!await page.locator('#mutation-review-confirm').isDisabled());
      await page.locator('#mutation-review-confirm').click(); await page.locator('#mutation-review').waitFor({state: 'hidden'});
      assert(!await action(page).isDisabled()); assert.equal(state.authPosts.length, 1);
    });
  }],
  ['legacy Bearer commands remain unchanged and standard login uses only public app ID with an environment token reference', async browser => {
    for (const mode of [undefined, 'bearer', BASIC]) await fixture(browser,
      {applications: [app(mode === undefined ? {} : {proxy_authentication: mode})],
        rules: [rule({credential_input: 'replace_exact', placeholder: DUMMY})]}, async (page, state) => {
        await view(page, 'proxy'); await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
        const args = checkCommand(await page.locator('#client-command').innerText(), mode === BASIC);
        assert(values(args, '--header').includes('Authorization: ' + DUMMY));
        if (mode === BASIC) {
          assert.equal(await page.locator('#client-proxy-username').innerText(), IDS.application);
          assert.equal(await page.locator('#client-proxy-host').innerText(), 'proxy.example.test');
          assert.equal(await page.locator('#client-proxy-port').innerText(), '443');
          assert.match(await page.locator('#client-proxy-password-note').innerText(), /application.*token|client token/i);
          assert(!await page.locator('#client-proxy-login input').count());
        }
        assert.equal(state.authPosts.length, 0); assert.equal(state.creates.length, 0);
      });
  }],
  ['private Basic export uses the held application token without provider key or credential-bearing URL', browser => fixture(browser,
    {applications: [], rules: []}, async (page, state) => {
      await create(page); const held = await page.locator('#client-token').inputValue();
      // A fresh intercepted catalog represents an independently saved assignment;
      // no rule write is simulated as a side effect of application creation.
      state.rules.push(rule()); state.revision++; state.active = digest(++state.sequence); state.loaded = state.active;
      await refresh(page); await view(page, 'proxy'); await page.waitForFunction(() => !document.querySelector('#download-config').disabled);
      const pending = page.waitForEvent('download'); await page.locator('#download-config').click(); const download = await pending;
      assert(download.url().startsWith('blob:' + ORIGIN + '/'), 'only local Blob download is allowed');
      try {
        const file = await download.path(); assert(file); const config = JSON.parse(await readFile(file, 'utf8'));
        assert.equal(config.application_id, IDS.application); assert.equal(config.access_rule_id, IDS.rule);
        assert.equal(config.proxy_username, IDS.application); assert.equal(config.proxy_password, held);
        assert(!Object.hasOwn(config, 'proxy_authorization')); assert.equal(config.proxy_url, 'https://proxy.example.test');
        assert(!JSON.stringify(config).includes(PRIVATE)); assert.equal(config.token_expires_at_epoch_ms, NOW + 3600000);
      } finally { await download.delete(); }
      assert.equal(state.authPosts.length, 0); assert.equal(state.creates.length, 1);
    })],
  ['desktop and mobile public standard-login guidance has usable controls and no stored token', browser => fixture(browser,
    {applications: [app({proxy_authentication: BASIC})]}, async (page, state) => {
      await view(page, 'proxy');
      for (const width of [1280, 390]) {
        await page.setViewportSize({width, height: width < 800 ? 844 : 960});
        assert(await page.locator('#client-proxy-login').isVisible()); assert(!await page.locator('#copy-command').isDisabled());
        assert.equal(await page.locator('#client-proxy-username').innerText(), IDS.application);
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
        await screenshot(page, 'standard-proxy-login-' + width); await privateAbsent(page);
      }
      assert.equal(state.authPosts.length, 0); assert.equal(state.creates.length, 0);
    })],
];

async function main() {
  assert.equal(process.argv.length, 2, 'usage: test_operator_proxy_auth_browser.cjs; no targets tokens or external arguments accepted');
  assert.equal(tests.length, 13);
  const before = await hashes(); console.log(JSON.stringify({phase: 'source-before', hashes: before}));
  console.log(JSON.stringify({phase: 'selection', groups: tests.length, pureGroups: 1, names: tests.map(([name]) => name)}));
  console.log(JSON.stringify(projectionChecks()));
  const artifactRoot = '/srv/catchplate-fast/projects/serverware-operator-artifacts';
  assert((await stat(artifactRoot)).isDirectory()); artifacts = await mkdtemp(join(artifactRoot, 'proxy-auth-browser-synthetic-'));
  console.log(JSON.stringify({screenshotDirectory: artifacts}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']}); let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of tests) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: tests.length, contexts, pureGroups: 1,
        scope: 'intercepted proxy-login UI contracts only', liveRequests: 0, generatedCommandsExecuted: false,
        backendTransactionTested: false, proxyHandshakeTested: false, tlsTrustTested: false, productionAcceptance: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('proxy-auth browser absolute deadline')), 150000); })]);
  } finally {
    clearTimeout(deadline); try { await browser.close(); }
    finally { const after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after})); assert.deepEqual(after, before); }
  }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

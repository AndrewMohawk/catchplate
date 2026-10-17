#!/usr/bin/env node
// Rendered UI/DTO checks only. The inherited fixture intercepts all HTTP and
// denies unknown requests/WebSockets. No real backend, registry, proxy, CA,
// package manager, generated recipe or provider operation is exercised.
const assert = require('node:assert/strict');
const {withoutMutationReview} = require('./operator_mutation_recovery_test_helpers.cjs');
const {createHash} = require('node:crypto');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {ready, view, application, IDS} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture, publicCatalog, digest, pair, review, grant} = require('./test_operator_ordinary_modes_browser.cjs');
const {npmCredential, npmRule, cap, clone} = require('./test_operator_npm_ui.cjs');
const {publishRule, capability: publishCapability} = require('./test_operator_npm_publish_ui.cjs');
const {capability, installRule} = require('./test_operator_npm_install_ui.cjs');

const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const REGISTRY = 'https://registry.npmjs.org';
const CATALOG = '/api/operator-demo/catalog';
const GRANT = '/api/operator-demo/access-rules/npm-install';
const BUNDLE = 'npm_install_v1';
const PACKAGES = ['@example/fixture', 'example-package'];
const PROVIDER = 'synthetic-install-provider-secret-NEVER-RENDER';
// Independent expected token from the existing base fixture's explicit rotation.
const TOKEN = 'synthetic_application_' + IDS.application.replaceAll('-', '') + '_generation_2';
const options = changes => ({credentials: [npmCredential({secret: PROVIDER})],
  applications: [application({proxy_authentication: 'basic_and_bearer_v1'})], rules: [], allowedUpstreams: [REGISTRY],
  requestBodyModes: ['preserve_json_v1'], responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'],
  credentialInputModes: ['insert', 'replace_exact'], ...changes});

function catalog(state) {
  const result = publicCatalog(state);
  result.capabilities.npm = cap(); result.capabilities.npm_publish = publishCapability();
  result.capabilities.npm_install = state.installCapability;
  result.capabilities.application_proxy_authentication = {schema: 'catchplate.operatorProxyAuthentication/v1',
    modes: ['bearer', 'basic_and_bearer_v1'], path: '/api/operator-demo/applications/proxy-authentication'};
  return result;
}

async function privateSurfaces(page, held = false) {
  const surfaces = await page.evaluate(() => ({html: document.documentElement.outerHTML, text: document.body.innerText,
    inputs: [...document.querySelectorAll('input,textarea')].map(node => ({id: node.id, type: node.type, value: node.value})),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  assert(!JSON.stringify(surfaces).includes(PROVIDER), 'provider token never enters browser surfaces');
  assert(!surfaces.html.includes(TOKEN) && !surfaces.text.includes(TOKEN), 'app token stays out of text/HTML');
  assert.deepEqual(surfaces.local, []); assert.deepEqual(withoutMutationReview(surfaces.session), []);
  for (const input of surfaces.inputs) if (input.value.includes(TOKEN)) {
    assert(held); assert.equal(input.id, 'client-token'); assert.equal(input.type, 'password'); assert.equal(input.value, TOKEN);
  }
  if (held) assert(surfaces.inputs.some(input => input.id === 'client-token' && input.type === 'password' && input.value === TOKEN));
}

async function fixture(browser, config, exercise) {
  return ordinaryFixture(browser, options(config), async (page, state, controls) => {
    state.installCapability = Object.hasOwn(config, 'capability') ? config.capability : capability();
    const observed = {grants: [], requests: 0};
    page.on('download', () => state.errors.push('unexpected download'));
    const handler = async route => {
      const request = route.request(); const url = new URL(request.url()); const bytes = request.postDataBuffer();
      try {
        assert.equal(url.origin, ORIGIN); assert(!url.search); assert(++observed.requests <= 40);
        let result; let status = 200;
        if (url.pathname === CATALOG) {
          assert.equal(request.method(), 'GET'); assert(!bytes?.length); state.catalogCalls++; result = catalog(state);
        } else {
          assert.equal(url.pathname, GRANT); assert.equal(request.method(), 'POST');
          assert(bytes && bytes.length <= 16384); assert(request.headers()['content-type']?.startsWith('application/json'));
          assert.equal(observed.grants.length, 0, 'only one explicit grant, never a replay');
          const body = JSON.parse(bytes.toString('utf8'));
          assert.deepEqual(Object.keys(body).sort(), ['application_id', 'credential_id', 'expected_policy_hash',
            'expected_revision', 'name', 'operation_bundle', 'packages']);
          assert.equal(body.application_id, IDS.application); assert.equal(body.credential_id, IDS.credential);
          assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
          assert.equal(body.name, 'Install packages and run npm audit'); assert.equal(body.operation_bundle, BUNDLE);
          assert.deepEqual(body.packages, PACKAGES); assert.deepEqual(state.installCapability, capability());
          assert(state.allowedUpstreams.includes(REGISTRY)); assert.equal(state.rules.length, 0);
          assert(state.credentials.some(row => row.id === body.credential_id && row.status === 'active' && row.connection_type === 'npm_token_v1'));
          assert(state.applications.some(row => row.id === body.application_id && row.status === 'active'));
          observed.grants.push(clone(body)); state.rules.push(installRule()); state.revision++;
          state.active = digest(++state.sequence); if (state.autoLoad) state.loaded = state.active;
          const current = catalog(state);
          result = {access_rule: current.access_rules[0], revision: state.revision, policy: current.policy}; status = 201;
        }
        await route.fulfill({status, contentType: 'application/json', body: JSON.stringify(result)});
      } catch (_) { state.errors.push('npm install fixture DTO/CAS boundary failed'); await route.abort(); }
    };
    for (const path of [CATALOG, GRANT]) await controls.context.route(ORIGIN + path, handler);
    await page.reload({waitUntil: 'networkidle'});
    assert.equal(await page.title(), 'Overview - Catchplate operator workspace'); assert.equal(new URL(page.url()).origin, ORIGIN);
    await exercise(page, state, observed);
    if (config.holdToken) {
      assert.deepEqual(state.posts, [{name: 'applications/rotate-token', body: {id: IDS.application,
        token_lifetime_seconds: 86400, expected_revision: 1, expected_policy_hash: digest(1)}}]);
    } else assert.deepEqual(state.posts, [], 'no generic grant, consent, token or resource mutation');
    assert(observed.grants.length <= 1); await privateSurfaces(page, Boolean(config.holdToken));
  });
}

async function refresh(page) {
  const response = page.waitForResponse(item => item.url() === ORIGIN + CATALOG && item.request().method() === 'GET');
  await page.locator('#connect-status-refresh').click(); await (await response).finished();
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
}
async function form(page) {
  await pair(page); assert.equal(await page.locator('#connect-operation').inputValue(), 'npm_metadata_read_v1');
  await page.locator('#connect-operation').selectOption(BUNDLE);
  assert(await page.locator('#connect-npm-packages-group').isVisible()); assert(await page.locator('#connect-npm-publish-group').isHidden());
  assert.match(await page.locator('#connect-npm-packages-help').innerText(), /direct, transitive, optional and peer/);
  for (const id of ['connect-path', 'connect-response-mode', 'connect-request-body-mode', 'connect-query-keys', 'connect-credential-input']) {
    assert(await page.locator('#' + id).isHidden()); assert(await page.locator('#' + id).isDisabled());
  }
  await page.locator('#connect-npm-packages').fill([...PACKAGES].reverse().join('\n'));
}
async function recipe(page, held = false) {
  await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  assert(await page.locator('#npm-client-controls').isHidden()); assert(await page.locator('#npm-publish-client-controls').isHidden());
  const text = await page.locator('#client-command').innerText();
  for (const expected of ['CATCHPLATE_PROXY_TOKEN', 'CATCHPLATE_CA_FILE', 'CATCHPLATE_NPM_PACKAGE', 'CATCHPLATE_NPM_VERSION',
    'CATCHPLATE_NPM_PROJECT', 'CATCHPLATE_NPM_OUTPUT', 'node client.mjs install', 'node client.mjs ci',
    'Lifecycle scripts are disabled', 'default npm audit remains on', 'including dependencies', 'does not exist']) assert(text.includes(expected), expected);
  assert(text.includes("export CATCHPLATE_APP_ID='" + IDS.application + "'"));
  assert(text.includes("export CATCHPLATE_PROXY_URL='https://proxy.example.test'"));
  assert(!text.includes(PROVIDER) && !text.includes(TOKEN));
  assert(!/strict-ssl=false|NODE_TLS_REJECT_UNAUTHORIZED|--insecure|--proxy-insecure/.test(text));
  assert.match(await page.locator('#client-template-title').innerText(), /verification pending/);
  const guidance = await page.locator('#client-guidance').innerText();
  assert.match(guidance, /no publishing or automatic dependency grants/);
  assert.match(guidance, /do not mistake npm exit 0 for a successful audit/);
  assert.match(guidance, /not established by this setup/);
  assert.equal(await page.locator('#download-config').isDisabled(), !held);
  await page.locator('#copy-command').click(); assert.equal(await page.evaluate(() => navigator.clipboard.readText()), text);
  await privateSurfaces(page, held); return text;
}

const tests = [
  ['missing or malformed paired install capability leaves the old choices unchanged', async browser => {
    for (const value of [null, {...capability(), modes: ['audit', 'metadata', 'tarball']}]) await fixture(browser,
      {capability: value}, async (page, state, observed) => {
        await pair(page); assert.equal(await page.locator('#connect-operation').inputValue(), 'npm_metadata_read_v1');
        assert.equal(await page.locator('#connect-operation option[value="npm_install_v1"]').count(), 0);
        assert.equal(await page.locator('#connect-operation option[value="npm_metadata_read_v1"]').count(), 1);
        assert.equal(await page.locator('#connect-operation option[value="npm_publish_v1"]').count(), 1);
        assert.equal(observed.grants.length, 0); assert.equal(state.rules.length, 0);
      });
  }],
  ['explicit dependency review sends one exact install grant and waits for loaded policy', (browser, directory) => fixture(browser,
    {autoLoad: false}, async (page, state, observed) => {
      await form(page); await review(page);
      const details = await page.locator('#connect-review-details').innerText();
      assert(details.includes(PACKAGES.join(', '))); assert.match(details, /Explicit package and dependency allowlist/);
      assert.match(details, /No publish.*automatic dependency grants/); assert.equal(observed.grants.length, 0);
      await grant(page); assert.equal(observed.grants.length, 1); assert.deepEqual(observed.grants[0].packages, PACKAGES);
      assert.equal(state.revision, 2); assert.equal(state.sequence, 2); assert.equal(state.rules[0].operation_bundle, BUNDLE);
      assert(await page.locator('#connect-setup-slot').isHidden()); state.loaded = state.active; await refresh(page);
      await recipe(page); assert.equal(observed.grants.length, 1);
      await page.screenshot({path: join(directory, 'install-grant-desktop.png'), fullPage: true});
    })],
  ['old metadata and publish grants are neither widened nor revoked by install selection', async browser => {
    for (const saved of [npmRule(), publishRule()]) await fixture(browser, {rules: [saved]}, async (page, state, observed) => {
      const before = clone(state.rules); await form(page);
      assert(await page.locator('#connect-review').isDisabled());
      assert.match(await page.locator('#connect-npm-summary').innerText(), /Explicitly revoke.*never upgraded/);
      await page.locator('#connect-rule-choice').selectOption(IDS.rule); await review(page); await grant(page);
      assert.equal(observed.grants.length, 0); assert.deepEqual(state.rules, before);
      assert.equal(state.revision, 1); assert.equal(state.sequence, 1);
      assert(await page.locator(saved.operation_bundle === 'npm_metadata_read_v1' ? '#npm-client-controls' : '#npm-publish-client-controls').isVisible());
    });
  }],
  ['retained install recipe keeps a held token masked and states audit and authority limits', (browser, directory) => fixture(browser,
    {rules: [installRule()], holdToken: true}, async (page, state, observed) => {
      const before = clone(state.rules); await ready(page); await view(page, 'applications');
      const card = page.locator('#applications-list [data-resource-id="' + IDS.application + '"]');
      const details = card.locator('details');
      for (const item of await details.all()) if (!await item.evaluate(node => node.open)) await item.locator(':scope > summary').click();
      await card.locator('.application-rotate-ttl').selectOption('86400');
      await card.locator('[data-action="rotate-application"]').click();
      await page.waitForFunction(value => document.querySelector('#client-token').value === value, TOKEN);
      assert.equal(await page.locator('#client-token').getAttribute('type'), 'password');
      assert.equal(await page.locator('#reveal-token').getAttribute('aria-pressed'), 'false');
      await privateSurfaces(page, true);
      await pair(page); await page.locator('#connect-rule-choice').selectOption(IDS.rule); await review(page); await grant(page);
      await recipe(page, true); assert.deepEqual(state.rules, before); assert.equal(observed.grants.length, 0);
      assert.equal(state.applications[0].token_generation, 2); assert.equal(state.revision, 2); assert.equal(state.sequence, 2);
      await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.screenshot({path: join(directory, 'retained-install-mobile.png'), fullPage: true});
    })],
];

async function hashes() {
  const names = ['scripts/test_operator_npm_install_browser.cjs', 'scripts/test_operator_npm_install_ui.cjs',
    'scripts/test_operator_npm_publish_ui.cjs', 'scripts/test_operator_npm_ui.cjs', 'scripts/test_operator_catalog_browser.cjs',
    'scripts/test_operator_ordinary_modes_browser.cjs', 'catchplate/operator_demo_portal.py',
    ...(await readdir(join(ROOT, 'catchplate/operator_demo_web'))).filter(name => /\.(html|css|js)$/.test(name)).sort()
      .map(name => 'catchplate/operator_demo_web/' + name)];
  return Object.fromEntries(await Promise.all(names.map(async name => [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
async function runSuite(browser) {
  const before = await hashes(); const directory = await mkdtemp('/tmp/catchplate-npm-install-browser-');
  console.log(JSON.stringify({phase: 'source-before', hashes: before, artifactDirectory: directory}));
  const contexts = new Set(); let timer; let finished = false; let passed = 0;
  const bounded = {async newContext(...args) { assert(!finished); const context = await browser.newContext(...args);
    if (finished) { await context.close(); throw new Error('suite finished'); }
    contexts.add(context); context.on('close', () => contexts.delete(context)); return context; }};
  try {
    await Promise.race([(async () => { for (const [name, test] of tests) { await test(bounded, directory); passed++; console.log('PASS ' + name); } })(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('rendered installation suite exceeded 120 seconds')), 120000); })]);
    const result = {ok: true, groups: passed, artifactDirectory: directory, backendAcceptance: false,
      providerRequests: 0, proxyRequests: 0, sdkExecuted: false, generatedRecipeExecuted: false};
    console.log(JSON.stringify(result)); return result;
  } finally {
    finished = true; clearTimeout(timer); await Promise.all([...contexts].map(context => context.close()));
    assert.deepEqual(await hashes(), before, 'source changed during rendered fixture');
    console.log(JSON.stringify({phase: 'source-after', sameSource: true, passed}));
  }
}
async function run(page) { return runSuite(page.context().browser()); }
async function main() {
  assert.equal(process.argv.length, 2, 'No live targets or recipe execution arguments accepted');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  try { await runSuite(browser); } finally { await browser.close(); }
}
module.exports = {run};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

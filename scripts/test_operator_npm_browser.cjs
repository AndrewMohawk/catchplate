#!/usr/bin/env node
// Rendered synthetic UI/DTO checks only. Inherited routes deny all unmatched
// HTTP/WebSockets; no provider, proxy, backend, CA download or recipe executes.
// MCP may call exported run(page); CLI owns a separate headless browser.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {ready, view, credential, application, rule, IDS} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture, publicCatalog, digest, pair, step, review, grant} = require('./test_operator_ordinary_modes_browser.cjs');

const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const REGISTRY = 'https://registry.npmjs.org';
const CREATE = '/api/operator-demo/credentials/npm-token';
const GRANT = '/api/operator-demo/access-rules/npm-metadata';
const BUNDLE = 'npm_metadata_read_v1';
const DUMMY = 'serverware-npm-placeholder-v1';
const PRIVATE = 'synthetic-npm-token-NEVER-RENDER';
const PACKAGES = ['@example/fixture', 'example-package'];
const HEADERS = ['accept', 'npm-auth-type', 'npm-command', 'npm-in-ci', 'npm-scope', 'pacote-pkg-id', 'pacote-req-type', 'pacote-version', 'user-agent'];
const clone = value => JSON.parse(JSON.stringify(value));
// Independent server DTO oracle, never constructed from production helpers.
const capability = (allowed = true) => ({schema: 'serverware.operatorNpmMetadata/v1', connection_type: 'npm_token_v1',
  create_credential_path: CREATE, create_rule_path: GRANT, registry_origin: REGISTRY, destination_allowed: allowed,
  operation_bundles: [BUNDLE], sdk_auth_token: DUMMY, placeholder: 'Bearer ' + DUMMY,
  response_mode: 'npm_metadata_json_v1', source_pair_required: true, metadata_only: true, max_active_rules_per_application: 1});
const npmCredential = (changes = {}) => credential({name: 'npm test token', connection_type: 'npm_token_v1', provider_id: 'npm', ...changes});
const npmRule = (changes = {}) => rule({name: 'Read package metadata', operation_bundle: BUNDLE, packages: [...PACKAGES],
  upstream_url: REGISTRY + '/', methods: ['GET'], request_fields: [], response_fields: [], query_keys: [],
  allowed_headers: [...HEADERS], response_mode: 'npm_metadata_json_v1', credential_input: 'replace_exact', placeholder: 'Bearer ' + DUMMY, ...changes});
const options = (changes = {}) => ({credentials: [npmCredential()],
  applications: [application({proxy_authentication: 'basic_and_bearer_v1'})], rules: [], allowedUpstreams: [REGISTRY],
  requestBodyModes: ['preserve_json_v1'], responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'],
  credentialInputModes: ['insert', 'replace_exact'], ...changes});
function catalog(state) {
  const value = publicCatalog(state);
  value.capabilities.application_proxy_authentication = {schema: 'serverware.operatorProxyAuthentication/v1',
    modes: ['bearer', 'basic_and_bearer_v1'], path: '/api/operator-demo/applications/proxy-authentication'};
  if (state.npmCapability !== undefined) value.capabilities.npm = clone(state.npmCapability);
  return value;
}
function exactCAS(state, body) {
  assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
}
function createCredential(state, body) {
  assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'name', 'secret']);
  exactCAS(state, body); assert.equal(body.name, 'My npm token'); assert.equal(body.secret, PRIVATE);
  assert.deepEqual(state.npmCapability, capability(state.npmCapability.destination_allowed)); assert.equal(state.credentials.length, 0);
  state.credentials.push(npmCredential({name: body.name})); state.revision++; body.secret = '';
  return {credential: catalog(state).credentials[0], revision: state.revision, policy: catalog(state).policy};
}
function createRule(state, body) {
  assert.deepEqual(Object.keys(body).sort(), ['application_id', 'credential_id', 'expected_policy_hash',
    'expected_revision', 'name', 'operation_bundle', 'packages']);
  exactCAS(state, body); assert.deepEqual(state.npmCapability, capability()); assert(state.allowedUpstreams.includes(REGISTRY));
  assert.equal(body.application_id, IDS.application); assert.equal(body.credential_id, IDS.credential);
  assert.equal(body.name, 'Read package metadata'); assert.equal(body.operation_bundle, BUNDLE); assert.deepEqual(body.packages, PACKAGES);
  assert(state.credentials.some(item => item.id === body.credential_id && item.status === 'active' && item.connection_type === 'npm_token_v1'));
  assert(state.applications.some(item => item.id === body.application_id && item.status === 'active')); assert.equal(state.rules.length, 0);
  state.rules.push(npmRule()); state.revision++; state.active = digest(++state.sequence); if (state.autoLoad) state.loaded = state.active;
  return {access_rule: catalog(state).access_rules[0], revision: state.revision, policy: catalog(state).policy};
}
async function privateAbsent(page) {
  const surfaces = await page.evaluate(() => JSON.stringify({html: document.documentElement.outerHTML,
    values: [...document.querySelectorAll('input,textarea')].map(node => node.value),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  assert(!surfaces.includes(PRIVATE), 'provider material must not remain in DOM, form values or storage');
}
async function fixture(browser, config, exercise) {
  return ordinaryFixture(browser, options(config), async (page, state, controls) => {
    state.npmCapability = Object.hasOwn(config, 'capability') ? config.capability : capability();
    const observed = {creates: [], grants: [], requests: 0};
    const handler = async route => {
      const request = route.request(); const url = new URL(request.url()); const bytes = request.postDataBuffer();
      try {
        assert.equal(url.origin, ORIGIN); assert(!url.search); assert(++observed.requests <= 40);
        let result; let status = 200;
        if (url.pathname === '/api/operator-demo/catalog') {
          assert.equal(request.method(), 'GET'); assert(!bytes?.length); state.catalogCalls++; result = catalog(state);
        } else {
          assert.equal(request.method(), 'POST'); assert(bytes && bytes.length <= 16384);
          assert(request.headers()['content-type']?.startsWith('application/json'));
          const body = JSON.parse(bytes.toString()); status = 201;
          if (url.pathname === CREATE) {
            assert.equal(observed.creates.length, 0, 'never automatically repeat credential submission');
            result = createCredential(state, body); observed.creates.push({name: body.name, secretMatched: true});
          } else {
            assert.equal(url.pathname, GRANT); assert.equal(observed.grants.length, 0, 'never automatically repeat a grant');
            observed.grants.push(clone(body)); result = createRule(state, body);
            if (config.loseReceipt) { state.expectedFailures.add(GRANT); await route.abort('failed'); return; }
          }
        }
        await route.fulfill({status, contentType: 'application/json', body: JSON.stringify(result)});
      } catch (_) { state.errors.push('npm fixture DTO/CAS boundary failed'); await route.abort(); }
    };
    for (const path of ['/api/operator-demo/catalog', CREATE, GRANT]) await controls.context.route(ORIGIN + path, handler);
    await page.reload({waitUntil: 'networkidle'});
    assert.equal(await page.title(), 'Overview - Serverware operator workspace');
    assert.equal(new URL(page.url()).origin, ORIGIN);
    await exercise(page, state, observed);
    assert.deepEqual(state.posts, [], 'no generic creation, auth-mode change, token rotation, consent or revoke');
    assert(observed.creates.length <= 1 && observed.grants.length <= 1); await privateAbsent(page);
  });
}
async function refresh(page) {
  const pending = page.waitForResponse(response => response.url() === ORIGIN + '/api/operator-demo/catalog' && response.request().method() === 'GET');
  await page.locator('#connect-status-refresh').click(); await (await pending).finished();
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
}
async function form(page) {
  await pair(page); assert.equal(await page.locator('#connect-operation').inputValue(), BUNDLE);
  assert.equal(await page.locator('#connect-operation option').count(), 1);
  assert(await page.locator('#connect-npm-packages-group').isVisible());
  for (const id of ['connect-path', 'connect-response-mode', 'connect-request-body-mode', 'connect-query-keys', 'connect-credential-input']) {
    assert(await page.locator('#' + id).isHidden()); assert(await page.locator('#' + id).isDisabled());
  }
  await page.locator('#connect-npm-packages').fill('example-package\n@example/fixture');
}
async function recipe(page, packageName = PACKAGES[0]) {
  await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  assert(await page.locator('#npm-client-controls').isVisible()); assert(await page.locator('#github-client-controls').isHidden());
  const text = await page.locator('#client-command').innerText();
  for (const expected of ['npm 11.8.0', 'Node.js 25.5.0', 'strict-ssl=true', 'NODE_EXTRA_CA_CERTS=',
    'registry=' + REGISTRY + '/', 'https-proxy=https://' + IDS.application + ':${SERVERWARE_PROXY_TOKEN}@proxy.example.test',
    '//registry.npmjs.org/:_authToken=' + DUMMY, 'fetch-retries=0', 'cache=${SERVERWARE_NPM_CACHE}', '--globalconfig /dev/null',
    "view '" + packageName + "' --json"]) assert(text.includes(expected), expected);
  assert(!/strict-ssl=false|NODE_TLS_REJECT_UNAUTHORIZED|--insecure|--proxy-insecure/.test(text)); assert(!text.includes(PRIVATE));
  assert.match(await page.locator('#client-guidance').innerText(), /No npm lookup was tested here/);
  assert.match(await page.locator('#client-guidance').innerText(), /no install, publish, tarballs or npm audit/);
  assert(await page.locator('#download-config').isDisabled(), 'saved inventory never retrieves a one-time app token');
  return text;
}
async function screenshot(page, directory, name) {
  await page.screenshot({path: join(directory, name + '.png'), fullPage: true,
    mask: [page.locator('#client-token'), page.locator('#connect-credential-secret')]});
}
const tests = [
  ['missing or malformed npm capability disables only npm entry', async browser => {
    for (const cap of [undefined, {...capability(), metadata_only: false}]) await fixture(browser, {capability: cap}, async (page, state, observed) => {
      await ready(page); await view(page, 'connect'); assert(await page.locator('#connect-use-npm').isDisabled());
      assert(!await page.locator('#connect-use-key').isDisabled()); assert.match(await page.locator('#connect-npm-status').innerText(), /not advertised/);
      assert.equal(observed.creates.length + observed.grants.length, 0);
    });
  }],
  ['npm token save is separate and clears the secret without provider access', browser => fixture(browser,
    {credentials: [], capability: capability(false), allowedUpstreams: []}, async (page, state, observed) => {
      await ready(page); await view(page, 'connect'); await page.locator('#connect-use-npm').click();
      assert(await page.locator('#connect-credential-auth-group').isHidden()); assert(await page.locator('#connect-npm-token-note').isVisible());
      await page.locator('#connect-credential-name').fill('My npm token'); await page.locator('#connect-credential-secret').fill(PRIVATE);
      await page.locator('#connect-credential-next').click(); await step(page, 'application');
      assert.equal(observed.creates.length, 1); assert.equal(observed.grants.length, 0); assert.equal(state.rules.length, 0);
      assert.equal(await page.locator('#connect-credential-secret').inputValue(), ''); assert.equal(state.active, digest(1));
      await privateAbsent(page);
    })],
  ['named-package grant waits for exact loaded policy then renders stock npm setup', (browser, directory) => fixture(browser,
    {autoLoad: false}, async (page, state, observed) => {
      await form(page); await review(page); const reviewed = await page.locator('#connect-review-details').innerText();
      assert(reviewed.includes('Read package metadata')); for (const name of PACKAGES) assert(reviewed.includes(name));
      assert.equal(observed.grants.length, 0); await grant(page); assert.equal(observed.grants.length, 1);
      assert.deepEqual(observed.grants[0].packages, PACKAGES); assert(await page.locator('#connect-setup-slot').isHidden());
      assert.match(await page.locator('#connect-activation').innerText(), /Waiting/);
      state.loaded = state.active; await refresh(page); const text = await recipe(page);
      await page.locator('#copy-command').click(); assert.equal(await page.evaluate(() => navigator.clipboard.readText()), text);
      await screenshot(page, directory, 'npm-setup-desktop');
      await page.locator('#npm-client-package').selectOption(PACKAGES[1]); await recipe(page, PACKAGES[1]);
      await page.setViewportSize({width: 390, height: 844}); assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await screenshot(page, directory, 'npm-setup-mobile'); assert.equal(observed.creates.length, 0);
    })],
  ['existing npm permission is reusable but cannot create a second rule or silently enable Basic', async browser => {
    for (const basic of [true, false]) await fixture(browser, {rules: [npmRule()], applications: [application(basic ? {proxy_authentication: 'basic_and_bearer_v1'} : {})]},
      async (page, state, observed) => {
        await pair(page); assert(await page.locator('#connect-review').isDisabled());
        assert.match(await page.locator('#connect-npm-summary').innerText(), /already has/);
        await page.locator('#connect-rule-choice').selectOption(IDS.rule); await review(page); await grant(page);
        if (basic) await recipe(page);
        else {
          assert(await page.locator('#copy-command').isDisabled());
          assert.match(await page.locator('#client-guidance').innerText(), /explicitly enable standard proxy login/);
          assert(!Object.hasOwn(state.applications[0], 'proxy_authentication'));
        }
        assert.equal(observed.creates.length + observed.grants.length, 0);
      });
  }],
  ['invalid package input cannot reach review; withdrawn capability blocks a reviewed grant', browser => fixture(browser, {}, async (page, state, observed) => {
    await form(page); await page.locator('#connect-npm-packages').fill('example-package\nexample-package');
    await page.locator('#connect-review').click(); assert(await page.locator('#connect-review-step').isHidden());
    assert.match(await page.locator('#connect-status').innerText(), /unique.*exact lowercase package names/);
    await page.locator('#connect-npm-packages').fill(PACKAGES.join('\n')); await review(page);
    state.npmCapability = capability(false); state.allowedUpstreams = []; state.revision++; await refresh(page);
    assert(await page.locator('#connect-grant').isDisabled()); assert.equal(observed.grants.length, 0);
  })],
  ['lost committed grant receipt is uncertain and never repeated', browser => fixture(browser, {loseReceipt: true}, async (page, state, observed) => {
    await form(page); await review(page); await page.locator('#connect-grant').click();
    await page.locator('#mutation-review').waitFor({state: 'visible'});
    await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
    assert.equal(observed.grants.length, 1); assert.equal(state.rules.length, 1); assert(await page.locator('#connect-grant').isDisabled());
    assert(await page.locator('#connect-setup-step').isHidden()); await refresh(page); assert.equal(observed.grants.length, 1);
  })],
];
async function hashes() {
  const directory = join(ROOT, 'serverware/operator_demo_web');
  const names = ['scripts/test_operator_npm_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
    'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py',
    ...(await readdir(directory)).filter(name => /\.(?:html|css|js)$/.test(name)).sort().map(name => 'serverware/operator_demo_web/' + name)];
  return Object.fromEntries(await Promise.all(names.map(async name => [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
async function runSuite(browser) {
  assert(browser && typeof browser.newContext === 'function', 'a Playwright Browser is required');
  const before = await hashes(); const directory = await mkdtemp('/tmp/serverware-npm-browser-');
  console.log(JSON.stringify({phase: 'source-before', hashes: before, artifactDirectory: directory}));
  let timeout; let passed = 0; let finished = false;
  // On timeout close only this suite's new contexts, never an MCP-owned browser.
  const activeContexts = new Set();
  const boundedBrowser = {async newContext(...args) {
    assert(!finished, 'suite already finished'); const context = await browser.newContext(...args);
    if (finished) { await context.close(); throw new Error('suite already finished'); }
    activeContexts.add(context); context.on('close', () => activeContexts.delete(context)); return context;
  }};
  try {
    await Promise.race([(async () => {
      for (const [name, test] of tests) { await test(boundedBrowser, directory); passed++; console.log('PASS ' + name); }
    })(), new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('npm rendered suite exceeded 120 seconds')), 120000); })]);
    const result = {ok: true, renderedGroups: tests.length, passed, artifactDirectory: directory,
      backendAcceptance: false, sdkExecuted: false, providerRequests: 0, proxyRequests: 0,
      nativeHttpDownloads: 0, generatedCommandsExecuted: false};
    console.log(JSON.stringify(result)); return result;
  } finally {
    finished = true; clearTimeout(timeout); await Promise.all([...activeContexts].map(context => context.close()));
    const after = await hashes(); assert.deepEqual(after, before, 'rendered source and fixtures changed during execution');
    console.log(JSON.stringify({phase: 'source-after', hashes: after, sameSource: true, passed}));
  }
}
async function run(page) {
  assert(page && typeof page.context === 'function', 'MCP must provide its Page');
  return runSuite(page.context().browser());
}
async function main() {
  assert.equal(process.argv.length, 2, 'No live target, selector or execution arguments accepted');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  try { await runSuite(browser); } finally { await browser.close(); }
}
module.exports = {run, fixture, npmRule};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

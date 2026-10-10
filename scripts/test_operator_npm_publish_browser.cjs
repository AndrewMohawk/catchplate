#!/usr/bin/env node
// Rendered source-only npm publishing UI fixture. Every HTTP response is local
// interception; no npm/provider/proxy/backend/CA request or recipe is executed.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {ready, view, application, IDS} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture, publicCatalog, digest, pair, step, review, grant} = require('./test_operator_ordinary_modes_browser.cjs');
const {npmCredential, npmRule, cap, clone} = require('./test_operator_npm_ui.cjs');
const {capability, publishRule, PACKAGE, BUNDLE} = require('./test_operator_npm_publish_ui.cjs');
const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const GRANT = '/api/operator-demo/access-rules/npm-publish';
const options = changes => ({credentials: [npmCredential()], applications: [application({proxy_authentication: 'basic_and_bearer_v1'})],
  rules: [], allowedUpstreams: ['https://registry.npmjs.org'], requestBodyModes: ['preserve_json_v1'],
  responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'], credentialInputModes: ['insert', 'replace_exact'], ...changes});
function catalog(state) {
  const result = publicCatalog(state); result.capabilities.npm = cap(); result.capabilities.npm_publish = state.publishCapability;
  result.capabilities.application_proxy_authentication = {schema: 'serverware.operatorProxyAuthentication/v1',
    modes: ['bearer', 'basic_and_bearer_v1'], path: '/api/operator-demo/applications/proxy-authentication'};
  return result;
}
async function fixture(browser, config, exercise) {
  return ordinaryFixture(browser, options(config), async (page, state, controls) => {
    state.publishCapability = Object.hasOwn(config, 'capability') ? config.capability : capability();
    const observed = {grants: [], requests: 0}; page.on('download', () => state.errors.push('unexpected download'));
    const handler = async route => {
      const request = route.request(); const url = new URL(request.url()); const bytes = request.postDataBuffer();
      try {
        assert.equal(url.origin, ORIGIN); assert(!url.search); assert(++observed.requests <= 40);
        let result; let status = 200;
        if (url.pathname === '/api/operator-demo/catalog') {
          assert.equal(request.method(), 'GET'); assert(!bytes?.length); state.catalogCalls++; result = catalog(state);
        } else {
          assert.equal(url.pathname, GRANT); assert.equal(request.method(), 'POST'); assert(bytes && bytes.length <= 4096);
          assert(request.headers()['content-type']?.startsWith('application/json')); assert.equal(observed.grants.length, 0);
          const body = JSON.parse(bytes.toString());
          assert.deepEqual(Object.keys(body).sort(), ['application_id', 'credential_id', 'expected_policy_hash', 'expected_revision',
            'name', 'operation_bundle', 'package', 'publishing_window', 'tag']);
          assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
          assert.equal(body.application_id, IDS.application); assert.equal(body.credential_id, IDS.credential);
          assert.equal(body.operation_bundle, BUNDLE); assert.equal(body.package, PACKAGE); assert.equal(body.tag, 'latest');
          assert.deepEqual(body.publishing_window, config.window || null); assert.deepEqual(state.publishCapability, capability());
          assert.equal(state.rules.length, 0); observed.grants.push(clone(body));
          const saved = Object.fromEntries(Object.entries(body).filter(([key]) => !key.startsWith('expected_')));
          state.rules.push(publishRule({...saved, ...(config.receiptChange || {})})); state.revision++;
          state.active = digest(++state.sequence); if (state.autoLoad) state.loaded = state.active;
          result = {access_rule: catalog(state).access_rules[0], revision: state.revision, policy: catalog(state).policy}; status = 201;
          if (config.loseReceipt) { state.expectedFailures.add(GRANT); await route.abort('failed'); return; }
        }
        await route.fulfill({status, contentType: 'application/json', body: JSON.stringify(result)});
      } catch (error) { state.errors.push('npm publish fixture: ' + error.message); await route.abort(); }
    };
    for (const path of ['/api/operator-demo/catalog', GRANT]) await controls.context.route(ORIGIN + path, handler);
    await page.reload({waitUntil: 'networkidle'}); assert.equal(await page.title(), 'Overview - Serverware operator workspace');
    assert.equal(new URL(page.url()).origin, ORIGIN); await exercise(page, state, observed);
    assert.deepEqual(state.posts, [], 'no generic creation, revoke, token rotation, provider consent or proxy-login mutation');
    assert(observed.grants.length <= 1);
    const storage = await page.evaluate(() => ({local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
    assert.deepEqual(storage, {local: [], session: []}, 'publish setup must not persist tokens or drafts');
  });
}
async function refresh(page) {
  const response = page.waitForResponse(item => item.url() === ORIGIN + '/api/operator-demo/catalog');
  await page.locator('#connect-status-refresh').click(); await (await response).finished();
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
}
async function form(page, window = null) {
  await pair(page); assert.equal(await page.locator('#connect-operation').inputValue(), 'npm_metadata_read_v1');
  await page.locator('#connect-operation').selectOption(BUNDLE);
  assert(await page.locator('#connect-npm-publish-group').isVisible()); assert(await page.locator('#connect-npm-packages-group').isHidden());
  for (const id of ['connect-path', 'connect-response-mode', 'connect-request-body-mode', 'connect-query-keys', 'connect-credential-input']) {
    assert(await page.locator('#' + id).isHidden()); assert(await page.locator('#' + id).isDisabled());
  }
  assert.equal(await page.locator('#connect-npm-publish-tag').inputValue(), 'latest');
  await page.locator('#connect-npm-publish-package').fill(PACKAGE);
  if (window) {
    await page.locator('#connect-npm-publish-hours').selectOption('window');
    await page.locator('#connect-npm-publish-start').fill(window.start); await page.locator('#connect-npm-publish-end').fill(window.end);
  }
}
async function recipe(page) {
  await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  assert(await page.locator('#npm-publish-client-controls').isVisible()); assert(await page.locator('#npm-client-controls').isHidden());
  const text = await page.locator('#client-command').innerText();
  for (const expected of ['strict-ssl=true', 'NODE_EXTRA_CA_CERTS=', 'fetch-retries=0', 'cache=${SERVERWARE_NPM_CACHE}',
    'https-proxy=https://' + IDS.application + ':${SERVERWARE_PROXY_TOKEN}@proxy.example.test',
    '//registry.npmjs.org/:_authToken=serverware-npm-placeholder-v1', "publish ./package.tgz --access=public --tag='latest'",
    '--ignore-scripts=true --provenance=false --force=false --dry-run=false --workspaces=false --json']) assert(text.includes(expected), expected);
  assert(!/strict-ssl=false|NODE_TLS_REJECT_UNAUTHORIZED|--insecure|--proxy-insecure/.test(text));
  assert.match(await page.locator('#client-template-warning').innerText(), /public-publishing.*neither executes/);
  assert.match(await page.locator('#client-guidance').innerText(), /No npm publication was tested here/);
  assert(await page.locator('#download-config').isDisabled()); return text;
}
const tests = [
  ['explicit publishing review, policy loading and ordinary tarball recipe desktop/mobile', (browser, directory) => fixture(browser,
    {autoLoad: false, window: {start: '09:00', end: '17:00'}}, async (page, state, observed) => {
      await form(page, {start: '09:00', end: '17:00'}); await review(page);
      assert.match(await page.locator('#connect-review-context').innerText(), /09:00–17:00 UTC.*metadata at any time/);
      assert.equal(observed.grants.length, 0); await grant(page); assert.equal(observed.grants.length, 1);
      assert(await page.locator('#connect-setup-slot').isHidden()); state.loaded = state.active; await refresh(page);
      const text = await recipe(page); await page.locator('#copy-command').click(); assert.equal(await page.evaluate(() => navigator.clipboard.readText()), text);
      await page.screenshot({path: join(directory, 'publish-desktop.png'), fullPage: true});
      await page.setViewportSize({width: 390, height: 844}); assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await page.screenshot({path: join(directory, 'publish-mobile.png'), fullPage: true});
    })],
  ['unrestricted publishing is explicit null, not a fabricated full-day interval', browser => fixture(browser, {}, async (page, state, observed) => {
    await form(page); assert(await page.locator('#connect-npm-publish-window').isHidden()); await review(page); await grant(page); await recipe(page);
    assert.equal(observed.grants[0].publishing_window, null);
  })],
  ['absent or malformed new capability never upgrades metadata access', async browser => {
    for (const capabilityValue of [null, {...capability(), read_metadata_included: false}]) await fixture(browser,
      {capability: capabilityValue}, async (page, state, observed) => {
        await pair(page); assert.equal(await page.locator('#connect-operation option').count(), 1);
        assert.equal(await page.locator('#connect-operation').inputValue(), 'npm_metadata_read_v1');
        assert(await page.locator('#connect-npm-publish-group').isHidden()); assert.equal(observed.grants.length, 0);
      });
  }],
  ['invalid UTC interval and capability withdrawal block grants', browser => fixture(browser, {}, async (page, state, observed) => {
    await form(page, {start: '17:00', end: '09:00'}); await page.locator('#connect-review').click();
    assert(await page.locator('#connect-review-step').isHidden()); assert.match(await page.locator('#connect-status').innerText(), /start before end/);
    await page.locator('#connect-npm-publish-hours').selectOption('any'); await review(page);
    state.publishCapability = capability(false); state.revision++; await refresh(page);
    assert(await page.locator('#connect-grant').isDisabled()); assert.equal(observed.grants.length, 0);
  })],
  ['saved metadata grant is never broadened or revoked by selecting publishing', browser => fixture(browser,
    {rules: [npmRule()]}, async (page, state, observed) => {
      await form(page); assert(await page.locator('#connect-review').isDisabled());
      assert.match(await page.locator('#connect-npm-publish-summary').innerText(), /already has an npm permission/);
      await page.locator('#connect-rule-choice').selectOption(IDS.rule); await review(page); await grant(page);
      assert(await page.locator('#npm-client-controls').isVisible()); assert(await page.locator('#npm-publish-client-controls').isHidden());
      assert.equal(state.rules[0].operation_bundle, 'npm_metadata_read_v1'); assert.equal(observed.grants.length, 0);
    })],
  ['lost grant response stays uncertain without automatic resubmission', browser => fixture(browser,
    {loseReceipt: true}, async (page, state, observed) => {
      await form(page); await review(page); await page.locator('#connect-grant').click(); await page.locator('#mutation-review').waitFor({state: 'visible'});
      await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
      assert.equal(observed.grants.length, 1); assert.equal(state.rules.length, 1); assert(await page.locator('#connect-grant').isDisabled());
      await refresh(page); assert.equal(observed.grants.length, 1); assert(await page.locator('#connect-setup-step').isHidden());
    })],
];
async function hashes() {
  const names = ['scripts/test_operator_npm_publish_browser.cjs', 'scripts/test_operator_npm_publish_ui.cjs', 'scripts/test_operator_npm_ui.cjs',
    'scripts/test_operator_catalog_browser.cjs', 'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py',
    ...(await readdir(join(ROOT, 'serverware/operator_demo_web'))).filter(name => /\.(html|css|js)$/.test(name)).sort().map(name => 'serverware/operator_demo_web/' + name)];
  return Object.fromEntries(await Promise.all(names.map(async name => [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
async function runSuite(browser) {
  const before = await hashes(); const directory = await mkdtemp('/tmp/serverware-npm-publish-browser-');
  console.log(JSON.stringify({phase: 'source-before', hashes: before, artifactDirectory: directory}));
  const contexts = new Set(); let timer; let finished = false; let passed = 0;
  const bounded = {async newContext(...args) { assert(!finished); const context = await browser.newContext(...args);
    if (finished) { await context.close(); throw new Error('suite finished'); }
    contexts.add(context); context.on('close', () => contexts.delete(context)); return context; }};
  try {
    await Promise.race([(async () => { for (const [name, test] of tests) { await test(bounded, directory); passed++; console.log('PASS ' + name); } })(),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('rendered publishing suite exceeded 120 seconds')), 120000); })]);
    const result = {ok: true, groups: passed, artifactDirectory: directory, backendAcceptance: false, providerRequests: 0,
      proxyRequests: 0, sdkExecuted: false, generatedRecipeExecuted: false}; console.log(JSON.stringify(result)); return result;
  } finally {
    finished = true; clearTimeout(timer); await Promise.all([...contexts].map(context => context.close()));
    assert.deepEqual(await hashes(), before, 'source changed during rendered fixture');
    console.log(JSON.stringify({phase: 'source-after', sameSource: true, passed}));
  }
}
async function run(page) { return runSuite(page.context().browser()); }
async function main() {
  assert.equal(process.argv.length, 2, 'No live target arguments accepted');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  try { await runSuite(browser); } finally { await browser.close(); }
}
module.exports = {run};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

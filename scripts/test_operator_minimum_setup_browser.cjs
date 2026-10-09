#!/usr/bin/env node
// Independent minimum-setup UI acceptance. Imports bounded synthetic fixtures,
// never their suites. No live API, provider, CA download or command execution.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFileSync} = require('node:fs');
const {readFile, mkdtemp, stat} = require('node:fs/promises');
const {resolve, join} = require('node:path');
const vm = require('node:vm');
const {ready, view, openRestrictions, credential, application, rule, IDS} = require('./test_operator_catalog_browser.cjs');
const {fixture, supplied, google, pair, method, review, grant, step, refresh, command, downloadedConfig,
  privateAbsent, PRIVATE, DUMMY} = require('./test_operator_ordinary_modes_browser.cjs');
const ROOT = resolve(__dirname, '..');
const V2 = 'unfiltered_json_or_empty_v2'; const V1 = 'unfiltered_json_or_empty_v1';
const ALL = ['projected_json', 'unfiltered_json', V1, V2];
const options = changes => supplied({responseModes: ALL, ...changes});
const SOURCE_FILES = ['scripts/test_operator_minimum_setup_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
  'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py', ...['index.html', 'style.css', 'app.js',
    'workspace_core.js', 'workspace_google.js', 'workspace_applications.js', 'workspace_resources.js', 'workspace_proxy_audit.js', 'workspace_connect.js']
    .map(name => 'serverware/operator_demo_web/' + name)];
let artifacts;
async function hashes() { return Object.fromEntries(await Promise.all(SOURCE_FILES.map(async name =>
  [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')]))); }
async function shot(page, name) { await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true}); }
async function basic(page, prefix, mode = V2) {
  assert(!await page.locator('#' + prefix + '-restrictions').evaluate(node => node.open));
  for (const id of ['response-mode', 'request-body-mode', 'response-fields', 'request-fields', prefix === 'rule' ? 'name' : 'rule-name'])
    assert(!await page.locator('#' + prefix + '-' + id).isVisible(), 'no basic policy editor: ' + id);
  assert.equal(await page.locator('#' + prefix + '-response-mode').inputValue(), mode);
  assert(await page.locator('#' + prefix + '-basic-compatibility').isVisible());
  assert.match(await page.locator('#' + prefix + '-basic-compatibility').innerText(), /No query parameters/);
  const choices = await page.locator('#' + prefix + '-response-mode option').evaluateAll(items => items.map(item => ({value: item.value, label: item.textContent})));
  assert(choices.length <= 2, 'only whole-content versus explicit filtering, not compatibility generations');
  assert(choices.every(item => !/v1|v2|204|buffered|unfiltered_json/i.test(item.label)), 'no wire-version choice labels');
}
async function watchContentDecisions(page) {
  await page.evaluate(() => {
    window.minimumSetupContentEvents = [];
    for (const event of ['input', 'change']) document.addEventListener(event, value => {
      if (/^(rule|connect)-(response-mode|response-fields|request-body-mode|request-fields)$/.test(value.target.id))
        window.minimumSetupContentEvents.push(value.target.id);
    });
  });
}
async function noContentDecisions(page) { assert.deepEqual(await page.evaluate(() => window.minimumSetupContentEvents), []); }
async function directBasic(page, path = '/v1/status') {
  await ready(page); await view(page, 'access-rules'); await page.locator('#rule-path').fill(path);
}
async function guidedBasic(page, path = '/v1/status') { await pair(page); await page.locator('#connect-path').fill(path); }
async function submitDirect(page) { await page.locator('#rule-save').click(); await ready(page); }
function exactDefault(body, name, methods = ['GET']) {
  assert.equal(body.name, name); assert.equal(body.response_mode, V2); assert.deepEqual(body.response_fields, []);
  assert.deepEqual(body.methods, methods); assert.deepEqual(body.query_keys, []); assert.deepEqual(body.allowed_headers, ['accept', 'user-agent']);
}
function pureChecks() {
  const source = readFileSync(join(ROOT, 'serverware/operator_demo_web/workspace_core.js'), 'utf8');
  const evaluate = (expression, input) => vm.runInNewContext(source + '\n' + expression, {input}, {timeout: 1000});
  const catalog = modes => ({capabilities: {response_modes: modes}});
  assert.equal(evaluate('operatorPermissionName("", ["POST"], "/v1/send")'), 'POST /v1/send');
  assert.equal(evaluate('operatorPermissionName("  Custom label  ", ["GET"], "/x")'), 'Custom label');
  assert.equal(evaluate('operatorPermissionName("", ["GET"], "/" + "x".repeat(1024)).length'), 128);
  for (const current of ['', 'projected_json', ...ALL]) {
    const choices = evaluate('responseFormChoices(input.catalog, input.current)', {catalog: catalog(ALL), current});
    assert.equal(choices.length, 2); assert.equal(choices[0].id, current && current !== 'projected_json' ? current : V2);
    assert.equal(choices[1].id, 'projected_json');
  }
  assert.equal(evaluate('responseFormChoices(input, "").length', catalog(['future_mode'])), 0);
  assert.equal(evaluate('responseFormChoices(input, "")[0].id', catalog(['projected_json'])), 'projected_json');
  return {ok: true, groups: 1, scope: 'deterministic names and actual semantic response choices'};
}

const tests = [
  ['basic direct replacement publishes without opening restrictions or naming a permission', browser => fixture(browser, options(), async (page, state) => {
    await directBasic(page); await watchContentDecisions(page); await method(page, 'rule', 'POST');
    await page.locator('#rule-credential-input').selectOption('replace_exact'); await page.locator('#rule-placeholder').fill(DUMMY);
    await basic(page, 'rule'); const limits = await page.locator('#rule-basic-compatibility').innerText();
    assert.match(limits, /JSON requests up to 64 KiB/); assert.match(limits, /empty HTTP 204/); assert.match(limits, /metadata is checked and discarded/);
    await shot(page, 'minimum-direct-desktop'); await submitDirect(page); assert.equal(state.posts.length, 1);
    exactDefault(state.posts[0].body, 'POST /v1/status', ['POST']); assert.equal(state.posts[0].body.placeholder, DUMMY);
    assert.equal(state.posts[0].body.request_body_mode, 'preserve_json_v1'); assert.deepEqual(state.posts[0].body.request_fields, []);
    await noContentDecisions(page); await view(page, 'proxy'); await command(page);
  })],
  ['guided replacement creates an app and exports setup with zero content decisions', browser => fixture(browser,
    options({applications: [], credentials: [credential({secret: PRIVATE[0], refresh_token: PRIVATE[1]})]}), async (page, state) => {
      await ready(page); await watchContentDecisions(page); await page.locator('#connect-use-saved').click();
      assert(await page.locator('#connect-credential-new').isHidden()); assert(await page.locator('#connect-google').isHidden());
      await page.locator('#connect-credential-choice').selectOption(IDS.credential);
      await page.locator('#connect-credential-next').click(); await step(page, 'application');
      await page.locator('#connect-application-name').fill('Billing worker'); await page.locator('#connect-application-next').click(); await step(page, 'access');
      const token = await page.locator('#client-token').inputValue(); assert(token.startsWith('synthetic_application_'));
      await page.locator('#connect-path').fill('/v1/status'); await page.locator('#connect-credential-input').selectOption('replace_exact');
      await page.locator('#connect-placeholder').fill(DUMMY); await basic(page, 'connect'); await privateAbsent(page);
      await page.setViewportSize({width: 390, height: 844}); assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await shot(page, 'minimum-guided-mobile'); await review(page); assert.match(await page.locator('#connect-review-details').innerText(), /No field list required/);
      await shot(page, 'minimum-guided-review-mobile'); await grant(page); await page.locator('#connect-setup-slot').waitFor({state: 'visible'});
      assert.deepEqual(state.posts.map(item => item.name), ['applications', 'access-rules']); exactDefault(state.posts[1].body, 'GET /v1/status');
      await noContentDecisions(page); const config = await downloadedConfig(page); assert.equal(config.response_mode, V2);
      assert.equal(config.request_body_mode, 'preserve_json_v1'); assert.equal(config.proxy_authorization, 'Bearer ' + token);
      assert.deepEqual(config.request_headers, {Authorization: DUMMY}); await command(page); await privateAbsent(page);
    })],
  ...['rule', 'connect'].map(prefix => [prefix + ' deliberate field restrictions survive closing and preserve the entered name', browser => fixture(browser, options(), async (page, state) => {
    if (prefix === 'rule') await directBasic(page); else await guidedBasic(page);
    await basic(page, prefix); await openRestrictions(page, prefix);
    const labels = await page.locator('#' + prefix + '-response-mode option').allTextContents();
    assert.deepEqual(labels, ['Do not filter response content', 'Only return selected JSON fields']);
    await page.locator('#' + prefix + '-request-body-mode').selectOption('legacy_fields');
    await page.locator('#' + prefix + '-request-fields').fill('message'); await page.locator('#' + prefix + '-response-mode').selectOption('projected_json');
    await page.locator('#' + prefix + '-response-fields').fill('result.id');
    await page.locator('#' + prefix + (prefix === 'rule' ? '-name' : '-rule-name')).fill('Explicit constrained operation');
    await page.locator('#' + prefix + '-restrictions > summary').click(); assert(!await page.locator('#' + prefix + '-restrictions').evaluate(node => node.open));
    if (prefix === 'rule') await submitDirect(page); else { await review(page); await grant(page); }
    assert.equal(state.posts.length, 1); const body = state.posts[0].body; assert.equal(body.name, 'Explicit constrained operation');
    assert(!Object.hasOwn(body, 'request_body_mode')); assert.deepEqual(body.request_fields, ['message']);
    assert.equal(body.response_mode, 'projected_json'); assert.deepEqual(body.response_fields, ['result.id']);
  })]),
  ['legacy projection-only advertises its limitation and opens required fields instead of hiding them', browser => fixture(browser,
    options({responseModes: ['projected_json'], requestBodyModes: []}), async (page, state) => {
      await directBasic(page); assert(await page.locator('#rule-restrictions').evaluate(node => node.open));
      assert(await page.locator('#rule-response-fields').isVisible()); assert(await page.locator('#rule-response-fields').evaluate(node => node.required));
      const text = await page.locator('#rule-basic-compatibility').innerText(); assert.match(text, /No request body/); assert.match(text, /Selected response fields are required/);
      await page.locator('#rule-save').click(); assert.equal(state.posts.length, 0); await page.locator('#rule-response-fields').fill('id'); await submitDirect(page);
      assert.equal(state.posts[0].body.response_mode, 'projected_json'); assert.deepEqual(state.posts[0].body.response_fields, ['id']);
      assert(!Object.hasOwn(state.posts[0].body, 'request_body_mode'));
    })],
  ['old whole-JSON capability is not silently upgraded and shows body/query limitations', browser => fixture(browser,
    options({responseModes: ['projected_json', 'unfiltered_json'], requestBodyModes: []}), async (page, state) => {
      await directBasic(page); await basic(page, 'rule', 'unfiltered_json'); await method(page, 'rule', 'POST');
      const text = await page.locator('#rule-basic-compatibility').innerText(); assert.match(text, /No request body/); assert.match(text, /Nonempty JSON responses only/);
      assert.match(text, /Strict upstream-header limits/); await submitDirect(page);
      assert.equal(state.posts[0].body.response_mode, 'unfiltered_json'); assert(!Object.hasOwn(state.posts[0].body, 'request_body_mode'));
      assert.deepEqual(state.posts[0].body.request_fields, []); assert.deepEqual(state.posts[0].body.query_keys, []);
    })],
  ['adding newer capabilities retains existing direct and guided drafts exactly', browser => fixture(browser,
    options({responseModes: ['projected_json', V1]}), async (page, state) => {
      await directBasic(page); await guidedBasic(page); await basic(page, 'connect', V1); state.responseModes = ALL; await refresh(page);
      await basic(page, 'connect', V1); await view(page, 'access-rules'); await basic(page, 'rule', V1);
      await openRestrictions(page, 'rule'); assert.deepEqual(await page.locator('#rule-response-mode option').evaluateAll(items => items.map(item => item.value)), [V1, 'projected_json']);
      assert.equal(state.posts.length, 0);
    })],
  ['withdrawn no-filter capability stays blocked until a deliberate supported choice', browser => fixture(browser, options(), async (page, state) => {
    await guidedBasic(page); await review(page); state.responseModes = ['projected_json']; await refresh(page);
    assert(await page.locator('#connect-grant').isDisabled()); await page.locator('#connect-back').click(); await step(page, 'access');
    assert.equal(await page.locator('#connect-response-mode').inputValue(), V2);
    assert.match(await page.locator('#connect-basic-compatibility').innerText(), /unavailable.*nothing is changed automatically/);
    await openRestrictions(page, 'connect'); assert(await page.locator('#connect-response-mode option:checked').evaluate(node => node.disabled));
    await page.locator('#connect-review').click(); assert.equal(state.posts.length, 0);
    await page.locator('#connect-response-mode').selectOption('projected_json'); assert(await page.locator('#connect-response-fields').isVisible());
    await page.locator('#connect-response-fields').fill('id'); await review(page); await grant(page);
    assert.equal(state.posts[0].body.response_mode, 'projected_json'); assert.deepEqual(state.posts[0].body.response_fields, ['id']);
  })],
  ['selecting a saved projected permission does not recreate or broaden it', browser => fixture(browser,
    options({rules: [rule({credential_input: 'insert', request_fields: ['message']})]}), async (page, state) => {
      const before = JSON.stringify(state.rules); await pair(page); await page.locator('#connect-rule-choice').selectOption(IDS.rule);
      await review(page); assert.match(await page.locator('#connect-review-details').innerText(), /message/); await grant(page); await command(page);
      assert.equal(state.posts.length, 0); assert.equal(JSON.stringify(state.rules), before);
    })],
  ['basic Google keeps GET/no-body, no provider UI activation, and zero response decisions', browser => fixture(browser,
    options({credentials: [google()], allowedUpstreams: ['https://gmail.googleapis.com']}), async (page, state) => {
      await pair(page); await watchContentDecisions(page); await page.locator('#connect-path').fill('/gmail/v1/users/me/messages');
      await basic(page, 'connect'); assert.match(await page.locator('#connect-basic-compatibility').innerText(), /Google permits GET with no request body/);
      assert(await page.locator('#connect-google').isDisabled()); await review(page); await grant(page);
      const body = state.posts[0].body; exactDefault(body, 'GET /gmail/v1/users/me/messages');
      assert(!Object.hasOwn(body, 'request_body_mode')); assert.deepEqual(body.request_fields, []); await noContentDecisions(page);
      assert(!state.requests.some(item => /oauth|google/.test(item.path)));
    })],
  ['query permission remains separate and explicit without touching response configuration', browser => fixture(browser, options(), async (page, state) => {
    await directBasic(page); await watchContentDecisions(page); await basic(page, 'rule');
    await page.locator('#rule-request-extras > summary').click(); await page.locator('#rule-query-keys').fill('cursor');
    assert.match(await page.locator('#rule-basic-compatibility').innerText(), /Only 1 named query parameter/);
    assert(!await page.locator('#rule-restrictions').evaluate(node => node.open)); await submitDirect(page);
    assert.deepEqual(state.posts[0].body.query_keys, ['cursor']); assert.equal(state.posts[0].body.response_mode, V2); await noContentDecisions(page);
  })],
];

async function main() {
  assert.equal(process.argv.length, 2, 'no live target or credential inputs'); const before = await hashes();
  console.log(JSON.stringify({phase: 'source-before', hashes: before})); console.log(JSON.stringify(pureChecks()));
  const root = '/srv/catchplate-fast/projects/serverware-operator-artifacts'; assert((await stat(root)).isDirectory());
  artifacts = await mkdtemp(join(root, 'minimum-setup-browser-synthetic-')); console.log(JSON.stringify({artifactDirectory: artifacts}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']}); let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of tests) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: tests.length, pureGroups: 1, scope: 'minimum setup intercepted UI only',
        liveRequests: 0, providerRequests: 0, nativeCaDownloadExecuted: false, generatedCommandsExecuted: false, runtimeAcceptance: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('minimum setup fixture deadline')), 150000); })]);
  } finally {
    clearTimeout(deadline); try { await browser.close(); }
    finally { const after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after})); assert.deepEqual(after, before); }
  }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

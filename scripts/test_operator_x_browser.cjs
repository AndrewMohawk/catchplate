#!/usr/bin/env node
// Rendered synthetic X source fixture. All API/provider traffic is intercepted
// or refused. No SDK, generated recipe, provider, native authority or live API
// is executed. Real API/SQLite and ordinary-client acceptance are separate.
const assert = require('node:assert/strict');
const {acknowledgeMutationReview} = require('./operator_mutation_recovery_test_helpers.cjs');
const {createHash} = require('node:crypto');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {ready, view, credential, application, IDS, UPSTREAM} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture, supplied, pair, step, review, grant, draft} = require('./test_operator_ordinary_modes_browser.cjs');
const {fixture, capability, xCredential, xRule, privateAbsent, ORIGIN, API, GRANT,
  BUNDLE, USERNAME, DUMMY, PRIVATE, APP_TOKEN} = require('./operator_x_browser_fixture.cjs');
const ROOT = resolve(__dirname, '..');

async function refresh(page) {
  const response = page.waitForResponse(item => item.url() === ORIGIN + '/api/operator-demo/catalog' && item.request().method() === 'GET');
  await page.locator('#connect-status-refresh').click(); await (await response).finished();
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
}
async function keyForm(page) {
  await ready(page); await view(page, 'connect'); await page.locator('#connect-use-x').click();
  assert(await page.locator('#connect-x-secret').isVisible());
  assert.equal(await page.locator('#connect-x-secret').getAttribute('type'), 'password');
  assert(await page.locator('#connect-credential-secret').isHidden());
  await page.locator('#connect-x-name').fill('My X token'); await page.locator('#connect-x-secret').fill(PRIVATE);
}
async function fixedUsernameForm(page) {
  assert.equal(await page.locator('#connect-operation').inputValue(), BUNDLE);
  assert.equal(await page.locator('#connect-operation option').count(), 1);
  assert(await page.locator('#connect-x-username-group').isVisible());
  for (const id of ['connect-path', 'connect-response-mode', 'connect-response-fields',
    'connect-request-fields', 'connect-request-body-mode', 'connect-query-keys', 'connect-credential-input']) {
    assert(await page.locator('#' + id).isHidden(), id + ' hidden');
    assert(await page.locator('#' + id).isDisabled(), id + ' disabled');
  }
  await page.locator('#connect-x-username').fill(USERNAME);
}
async function form(page) { await pair(page); await fixedUsernameForm(page); }
async function recipe(page) {
  await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  assert(await page.locator('#connect-setup-slot').isVisible());
  const text = await page.locator('#client-command').innerText();
  assert(text.includes(DUMMY)); assert(text.includes(USERNAME));
  assert(text.includes('CATCHPLATE_PROXY_TOKEN'));
  assert(text.includes("--request 'GET'")); assert(text.includes(API + '/2/users/by/username/' + USERNAME));
  assert(!/--data|--json|--form/.test(text), 'username lookup has no request body');
  assert(/NODE_EXTRA_CA_CERTS|--cacert|ca_bundle|CA_CERT/.test(text), 'verified CA trust must be explicit');
  assert(!/--insecure|--proxy-insecure|NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized:\s*false|verify\s*=\s*False/.test(text));
  assert(!text.includes(PRIVATE)); assert(!text.includes(APP_TOKEN));
  assert.match(await page.locator('#connect-activation').innerText(), /no upstream request has been tested here/);
  assert.match(await page.locator('#client-guidance').innerText(), /No X lookup was tested here/);
  assert.match(await page.locator('#client-guidance').innerText(), /No posting.*user OAuth/);
  const source = 'https://github.com/AndrewMohawk/catchplate/';
  const branch = 'main/';
  const expectedLinks = [
    ['Node.js', source + 'tree/' + branch + 'examples/x-username-node'],
    ['Python', source + 'tree/' + branch + 'examples/x-username-python'],
    ['Go', source + 'tree/' + branch + 'examples/x-username-go'],
    ['GitHub Actions recipe (inactive)', source + 'blob/' + branch + 'examples/x-username-node/workflow.example.yml'],
    ['X preset scope and compatibility', source + 'blob/' + branch + 'docs/operator-provider-presets.md'],
  ];
  const links = page.locator('#client-example-links a');
  assert.deepEqual(await links.evaluateAll(items => items.map(item => [item.textContent, item.getAttribute('href')])), expectedLinks);
  for (const link of await links.all()) {
    assert.equal(await link.getAttribute('target'), '_blank');
    assert.equal(await link.getAttribute('rel'), 'noopener noreferrer');
    assert.equal(await link.getAttribute('referrerpolicy'), 'no-referrer');
  }
  const acceptance = 'Pinned Node.js, Python and Go examples passed isolated SDK-through-proxy checks. ' +
    'This page has not tested your X credentials or provider entitlement. ' +
    'The GitHub Actions recipe is inactive and has not been run.';
  assert.equal(await page.locator('#client-example-note').innerText(),
    'Public source only, separate from your private client config. ' + acceptance);
  assert((await page.locator('#client-guidance').innerText()).endsWith(acceptance));
  await privateAbsent(page); return text;
}
async function noAutomaticWrite(page, observed, expected = 1) {
  await page.locator('#mutation-review').waitFor({state: 'visible'});
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
  assert.equal(observed.grants.length, expected);
  assert(await page.locator('#connect-grant').isDisabled());
  assert(await page.locator('#connect-setup-step').isHidden());
  await refresh(page); assert.equal(observed.grants.length, expected);
  await page.reload({waitUntil: 'networkidle'}); await ready(page);
  assert.equal(observed.grants.length, expected, 'reload is GET-only, not grant recovery by replay');
}
async function screenshot(page, directory, name) {
  await page.screenshot({path: join(directory, name + '.png'), fullPage: true,
    mask: [page.locator('#client-token'), page.locator('#connect-x-secret')]});
}

const tests = [
  ['key -> new app -> exact username -> review -> pending -> active, desktop/mobile', (browser, directory) => fixture(browser,
    {credentials: [], applications: [], autoLoad: false, holdCredential: true}, async (page, state, observed, controls) => {
      await keyForm(page); await page.locator('#connect-credential-next').click(); await controls.credentialArrived;
      assert.equal(await page.locator('#connect-x-secret').inputValue(), ''); await privateAbsent(page);
      assert.equal(state.credentials.length, 0); assert.equal(observed.credentials.length, 1);
      controls.releaseCredential(); await step(page, 'application');
      assert.equal(state.rules.length, 0); assert.equal(state.applications.length, 0);
      await page.locator('#connect-application-choice').selectOption('new');
      await page.locator('#connect-application-name').fill('X lookup client'); await page.locator('#connect-token-ttl').selectOption('3600');
      await page.locator('#connect-application-next').click(); await step(page, 'access');
      assert.equal(observed.applications.length, 1); assert.equal(state.rules.length, 0);
      assert.equal(await page.locator('#client-token').inputValue(), APP_TOKEN);
      await fixedUsernameForm(page); await review(page);
      const summary = await page.locator('#connect-review-details').innerText();
      assert(summary.includes(USERNAME)); assert.match(summary, /GET|Read/); assert.equal(observed.grants.length, 0);
      await screenshot(page, directory, 'x-review-desktop');
      await grant(page); assert.equal(observed.grants.length, 1);
      const savedRule = JSON.stringify(state.rules[0]); const savedRevision = state.revision;
      assert.equal(observed.catalogs.at(-1).x, null, 'old loaded hash must suppress the advertised X capability');
      assert.deepEqual(observed.catalogs.at(-1).ruleIds, [IDS.rule], 'saved rule survives capability suppression');
      assert(await page.locator('#mutation-review').isHidden(), 'pending policy loading is not an uncertain mutation');
      assert(await page.locator('#connect-setup-slot').isHidden()); assert.match(await page.locator('#connect-activation').innerText(), /Waiting/);
      assert(await page.locator('#copy-command').isDisabled()); assert.notEqual(state.loaded, state.active);
      const pendingRequestCount = observed.requests.length;
      await refresh(page);
      assert.equal(observed.catalogs.at(-1).x, null); assert(await page.locator('#connect-setup-step').isVisible());
      assert(await page.locator('#mutation-review').isHidden()); assert.equal(observed.grants.length, 1);
      state.loaded = state.active; await refresh(page);
      assert.deepEqual(observed.catalogs.at(-1).x, capability(), 'matching loaded policy restores exactly the advertised descriptor');
      assert.equal(JSON.stringify(state.rules[0]), savedRule); assert.equal(state.revision, savedRevision);
      assert(observed.requests.slice(pendingRequestCount).every(item => item.method === 'GET'), 'loading recovery must not resubmit anything');
      assert(await page.locator('#mutation-review').isHidden()); assert.equal(observed.grants.length, 1);
      const command = await recipe(page); await page.locator('#copy-command').click();
      assert.equal(await page.evaluate(() => navigator.clipboard.readText()), command);
      await screenshot(page, directory, 'x-setup-desktop'); await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await screenshot(page, directory, 'x-setup-mobile');
      assert.deepEqual(observed.credentials.map(item => item.expected_revision), [1]);
      assert.equal(observed.applications[0].expected_revision, 2); assert.equal(observed.grants[0].expected_revision, 3);
    })],
  ['blocked destination is explicit and never approved by choosing the provider', browser => fixture(browser,
    {credentials: [], applications: [], allowedUpstreams: [], capability: capability(false)}, async (page, state, observed) => {
      await ready(page); await view(page, 'connect'); assert(await page.locator('#connect-use-x').isDisabled());
      assert.match(await page.locator('#connect-x-status').innerText(), /api\.x\.com.*Proxy setup/);
      assert.equal(observed.credentials.length, 0); assert.equal(state.credentials.length, 0);
      assert.deepEqual(state.allowedUpstreams, []); assert.equal(state.rules.length + state.applications.length, 0);
      assert.equal(observed.grants.length, 0);
    })],
  ['X secret clears on method changes and navigation without any submission', browser => fixture(browser,
    {credentials: [], applications: []}, async (page, state, observed) => {
      await keyForm(page); await page.locator('#connect-method-change').click();
      assert.equal(await page.locator('#connect-x-secret').inputValue(), '');
      await page.locator('#connect-use-key').click(); assert(await page.locator('#connect-credential-secret').isVisible());
      assert(await page.locator('#connect-x-secret').isHidden()); await page.locator('#connect-method-change').click();
      await page.locator('#connect-use-x').click(); await page.locator('#connect-x-secret').fill(PRIVATE);
      await view(page, 'overview'); assert.equal(await page.locator('#connect-x-secret').inputValue(), '');
      assert.equal(observed.credentials.length + observed.applications.length + observed.grants.length, 0);
    })],
  ['failed key storage clears secret and exposes no raw error or automatic retry', browser => fixture(browser,
    {credentials: [], applications: [], credentialFault: true}, async (page, state, observed) => {
      await keyForm(page); await page.locator('#connect-credential-next').click();
      await page.locator('#mutation-review').waitFor({state: 'visible'});
      await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
      assert.equal(await page.locator('#connect-x-secret').inputValue(), ''); await privateAbsent(page);
      assert(await page.locator('#connect-credential-next').isDisabled()); await refresh(page);
      assert.equal(observed.credentials.length, 1); assert.equal(state.credentials.length, 0);
      await page.reload({waitUntil: 'networkidle'});
      assert(await page.locator('#credential-fields').evaluate(node => node.disabled), 'reload preserves explicit review');
      await acknowledgeMutationReview(page); await ready(page);
      assert.equal(observed.credentials.length, 1); await privateAbsent(page);
    })],
  ['changed key name or provider marker is not accepted as the saved X connection', async browser => {
    for (const change of [{name: 'Different saved name'}, {connection_type: 'github_token_v1', provider_id: 'github'}])
      await fixture(browser, {credentials: [], applications: [], credentialChange: change}, async (page, state, observed) => {
        await keyForm(page); await page.locator('#connect-credential-next').click();
        await page.locator('#mutation-review').waitFor({state: 'visible'});
        await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
        assert(await page.locator('#connect-application-step').isHidden());
        assert.equal(await page.locator('#connect-x-secret').inputValue(), '');
        await refresh(page); assert.equal(observed.credentials.length, 1); assert.equal(observed.applications.length, 0);
      });
  }],
  ['missing or malformed closed capability never enables X', async browser => {
    for (const value of [null, {...capability(), extra: true}, {...capability(), source_pair_required: false},
      {...capability(), api_origin: 'https://api.twitter.com'}, {...capability(), placeholder: 'Bearer wrong'}])
      await fixture(browser, {capability: value}, async (page, state, observed) => {
        assert.equal(state.loaded, state.active);
        assert.deepEqual(observed.catalogs.at(-1).x, value, 'malformed capability is delivered intact to the UI validator');
        await view(page, 'connect'); assert(await page.locator('#connect-use-x').isDisabled());
        assert.equal(observed.credentials.length + observed.applications.length + observed.grants.length, 0);
      });
  }],
  ['invalid usernames cannot reach review or become a broad endpoint', browser => fixture(browser, {}, async (page, state, observed) => {
    await form(page);
    for (const username of ['@example', 'UpperCase', '../users/me', 'name?x=1', '']) {
      await page.locator('#connect-x-username').fill(username); await page.locator('#connect-review').click();
      assert(await page.locator('#connect-review-step').isHidden()); assert.equal(observed.grants.length, 0);
    }
    await page.locator('#connect-x-username').fill(USERNAME); await review(page); assert.equal(observed.grants.length, 0);
  })],
  ['destination approval, capability, revision and selected-key changes invalidate review', async browser => {
    for (const change of [state => { state.allowedUpstreams = []; }, state => { state.xCapability = capability(false); },
      state => { state.xCapability = null; }, state => { state.credentials[0].status = 'revoked'; },
      state => { state.credentials[0].credential_generation++; return false; }, state => { state.applications[0].token_status = 'expired';
        state.applications[0].token_expires_at_epoch_ms = 1; }]) await fixture(browser, {}, async (page, state, observed) => {
        await form(page); await review(page);
        // Key identity must remain exact even if a malformed public source
        // changes its generation without incrementing the catalog revision.
        if (change(state) !== false) state.revision++;
        await refresh(page);
        assert(await page.locator('#connect-grant').isDisabled()); assert.equal(observed.grants.length, 0);
      });
  }],
  ['cross-provider credential markers never inherit the X permission', async browser => {
    await fixture(browser, {credentials: [credential()]}, async (page, state, observed) => {
      await pair(page); assert.notEqual(await page.locator('#connect-operation').inputValue(), BUNDLE);
      assert(await page.locator('#connect-x-username-group').isHidden()); assert.equal(observed.grants.length, 0);
    });
    for (const changes of [{provider_id: 'github'}, {connection_type: 'github_token_v1'}, {auth_type: 'header', header_name: 'X-API-Key'}])
      await fixture(browser, {credentials: [xCredential(changes)]}, async (page, state, observed) => {
        await page.locator('#load-error').waitFor({state: 'visible'}); await view(page, 'connect');
        assert(await page.locator('#connect-use-x').isDisabled()); assert.equal(observed.grants.length, 0);
      });
  }],
  ['a saved response with a different username is not accepted as the reviewed grant', browser => fixture(browser,
    {ruleChange: {username: 'another_user', upstream_url: API + '/2/users/by/username/another_user'}}, async (page, state, observed) => {
      await form(page); await review(page); await page.locator('#connect-grant').click();
      await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
      assert.equal(observed.grants.length, 1); assert(await page.locator('#connect-setup-step').isHidden());
      assert(await page.locator('#connect-grant').isDisabled()); await refresh(page); assert.equal(observed.grants.length, 1);
    })],
  ['revoked saved X access hides client setup without replacing the rule', browser => fixture(browser,
    {rules: [xRule()]}, async (page, state, observed) => {
      await pair(page); await page.locator('#connect-rule-choice').selectOption(IDS.rule); await review(page); await grant(page);
      await recipe(page); state.rules[0].status = 'revoked'; state.revision++; await refresh(page);
      assert(await page.locator('#connect-setup-slot').isHidden()); assert(await page.locator('#copy-command').isDisabled());
      assert.equal(observed.grants.length, 0);
    })],
  ['CAS refusal, storage uncertainty and lost committed response never replay POST', async browser => {
    for (const fault of ['409', '503', 'lost-after-commit']) await fixture(browser, {grantFault: fault}, async (page, state, observed) => {
      await form(page); await review(page); await page.locator('#connect-grant').click(); await noAutomaticWrite(page, observed);
      assert.equal(state.rules.length, fault === 'lost-after-commit' ? 1 : 0); await privateAbsent(page);
    });
  }],
  ['ordinary manual API-key flow remains independent of X presets', browser => ordinaryFixture(browser,
    supplied({credentials: [credential()], applications: [application()], responseModes: ['projected_json', 'unfiltered_json_or_empty_v2']}),
    async (page, state) => {
      await draft(page); assert(await page.locator('#connect-x-username-group').isHidden());
      assert.equal(await page.locator('#connect-operation').inputValue(), 'exact');
      await review(page); await grant(page);
      assert.equal(state.posts.length, 1); assert.equal(state.posts[0].name, 'access-rules');
      assert.equal(state.posts[0].body.upstream_url, UPSTREAM + '/v1/status');
      assert(!Object.hasOwn(state.posts[0].body, 'operation_bundle')); assert.deepEqual(state.posts[0].body.response_fields, []);
    })],
];

async function hashes() {
  const names = ['scripts/test_operator_x_browser.cjs', 'scripts/operator_x_browser_fixture.cjs',
    'scripts/test_operator_catalog_browser.cjs', 'scripts/test_operator_ordinary_modes_browser.cjs',
    'catchplate/operator_demo_portal.py', ...(await readdir(join(ROOT, 'catchplate/operator_demo_web')))
      .filter(name => /\.(?:html|css|js)$/.test(name)).sort().map(name => 'catchplate/operator_demo_web/' + name)];
  return Object.fromEntries(await Promise.all(names.map(async name =>
    [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
async function runSuite(browser) {
  assert(browser && typeof browser.newContext === 'function');
  const before = await hashes(); const directory = await mkdtemp('/tmp/catchplate-x-browser-');
  console.log(JSON.stringify({phase: 'source-before', hashes: before, artifactDirectory: directory}));
  const contexts = new Set(); let timer; let finished = false; let passed = 0;
  const bounded = {async newContext(...args) {
    assert(!finished); const context = await browser.newContext(...args);
    if (finished) { await context.close(); throw new Error('suite finished'); }
    contexts.add(context); context.on('close', () => contexts.delete(context)); return context;
  }};
  try {
    await Promise.race([(async () => { for (const [name, test] of tests) {
      await test(bounded, directory); passed++; console.log('PASS ' + name);
    } })(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('X rendered suite exceeded 180 seconds')), 180000); })]);
    const result = {ok: true, groups: passed, artifactDirectory: directory, backendAcceptance: false,
      sdkExecuted: false, providerRequests: 0, proxyRequests: 0, nativeDownloads: 0, generatedRecipeExecuted: false};
    console.log(JSON.stringify(result)); return result;
  } finally {
    finished = true; clearTimeout(timer); await Promise.all([...contexts].map(context => context.close()));
    assert.deepEqual(await hashes(), before, 'source changed during intercepted X suite');
    console.log(JSON.stringify({phase: 'source-after', sameSource: true, passed}));
  }
}
async function run(page) { return runSuite(page.context().browser()); }
async function main() {
  assert.equal(process.argv.length, 2, 'No live target or execution arguments accepted');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  try { await runSuite(browser); } finally { await browser.close(); }
}
module.exports = {run, runSuite};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

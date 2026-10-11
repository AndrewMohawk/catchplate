#!/usr/bin/env node
// Rendered production UI with intercepted, independently validated synthetic
// catalog responses only. No app, OAuth, provider, proxy, SDK or CA is contacted.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFile, readdir, mkdtemp, writeFile} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {fixture, options, bundleRule} = require('./test_operator_gmail_bundle_browser.cjs');
const {ready, view, openRestrictions, credential, application, rule, IDS} = require('./test_operator_catalog_browser.cjs');
const {pair, step, review, grant, refresh, google, digest} = require('./test_operator_ordinary_modes_browser.cjs');

const ROOT = resolve(__dirname, '..');
const BUNDLE = 'gmail_read_v1';
const DUMMY = 'Bearer serverware-gmail-placeholder-v1';
const CUSTOM = "Bearer synthetic-custom-'literal'-$value";
const BASIC = 'basic_and_bearer_v1';
const GMAIL = 'https://gmail.googleapis.com';
const AUTH = {schema: 'serverware.operatorProxyAuthentication/v1', modes: ['bearer', BASIC],
  path: '/api/operator-demo/applications/proxy-authentication'};
const PROJECT = 'https://github.com/AndrewMohawk/serverware/tree/serverware/operator-workspace/examples/google-gmail-go';
const GUIDE = 'https://github.com/AndrewMohawk/serverware/blob/serverware/operator-workspace/docs/operator-gmail-job-verification.md';
const clone = value => JSON.parse(JSON.stringify(value));
function sdkOptions(changes = {}) {
  const transform = changes.gmailTransform;
  return options({...changes, applications: changes.applications || [application({proxy_authentication: BASIC})],
    gmailTransform(value) {
      value.capabilities.application_proxy_authentication = clone(AUTH);
      return transform ? transform(value) : value;
    }});
}
function noWrites(state, observed) {
  assert.equal(state.posts.length, 0, 'no generic grant, token rotation or proxy-login mutation');
  assert.equal(observed.posts.length, 0, 'no Gmail grant');
}
async function hiddenManualFields(page) {
  for (const id of ['connect-path', 'connect-query-keys', 'connect-request-body-mode', 'connect-response-mode',
    'connect-response-fields', 'connect-credential-input', 'connect-placeholder']) {
    assert(await page.locator('#' + id).isHidden(), id + ' hidden');
    assert(await page.locator('#' + id).isDisabled(), id + ' disabled');
  }
}
async function sdkDraft(page) {
  await pair(page);
  assert.equal(await page.locator('#connect-operation').inputValue(), BUNDLE);
  assert.equal(await page.locator('#connect-gmail-client').inputValue(), 'sdk');
  await hiddenManualFields(page);
}
async function projects(page, expected) {
  await view(page, 'proxy');
  assert.deepEqual(await page.locator('#client-example-links a').evaluateAll(nodes => nodes.map(node => node.href)), expected);
  for (const link of await page.locator('#client-example-links a').all()) {
    assert.equal(await link.getAttribute('target'), '_blank');
    assert.match(await link.getAttribute('rel'), /noopener/);
  }
}
async function shot(page, directory, name) {
  await page.screenshot({path: join(directory, name + '.png'), fullPage: true, mask: [page.locator('#client-token')]});
}

const tests = [
  ['default SDK has no manual dummy or response fields and sends exactly the reviewed fixed grant', async (browser, evidence) =>
    fixture(browser, sdkOptions(), async (page, state, observed) => {
      await sdkDraft(page); noWrites(state, observed);
      assert.equal(await page.locator('#connect-gmail-client option:checked').innerText(), 'Official Gmail SDK');
      assert.match(await page.locator('#connect-gmail-sdk-summary').innerText(), /Authorization: Bearer serverware-gmail-placeholder-v1/);
      assert(await page.locator('#connect-review').isEnabled());
      await shot(page, evidence, 'sdk-permission'); await review(page); noWrites(state, observed);
      const details = await page.locator('#connect-review-details').innerText();
      assert.match(details, /Official Gmail SDK/); assert(details.includes(DUMMY));
      await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await shot(page, evidence, 'sdk-review-mobile'); await grant(page);
      assert.deepEqual(observed.posts, [{name: 'Read Gmail', application_id: IDS.application, credential_id: IDS.credential,
        operation_bundle: BUNDLE, age_policy: {mode: 'unrestricted'}, credential_input: 'replace_exact', placeholder: DUMMY,
        expected_revision: 1, expected_policy_hash: digest(1)}]);
      assert.equal(state.posts.length, 0);
      assert.equal(state.rules[0].query_mode, 'orderedFormV1');
      await projects(page, [PROJECT, GUIDE]);
      assert.match(await page.locator('#gmail-sdk-guidance').innerText(), /has not run the job or tested your account/);
      assert(await page.locator('#download-config').isDisabled(), 'no saved token is retrieved');
      await view(page, 'connect'); await refresh(page); assert.equal(observed.posts.length, 1);
    })],
  ['explicit Custom retains insertion and arbitrary exact public dummy without SDK or Basic authority', async browser => {
    for (const replacement of [false, true]) await fixture(browser, options(), async (page, state, observed) => {
      await sdkDraft(page); assert(await page.locator('#connect-review').isDisabled());
      await page.locator('#connect-gmail-client').selectOption('custom');
      assert(await page.locator('#connect-credential-input').isVisible());
      if (replacement) {
        await page.locator('#connect-credential-input').selectOption('replace_exact');
        await page.locator('#connect-placeholder').fill(CUSTOM);
      }
      await review(page); await grant(page);
      const expected = {name: 'Read Gmail', application_id: IDS.application, credential_id: IDS.credential,
        operation_bundle: BUNDLE, age_policy: {mode: 'unrestricted'}, credential_input: replacement ? 'replace_exact' : 'insert',
        expected_revision: 1, expected_policy_hash: digest(1), ...(replacement ? {placeholder: CUSTOM} : {})};
      assert.deepEqual(observed.posts, [expected]); assert.equal(state.posts.length, 0);
      await projects(page, [GUIDE]);
    });
  }],
  ['saved insertion, custom dummy and pre-query grants are reused unchanged and never upgraded', async browser => {
    const legacy = bundleRule({credential_input: 'replace_exact', placeholder: DUMMY,
      allowed_headers: ['accept', 'accept-encoding', 'user-agent', 'x-goog-api-client']});
    delete legacy.query_mode;
    for (const saved of [bundleRule(), bundleRule({credential_input: 'replace_exact', placeholder: CUSTOM}), legacy])
      await fixture(browser, sdkOptions({rules: [saved]}), async (page, state, observed) => {
        const before = clone(state.rules); await pair(page);
        await page.locator('#connect-rule-choice').selectOption(IDS.rule);
        assert(await page.locator('#connect-gmail-client-group').isHidden());
        await review(page); await grant(page); await projects(page, [GUIDE]);
        assert.deepEqual(state.rules, before); noWrites(state, observed);
        assert.match(await page.locator('#gmail-sdk-guidance').innerText(), /No saved rule is upgraded or widened/);
      });
  }],
  ['missing replacement or missing/malformed Basic capability blocks SDK without fallback', async browser => {
    const variants = [
      {credentialInputModes: ['insert']},
      {gmailTransform(value) { delete value.capabilities.application_proxy_authentication; return value; }},
      {gmailTransform(value) { value.capabilities.application_proxy_authentication.extra = true; return value; }},
      {applications: [application()]},
    ];
    for (const variant of variants) await fixture(browser, sdkOptions(variant), async (page, state, observed) => {
      await sdkDraft(page); assert(await page.locator('#connect-review').isDisabled());
      assert.match(await page.locator('#connect-gmail-sdk-status').innerText(), /advertised|Applications/);
      if (variant.applications) {
        assert.equal(await page.locator('#connect-gmail-sdk-app-link').getAttribute('href'), '#applications');
        assert(await page.locator('#connect-gmail-sdk-app-link').isVisible());
      }
      await refresh(page); assert.equal(await page.locator('#connect-gmail-client').inputValue(), 'sdk');
      assert(await page.locator('#connect-review').isDisabled()); noWrites(state, observed);
    });
  }],
  ['freshly withdrawn SDK prerequisites invalidate an already reviewed grant with no downgrade POST', async browser => {
    const changes = [state => { state.bundles = []; }, state => { state.credentialInputModes = ['insert']; },
      state => { state.gmailTransform = value => { delete value.capabilities.application_proxy_authentication; return value; }; },
      state => { state.applications[0].proxy_authentication = 'bearer'; }];
    for (const change of changes) await fixture(browser, sdkOptions(), async (page, state, observed) => {
      await sdkDraft(page); await review(page); change(state); await refresh(page);
      assert(await page.locator('#connect-grant').isDisabled()); noWrites(state, observed);
      await page.locator('#connect-back').click(); await step(page, 'access');
      assert.equal(await page.locator('#connect-gmail-client').inputValue(), 'sdk');
      assert.equal(await page.locator('#connect-operation').inputValue(), BUNDLE);
      assert(await page.locator('#connect-review').isDisabled()); noWrites(state, observed);
    });
  }],
  ['missing or malformed Gmail descriptor never grants SDK access', async browser => {
    await fixture(browser, sdkOptions({bundles: undefined}), async (page, state, observed) => {
      await pair(page); assert.equal(await page.locator('#connect-operation option[value="gmail_read_v1"]').count(), 0);
      assert(await page.locator('#connect-gmail-client-group').isHidden()); noWrites(state, observed);
    });
    await fixture(browser, sdkOptions({gmailTransform(value) {
      value.capabilities.operation_bundles[0].response_contract.body_presence = 'optional'; return value;
    }}), async (page, state, observed) => {
      await page.locator('#load-error').waitFor({state: 'visible'});
      assert(await page.locator('#connect-use-saved').isDisabled()); noWrites(state, observed);
    });
    // An advertised Google origin outside the approved destination roster is
    // an inconsistent catalog, not a partially admitted SDK configuration.
    await fixture(browser, sdkOptions({allowedUpstreams: ['https://other.example.test']}), async (page, state, observed) => {
      await page.locator('#load-error').waitFor({state: 'visible'});
      assert(await page.locator('#connect-use-saved').isDisabled()); noWrites(state, observed);
    });
    await fixture(browser, sdkOptions(), async (page, state, observed) => {
      await sdkDraft(page); await review(page); state.allowedUpstreams = ['https://other.example.test'];
      await refresh(page); await page.locator('#load-error').waitFor({state: 'visible'});
      assert(await page.locator('#connect-grant').isDisabled()); noWrites(state, observed);
    });
  }],
  ['stale CAS blocks SDK grant until explicit re-review with the fresh revision', async browser =>
    fixture(browser, sdkOptions(), async (page, state, observed) => {
      await sdkDraft(page); await review(page); state.revision++; await refresh(page);
      assert(await page.locator('#connect-grant').isDisabled()); noWrites(state, observed);
      await page.locator('#connect-back').click(); await review(page); await grant(page);
      assert.equal(observed.posts.length, 1); assert.equal(observed.posts[0].expected_revision, 2);
      assert.equal(observed.posts[0].placeholder, DUMMY); assert.equal(state.posts.length, 0);
    })],
  ['uncertain committed SDK grant and failed confirmation never re-POST on refresh', async browser => {
    for (const lost of [true, false]) await fixture(browser, sdkOptions(lost ? {loseReceipt: true} : {failCatalogAfterSave: true}),
      async (page, state, observed) => {
        await sdkDraft(page); await review(page); await page.locator('#connect-grant').click();
        await page.locator(lost ? '#mutation-review' : '#load-error').waitFor({state: 'visible'});
        await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
        assert.equal(observed.posts.length, 1); assert.equal(state.rules.length, 1);
        assert(await page.locator('#connect-grant').isDisabled()); assert(await page.locator('#connect-setup-step').isHidden());
        state.gmailCatalogFailure = false; await refresh(page);
        assert.equal(observed.posts.length, 1); assert.equal(state.posts.length, 0);
        assert.equal(state.rules[0].placeholder, DUMMY);
        if (!lost) await step(page, 'setup');
      });
  }],
  ['SDK/custom, exact draft and provider navigation preserve deliberate choices', async browser =>
    fixture(browser, sdkOptions({credentials: [google(), credential({id: IDS.other})]}), async (page, state, observed) => {
      await sdkDraft(page); await page.locator('#connect-gmail-client').selectOption('custom');
      await page.locator('#connect-credential-input').selectOption('replace_exact'); await page.locator('#connect-placeholder').fill(CUSTOM);
      await page.locator('#connect-operation').selectOption('exact'); await openRestrictions(page, 'connect');
      await page.locator('#connect-path').fill('/gmail/v1/users/me/profile'); await page.locator('#connect-rule-name').fill('My exact draft');
      await page.locator('#connect-response-mode').selectOption('projected_json'); await page.locator('#connect-response-fields').fill('emailAddress');
      await page.locator('#connect-operation').selectOption(BUNDLE); await page.locator('#connect-gmail-client').selectOption('sdk');
      await hiddenManualFields(page); await refresh(page);
      assert.equal(await page.locator('#connect-gmail-client').inputValue(), 'sdk');
      await page.locator('#connect-gmail-client').selectOption('custom');
      assert.equal(await page.locator('#connect-placeholder').inputValue(), CUSTOM);
      await page.locator('#connect-operation').selectOption('exact');
      assert.equal(await page.locator('#connect-path').inputValue(), '/gmail/v1/users/me/profile');
      assert.equal(await page.locator('#connect-rule-name').inputValue(), 'My exact draft');
      assert.equal(await page.locator('#connect-response-fields').inputValue(), 'emailAddress');
      await page.locator('#connect-back').click(); await step(page, 'application');
      await page.locator('#connect-back').click(); await step(page, 'credential');
      await page.locator('#connect-credential-choice').selectOption(IDS.other); await page.locator('#connect-credential-next').click();
      await step(page, 'application'); await page.locator('#connect-application-next').click(); await step(page, 'access');
      assert(await page.locator('#connect-gmail-client-group').isHidden());
      await page.locator('#connect-back').click(); await step(page, 'application');
      await page.locator('#connect-back').click(); await step(page, 'credential');
      await page.locator('#connect-credential-choice').selectOption(IDS.credential); await page.locator('#connect-credential-next').click();
      await step(page, 'application'); await page.locator('#connect-application-next').click(); await step(page, 'access');
      assert.equal(await page.locator('#connect-operation').inputValue(), 'exact');
      await page.locator('#connect-operation').selectOption(BUNDLE);
      assert.equal(await page.locator('#connect-gmail-client').inputValue(), 'custom');
      assert.equal(await page.locator('#connect-placeholder').inputValue(), CUSTOM); noWrites(state, observed);
    })],
  ['saved fixed dummy still requires the assigned Basic app for SDK project discovery', async browser =>
    fixture(browser, sdkOptions({applications: [application()], rules: [bundleRule({credential_input: 'replace_exact', placeholder: DUMMY})]}),
      async (page, state, observed) => {
        await ready(page); const before = clone(state.rules); await projects(page, [GUIDE]);
        assert(await page.locator('#gmail-sdk-app-link').isVisible()); assert(await page.locator('#copy-command').isEnabled());
        assert.match(await page.locator('#gmail-sdk-guidance').innerText(), /explicitly enable/);
        assert.deepEqual(state.rules, before); noWrites(state, observed);
      })],
];

async function hashes() {
  const web = 'serverware/operator_demo_web/';
  const files = ['scripts/test_operator_gmail_sdk_choice_browser.cjs', 'scripts/test_operator_gmail_bundle_browser.cjs',
    'scripts/test_operator_catalog_browser.cjs', 'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py',
    ...(await readdir(join(ROOT, web))).filter(name => /\.(?:js|css|html)$/.test(name)).map(name => web + name)];
  return Object.fromEntries(await Promise.all(files.sort().map(async file =>
    [file, createHash('sha256').update(await readFile(join(ROOT, file))).digest('hex')])));
}
async function run(browser, directory) {
  const before = await hashes(); let finished = 0; let timer;
  await writeFile(join(directory, 'sources-before.json'), JSON.stringify(before, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  try {
    await Promise.race([(async () => {
      for (const [name, test] of tests) {
        await test(browser, directory); finished++; console.log('PASS ' + name);
      }
    })(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('bounded_browser_deadline')), 150000); })]);
  } finally {
    clearTimeout(timer); const after = await hashes();
    await writeFile(join(directory, 'sources-after.json'), JSON.stringify(after, null, 2) + '\n', {flag: 'wx', mode: 0o600});
    assert.deepEqual(after, before, 'source frozen during browser controls');
  }
  const result = {ok: true, groups: finished, liveRequests: 0, providerRequests: 0, sdkExecuted: false,
    scope: 'intercepted rendered UI only; no API-store, proxy, TLS or provider acceptance', artifactDirectory: directory};
  await writeFile(join(directory, 'result.json'), JSON.stringify(result, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  return result;
}
async function main() {
  assert.equal(process.argv.length, 2, 'no target or credential arguments accepted');
  const directory = await mkdtemp('/tmp/serverware-gmail-sdk-choice-');
  console.log(JSON.stringify({artifactDirectory: directory}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  try { console.log(JSON.stringify(await run(browser, directory))); } finally { await browser.close(); }
}
if (require.main === module) main().catch(error => {
  // Fixed class and local frame locations only, never raw browser/API values.
  console.error(JSON.stringify({ok: false, error: error.name,
    frames: String(error.stack).split('\n').filter(line => /test_operator_gmail_sdk_choice_browser\.cjs:\d+:\d+/.test(line))}));
  process.exitCode = 1;
});
module.exports = {run};

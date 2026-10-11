#!/usr/bin/env node
// Rendered production UI with intercepted, independently validated synthetic
// catalog responses and a controlled local shell stub only. No real app, OAuth,
// provider, proxy, SDK or CA is contacted.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {execFile} = require('node:child_process');
const {promisify} = require('node:util');
const vm = require('node:vm');
const {readFile, readdir, mkdtemp, writeFile, stat} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {fixture, options, bundleRule} = require('./test_operator_gmail_bundle_browser.cjs');
const {ready, view, openRestrictions, credential, application, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {pair, step, review, grant, refresh, google, digest, downloadedConfig, publicCatalog} = require('./test_operator_ordinary_modes_browser.cjs');
const {buildCurlCommand} = require('../serverware/operator_demo_web/app.js');

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
const PRIVATE = ['synthetic-gmail-provider-private-never-render', 'synthetic-gmail-refresh-private-never-render'];
const CLIENT_TOKEN = Buffer.alloc(32, 85).toString('base64url');
const executeFile = promisify(execFile);
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
function sdkRule(changes = {}) { return bundleRule({credential_input: 'replace_exact', placeholder: DUMMY, ...changes}); }
async function copiedCommand(page) {
  assert(await page.locator('#copy-command').isEnabled());
  const displayed = await page.locator('#client-command').innerText();
  await page.evaluate(() => navigator.clipboard.writeText('synthetic-before-copy'));
  await page.locator('#copy-command').click();
  await page.waitForFunction(async expected => (await navigator.clipboard.readText()) === expected, displayed);
  assert((await page.locator('#client-copy-status').innerText()).startsWith('Copied'));
  const copied = await page.evaluate(() => navigator.clipboard.readText());
  assert.equal(copied, displayed, 'the real Copy handler writes the displayed complete recipe');
  return copied;
}
async function rotateHeldToken(page, state, controls) {
  // This one synthetic API response needs the real token wire shape. The old
  // generic fixture intentionally uses a noncanonical descriptive token. Keep
  // real UI rotation/hold/reconciliation, with an independent bounded DTO oracle.
  await controls.context.route('**/api/operator-demo/applications/rotate-token', async route => {
    try {
      const request = route.request(); const url = new URL(request.url());
      assert.equal(url.origin, 'https://operator-catalog.example.test'); assert.equal(url.search, '');
      assert.equal(request.method(), 'POST'); assert(request.headers()['content-type'].startsWith('application/json'));
      const bytes = request.postDataBuffer(); assert(bytes && bytes.length <= 2048);
      const body = JSON.parse(bytes.toString());
      assert.deepEqual(body, {id: IDS.application, token_lifetime_seconds: 86400,
        expected_revision: state.revision, expected_policy_hash: state.active});
      assert.equal(state.posts.length, 0);
      state.posts.push({name: 'applications/rotate-token', body});
      state.requests.push({path: url.pathname, query: '', method: 'POST'});
      const app = state.applications.find(value => value.id === IDS.application);
      assert.equal(app.status, 'active'); assert.equal(app.proxy_authentication, BASIC);
      app.token_generation++; app.token_status = 'valid'; app.token_expires_at_epoch_ms = NOW + 86400000;
      state.revision++; state.active = digest(++state.sequence); state.loaded = state.active;
      const catalog = publicCatalog(state);
      await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify({
        application: catalog.applications.find(value => value.id === IDS.application),
        revision: catalog.revision, policy: catalog.policy, client_token: CLIENT_TOKEN})});
    } catch (error) { state.errors.push('synthetic SDK rotation contract: ' + error.name); await route.abort(); }
  });
  await view(page, 'applications');
  const card = page.locator(`#applications-list [data-resource-id="${IDS.application}"]`);
  await card.locator('.application-rotate-ttl').selectOption('86400');
  await card.locator('[data-action="rotate-application"]').click();
  await page.locator('#one-time-access').waitFor({state: 'visible'});
  await page.waitForFunction(() => !document.querySelector('#application-fields').disabled);
  assert.deepEqual(state.posts.map(value => value.name), ['applications/rotate-token']);
  const held = await page.locator('#client-token').inputValue();
  assert.equal(held, CLIENT_TOKEN); return held;
}
async function publicSecretsAbsent(page, command, token = '') {
  const publicText = await page.locator('body').innerText();
  const storage = await page.evaluate(() => JSON.stringify([Object.values(localStorage), Object.values(sessionStorage)]));
  for (const secret of [...PRIVATE, ...(token ? [token] : [])]) {
    assert(!command.includes(secret), 'public recipe never embeds a credential');
    assert(!publicText.includes(secret), 'public text never displays a credential');
    assert(!storage.includes(secret), 'client handoff stores no credential in browser storage');
  }
}
async function sdkHelpers() {
  const source = await readFile(join(ROOT, 'serverware/operator_demo_web/workspace_gmail_sdk.js'), 'utf8');
  return vm.runInNewContext(source + '\n({buildGmailSdkClientRecipe, gmailSdkClientConfiguration});', {}, {timeout: 1000});
}
async function stubDirectory(evidence) {
  const directory = await mkdtemp(join(evidence, 'sdk-shell-stub-'));
  // No SDK, network modules, CA reads or child launches. Inspect only this
  // controlled process, its own input and the reserved parent command line.
  const source = '#!' + process.execPath + '\n' + [
    "const fs = require('node:fs');",
    'const deadline = setTimeout(() => process.exit(97), 2000);',
    "fs.readFile(0, 'utf8', (error, input) => {",
    'if (error || input.length > 1024) process.exit(98); clearTimeout(deadline);',
    "const token = process.env.SERVERWARE_PROXY_TOKEN || '';",
    "const parent = fs.readFileSync('/proc/' + process.ppid + '/cmdline', 'utf8');",
    'process.stdout.write(JSON.stringify({environment: process.env, args: process.argv.slice(2), input,',
    '  tokenInArgv: process.argv.some(value => value.includes(token)), tokenInParentArgv: parent.includes(token)}));',
    '});',
  ].join('\n');
  await writeFile(join(directory, 'gmail-example'), source, {flag: 'wx', mode: 0o700});
  return directory;
}
async function runCopiedRecipe(command, directory, token) {
  const ambient = {PATH: '/usr/bin:/bin', HOME: '/synthetic-home-not-used', SERVERWARE_PROXY_TOKEN: token,
    GOOGLE_APPLICATION_CREDENTIALS: '/synthetic-no-google-credentials', GOOGLE_API_USE_CLIENT_CERTIFICATE: 'true',
    GOOGLE_API_USE_MTLS_ENDPOINT: 'always', GODEBUG: 'synthetic-must-not-reach-client',
    SSL_CERT_FILE: '/synthetic-wrong-roots', SSL_CERT_DIR: '/synthetic-wrong-directory',
    HTTPS_PROXY: 'http://ambient.invalid', HTTP_PROXY: 'http://ambient.invalid', ALL_PROXY: 'http://ambient.invalid',
    NO_PROXY: '*', https_proxy: 'http://ambient.invalid', http_proxy: 'http://ambient.invalid', no_proxy: '*',
    SERVERWARE_PROXY_CA_FILE: '/synthetic-stale-outer-root', SERVERWARE_CA_FILE: '/synthetic-stale-inner-root'};
  return executeFile('/bin/bash', ['--noprofile', '--norc', '-c', command], {
    cwd: directory, env: ambient, timeout: 5000, maxBuffer: 32768, encoding: 'utf8', killSignal: 'SIGKILL'});
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
      assert.match(await page.locator('#gmail-sdk-guidance').innerText(), /has not run it or tested your account/);
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

// The added handoff controls use the same intercepted rendered application.
// A local stub may inspect a copied shell recipe; the real SDK is never run.
const handoffTests = [
  ['SDK handoff pure helpers keep public and private inputs separate and refuse malformed configuration', async () => {
    const helpers = await sdkHelpers();
    const input = {proxyUrl: 'https://proxy.example.test', applicationId: IDS.application, accessRuleId: IDS.rule,
      tokenExpiresAtEpochMs: NOW + 86400000, nowEpochMs: NOW, caPath: './serverware-ca.pem', proxyCaPath: ''};
    const publicRecipe = helpers.buildGmailSdkClientRecipe({...input, token: CLIENT_TOKEN, providerSecret: PRIVATE[0]});
    assert(!publicRecipe.includes(CLIENT_TOKEN)); assert(!publicRecipe.includes(PRIVATE[0]));
    const config = clone(helpers.gmailSdkClientConfiguration(input, CLIENT_TOKEN));
    assert.deepEqual(config, {schema: 'serverware.gmailSdkClient/v1', example_directory: 'examples/google-gmail-go',
      entrypoint: './gmail-example', clear_environment: true, environment: {LANG: 'C.UTF-8',
        SERVERWARE_PROXY_URL: input.proxyUrl, SERVERWARE_APP_ID: IDS.application,
        SERVERWARE_CA_FILE: input.caPath, SERVERWARE_PROXY_TOKEN: CLIENT_TOKEN},
      token_expires_at_epoch_ms: input.tokenExpiresAtEpochMs, access_rule_id: IDS.rule});
    for (const [key, values] of [
      ['proxyUrl', ['http://proxy.example.test', 'https://user:password@proxy.example.test',
        'https://proxy.example.test/path', 'https://proxy.example.test/?q=1', 'https://proxy.example.test/#fragment',
        'https://gmail.googleapis.com', 'https://127.0.0.1', 'https://proxy.local', 'https://proxy.example.test:65536']],
      ['applicationId', ['', 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA', IDS.application + "'", null]],
      ['accessRuleId', ['', '../rule', null]],
      ['tokenExpiresAtEpochMs', [NOW, NOW - 1, null, String(NOW + 1), Infinity]],
      ['nowEpochMs', [0, -1, null, 1.5]],
      ['caPath', ['', 'inner\nroot.pem', 'inner\0root.pem', 'x'.repeat(513), null]],
      ['proxyCaPath', ['outer\rroot.pem', 'outer\x7froot.pem', 'x'.repeat(513), null]],
    ]) for (const value of values) {
      assert.throws(() => helpers.buildGmailSdkClientRecipe({...input, [key]: value}), key);
      assert.throws(() => helpers.gmailSdkClientConfiguration({...input, [key]: value}, CLIENT_TOKEN), key);
    }
    for (const value of ['', CLIENT_TOKEN + 'A', CLIENT_TOKEN.slice(0, -1) + 'B', 'bad\nvalue', PRIVATE[0], null])
      assert.throws(() => helpers.gmailSdkClientConfiguration(input, value));
    const distinct = helpers.gmailSdkClientConfiguration(input, CLIENT_TOKEN);
    distinct.environment.SERVERWARE_APP_ID = IDS.other;
    assert.equal(helpers.gmailSdkClientConfiguration(input, CLIENT_TOKEN).environment.SERVERWARE_APP_ID, IDS.application);
  }],
  ['SDK handoff actual Copy executes only the local stub with quoted roots, clean env and private stdin token', async (browser, evidence) => {
    const directory = await stubDirectory(evidence); const marker = join(directory, 'must-not-exist');
    const inner = "./interception's $(touch " + marker + ').pem';
    const outer = "./proxy's `touch " + marker + '` $HOME.pem';
    await fixture(browser, sdkOptions({rules: [sdkRule()]}), async (page, state, observed) => {
      await ready(page); await view(page, 'proxy');
      assert(await page.locator('#gmail-sdk-client-controls').isVisible());
      assert(await page.locator('#gmail-client-controls').isHidden());
      assert(await page.locator('#proxy-method').isHidden()); assert(await page.locator('#proxy-method').isDisabled());
      assert(await page.locator('#gmail-message-id').isHidden());
      assert(await page.locator('#download-config').isDisabled(), 'saved tokens are never retrieved');
      await page.locator('#ca-path').fill('');
      assert(await page.locator('#copy-command').isDisabled(), 'no missing inner root fallback');
      await page.locator('#ca-path').fill(inner); await page.locator('#gmail-proxy-ca-path').fill(outer);
      const command = await copiedCommand(page);
      assert(command.includes('./gmail-example')); assert(!command.includes('curl '));
      assert(!/--insecure|--proxy-insecure|InsecureSkipVerify/.test(command));
      await publicSecretsAbsent(page, command, CLIENT_TOKEN);
      const {stdout, stderr} = await runCopiedRecipe(command, directory, CLIENT_TOKEN);
      assert.equal(stderr, '');
      assert.deepEqual(JSON.parse(stdout), {environment: {LANG: 'C.UTF-8', SERVERWARE_PROXY_URL: 'https://proxy.example.test',
        SERVERWARE_APP_ID: IDS.application, SERVERWARE_CA_FILE: inner, SERVERWARE_PROXY_CA_FILE: outer,
        SERVERWARE_PROXY_TOKEN: CLIENT_TOKEN}, args: [], input: '', tokenInArgv: false, tokenInParentArgv: false});
      await assert.rejects(stat(marker), {code: 'ENOENT'});
      // Clearing the optional outer root means system roots, never inheritance
      // from the poisoned ambient SERVERWARE_PROXY_CA_FILE or SSL settings.
      await page.locator('#gmail-proxy-ca-path').fill('');
      const defaultRoots = await runCopiedRecipe(await copiedCommand(page), directory, CLIENT_TOKEN);
      assert.equal(defaultRoots.stderr, '');
      const expected = {LANG: 'C.UTF-8', SERVERWARE_PROXY_URL: 'https://proxy.example.test',
        SERVERWARE_APP_ID: IDS.application, SERVERWARE_CA_FILE: inner, SERVERWARE_PROXY_TOKEN: CLIENT_TOKEN};
      assert.deepEqual(JSON.parse(defaultRoots.stdout).environment, expected);
      for (const token of ['', 'bad-token', CLIENT_TOKEN + '\n']) {
        await assert.rejects(runCopiedRecipe(command, directory, token), error => {
          assert.equal(error.code, 1); assert.equal(error.stdout, '');
          assert.equal(error.stderr, 'Set the issued Serverware application token privately\n'); return true;
        });
      }
      await page.setViewportSize({width: 390, height: 844});
      assert(await page.locator('#gmail-sdk-client-controls').isVisible());
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await shot(page, evidence, 'sdk-handoff-mobile'); noWrites(state, observed);
    });
  }],
  ['SDK handoff actual private Download matches the held generation and clears on expiry or dismissal', async browser =>
    fixture(browser, sdkOptions({rules: [sdkRule()]}), async (page, state, observed, controls) => {
      await ready(page); const held = await rotateHeldToken(page, state, controls); await view(page, 'proxy');
      const inner = "./inner's literal $name.pem"; const outer = "./outer's literal $name.pem";
      await page.locator('#ca-path').fill(inner); await page.locator('#gmail-proxy-ca-path').fill(outer);
      assert(await page.locator('#download-config').isEnabled());
      const command = await copiedCommand(page); await publicSecretsAbsent(page, command, held);
      const downloadEvent = page.waitForEvent('download');
      const config = await downloadedConfig(page);
      assert.equal((await downloadEvent).suggestedFilename(), 'serverware-client.private.json');
      assert.equal(config.proxy_authentication, BASIC); assert.equal(config.proxy_username, IDS.application);
      assert.equal(config.proxy_password, held); assert.equal(config.ca_file, inner); assert.equal(config.proxy_ca_file, outer);
      assert.deepEqual(config.request_headers, {Authorization: DUMMY});
      assert.deepEqual(config.client_recipe, {schema: 'serverware.gmailSdkClient/v1',
        example_directory: 'examples/google-gmail-go', entrypoint: './gmail-example', clear_environment: true,
        environment: {LANG: 'C.UTF-8', SERVERWARE_PROXY_URL: 'https://proxy.example.test', SERVERWARE_APP_ID: IDS.application,
          SERVERWARE_CA_FILE: inner, SERVERWARE_PROXY_CA_FILE: outer, SERVERWARE_PROXY_TOKEN: held},
        token_expires_at_epoch_ms: state.applications[0].token_expires_at_epoch_ms, access_rule_id: IDS.rule});
      for (const secret of PRIVATE) assert(!JSON.stringify(config).includes(secret));
      await view(page, 'applications'); await page.locator('#dismiss-token').click(); await view(page, 'proxy');
      assert(await page.locator('#download-config').isDisabled()); assert(await page.locator('#copy-command').isEnabled());
      state.applications[0].token_expires_at_epoch_ms = NOW; await refresh(page, 'proxy-refresh');
      assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
      assert.equal(state.posts.length, 1); assert.equal(observed.posts.length, 0);
    })],
  ['SDK handoff forgets a held token whose catalog generation or original expiry changed', async browser => {
    for (const change of [state => { state.applications[0].token_generation++; },
      state => { state.applications[0].token_expires_at_epoch_ms = NOW; }]) {
      await fixture(browser, sdkOptions({rules: [sdkRule()]}), async (page, state, observed, controls) => {
        await ready(page); await rotateHeldToken(page, state, controls); await view(page, 'proxy');
        assert(await page.locator('#download-config').isEnabled());
        change(state); await refresh(page, 'proxy-refresh');
        assert(await page.locator('#download-config').isDisabled());
        assert.equal(await page.locator('#client-token').inputValue(), '');
        assert.equal(state.posts.length, 1); assert.equal(observed.posts.length, 0);
      });
    }
  }],
  ['SDK handoff preserves the legacy cURL bytes for every non-SDK Gmail choice', async browser => {
    const legacy = sdkRule({allowed_headers: ['accept', 'accept-encoding', 'user-agent', 'x-goog-api-client']});
    delete legacy.query_mode;
    for (const [saved, app] of [[bundleRule(), application({proxy_authentication: BASIC})],
      [bundleRule({credential_input: 'replace_exact', placeholder: CUSTOM}), application({proxy_authentication: BASIC})],
      [legacy, application({proxy_authentication: BASIC})], [sdkRule(), application()]]) {
      await fixture(browser, sdkOptions({rules: [saved], applications: [app]}), async (page, state, observed) => {
        await ready(page); const before = clone(state.rules); await view(page, 'proxy');
        assert(await page.locator('#gmail-sdk-client-controls').isHidden());
        assert(await page.locator('#gmail-client-controls').isVisible());
        assert(await page.locator('#proxy-method').isVisible());
        const inputs = {proxyUrl: 'https://proxy.example.test', upstreamUrl: saved.upstream_url,
          method: 'GET', caPath: './serverware-ca.pem', allowedHeaders: saved.allowed_headers,
          credentialInput: saved.credential_input, placeholder: saved.placeholder, credential: google(),
          proxyAuthentication: app.proxy_authentication || 'bearer', applicationId: IDS.application};
        assert.equal(await copiedCommand(page), buildCurlCommand(inputs));
        await page.locator('#gmail-client-operation').selectOption('message');
        assert(await page.locator('#copy-command').isDisabled(), 'a real returned message ID is still required');
        await page.locator('#gmail-message-id').fill('synthetic_message_1');
        assert.equal(await copiedCommand(page), buildCurlCommand({...inputs,
          upstreamUrl: saved.upstream_url + '/synthetic_message_1'}));
        assert.deepEqual(state.rules, before); noWrites(state, observed);
      });
    }
  }],
  ['SDK handoff requires current loaded policy, valid app expiry and active credential', async browser => {
    const changes = [
      state => { state.loaded = digest(0); },
      state => { state.activationOverride = 'pending'; },
      state => { state.applications[0].token_status = 'expired'; },
      state => { state.applications[0].token_expires_at_epoch_ms = NOW; },
      state => { state.applications[0].token_status = 'revoked'; },
      state => { state.credentials[0].status = 'revoked'; },
    ];
    for (const change of changes) await fixture(browser, sdkOptions({rules: [sdkRule()]}), async (page, state, observed) => {
      await ready(page); await view(page, 'proxy');
      assert(await page.locator('#gmail-sdk-client-controls').isVisible());
      assert(await page.locator('#copy-command').isEnabled());
      change(state); await refresh(page, 'proxy-refresh');
      assert(await page.locator('#copy-command').isDisabled());
      assert(await page.locator('#download-config').isDisabled());
      noWrites(state, observed);
    });
  }],
  ['SDK handoff cannot copy or export a saved but uncertain grant', async browser =>
    fixture(browser, sdkOptions({loseReceipt: true}), async (page, state, observed) => {
      await sdkDraft(page); await review(page); await page.locator('#connect-grant').click();
      await page.locator('#mutation-review').waitFor({state: 'visible'});
      await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
      await refresh(page); await view(page, 'proxy');
      assert.equal(observed.posts.length, 1); assert.equal(state.rules.length, 1);
      assert.equal(state.active, state.loaded, 'synthetic policy loading alone does not clear uncertainty');
      assert(await page.locator('#copy-command').isDisabled());
      assert(await page.locator('#download-config').isDisabled());
      await refresh(page, 'proxy-refresh');
      assert.equal(observed.posts.length, 1); assert.equal(state.posts.length, 0);
      assert(await page.locator('#copy-command').isDisabled());
    })],
];
tests.push(...handoffTests);

async function hashes() {
  const web = 'serverware/operator_demo_web/';
  const files = ['scripts/test_operator_gmail_sdk_choice_browser.cjs', 'scripts/test_operator_gmail_bundle_browser.cjs',
    'scripts/test_operator_catalog_browser.cjs', 'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py',
    ...(await readdir(join(ROOT, web))).filter(name => /\.(?:js|css|html)$/.test(name)).map(name => web + name)];
  return Object.fromEntries(await Promise.all(files.sort().map(async file =>
    [file, createHash('sha256').update(await readFile(join(ROOT, file))).digest('hex')])));
}
async function run(browser, directory, selected = tests) {
  const before = await hashes(); let finished = 0; let timer;
  await writeFile(join(directory, 'sources-before.json'), JSON.stringify(before, null, 2) + '\n', {flag: 'wx', mode: 0o600});
  try {
    await Promise.race([(async () => {
      for (const [name, test] of selected) {
        await test(browser, directory); finished++; console.log('PASS ' + name);
      }
    })(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('bounded_browser_deadline')), 150000); })]);
  } finally {
    clearTimeout(timer); const after = await hashes();
    await writeFile(join(directory, 'sources-after.json'), JSON.stringify(after, null, 2) + '\n', {flag: 'wx', mode: 0o600});
    assert.deepEqual(after, before, 'source frozen during browser controls');
  }
  const result = {ok: true, groups: finished, liveRequests: 0, providerRequests: 0, sdkExecuted: false,
    scope: 'intercepted rendered UI and local shell stub only; no API-store, SDK, proxy, TLS or provider acceptance', artifactDirectory: directory};
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
module.exports = {run, runFocused: (browser, directory) => run(browser, directory, handoffTests)};

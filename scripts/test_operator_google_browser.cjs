#!/usr/bin/env node
// Public Google account presentation only. No consent, cleanup, provider request,
// live proxy, generated command execution, or native HTTP download is exercised.
// Secret-like fixture extras test allowlisted display; they do not assert that a
// real backend would return provider secrets in its public catalog.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFileSync} = require('node:fs');
const {readFile, mkdtemp, stat} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {runInNewContext} = require('node:vm');
const {fixture, ready, view, credential, application, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');

const ROOT = resolve(__dirname, '..');
const SCOPES = ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'];
const ACCOUNT = 'operator-fixture@example.test';
const SUBJECT = 'synthetic-google-subject';
const CLIENT = 'synthetic-client.apps.googleusercontent.com';
const DUMMY = "Bearer GOOGLE-DUMMY-'literal'-$value";
const PRIVATE = ['synthetic-google-access-private-NEVER-RENDER', 'synthetic-google-refresh-private-NEVER-RENDER',
  'synthetic-google-client-secret-NEVER-RENDER', 'synthetic-google-ciphertext-NEVER-RENDER'];
const STATIC_ID = '66666666-6666-4666-8666-666666666666';
const FORMER_RULE_ID = '77777777-7777-4777-8777-777777777777';
const ACTIVE_CARD_TEST = 'Google card shows account, friendly permission and app names with one optional Details disclosure';
const QUARANTINED_CARD_TEST = 'quarantine stays visibly unusable while former assignments and technical metadata stay in Details';
const UNKNOWN_PRESET_TEST = 'malformed public Google metadata: unknown permission preset';
const capabilities = {responseModes: ['projected_json', 'unfiltered_json'], credentialInputModes: ['insert', 'replace_exact']};
const digest = n => 'sha256:' + n.toString(16).padStart(64, '0');
const google = (changes = {}) => credential({name: 'Saved test Google account', auth_type: 'google_oauth', header_name: 'Authorization',
  provider_account: ACCOUNT, provider_subject: SUBJECT, oauth_client_id: CLIENT, permission_preset: 'gmail_readonly', scopes: [...SCOPES], ...changes});
const quarantine = (changes = {}) => google({status: 'quarantined', quarantined_at: new Date(NOW).toISOString(),
  quarantine_reason: 'operator_google_cleanup_fence', provider_revocation_status: 'not_proven', ...changes});
const googleRule = (mode = 'replace_exact', changes = {}) => rule({name: 'Read Gmail profile',
  upstream_url: 'https://gmail.googleapis.com/gmail/v1/users/me/profile', response_mode: 'unfiltered_json', response_fields: [],
  credential_input: mode, ...(mode === 'replace_exact' ? {placeholder: DUMMY} : {}), ...changes});
const supplied = (changes = {}) => ({...capabilities, credentials: [google()], applications: [application()], ...changes});
const accountCard = page => page.locator('#credentials-list [data-resource-id="' + IDS.credential + '"][data-credential-type="google_oauth"]');
const INPUTS = ['scripts/test_operator_google_browser.cjs', 'scripts/test_operator_catalog_browser.cjs', 'serverware/operator_demo_portal.py',
  ...['index.html', 'style.css', 'app.js', 'workspace_core.js', 'workspace_applications.js', 'workspace_resources.js',
    'workspace_proxy_audit.js', 'workspace_connect.js', 'workspace_google.js'].map(name => 'serverware/operator_demo_web/' + name)];
let artifacts;

async function hashes() { return Object.fromEntries(await Promise.all(INPUTS.map(async name =>
  [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')]))); }
async function screenshot(page, name) {
  if (!artifacts) return;
  await page.evaluate(() => window.scrollTo({top: 0, left: 0, behavior: 'instant'}));
  await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true});
}
async function privateAbsent(page) {
  const surfaces = await page.evaluate(() => [document.documentElement.outerHTML,
    ...[...document.querySelectorAll('input,textarea')].map(item => item.value)].join('\n'));
  for (const value of PRIVATE) assert(!surfaces.includes(value), 'provider-private fixture extra must not enter DOM, source or form values');
}
async function refresh(page) {
  const response = page.waitForResponse(value => new URL(value.url()).pathname === '/api/operator-demo/catalog');
  await page.locator('#connect-status-refresh').click(); await response; await page.waitForLoadState('networkidle');
}
async function useGoogle(page) {
  await ready(page); await view(page, 'connect'); await page.locator('#connect-use-saved').click();
  await page.locator('#connect-credential-choice').selectOption(IDS.credential);
  await page.locator('#connect-credential-next').click(); await page.locator('#connect-application-step').waitFor({state: 'visible'});
  await page.locator('#connect-application-choice').selectOption(IDS.application); await page.locator('#connect-application-next').click();
  await page.locator('#connect-access-step').waitFor({state: 'visible'});
}
async function reviewSaved(page) {
  await page.locator('#connect-rule-choice').selectOption(IDS.rule); await page.locator('#connect-review').click();
  await page.locator('#connect-review-step').waitFor({state: 'visible'});
}
async function configured(page) {
  await page.locator('#connect-grant').click(); await page.locator('#connect-setup-slot').waitFor({state: 'visible'});
  await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  assert.equal(await page.locator('#proxy-rule').inputValue(), IDS.rule);
  assert.match(await page.locator('#connect-provider-status').innerText(), /saved metadata only.*has not tested consent, token refresh or a Google request.*connection remains disabled/is);
}
function quarantineState(state) {
  state.credentials[0] = quarantine(); for (const value of state.rules) if (value.credential_id === IDS.credential) value.status = 'revoked';
  state.revision++; state.active = state.loaded = digest(++state.sequence);
}
async function unavailable(page, state) {
  await page.locator('#load-error').waitFor({state: 'visible'});
  assert(await page.locator('#credential-save').isDisabled()); assert(await page.locator('#application-create').isDisabled());
  assert(await page.locator('#rule-save').isDisabled()); assert(await page.locator('#connect-credential-next').isDisabled());
  await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
  assert.equal(state.posts.length, 0); await privateAbsent(page);
}
function generatorChecks() {
  const {credentialHeaderTarget, clientCredentialInput, buildCurlCommand} = require('../serverware/operator_demo_web/app.js');
  assert.equal(credentialHeaderTarget(google()), 'Authorization');
  assert.equal(clientCredentialInput({credentialInput: 'insert', credential: google()}), null);
  assert.deepEqual(clientCredentialInput({credentialInput: 'replace_exact', placeholder: DUMMY, credential: google()}), {name: 'Authorization', value: DUMMY});
  for (const header_name of ['X-API-Key', 'authorization', 'Proxy-Authorization']) assert.throws(() => credentialHeaderTarget(google({header_name})));
  const command = buildCurlCommand({proxyUrl: 'https://proxy.example.test', upstreamUrl: googleRule().upstream_url, method: 'GET',
    credentialInput: 'replace_exact', placeholder: DUMMY, credential: google({access_token: PRIVATE[0], refresh_token: PRIVATE[1]})});
  assert(command.includes("Authorization: Bearer GOOGLE-DUMMY-'\\''literal'\\''-$value"));
  assert(command.includes('Proxy-Authorization: Bearer $SERVERWARE_PROXY_TOKEN')); assert(command.includes('--cacert'));
  for (const value of PRIVATE) assert(!command.includes(value));
  const resources = readFileSync(join(ROOT, 'serverware/operator_demo_web/workspace_resources.js'), 'utf8');
  const permission = input => runInNewContext(resources + '\noperatorGooglePermission(input)', {input}, {timeout: 1000});
  assert.equal(permission(google()), 'Read Gmail');
  for (const permission_preset of ['gmail_full_access', '', null, undefined])
    assert.equal(permission(google({permission_preset})), 'Unsupported permission preset');
  return {ok: true, groups: 1, scope: 'pure Google header target, safe command generation and defensive permission labels; commands never executed'};
}

const malformed = [
  ['missing account', {provider_account: undefined}], ['empty account', {provider_account: ''}],
  ['control character in account', {provider_account: ACCOUNT + '\n'}], ['missing subject', {provider_subject: undefined}],
  ['missing OAuth client ID', {oauth_client_id: undefined}], ['unrecognized OAuth client ID', {oauth_client_id: 'not-a-google-client'}],
  ['nonarray scopes', {scopes: 'openid'}], ['changed permission scope', {scopes: ['email', 'https://www.googleapis.com/auth/gmail.modify', 'openid']}],
  ['duplicate scope', {scopes: ['email', 'email', 'openid']}], ['unknown permission preset', {permission_preset: 'gmail_full_access'}],
  ['wrong provider header', {header_name: 'X-API-Key'}], ['ordinary revoked Google status', {status: 'revoked'}],
  ['missing quarantine timestamp', {...quarantine(), quarantined_at: undefined}],
  ['invalid quarantine timestamp', {...quarantine(), quarantined_at: 'not-a-date'}],
  ['missing quarantine reason', {...quarantine(), quarantine_reason: undefined}],
  ['false provider-revocation success', {...quarantine(), provider_revocation_status: 'revoked'}],
];

const tests = [
  [ACTIVE_CARD_TEST, browser => fixture(browser,
    supplied({credentials: [google(), credential({id: STATIC_ID, name: 'Separate static key'})],
      applications: [application(), application({id: IDS.other, name: 'Former worker'})],
      rules: [googleRule(), googleRule('insert', {id: FORMER_RULE_ID, route_id: 'operator.' + FORMER_RULE_ID,
        application_id: IDS.other, status: 'revoked'})]}), async (page, state) => {
      await ready(page); await view(page, 'credentials'); const card = accountCard(page); await card.waitFor({state: 'visible'});
      const details = card.locator('[data-google-identity]'); assert.equal(await card.locator('details').count(), 1);
      assert.equal(await details.locator('summary').innerText(), 'Details'); assert(!await details.evaluate(item => item.open));
      const text = await card.innerText(); for (const value of [ACCOUNT, 'Read Gmail', 'Assigned apps', 'Reporting application']) assert(text.includes(value));
      for (const value of ['gmail_readonly', ...SCOPES, SUBJECT, CLIENT, IDS.credential, IDS.application, IDS.other, 'Former worker'])
        assert(!text.includes(value), 'technical or former-assignment detail must not appear on the compact card');
      assert.match(await card.locator('[data-google-account-notice]').innerText(), /refresh health not checked.*do not confirm proxy activation/is);
      assert.equal(await card.locator('[data-action="revoke-credential"]').count(), 0);
      const staticCard = page.locator('#credentials-list [data-resource-id="' + STATIC_ID + '"]');
      assert.match(await staticCard.innerText(), /Authentication\s+Bearer token/); assert((await staticCard.innerText()).includes(STATIC_ID));
      assert(!await staticCard.locator('[data-action="revoke-credential"]').isDisabled());
      assert(await page.locator('#credential-google-connect').isDisabled()); await screenshot(page, 'google-account-desktop');
      await details.locator('summary').click(); assert(await details.evaluate(item => item.open));
      const detailText = await details.innerText();
      for (const value of ['gmail_readonly', ...SCOPES, SUBJECT, CLIENT, IDS.credential, IDS.application, IDS.other, 'Former worker'])
        assert(detailText.includes(value), 'Details retains exact metadata and assignment identities');
      assert.match(detailText, /saved active assignments\s+reporting application/i);
      assert.match(detailText, /former assignments\s+former worker/i);
      await details.locator('summary').click(); assert(!await details.evaluate(item => item.open));
      assert(!(await card.innerText()).includes(SUBJECT));
      await page.setViewportSize({width: 390, height: 844});
      assert(await details.locator('summary').isVisible());
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'compact account view fits mobile width');
      await screenshot(page, 'google-account-mobile');
      await view(page, 'connect'); assert(await page.locator('#connect-google').isDisabled());
      await page.locator('#connect-use-saved').click();
      assert((await page.locator('#connect-credential-choice option[value="' + IDS.credential + '"]').innerText()).includes(ACCOUNT));
      await page.locator('#connect-credential-choice').selectOption(IDS.credential);
      assert((await page.locator('#connect-google-account-summary').innerText()).includes(ACCOUNT));
      assert.equal(state.posts.length, 0);
    })],
  ['Google replacement uses the fixed Authorization header and full Bearer dummy hint in both editors', browser => fixture(browser, supplied(), async (page, state) => {
    await ready(page); await view(page, 'access-rules'); await page.locator('#rule-credential-input').selectOption('replace_exact');
    assert.equal(await page.locator('#rule-credential-header').innerText(), 'Authorization');
    assert.equal(await page.locator('#rule-placeholder').getAttribute('placeholder'), 'Bearer SERVERWARE_DUMMY');
    await useGoogle(page); await page.locator('#connect-credential-input').selectOption('replace_exact');
    assert.equal(await page.locator('#connect-header-target').innerText(), 'Authorization');
    assert.equal(await page.locator('#connect-placeholder').getAttribute('placeholder'), 'Bearer SERVERWARE_DUMMY');
    assert.equal(state.posts.length, 0);
  })],
  ...['insert', 'replace_exact'].map(mode => ['active saved Google ' + mode + ' rule produces a separate application-auth connection template', browser => fixture(browser,
    supplied({rules: [googleRule(mode)]}), async (page, state) => {
      await useGoogle(page); await reviewSaved(page); await configured(page);
      const command = await page.locator('#client-command').innerText();
      assert(command.includes('Proxy-Authorization: Bearer $SERVERWARE_PROXY_TOKEN'));
      assert.equal(command.includes("--header 'Authorization:"), mode === 'replace_exact');
      if (mode === 'replace_exact') assert(command.includes("Authorization: Bearer GOOGLE-DUMMY-'\\''literal'\\''-$value"));
      assert(await page.locator('#download-config').isDisabled(), 'existing application token is not retrieved');
      assert.equal(state.posts.length, 0); await privateAbsent(page);
    })]),
  ['secret-like extra API fields never enter DOM, embedded page source or private client configuration', browser => fixture(browser,
    supplied({applications: [], credentials: [google({access_token: PRIVATE[0], refresh_token: PRIVATE[1], client_secret: PRIVATE[2],
      encrypted_value: PRIVATE[3], secret: PRIVATE[0], metadata: {refresh_token: PRIVATE[1]}})]}), async (page, state) => {
      await ready(page); await view(page, 'credentials'); await privateAbsent(page); await view(page, 'applications');
      await page.locator('#application-name').fill('Synthetic Google client'); await page.locator('#application-token-ttl').selectOption('3600');
      await page.locator('#application-create').click(); await ready(page);
      await page.locator('#one-time-access').waitFor({state: 'visible'}); const held = await page.locator('#client-token').inputValue();
      assert(held.startsWith('synthetic_application_'));
      // Supply a public saved-rule observation, not a mock Google rule admission.
      state.rules.push(googleRule()); state.revision++; state.active = state.loaded = digest(++state.sequence);
      await view(page, 'connect'); await refresh(page); await useGoogle(page); await reviewSaved(page); await configured(page); await privateAbsent(page);
      const pending = page.waitForEvent('download'); await page.locator('#download-config').click(); const download = await pending;
      assert(download.url().startsWith('blob:'), 'native HTTP downloads are prohibited');
      const stream = await download.createReadStream(); const chunks = []; let bytes = 0;
      for await (const chunk of stream) { bytes += chunk.length; assert(bytes <= 16384); chunks.push(chunk); }
      const contents = Buffer.concat(chunks).toString(); const config = JSON.parse(contents);
      assert.equal(config.proxy_authorization, 'Bearer ' + held); assert.deepEqual(config.request_headers, {Authorization: DUMMY});
      assert.equal(config.credential_input, 'replace_exact'); for (const value of PRIVATE) assert(!contents.includes(value));
      assert(!contents.includes(SUBJECT) && !contents.includes(CLIENT), 'client setup does not need provider account identifiers');
      await download.delete(); assert.deepEqual(state.posts.map(item => item.name), ['applications']);
    })],
  [QUARANTINED_CARD_TEST, browser => fixture(browser,
    supplied({credentials: [quarantine()], rules: [googleRule('replace_exact', {status: 'revoked'})]}), async (page, state) => {
      await ready(page); await view(page, 'credentials'); const card = accountCard(page);
      assert.match(await card.locator('.badge').innerText(), /quarantined.*unusable/i);
      assert.match(await card.locator('[data-google-account-notice]').innerText(), /unavailable for use.*google revocation is not proven.*health.*activation.*not confirmed/is);
      const text = await card.innerText(); assert.match(text, /assigned apps\s+none/i); assert(text.includes('Read Gmail'));
      for (const value of ['Former assignments', 'Reporting application', 'gmail_readonly', SUBJECT, CLIENT, IDS.application]) assert(!text.includes(value));
      assert.equal(await card.locator('[data-action]').count(), 0); assert.equal(await card.locator('details').count(), 1);
      const details = card.locator('[data-google-identity]'); assert(!await details.evaluate(item => item.open));
      await details.locator('summary').click(); assert.match(await details.innerText(), /provider revocation\s+not proven/i);
      assert.match(await details.innerText(), /former assignments\s+reporting application/i); assert((await details.innerText()).includes(IDS.application));
      await details.locator('summary').click(); assert(!await details.evaluate(item => item.open));
      await screenshot(page, 'google-quarantine-desktop'); await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'compact quarantine view fits mobile width');
      await screenshot(page, 'google-quarantine-mobile');
      await view(page, 'access-rules'); assert(await page.locator('#rule-save').isDisabled());
      assert.equal(await page.locator('#rule-credential-id option[value="' + IDS.credential + '"]').count(), 0);
      await view(page, 'connect'); assert.equal(await page.locator('#connect-credential-choice option[value="' + IDS.credential + '"]').count(), 0);
      await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
      assert.equal(state.posts.length, 0);
    })],
  ['quarantining the selected account at step one preserves the unavailable choice and cannot resubmit it', browser => fixture(browser,
    supplied({credentials: [google(), credential({id: STATIC_ID})]}), async (page, state) => {
      await ready(page); await page.locator('#connect-use-saved').click();
      await page.locator('#connect-credential-choice').selectOption(IDS.credential); quarantineState(state); await refresh(page);
      assert.equal(await page.locator('#connect-credential-choice').inputValue(), IDS.credential);
      assert(await page.locator('#connect-credential-choice option:checked').evaluate(item => item.disabled));
      assert(await page.locator('#connect-credential-next').isDisabled());
      assert.match(await page.locator('#connect-google-account-summary').innerText(), /quarantined.*unavailable/is); assert.equal(state.posts.length, 0);
    })],
  ...['review', 'setup'].map(stage => ['quarantine during selected Google ' + stage + ' disables the exact workflow without switching accounts', browser => fixture(browser,
    supplied({credentials: [google(), credential({id: STATIC_ID})], rules: [googleRule()]}), async (page, state) => {
      await useGoogle(page); await reviewSaved(page); if (stage === 'setup') await configured(page);
      quarantineState(state); await refresh(page);
      assert.match(await page.locator('#connect-google-account-summary').innerText(), /quarantined.*not proven/is);
      if (stage === 'review') assert(await page.locator('#connect-grant').isDisabled());
      else {
        assert(!await page.locator('#connect-setup-slot').isVisible());
        assert.match(await page.locator('#connect-provider-status').innerText(), /quarantined and unavailable.*provider revocation is not proven.*does not start consent or cleanup/is);
      }
      assert.equal(state.posts.length, 0);
    })]),
  ['quarantined Google account with a contradictory active assignment fails the whole catalog closed', browser => fixture(browser,
    supplied({credentials: [quarantine()], rules: [googleRule()]}), unavailable)],
  ['a false public zero count cannot conceal an active rule referencing a quarantined Google account', browser => fixture(browser,
    supplied({credentials: [quarantine()], rules: [googleRule('replace_exact', {status: 'revoked'})]}), async (page, state, {context}) => {
      await ready(page); // Nearby control: quarantined account with only revoked references is accepted.
      const endpoint = 'https://operator-catalog.example.test/api/operator-demo/catalog'; let calls = 0;
      const observed = {schema: 'serverware.operatorCatalog/v1', mode: 'operator-development', productionReady: false,
        hardwareVerified: false, revision: 2, policy: {policy_hash: digest(1), loaded_policy_hash: digest(1), sequence: 1, activation: 'active'},
        proxy_url: 'https://proxy.example.test', allowed_upstreams: ['https://gmail.googleapis.com'],
        credentials: [quarantine({active_rule_count: 0})], applications: [application({active_rule_count: 1, access_status: 'active'})],
        access_rules: [googleRule()], capabilities: {credential_types: ['bearer', 'header'], oauth: false,
          response_modes: capabilities.responseModes, credential_input_modes: capabilities.credentialInputModes,
          token_lifetime_seconds: {min: 3600, max: 7776000, default: 2592000}},
        limits: Object.fromEntries(['credentials', 'applications', 'access_rules'].map(name => [name,
          {active: name === 'credentials' ? 0 : 1, retained: 1, active_max: 32, retained_max: 1024}]))};
      // One exact synthetic GET response is overridden; no fallback, redirects,
      // route.fetch, browser navigation, or additional network admission exists.
      await context.route(endpoint, async route => {
        const request = route.request(); state.requests.push({path: '/api/operator-demo/catalog', query: '', method: request.method()});
        if (++calls !== 1 || state.requests.length > 150 || request.url() !== endpoint || request.method() !== 'GET' || request.postDataBuffer()?.length) {
          state.unexpected.push('contradictory catalog override boundary refused'); await route.abort(); return;
        }
        state.catalogCalls++; await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(observed)});
      });
      await refresh(page); await unavailable(page, state); assert.equal(calls, 1);
    })],
  ...malformed.map(([name, changes]) => ['malformed public Google metadata: ' + name, browser => fixture(browser,
    supplied({credentials: [google(changes)]}), async (page, state) => {
      await unavailable(page, state);
      if (name === 'unknown permission preset') assert.equal(await accountCard(page).count(), 0, 'unknown preset is rejected before any account card is rendered');
    })]),
];

async function main() {
  const args = process.argv.slice(2);
  assert(args.length === 0 || (args.length === 1 && args[0] === '--cards-only'), 'Google presentation tests accept only --cards-only or no arguments');
  const cardTests = new Set([ACTIVE_CARD_TEST, QUARANTINED_CARD_TEST, UNKNOWN_PRESET_TEST]);
  const selected = args.length ? tests.filter(([name]) => cardTests.has(name)) : tests;
  if (args.length) assert.equal(selected.length, 3, 'focused card selection remains exact');
  const before = await hashes(); console.log(JSON.stringify({phase: 'source-before', hashes: before}));
  console.log(JSON.stringify(generatorChecks()));
  const artifactRoot = '/srv/catchplate-fast/projects/serverware-operator-artifacts';
  assert((await stat(artifactRoot)).isDirectory()); artifacts = await mkdtemp(join(artifactRoot, 'google-browser-synthetic-'));
  console.log(JSON.stringify({artifactDirectory: artifacts, scope: 'public-account synthetic screenshots only'}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']}); let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of selected) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: selected.length, totalGroups: tests.length, selection: args.length ? 'cards-only' : 'all',
        scope: 'intercepted Google public-account presentation fixtures only',
        consentTested: false, cleanupTested: false, otherBrowserSuitesExecuted: false, liveRequests: 0,
        generatedCommandsExecuted: false, productionAcceptance: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('Google presentation fixture absolute deadline')), 120000); })]);
  } finally {
    clearTimeout(deadline); try { await browser.close(); }
    finally { const after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after})); assert.deepEqual(after, before, 'sources remained frozen'); }
  }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

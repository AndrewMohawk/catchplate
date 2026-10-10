#!/usr/bin/env node
// Independent acceptance of the guided composition, not a provider/proxy test.
// Only the existing bounded, intercepted synthetic fixture may supply responses.
// No CA download, generated-command execution, live target or secret is accepted.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFile, mkdtemp, stat} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {runInNewContext} = require('node:vm');
const {fixture, ready, view, openRestrictions, credential, application, rule, IDS, NOW, UPSTREAM} = require('./test_operator_catalog_browser.cjs');

const ROOT = resolve(__dirname, '..');
const SECRET = 'synthetic-provider-key-for-connect-fixture';
const DUMMY = "Bearer CONNECT-DUMMY-'literal'-$value";
const OTHER_CREDENTIAL = '66666666-6666-4666-8666-666666666666';
const OTHER_RULE = '77777777-7777-4777-8777-777777777777';
const SYNTHETIC_ORIGIN = 'https://demo-upstream:8443';
const fixtureId = number => '00000000-0000-4000-8000-' + String(number).padStart(12, '0');
const digest = n => 'sha256:' + n.toString(16).padStart(64, '0');
const token = id => 'synthetic_application_' + id.replaceAll('-', '') + '_generation_1';
const capabilities = {responseModes: ['projected_json', 'unfiltered_json'], credentialInputModes: ['insert', 'replace_exact']};
const supplied = (changes = {}) => ({...capabilities, credentials: [credential()], applications: [application()], ...changes});
const savedRule = (changes = {}) => rule({credential_input: 'replace_exact', placeholder: DUMMY,
  response_mode: 'unfiltered_json', response_fields: [], ...changes});
const SOURCE_FILES = ['scripts/test_operator_connect_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
  'serverware/operator_demo_portal.py', ...['index.html', 'style.css', 'app.js', 'workspace_core.js', 'workspace_github.js',
    'workspace_google.js', 'workspace_google_reauthorization.js', 'workspace_applications.js', 'workspace_resources.js', 'workspace_proxy_audit.js', 'workspace_connect.js']
    .map(name => 'serverware/operator_demo_web/' + name)];
let artifacts;

async function hashes() {
  return Object.fromEntries(await Promise.all(SOURCE_FILES.map(async name =>
    [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
async function idle(page) { await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled); }
async function step(page, name) {
  await page.locator('#connect-' + name + '-step').waitFor({state: 'visible'});
  assert.equal(await page.locator('#connect > [id$="-step"]:visible').count(), 1, 'one guided step at a time');
  await idle(page);
}
async function start(page) {
  await ready(page);
  if (!await page.locator('#connect').isVisible()) await view(page, 'connect');
  await page.locator('#connect').waitFor({state: 'visible'});
  assert.equal(await page.locator('.page:visible').count(), 1);
  assert.equal(await page.locator('nav a[href="#connect"]').getAttribute('aria-current'), 'page');
  await step(page, 'credential');
  assert(await page.locator('#connect-method-choice').isVisible());
  assert(await page.locator('#connect-credential-form').isHidden()); assert(await page.locator('#google-consent-panel').isHidden());
}
async function chooseMethod(page, method) {
  const active = method === 'key' ? '#connect-credential-new' : '#connect-saved-choice';
  if (await page.locator(active).isVisible()) return;
  if (await page.locator('#connect-method-change').isVisible()) await page.locator('#connect-method-change').click();
  await page.locator('#connect-use-' + method).click();
  assert(await page.locator('#connect-method-choice').isHidden()); assert(await page.locator(active).isVisible());
  assert(await page.locator('#google-consent-panel').isHidden());
}
async function useCredential(page, id = IDS.credential) {
  await chooseMethod(page, 'saved');
  await page.locator('#connect-credential-choice').selectOption(id);
  await page.locator('#connect-credential-next').click(); await step(page, 'application');
}
async function fillCredential(page, name = 'Reusable provider key') {
  await chooseMethod(page, 'key');
  await page.locator('#connect-credential-name').fill(name);
  await page.locator('#connect-credential-secret').fill(SECRET);
}
async function createCredential(page, name) {
  await fillCredential(page, name); await page.locator('#connect-credential-next').click(); await step(page, 'application');
}
async function fillApplication(page, name = 'Ordinary client', lifetime = '2592000') {
  await page.locator('#connect-application-choice').selectOption('new');
  await page.locator('#connect-application-name').fill(name);
  await page.locator('#connect-token-ttl').selectOption(lifetime);
}
async function createApplication(page, name, lifetime) {
  await fillApplication(page, name, lifetime); await page.locator('#connect-application-next').click(); await step(page, 'access');
}
async function useApplication(page, id = IDS.application) {
  await page.locator('#connect-application-choice').selectOption(id);
  await page.locator('#connect-application-next').click(); await step(page, 'access');
}
async function pair(page) { await start(page); await useCredential(page); await useApplication(page); }
async function draft(page) {
  await page.locator('#connect-rule-choice').selectOption('new');
  await openRestrictions(page, 'connect');
  await page.locator('#connect-rule-name').fill('Read account status');
  await page.locator('#connect-origin').selectOption(UPSTREAM);
  await page.locator('#connect-path').fill('/v1/status');
  assert.equal(await page.locator('#connect-credential-input').inputValue(), 'insert', 'insertion is the initial explicit default');
  await page.locator('#connect-credential-input').selectOption('replace_exact');
  await page.locator('#connect-placeholder').fill(DUMMY);
  assert.equal(await page.locator('#connect-response-mode').inputValue(), 'unfiltered_json');
  assert(await page.locator('#connect-response-fields').isDisabled());
}
async function review(page) { await page.locator('#connect-review').click(); await step(page, 'review'); }
async function grant(page) { await page.locator('#connect-grant').click(); await step(page, 'setup'); }
async function refresh(page) {
  const response = page.waitForResponse(value => new URL(value.url()).pathname === '/api/operator-demo/catalog');
  await page.locator('#connect-status-refresh').click(); await response;
  await page.waitForLoadState('networkidle'); await idle(page);
}
async function noToken(page) {
  assert.equal(await page.locator('#client-token').inputValue(), '');
  assert(await page.locator('#copy-token').isDisabled()); assert(await page.locator('#download-config').isDisabled());
}
async function setup(page, app = IDS.application, selectedRule = IDS.rule) {
  await step(page, 'setup'); await page.locator('#connect-setup-slot').waitFor({state: 'visible'});
  await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  assert.equal(await page.locator('#proxy-application').inputValue(), app);
  assert.equal(await page.locator('#proxy-rule').inputValue(), selectedRule);
  assert(await page.locator('#proxy-application').isDisabled()); assert(await page.locator('#proxy-rule').isDisabled());
  assert.equal(await page.locator('#proxy-setup-content').count(), 1);
  assert.equal(await page.locator('#connect-setup-slot #proxy-setup-content').count(), 1);
  assert.match(await page.locator('#connect-activation').innerText(), /active.*no upstream request has been tested/i);
}
async function screenshot(page, name) {
  if (artifacts) await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true});
}
async function chooseSavedRule(page, id = IDS.rule) {
  await page.locator('#connect-rule-choice').selectOption(id); await review(page);
  assert.match(await page.locator('#connect-grant').innerText(), /use.*saved rule/i); await grant(page);
}
function changePolicy(state) { state.revision++; state.active = state.loaded = digest(++state.sequence); }

const tests = [
  ['Overview is the honest starting point and connects a real service only by deliberate choice', browser => fixture(browser,
    supplied({rules: [savedRule()]}), async (page, state) => {
      await ready(page); await page.locator('#overview').waitFor({state: 'visible'});
      assert.equal(await page.locator('.page:visible').count(), 1);
      assert.equal(await page.locator('nav a[href="#overview"]').getAttribute('aria-current'), 'page');
      assert.equal(await page.locator('nav a[href="#credentials"]').innerText(), 'Accounts & keys');
      assert.equal(await page.locator('nav a[href="#access-rules"]').innerText(), 'Permissions');
      assert.match(await page.locator('#overview-policy').innerText(), /proxy.*loaded.*saved policy/i);
      assert.match(await page.locator('#overview').innerText(), /not proof.*upstream.*succeeded/i);
      assert(await page.locator('#overview-try-demo').isEnabled());
      assert(await page.locator('#overview-demo-panel').isHidden());
      await page.locator('#overview-connect-service').click(); await step(page, 'credential');
      assert.match(await page.locator('#connect-progress').innerText(), /account or api key/i);
      assert(await page.locator('#connect-google').isDisabled());
      assert(await page.locator('#connect-use-github').isDisabled());
      assert.equal(state.posts.length, 0);
      assert(!state.requests.some(item => /oauth|google|github/.test(item.path)));
    })],
  ['compact credential cards retain user records and reveal exact technical details without writes', browser => fixture(browser,
    supplied({credentials: [credential(), credential({id: OTHER_CREDENTIAL, name: 'My custom integration',
      auth_type: 'header', header_name: 'X-Customer-Key', status: 'revoked'})], rules: [savedRule({name: 'Read saved customer status'})]}), async (page, state) => {
      const retained = JSON.stringify([state.credentials, state.applications, state.rules]);
      await ready(page); await view(page, 'credentials');
      assert.equal(await page.locator('#credentials-list > [data-resource-id]').count(), 2);
      const card = page.locator('#credentials-list > [data-resource-id="' + IDS.credential + '"]');
      assert.equal(await card.locator('.badge').innerText(), 'Saved');
      assert.match(await card.innerText(), /Assigned apps/);
      assert.match(await card.innerText(), /Reporting application/);
      assert.match(await card.innerText(), /Saved permissions/);
      for (const text of ['Read saved customer status', 'GET', UPSTREAM + '/v1/status']) assert((await card.innerText()).includes(text));
      const details = card.locator('details[data-credential-details]');
      assert.equal(await details.evaluate(node => node.open), false);
      assert(await card.getByText(IDS.credential, {exact: true}).isHidden());
      await details.locator(':scope > summary').click();
      assert(await card.getByText(IDS.credential, {exact: true}).isVisible());
      assert.match(await details.innerText(), /Authentication/); assert.match(await details.innerText(), /Bearer token/);
      assert.match(await details.innerText(), /Active rules/);
      assert(!(await page.locator('#credentials-list').innerText()).includes(SECRET));
      const old = page.locator('#credentials-list > [data-resource-id="' + OTHER_CREDENTIAL + '"]');
      assert.equal(await old.locator('.badge').innerText(), 'Revoked locally');
      await old.locator('details[data-credential-details] > summary').click();
      assert(await old.getByText(OTHER_CREDENTIAL, {exact: true}).isVisible());
      assert.match(await old.innerText(), /X-Customer-Key/);
      await screenshot(page, 'saved-credentials-details');
      await view(page, 'overview'); await view(page, 'credentials');
      assert.equal(await page.locator('#credentials-list > [data-resource-id]').count(), 2);
      assert.equal(JSON.stringify([state.credentials, state.applications, state.rules]), retained);
      assert.equal(state.posts.length, 0);
    })],
  ['synthetic-demo disclosure does not mistake friendly names for a saved demo permission', browser => fixture(browser,
    supplied({allowedUpstreams: [UPSTREAM, SYNTHETIC_ORIGIN], credentials: [credential({name: 'Demo starter key'})],
      applications: [application({name: 'Demo starter application'})], rules: [savedRule({name: 'Demo GET echo'}),
        savedRule({id: OTHER_RULE, name: 'Another demo name', upstream_url: UPSTREAM + '/echo'})]}), async (page, state) => {
      await ready(page); await page.locator('#overview-try-demo').click();
      await page.locator('#overview-demo-panel').waitFor({state: 'visible'});
      assert.equal(await page.locator('[data-demo-rule-id]').count(), 0);
      assert.match(await page.locator('#overview-demo-status').innerText(), /no.*saved|not.*configured|not.*found/i);
      assert.equal(state.posts.length, 0);
      assert(!state.requests.some(item => item.path === '/echo' || item.path === '/ca.pem'));
      await page.locator('#overview-try-demo').click(); assert(await page.locator('#overview-demo-panel').isHidden());
    })],
  ['expired-app grouping preserves every credential and keeps mixed, unknown and unlinked accounts primary', browser => fixture(browser,
    supplied({credentials: [credential({id: fixtureId(1), name: 'Expired-only saved credential'}),
      credential({id: fixtureId(2), name: 'Shared with a current app'}), credential({id: fixtureId(3), name: 'Unknown expiry'}),
      credential({id: fixtureId(4), name: 'New unlinked key'}), credential({id: fixtureId(5), name: 'Revoked-app history'})],
      applications: [application({id: fixtureId(11), name: 'Expired app', token_expires_at_epoch_ms: NOW - 1000, token_status: 'expired'}),
        application({id: fixtureId(12), name: 'Current app'}),
        application({id: fixtureId(13), name: 'Uncertain expiry app', token_expires_at_epoch_ms: null, token_status: 'unknown'}),
        application({id: fixtureId(14), name: 'Revoked app', status: 'revoked', token_status: 'revoked'})],
      rules: [savedRule({id: fixtureId(21), credential_id: fixtureId(1), application_id: fixtureId(11)}),
        savedRule({id: fixtureId(22), credential_id: fixtureId(2), application_id: fixtureId(11)}),
        savedRule({id: fixtureId(23), credential_id: fixtureId(2), application_id: fixtureId(12)}),
        savedRule({id: fixtureId(24), credential_id: fixtureId(3), application_id: fixtureId(13)}),
        savedRule({id: fixtureId(25), credential_id: fixtureId(5), application_id: fixtureId(14), status: 'revoked'})]}), async (page, state) => {
      const before = JSON.stringify([state.credentials, state.applications, state.rules]);
      await ready(page); await view(page, 'credentials');
      const group = page.locator('#credentials-list details[data-expired-app-access]');
      assert.equal(await group.evaluate(node => node.open), false);
      assert.match(await group.locator(':scope > summary').innerText(), /Connections with expired app access \(2\)/);
      assert.equal(await page.locator('#credentials-list [data-resource-id]').count(), 5);
      for (const number of [1, 5]) assert(await group.locator('[data-resource-id="' + fixtureId(number) + '"]').isHidden());
      for (const number of [2, 3, 4]) assert(await page.locator('#credentials-list > [data-resource-id="' + fixtureId(number) + '"]').isVisible());
      await group.locator(':scope > summary').click();
      for (const number of [1, 5]) assert(await group.locator('[data-resource-id="' + fixtureId(number) + '"]').isVisible());
      const source = await readFile(join(ROOT, 'serverware/operator_demo_web/workspace_resources.js'), 'utf8');
      const predicate = runInNewContext(source + '\noperatorCredentialHasExpiredAppAccess;', {}, {timeout: 1000});
      const conservative = (() => {
        // These inputs cannot pass catalog admission; exercise the actual pure
        // grouping predicate without presenting them as accepted UI state.
        const credential = {id: 'synthetic-credential'};
        const linked = [{credential_id: credential.id, application_id: 'synthetic-app'}];
        const app = {id: 'synthetic-app', status: 'active', token_status: 'expired', token_expires_at_epoch_ms: NOW - 1};
        const grouped = changes => predicate(credential,
          {access_rules: linked, applications: [{...app, ...changes}]}, NOW);
        return {
          missing: predicate(credential, {access_rules: linked, applications: []}, NOW),
          unlinked: predicate(credential, {access_rules: [], applications: [app]}, NOW),
          unknownStatus: grouped({status: 'unknown'}), unknownToken: grouped({token_status: 'unknown'}),
          nonfinite: grouped({token_expires_at_epoch_ms: Infinity}), absentExpiry: grouped({token_expires_at_epoch_ms: null}),
          stringExpiry: grouped({token_expires_at_epoch_ms: String(NOW - 1)}), zeroExpiry: grouped({token_expires_at_epoch_ms: 0})};
      })();
      assert(Object.values(conservative).every(value => value === false), 'unknown evidence never hides a credential');
      await screenshot(page, 'expired-app-access-retained');
      assert.equal(JSON.stringify([state.credentials, state.applications, state.rules]), before);
      assert.equal(state.posts.length, 0);
    })],
  ['multiple exact synthetic-demo permissions remain explicit choices and keep unusable history visible', browser => fixture(browser,
    supplied({allowedUpstreams: [UPSTREAM, SYNTHETIC_ORIGIN],
      credentials: [credential(), credential({id: OTHER_CREDENTIAL, name: 'Another saved account'})],
      applications: [application(), application({id: IDS.other, name: 'Second existing client'})], rules: [
        savedRule({name: 'First synthetic permission', upstream_url: SYNTHETIC_ORIGIN + '/echo', methods: ['GET', 'POST']}),
        savedRule({id: OTHER_RULE, name: 'Second synthetic permission', application_id: IDS.other,
          credential_id: OTHER_CREDENTIAL, upstream_url: SYNTHETIC_ORIGIN + '/echo', methods: ['POST']}),
        savedRule({id: '88888888-8888-4888-8888-888888888888', name: 'Revoked synthetic permission',
          upstream_url: SYNTHETIC_ORIGIN + '/echo', status: 'revoked'}),
        savedRule({id: '99999999-9999-4999-8999-999999999999', name: 'Demo starter but unrelated path',
          upstream_url: SYNTHETIC_ORIGIN + '/not-echo'}),
        savedRule({id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa', name: 'Non-demo method',
          upstream_url: SYNTHETIC_ORIGIN + '/echo', methods: ['DELETE']})]}), async (page, state) => {
      const before = JSON.stringify([state.credentials, state.applications, state.rules]);
      await ready(page); await page.locator('#overview-try-demo').click();
      await page.locator('#overview-demo-panel').waitFor({state: 'visible'});
      assert(await page.locator('#overview').isVisible(), 'opening a list never silently selects a client');
      assert.deepEqual((await page.locator('[data-demo-rule-id]').evaluateAll(items => items.map(item => item.dataset.demoRuleId))).sort(),
        [IDS.rule, OTHER_RULE, '88888888-8888-4888-8888-888888888888'].sort());
      const first = page.locator('[data-demo-rule-id="' + IDS.rule + '"]');
      const second = page.locator('[data-demo-rule-id="' + OTHER_RULE + '"]');
      const revoked = page.locator('[data-demo-rule-id="88888888-8888-4888-8888-888888888888"]');
      assert.match(await first.innerText(), /Reporting application/);
      assert.match(await second.innerText(), /Second existing client/);
      assert.match(await second.innerText(), /Another saved account/);
      assert.match(await first.innerText(), /GET.*POST/); assert.match(await second.innerText(), /POST/);
      assert(await first.getByRole('button', {name: 'Open client setup', exact: true}).isEnabled());
      assert(await second.getByRole('button', {name: 'Open client setup', exact: true}).isEnabled());
      assert(await revoked.getByRole('button', {name: 'Open client setup', exact: true}).isDisabled());
      assert.equal(state.posts.length, 0); await screenshot(page, 'synthetic-demo-explicit-choices');
      await second.getByRole('button', {name: 'Open client setup', exact: true}).click();
      await page.locator('#proxy').waitFor({state: 'visible'});
      assert.equal(await page.locator('#proxy-application').inputValue(), IDS.other);
      assert.equal(await page.locator('#proxy-rule').inputValue(), OTHER_RULE);
      assert.equal(await page.locator('#proxy-method').inputValue(), 'POST');
      assert.match(await page.locator('#client-command').innerText(), /https:\/\/demo-upstream:8443\/echo/);
      assert.match(await page.locator('#client-template-warning').innerText(), /not.*successful request test/i);
      await noToken(page);
      assert.equal(state.posts.length, 0); assert.equal(JSON.stringify([state.credentials, state.applications, state.rules]), before);
      assert(!state.requests.some(item => item.path === '/echo' || item.path === '/ca.pem'));
    })],
  ['exclusive method choice preserves both key draft and exact saved selection without writes', browser => fixture(browser,
    supplied({credentials: [credential(), credential({id: OTHER_CREDENTIAL, name: 'Another saved key'})]}), async (page, state) => {
      await start(page); await chooseMethod(page, 'key');
      await page.locator('#connect-credential-name').fill('Keep this draft'); await page.locator('#connect-credential-auth-type').selectOption('header');
      await page.locator('#connect-credential-header-name').fill('X-Draft-Key'); await page.locator('#connect-credential-secret').fill(SECRET);
      assert(await page.locator('#connect-saved-choice').isHidden()); assert(await page.locator('#connect-google').isHidden());
      await chooseMethod(page, 'saved'); assert(await page.locator('#connect-credential-new').isHidden());
      assert(await page.locator('#connect-credential-secret').isDisabled());
      assert.equal(await page.locator('#connect-credential-choice option[value="new"]').count(), 0);
      await page.locator('#connect-credential-choice').selectOption(OTHER_CREDENTIAL); await chooseMethod(page, 'key');
      assert.equal(await page.locator('#connect-credential-name').inputValue(), 'Keep this draft');
      assert.equal(await page.locator('#connect-credential-auth-type').inputValue(), 'header');
      assert.equal(await page.locator('#connect-credential-header-name').inputValue(), 'X-Draft-Key');
      assert.equal(await page.locator('#connect-credential-secret').inputValue(), SECRET);
      await chooseMethod(page, 'saved'); assert.equal(await page.locator('#connect-credential-choice').inputValue(), OTHER_CREDENTIAL);
      state.credentials[1].status = 'revoked'; state.revision++; await refresh(page);
      assert.equal(await page.locator('#connect-credential-choice').inputValue(), OTHER_CREDENTIAL);
      assert(await page.locator('#connect-credential-choice option:checked').evaluate(item => item.disabled));
      assert(await page.locator('#connect-credential-next').isDisabled()); assert.equal(state.posts.length, 0);
    })],
  ['empty workspace connects inline with exact CAS writes, separate token, and a private client configuration', browser => fixture(browser, capabilities, async (page, state) => {
    await start(page); await createCredential(page);
    assert.equal(state.active, digest(1)); assert.equal(state.rules.length, 0); assert.equal(state.applications.length, 0);
    assert.equal(await page.locator('#connect-credential-secret').inputValue(), '');
    assert.equal(await page.locator('#connect-token-ttl').inputValue(), '2592000');
    assert.match(await page.locator('#connect-application-next').innerText(), /show token/i);
    await createApplication(page); assert.equal(state.rules.length, 0); assert.equal(state.active, digest(1));
    assert.equal(await page.locator('#client-token').inputValue(), token(IDS.application));
    assert.equal(await page.locator('#connect-token-slot #one-time-access').count(), 1);
    await draft(page); assert.equal(await page.locator('#connect-header-target').innerText(), 'Authorization');
    assert.match(await page.locator('#connect-placeholder-group').innerText(), /never.*real provider secret.*app token/i);
    await review(page); assert.equal(state.posts.length, 2, 'review is not publication');
    const summary = (await page.locator('#connect-review-details').innerText()).replace(/\s+/g, ' ');
    for (const value of [UPSTREAM + '/v1/status', 'GET', DUMMY]) assert(summary.includes(value));
    assert.match(summary, /no.*body|body.*forbidden/i); assert.match(summary, /no.*query|query.*none/i);
    await screenshot(page, 'review-desktop'); await grant(page); await setup(page);
    assert.deepEqual(state.posts, [
      {name: 'credentials', body: {name: 'Reusable provider key', auth_type: 'bearer', header_name: 'Authorization', secret: SECRET, expected_revision: 1, expected_policy_hash: digest(1)}},
      {name: 'applications', body: {name: 'Ordinary client', token_lifetime_seconds: 2592000, expected_revision: 2, expected_policy_hash: digest(1)}},
      {name: 'access-rules', body: {name: 'Read account status', application_id: IDS.application, credential_id: IDS.credential,
        upstream_url: UPSTREAM + '/v1/status', methods: ['GET'], credential_input: 'replace_exact', placeholder: DUMMY,
        response_mode: 'unfiltered_json', response_fields: [], request_fields: [], query_keys: [], allowed_headers: ['accept', 'user-agent'],
        expected_revision: 3, expected_policy_hash: digest(1)}}
    ]);
    const command = await page.locator('#client-command').innerText();
    assert(command.includes('Proxy-Authorization: Bearer $SERVERWARE_PROXY_TOKEN'));
    assert(command.includes("Authorization: Bearer CONNECT-DUMMY-'\\''literal'\\''-$value"));
    assert(!command.includes(SECRET) && !command.includes(token(IDS.application)));
    assert(command.includes('--cacert') && !command.includes('--insecure'));
    assert.equal(await page.locator('#ca-download').getAttribute('href'), '/ca.pem'); // Inspect only; native HTTP downloads bypass routing.
    const pending = page.waitForEvent('download'); await page.locator('#download-config').click(); const download = await pending;
    assert(download.url().startsWith('blob:'), 'only an in-memory synthetic private-config download is allowed');
    const stream = await download.createReadStream(); const chunks = []; let size = 0;
    for await (const chunk of stream) { size += chunk.length; assert(size <= 16384); chunks.push(chunk); }
    const config = JSON.parse(Buffer.concat(chunks).toString());
    assert.equal(config.application_id, IDS.application); assert.equal(config.access_rule_id, IDS.rule);
    assert.deepEqual(config.request_headers, {Authorization: DUMMY}); assert.equal(config.proxy_authorization, 'Bearer ' + token(IDS.application));
    assert(!JSON.stringify(config).includes(SECRET)); assert.match(config.note, /private.*never commit/i);
    await download.delete(); await screenshot(page, 'setup-desktop');
    await page.setViewportSize({width: 390, height: 844});
    assert(await page.locator('#copy-command').isVisible()); await screenshot(page, 'setup-mobile');
    assert.equal(await page.evaluate(() => document.querySelectorAll('#client-token').length), 1);
  })],
  ['reusing credential and application creates only a rule, never retrieves or rotates a token', browser => fixture(browser, supplied(), async (page, state) => {
    const before = JSON.stringify(state.applications); await pair(page); await draft(page); await review(page); await grant(page); await setup(page);
    assert.deepEqual(state.posts.map(item => item.name), ['access-rules']); assert.equal(JSON.stringify(state.applications), before);
    await noToken(page); assert.match(await page.locator('#connect-token-note').innerText(), /already.*token|explicit.*rotat|not.*held/i);
  })],
  ['duplicate friendly names never replace returned resource IDs with the first saved option', browser => fixture(browser,
    supplied({credentials: [credential({id: OTHER_CREDENTIAL, name: 'Same name'})], applications: [application({name: 'Same name'})]}), async (page, state) => {
      await start(page); await createCredential(page, 'Same name'); await createApplication(page, 'Same name', '3600');
      await draft(page); await review(page); await grant(page); await setup(page, IDS.other);
      assert.equal(state.posts[2].body.credential_id, IDS.credential); assert.equal(state.posts[2].body.application_id, IDS.other);
      assert.equal(state.posts[1].body.token_lifetime_seconds, 3600);
      assert.equal(await page.locator('#client-token').inputValue(), token(IDS.other));
    })],
  ['saved rule reuse lists only the exact active application-credential pair and publishes nothing', browser => fixture(browser,
    supplied({credentials: [credential(), credential({id: OTHER_CREDENTIAL})], applications: [application(), application({id: IDS.other})], rules: [
      savedRule(), savedRule({id: OTHER_RULE, application_id: IDS.other}),
      savedRule({id: '88888888-8888-4888-8888-888888888888', credential_id: OTHER_CREDENTIAL}),
      savedRule({id: '99999999-9999-4999-8999-999999999999', status: 'revoked'})]}), async (page, state) => {
      await pair(page); assert.deepEqual(await page.locator('#connect-rule-choice option').evaluateAll(items => items.map(item => item.value)), ['new', IDS.rule]);
      await chooseSavedRule(page); await setup(page); assert.equal(state.posts.length, 0); await noToken(page);
    })],
  ['Back and Leave preserve saved resources and the single held token without retry or rotation', browser => fixture(browser, capabilities, async (page, state) => {
    await start(page); await createCredential(page); await createApplication(page); const before = JSON.stringify([state.credentials, state.applications]);
    await page.locator('#connect-back').click(); await step(page, 'application');
    assert.equal(await page.locator('#client-token').inputValue(), token(IDS.application));
    await page.locator('#connect-cancel').click(); await page.locator('#overview').waitFor({state: 'visible'});
    assert.match(state.dialogs.at(-1), /saved.*remain.*token/i);
    await view(page, 'applications'); assert.equal(await page.locator('#applications #one-time-access').count(), 1);
    assert.equal(await page.locator('#client-token').inputValue(), token(IDS.application));
    await view(page, 'connect'); await step(page, 'credential');
    assert.equal(await page.locator('#connect-token-slot #one-time-access').count(), 1);
    await useCredential(page); await useApplication(page);
    assert.equal(state.posts.length, 2); assert.equal(JSON.stringify([state.credentials, state.applications]), before);
    assert.equal(await page.locator('#client-token').count(), 1);
  })],
  ...['revision', 'policy hash'].map(kind => [kind + ' change invalidates the effective review until explicitly reviewed again', browser => fixture(browser, supplied(), async (page, state) => {
    await pair(page); await draft(page); await review(page); const original = await page.locator('#connect-review-details').innerText();
    if (kind === 'revision') state.revision++; else state.active = state.loaded = digest(++state.sequence);
    const reviewedHash = state.active;
    await refresh(page); assert(await page.locator('#connect-grant').isDisabled());
    assert.match(await page.locator('#connect-review-context').innerText(), /changed.*back.*review/i);
    assert.equal(await page.locator('#connect-review-details').innerText(), original); assert.equal(state.posts.length, 0);
    await page.locator('#connect-back').click(); await step(page, 'access'); await review(page); await grant(page); await setup(page);
    assert.equal(state.posts[0].body.expected_revision, kind === 'revision' ? 2 : 1);
    assert.equal(state.posts[0].body.expected_policy_hash, reviewedHash);
  })]),
  ...['credential', 'application', 'rule'].map(kind => [kind + ' revocation cannot silently select another usable resource', browser => fixture(browser,
    supplied({credentials: [credential(), credential({id: OTHER_CREDENTIAL})], applications: [application(), application({id: IDS.other})],
      rules: [savedRule(), savedRule({id: OTHER_RULE, application_id: IDS.other, credential_id: OTHER_CREDENTIAL})]}), async (page, state) => {
      await pair(page); await chooseSavedRule(page); await setup(page);
      state.rules[0].status = 'revoked';
      if (kind === 'credential') state.credentials[0].status = 'revoked';
      if (kind === 'application') { state.applications[0].status = 'revoked'; state.applications[0].token_status = 'revoked'; }
      changePolicy(state); await refresh(page);
      assert(!await page.locator('#connect-setup-slot').isVisible());
      assert.match(await page.locator('#connect-activation').innerText(), /no longer available|unavailable/i);
      assert.equal(state.posts.length, 0);
    })]),
  ...['credential', 'application', 'rule'].map(kind => ['successful ' + kind + ' POST cannot advance until a failed fresh catalog is reconciled', browser => fixture(browser,
    {...capabilities, credentials: kind === 'credential' ? [] : [credential()], applications: kind === 'rule' ? [application()] : []}, async (page, state) => {
      await start(page);
      if (kind === 'credential') await fillCredential(page);
      else { await useCredential(page); if (kind === 'application') await fillApplication(page); else { await useApplication(page); await draft(page); await review(page); } }
      const control = {credential: '#connect-credential-next', application: '#connect-application-next', rule: '#connect-grant'}[kind];
      const before = {credential: 'credential', application: 'application', rule: 'review'}[kind];
      const after = {credential: 'application', application: 'access', rule: 'setup'}[kind];
      state.catalogStatus = 503; await page.locator(control).click(); await page.locator('#load-error').waitFor({state: 'visible'}); await idle(page);
      await step(page, before); assert(await page.locator(control).isDisabled());
      assert.match(await page.locator('#connect-status').innerText(), /not yet confirmed|refresh|do not submit/i);
      assert.equal(state.posts.length, 1); assert.equal(await page.locator('#connect-credential-secret').inputValue(), '');
      await noToken(page); await page.clock.runFor(6000); assert.equal(state.posts.length, 1);
      state.catalogStatus = 200; await refresh(page); await step(page, after); assert.equal(state.posts.length, 1);
      if (kind === 'application') { await noToken(page); assert.match(await page.locator('#connect-token-note').innerText(), /rotat|not.*held|already/i); }
      if (kind === 'rule') await setup(page);
    })]),
  ['a vanished saved receipt can be left without replaying or deleting it', browser => fixture(browser, capabilities, async (page, state) => {
    await start(page); await fillCredential(page); state.catalogStatus = 503;
    await page.locator('#connect-credential-next').click(); await page.locator('#load-error').waitFor({state: 'visible'}); await idle(page);
    state.credentials[0].status = 'revoked'; state.revision++; state.catalogStatus = 200; await refresh(page);
    await step(page, 'credential'); assert(await page.locator('#connect-credential-next').isDisabled());
    await page.locator('#connect-cancel').click(); await view(page, 'connect'); await step(page, 'credential');
    assert(await page.locator('#connect-method-choice').isVisible()); await chooseMethod(page, 'key');
    assert(!await page.locator('#connect-credential-next').isDisabled()); assert.equal(state.posts.length, 1);
    assert.equal(state.credentials.length, 1); assert.equal(state.credentials[0].status, 'revoked');
  })],
  ['lost application response stays uncertain across Leave and never retrieves or reissues the token', browser => fixture(browser,
    supplied({applications: []}), async (page, state) => {
      await start(page); await useCredential(page); await fillApplication(page);
      state.fault = 'lost-after-commit'; await page.locator('#connect-application-next').click();
      await page.locator('#mutation-review').waitFor({state: 'visible'}); await idle(page); await step(page, 'application');
      assert.equal(state.applications.length, 1); assert.equal(state.posts.length, 1); await noToken(page);
      await page.locator('#connect-cancel').click(); await view(page, 'connect'); await step(page, 'credential');
      assert(await page.locator('#connect-credential-next').isDisabled()); assert(await page.locator('#mutation-review').isVisible());
      await page.clock.runFor(6000); assert.equal(state.posts.length, 1);
      await page.locator('#mutation-review-confirm').click(); await useCredential(page); await useApplication(page);
      await noToken(page); assert.equal(state.posts.length, 1);
      assert.match(await page.locator('#connect-token-note').innerText(), /rotat|not.*held|already/i);
    })],
  ...['409', '422', '503'].map(fault => [fault + ' rule rejection requires explicit state review and sends no retry', browser => fixture(browser, supplied(), async (page, state) => {
    await pair(page); await draft(page); await review(page); state.fault = fault;
    await page.locator('#connect-grant').click(); await page.locator('#mutation-review').waitFor({state: 'visible'}); await idle(page);
    await step(page, 'review'); assert(await page.locator('#connect-grant').isDisabled());
    assert.equal(state.rules.length, 0); assert.equal(state.posts.length, 1);
    assert.match(await page.locator('#mutation-review-text').innerText(), /no automatic retry/i);
    assert(!(await page.locator('body').innerText()).includes('synthetic-provider-value-not-a-real-credential'));
    await page.clock.runFor(6000); await refresh(page); assert.equal(state.posts.length, 1);
    assert(await page.locator('#connect-grant').isDisabled());
  })]),
  ['matching hashes with pending activation never expose ready setup, then an observed active policy does', browser => fixture(browser,
    supplied({activationOverride: 'pending'}), async (page, state) => {
      await pair(page); await draft(page); await review(page); await grant(page);
      assert.equal(state.active, state.loaded); assert(!await page.locator('#connect-setup-slot').isVisible());
      assert.match(await page.locator('#connect-activation').innerText(), /waiting.*confirm/i);
      assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
      await screenshot(page, 'activation-pending'); const calls = state.catalogCalls;
      await page.clock.runFor(1999); assert.equal(state.catalogCalls, calls);
      state.activationOverride = 'active'; await page.clock.runFor(1); await setup(page);
      assert.equal(state.posts.length, 1); assert.equal(state.catalogCalls, calls + 1);
    })],
  ['Google is honestly unavailable and absent rule capabilities cannot produce a silent fallback grant', browser => fixture(browser,
    supplied({credentialInputModes: undefined}), async (page, state) => {
      await start(page); assert(await page.locator('#connect-google').isDisabled());
      const googleStatus = await page.locator('#connect-google-status').innerText();
      assert.match(googleStatus, /Google connection is unavailable in this deployment/);
      assert.match(googleStatus, /administrator must enable the supported Google profile/);
      assert.match(googleStatus, /Do not paste Google access or refresh tokens/);
      await useCredential(page); await useApplication(page); assert(await page.locator('#connect-review').isDisabled());
      assert.equal(state.posts.length, 0); assert(!state.requests.some(item => /oauth|google/.test(item.path)));
    })],
  ['capability withdrawal preserves the refused choice instead of changing the requested access', browser => fixture(browser, supplied(), async (page, state) => {
    await pair(page); await draft(page); await review(page); state.credentialInputModes = ['insert']; state.responseModes = ['projected_json'];
    await refresh(page); assert(await page.locator('#connect-grant').isDisabled());
    await page.locator('#connect-back').click(); await step(page, 'access');
    assert.equal(await page.locator('#connect-credential-input').inputValue(), 'replace_exact');
    assert.equal(await page.locator('#connect-response-mode').inputValue(), 'unfiltered_json');
    for (const id of ['connect-credential-input', 'connect-response-mode']) assert(await page.locator('#' + id + ' option:checked').evaluate(item => item.disabled));
    await page.locator('#connect-review').click(); await step(page, 'access'); assert.equal(state.posts.length, 0);
  })],
  ['ordinary POST and query constraints remain explicit when response filtering is disabled', browser => fixture(browser, supplied(), async (page, state) => {
    await pair(page); await draft(page); await page.locator('input[name="connect-method"][value="GET"]').uncheck();
    await page.locator('input[name="connect-method"][value="POST"]').check();
    assert(await page.locator('#connect-body-warning').isVisible()); assert.match(await page.locator('#connect-body-warning').innerText(), /no request body.*even.*post/i);
    await page.locator('#connect-compatibility summary').click();
    assert.match(await page.locator('#connect-compatibility').innerText(), /204|empty/i);
    await page.locator('#connect-request-fields').fill('message\nrecipient');
    await page.locator('#connect-request-extras > summary').click(); await page.locator('#connect-query-keys').fill('page\nlimit');
    await review(page); const summary = await page.locator('#connect-review-details').innerText();
    for (const text of ['message', 'recipient', 'page', 'limit', 'POST']) assert(summary.includes(text));
    await grant(page); await setup(page); const body = state.posts[0].body;
    assert.deepEqual(body.request_fields, ['message', 'recipient']); assert.deepEqual(body.query_keys, ['page', 'limit']);
    assert.deepEqual(body.methods, ['POST']); assert.equal(body.response_mode, 'unfiltered_json'); assert.deepEqual(body.response_fields, []);
    assert.match(await page.locator('#client-guidance').innerText(), /connection template.*no request body or query/is);
    assert(!/--data|[?&]page=/.test(await page.locator('#client-command').innerText()));
  })],
  ['reload clears the guided one-time token without rotating the persisted application', browser => fixture(browser, capabilities, async (page, state) => {
    await start(page); await createCredential(page); await createApplication(page); await draft(page); await review(page); await grant(page); await setup(page);
    assert(!await page.locator('#download-config').isDisabled()); const before = JSON.stringify(state.applications);
    await page.reload({waitUntil: 'networkidle'}); await start(page); await noToken(page);
    await useCredential(page); await useApplication(page); await chooseSavedRule(page); await setup(page);
    await noToken(page); assert.equal(state.posts.length, 3); assert.equal(JSON.stringify(state.applications), before);
    assert.equal(await page.locator('#client-token').count(), 1);
  })],
];

async function main() {
  assert.equal(process.argv.length, 2, 'connect fixtures accept no live target or credentials');
  const before = await hashes(); console.log(JSON.stringify({phase: 'source-before', hashes: before}));
  const artifactRoot = '/srv/catchplate-fast/projects/serverware-operator-artifacts';
  assert((await stat(artifactRoot)).isDirectory()); artifacts = await mkdtemp(join(artifactRoot, 'connect-browser-synthetic-'));
  console.log(JSON.stringify({artifactDirectory: artifacts, scope: 'synthetic screenshots; no actual credentials'}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of tests) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: tests.length, scope: 'intercepted Connect an app synthetic fixtures only',
        otherBrowserSuitesExecuted: false, liveRequests: 0, generatedCommandsExecuted: false, productionAcceptance: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('connect fixture absolute deadline')), 150000); })]);
  } finally {
    clearTimeout(deadline);
    try { await browser.close(); }
    finally { const after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after})); assert.deepEqual(after, before, 'sources remained frozen'); }
  }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

// Invoke runSuite(browser) through the Playwright MCP's retained browser.
// Reuses the existing real-renderer/intercepted-catalog fixture; no live API,
// provider, proxy, private key, token issuance or deployment is exercised.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFile, mkdtemp} = require('node:fs/promises');
const {join} = require('node:path');
const {fixture: baseFixture, ready, view, application, credential, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {publicCatalog} = require('./test_operator_ordinary_modes_browser.cjs');
const ORIGIN = 'https://operator-catalog.example.test';
const PROXY = 'https://proxy.example.test:443';
const CATALOG = '/api/operator-demo/catalog';
const ENROLL = '/api/operator-demo/applications/renewal/enroll';
const CANCEL = '/api/operator-demo/applications/renewal/cancel';
const ENROLLMENT = '77777777-7777-4777-8777-777777777777';
const REPLACEMENT = '88888888-8888-4888-8888-888888888888';
const KEY = '12'.repeat(32);
const FINGERPRINT = 'sha256:' + createHash('sha256').update(Buffer.from(KEY, 'hex')).digest('hex');
const PRIVATE = 'synthetic-provider-private-never-render';
const clone = value => JSON.parse(JSON.stringify(value));
const capability = () => ({schema: 'serverware.workloadTokenRenewal/v1', enroll_path: ENROLL, cancel_path: CANCEL,
  path: '/v1/workload/renew', audience: PROXY + '/v1/workload/renew', overlap_seconds: 300,
  token_lifetime_seconds: {min: 3600, max: 86400, default: 3600},
  enrollment_lifetime_seconds: {min: 86400, max: 7776000, default: 2592000}, single_writer: true});
const renewal = (changes = {}) => ({version: 1, enrollment_id: ENROLLMENT, expires_at_epoch_ms: NOW + 30 * 86400000,
  public_key_fingerprint: FINGERPRINT, token_lifetime_seconds: 3600, overlap_seconds: 300,
  audience: PROXY + '/v1/workload/renew', status: 'active', ...changes});
function projected(state, options) {
  const value = publicCatalog(state); value.proxy_url = PROXY;
  if (!options.unsupported) value.capabilities.workload_renewal = capability();
  return value;
}
function mutation(state, path, body, options) {
  const enroll = path === ENROLL;
  assert.deepEqual(Object.keys(body).sort(), ['expected_revision', 'expected_policy_hash', 'id',
    ...(enroll ? ['public_key', 'enrollment_lifetime_seconds', 'token_lifetime_seconds'] : [])].sort());
  assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
  assert.equal(body.id, IDS.application);
  const item = state.applications.find(value => value.id === body.id); assert.equal(item.status, 'active');
  if (enroll) {
    assert.equal(body.public_key, KEY);
    assert(Number.isSafeInteger(body.enrollment_lifetime_seconds) && body.enrollment_lifetime_seconds >= 86400 && body.enrollment_lifetime_seconds <= 7776000);
    assert(Number.isSafeInteger(body.token_lifetime_seconds) && body.token_lifetime_seconds >= 3600 && body.token_lifetime_seconds <= 86400);
    item.client_renewal = renewal({enrollment_id: item.client_renewal ? REPLACEMENT : ENROLLMENT,
      expires_at_epoch_ms: NOW + body.enrollment_lifetime_seconds * 1000, token_lifetime_seconds: body.token_lifetime_seconds});
    item.token_expires_at_epoch_ms = Math.min(item.token_expires_at_epoch_ms, item.client_renewal.expires_at_epoch_ms);
    delete item.client_renewal_cancelled_at_epoch_ms;
  } else { assert(item.client_renewal); item.client_renewal = null; item.client_renewal_cancelled_at_epoch_ms = NOW; }
  state.revision++;
  if (state.rules.some(value => value.application_id === item.id && value.status === 'active')) {
    state.active = 'sha256:' + (++state.sequence).toString(16).padStart(64, '0');
    if (state.autoLoad) state.loaded = state.active;
  }
  const catalog = projected(state, options);
  return {application: catalog.applications.find(value => value.id === item.id), revision: state.revision, policy: catalog.policy};
}
async function noPrivateMaterial(page) {
  const value = await page.evaluate(() => ({html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].map(node => node.value), local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  assert(!JSON.stringify(value).includes(PRIVATE));
  assert.equal(await page.locator('#client-token').inputValue(), '');
  assert.equal(value.local.length, 0); assert.equal(value.session.length, 0);
}
async function fixture(browser, options, exercise) {
  return baseFixture(browser, {credentials: [credential({secret: PRIVATE})],
    applications: [application({client_renewal: options.enrolled ? renewal() : null})], rules: options.assigned ? [rule()] : [],
    pending: options.pending, autoLoad: options.autoLoad !== false}, async (page, state, controls) => {
    state.renewalPosts = []; let reads = 0;
    await controls.context.route(ORIGIN + CATALOG, async route => {
      assert(++reads <= 30); assert.equal(route.request().method(), 'GET'); assert.equal(route.request().postDataBuffer(), null);
      await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(projected(state, options))});
    });
    for (const path of [ENROLL, CANCEL]) await controls.context.route(ORIGIN + path, async route => {
      const request = route.request();
      try {
        assert.equal(request.url(), ORIGIN + path); assert.equal(request.method(), 'POST');
        const bytes = request.postDataBuffer(); assert(bytes && bytes.length <= 2048);
        assert.equal(request.headers()['content-type'], 'application/json'); assert(state.renewalPosts.length < 3);
        const body = JSON.parse(bytes.toString()); state.renewalPosts.push({path, body: clone(body)});
        const result = mutation(state, path, body, options);
        if (options.fault === 'lost-after-commit') { state.expectedFailures.add(path); await route.abort('failed'); return; }
        if (options.fault === 'malformed-receipt') result.application.client_renewal.public_key_fingerprint = 'sha256:' + 'f'.repeat(64);
        await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(result)});
      } catch (error) { state.errors.push('renewal fixture: ' + error.message); await route.abort(); }
    });
    await page.reload({waitUntil: 'networkidle'}); await ready(page); await view(page, 'applications');
    assert.equal(await page.title(), 'Clients - Serverware operator workspace');
    assert.equal(new URL(page.url()).origin, ORIGIN);
    await exercise(page, state);
    assert.deepEqual(state.posts, [], 'no unrelated catalog writes'); assert(reads > 0); await noPrivateMaterial(page);
  });
}
async function select(page) {
  await page.locator('#application-renewal-client').selectOption(IDS.application);
  assert.equal(await page.locator('#application-renewal-client').inputValue(), IDS.application);
}
async function fill(page) {
  await select(page); await page.locator('#application-renewal-key').fill(KEY);
  await page.locator('#application-renewal-consent').check();
}
async function save(page) {
  await page.locator('#application-renewal-enroll').click();
  await page.waitForFunction(() => document.querySelector('#application-renewal-status').textContent.startsWith('Enrollment saved.'));
}
async function cancel(page) {
  await page.locator('#application-renewal-cancel').click();
  await page.waitForFunction(() => document.querySelector('#application-renewal-status').textContent.startsWith('Renewal enrollment cancelled.'));
}
async function runSuite(browser, {fromGroup = 1} = {}) {
  const artifacts = await mkdtemp('/tmp/serverware-renewal-ui-'); const screenshots = []; let groups = 0;
  console.log(JSON.stringify({artifactDirectory: artifacts, scope: 'synthetic renewal browser fixture'}));
  const capture = async (page, name) => {
    const path = join(artifacts, name + '.png');
    await page.locator('#application-renewal').scrollIntoViewIfNeeded();
    await page.screenshot({path, fullPage: true, mask: [page.locator('#client-token')]}); screenshots.push(path);
    const panel = join(artifacts, name + '-panel.png');
    await page.locator('#application-renewal').screenshot({path: panel}); screenshots.push(panel);
  };
  const tests = [
    ['actual selected-client enrollment, confirmation and public setup download', () => fixture(browser, {assigned: true}, async (page, state) => {
      await fill(page); assert.equal(await page.locator('#application-renewal-days').inputValue(), '30');
      assert.equal(await page.locator('#application-renewal-hours').inputValue(), '1');
      await save(page); assert.equal(state.renewalPosts.length, 1); assert.equal(state.dialogs.length, 1);
      assert.match(state.dialogs[0], /replaces any previous enrollment/);
      assert.equal(await page.locator('#application-renewal-key').inputValue(), ''); assert(!await page.locator('#application-renewal-consent').isChecked());
      await page.locator('#application-renewal details > summary').click();
      const displayed = JSON.parse(await page.locator('#application-renewal-setup').textContent());
      const downloadEvent = page.waitForEvent('download'); await page.locator('#application-renewal-download').click();
      const download = await downloadEvent; assert.equal(download.suggestedFilename(), 'serverware-managed-client.json');
      const filename = join(artifacts, download.suggestedFilename()); await download.saveAs(filename);
      const downloaded = JSON.parse(await readFile(filename, 'utf8')); assert.deepEqual(downloaded, displayed);
      assert.deepEqual(downloaded, {schema: 'serverware.managedClientSetup/v1', application_id: IDS.application,
        enrollment_id: ENROLLMENT, audience: PROXY + '/v1/workload/renew', public_key_fingerprint: FINGERPRINT,
        token_generation: 1, token_expires_at_epoch_ms: NOW + 86400000,
        enrollment_expires_at_epoch_ms: NOW + 30 * 86400000, token_lifetime_seconds: 3600, overlap_seconds: 300});
      await capture(page, 'desktop-enrolled-public-setup');
    })],
    ['browser required consent and finite input validity precede explicit replacement', () => fixture(browser, {enrolled: true}, async (page, state) => {
      await select(page); await page.locator('#application-renewal-key').fill(KEY);
      await page.locator('#application-renewal-enroll').click(); assert.equal(state.renewalPosts.length, 0);
      await page.locator('#application-renewal-consent').check(); await page.locator('#application-renewal-days').fill('91');
      await page.locator('#application-renewal-enroll').click(); assert.equal(state.renewalPosts.length, 0);
      await page.locator('#application-renewal-days').fill('1'); await page.locator('#application-renewal-hours').fill('24');
      state.cancelNextDialog = true; await page.locator('#application-renewal-enroll').click(); assert.equal(state.renewalPosts.length, 0);
      await save(page); assert.equal(state.renewalPosts.length, 1); assert.equal(state.applications[0].client_renewal.enrollment_id, REPLACEMENT);
      assert.equal(state.applications[0].client_renewal.token_lifetime_seconds, 86400);
    })],
    ['cancellation remains usable with unavailable capability or pending policy', async () => {
      for (const options of [{unsupported: true}, {pending: true}]) await fixture(browser, {...options, enrolled: true}, async (page, state) => {
        await select(page); assert(await page.locator('#application-renewal-enroll').isDisabled());
        assert(await page.locator('#application-renewal-download').isDisabled()); assert(await page.locator('#application-renewal-cancel').isEnabled());
        await cancel(page); assert.equal(state.renewalPosts.length, 1); assert.equal(state.renewalPosts[0].path, CANCEL);
        assert.equal(state.applications[0].client_renewal, null); assert.equal(state.applications[0].token_generation, 1);
        assert.equal(state.applications[0].token_expires_at_epoch_ms, NOW + 86400000);
        assert.match(await page.locator('#application-renewal-summary').textContent(), /Renewal cancelled/);
      });
    }],
    ['unknown committed outcome is reviewed without automatic resubmission', () => fixture(browser, {fault: 'lost-after-commit'}, async (page, state) => {
      await fill(page); await page.locator('#application-renewal-enroll').click();
      await page.locator('#mutation-review').waitFor({state: 'visible'});
      await page.waitForFunction(() => !document.querySelector('#mutation-review-confirm').disabled);
      assert.equal(state.renewalPosts.length, 1); assert.equal(state.applications[0].client_renewal.enrollment_id, ENROLLMENT);
      assert(await page.locator('#application-renewal-enroll').isDisabled()); assert(await page.locator('#application-renewal-cancel').isDisabled());
      assert(await page.locator('#application-renewal-download').isDisabled()); assert.equal(await page.locator('#application-renewal-key').inputValue(), '');
      await page.locator('#application-renewal-form').dispatchEvent('submit'); assert.equal(state.renewalPosts.length, 1);
      await capture(page, 'unknown-outcome-review-required');
      await page.locator('#mutation-review-confirm').click(); assert.equal(state.renewalPosts.length, 1);
    })],
    ['wrong public receipt fingerprint blocks helper setup', () => fixture(browser, {fault: 'malformed-receipt'}, async (page, state) => {
      await fill(page); await page.locator('#application-renewal-enroll').click();
      await page.locator('#mutation-review').waitFor({state: 'visible'}); assert.equal(state.renewalPosts.length, 1);
      assert(await page.locator('#application-renewal-download').isDisabled());
      assert.match(await page.locator('#application-renewal-status').textContent(), /could not be confirmed/);
    })],
    ['390px mobile layout, real input and expired authority withdrawal', () => fixture(browser, {enrolled: true}, async (page, state) => {
      await page.setViewportSize({width: 390, height: 844}); await select(page);
      const dimensions = await page.evaluate(() => ({viewport: innerWidth, content: document.documentElement.scrollWidth}));
      await capture(page, 'mobile-enrollment');
      assert(dimensions.content <= dimensions.viewport, 'mobile content must not overflow: ' + JSON.stringify(dimensions));
      await page.locator('#application-renewal-key').fill(KEY); await page.locator('#application-renewal-consent').check();
      await view(page, 'overview'); await view(page, 'applications');
      assert.equal(await page.locator('#application-renewal-key').inputValue(), ''); assert(!await page.locator('#application-renewal-consent').isChecked());
      await select(page);
      // Keep each Playwright clock duration below signed 32-bit milliseconds;
      // retain the real expiry timer oracle, without a refresh/render shortcut.
      await page.clock.fastForward(15 * 86400000);
      await page.clock.fastForward(15 * 86400000 + 1);
      assert(await page.locator('#application-renewal-download').isDisabled());
      assert.match(await page.locator('#application-renewal-summary').textContent(), /Enrollment expired/);
      assert.equal(state.renewalPosts.length, 0);
    })],
  ];
  assert(Number.isSafeInteger(fromGroup) && fromGroup >= 1 && fromGroup <= tests.length);
  let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, test] of tests.slice(fromGroup - 1)) { await test(); groups++; console.log('PASS ' + name); }
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('renewal browser fixture deadline')), 120000); })]);
  } finally { clearTimeout(deadline); }
  return {ok: true, groups, totalGroups: tests.length, firstGroup: fromGroup, scope: 'actual HTML/assets with independent synthetic intercepted API only',
    liveRequests: 0, backendAcceptance: false, productionAcceptance: false, artifactDirectory: artifacts, screenshots};
}
module.exports = {runSuite};

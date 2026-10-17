#!/usr/bin/env node
// Intercepted UI/DTO acceptance only. No live backend, provider, proxy,
// deployment file, restart, environment mutation or generated command.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {ready, view, credential, application, rule, NOW} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture} = require('./test_operator_ordinary_modes_browser.cjs');
const {review, receipt, OLD, TARGET, FIXTURE, NPM, digest} = require('./test_operator_upstreams_ui.cjs');
const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const PATH = '/api/operator-demo/proxy/upstreams';
const STORAGE = 'catchplate.operator.upstreams.operation.v1';
const clone = value => JSON.parse(JSON.stringify(value));
const uuid = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
function reviewed(state) {
  const pending = state.operation?.status === 'pending';
  return review({expected_revision: state.revision, expected_policy_hash: state.active,
    expected_settings_digest: state.settingsDigest, old_settings: clone(state.settings),
    protected_origins: [{origin: FIXTURE, reasons: ['active_rule', 'fixture', 'retained_policy']}],
    eligible: !pending, pending_operation_id: pending ? state.operation.operation_id : null, blocked_reason: pending ? 'pending_operation' : null});
}
function terminal(state, status) {
  const value = {...clone(state.operation), status, revision: ++state.revision, completed_at: '2026-10-10T12:01:00+00:00'};
  if (status === 'activated') {
    value.activation_receipt = {schema: 'catchplate.operatorUpstreamSetupActivation/v1', operation_id: value.operation_id,
      activated_revision: value.revision, policy_hash: value.policy_hash, settings_digest: value.target_settings_digest, activated_at: value.completed_at};
    state.settings = clone(value.target_settings); state.settingsDigest = value.target_settings_digest;
    state.allowedUpstreams = [...state.settings.allowed_upstreams];
  }
  state.operation = value; return value;
}
async function fixture(browser, config, exercise) {
  return ordinaryFixture(browser, {credentials: [credential()], applications: [application({token_status: 'expired', token_expires_at_epoch_ms: NOW - 1})],
    rules: [rule({upstream_url: FIXTURE + '/echo'})], allowedUpstreams: [FIXTURE], responseModes: ['projected_json'],
    requestBodyModes: [], credentialInputModes: ['insert']}, async (page, state, controls) => {
    state.settings = clone(OLD); state.settingsDigest = digest('b'); state.operation = null;
    const observed = {requests: [], prepares: [], cancels: []};
    const resourceBefore = clone({credentials: state.credentials, applications: state.applications, rules: state.rules});
    const handler = async route => {
      const request = route.request(); const url = new URL(request.url()); const bytes = request.postDataBuffer();
      try {
        assert.equal(url.origin, ORIGIN); assert(!url.search); assert(observed.requests.length < 40);
        observed.requests.push({method: request.method(), path: url.pathname}); let body; let status = 200;
        if (request.method() === 'GET') {
          assert(!bytes?.length);
          if (url.pathname === PATH) {
            if (config.unsupported) { status = 404; body = {detail: 'not found'}; }
            else body = reviewed(state);
            if (config.badReview) body = {...body, cold_restart_required: false};
          } else {
            const id = url.pathname.slice(PATH.length + 1); assert(uuid(id)); assert.equal(state.operation?.operation_id || observed.prepares[0]?.operation_id, id);
            if (state.operation) body = state.operation; else { status = 404; body = {detail: 'not found'}; }
          }
        } else {
          assert.equal(request.method(), 'POST'); assert(bytes && bytes.length <= 8192); assert(request.headers()['content-type']?.startsWith('application/json'));
          const input = JSON.parse(bytes.toString()); assert(uuid(input.operation_id));
          const savedReference = await page.evaluate(key => sessionStorage.getItem(key), STORAGE);
          const reference = JSON.parse(savedReference); assert.equal(reference.operation_id, input.operation_id, 'reference must already be persisted');
          assert.equal(input.expected_revision, state.revision); assert.equal(input.expected_policy_hash, state.active);
          if (url.pathname === PATH) {
            assert.equal(reference.kind, 'prepare'); assert.equal(observed.prepares.length, 0, 'prepare must never be replayed');
            assert.deepEqual(Object.keys(input).sort(), ['allowed_upstreams', 'expected_policy_hash', 'expected_revision', 'expected_settings_digest', 'operation_id']);
            assert.equal(input.expected_settings_digest, state.settingsDigest); assert.deepEqual(input.allowed_upstreams, TARGET.allowed_upstreams);
            observed.prepares.push(clone(input));
            if (config.prepareFailure) {
              status = config.prepareFailure; body = {detail: status === 409 ? 'upstream setup review changed; inspect saved status before preparing again' : 'upstream setup outcome unavailable'};
            } else {
              state.operation = receipt({operation_id: input.operation_id, reviewed_revision: state.revision, staged_revision: state.revision + 1,
                revision: ++state.revision, policy_hash: state.active}); body = state.operation; status = 201;
              if (config.lostPrepare) { state.expectedFailures.add(PATH); await route.abort('failed'); return; }
            }
          } else {
            assert.equal(url.pathname, PATH + '/cancel'); assert.equal(reference.kind, 'cancel'); assert.equal(observed.cancels.length, 0);
            assert.equal(input.operation_id, state.operation.operation_id); assert.deepEqual(Object.keys(input).sort(), ['expected_policy_hash', 'expected_revision', 'operation_id']);
            observed.cancels.push(clone(input)); body = terminal(state, 'cancelled');
          }
        }
        if (status >= 400) state.expectedFailures.add(url.pathname);
        await route.fulfill({status, contentType: 'application/json', headers: {'Cache-Control': 'no-store'}, body: JSON.stringify(body)});
      } catch (_) { state.errors.push('upstream fixture DTO/CAS/reference boundary failed'); await route.abort(); }
    };
    await controls.context.route(ORIGIN + PATH, handler); await controls.context.route(ORIGIN + PATH + '/**', handler);
    await page.reload({waitUntil: 'networkidle'}); await ready(page);
    assert.equal(await page.title(), 'Overview - Catchplate operator workspace'); assert.equal(new URL(page.url()).origin, ORIGIN);
    await exercise(page, state, observed);
    assert.deepEqual(state.posts, [], 'no unrelated catalog, token or notification writes');
    assert.deepEqual({credentials: state.credentials, applications: state.applications, rules: state.rules}, resourceBefore);
  });
}
async function idle(page) { await page.waitForFunction(() => !document.querySelector('#upstreams-review').disabled); }
async function inspect(page) { await view(page, 'proxy'); await page.locator('#upstreams-review').click(); await idle(page); }
async function proposed(page) {
  await inspect(page); await page.locator('#upstreams-proposed').fill(TARGET.allowed_upstreams.join('\n'));
  assert(!await page.locator('#upstreams-prepare').isDisabled());
}
async function prepare(page) { await proposed(page); await page.locator('#upstreams-prepare').click(); await idle(page); }
async function screenshot(page, directory, name) {
  await page.screenshot({path: join(directory, name + '.png'), fullPage: true,
    mask: [page.locator('#client-token'), page.locator('#connect-credential-secret')]});
}
const tests = [
  ['default stays concise and inert; unsupported or malformed review never offers a fake save', async browser => {
    for (const config of [{unsupported: true}, {badReview: true}]) await fixture(browser, config, async (page, state, observed) => {
      await view(page, 'proxy'); assert.equal(observed.requests.length, 0);
      assert(await page.locator('#upstreams-form').isHidden()); assert(await page.locator('#upstreams-operation').isHidden());
      assert.match(await page.locator('#proxy-upstreams').innerText(), /Apps still need permission. Changes require a controlled restart./);
      assert.equal(await page.locator('#upstreams-effective').innerText(), FIXTURE);
      await page.locator('#upstreams-review').click(); await idle(page); assert(await page.locator('#upstreams-form').isHidden());
      assert(await page.locator('#upstreams-prepare').isDisabled()); assert.equal(observed.prepares.length + observed.cancels.length, 0);
    });
  }],
  ['review shows exact additions, preserves required destinations, and prepares without hot apply', (browser, directory) => fixture(browser, {}, async (page, state, observed) => {
    await inspect(page); await page.locator('#upstreams-proposed').fill(NPM);
    assert(await page.locator('#upstreams-prepare').isDisabled()); assert.match(await page.locator('#upstreams-input-status').innerText(), /retained first|protected/);
    await page.locator('#upstreams-proposed').fill(TARGET.allowed_upstreams.join('\n'));
    assert.equal(await page.locator('#upstreams-added').innerText(), NPM); assert.equal(await page.locator('#upstreams-removed').innerText(), 'None');
    assert.match(await page.locator('#upstreams-form').innerText(), /cold restart before it takes effect/);
    await page.locator('#upstreams-prepare').click(); await idle(page); assert.equal(observed.prepares.length, 1);
    assert.equal(await page.locator('#upstreams-effective').innerText(), FIXTURE); assert.deepEqual(state.settings, OLD);
    assert.match(await page.locator('#upstreams-operation-status').innerText(), /Prepared.*restart required/);
    await page.locator('#upstreams-copy').click(); const copied = await page.evaluate(() => navigator.clipboard.readText());
    assert.deepEqual(JSON.parse(copied), TARGET.allowed_upstreams); assert(!copied.includes('fixture_cidrs'));
    await screenshot(page, directory, 'destinations-prepared-desktop'); await page.setViewportSize({width: 390, height: 844});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)); await screenshot(page, directory, 'destinations-prepared-mobile');
    await view(page, 'applications'); assert.match(await page.locator('#applications-list').innerText(), /Token expired/);
    assert(await page.locator('#one-time-access').isHidden()); assert.equal(observed.cancels.length, 0);
  })],
  ['lost prepared reply survives reload and recovers by GET before separate cancellation', browser => fixture(browser, {lostPrepare: true}, async (page, state, observed) => {
    await prepare(page); assert.match(await page.locator('#upstreams-operation-status').innerText(), /unconfirmed/);
    const retained = JSON.parse(await page.evaluate(key => sessionStorage.getItem(key), STORAGE)); assert.equal(retained.operation_id, state.operation.operation_id);
    await page.reload({waitUntil: 'networkidle'}); await ready(page); await view(page, 'proxy'); assert.equal(observed.prepares.length, 1);
    assert(await page.locator('#upstreams-prepare').isDisabled()); await page.locator('#upstreams-check').click(); await idle(page);
    assert.match(await page.locator('#upstreams-operation-status').innerText(), /Prepared/); assert(!await page.locator('#upstreams-cancel').isDisabled());
    await page.locator('#upstreams-cancel').click(); await idle(page); assert.equal(observed.cancels.length, 1);
    assert.match(await page.locator('#upstreams-operation-status').innerText(), /cancelled/); assert.equal(observed.prepares.length, 1);
    assert.deepEqual(state.settings, OLD); assert.equal(await page.locator('#upstreams-effective').innerText(), FIXTURE);
  })],
  ['409 and 503 retain the exact reference; missing receipts never cause retry', async browser => {
    for (const status of [409, 503]) await fixture(browser, {prepareFailure: status}, async (page, state, observed) => {
      await prepare(page); const id = observed.prepares[0].operation_id;
      await page.locator('#upstreams-check').click(); await idle(page); assert.match(await page.locator('#upstreams-status').innerText(), /could still complete/);
      await page.reload({waitUntil: 'networkidle'}); await ready(page); await view(page, 'proxy');
      assert.equal(JSON.parse(await page.evaluate(key => sessionStorage.getItem(key), STORAGE)).operation_id, id);
      assert.equal(observed.prepares.length, 1); assert(await page.locator('#upstreams-cancel').isDisabled());
      await page.locator('#upstreams-check').click(); await idle(page); assert.equal(observed.prepares.length, 1); assert.equal(observed.cancels.length, 0);
    });
  }],
  ['catalog changes invalidate the reviewed CAS until explicitly reviewed again', browser => fixture(browser, {}, async (page, state, observed) => {
    await proposed(page); state.revision++;
    const loaded = page.waitForResponse(response => response.url() === ORIGIN + '/api/operator-demo/catalog');
    await page.locator('#proxy-refresh').click(); await (await loaded).finished();
    await page.waitForFunction(() => document.querySelector('#upstreams-prepare').disabled);
    assert.match(await page.locator('#upstreams-review-state').innerText(), /Workspace state changed/); assert.equal(observed.prepares.length, 0);
    await page.locator('#upstreams-review').click(); await idle(page); assert(!await page.locator('#upstreams-prepare').isDisabled());
  })],
  ['synthetic cold activation receipt is distinct from a successful client request', browser => fixture(browser, {}, async (page, state, observed) => {
    await prepare(page); terminal(state, 'activated'); await page.locator('#upstreams-check').click(); await idle(page);
    assert.match(await page.locator('#upstreams-operation-status').innerText(), /Cold-start activation is recorded/);
    assert.match(await page.locator('#upstreams-operation-status').innerText(), /not a successful client request/);
    assert.equal(await page.locator('#upstreams-effective').innerText(), TARGET.allowed_upstreams.join('\n'));
    assert(await page.locator('#upstreams-cancel').isDisabled()); assert.equal(observed.prepares.length, 1); assert.equal(observed.cancels.length, 0);
  })],
];
async function hashes() {
  const assets = await readdir(join(ROOT, 'catchplate/operator_demo_web'));
  const files = ['scripts/test_operator_upstreams_browser.cjs', 'scripts/test_operator_upstreams_ui.cjs',
    'scripts/test_operator_catalog_browser.cjs', 'scripts/test_operator_ordinary_modes_browser.cjs', 'catchplate/operator_demo_portal.py',
    ...assets.filter(name => /\.(?:js|css|html)$/.test(name)).sort().map(name => 'catchplate/operator_demo_web/' + name)];
  return Object.fromEntries(await Promise.all(files.map(async name => [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
async function runSuite(browser) {
  const before = await hashes(); const directory = await mkdtemp('/tmp/catchplate-upstreams-browser-');
  console.log(JSON.stringify({phase: 'source-before', hashes: before, artifactDirectory: directory}));
  const contexts = new Set(); let finished = false; let timeout; let passed = 0;
  const bounded = {async newContext(...args) {
    assert(!finished); const context = await browser.newContext(...args);
    if (finished) { await context.close(); throw new Error('Suite already finished'); }
    contexts.add(context); context.on('close', () => contexts.delete(context)); return context;
  }};
  try {
    await Promise.race([(async () => { for (const [name, test] of tests) { await test(bounded, directory); passed++; console.log('PASS ' + name); } })(),
      new Promise((_, reject) => { timeout = setTimeout(() => reject(new Error('Rendered destination suite exceeded 120 seconds')), 120000); })]);
    const result = {ok: true, renderedGroups: tests.length, passed, artifactDirectory: directory, backendAcceptance: false,
      externalRequests: 0, providerRequests: 0, proxyRequests: 0, deploymentFilesChanged: false, restarted: false};
    console.log(JSON.stringify(result)); return result;
  } finally {
    finished = true; clearTimeout(timeout); await Promise.all([...contexts].map(context => context.close()));
    const after = await hashes(); assert.deepEqual(after, before, 'source changed during rendered suite');
    console.log(JSON.stringify({phase: 'source-after', hashes: after, sameSource: true, passed}));
  }
}
async function run(page) { return runSuite(page.context().browser()); }
async function main() {
  assert.equal(process.argv.length, 2, 'No live target or execution arguments accepted');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  try { await runSuite(browser); } finally { await browser.close(); }
}
module.exports = {run};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

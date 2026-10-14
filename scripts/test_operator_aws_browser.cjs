#!/usr/bin/env node
// Rendered, intercepted AWS custody UI only. Reuses the catalog/ordinary fixture
// and its deny-all HTTP/WebSocket boundary; no backend, AWS, proxy or SDK proof.
const assert = require('node:assert/strict');
const {withoutMutationReview} = require('./operator_mutation_recovery_test_helpers.cjs');
const {createHash} = require('node:crypto');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {ready, view, credential, application, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture, publicCatalog, digest} = require('./test_operator_ordinary_modes_browser.cjs');
const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const CATALOG = '/api/operator-demo/catalog';
const CREATE = '/api/operator-demo/credentials/aws-sigv4';
const REPLACE = CREATE + '/replace';
const REVOKE = '/api/operator-demo/credentials/revoke';
const EXPIRY = '2026-10-09T12:00:00Z';
const ACCESS = 'AKIA' + 'A'.repeat(16);
const SESSION_ACCESS = 'ASIA' + 'B'.repeat(16);
const SECRET = 'C'.repeat(40);
const TOKEN = 'synthetic-aws-session-' + 'D'.repeat(64);
const ERROR = 'synthetic-private-aws-error-NEVER-RENDER';
const PRIVATE = [ACCESS, SESSION_ACCESS, SECRET, TOKEN, ERROR];
const clone = value => JSON.parse(JSON.stringify(value));
const CAPABILITY = {schema: 'serverware.operatorAwsCredentials/v1', connection_type: 'aws_sigv4_v1',
  create_path: CREATE, replace_path: REPLACE, revoke_path: REVOKE,
  credential_kinds: ['long_term', 'session'], signing_available: false, automatic_renewal: false};
const awsCredential = (changes = {}) => credential({name: 'Stored AWS tuple', version: 1,
  auth_type: 'aws_sigv4_v1', connection_type: 'aws_sigv4_v1', header_name: null, provider_id: 'aws',
  credential_kind: 'long_term', expires_at: null, expired: false, signing_available: false,
  credential_generation: 7, ...changes});
const card = page => page.locator('#credentials-list [data-resource-id="' + IDS.credential + '"]');
const replaceAction = page => card(page).locator('[data-action="replace-aws-credentials"]');
const panel = page => page.locator('#aws-replace-panel');
let artifacts;

function catalog(state) {
  const result = publicCatalog(state);
  if (state.awsCapability !== undefined) result.capabilities.aws_credentials = clone(state.awsCapability);
  return state.awsTransform ? state.awsTransform(result) : result;
}
async function privateAbsent(page) {
  const surfaces = await page.evaluate(() => ({url: location.href, html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].map(node => node.value),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage), writes: window.__awsStorageWrites}));
  for (const value of PRIVATE) assert(!JSON.stringify(surfaces).includes(value), 'write-only tuple or private error escaped');
  assert.deepEqual(surfaces.local, []); assert.deepEqual(withoutMutationReview(surfaces.session), []); assert.equal(surfaces.writes, 0);
}
// Independent closed DTO oracle. Synthetic values are compared but never copied
// to retained observations or assertion diagnostics. No production UI helper is used.
function admit(state, path, body) {
  assert.deepEqual(state.awsCapability, CAPABILITY);
  const fields = ['expected_policy_hash', 'expected_revision', ...(path === REVOKE ? ['id'] :
    ['credential_kind', 'access_key_id', 'secret_access_key', 'session_token', 'expires_at',
      ...(path === CREATE ? ['name'] : ['id', 'expected_credential_generation'])])];
  assert.deepEqual(Object.keys(body).sort(), fields.sort());
  assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
  if (path !== CREATE) {
    assert.equal(body.id, IDS.credential); assert.equal(state.credentials[0].status, 'active');
    if (path === REPLACE) assert.equal(body.expected_credential_generation, state.credentials[0].credential_generation);
  }
  if (path !== REVOKE) {
    const session = body.credential_kind === 'session'; assert(['long_term', 'session'].includes(body.credential_kind));
    assert(body.access_key_id === (session ? SESSION_ACCESS : ACCESS), 'complete synthetic access ID');
    assert(body.secret_access_key === SECRET, 'complete synthetic secret');
    assert(body.session_token === (session ? TOKEN : null), 'complete synthetic token or explicit null');
    assert.equal(body.expires_at, session ? EXPIRY : null);
    if (path === CREATE) { assert.equal(body.name, 'My AWS credentials'); assert.equal(state.credentials.length, 0); }
  }
}
function commit(state, path, body) {
  let target = state.credentials[0]; const previous = target?.credential_generation;
  if (path === CREATE) {
    target = awsCredential({name: body.name, credential_generation: 1}); state.credentials.push(target);
  }
  if (path === REVOKE) Object.assign(target, {status: 'revoked', credential_generation: null, revoked_at: new Date(NOW).toISOString()});
  else {
    Object.assign(target, {credential_kind: body.credential_kind, expires_at: body.expires_at,
      expired: body.expires_at !== null && Date.parse(body.expires_at) <= NOW});
    if (path === REPLACE) {
      target.credential_generation++; target.version++; target.key_replaced_at = new Date(NOW).toISOString();
    }
  }
  state.revision++;
  return {credential: clone(target), revision: state.revision, policy: catalog(state).policy,
    ...(path === REPLACE ? {key_replacement: {previous_credential_generation: previous,
      credential_generation: target.credential_generation, cache_invalidation: 'local_completed', in_flight_requests: 'not_recalled'}} : {})};
}
async function fixture(browser, options, exercise) {
  return ordinaryFixture(browser, {credentials: [awsCredential()], applications: [application()], rules: [],
    requestBodyModes: ['preserve_json_v1'], responseModes: ['projected_json', 'unfiltered_json_or_empty_v2'],
    credentialInputModes: ['insert', 'replace_exact'], ...options}, async (page, state, controls) => {
    state.awsCapability = Object.hasOwn(options, 'capability') ? options.capability : clone(CAPABILITY);
    state.awsTransform = options.transform; const observed = {posts: [], reads: 0};
    let arrived; let release;
    const arrival = new Promise(resolve => { arrived = resolve; });
    const held = options.hold ? new Promise(resolve => { release = resolve; }) : Promise.resolve();
    const answer = (route, result, status = 200) => route.fulfill({status, contentType: 'application/json',
      headers: {'Cache-Control': 'no-store'}, body: JSON.stringify(result)});
    await controls.context.addInitScript(() => {
      window.__awsStorageWrites = 0;
      const original = Storage.prototype.setItem;
      Storage.prototype.setItem = function(...args) {
        if (!(this === sessionStorage && args.length === 2 &&
            args[0] === 'serverware.operator.mutation.review.v1' && args[1] === 'required')) window.__awsStorageWrites++;
        return original.apply(this, args);
      };
    });
    page.on('download', () => state.errors.push('unexpected download'));
    const handler = async route => {
      try {
        const request = route.request(); const url = new URL(request.url()); const bytes = request.postDataBuffer();
        assert.equal(url.origin, ORIGIN); assert.equal(url.search, '');
        if (url.pathname === CATALOG) {
          assert.equal(request.method(), 'GET'); assert(!bytes?.length); assert(++observed.reads <= 48);
          await answer(route, catalog(state)); return;
        }
        assert([CREATE, REPLACE, REVOKE].includes(url.pathname)); assert.equal(request.method(), 'POST');
        assert(bytes?.length && bytes.length <= (url.pathname === REVOKE ? 2048 : 32768));
        assert(request.headers()['content-type']?.startsWith('application/json'));
        assert.equal(observed.posts.length, 0, 'at most one explicit mutation; no automatic POST retry');
        const body = JSON.parse(bytes.toString()); admit(state, url.pathname, body);
        observed.posts.push({path: url.pathname, revision: body.expected_revision,
          generation: body.expected_credential_generation ?? null, completeTuple: url.pathname !== REVOKE});
        // Commit consumes only public fields below; do not retain private request values.
        for (const name of ['access_key_id', 'secret_access_key', 'session_token']) if (Object.hasOwn(body, name)) body[name] = '';
        arrived(); await held;
        if (['409', '503'].includes(options.fault)) {
          state.expectedFailures.add(url.pathname); await answer(route, {detail: ERROR}, Number(options.fault)); return;
        }
        const result = commit(state, url.pathname, body);
        if (options.fault === 'lost-after-commit') { state.expectedFailures.add(url.pathname); await route.abort('failed'); return; }
        if (options.fault === 'bad-generation') result.key_replacement.credential_generation++;
        if (options.fault === 'bad-cache') result.key_replacement.cache_invalidation = 'provider_revoked';
        if (options.fault === 'stale-catalog') state.credentials[0].credential_generation--;
        await answer(route, result, url.pathname === CREATE ? 201 : 200);
      } catch (_) { arrived(); state.errors.push('AWS fixture closed DTO/CAS boundary failed'); await route.abort(); }
    };
    for (const path of [CATALOG, CREATE, REPLACE, REVOKE]) await controls.context.route(ORIGIN + path, handler);
    try {
      await page.reload({waitUntil: 'networkidle'}); assert.equal(new URL(page.url()).origin, ORIGIN);
      assert.match(await page.title(), /Serverware/i);
      await exercise(page, state, observed, {arrival, release: () => release?.()});
      assert.deepEqual(state.posts, [], 'no generic credential/grant/application mutation');
      assert(observed.posts.length <= 1); await privateAbsent(page);
      for (const item of state.consoleErrors) for (const value of PRIVATE) assert(!item.message.includes(value), 'private console output');
    } finally { release?.(); }
  });
}
async function accounts(page) { await ready(page); await view(page, 'credentials'); }
async function createForm(page) {
  await accounts(page); await page.locator('#credential-storage-type').selectOption('aws');
  await page.locator('#aws-credential-form').waitFor({state: 'visible'});
  await page.locator('#aws-credential-name').fill('My AWS credentials');
}
async function openReplacement(page) { await accounts(page); await replaceAction(page).click(); await panel(page).waitFor({state: 'visible'}); }
async function fillTuple(page, prefix, kind = 'long_term', expiry = EXPIRY) {
  await page.locator('#' + prefix + '-kind').selectOption(kind);
  await page.locator('#' + prefix + '-access-key-id').fill(kind === 'session' ? SESSION_ACCESS : ACCESS);
  await page.locator('#' + prefix + '-secret-access-key').fill(SECRET);
  if (kind === 'session') {
    await page.locator('#' + prefix + '-session-token').fill(TOKEN);
    await page.locator('#' + prefix + '-expires-at').fill(expiry);
  }
}
async function refresh(page) {
  await page.evaluate(() => {
    window.__awsRendered = false;
    const observer = new MutationObserver(() => { window.__awsRendered = true; observer.disconnect(); });
    observer.observe(document.querySelector('#credentials-list'), {childList: true});
  });
  const response = page.waitForResponse(value => value.url() === ORIGIN + CATALOG);
  await page.locator('#credentials-refresh').click(); await (await response).finished();
  await page.waitForFunction(() => window.__awsRendered); await page.evaluate(() => { delete window.__awsRendered; });
}
async function saved(page, prefix) {
  await page.waitForFunction(id => /(?:credentials saved|tuple replaced) in Serverware/.test(document.getElementById(id).textContent), prefix + '-status');
  await privateAbsent(page);
}
async function uncertain(page, reviewed = true) {
  await page.locator('#mutation-review').waitFor({state: 'visible'});
  if (reviewed) await page.waitForFunction(() => !document.querySelector('#mutation-review-confirm').disabled);
  await privateAbsent(page); assert.match(await page.locator('#mutation-review-text').innerText(), /no automatic retry/i);
}
async function screenshot(page, name) {
  await privateAbsent(page); await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true});
}

const tests = [
  ['AWS storage guidance follows the selected credential type on desktop and mobile', async browser => {
    const initialHtml = await readFile(join(ROOT, 'serverware/operator_demo_web/index.html'), 'utf8');
    assert.match(initialHtml, /<p\b[^>]*\bid="aws-storage-availability"[^>]*\bhidden(?:\s|>)/,
      'AWS-only guidance starts hidden for the default manual selection');
    for (const width of [1280, 390]) await fixture(browser, {credentials: []}, async (page, state, observed) => {
      await page.setViewportSize({width, height: 960}); await accounts(page);
      const selector = page.locator('#credential-storage-type');
      const guidance = page.locator('#aws-storage-availability');
      assert.equal(await selector.inputValue(), 'manual');
      assert(!await guidance.isVisible()); assert(await page.locator('#credential-form').isVisible());
      assert(!await page.locator('#aws-credential-form').isVisible());
      await screenshot(page, 'manual-guidance-' + width);
      await selector.selectOption('aws');
      assert(await guidance.isVisible()); assert(await page.locator('#aws-credential-form').isVisible());
      assert(!await page.locator('#credential-form').isVisible());
      assert.equal(await guidance.innerText(), 'Stored only — ECR publishing not available yet. Save or replace credentials only. No AWS validation request, application access or automatic renewal.');
      await screenshot(page, 'aws-guidance-' + width);
      await selector.selectOption('manual'); assert(!await guidance.isVisible());
      await selector.selectOption('aws'); state.awsCapability = null; await refresh(page);
      assert.equal(await selector.inputValue(), 'aws'); assert(await guidance.isVisible());
      assert.equal(await guidance.innerText(), 'AWS credential storage is not advertised by this deployment. Manual header credentials are not a substitute.');
      assert(await page.locator('#aws-credential-save').isDisabled());
      await selector.selectOption('manual'); assert(!await guidance.isVisible());
      assert(await page.locator('#credential-form').isVisible()); assert.equal(observed.posts.length, 0);
    });
  }],
  ...['long_term', 'session'].map(kind => [kind + ' complete create clears fields before response and grants nothing', browser =>
    fixture(browser, {credentials: [], hold: true}, async (page, state, observed, control) => {
      const before = clone({applications: state.applications, rules: state.rules, policy: catalog(state).policy});
      await createForm(page); await fillTuple(page, 'aws-credential', kind);
      assert.equal(await page.locator('#aws-credential-secret-access-key').getAttribute('type'), 'password');
      assert.equal(await page.locator('#aws-credential-session-token').getAttribute('type'), 'password');
      await page.locator('#aws-credential-save').click(); await control.arrival; await privateAbsent(page);
      assert(await page.locator('#aws-credential-save').isDisabled()); control.release(); await saved(page, 'aws-credential');
      assert.equal(observed.posts.length, 1); assert.equal(state.credentials[0].credential_kind, kind);
      assert.equal(state.credentials[0].credential_generation, 1); assert.equal(state.revision, 2);
      assert.deepEqual({applications: state.applications, rules: state.rules, policy: catalog(state).policy}, before);
      assert.match(await card(page).innerText(), /stored only.*ECR publishing not available/i);
      await card(page).locator('details > summary').click();
      assert.match(await card(page).innerText(), /validity not tested/i);
      if (kind === 'session') { await screenshot(page, 'aws-session-desktop'); await page.setViewportSize({width: 390, height: 844});
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)); await screenshot(page, 'aws-session-mobile'); }
    })]),
  ['invalid expiry, incomplete session and mismatched key kind clear secrets without a POST', browser =>
    fixture(browser, {credentials: []}, async (page, state, observed) => {
      await createForm(page);
      for (const expiry of ['2026-02-30T12:00:00Z', '2026-10-09T12:00:00+00:00', '2026-10-09T12:00:00.000Z',
        '2026-10-08T12:00:00Z', '2026-10-07T12:00:00Z', '']) {
        await fillTuple(page, 'aws-credential', 'session', expiry); await page.locator('#aws-credential-save').click(); await privateAbsent(page);
      }
      await fillTuple(page, 'aws-credential', 'session'); await page.locator('#aws-credential-session-token').fill('');
      await page.locator('#aws-credential-save').click(); await privateAbsent(page);
      await fillTuple(page, 'aws-credential'); await page.locator('#aws-credential-access-key-id').fill(SESSION_ACCESS);
      await page.locator('#aws-credential-save').click(); await privateAbsent(page);
      assert.equal(observed.posts.length, 0); assert.equal(state.credentials.length, 0);
    })],
  ['replacement sends full new tuple with exact revision and generation CAS', browser =>
    fixture(browser, {hold: true}, async (page, state, observed, control) => {
      const before = clone({applications: state.applications, rules: state.rules, policy: catalog(state).policy});
      await openReplacement(page); await fillTuple(page, 'aws-replace', 'session');
      await page.locator('#aws-replace-submit').click(); await control.arrival;
      assert(!await panel(page).isVisible()); await privateAbsent(page); control.release(); await saved(page, 'aws-replace');
      assert.deepEqual(observed.posts, [{path: REPLACE, revision: 1, generation: 7, completeTuple: true}]);
      assert.equal(state.credentials[0].credential_generation, 8); assert.equal(state.credentials[0].credential_kind, 'session');
      assert.deepEqual({applications: state.applications, rules: state.rules, policy: catalog(state).policy}, before);
      assert.match(await page.locator('#aws-replace-status').innerText(), /does not revoke or renew.*AWS/i);
    })],
  ['refreshed generation, revision, identity and policy races invalidate the draft before POST', browser =>
    fixture(browser, {}, async (page, state, observed) => {
      for (const change of [s => s.revision++, s => s.credentials[0].credential_generation++,
        s => { s.credentials[0].name = 'Renamed AWS tuple'; }, s => { s.active = s.loaded = digest(++s.sequence); }]) {
        await openReplacement(page); await fillTuple(page, 'aws-replace'); change(state); await refresh(page);
        assert(!await panel(page).isVisible()); await privateAbsent(page);
        assert.match(await page.locator('#aws-replace-status').innerText(), /saved state changed/i);
      }
      assert.equal(observed.posts.length, 0);
    })],
  ['type changes, cancel, navigation and pagehide clear unsent tuples', browser => fixture(browser, {}, async (page, state, observed) => {
    await createForm(page); await fillTuple(page, 'aws-credential', 'session');
    await page.locator('#aws-credential-kind').selectOption('long_term'); await privateAbsent(page);
    await fillTuple(page, 'aws-credential'); await page.locator('#credential-storage-type').selectOption('manual'); await privateAbsent(page);
    await openReplacement(page); await fillTuple(page, 'aws-replace'); await page.locator('#aws-replace-kind').selectOption('session'); await privateAbsent(page);
    await fillTuple(page, 'aws-replace', 'session'); await page.locator('#aws-replace-cancel').click(); await privateAbsent(page);
    assert(!await panel(page).isVisible()); await openReplacement(page); await fillTuple(page, 'aws-replace');
    await view(page, 'applications'); await privateAbsent(page); await openReplacement(page); await fillTuple(page, 'aws-replace');
    await page.evaluate(() => dispatchEvent(new PageTransitionEvent('pagehide'))); await privateAbsent(page);
    assert(!await panel(page).isVisible()); assert.equal(observed.posts.length, 0);
  })],
  ['local revocation warns that AWS is unchanged and removes only the stored tuple', browser => fixture(browser, {}, async (page, state, observed) => {
    await accounts(page); const policy = clone(catalog(state).policy);
    await card(page).locator('[data-action="revoke-credential"]').click();
    await page.waitForFunction(() => document.querySelector('#credentials-list').textContent.includes('Revoked'));
    assert.equal(state.dialogs.length, 1); assert.match(state.dialogs[0], /does not revoke.*AWS/i);
    assert.deepEqual(observed.posts, [{path: REVOKE, revision: 1, generation: null, completeTuple: false}]);
    assert.equal(state.credentials[0].status, 'revoked'); assert.equal(state.credentials[0].credential_generation, null);
    assert.deepEqual(catalog(state).policy, policy); assert.equal(state.rules.length, 0);
  })],
  ['stored and expired sessions never appear in grants, Connect or client setup', browser =>
    fixture(browser, {credentials: [awsCredential({credential_kind: 'session', expires_at: '2026-10-07T12:00:00Z', expired: true})]}, async (page, state, observed) => {
      await accounts(page); await card(page).locator('details > summary').click(); assert.match(await card(page).innerText(), /expired.*replace the complete tuple/i);
      assert(!await replaceAction(page).isDisabled());
      assert.equal(await card(page).locator('[data-action="connect-credential"]').count(), 0);
      await view(page, 'access-rules'); assert.equal(await page.locator('#rule-credential-id option[value="' + IDS.credential + '"]').count(), 0);
      await view(page, 'connect'); assert(await page.locator('#connect-use-saved').isDisabled());
      assert.equal(await page.locator('#connect-credential-choice option[value="' + IDS.credential + '"]').count(), 0);
      assert.equal(await page.locator('button[data-connection-type="aws_sigv4_v1"]').count(), 0);
      await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
      assert.equal(observed.posts.length, 0); assert.equal(state.rules.length, 0);
    })],
  ['missing, malformed and withdrawn capabilities fail closed without disabling manual storage', browser => fixture(browser, {}, async (page, state, observed) => {
    await openReplacement(page); await fillTuple(page, 'aws-replace');
    for (const capability of [undefined, null, {...CAPABILITY, signing_available: true}, {...CAPABILITY, automatic_renewal: true},
      {...CAPABILITY, replace_path: '/api/operator-demo/credentials/replace-key'}, {...CAPABILITY, extra: true}]) {
      state.awsCapability = capability; await refresh(page); assert(!await panel(page).isVisible()); await privateAbsent(page);
      assert(await page.locator('#credential-storage-aws-option').isDisabled());
      assert(!await page.locator('#credential-fields').isDisabled());
      assert(await replaceAction(page).count() === 0 || await replaceAction(page).isDisabled());
      assert(await card(page).locator('[data-action="revoke-credential"]').isDisabled());
    }
    assert.equal(observed.posts.length, 0);
  })],
  ['create and replacement uncertainty never retry after conflicts, failure or lost committed replies', async browser => {
    for (const replacing of [false, true]) for (const fault of ['409', '503', 'lost-after-commit'])
      await fixture(browser, {credentials: replacing ? [awsCredential()] : [], fault}, async (page, state, observed) => {
        if (replacing) await openReplacement(page); else await createForm(page);
        const prefix = replacing ? 'aws-replace' : 'aws-credential'; await fillTuple(page, prefix, 'session');
        await page.locator('#' + prefix + (replacing ? '-submit' : '-save')).click(); await uncertain(page);
        assert.equal(observed.posts.length, 1); assert.equal(state.revision, fault === 'lost-after-commit' ? 2 : 1);
        await page.clock.runFor(6000); assert.equal(observed.posts.length, 1);
        await page.locator('#mutation-review-confirm').click(); await page.locator('#mutation-review').waitFor({state: 'hidden'});
        await privateAbsent(page); await page.reload({waitUntil: 'networkidle'}); await ready(page);
        assert.equal(observed.posts.length, 1); await privateAbsent(page);
      });
  }],
  ['receipt generation, cache result and refreshed-generation mismatches remain uncertain', async browser => {
    for (const fault of ['bad-generation', 'bad-cache', 'stale-catalog']) await fixture(browser, {fault}, async (page, state, observed) => {
      await openReplacement(page); await fillTuple(page, 'aws-replace'); await page.locator('#aws-replace-submit').click();
      await uncertain(page, fault !== 'stale-catalog');
      if (fault === 'stale-catalog') {
        assert(await page.locator('#mutation-review-confirm').isDisabled());
        await refresh(page); await uncertain(page); assert.equal(observed.posts.length, 1);
      }
      assert.equal(state.revision, 2); assert.equal(observed.posts.length, 1);
      assert(!/Complete AWS tuple replaced in Serverware/.test(await page.locator('#aws-replace-status').innerText()));
      await page.clock.runFor(6000); assert.equal(observed.posts.length, 1);
    });
  }],
  ['contradictory public AWS metadata is rejected rather than used as generic authorization', async browser => {
    for (const changes of [{header_name: 'Authorization'}, {signing_available: true}, {credential_generation: null}, {active_rule_count: 1}])
      await fixture(browser, {transform: value => { Object.assign(value.credentials[0], changes); return value; }}, async (page, state, observed) => {
        await page.locator('#load-error').waitFor({state: 'visible'});
        for (const id of ['credential-fields', 'aws-credential-fields'])
          assert(await page.locator('#' + id).evaluate(node => node.disabled));
        for (const id of ['credential-add', 'aws-credential-name', 'aws-credential-save'])
          assert(await page.locator('#' + id).isDisabled());
        assert.equal(observed.posts.length, 0);
      });
  }],
];

async function hashes() {
  const names = ['scripts/test_operator_aws_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
    'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py',
    ...(await readdir(join(ROOT, 'serverware/operator_demo_web'))).filter(name => /\.(?:html|css|js)$/.test(name))
      .sort().map(name => 'serverware/operator_demo_web/' + name)];
  return Object.fromEntries(await Promise.all(names.map(async name =>
    [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
async function runSuite(browser) {
  assert(browser && typeof browser.newContext === 'function'); const before = await hashes();
  artifacts = await mkdtemp('/tmp/serverware-aws-browser-');
  console.log(JSON.stringify({phase: 'source-before', hashes: before, artifactDirectory: artifacts}));
  const contexts = new Set(); let timer; let finished = false; let passed = 0;
  const bounded = {async newContext(...args) {
    assert(!finished); const context = await browser.newContext(...args);
    if (finished) { await context.close(); throw new Error('suite finished'); }
    contexts.add(context); context.on('close', () => contexts.delete(context)); return context;
  }};
  try {
    await Promise.race([(async () => { for (const [name, test] of tests) {
      await test(bounded); passed++; console.log('PASS ' + name);
    } })(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('AWS rendered suite exceeded 180 seconds')), 180000); })]);
    const result = {ok: true, groups: passed, artifactDirectory: artifacts, backendAcceptance: false,
      sdkExecuted: false, providerRequests: 0, proxyRequests: 0, nativeDownloads: 0, generatedRecipeExecuted: false};
    console.log(JSON.stringify(result)); return result;
  } finally {
    finished = true; clearTimeout(timer); await Promise.all([...contexts].map(context => context.close()));
    assert.deepEqual(await hashes(), before, 'source changed during intercepted AWS suite');
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

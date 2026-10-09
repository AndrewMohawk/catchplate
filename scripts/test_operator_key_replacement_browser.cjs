#!/usr/bin/env node
// UI contract fixtures only: no real credential store, provider, proxy, cache or
// dispatch is exercised. The replacement oracle checks the public DTO/CAS and
// unchanged assignments; backend transaction/cache tests remain separate proof.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFileSync} = require('node:fs');
const {readFile, mkdtemp, stat} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {runInNewContext} = require('node:vm');
const {fixture: baseFixture, ready, view, credential, application, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const {publicCatalog} = require('./test_operator_ordinary_modes_browser.cjs');

const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://operator-catalog.example.test';
const CATALOG = ORIGIN + '/api/operator-demo/catalog';
const PATH = '/api/operator-demo/credentials/replace-key';
const ENDPOINT = ORIGIN + PATH;
const CAPABILITY = {schema: 'serverware.operatorStaticKeyReplacement/v1', path: PATH, credential_types: ['bearer', 'header']};
const KEY = 'synthetic-replacement-key-NEVER-PERSIST-$literal-123';
const OTHER_DRAFT = 'synthetic-other-key-draft-NEVER-PERSIST';
const ERROR = 'synthetic-provider-error-private-NEVER-DISPLAY';
const OTHER_KEY = '66666666-6666-4666-8666-666666666666';
const GOOGLE = '77777777-7777-4777-8777-777777777777';
const FORMER_APP = '22222222-3333-4333-8333-333333333333';
const UNRELATED_APP = '22222222-4444-4444-8444-444444444444';
const SECOND_RULE = '44444444-5555-4555-8555-555555555555';
const DUPLICATE_RULE = '44444444-6666-4666-8666-666666666666';
const FORMER_RULE = '44444444-7777-4777-8777-777777777777';
const UNRELATED_RULE = '44444444-8888-4888-8888-888888888888';
const digest = value => 'sha256:' + value.toString(16).padStart(64, '0');
const clone = value => JSON.parse(JSON.stringify(value));
const staticKey = (changes = {}) => credential({name: 'Shared reporting key', credential_generation: 7, version: 1, ...changes});
const googleKey = () => credential({id: GOOGLE, name: 'Saved Google account', auth_type: 'google_oauth',
  provider_account: 'replacement-fixture@example.test', provider_subject: 'synthetic-subject',
  oauth_client_id: 'synthetic-client.apps.googleusercontent.com', permission_preset: 'gmail_readonly',
  scopes: ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid']});
const ruleFor = (id, changes = {}) => rule({id, route_id: 'operator.' + id, ...changes});
const supplied = (changes = {}) => ({credentials: [staticKey(), staticKey({id: OTHER_KEY, name: 'Unrelated key',
    auth_type: 'header', header_name: 'X-API-Key', credential_generation: 3})],
  applications: [application(), application({id: IDS.other, name: 'Indexing worker'}),
    application({id: FORMER_APP, name: 'Former worker'}), application({id: UNRELATED_APP, name: 'Unrelated worker'})],
  rules: [rule(), ruleFor(SECOND_RULE, {application_id: IDS.other}), ruleFor(DUPLICATE_RULE),
    ruleFor(FORMER_RULE, {application_id: FORMER_APP, status: 'revoked'}),
    ruleFor(UNRELATED_RULE, {credential_id: OTHER_KEY, application_id: UNRELATED_APP})],
  credentialInputModes: ['insert', 'replace_exact'], ...changes});
const card = (page, id = IDS.credential) => page.locator('#credentials-list [data-resource-id="' + id + '"]');
const replaceAction = (page, id = IDS.credential) => card(page, id).locator('[data-action="replace-key"]');
const panel = page => page.locator('#credential-replace-panel');
const secret = page => page.locator('#credential-replace-secret');
const INPUTS = ['scripts/test_operator_key_replacement_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
  'scripts/test_operator_ordinary_modes_browser.cjs', 'serverware/operator_demo_portal.py',
  ...['index.html', 'style.css', 'app.js', 'workspace_core.js', 'workspace_github.js', 'workspace_resources.js', 'workspace_applications.js',
    'workspace_proxy_audit.js', 'workspace_connect.js', 'workspace_google.js'].map(name => 'serverware/operator_demo_web/' + name)];
let artifacts;
async function hashes() { return Object.fromEntries(await Promise.all(INPUTS.map(async name =>
  [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')]))); }
async function screenshot(page, name) {
  await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true,
    mask: [secret(page), page.locator('#client-token')]});
}
async function noSecret(page) {
  const text = await page.evaluate(() => JSON.stringify({html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].map(item => item.value),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  for (const value of [KEY, OTHER_DRAFT, ERROR]) assert(!text.includes(value), 'replacement material and raw errors must not remain in browser surfaces');
}
async function refreshCatalog(page) {
  await page.evaluate(() => {
    window.__replacementRendered = false;
    const observer = new MutationObserver(() => { window.__replacementRendered = true; observer.disconnect(); });
    observer.observe(document.querySelector('#credentials-list'), {childList: true});
  });
  const response = page.waitForResponse(value => value.url() === CATALOG && value.request().method() === 'GET');
  await page.locator('#credentials-refresh').click(); await (await response).finished();
  await page.waitForFunction(() => window.__replacementRendered === true); await page.evaluate(() => { delete window.__replacementRendered; });
}
function catalog(state) {
  const value = publicCatalog(state);
  if (state.replacementCapability !== undefined) value.capabilities.static_key_replacement = state.replacementCapability;
  if (state.publicGenerationOverride !== undefined) value.credentials.find(item => item.id === IDS.credential).credential_generation = state.publicGenerationOverride;
  return value;
}
function admitReplacement(state, body) {
  assert.deepEqual(state.replacementCapability, CAPABILITY, 'replacement requires its exact advertised capability');
  assert.deepEqual(Object.keys(body).sort(), ['expected_credential_generation', 'expected_policy_hash', 'expected_revision', 'id', 'secret']);
  assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
  assert(Number.isSafeInteger(body.expected_credential_generation) && body.expected_credential_generation > 0 &&
    body.expected_credential_generation < Number.MAX_SAFE_INTEGER);
  const target = state.credentials.find(item => item.id === body.id);
  assert(target?.status === 'active' && ['bearer', 'header'].includes(target.auth_type));
  assert.equal(body.expected_credential_generation, target.credential_generation);
  assert(typeof body.secret === 'string' && /^[\x20-\x7e]{1,8192}$/.test(body.secret)); assert.equal(body.secret, KEY);
  // Record only the public CAS and proof that the synthetic value matched; never
  // include submitted secret bytes in evidence or failure-summary objects.
  const receipt = {id: body.id, expected_revision: body.expected_revision, expected_policy_hash: body.expected_policy_hash,
    expected_credential_generation: body.expected_credential_generation, secretMatched: true};
  state.replacements.push(receipt); return target;
}
function commitReplacement(state, target) {
  const previous = target.credential_generation; target.credential_generation++; target.version++;
  target.key_replaced_at = new Date(NOW).toISOString(); state.revision++;
  return {credential: catalog(state).credentials.find(item => item.id === target.id), revision: state.revision,
    policy: catalog(state).policy, key_replacement: {previous_credential_generation: previous,
      credential_generation: target.credential_generation, cache_invalidation: state.replacementFault === 'cache-unconfirmed' ? 'local_unconfirmed' : 'local_completed',
      in_flight_requests: 'not_recalled'}};
}
async function fixture(browser, options, exercise) {
  return baseFixture(browser, supplied(options), async (page, state, controls) => {
    state.replacementCapability = Object.hasOwn(options, 'capability') ? options.capability : clone(CAPABILITY);
    state.replacements = []; state.replacementRequests = []; state.replacementFault = options.replacementFault;
    let catalogReads = 0; let release; let received;
    const arrival = new Promise(resolve => { received = resolve; });
    const responseGate = options.deferResponse ? new Promise(resolve => { release = resolve; }) : Promise.resolve();
    const answer = (route, value, status = 200) => route.fulfill({status, contentType: 'application/json', body: JSON.stringify(value)});
    await controls.context.route(CATALOG, async route => {
      const request = route.request();
      if (++catalogReads > 20 || request.url() !== CATALOG || request.method() !== 'GET' || request.postDataBuffer()?.length) {
        state.unexpected.push('replacement catalog boundary refused'); await route.abort(); return;
      }
      state.catalogCalls++;
      if (state.catalogStatus !== 200) { state.expectedFailures.add('/api/operator-demo/catalog'); await answer(route, {detail: ERROR}, state.catalogStatus); return; }
      await answer(route, catalog(state));
    });
    await controls.context.route(ENDPOINT, async route => {
      const request = route.request(); const bytes = request.postDataBuffer();
      try {
        assert.equal(request.url(), ENDPOINT); assert.equal(request.method(), 'POST');
        assert(bytes && bytes.length <= 16384 && state.replacementRequests.length === 0, 'one bounded explicit replacement only');
        assert(request.headers()['content-type']?.startsWith('application/json'));
        state.replacementRequests.push({method: request.method(), path: PATH});
        const body = JSON.parse(bytes.toString()); const target = admitReplacement(state, body); body.secret = '';
        received(); await responseGate;
        if (state.replacementFault === '409') { state.expectedFailures.add(PATH); await answer(route, {detail: ERROR}, 409); return; }
        if (state.replacementFault === 'lost-before-commit') { state.expectedFailures.add(PATH); await route.abort('failed'); return; }
        const result = commitReplacement(state, target);
        if (state.replacementFault === 'lost-after-commit') { state.expectedFailures.add(PATH); await route.abort('failed'); return; }
        if (state.replacementFault === 'stale-catalog') state.publicGenerationOverride = target.credential_generation - 1;
        if (state.replacementFault === 'catalog-failure') state.catalogStatus = 503;
        if (state.replacementFault === 'malformed-receipt') result.key_replacement.credential_generation++;
        await answer(route, result);
      } catch (error) {
        // Assertions compare synthetic values only. Keep the page's diagnostic
        // channel free of request bodies even on an oracle mismatch.
        state.errors.push('replacement fixture DTO/CAS boundary failed'); received(); await route.abort();
      }
    });
    try {
      await ready(page); await view(page, 'credentials'); await refreshCatalog(page);
      await exercise(page, state, {arrival, release: () => release?.()});
      assert(state.replacementRequests.length <= 1);
      assert.deepEqual(state.posts.map(item => item.name), options.allowApplicationCreation ? ['applications'] : [],
        'only the held-token control may explicitly create an app; never recreate credentials or rules, start OAuth or revoke');
      assert(catalogReads >= 1); await noSecret(page);
    } finally { release?.(); }
  });
}
async function open(page, id = IDS.credential) {
  await replaceAction(page, id).click(); await panel(page).waitFor({state: 'visible'});
  assert.equal(await secret(page).inputValue(), ''); assert.equal(await secret(page).getAttribute('type'), 'password');
  assert.equal(await secret(page).getAttribute('autocomplete'), 'new-password');
}
async function submit(page) { await secret(page).fill(KEY); await page.locator('#credential-replace-submit').click(); }
async function uncertain(page, freshRequired = false) {
  await page.locator('#mutation-review').waitFor({state: 'visible'});
  if (freshRequired) assert(await page.locator('#mutation-review-confirm').isDisabled());
  else await page.waitForFunction(() => !document.querySelector('#mutation-review-confirm').disabled);
  assert(!await panel(page).isVisible()); assert.equal(await secret(page).inputValue(), '');
  assert.match(await page.locator('#mutation-review-text').innerText(), /no automatic retry/i);
  assert(await replaceAction(page).isDisabled()); assert(await page.locator('#credential-save').isDisabled());
  assert(await page.locator('#application-create').isDisabled()); assert(await page.locator('#rule-save').isDisabled()); await noSecret(page);
}

function projectionChecks() {
  const source = ['workspace_core.js', 'workspace_github.js']
    .map(name => readFileSync(join(ROOT, 'serverware/operator_demo_web', name), 'utf8')).join('\n');
  const {clientCredentialInput, credentialHeaderTarget} = require('../serverware/operator_demo_web/app.js');
  const projected = (capability, target = staticKey()) => {
    const state = {...supplied({credentials: [target], applications: [], rules: []}), revision: 1,
      sequence: 1, active: digest(1), loaded: digest(1), responseModes: ['projected_json'], replacementCapability: capability};
    const input = catalog(state);
    return clone(runInNewContext(source + '\n(() => { const result = projectCatalog(input); return {result, available: staticKeyReplacementAvailable(result, result.credentials[0])}; })()',
      {input, clientCredentialInput, credentialHeaderTarget}, {timeout: 1000}));
  };
  assert.equal(projected(CAPABILITY).available, true);
  for (const value of [undefined, null, {}, {...CAPABILITY, schema: 'unknown'}, {...CAPABILITY, path: '/api/operator-demo/credentials'},
    {...CAPABILITY, credential_types: ['bearer']}, {...CAPABILITY, credential_types: ['bearer', 'header', 'google_oauth']}, {...CAPABILITY, extra: true}]) {
    const valueProjected = projected(value); assert.equal(valueProjected.available, false); assert.equal(valueProjected.result.credentials[0].id, IDS.credential);
  }
  for (const credential_generation of [undefined, null, 0, -1, 1.5, '7', Number.MAX_SAFE_INTEGER]) {
    const value = projected(CAPABILITY, staticKey({credential_generation})); assert.equal(value.available, false); assert.equal(value.result.credentials[0].id, IDS.credential);
  }
  for (const key_replaced_at of [null, '', '2026-02-30T12:00:00Z', 'not-a-time', '2026-10-09T12:00:00+04:00'])
    assert.equal(projected(CAPABILITY, staticKey({key_replaced_at})).available, false);
  const replaced = projected(CAPABILITY, staticKey({key_replaced_at: new Date(NOW).toISOString(), secret: KEY, access_token: ERROR}));
  assert.equal(replaced.available, true); assert(!JSON.stringify(replaced).includes(KEY)); assert(!JSON.stringify(replaced).includes(ERROR));
  assert.equal(projected(CAPABILITY, staticKey({status: 'revoked', credential_generation: null})).available, false);
  const oauth = projected(CAPABILITY, {...googleKey(), credential_generation: 7, key_replaced_at: new Date(NOW).toISOString()});
  assert.equal(oauth.available, false); assert(!Object.hasOwn(oauth.result.credentials[0], 'credential_generation'));
  return {ok: true, groups: 1, scope: 'real public capability/metadata projection only; no replacement runtime or provider validation'};
}
async function replacementLayout(page) {
  return page.evaluate(() => {
    const parent = document.querySelector('#credential-replace-panel').getBoundingClientRect();
    const selectors = ['#credential-replace-panel', '#credential-replace-title', '#credential-replace-apps',
      '#credential-replace-apps li', '#credential-replace-panel .actions', '#credential-replace-secret',
      '#credential-replace-submit', '#credential-replace-cancel'];
    const inside = (rect, outer) => rect.left >= outer.left - 1 && rect.right <= outer.right + 1;
    const items = selectors.map(selector => {
      const node = document.querySelector(selector); const box = node.getBoundingClientRect();
      return {selector, visible: box.width > 0 && box.height > 0,
        fits: box.left >= -1 && box.right <= innerWidth + 1 && inside(box, parent) &&
          node.scrollWidth <= node.clientWidth + 1};
    });
    const text = ['#credential-replace-title', '#credential-replace-apps li'].map(selector => {
      const node = document.querySelector(selector); const box = node.getBoundingClientRect();
      const range = document.createRange(); range.selectNodeContents(node);
      const lines = [...range.getClientRects()];
      let unclipped = true;
      for (let ancestor = node; ancestor; ancestor = ancestor.parentElement) {
        const style = getComputedStyle(ancestor);
        if (['hidden', 'clip'].includes(style.overflowX) || ['hidden', 'clip'].includes(style.overflowY) ||
            style.textOverflow === 'ellipsis' || style.clipPath !== 'none' ||
            !['none', ''].includes(style.getPropertyValue('-webkit-line-clamp'))) unclipped = false;
        if (ancestor.id === 'credential-replace-panel') break;
      }
      return {selector, unclipped, fits: lines.length > 0 && lines.every(rect => inside(rect, box) &&
        inside(rect, parent) && rect.top >= box.top - 1 && rect.bottom <= box.bottom + 1)};
    });
    return {viewport: innerWidth, documentFits: document.documentElement.scrollWidth <= innerWidth + 1, items, text};
  });
}
function assertReplacementLayout(measured, width) {
  assert.equal(measured.viewport, width);
  assert(measured.documentFits, 'replacement review must not create horizontal document scrolling at ' + width);
  for (const item of measured.items) assert(item.visible && item.fits, item.selector + ' must fit at ' + width);
  for (const item of measured.text) assert(item.unclipped && item.fits, item.selector + ' must show every wrapped text line at ' + width);
}
const layoutTest = ['long live-style names wrap without clipping and keep replacement controls usable on mobile', browser => {
  const prefix = 'serverware-live-smoke-aebf2cf3eea3401d9accc224004dfd85';
  const credentialName = prefix + '-credential'; const applicationName = prefix + '-application';
  return fixture(browser, {credentials: [staticKey({name: credentialName})],
    applications: [application({name: applicationName})], rules: [rule()]}, async (page, state) => {
    const before = clone({credentials: state.credentials, applications: state.applications,
      rules: state.rules, revision: state.revision, policy: catalog(state).policy});
    // One group: two bounded mobile widths plus unchanged desktop rendering.
    for (const width of [390, 320, 1280]) {
      await page.setViewportSize({width, height: width < 800 ? 844 : 960}); await open(page);
      assert.equal(await page.locator('#credential-replace-title').innerText(), 'Replace key · ' + credentialName);
      assert.deepEqual(await page.locator('#credential-replace-apps li').allTextContents(), [applicationName]);
      assertReplacementLayout(await replacementLayout(page), width);
      if (width < 800) {
        // Synthetic causal control only: temporarily undo the scoped wrapping
        // rule in this intercepted document, never production files/live DOM.
        const control = await page.addStyleTag({content: '#credential-replace-panel{overflow-wrap:normal}'});
        try {
          const unwrapped = await replacementLayout(page);
          assert(!unwrapped.documentFits || unwrapped.items.some(item => !item.fits) ||
            unwrapped.text.some(item => !item.fits), 'unwrapped long-name control must reproduce overflow at ' + width);
        } finally { await control.evaluate(node => node.remove()); }
        assertReplacementLayout(await replacementLayout(page), width);
      }
      assert(await secret(page).isEditable());
      assert(!await page.locator('#credential-replace-submit').isDisabled());
      assert(!await page.locator('#credential-replace-cancel').isDisabled());
      // Trial checks click reachability without submitting even an empty form.
      await page.locator('#credential-replace-submit').click({trial: true});
      await screenshot(page, 'replace-key-long-names-' + width);
      await secret(page).fill(KEY); assert.equal(await secret(page).inputValue(), KEY);
      await page.locator('#credential-replace-cancel').click();
      assert(!await panel(page).isVisible()); await noSecret(page);
      await open(page); await page.locator('#credential-replace-cancel').click();
    }
    assert.equal(state.replacementRequests.length, 0); assert.equal(state.replacements.length, 0);
    assert.equal(state.posts.length, 0); assert(state.requests.every(request => request.method === 'GET'));
    assert.deepEqual({credentials: state.credentials, applications: state.applications,
      rules: state.rules, revision: state.revision, policy: catalog(state).policy}, before);
  });
}];
const tests = [
  ...['bearer', 'header'].map(auth_type => [auth_type + ' replacement reviews exact affected apps and preserves identity and assignments', browser => fixture(browser,
    {credentials: [staticKey({auth_type, header_name: auth_type === 'bearer' ? 'Authorization' : 'X-Reporting-Key'}), supplied().credentials[1]],
      deferResponse: true}, async (page, state, controls) => {
      const before = clone({credentials: state.credentials, applications: state.applications, rules: state.rules,
        policy: catalog(state).policy, revision: state.revision});
      await open(page); assert.equal(await page.locator('#credential-replace-title').innerText(), 'Replace key · Shared reporting key');
      assert.equal(await page.locator('#credential-replace-count').innerText(), '2 affected apps · 3 active access rules. Existing permissions stay unchanged.');
      assert.deepEqual(await page.locator('#credential-replace-apps li').evaluateAll(items => items.map(item =>
        ({id: item.dataset.applicationId, name: item.textContent}))), [{id: IDS.application, name: 'Reporting application'}, {id: IDS.other, name: 'Indexing worker'}]);
      const text = await panel(page).innerText(); assert(!text.includes('Former worker') && !text.includes('Unrelated worker'));
      assert.match(text, /previously issued proxy leases and requests already in flight may still use the old key/i);
      assert.match(text, /does not revoke it at the provider/i); assert.match(text, /no provider validation request is made/i);
      if (auth_type === 'bearer') {
        await screenshot(page, 'replace-key-review-desktop'); await page.setViewportSize({width: 390, height: 844});
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1));
        await screenshot(page, 'replace-key-review-mobile');
      }
      await submit(page); await controls.arrival; assert(!await panel(page).isVisible()); await noSecret(page);
      assert(await page.locator('#credential-save').isDisabled()); controls.release();
      await page.waitForFunction(() => document.querySelector('#credential-action-status').textContent.startsWith('Replacement saved in Serverware.'));
      assert.deepEqual(state.replacements, [{id: IDS.credential, expected_revision: 1, expected_policy_hash: digest(1), expected_credential_generation: 7, secretMatched: true}]);
      assert.deepEqual(state.applications, before.applications); assert.deepEqual(state.rules, before.rules); assert.deepEqual(catalog(state).policy, before.policy);
      assert.deepEqual(state.credentials.map(item => item.id), before.credentials.map(item => item.id)); assert.equal(state.credentials[0].credential_generation, 8);
      for (const key of ['id', 'name', 'auth_type', 'header_name', 'status', 'created_at']) assert.equal(state.credentials[0][key], before.credentials[0][key]);
      assert.deepEqual(state.credentials[1], before.credentials[1]); assert.equal(state.revision, before.revision + 1); assert.equal(state.posts.length, 0);
      await card(page).locator('details > summary').click(); assert.match(await card(page).locator('[data-key-replacement-details]').innerText(), /stored key generation\s+8/i);
      assert.match(await page.locator('#credential-action-status').innerText(), /leases.*in flight.*old key.*does not revoke/is);
      assert(!await replaceAction(page).isDisabled()); await noSecret(page);
    })]),
  ['cancel clears the unsent value and reopening starts blank without mutating resources', browser => fixture(browser, {}, async (page, state) => {
    await open(page); await secret(page).fill(KEY); await page.locator('#credential-replace-cancel').click();
    assert(!await panel(page).isVisible()); await noSecret(page); assert.match(await page.locator('#credential-action-status').innerText(), /no key was submitted/i);
    await open(page); await page.locator('#credential-replace-cancel').click(); assert.equal(state.replacements.length, 0); assert.equal(state.posts.length, 0);
  })],
  ['navigation and pagehide clear only the unsent replacement draft', browser => fixture(browser, {}, async (page, state) => {
    await open(page); await secret(page).fill(KEY); await view(page, 'applications'); await noSecret(page);
    await view(page, 'credentials'); assert(!await panel(page).isVisible()); await open(page); await secret(page).fill(KEY);
    await page.evaluate(() => window.dispatchEvent(new PageTransitionEvent('pagehide'))); assert(!await panel(page).isVisible()); await noSecret(page);
    await page.reload({waitUntil: 'networkidle'}); await ready(page); await view(page, 'credentials');
    assert(!await panel(page).isVisible()); await noSecret(page); assert.equal(state.replacements.length, 0);
  })],
  ['changing the selected key clears its prior secret and reviews only the new exact target', browser => fixture(browser, {}, async (page, state) => {
    await open(page); await secret(page).fill(OTHER_DRAFT); await open(page, OTHER_KEY);
    assert.equal(await page.locator('#credential-replace-title').innerText(), 'Replace key · Unrelated key');
    assert.deepEqual(await page.locator('#credential-replace-apps li').evaluateAll(items => items.map(item => item.dataset.applicationId)), [UNRELATED_APP]);
    await noSecret(page); await page.locator('#credential-replace-cancel').click(); await open(page); await noSecret(page);
    await page.locator('#credential-replace-cancel').click(); assert.equal(state.replacements.length, 0);
  })],
  ['refresh drift in revision policy generation identity or assignments clears the unsent draft', browser => fixture(browser, {}, async (page, state) => {
    const baseline = clone({credentials: state.credentials, applications: state.applications, rules: state.rules});
    const changes = [value => { value.revision++; }, value => { value.active = value.loaded = digest(++value.sequence); },
      value => { value.credentials[0].credential_generation++; }, value => { value.credentials[0].name = 'Renamed key'; },
      value => { value.rules[0].name = 'Changed permission'; }, value => { value.applications[0].token_generation++; }];
    for (const change of changes) {
      Object.assign(state, clone(baseline)); await refreshCatalog(page); await open(page); await secret(page).fill(KEY);
      change(state); await refreshCatalog(page); assert(!await panel(page).isVisible()); await noSecret(page);
      assert.match(await page.locator('#credential-action-status').innerText(), /saved state changed.*new key was cleared.*open replace key again/is);
    }
    assert.equal(state.replacements.length, 0);
  })],
  ['conflict and lost POST outcomes never retry and require the shared explicit review', async browser => {
    for (const replacementFault of ['409', 'lost-before-commit', 'lost-after-commit']) await fixture(browser, {replacementFault}, async (page, state) => {
      await open(page); await submit(page); await uncertain(page);
      assert.equal(state.replacements.length, 1); assert.equal(state.credentials[0].credential_generation, replacementFault === 'lost-after-commit' ? 8 : 7);
      await page.clock.runFor(6000); assert.equal(state.replacements.length, 1);
      await page.locator('#mutation-review-confirm').click(); await page.locator('#mutation-review').waitFor({state: 'hidden'});
      assert(!await replaceAction(page).isDisabled()); assert.equal(state.replacements.length, 1); assert.equal(state.posts.length, 0); await noSecret(page);
    });
  }],
  ['failed reconciliation requires fresh review and catalog authorization loss clears an unsent key', async browser => {
    for (const replacementFault of ['malformed-receipt', 'stale-catalog', 'catalog-failure']) await fixture(browser, {replacementFault}, async (page, state) => {
      await open(page); await submit(page); await uncertain(page, replacementFault !== 'malformed-receipt');
      assert.equal(state.credentials[0].credential_generation, 8); assert.equal(state.replacements.length, 1);
      assert(!/^Replacement saved in Serverware\./.test(await page.locator('#credential-action-status').innerText()));
      assert.match(await page.locator('#mutation-review-text').innerText(), /do not assume rollback/i);
      if (replacementFault === 'catalog-failure') assert(await page.locator('#load-error').isVisible());
      await page.clock.runFor(6000); assert.equal(state.replacements.length, 1);
      state.publicGenerationOverride = undefined; state.catalogStatus = 200; await refreshCatalog(page);
      assert(await replaceAction(page).isDisabled()); assert(!await page.locator('#mutation-review-confirm').isDisabled());
      await page.locator('#mutation-review-confirm').click(); await page.locator('#mutation-review').waitFor({state: 'hidden'});
      assert(!await replaceAction(page).isDisabled()); assert.equal(state.replacements.length, 1); await noSecret(page);
    });
    for (const catalogStatus of [401, 403]) await fixture(browser, {}, async (page, state) => {
      await open(page); await secret(page).fill(KEY); state.catalogStatus = catalogStatus;
      // Authorization loss disables retained cards rather than replacing them,
      // so await the exact response and terminal error instead of the success
      // helper's resource-list MutationObserver.
      const response = page.waitForResponse(value => value.url() === CATALOG && value.request().method() === 'GET');
      await page.locator('#credentials-refresh').click(); const result = await response;
      assert.equal(result.status(), catalogStatus); await result.finished(); await page.locator('#load-error').waitFor({state: 'visible'});
      assert.equal(await page.locator('#load-error-text').innerText(), 'Your session or request origin could not be verified. Reload and sign in again.');
      assert(!await panel(page).isVisible()); assert.equal(await secret(page).inputValue(), '');
      for (const id of ['credential-save', 'application-create', 'rule-save', 'mutation-review-confirm']) assert(await page.locator('#' + id).isDisabled());
      assert(await replaceAction(page).isDisabled()); await noSecret(page);
      await page.clock.runFor(6000); assert.equal(state.replacements.length, 0); assert.equal(state.replacementRequests.length, 0);
      assert.equal(state.posts.length, 0); assert.equal(state.credentials[0].credential_generation, 7);
    });
  }],
  ['missing malformed or withdrawn capability disables replacement only and clears an open draft', browser => fixture(browser, {}, async (page, state) => {
    await open(page); await secret(page).fill(KEY);
    for (const capability of [undefined, null, {}, {...CAPABILITY, schema: 'unsupported'}, {...CAPABILITY, path: '/api/operator-demo/credentials'},
      {...CAPABILITY, credential_types: ['bearer', 'header', 'google_oauth']}, {...CAPABILITY, extra: true}]) {
      state.replacementCapability = capability; await refreshCatalog(page); assert(!await panel(page).isVisible());
      assert.equal(await replaceAction(page).count(), 0); assert(!await page.locator('#load-error').isVisible());
      assert(!await page.locator('#credential-save').isDisabled()); await noSecret(page);
    }
    state.replacementCapability = clone(CAPABILITY); await refreshCatalog(page); await open(page);
    await page.locator('#credential-replace-cancel').click(); assert.equal(state.replacements.length, 0);
  })],
  ['Google and revoked credentials never expose the static replacement action', browser => fixture(browser,
    {credentials: [staticKey(), staticKey({id: OTHER_KEY, status: 'revoked', credential_generation: null}), googleKey()],
      rules: [rule()]}, async (page, state) => {
      assert.equal(await replaceAction(page, GOOGLE).count(), 0); assert.equal(await replaceAction(page, OTHER_KEY).count(), 0);
      assert.equal(await replaceAction(page).count(), 1); assert(await page.locator('#credential-google-connect').isDisabled());
      assert.equal(await card(page, GOOGLE).locator('[data-action="revoke-credential"]').count(), 0);
      assert.equal(state.replacements.length, 0); assert.equal(state.posts.length, 0);
    })],
  ['missing invalid or unadvanceable public generation and invalid replacement time fail only the action closed', browser => fixture(browser, {}, async (page, state) => {
    const baseline = clone(state.credentials[0]);
    for (const changes of [{credential_generation: undefined}, {credential_generation: null}, {credential_generation: 0}, {credential_generation: '7'},
      {credential_generation: Number.MAX_SAFE_INTEGER}, {key_replaced_at: 'not-a-time'}, {key_replaced_at: '2026-02-30T12:00:00Z'}]) {
      state.credentials[0] = {...baseline, ...changes}; await refreshCatalog(page);
      assert.equal(await replaceAction(page).count(), 0); assert(!await page.locator('#load-error').isVisible());
      assert(!await page.locator('#credential-save').isDisabled());
    }
    state.credentials[0] = baseline; await refreshCatalog(page); await open(page); await page.locator('#credential-replace-cancel').click();
    assert.equal(state.replacements.length, 0);
  })],
  ['replacement preserves an already held one-time application token without recreating credentials or rules', browser => fixture(browser,
    {applications: [], rules: [], allowApplicationCreation: true}, async (page, state) => {
      await view(page, 'applications'); await page.locator('#application-name').fill('New worker');
      await page.locator('#application-token-ttl').selectOption('3600'); await page.locator('#application-create').click();
      await page.locator('#one-time-access').waitFor({state: 'visible'}); const held = await page.locator('#client-token').inputValue();
      assert(held.startsWith('synthetic_application_')); await view(page, 'credentials'); await open(page); await submit(page);
      await page.waitForFunction(() => document.querySelector('#credential-action-status').textContent.startsWith('Replacement saved in Serverware.'));
      assert.equal(await page.locator('#client-token').inputValue(), held); assert.equal(state.applications.length, 1); assert.equal(state.rules.length, 0);
      assert.deepEqual(state.posts.map(item => item.name), ['applications']); assert.equal(state.replacements.length, 1); await noSecret(page);
    })],
  ['local cache uncertainty remains explicit after confirmed storage and does not imply provider revocation or immediate use', browser => fixture(browser,
    {replacementFault: 'cache-unconfirmed'}, async (page, state) => {
      await open(page); await submit(page);
      await page.waitForFunction(() => document.querySelector('#credential-action-status').textContent.startsWith('Replacement saved in Serverware.'));
      const text = await page.locator('#credential-action-status').innerText();
      assert.match(text, /local cache invalidation was not confirmed/i); assert.match(text, /leases.*in flight.*old key/is);
      assert.match(text, /does not revoke it at the provider/i); assert(!/all (new )?requests use|provider (valid|healthy)|revoked at provider/i.test(text));
      assert.equal(state.replacements.length, 1); assert.equal(state.posts.length, 0);
    })],
  layoutTest,
];

async function main() {
  const args = process.argv.slice(2); const layoutOnly = args.length === 1 && args[0] === '--layout-only';
  assert(args.length === 0 || layoutOnly, 'usage: test_operator_key_replacement_browser.cjs [--layout-only]; no live target or token accepted');
  assert.equal(tests.length, 14, 'focused rendered group count stays exact');
  const selected = layoutOnly ? [layoutTest] : tests;
  const before = await hashes(); console.log(JSON.stringify({phase: 'source-before', hashes: before}));
  console.log(JSON.stringify({phase: 'selection', groups: selected.length, totalGroups: tests.length,
    layoutOnly, projectionGroups: layoutOnly ? 0 : 1, names: selected.map(([name]) => name)}));
  if (!layoutOnly) console.log(JSON.stringify(projectionChecks()));
  const artifactRoot = '/srv/catchplate-fast/projects/serverware-operator-artifacts';
  assert((await stat(artifactRoot)).isDirectory()); artifacts = await mkdtemp(join(artifactRoot, 'key-replacement-browser-synthetic-'));
  console.log(JSON.stringify({artifactDirectory: artifacts, scope: 'synthetic replacement review screenshots only; password fields masked'}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']}); let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of selected) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: selected.length, totalGroups: tests.length, layoutOnly,
        scope: 'intercepted static key replacement UI fixtures only',
        backendTransactionTested: false, cacheInvalidationTested: false, providerValidationTested: false,
        liveRequests: 0, generatedCommandsExecuted: false, productionAcceptance: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('key replacement fixture absolute deadline')), layoutOnly ? 60000 : 150000); })]);
  } finally {
    clearTimeout(deadline); try { await browser.close(); }
    finally { const after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after})); assert.deepEqual(after, before, 'sources remained frozen'); }
  }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });


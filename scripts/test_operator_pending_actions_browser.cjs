'use strict';
// Actual complete public renderer, intercepted synthetic GETs, fresh contexts.
// The caller owns the browser and outer deadline. No browser launch, server,
// provider, private review, decision, native acceptance or deployment claim.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {createHash} = require('node:crypto');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {tmpdir} = require('node:os');
const {capability, approval, CAP, LIST, NOW, ID, OTHER, PRIVATE, INJECTED} = require('./test_operator_pending_actions_ui.cjs');
const ROOT = resolve(__dirname, '..'), ORIGIN = 'https://pending-actions.example.test';
const CATALOG = '/api/operator-demo/catalog', X = '/api/operator-demo/oauth/x/configuration/v1';
const ASSETS = join(ROOT, 'catchplate/operator_demo_web');
function latch() { let release; const promise = new Promise(resolve => { release = resolve; }); return {promise, release}; }
async function hashes() {
  const files = (await readdir(ASSETS)).filter(name => /\.(js|css|html)$/.test(name)).sort();
  const paths = ['catchplate/operator_demo_portal.py', 'scripts/test_operator_pending_actions_ui.cjs',
    'scripts/test_operator_pending_actions_browser.cjs', ...files.map(name => 'catchplate/operator_demo_web/' + name)];
  return Object.fromEntries(await Promise.all(paths.map(async name => [name,
    createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
function renderDocument() {
  // Reuse the maintained isolated public-renderer pattern, not app.py startup
  // or a second JS template implementation. No inherited application settings.
  return execFileSync('/usr/bin/python3', ['-I', '-B', '-c', `
import importlib.util, pathlib, sys
def deny_runtime(event, args):
    if event.startswith(('socket.', 'subprocess.')) or event in {'os.system', 'os.fork', 'os.posix_spawn'}:
        raise AssertionError('renderer attempted runtime I/O')
sys.addaudithook(deny_runtime)
spec = importlib.util.spec_from_file_location('public_renderer_only', pathlib.Path(sys.argv[1]))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(module.render())
`, join(ROOT, 'catchplate/operator_demo_portal.py')], {encoding: 'utf8', timeout: 10000,
    maxBuffer: 2 * 1024 * 1024, env: {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8'}});
}
async function ready(page) {
  await page.waitForFunction(() => {
    const panel = document.getElementById('pending-actions');
    return !panel.hidden && panel.getAttribute('aria-busy') === 'false' &&
      !/Loading|have not been loaded/.test(document.getElementById('pending-actions-status').textContent);
  });
}
const count = (state, path) => state.requests.filter(item => item.path === path).length;
const selected = page => page.locator('#pending-actions-selected');
async function noReview(page) {
  for (const button of await page.locator('#pending-actions [data-pending-review]').all())
    assert(await button.isDisabled(), 'unavailable or held review must not be actionable');
  assert.equal(await page.locator('#pending-actions').getByRole('button', {name: /^(Approve|Deny)/}).count(), 0);
}
async function fixture(browser, html, artifacts, label, options, exercise) {
  const state = {requests: [], unexpected: [], errors: [], consoleErrors: [], expectedFailures: new Set(),
    rows: options.rows || [], capability: options.capability || capability(), capStatus: options.capStatus || 200,
    listStatus: options.listStatus || 200, selected: options.selected || null,
    catalogStatus: 503, capReplies: 0, released: [], contextClosed: false};
  const context = await browser.newContext({viewport: {width: 1280, height: 960}, serviceWorkers: 'block'});
  let page, failure, result;
  try {
    await context.route('**/*', async route => {
      const request = route.request(), url = new URL(request.url()), path = url.pathname + url.search;
      state.requests.push({method: request.method(), path});
      const json = async (body, status = 200) => {
        if (status >= 400) state.expectedFailures.add(path);
        await route.fulfill({status, contentType: 'application/json', headers: {'Cache-Control': 'no-store'}, body: JSON.stringify(body)});
      };
      try {
        assert.equal(url.origin, ORIGIN); assert.equal(request.method(), 'GET'); assert.equal(request.postDataBuffer(), null);
        assert(state.requests.length <= 40, 'bounded synthetic request count');
        if (request.isNavigationRequest() && [options.path || '/', '/'].includes(url.pathname) && !url.search)
          return await route.fulfill({status: 200, contentType: 'text/html', body: html});
        if (path === '/favicon.ico') return await route.fulfill({status: 204, body: ''});
        if (path === CATALOG) return await json({detail: 'synthetic catalog unavailable'}, state.catalogStatus);
        if (path === X) return await json({detail: 'X configuration is not supported by this deployment'}, 404);
        if (path === CAP) {
          if (options.capGate && count(state, CAP) === 1) await options.capGate.promise;
          state.capReplies++;
          return await json(state.capStatus === 200 ? state.capability : {detail: PRIVATE}, state.capStatus);
        }
        if (path === LIST) {
          assert(state.capReplies >= count(state, LIST), 'each list must follow a capability reply');
          assert.equal(state.capability.can_list, true, 'list must be advertised');
          const rows = state.rows;
          if (options.listGate && count(state, LIST) === 1) await options.listGate.promise;
          return await json(state.listStatus === 200 ? rows : {detail: PRIVATE}, state.listStatus);
        }
        if (path === '/api/approvals/' + ID)
          return await json(state.selected || {detail: 'approval not found'}, state.selected ? 200 : 404);
        state.unexpected.push('unlisted synthetic path'); await route.abort('blockedbyclient');
      } catch (error) {
        // A deliberately aborted old metadata fetch may finish after navigation.
        if (request.failure()?.errorText === 'net::ERR_ABORTED') return;
        state.errors.push({kind: 'fixture contract', message: error.message});
        try { await route.abort('failed'); } catch (_) {}
      }
    });
    await context.routeWebSocket('**/*', socket => { state.unexpected.push('WebSocket'); socket.close(); });
    if (options.storage) await context.addInitScript(entries => {
      for (const [key, value] of entries) sessionStorage.setItem(key, value);
    }, options.storage);
    page = await context.newPage(); page.setDefaultTimeout(5000); page.setDefaultNavigationTimeout(10000);
    page.on('pageerror', error => state.errors.push({kind: 'pageerror', message: error.message}));
    page.on('console', message => { if (message.type() === 'error') state.consoleErrors.push({text: message.text(), url: message.location().url}); });
    page.on('dialog', async dialog => { state.unexpected.push('dialog'); await dialog.dismiss(); });
    await page.clock.setFixedTime(new Date(NOW));
    // Wait for application state, not a browser-wide network-idle heuristic.
    // Held-response stories deliberately exercise the intermediate loading UI.
    await page.goto(ORIGIN + (options.path || '/') + (options.hash || ''), {waitUntil: 'domcontentloaded'});
    result = await exercise(page, state);
    await page.locator('#load-error').waitFor({state: 'visible'});
    assert.deepEqual(state.unexpected, []); assert.deepEqual(state.errors, []);
    for (const error of state.consoleErrors) {
      const url = new URL(error.url);
      assert.equal(url.origin, ORIGIN); assert(state.expectedFailures.has(url.pathname + url.search), 'only expected synthetic HTTP failures');
      assert.match(error.text, /^Failed to load resource:/);
    }
    assert(state.requests.every(item => item.method === 'GET'));
    assert(!state.requests.some(item => /bootstrap|\/review|\/options|\/approve|\/deny/.test(item.path)));
    await noReview(page);
  } catch (error) {
    failure = error;
    if (page) try { await page.screenshot({path: join(artifacts, label + '-failure.png'), fullPage: true, timeout: 3000}); } catch (_) {}
  } finally {
    options.capGate?.release(); options.listGate?.release();
    try { await context.close(); state.contextClosed = true; }
    catch (error) { if (!failure) failure = error; }
  }
  const receipt = {label, ok: !failure, contextClosed: state.contextClosed, requests: state.requests,
    unexpected: state.unexpected, errors: state.errors};
  if (failure) { failure.fixtureReceipt = receipt; throw failure; }
  return {...receipt, result};
}
const tests = [
  ['lazy queue remains usable when catalog is unavailable; select desktop and mobile', async (browser, html, artifacts) =>
    fixture(browser, html, artifacts, 'navigation', {rows: [approval({route_id: INJECTED, canonical_request: PRIVATE})]}, async (page, state) => {
      await page.locator('#load-error').waitFor({state: 'visible'});
      assert.equal(count(state, CAP), 0); assert.equal(count(state, LIST), 0);
      await page.locator('nav a[href="#pending-actions"]').click(); await ready(page);
      assert.equal(await page.title(), 'Pending actions - Catchplate operator workspace');
      assert.equal(await page.locator('#pending-actions-list [data-pending-approval-id]').count(), 1);
      assert(await page.locator('#load-error').isVisible());
      await page.locator('[data-pending-select="' + ID + '"]').click();
      assert.equal(new URL(page.url()).pathname, '/approvals/' + ID); assert.equal(new URL(page.url()).hash, '#pending-actions');
      assert((await selected(page).innerText()).includes('Permission name unavailable'));
      const details = selected(page).locator('[data-pending-exact-details]');
      assert.equal(await details.getAttribute('open'), null);
      await details.locator('summary').click();
      assert((await selected(page).innerText()).includes(ID)); assert((await selected(page).innerText()).includes(INJECTED));
      assert(!(await page.locator('#pending-actions').innerText()).includes(PRIVATE));
      assert.equal(await page.locator('#pending-actions img, #pending-actions script').count(), 0);
      assert.equal(await page.evaluate(() => globalThis.pendingInjected), undefined);
      await page.screenshot({path: join(artifacts, 'pending-actions-desktop.png'), fullPage: true});
      await page.setViewportSize({width: 390, height: 844}); assert(await selected(page).isVisible());
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.screenshot({path: join(artifacts, 'pending-actions-mobile.png'), fullPage: true});
      const beforeJump = state.requests.length;
      await page.locator('#pending-requests-jump').focus(); await page.keyboard.press('Enter');
      assert.equal(await page.evaluate(() => document.activeElement.id), 'pending-requests-title');
      assert(await page.locator('#pending-images-jump').isDisabled());
      assert.equal(state.requests.length, beforeJump, 'queue shortcut is navigation only');
      assert.equal(count(state, CAP), 1); assert.equal(count(state, LIST), 1);
    })],
  ['capability and metadata loading are separate and never open review', async (browser, html, artifacts) => {
    const capGate = latch(), listGate = latch();
    return fixture(browser, html, artifacts, 'loading', {path: '/approvals', capGate, listGate, rows: [approval()]}, async (page, state) => {
      await page.waitForFunction(() => document.getElementById('pending-actions-status').textContent.includes('Loading'));
      assert.equal(count(state, LIST), 0); assert(await page.locator('#pending-actions-refresh').isDisabled());
      const listed = page.waitForRequest(request => new URL(request.url()).pathname + new URL(request.url()).search === LIST);
      capGate.release(); await listed; assert(await page.locator('#pending-actions-refresh').isDisabled());
      assert.equal(await page.locator('#pending-actions-list article').count(), 0);
      listGate.release(); await ready(page); assert.equal(count(state, CAP), 1); assert.equal(count(state, LIST), 1);
    });
  }],
  ['deep link survives reload and a missing exact request never falls back', async (browser, html, artifacts) =>
    fixture(browser, html, artifacts, 'deep-link', {path: '/approvals/' + ID, rows: [approval(), approval({id: OTHER})]}, async (page, state) => {
      await ready(page); assert((await selected(page).textContent()).includes(ID));
      assert(!(await selected(page).textContent()).includes(OTHER));
      await page.reload({waitUntil: 'domcontentloaded'}); await ready(page);
      assert.equal(new URL(page.url()).pathname, '/approvals/' + ID); assert((await selected(page).textContent()).includes(ID));
      state.rows = [approval({id: OTHER})]; await page.locator('#pending-actions-refresh').click(); await ready(page);
      assert((await selected(page).innerText()).includes('not found'));
      assert(!(await selected(page).innerText()).includes(OTHER)); assert.equal(new URL(page.url()).pathname, '/approvals/' + ID);
      assert.equal(count(state, LIST), 3);
    })],
  ['invalid link remains explicit, and role refusal never loads metadata', async (browser, html, artifacts) => {
    const receipts = [];
    receipts.push(await fixture(browser, html, artifacts, 'invalid-link', {path: '/approvals/not-a-uuid', rows: [approval()]}, async page => {
      await ready(page); assert((await selected(page).innerText()).includes('link is invalid'));
      assert(!(await selected(page).innerText()).includes(ID)); assert.equal(new URL(page.url()).pathname, '/approvals/not-a-uuid');
    }));
    receipts.push(await fixture(browser, html, artifacts, 'role-refusal', {path: '/approvals',
      capability: capability({can_list: false, reason: 'role_required'})}, async (page, state) => {
      await ready(page); assert((await page.locator('#pending-actions-access').innerText()).includes('role does not allow'));
      assert.equal(count(state, LIST), 0); assert.equal(await page.locator('#pending-actions-list article').count(), 0);
    })); return receipts;
  }],
  ['empty, failed refresh, and recovered metadata have distinct honest states', async (browser, html, artifacts) =>
    fixture(browser, html, artifacts, 'empty-error', {path: '/approvals'}, async (page, state) => {
      await ready(page); assert.equal(await page.locator('#pending-actions-status').innerText(), 'No individual requests awaiting approval.');
      state.listStatus = 503; await page.locator('#pending-actions-refresh').click(); await ready(page);
      assert((await page.locator('#pending-actions-status').innerText()).includes('could not be loaded'));
      assert(!(await page.locator('#pending-actions').innerText()).includes(PRIVATE));
      state.listStatus = 200; state.rows = [approval()]; await page.locator('#pending-actions-refresh').click(); await ready(page);
      assert.equal(await page.locator('#pending-actions-list article').count(), 1);
      assert.equal(count(state, CAP), 3); assert.equal(count(state, LIST), 3);
    })],
  ['leaving aborts stale metadata and re-entry reads a fresh exact selection', async (browser, html, artifacts) => {
    const listGate = latch();
    return fixture(browser, html, artifacts, 'stale-navigation', {path: '/approvals/' + ID, listGate, rows: [approval()]}, async (page, state) => {
      await page.waitForFunction(() => document.getElementById('pending-actions-status').textContent.includes('Loading'));
      // Observe the actual held list request before leaving, without a sleep.
      if (!count(state, LIST)) await page.waitForRequest(request => new URL(request.url()).pathname + new URL(request.url()).search === LIST);
      await page.locator('nav a[href="#overview"]').click();
      assert.equal(await page.locator('#pending-actions-list article').count(), 0);
      state.rows = [approval({id: OTHER})]; listGate.release();
      await page.locator('nav a[href="#pending-actions"]').click(); await ready(page);
      assert.equal(await page.locator('#pending-actions-list [data-pending-approval-id="' + OTHER + '"]').count(), 1);
      assert((await selected(page).innerText()).includes('not found'));
      assert(!(await selected(page).innerText()).includes(OTHER)); assert.equal(new URL(page.url()).pathname, '/approvals/' + ID);
    });
  }],
  ['held decisions stay held even when a synthetic capability advertises protected review', async (browser, html, artifacts) => {
    const key = 'catchplate.approvalDecisionUncertain.' + ID;
    return fixture(browser, html, artifacts, 'held-decision', {path: '/approvals/' + ID, rows: [approval()], storage: [[key, ID]],
      capability: capability({can_open_native_review: true, can_decide: true, reason: null})}, async (page, state) => {
      await ready(page); assert((await selected(page).innerText()).includes('submitted decision needs status recovery'));
      assert.match(await page.locator('#pending-actions-access').innerText(), /inspect its protected review before deciding/);
      const before = await page.evaluate(() => Object.entries(sessionStorage));
      await page.locator('#pending-actions-refresh').click(); await ready(page);
      assert.deepEqual(await page.evaluate(() => Object.entries(sessionStorage)), before);
      assert.deepEqual(before.filter(([name]) => name === key), [[key, ID]]);
      assert.equal(count(state, LIST), 2); await noReview(page);
    });
  }],
  ['external catalog authentication loss clears queue but transient catalog failure does not', async (browser, html, artifacts) =>
    fixture(browser, html, artifacts, 'external-auth-loss', {path: '/approvals/' + ID, rows: [approval()]}, async (page, state) => {
      await ready(page); assert.equal(await page.locator('#pending-actions-list article').count(), 1);
      const refreshed = page.waitForResponse(response => new URL(response.url()).pathname === CATALOG);
      await page.locator('#retry-load').click(); assert.equal((await refreshed).status(), 503);
      assert.equal(await page.locator('#pending-actions-list article').count(), 1);
      state.catalogStatus = 401; await page.locator('#retry-load').click();
      await page.waitForFunction(() => document.getElementById('pending-actions-status').textContent.includes('sign in again'));
      assert.equal(await page.locator('#pending-actions-list article').count(), 0);
      assert(!(await selected(page).innerText()).includes('synthetic.status.read')); assert.equal(count(state, LIST), 1);
    })],
  ['exact selected request shows its terminal outcome after refresh and reload', async (browser, html, artifacts) =>
    fixture(browser, html, artifacts, 'terminal-status', {path: '/approvals/' + ID, rows: [approval()]}, async (page, state) => {
      await ready(page); assert((await selected(page).innerText()).includes('Status: Pending'));
      state.rows = []; state.selected = approval({status: 'approved', canonical_request: PRIVATE});
      await page.locator('#pending-actions-refresh').click(); await ready(page);
      assert((await selected(page).innerText()).includes('Status: Approved'));
      assert((await selected(page).innerText()).includes('does not confirm that the provider request completed'));
      assert(!(await selected(page).innerText()).includes(PRIVATE));
      assert.equal(await page.locator('#pending-actions-list article').count(), 0);
      await page.reload({waitUntil: 'domcontentloaded'}); await ready(page);
      assert((await selected(page).innerText()).includes('Status: Approved'));
      await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.screenshot({path: join(artifacts, 'terminal-status-mobile.png'), fullPage: true});
      assert.equal(count(state, '/api/approvals/' + ID), 2);
    })],
  ['request approvals precede image reviews and both keyboard shortcuts only move focus', async (browser, _html, artifacts) => {
    const catalogFixture = require('./test_operator_catalog_browser.cjs');
    const {CAPABILITY} = require('./test_operator_ecr_ui.cjs');
    return catalogFixture.fixture(browser, {catalogTransform: value => ({...value,
      capabilities: {...value.capabilities, ecr_publication: CAPABILITY}})}, async (page, state) => {
      const reads = [], errors = [];
      await page.route('**/api/**', async route => {
        const request = route.request(), url = new URL(request.url()), path = url.pathname + url.search;
        const replies = {[CAP]: capability(), [LIST]: [], '/api/operator-demo/ecr-publications': {publications: [], next_cursor: null}};
        if (!Object.hasOwn(replies, path)) return route.fallback();
        if (request.method() !== 'GET' || request.postData() !== null || url.origin !== 'https://operator-catalog.example.test') {
          errors.push('unexpected request'); return route.abort();
        }
        reads.push(path);
        await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(replies[path])});
      });
      await catalogFixture.ready(page); await catalogFixture.view(page, 'pending-actions'); await ready(page);
      await page.waitForFunction(() => document.getElementById('ecr-publications-summary').dataset.state === 'ready');
      const before = reads.length;
      assert.deepEqual([...reads].sort(), [CAP, LIST, '/api/operator-demo/ecr-publications'].sort());
      for (const width of [1280, 390]) {
        await page.setViewportSize({width, height: 844});
        assert((await page.locator('#pending-requests-panel').boundingBox()).y < (await page.locator('#ecr-publications-panel').boundingBox()).y);
        for (const [jump, title] of [['pending-images-jump', 'ecr-publications-title'], ['pending-requests-jump', 'pending-requests-title']]) {
          await page.locator('#' + jump).focus(); await page.keyboard.press('Enter');
          assert.equal(await page.evaluate(() => document.activeElement.id), title);
        }
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
        await page.screenshot({path: join(artifacts, 'request-and-image-queues-' + width + '.png'), fullPage: true});
      }
      assert.equal(reads.length, before); assert.equal(state.posts.length, 0); assert.deepEqual(errors, []);
    });
  }],
];
async function runSuite(browser, {onlyGroups = null} = {}) {
  const selectedGroups = onlyGroups === null ? tests.map((_, index) => index) : onlyGroups;
  assert(Array.isArray(selectedGroups) && selectedGroups.length > 0 &&
    new Set(selectedGroups).size === selectedGroups.length && selectedGroups.every(index =>
      Number.isInteger(index) && index >= 0 && index < tests.length), 'exact nonempty group selection');
  const before = await hashes(), html = renderDocument();
  const artifactDirectory = await mkdtemp(join(tmpdir(), 'catchplate-pending-actions-browser-'));
  const groups = []; let activeGroup = null, failure;
  try {
    for (const index of selectedGroups) {
      const [name, run] = tests[index]; activeGroup = name;
      groups.push({name, receipts: await run(browser, html, artifactDirectory)});
    }
  } catch (error) { failure = error; }
  const after = await hashes();
  try { assert.deepEqual(after, before, 'public source unchanged during rendered suite'); } catch (error) { failure ||= error; }
  const result = {ok: !failure, groups: groups.length, totalGroups: tests.length,
    selectedGroups, completed: groups, failedGroup: failure ? activeGroup : null,
    failureReceipt: failure?.fixtureReceipt || null, artifactDirectory, before, after,
    scope: 'actual rendered public workspace with intercepted synthetic GETs only',
    backendAcceptance: false, nativeReviewAcceptance: false, productionAcceptance: false};
  if (failure) { failure.result = result; throw failure; } return result;
}
if (require.main === module) throw new Error('Caller must supply an existing bounded browser via runSuite(browser); no live target CLI.');
module.exports = {runSuite};

#!/usr/bin/env node
// Actual rendered assets with intercepted synthetic audit GETs. No app, proxy,
// audit producer, provider, write, retry or delivery is exercised.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {tmpdir} = require('node:os');
const {join, resolve} = require('node:path');
const {fixture: catalogFixture, ready, view, credential, application, rule} = require('./test_operator_catalog_browser.cjs');
const {marker, record, TYPE, UNKNOWN} = require('./test_operator_audit_outcome_ui.cjs');

const ROOT = resolve(__dirname, '..');
const PATH = '/api/audit/search';
const ORIGIN = 'https://operator-catalog.example.test';
const ATTEMPT = '11111111-1111-4111-8111-111111111111';
const INJECTED = '<img src="https://untrusted.example.test/audit" onerror="globalThis.auditInjected=true">';
const DENIED = 'data_plane.request.denied', APPROVAL = 'operator.host_approval.requested';
let artifacts; let activeGroup = null;
const item = (index, body, type = TYPE) => record(body, type, 'synthetic-audit-' + index);
async function hashes() {
  const assets = (await readdir(join(ROOT, 'catchplate/operator_demo_web'))).filter(name => /\.(js|css|html)$/.test(name)).sort();
  const paths = ['scripts/test_operator_audit_outcome_browser.cjs', 'scripts/test_operator_audit_outcome_ui.cjs',
    'scripts/test_operator_catalog_browser.cjs', 'catchplate/operator_demo_portal.py',
    ...assets.map(name => 'catchplate/operator_demo_web/' + name)];
  return Object.fromEntries(await Promise.all(paths.map(async name => [name,
    createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
async function fixture(browser, items, exercise, options = {}) {
  return catalogFixture(browser, options, async (page, state) => {
    const reads = []; const errors = [];
    await page.route('**/api/audit/search**', async route => {
      try {
        const request = route.request(); const url = new URL(request.url());
        assert.equal(request.method(), 'GET'); assert.equal(request.postData(), null);
        assert.equal(url.origin, ORIGIN); assert.equal(url.pathname, PATH); assert(reads.length < 16);
        assert.equal(url.searchParams.get('limit'), '20'); assert.equal(url.searchParams.get('scanLimit'), '5000');
        assert([...url.searchParams.keys()].every(key => ['limit', 'scanLimit', 'eventType', 'q'].includes(key)));
        const type = url.searchParams.get('eventType'); const query = url.searchParams.get('q');
        assert([null, TYPE, 'data_plane.response.released', DENIED, APPROVAL].includes(type)); assert([null, ATTEMPT].includes(query));
        const selected = items.filter(value => (!type || value.event_type === type) && (!query || value.event.attempt_id === query));
        reads.push({type, query});
        await route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify({
          ok: true, complete: true, has_more: false, next_cursor: null, items: selected})});
      } catch (_) { errors.push('audit fixture contract refused'); await route.abort('failed'); }
    });
    async function load(action, expected = items) {
      const response = page.waitForResponse(value => new URL(value.url()).pathname === PATH && value.request().method() === 'GET');
      await action(); await (await response).finished();
      await page.waitForFunction(values => document.getElementById('audit-status').textContent === values.length + ' events shown. End of matching history.' &&
        JSON.stringify([...document.querySelectorAll('#audit-list pre')].map(node => JSON.parse(node.textContent))) === JSON.stringify(values), expected);
      assert.deepEqual(await page.locator('#audit-list pre').evaluateAll(nodes => nodes.map(node => JSON.parse(node.textContent))), expected);
      assert.equal(await page.locator('#audit-list img, #audit-list script, #audit-list button').count(), 0);
      for (const link of await page.locator('#audit-list a').all()) {
        const href = await link.getAttribute('href');
        assert(href === '#pending-actions' && await link.getAttribute('data-audit-pending-link') !== null ||
          href === '#overview' && await link.locator('..').innerText() === 'Historical event. Check the current policy on Overview',
          'only fixed local review and current-policy links are allowed');
      }
      assert.equal(await page.evaluate(() => globalThis.auditInjected), undefined);
    }
    await ready(page);
    await load(() => view(page, 'audit'));
    await exercise(page, {load, reads});
    assert.deepEqual(errors, []); assert.equal(state.posts.length, 0);
    assert(state.requests.every(value => value.method === 'GET'));
    assert(!state.requests.some(value => /oauth|\/ca\.pem|\/echo/.test(value.path)));
    assert(reads.length > 0 && reads.length <= 16);
  });
}
const card = (page, index) => page.locator('#audit-list .event-card').nth(index);
const note = (page, index) => card(page, index).locator('[data-audit-provider-outcome]');
const tests = [
  ['denial and approval filters expose safe summaries with exact current resource joins', async browser => {
    const client = application(), permission = rule();
    const binding = {principal_id: client.principal_id, route_id: permission.route_id};
    const items = [item(1, {...binding, outcome: 'denied', status_code: 403, error: 'credential_lease_unavailable'}, DENIED),
      item(2, {...binding, outcome: 'requested'}, APPROVAL),
      item(3, {outcome: 'denied', status_code: 403, principal_id: INJECTED, route_id: INJECTED, error: INJECTED, reason: INJECTED}, DENIED)];
    await fixture(browser, items, async (page, {load, reads}) => {
      assert.equal(await card(page, 0).locator('h3').innerText(), 'Request denied');
      const summary = await card(page, 0).locator('[data-audit-summary]').innerText();
      assert(summary.includes('Client: ' + client.name)); assert(summary.includes('Permission: ' + permission.name));
      assert(summary.includes('Proxy HTTP 403'));
      assert.match(await card(page, 0).locator('[data-audit-reason]').innerText(), /credential could not be released/i);
      assert.equal(await card(page, 1).locator('h3').innerText(), 'Approval requested');
      assert.match(await card(page, 1).locator('[data-audit-reason]').innerText(), /not an approval/);
      assert.doesNotMatch(await card(page, 2).locator('[data-audit-summary], [data-audit-reason]').allTextContents().then(values => values.join(' ')), /untrusted|<img|auditInjected/);
      assert.match(await card(page, 2).locator('[data-audit-summary]').innerText(), /Not identified in the current catalog/);
      assert.equal(await page.locator('#audit-list [data-audit-provider-outcome]').count(), 0, 'denials do not acquire a fabricated provider outcome');
      await load(() => page.locator('#audit-filter').selectOption(DENIED), [items[0], items[2]]);
      await load(() => page.locator('#audit-filter').selectOption(APPROVAL), [items[1]]);
      assert.deepEqual(reads.at(-1), {type: APPROVAL, query: null});
      await page.screenshot({path: join(artifacts, 'approval-audit-summary.png'), fullPage: true});
    }, {credentials: [credential()], applications: [client], rules: [permission]});
  }],
  ['administrative audit rows explain historical policy errors and saved resources without unrelated placeholders', async browser => {
    const savedCredential = credential(), client = application(), permission = rule();
    const administrativeItem = (index, event, type) => ({...item(index, {}, type),
      actor_type: type.startsWith('operator_catalog.') ? 'admin' : 'data_plane', event});
    const items = [administrativeItem(1, {error: INJECTED}, 'data_plane.policy.reload_failed'),
      administrativeItem(2, {resource_type: 'credential', resource_id: savedCredential.id}, 'operator_catalog.credential.created'),
      administrativeItem(3, {resource_type: 'application', resource_id: client.id}, 'operator_catalog.application.revoked'),
      administrativeItem(4, {resource_type: 'access_rule', resource_id: permission.id, application_id: client.id}, 'operator_catalog.access_rule.created'),
      administrativeItem(5, {resource_type: 'credential', resource_id: INJECTED}, 'operator_catalog.credential.revoked'),
      administrativeItem(6, {}, INJECTED)];
    await fixture(browser, items, async page => {
      assert.deepEqual(await page.locator('#audit-list h3').allTextContents(), ['Policy refresh failed', 'Credential saved',
        'Client revoked', 'Permission saved', 'Credential revoked locally', 'Recorded event']);
      assert(await card(page, 0).getByRole('link', {name: 'Check the current policy on Overview'}).isVisible());
      await card(page, 0).locator('summary').click();
      assert.match(await card(page, 0).locator('[data-audit-reason]').innerText(), /historical event does not establish a current outage/);
      await card(page, 0).locator('summary').click();
      assert.equal(await card(page, 0).locator('[data-audit-summary]').count(), 0);
      assert.equal(await card(page, 1).locator('[data-audit-summary]').innerText(), 'Credential: ' + savedCredential.name);
      assert.equal(await card(page, 2).locator('[data-audit-summary]').innerText(), 'Client: ' + client.name);
      assert.equal(await card(page, 3).locator('[data-audit-summary]').innerText(), 'Client: ' + client.name + ' · Permission: ' + permission.name);
      for (const index of [4, 5]) assert.equal(await card(page, index).locator('[data-audit-summary]').count(), 0);
      assert.doesNotMatch((await page.locator('#audit-list h3, [data-audit-summary], [data-audit-reason]').allTextContents()).join(' '), /untrusted|<img|Not identified|auditInjected/);
      assert.equal(await page.locator('#audit-list [data-audit-provider-outcome]').count(), 0);
      await page.screenshot({path: join(artifacts, 'administrative-audit-summary.png'), fullPage: true});
    }, {credentials: [savedCredential], applications: [client], rules: [permission]});
  }],
  ['marked write and read-only outcomes remain distinct and retain exact details and attempt IDs', browser => fixture(browser, [
    item(1, {...marker(), error: INJECTED}), item(2, marker('attempted')),
    item(3, marker('response_received', false)), item(4, marker('attempted', false))
  ], async page => {
    const prefixes = ['Provider response withheld.', 'Provider dispatch was attempted.'];
    for (let index = 0; index < 4; index++) {
      const expected = prefixes[index % 2] + (index < 2 ?
        ' This write may have completed. Check the provider before retrying; do not retry automatically.' :
        ' Provider completion is unconfirmed; do not retry automatically.');
      assert.equal(await note(page, index).innerText(), expected);
      assert.equal(await note(page, index).getAttribute('data-audit-provider-outcome'), index < 2 ? 'write_unconfirmed' : 'completion_unconfirmed');
      assert.equal(await note(page, index).evaluate(node => node.classList.contains('warning')), index < 2);
      assert((await card(page, index).locator('pre').textContent()).includes(ATTEMPT));
    }
    await card(page, 0).locator('summary').click();
    assert.equal(JSON.parse(await card(page, 0).locator('pre').innerText()).event.error, INJECTED);
    assert.equal(await page.locator('#audit-filter option[value="' + TYPE + '"]').textContent(), 'Responses withheld');
    await page.screenshot({path: join(artifacts, 'marked-provider-outcomes.png'), fullPage: true});
  })],
  ['legacy status release-started partial and malformed markers remain unknown', browser => fixture(browser, [
    item(1, {upstream_status: 201, release_started: true}),
    item(2, {providerOperationMayHaveCommitted: true, retryProviderRequest: false}),
    item(3, {...marker(), retryProviderRequest: 0}),
    item(4, {response_validation: marker(), error: INJECTED})
  ], async page => {
    for (let index = 0; index < 4; index++) {
      assert.equal(await note(page, index).innerText(), UNKNOWN);
      assert.equal(await note(page, index).getAttribute('data-audit-provider-outcome'), 'unknown');
      assert.equal(await note(page, index).evaluate(node => node.classList.contains('warning')), false);
    }
    await page.screenshot({path: join(artifacts, 'legacy-provider-outcome-unknown.png'), fullPage: true});
  })],
  ['event filters and attempt search remain GET-only without inventing warnings for released records', async browser => {
    const items = [item(1, marker()), item(2, {...marker(), outcome: 'released'}, 'data_plane.response.released'),
      item(3, {attempt_id: '22222222-2222-4222-8222-222222222222'})];
    await fixture(browser, items, async (page, {load, reads}) => {
      assert.equal(await card(page, 1).locator('[data-audit-provider-outcome]').count(), 0);
      await load(() => page.locator('#audit-filter').selectOption(TYPE), [items[0], items[2]]);
      await page.locator('#audit-query').fill(ATTEMPT);
      await load(() => page.locator('#audit-search-form button').click(), [items[0]]);
      await load(() => page.locator('#audit-refresh').click(), [items[0]]);
      assert.deepEqual(reads.at(-1), {type: TYPE, query: ATTEMPT});
      assert.equal(await note(page, 0).getAttribute('data-audit-provider-outcome'), 'write_unconfirmed');
      await page.locator('#audit-integrity > summary').click();
      assert.equal(await page.locator('#audit-verification').innerText(), 'Verify the stored audit chain again for this history view.');
    });
  }],
  ['mobile warning and expandable metadata remain readable without an action or retry control', browser => fixture(browser,
    [item(1, marker())], async page => {
      await page.setViewportSize({width: 390, height: 844}); await card(page, 0).locator('summary').click();
      assert(await note(page, 0).isVisible()); assert(await card(page, 0).locator('pre').isVisible());
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      assert.equal(await card(page, 0).locator('button, a, input').count(), 0);
      await page.screenshot({path: join(artifacts, 'provider-write-warning-mobile.png'), fullPage: true});
    })],
  ['routine history is compact, details retain original records and an empty search is not absence proof', async browser => {
    const items = Array.from({length: 20}, (_, index) => item(index + 1, {}, 'operator_catalog.credential.created'));
    await fixture(browser, items, async (page, {load, reads}) => {
      for (const width of [1280, 390]) {
        await page.setViewportSize({width, height: 844});
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
        const height = (await page.locator('#audit-list').boundingBox()).height;
        assert(height < 4000, '20 routine records should not require more than 4000 pixels');
        assert.equal(await page.locator('#audit-list details[open]').count(), 0);
        assert.equal(await page.locator('#audit-list time').first().getAttribute('datetime'), items[0].created_at);
        assert.equal(await page.locator('#audit-integrity').getAttribute('open'), null);
        await page.screenshot({path: join(artifacts, 'compact-audit-' + width + '.png'), fullPage: true});
      }
      const before = reads.length;
      await card(page, 0).locator('summary').click();
      assert.deepEqual(JSON.parse(await card(page, 0).locator('pre').innerText()), items[0]);
      await page.locator('#audit-integrity > summary').click();
      assert(await page.locator('#audit-verify').isVisible());
      assert.equal(reads.length, before, 'opening details never requests another history page');
      await load(() => page.locator('#audit-filter').selectOption(DENIED), []);
      assert(await page.locator('#audit-empty').isVisible());
      assert.match(await page.locator('#audit-empty').innerText(), /does not prove.*never happened/);
      await load(() => page.locator('#audit-filter').selectOption(''), items);
      assert(!(await page.locator('#audit-empty').isVisible()));
    });
  }],
];
async function main() {
  assert.equal(process.argv.length, 2, 'synthetic fixture accepts no live targets');
  const before = await hashes(); console.log(JSON.stringify({phase: 'source-before', hashes: before}));
  artifacts = await mkdtemp(join(tmpdir(), 'catchplate-audit-outcome-browser-'));
  console.log(JSON.stringify({artifactDirectory: artifacts}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking',
    '--disable-component-update', '--disable-sync', '--host-resolver-rules=MAP * ~NOTFOUND']});
  let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of tests) { activeGroup = name; await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: tests.length, liveRequests: 0, providerRequests: 0,
        scope: 'intercepted rendered audit presentation; no audit producer, dispatch or provider completion proof'}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('audit fixture deadline')), 60000); })]);
  } finally {
    clearTimeout(deadline);
    try { await browser.close(); }
    finally { const after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after})); assert.deepEqual(after, before); }
  }
}
if (require.main === module) main().catch(error => {
  const frames = typeof error?.stack === 'string' ? error.stack.split('\n').slice(1).map(line =>
    line.match(/(?:test_operator_audit_outcome_browser|test_operator_catalog_browser)\.cjs:\d+:\d+/)?.[0]).filter(Boolean).slice(0, 8) : [];
  console.error(JSON.stringify({error: 'audit outcome browser fixture failed', group: activeGroup, frames})); process.exitCode = 1;
});

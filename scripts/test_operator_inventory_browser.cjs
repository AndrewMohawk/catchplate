#!/usr/bin/env node
// Saved-resource discovery against intercepted synthetic catalog GETs only.
const assert = require('node:assert/strict');
const {fixture, ready, view, credential, application, rule, NOW, UPSTREAM} = require('./test_operator_catalog_browser.cjs');
const id = n => '00000000-0000-4000-8000-' + String(n).padStart(12, '0');

async function run(browser) {
  const credentials = [], applications = [], rules = [];
  for (let n = 1; n <= 4; n++) {
    const name = ['Release automation', 'Billing worker', 'Local connection check', 'Former integration'][n - 1];
    const status = n === 4 ? 'revoked' : 'active';
    credentials.push(credential({id: id(n), name: name + ' key', status}));
    applications.push(application({id: id(n + 10), name, status,
      ...(n === 2 ? {token_status: 'expired', token_expires_at_epoch_ms: NOW - 1} : {})}));
    rules.push(rule({id: id(n + 20), route_id: 'operator.' + id(n + 20), name: name + ' permission',
      credential_id: id(n), application_id: id(n + 10), status,
      ...(n === 3 ? {upstream_url: 'https://demo-upstream:8443/echo'} : {})}));
  }
  const results = [];
  await fixture(browser, {credentials, applications, rules,
    allowedUpstreams: [UPSTREAM, 'https://demo-upstream:8443']}, async (page, state) => {
    await ready(page);
    const cases = [['credentials', 'credentials-list', 'credentials-refresh', 2],
      ['applications', 'applications-list', 'applications-refresh', 12],
      ['access-rules', 'access-rules-list', 'rules-refresh', 22]];
    for (const width of [1280, 390]) {
      await page.setViewportSize({width, height: 960});
      for (const [name, list, refresh, match] of cases) {
        await view(page, name);
        const search = page.locator('#' + list + '-inventory-search');
        const group = page.locator('#' + list + '-inventory-group');
        const clear = page.locator('#' + name + ' [role="search"] button');
        if (name !== 'access-rules') {
          await page.locator('[data-inventory-jump="' + list + '"]').click();
          assert(await search.evaluate(el => el === document.activeElement));
        }
        const requests = state.requests.length;
        await search.fill('  BILLING worker ');
        assert.equal(await page.locator('#' + list + ' [data-resource-id]').count(), 1);
        assert(await page.locator('#' + list + ' [data-resource-id="' + id(match) + '"]').isVisible());
        assert.match(await page.locator('#' + list + '-inventory-summary').innerText(), /^1 of 4/);
        if (name === 'credentials') assert(await page.locator('#' + list + ' [data-resource-group="expired"]').evaluate(el => el.open));
        if (name === 'applications') assert.match(await page.locator('[data-application-next-step]').innerText(), /replace this client’s token/);
        if (name === 'access-rules') {
          assert.equal(await page.locator('#' + list + ' .badge').innerText(), 'Permission loaded');
          assert.match(await page.locator('[data-rule-next-step]').innerText(), /token has expired/);
        }
        await search.fill(id(12));
        assert.equal(await page.locator('#' + list + ' [data-resource-id]').count(), 1, 'related client IDs are searchable');
        await search.fill('<nothing & no matches>');
        assert.equal(await page.locator('#' + list + ' [data-resource-id]').count(), 0);
        assert.match(await page.locator('#' + list).innerText(), /No saved .* match/);
        await clear.click();
        assert(await search.evaluate(el => el === document.activeElement));
        await group.selectOption('diagnostic');
        assert.equal(await page.locator('#' + list + ' [data-resource-id]').count(), 1);
        assert(await page.locator('#' + list + ' [data-resource-group="diagnostic"]').evaluate(el => el.open));
        await clear.click();
        assert.equal(await page.locator('#' + list + ' [data-resource-group="diagnostic"]').evaluate(el => el.open), false,
          'clearing a search restores normal group expansion');
        const history = page.locator('#' + list + ' [data-resource-group="revoked"]');
        if (!await history.evaluate(el => el.open)) await history.locator(':scope > summary').click();
        await search.fill('release automation'); await clear.click();
        assert(await history.evaluate(el => el.open), 'explicit history expansion survives filtering');
        await group.selectOption('revoked');
        assert.equal(await page.locator('#' + list + ' [data-resource-id] button').count(), 0, 'history does not regain actions');
        await clear.click(); await search.fill('billing worker');
        assert.equal(state.requests.length, requests, 'filtering never makes network requests');
        const catalogCalls = state.catalogCalls;
        await Promise.all([page.waitForResponse(r => new URL(r.url()).pathname === '/api/operator-demo/catalog'),
          page.locator('#' + refresh).click()]);
        await ready(page);
        assert(state.catalogCalls > catalogCalls);
        assert.equal(await search.inputValue(), 'billing worker', 'search survives catalog refresh');
        assert.equal(await page.locator('#' + list + ' [data-resource-id]').count(), 1);
        await search.scrollIntoViewIfNeeded();
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        await page.screenshot({path: '/tmp/catchplate-inventory-' + name + '-' + width + '.png', fullPage: false});
        await clear.click();
        results.push({name, width, passed: true});
      }
    }
    await view(page, 'applications');
    state.catalogStatus = 503;
    await page.locator('#applications-refresh').click();
    await page.locator('#load-error').waitFor({state: 'visible'});
    assert(await page.locator('#applications-list-inventory-search').isDisabled());
    assert.equal(await page.locator('#applications-list [data-resource-id]').count(), 0, 'unavailable catalog is not an actionable stale list');
    assert.deepEqual(state.posts, []);
    assert(state.requests.every(r => r.method === 'GET'));
  });
  await fixture(browser, {}, async (page, state) => {
    await ready(page); await view(page, 'credentials');
    assert(await page.locator('[data-inventory-jump="credentials-list"]').isDisabled());
    assert(await page.locator('#credentials [data-credential-provider="manual"]').isVisible(), 'first-use saving stays direct');
    assert.match(await page.locator('#credentials-list-inventory-summary').innerText(), /^0 saved credentials/);
    assert.deepEqual(state.posts, []);
  });
  return {ok: true, results, scope: 'synthetic catalog only; no live writes, provider requests or credential retrieval'};
}
async function main() {
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox']});
  try { console.log(JSON.stringify(await run(browser))); } finally { await browser.close(); }
}
if (require.main === module) main().catch(error => {console.error(error.stack); process.exitCode = 1;});
module.exports = {run};

'use strict';
// One rendered smoke, intercepted synthetic APIs only. No provider or live app.
const assert = require('node:assert/strict');
const {mkdtempSync} = require('node:fs');
const {join} = require('node:path');
const {fixture, NOW, application, credential, rule} = require('./test_operator_catalog_browser.cjs');
const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
const ORIGIN = 'https://operator-catalog.example.test', PREFIX = '/api/operator-demo/approvals';
const ID = '11111111-1111-4111-8111-111111111111', OTHER = '22222222-2222-4222-8222-222222222222';
const DIGEST = 'sha256:' + 'a'.repeat(64);
const row = id => ({id, status: 'pending', route_id: 'synthetic.reporting.read', method: 'POST',
  url: 'https://api.example.test/report', requested_at: new Date(NOW - 1000).toISOString(),
  expires_at: new Date(NOW + 600000).toISOString(), principal_id: 'agent:reporting-client',
  credential_id: '33333333-3333-4333-8333-333333333333', credential_version: 1, policy_hash: DIGEST,
  assurance: 'host-trusted', reviewer_id: 'user:operator', approved_until: null, consumed_at: null});
async function main() {
  assert.equal(process.argv.length, 2, 'synthetic smoke accepts no target');
  const directory = mkdtempSync('/tmp/serverware-host-approval-smoke-'), requests = [], errors = [];
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  try {
    const savedClient = application({name: 'Release automation', principal_id: row(ID).principal_id});
    const savedCredential = credential({id: row(ID).credential_id, name: 'Production reporting key'});
    const savedRule = rule({name: 'Submit release report', route_id: row(ID).route_id,
      application_id: savedClient.id, credential_id: savedCredential.id, upstream_url: row(ID).url, methods: ['POST']});
    await fixture(browser, {applications: [savedClient], credentials: [savedCredential], rules: [savedRule]}, async (page, state) => {
      const records = new Map([ID, OTHER].map(id => [id, row(id)]));
      const reply = (route, value) => route.fulfill({status: 200, contentType: 'application/json', body: JSON.stringify(value)});
      page.on('pageerror', error => errors.push(error.message));
      await page.route('**/api/approvals/capabilities', route => reply(route, {
        schema: 'serverware.approvalCapabilities/v2', mode: 'host_trusted_v1', can_list: true, can_review: true, can_decide: true, reason: null}));
      await page.route('**/api/operator-demo/approvals**', async route => {
        const request = route.request(), url = new URL(request.url()), path = url.pathname;
        assert.equal(url.origin, ORIGIN); assert.equal(url.search, ''); assert(requests.length < 12);
        requests.push({path, method: request.method()});
        if (path === PREFIX) { assert.equal(request.method(), 'GET'); return reply(route, [...records.values()].filter(item => item.status === 'pending')); }
        const [id, action] = path.slice(PREFIX.length + 1).split('/'); assert(records.has(id));
        const item = records.get(id);
        if (!action) { assert.equal(request.method(), 'GET'); return reply(route, item); }
        assert.equal(request.method(), 'POST'); const body = request.postDataJSON();
        if (action === 'review') {
          assert.deepEqual(body, {});
          return reply(route, {assurance: 'host-trusted', approval: item, document: {...item,
            request_digest: DIGEST, operation_digest: DIGEST, headers: {accept: 'application/json'}, query: {},
            body_sha256: DIGEST, operation: {name: 'Submit reporting job'}},
          review_receipt_id: id, review_digest: DIGEST, review_expires_at: new Date(NOW + 60000).toISOString()});
        }
        assert.equal(action, 'decision'); assert.deepEqual(body, {decision: 'approve', review_receipt_id: id, review_digest: DIGEST, note: null});
        Object.assign(item, {status: 'approved', approved_until: new Date(NOW + 30000).toISOString()});
        return reply(route, id === OTHER ? {} : item); // Ambiguous reply after the synthetic decision; status GET resolves it.
      });
      await page.locator('nav a[href="#pending-actions"]').click();
      await page.locator('[data-pending-select="' + ID + '"]').waitFor();
      assert.equal(await page.title(), 'Pending actions - Serverware operator workspace');
      await page.locator('[data-pending-select="' + ID + '"]').click();
      await page.getByRole('button', {name: 'Review request', exact: true}).click();
      await page.getByRole('button', {name: 'Approve once', exact: true}).waitFor();
      const selected = page.locator('#pending-actions-selected');
      for (const name of [savedClient.name, savedCredential.name, savedRule.name])
        assert((await selected.innerText()).includes(name));
      assert((await selected.innerText()).includes('may have changed'));
      const exact = selected.locator('[data-pending-exact-details]');
      assert.equal(await exact.getAttribute('open'), null);
      await exact.locator('summary').click();
      for (const value of [ID, row(ID).principal_id, row(ID).credential_id, row(ID).route_id, row(ID).url, DIGEST])
        assert((await exact.innerText()).includes(value));
      await exact.locator('summary').click();
      const reviewed = selected.locator('[data-host-review-details]');
      await reviewed.locator('summary').click();
      assert((await reviewed.innerText()).includes('body_sha256'));
      assert((await reviewed.innerText()).includes(DIGEST));
      await reviewed.locator('summary').click();
      assert((await selected.innerText()).includes('Request body contents are not displayed'));
      assert((await selected.innerText()).includes('server administrator can bypass'));
      await page.screenshot({path: join(directory, 'desktop-review.png'), fullPage: true});
      await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.screenshot({path: join(directory, 'mobile-named-review.png'), fullPage: true});
      await page.setViewportSize({width: 1280, height: 960});
      await page.getByRole('button', {name: 'Approve once', exact: true}).click();
      await selected.getByText(/Explicitly retry exactly the same request once/).waitFor();
      await page.locator('[data-pending-select="' + OTHER + '"]').click();
      await page.getByRole('button', {name: 'Review request', exact: true}).click();
      await page.getByRole('button', {name: 'Approve once', exact: true}).click();
      const recovery = page.getByRole('button', {name: 'Check decision status', exact: true});
      await recovery.waitFor(); await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await page.screenshot({path: join(directory, 'mobile-unknown-recovery.png'), fullPage: true});
      await recovery.click(); await selected.getByText(/Explicitly retry exactly the same request once/).waitFor();
      assert.equal(requests.filter(item => item.path.endsWith('/decision')).length, 2);
      assert.equal(requests.filter(item => item.method === 'POST').length, 4);
      assert.deepEqual(state.consoleErrors, []); assert.deepEqual(errors, []);
      assert.equal(new URL(page.url()).pathname, '/approvals/' + OTHER);
    });
    console.log(JSON.stringify({ok: true, scope: 'rendered named pending actions and synthetic host-approval UI only',
      liveRequests: 0, providerRequests: 0, requests, errors, screenshots: directory}));
  } finally { await browser.close(); }
}
main().catch(error => { console.error(error); process.exitCode = 1; });

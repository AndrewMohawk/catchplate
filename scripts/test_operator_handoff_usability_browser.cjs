#!/usr/bin/env node
// Rendered synthetic catalog only. No live target, provider, CA download or SDK.
const assert = require('node:assert/strict');
const {mkdtemp} = require('node:fs/promises');
const {join} = require('node:path');
const {fixture, ready, view, application, credential, rule, IDS, NOW} = require('./test_operator_catalog_browser.cjs');
const github = require('./test_operator_github_browser.cjs');

async function run(browser) {
  const directory = await mkdtemp('/tmp/catchplate-handoff-usability-');
  const results = [];
  const status = page => page.locator('#client-config-availability');
  async function refresh(page, state, expected) {
    const calls = state.catalogCalls;
    await Promise.all([page.waitForResponse(response => new URL(response.url()).pathname === '/api/operator-demo/catalog'),
      page.locator('#proxy-refresh').click()]);
    if (expected) try { await status(page).filter({hasText: expected}).waitFor(); }
    catch (error) { throw new Error('Synthetic handoff status mismatch: ' + JSON.stringify(await page.evaluate(() => ({
      status: document.querySelector('#client-config-availability').textContent,
      client: document.querySelector('#proxy-application').value, permission: document.querySelector('#proxy-rule').value,
      loadError: document.querySelector('#load-error').hidden ? null : document.querySelector('#load-error-text').textContent
    }))), {cause: error}); }
    assert(state.catalogCalls > calls);
  }
  async function screenshot(page, name) {
    assert.match(await page.title(), /Catchplate/);
    assert.equal(new URL(page.url()).origin, 'https://operator-catalog.example.test');
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'no horizontal overflow');
    const path = join(directory, name + '.png');
    await page.screenshot({path, fullPage: false}); return path;
  }
  const second = github.githubRule('github_issues_read_v1', {id: '00000000-0000-4000-8000-000000000099',
    name: 'Another repository', repository: {owner: 'Example-Owner', name: 'Second.Repo'},
    upstream_url: 'https://api.github.com/repos/Example-Owner/Second.Repo/issues'});
  await github.fixture(browser, {rules: [github.githubRule(), second]}, async (page, state, observed) => {
    await ready(page); await view(page, 'applications');
    await page.getByRole('button', {name: 'Configure client', exact: true}).click();
    await page.locator('#proxy').waitFor({state: 'visible'});
    assert.equal(await page.locator('#proxy-rule').inputValue(), '');
    assert.match(await status(page).innerText(), /Choose one of this client’s saved permissions/);
    await page.locator('#proxy-rule').selectOption(second.id);
    assert(await page.locator('#download-config').isDisabled());
    assert.match(await status(page).innerText(), /no longer holds this client’s one-time token/);
    assert.equal(await status(page).getAttribute('data-state'), 'unavailable');
    assert.equal(await page.locator('#client-advanced-template').evaluate(node => node.open), false);
    assert(await page.locator('#provider-config-command').isVisible());
    assert(!(await page.locator('#copy-provider-config-command').isDisabled()), 'public command does not need recovered token');
    for (const width of [1280, 390]) {
      await page.setViewportSize({width, height: 960});
      await status(page).scrollIntoViewIfNeeded();
      results.push({case: 'file-first-handoff-no-token', width, screenshot: await screenshot(page, 'handoff-' + width)});
    }
    await page.locator('#client-advanced-template > summary').click();
    await refresh(page, state);
    assert.equal(await page.locator('#client-advanced-template').evaluate(node => node.open), true, 'refresh preserves explicit expansion');
    state.loaded = 'sha256:' + '0'.repeat(64); await refresh(page, state, /exact saved permission is loaded/);
    assert.match(await status(page).innerText(), /exact saved permission is loaded/);
    state.loaded = state.active; state.applications[0].token_status = 'expired';
    state.applications[0].token_expires_at_epoch_ms = NOW - 1; await refresh(page, state, /token is expired, revoked or cannot be verified/);
    assert.match(await status(page).innerText(), /token is expired, revoked or cannot be verified/);
    assert(await page.locator('#download-config').isDisabled());
    assert.equal(observed.creates.length + observed.grants.length, 0); assert.deepEqual(state.posts, []);
    results.push({case: 'explicit-choice-policy-pending-expired', passed: true});
  });
  await fixture(browser, {credentials: [credential()], applications: [application()], rules: [rule()]}, async (page, state) => {
    await ready(page); await view(page, 'applications');
    await page.locator('#application-name').fill('New exact client');
    await page.locator('#application-create').click();
    await page.locator('#one-time-access').waitFor({state: 'visible'});
    await ready(page);
    const held = await page.locator('#client-token').inputValue();
    assert(held.includes(IDS.other.replaceAll('-', '')));
    assert.equal(await page.locator('#token-add-permission').getAttribute('aria-disabled'), 'false');
    await page.locator('#token-add-permission').click();
    await page.locator('#connect').waitFor({state: 'visible'});
    assert.equal(await page.locator('#connect-application-choice').inputValue(), IDS.other, 'CTA binds the held client, not first saved client');
    assert.equal(await page.locator('#client-token').inputValue(), held, 'navigation retains one-time token');
    await view(page, 'applications'); state.cancelNextDialog = true;
    await page.locator('#token-add-permission').click();
    assert.equal(new URL(page.url()).hash, '#applications', 'cancelled draft replacement must not follow anchor');
    assert.match(state.dialogs.at(-1), /Replace the current setup draft/);
    await view(page, 'proxy'); await page.locator('#proxy-application').selectOption(IDS.other);
    assert.match(await status(page).innerText(), /no saved permission/);
    state.rules.push(rule({id: '55555555-5555-4555-8555-555555555555', application_id: IDS.other,
      route_id: 'operator.55555555-5555-4555-8555-555555555555'}));
    await refresh(page, state, /Choose one of this client’s saved permissions/);
    await page.locator('#proxy-rule').selectOption('55555555-5555-4555-8555-555555555555');
    assert(!(await page.locator('#download-config').isDisabled()));
    assert.match(await status(page).innerText(), /^Ready to download/);
    assert.equal(await status(page).getAttribute('data-state'), 'available');
    assert.equal(await page.locator('#client-advanced-template').evaluate(node => node.open), true, 'manual HTTP workflow remains visible');
    await page.locator('#proxy-application').selectOption(IDS.application);
    assert(await page.locator('#download-config').isDisabled(), 'another client’s held token is not reused');
    assert.match(await status(page).innerText(), /no longer holds this client’s one-time token/);
    assert.deepEqual(state.posts.map(item => item.name), ['applications'], 'only the deliberate synthetic client creation');
    results.push({case: 'held-token-exact-client-draft-guard-download', passed: true});
  });
  await fixture(browser, {credentials: [credential()], applications: [application()], rules: [rule()],
    fault: 'lost-after-commit'}, async (page, state) => {
    await ready(page); await view(page, 'applications');
    await page.locator('[data-action="rotate-application"]').click();
    await page.locator('#mutation-review').waitFor({state: 'visible'});
    await view(page, 'proxy');
    assert.match(await status(page).innerText(), /review the uncertain change/);
    assert(await page.locator('#download-config').isDisabled());
    assert.deepEqual(state.posts.map(item => item.name), ['applications/rotate-token'], 'uncertain rotation is never repeated');
    results.push({case: 'uncertain-write-disabled-reason', passed: true});
  });
  await fixture(browser, {credentials: [credential()], applications: [application()], rules: [rule()]}, async (page, state, controls) => {
    await ready(page);
    let reads = 0;
    await controls.context.route('https://operator-catalog.example.test/api/audit/search?*', async route => {
      assert.equal(route.request().method(), 'GET'); assert(!route.request().postDataBuffer()); assert(++reads <= 1);
      const event = {status_code: 428, approval_request_id: 'https://untrusted.invalid/', action: 'approval_required'};
      const items = [
        {event_type: 'operator.host_approval.requested', event},
        {event_type: 'data_plane.request.denied', event},
        {event_type: 'data_plane.request.denied', event: {status_code: 403}},
        {event_type: 'unknown', event},
      ].map((item, index) => ({...item, id: 'synthetic-' + index, created_at: new Date(NOW).toISOString()}));
      await route.fulfill({contentType: 'application/json', body: JSON.stringify({ok: true, complete: true,
        has_more: false, next_cursor: null, items})});
    });
    await view(page, 'audit'); await page.locator('#audit-list .event-card').nth(3).waitFor();
    const links = page.locator('[data-audit-pending-link]'); assert.equal(await links.count(), 2);
    assert.deepEqual(await links.evaluateAll(nodes => nodes.map(node => node.getAttribute('href'))), ['#pending-actions', '#pending-actions']);
    assert.equal(await page.locator('#audit-list a[href*="untrusted"]').count(), 0, 'event values cannot choose link destinations');
    for (const width of [1280, 390]) {
      await page.setViewportSize({width, height: 960}); await links.first().scrollIntoViewIfNeeded();
      results.push({case: 'audit-review-link', width, screenshot: await screenshot(page, 'audit-' + width)});
    }
    assert.deepEqual(state.posts, []); assert.equal(reads, 1);
  });
  await fixture(browser, {credentials: [credential()], applications: [application()], rules: [rule()]}, async (page, state) => {
    await ready(page); await view(page, 'proxy');
    state.catalogStatus = 503; await page.locator('#proxy-refresh').click();
    await page.locator('#load-error').waitFor({state: 'visible'});
    assert.match(await status(page).innerText(), /refresh workspace status to confirm/);
    assert(await page.locator('#download-config').isDisabled());
    assert.deepEqual(state.posts, []);
    results.push({case: 'unavailable-saved-state', passed: true});
  });
  return {ok: true, scope: 'intercepted synthetic UI only', results, directory,
    providerRequests: 0, downloads: 0, tokenRetrieval: false, liveMutations: 0};
}
async function main() {
  assert.equal(process.argv.length, 2, 'No live target arguments accepted');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  try { console.log(JSON.stringify(await run(browser))); } finally { await browser.close(); }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });
module.exports = {run};

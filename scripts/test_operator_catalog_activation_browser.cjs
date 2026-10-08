#!/usr/bin/env node
// One intercepted fixture regression for a raced policy observation. Never
// contacts a live app or runs either the 21-group or 13-group browser suites.
const assert = require('node:assert/strict');
const {fixture, ready, view, credential, application, rule} = require('./test_operator_catalog_browser.cjs');

async function automaticPoll(page, milliseconds) {
  const pending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/operator-demo/catalog');
  await page.clock.runFor(milliseconds);
  const response = await pending; assert.equal(response.status(), 200); await response.finished();
  // Flush browser microtasks after fetch completes before advancing another timer.
  await page.evaluate(() => Promise.resolve());
}

async function main() {
  assert.equal(process.argv.length, 2, 'activation fixture does not accept live targets or credentials');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  let deadline;
  try {
    await Promise.race([fixture(browser, {credentials: [credential()], applications: [application()], rules: [rule()],
      activationOverride: 'pending'}, async (page, state) => {
      await ready(page); assert.equal(state.active, state.loaded, 'fixture hashes deliberately match');
      assert((await page.locator('#overview-policy').innerText()).startsWith('Pending:'));
      assert((await page.locator('#activation-status').innerText()).startsWith('Pending:'));
      assert((await page.locator('#applications-list .badge').innerText()).includes('pending'));
      assert((await page.locator('#access-rules-list .badge').innerText()).includes('pending'));
      await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled());
      const initialCalls = state.catalogCalls;
      await page.clock.runFor(1999); assert.equal(state.catalogCalls, initialCalls, 'no premature polling');
      await automaticPoll(page, 1);
      assert.equal(state.catalogCalls, initialCalls + 1, 'matching hashes with pending activation continue the two-second poll');
      assert((await page.locator('#overview-policy').innerText()).startsWith('Pending:'));
      assert(await page.locator('#copy-command').isDisabled());

      state.activationOverride = 'active'; await automaticPoll(page, 2000);
      await page.waitForFunction(() => document.querySelector('#overview-policy').textContent.startsWith('Active:') &&
        !document.querySelector('#copy-command').disabled);
      assert.equal(state.catalogCalls, initialCalls + 2);
      assert.equal(state.active, state.loaded);
      assert.equal(await page.locator('#applications-list .badge').innerText(), 'Active');
      assert.equal(await page.locator('#access-rules-list .badge').innerText(), 'Active');
      await page.clock.runFor(6000);
      assert.equal(state.catalogCalls, initialCalls + 2, 'coherent active observation stops automatic polling');
      assert.equal(state.posts.length, 0);
    }), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('activation fixture deadline')), 25000); })]);
    console.log('PASS matching hashes with pending activation keep pending resources and poll until coherent active recovery');
    console.log(JSON.stringify({ok: true, groups: 1, scope: 'intercepted synthetic activation-race UI fixture only',
      otherBrowserSuitesExecuted: false, liveRequests: 0, writes: 0, productionAcceptance: false}));
  } finally { clearTimeout(deadline); await browser.close(); }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

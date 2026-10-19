#!/usr/bin/env node
// Intercepted synthetic UI only. Public source pin changes links, never private
// configuration, provider requests, SDK execution or saved permissions.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {readFileSync, mkdtempSync} = require('node:fs');
const {resolve, join} = require('node:path');
const {fixture, githubRule} = require('./test_operator_github_browser.cjs');
const {ready, view} = require('./test_operator_catalog_browser.cjs');
const ROOT = resolve(__dirname, '..');
async function run(browser) {
  const pin = JSON.parse(readFileSync(join(ROOT, 'docker/catchplate-operator-demo/client-source.json')));
  const source = execFileSync('python3', ['-B', '-c', 'from catchplate.operator_demo_portal import render; print(render())'],
    {cwd: ROOT, encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024});
  const marker = "revision: 'main'"; assert.equal(source.split(marker).length, 2);
  const document = source.replace(marker, "revision: '" + pin.revision + "'");
  const directory = mkdtempSync('/tmp/catchplate-client-source-');
  const screenshots = [];
  await fixture(browser, {rules: [githubRule()]}, async (page, state, observed) => {
    const origin = 'https://operator-catalog.example.test';
    assert.equal(new URL(page.url()).origin, origin);
    await page.context().route(origin + '/', route => {
      assert.equal(route.request().method(), 'GET');
      return route.fulfill({status: 200, contentType: 'text/html', body: document});
    });
    await page.reload({waitUntil: 'networkidle'}); await ready(page); await view(page, 'proxy');
    assert.match(await page.title(), /Catchplate/);
    await page.locator('#proxy-application').selectOption(state.applications[0].id);
    await page.locator('#proxy-rule').selectOption(state.rules[0].id);
    const prefix = pin.repository + 'tree/' + pin.revision + '/examples/';
    const links = await page.locator('#client-example-links a').evaluateAll(nodes => nodes.map(node => node.href));
    assert.deepEqual(links, ['node', 'python', 'go'].map(language => prefix + 'github-issues-' + language));
    assert.equal(await page.locator('#client-mcp-guide').getAttribute('href'),
      pin.repository + 'blob/' + pin.revision + '/examples/mcp/README.md');
    assert.equal(await page.locator('#workload-client-guide').getAttribute('href'), prefix + 'managed-client');
    assert(await page.locator('#client-source-revision').isVisible());
    assert.equal(await page.locator('#client-source-revision-link').innerText(), pin.revision.slice(0, 8));
    assert.match(await page.locator('#client-source-revision').innerText(), /do not substitute code from main/);
    assert((await page.locator('#client-example-note').innerText()).includes('client revision ' + pin.revision.slice(0, 8)));
    assert(await page.locator('#download-config').isDisabled(), 'source links do not recover a client token');
    for (const width of [1280, 390]) {
      await page.setViewportSize({width, height: 960});
      await page.locator('#client-source-revision').scrollIntoViewIfNeeded();
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await page.locator('#client-source-revision-link').focus();
      assert.equal(await page.evaluate(() => document.activeElement.id), 'client-source-revision-link');
      const path = join(directory, 'source-' + width + '.png');
      await page.screenshot({path, fullPage: false}); screenshots.push(path);
    }
    assert.equal(observed.creates.length + observed.grants.length, 0); assert.deepEqual(state.posts, []);
  });
  return {ok: true, revision: pin.revision, directory, screenshots, providerRequests: 0,
    mutations: 0, sdkExecuted: false, scope: 'Rendered source-link pin; no protocol conversion or private export'};
}
async function main() {
  assert.equal(process.argv.length, 2, 'No live target arguments accepted');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  try { console.log(JSON.stringify(await run(browser))); } finally { await browser.close(); }
}
module.exports = {run};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

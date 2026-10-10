#!/usr/bin/env node
// Rendered local UI with intercepted synthetic APIs only; no provider/proxy access.
const assert = require('node:assert/strict');
const {mkdtemp} = require('node:fs/promises');
const {join} = require('node:path');
const {fixture, githubRule} = require('./test_operator_github_browser.cjs');
const {ready, view} = require('./test_operator_catalog_browser.cjs');
const npm = require('./test_operator_npm_browser.cjs');
const gmail = require('./test_operator_gmail_bundle_browser.cjs');

async function main() {
  assert.equal(process.argv.length, 2, 'No live target arguments accepted');
  const directory = await mkdtemp('/tmp/serverware-example-links-');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  const results = [];
  try {
    await fixture(browser, {rules: [githubRule()]}, async (page, state, observed) => {
      await ready(page); await view(page, 'proxy');
      await page.locator('#client-examples').waitFor({state: 'visible'});
      assert.match(await page.title(), /Serverware/);
      assert.equal(new URL(page.url()).origin, 'https://operator-catalog.example.test');
      const labels = ['Node.js + GitHub Actions', 'Python', 'Go'];
      assert.deepEqual(await page.locator('#client-example-links a').allTextContents(), labels);
      for (const [index, language] of ['node', 'python', 'go'].entries()) {
        const link = page.locator('#client-example-links a').nth(index);
        assert.equal(await link.getAttribute('href'),
          'https://github.com/AndrewMohawk/serverware/tree/serverware/operator-workspace/examples/github-issues-' + language);
        assert.equal(await link.getAttribute('rel'), 'noopener noreferrer');
      }
      for (const viewport of [{width: 1440, height: 1000}, {width: 390, height: 844}]) {
        await page.setViewportSize(viewport);
        await page.locator('#client-examples').scrollIntoViewIfNeeded();
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        const screenshot = join(directory, 'examples-' + viewport.width + '.png');
        await page.screenshot({path: screenshot, fullPage: false});
        results.push({viewport, screenshot, labels});
      }
      await view(page, 'connect');
      await page.getByRole('button', {name: 'Manual API key', exact: true}).click();
      await page.locator('#connect-credential-form').waitFor({state: 'visible'});
      assert.equal(observed.creates.length + observed.grants.length, 0);
      assert.deepEqual(state.errors, []);
      results.push({manualChoiceOpensForm: true, mutations: 0});
    });
    const source = 'https://github.com/AndrewMohawk/serverware/';
    const branch = 'serverware/operator-workspace/';
    async function checkLinks(page, name, expected) {
      await ready(page); await view(page, 'proxy');
      await page.locator('#client-examples').waitFor({state: 'visible'});
      assert.equal(new URL(page.url()).origin, 'https://operator-catalog.example.test');
      assert.deepEqual(await page.locator('#client-example-links a').evaluateAll(nodes =>
        nodes.map(node => node.href)), expected.map(path => source + path));
      for (const viewport of [{width: 1440, height: 1000}, {width: 390, height: 844}]) {
        await page.setViewportSize(viewport);
        await page.locator('#client-examples').scrollIntoViewIfNeeded();
        assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
        const screenshot = join(directory, name + '-' + viewport.width + '.png');
        await page.screenshot({path: screenshot, fullPage: false});
        results.push({name, viewport, screenshot, links: expected});
      }
    }
    await npm.fixture(browser, {rules: [npm.npmRule()]}, async (page, state, observed) => {
      await checkLinks(page, 'npm', ['tree/' + branch + 'examples/npm-registry',
        'blob/' + branch + 'docs/operator-npm-metadata.md']);
      assert.equal(observed.creates.length + observed.grants.length, 0);
      assert.deepEqual(state.errors, []);
    });
    for (const replace of [false, true]) {
      const rule = gmail.bundleRule(replace ? {credential_input: 'replace_exact',
        placeholder: 'Bearer serverware-gmail-placeholder-v1'} : {});
      await gmail.fixture(browser, gmail.options({rules: [rule]}), async (page, state, observed) => {
        const paths = ['blob/' + branch + 'docs/operator-gmail-job-verification.md'];
        if (replace) paths.unshift('tree/' + branch + 'examples/google-gmail-go');
        await checkLinks(page, replace ? 'gmail-project' : 'gmail-guide', paths);
        assert.equal(observed.posts.length, 0); assert.deepEqual(state.posts, []);
        assert.deepEqual(state.errors, []);
      });
    }
    console.log(JSON.stringify({ok: true, scope: 'synthetic rendered UI', results,
      externalNavigation: false, providerRequests: 0, sdkExecuted: false}));
  } finally { await browser.close(); }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

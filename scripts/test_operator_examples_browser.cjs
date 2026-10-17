#!/usr/bin/env node
// Rendered local UI with intercepted synthetic APIs only; no provider/proxy access.
const assert = require('node:assert/strict');
const {mkdtemp} = require('node:fs/promises');
const {join} = require('node:path');
const {fixture, githubRule} = require('./test_operator_github_browser.cjs');
const {ready, view, application, credential, rule} = require('./test_operator_catalog_browser.cjs');
const npm = require('./test_operator_npm_browser.cjs');
const gmail = require('./test_operator_gmail_bundle_browser.cjs');
const x = require('./operator_x_browser_fixture.cjs');
const alchemy = require('./operator_alchemy_browser_fixture.cjs');

async function main() {
  assert.equal(process.argv.length, 2, 'No live target arguments accepted');
  const directory = await mkdtemp('/tmp/catchplate-example-links-');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  const results = [];
  async function operatorPanelsAfterClient(page) {
    assert(await page.evaluate(() => {
      const client = document.querySelector('#proxy-setup-content');
      const settings = document.querySelector('#proxy-operator-settings');
      return client.parentElement === document.querySelector('#proxy') &&
        ['proxy-upstreams', 'google-configuration-panel', 'x-configuration-panel'].every(id => {
          const panel = document.getElementById(id);
          return panel && settings.contains(panel) &&
            Boolean(client.compareDocumentPosition(panel) & Node.DOCUMENT_POSITION_FOLLOWING);
        });
    }), 'actual operator panels belong after client setup, not only their heading');
  }
  try {
    await fixture(browser, {rules: [githubRule()]}, async (page, state, observed) => {
      try { await ready(page); } catch (error) {
        assert.deepEqual(state.errors, []);
        const status = await page.evaluate(() => ({counts: ['credentials', 'applications', 'rules'].map(name =>
          document.querySelector('#overview-' + name + '-count').textContent),
        loadError: document.querySelector('#load-error').hidden ? null : document.querySelector('#load-error-text').textContent,
        reviewHidden: document.querySelector('#mutation-review').hidden,
        busy: document.querySelector('#mutation-review-refresh').disabled}));
        throw new Error('Synthetic UI readiness failed: ' + JSON.stringify(status), {cause: error});
      }
      await view(page, 'proxy');
      await operatorPanelsAfterClient(page);
      await page.locator('#client-examples').waitFor({state: 'visible'});
      assert.match(await page.title(), /Catchplate/);
      assert.equal(new URL(page.url()).origin, 'https://operator-catalog.example.test');
      const labels = ['Node.js + GitHub Actions', 'Python', 'Go'];
      assert.deepEqual(await page.locator('#client-example-links a').allTextContents(), labels);
      for (const [index, language] of ['node', 'python', 'go'].entries()) {
        const link = page.locator('#client-example-links a').nth(index);
        assert.equal(await link.getAttribute('href'),
          'https://github.com/AndrewMohawk/catchplate/tree/main/examples/github-issues-' + language);
        assert.equal(await link.getAttribute('rel'), 'noopener noreferrer');
      }
      await page.evaluate(() => Object.defineProperty(navigator, 'clipboard', {configurable: true,
        value: {writeText: async text => { window.copiedExampleCommand = text; }}}));
      for (const [language, command] of [['node', 'node client.mjs'],
        ['python', '.venv/bin/python -I -B issues.py'], ['go', './github-issues']]) {
        await page.locator('#client-example-runtime').selectOption(language);
        const expected = command + ' --config ./catchplate-client.private.json';
        assert.equal(await page.locator('#provider-config-command').innerText(), expected);
        assert((await page.locator('#provider-config-prepare').innerText()).startsWith('cd examples/github-issues-' + language));
        await page.locator('#copy-provider-config-command').click();
        assert.equal(await page.evaluate(() => window.copiedExampleCommand), expected);
        assert(!/go run|npm ci|pip install|--execute-write/.test(expected));
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
      await view(page, 'proxy');
      await operatorPanelsAfterClient(page);
      assert.equal(observed.creates.length + observed.grants.length, 0);
      assert.deepEqual(state.errors, []);
      assert.deepEqual(state.unexpected, [], 'synthetic request paths: ' +
        JSON.stringify(state.requests.map(({method, path}) => ({method, path}))));
      results.push({manualChoiceOpensForm: true, mutations: 0});
    });
    const secondRule = githubRule('github_issues_read_v1', {id: '00000000-0000-4000-8000-000000000099',
      name: 'Second repository', repository: {owner: 'Example-Owner', name: 'Second.Repo'},
      upstream_url: 'https://api.github.com/repos/Example-Owner/Second.Repo/issues'});
    await fixture(browser, {rules: [githubRule(), secondRule]}, async (page, state, observed) => {
      await ready(page); await view(page, 'applications');
      await page.getByRole('button', {name: 'Configure client', exact: true}).click();
      await page.locator('#proxy-setup-content').waitFor({state: 'visible'});
      assert.equal(await page.locator('#proxy-rule').inputValue(), '', 'multiple permissions require explicit selection');
      assert.match(await page.locator('#client-guidance').innerText(), /Choose one of this client’s saved permissions above/);
      assert(await page.locator('#copy-provider-config-command').isDisabled());
      assert(await page.locator('#download-config').isDisabled());
      await page.locator('#proxy-rule').selectOption(secondRule.id);
      assert.equal(await page.locator('#proxy-rule').inputValue(), secondRule.id);
      assert(!(await page.locator('#copy-provider-config-command').isDisabled()));
      assert(await page.locator('#download-config').isDisabled(), 'the one-time token is not reconstructed');
      await operatorPanelsAfterClient(page);
      assert.equal(observed.creates.length + observed.grants.length, 0);
      assert.deepEqual(state.errors, []); assert.deepEqual(state.posts, []);
      results.push({contextualClientRequiresPermission: true, exactPermissionSelected: true, tokenRecovered: false, mutations: 0});
    });
    await fixture(browser, {credentials: [credential()], rules: [rule({upstream_url: 'https://demo-upstream:8443/echo'})],
      allowedUpstreams: ['https://demo-upstream:8443']}, async (page, state, observed) => {
      await ready(page); await view(page, 'proxy');
      assert.equal(await page.locator('#proxy-application').inputValue(), '', 'connection checks are not a default client');
      assert.equal(await page.locator('#proxy-application option').first().innerText(), 'Choose a client');
      assert.match(await page.locator('#proxy-application option').nth(1).innerText(), /Connection check/);
      assert.equal(await page.locator('#proxy-rule').inputValue(), '');
      assert(await page.locator('#copy-command').isDisabled());
      assert(await page.locator('#download-config').isDisabled());
      await page.locator('#proxy-application').selectOption(state.applications[0].id);
      assert.equal(await page.locator('#proxy-rule').inputValue(), state.rules[0].id, 'diagnostics remain explicitly selectable');
      await page.locator('#proxy-application').selectOption('');
      assert.equal(await page.locator('#proxy-rule').inputValue(), '');
      assert(await page.locator('#copy-command').isDisabled());
      assert.equal(observed.creates.length + observed.grants.length, 0);
      assert.deepEqual(state.errors, []); assert.deepEqual(state.posts, []);
      results.push({diagnosticClientRequiresChoice: true, explicitDiagnosticAvailable: true, mutations: 0});
    });
    const source = 'https://github.com/AndrewMohawk/catchplate/';
    const branch = 'main/';
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
    for (const [name, provider, savedRule, directory] of [
      ['x', x, x.xRule(), 'x-username'],
      ['alchemy', alchemy, alchemy.alchemyRule(), 'alchemy-chain-status'],
    ]) await provider.fixture(browser, {rules: [savedRule]}, async (page, state, observed) => {
      await checkLinks(page, name, [...['node', 'python', 'go'].map(language =>
        'tree/' + branch + 'examples/' + directory + '-' + language),
      'blob/' + branch + 'examples/' + directory + '-node/workflow.example.yml',
      'blob/' + branch + 'docs/operator-provider-presets.md']);
      const note = await page.locator('#client-example-note').innerText();
      if (name === 'alchemy') {
        assert.match(note, /Node\.js, Python and Go examples passed/);
        assert(!note.includes('pending'));
      }
      assert.equal(observed.credentials.length + observed.applications.length + observed.grants.length, 0);
      assert.deepEqual(state.posts, []); assert.deepEqual(state.errors, []);
      await provider.privateAbsent(page);
    });
    for (const [replace, basic] of [[false, false], [true, false], [true, true]]) {
      const rule = gmail.bundleRule(replace ? {credential_input: 'replace_exact',
        placeholder: 'Bearer catchplate-gmail-placeholder-v1'} : {});
      await gmail.fixture(browser, gmail.options({rules: [rule], applications: [application(basic ? {proxy_authentication: 'basic_and_bearer_v1'} : {})],
        gmailTransform(value) {
          if (basic) value.capabilities.application_proxy_authentication = {schema: 'catchplate.operatorProxyAuthentication/v1',
            modes: ['bearer', 'basic_and_bearer_v1'], path: '/api/operator-demo/applications/proxy-authentication'};
          return value;
        }}), async (page, state, observed) => {
        const paths = ['blob/' + branch + 'docs/operator-gmail-job-verification.md'];
        if (replace && basic) paths.unshift(...['go', 'node', 'python'].map(language =>
          'tree/' + branch + 'examples/google-gmail-' + language));
        await checkLinks(page, replace && basic ? 'gmail-project' : replace ? 'gmail-bearer-guide' : 'gmail-guide', paths);
        if (replace && basic) assert.deepEqual(await page.locator('#client-example-links a').allTextContents(), [
          'Go + Gmail SDK', 'Node.js + Gmail SDK',
          'Python + Gmail SDK', 'Google / Gmail guide']);
        assert.equal(observed.posts.length, 0); assert.deepEqual(state.posts, []);
        assert.deepEqual(state.errors, []);
      });
    }
    console.log(JSON.stringify({ok: true, scope: 'synthetic rendered UI', results,
      externalNavigation: false, providerRequests: 0, sdkExecuted: false}));
  } finally { await browser.close(); }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

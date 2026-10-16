#!/usr/bin/env node
'use strict';
// Rendered credential-only UX. Reuses the intercepted catalog fixture; every
// request is synthetic, and no provider, client or permission operation is run.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {fixture, ready, view, credential} = require('./test_operator_catalog_browser.cjs');
const {acknowledgeMutationReview, withoutMutationReview} = require('./operator_mutation_recovery_test_helpers.cjs');

const ROOT = resolve(__dirname, '..');
const SECRET = 'synthetic_quick_add_key_NEVER_RENDER';
const OTHER_SECRET = 'synthetic_abandoned_key_NEVER_RENDER';
const CAPABILITIES = JSON.parse(execFileSync('python3', ['-B', '-c',
  'import json; from serverware import operator_common_apps as a, operator_catalog_github as g, operator_github_app as ga, operator_catalog_npm as n, operator_demo as d; origins=sorted({op["origin"] for p in a.presets() for op in p["operations"]}|{g.ORIGIN,n.ORIGIN}); d.settings=lambda:{"allowed_upstreams":origins}; print(json.dumps({"origins":origins,"common_apps":a.capability(),"github":g.capability(),"github_app":ga.capability(),"npm":n.capability()}))'],
{cwd: ROOT, encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024}));
const SELECTORS = {
  openai: '[data-credential-app="openai"]', anthropic: '[data-credential-app="anthropic"]',
  github: '[data-credential-provider="github_token"]', npm: '[data-credential-provider="npm"]',
  manual: '[data-credential-provider="manual"]'
};
const DEFAULT_NAMES = {openai: 'OpenAI key', anthropic: 'Anthropic / Claude key', github: 'GitHub token', npm: 'npm token', manual: 'API key'};

async function synthetic(browser, options, exercise) {
  return fixture(browser, {
    allowedUpstreams: CAPABILITIES.origins,
    responseModes: ['unfiltered_json_or_empty_v2'], credentialInputModes: ['insert', 'replace_exact'],
    catalogTransform(value) {
      value.capabilities = {...value.capabilities, common_apps: CAPABILITIES.common_apps,
        github: CAPABILITIES.github, github_app: CAPABILITIES.github_app, npm: CAPABILITIES.npm};
      return value;
    },
    async credentialHandler({route, name, body, state, answer}) {
      const selected = options.provider;
      assert.equal(state.posts.length, 1, 'one explicit credential write only');
      assert.equal(name, selected === 'github' ? 'credentials/github-token' : selected === 'npm' ? 'credentials/npm-token' : 'credentials');
      assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.active);
      const payload = Object.fromEntries(Object.entries(body).filter(([key]) => !key.startsWith('expected_')));
      const common = ['openai', 'anthropic'].includes(selected);
      const header = selected === 'anthropic';
      assert.deepEqual(payload, {name: options.name || DEFAULT_NAMES[selected],
        ...(!['github', 'npm'].includes(selected) ? {auth_type: header ? 'header' : 'bearer', header_name: header ? 'x-api-key' : 'Authorization'} : {}),
        secret: SECRET, ...(common ? {app_preset: selected} : {})});
      const saved = credential({name: payload.name, auth_type: header ? 'header' : 'bearer', header_name: header ? 'x-api-key' : 'Authorization',
        ...(common ? {app_preset: selected} : {}),
        ...(['github', 'npm'].includes(selected) ? {provider_id: selected, connection_type: selected + '_token_v1'} : {})});
      state.credentials.push(saved); state.revision++;
      if (options.lostReply) {
        state.expectedFailures.add('/api/operator-demo/' + name);
        return route.abort('failed');
      }
      return answer(route, {credential: saved, revision: state.revision,
        policy: {policy_hash: state.active, loaded_policy_hash: state.loaded, sequence: state.sequence, activation: 'active'}}, 201);
    }
  }, async (page, state, controls) => {
    await ready(page); await view(page, 'credentials');
    await page.clock.resume(); // Exercise real focus/layout scheduling, not the base fixture's frozen rAF.
    await page.locator('#credential-provider-picker').waitFor({state: 'visible'});
    assert.equal(new URL(page.url()).origin, 'https://operator-catalog.example.test');
    assert.match(await page.title(), /Credentials.*Serverware/i);
    await exercise(page, state, controls);
    assert.equal(state.applications.length, 0); assert.equal(state.rules.length, 0);
    assert(state.posts.every(item => item.name.startsWith('credentials')), 'no client or permission writes');
    assert.equal(state.sequence, 1, 'credential storage does not publish policy');
  });
}

async function choose(page, provider) {
  await page.locator('#credentials ' + SELECTORS[provider]).click();
  await page.locator('#connect-credential-form').waitFor({state: 'visible'});
  assert.equal(await page.locator('#connect-credential-name').inputValue(), DEFAULT_NAMES[provider]);
  assert.equal(await page.locator('#connect-credential-next').innerText(), 'Save credential');
  assert.equal(await page.locator('#connect-method-choice').isVisible(), false, 'provider tile skips the old chooser');
  await page.waitForFunction(() => document.activeElement?.id === 'connect-credential-secret', null, {polling: 50});
  await settledFocus(page);
  assert.equal(await page.locator('#connect-credential-secret').inputValue(), '');
}

async function settledFocus(page) {
  // Real frames, with the clock already resumed before the provider click:
  // observing focus once must not hide a later hash/layout render that blurs it.
  await page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  assert.equal(await page.evaluate(() => document.activeElement?.id), 'connect-credential-secret', 'secret focus survives the settled render');
}

async function refreshWithoutMovingFocus(page, state) {
  const before = state.catalogCalls;
  await Promise.all([
    page.waitForResponse(response => response.url() === 'https://operator-catalog.example.test/api/operator-demo/catalog'),
    // Invoke the existing refresh listener without a pointer/keyboard action
    // that would legitimately move focus to the refresh button itself.
    page.locator('#connect-status-refresh').dispatchEvent('click')
  ]);
  await page.waitForFunction(() => !document.getElementById('connect-status-refresh').disabled, null, {polling: 50});
  assert.equal(state.catalogCalls, before + 1); assert.equal(state.posts.length, 0);
  await settledFocus(page);
}

async function privateAbsent(page) {
  const values = await page.evaluate(() => ({dom: document.documentElement.outerHTML,
    inputs: [...document.querySelectorAll('input,textarea')].map(item => item.value),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  for (const secret of [SECRET, OTHER_SECRET]) assert(!JSON.stringify(values).includes(secret), 'no abandoned/submitted secret retained in DOM or storage');
  assert.deepEqual(values.local, []); assert.deepEqual(withoutMutationReview(values.session), []);
}

async function saved(page, state) {
  await page.locator('#connect-credential-saved').waitFor({state: 'visible'});
  assert.equal(state.posts.length, 1); assert.equal(state.credentials.length, 1);
  assert.equal(await page.locator('#connect-application-step').isVisible(), false);
  assert.equal(await page.locator('#connect-access-step').isVisible(), false);
  assert.equal(await page.locator('#one-time-access').isVisible(), false);
  assert.match(await page.locator('#connect-credential-saved-summary').innerText(), /Provider request success has not been tested/);
  await privateAbsent(page);
}

function cases(artifacts) {
  return [
    ...['openai', 'github', 'npm', 'manual'].map(provider => [provider + ': provider tile, default name, focused secret and Enter save only a credential',
      browser => synthetic(browser, {provider}, async (page, state) => {
        await choose(page, provider);
        if (provider === 'openai') await refreshWithoutMovingFocus(page, state);
        await page.locator('#connect-credential-secret').fill(SECRET);
        await page.locator('#connect-credential-secret').press('Enter'); await saved(page, state);
        await page.locator('#connect-saved-done').click(); await page.locator('#credentials').waitFor({state: 'visible'});
        assert.match(await page.locator('#credentials-list').innerText(), new RegExp(DEFAULT_NAMES[provider]));
        assert.equal(state.posts.length, 1);
        if (provider === 'openai') await page.screenshot({path: join(artifacts, 'credential-saved-desktop.png'), fullPage: true});
        await choose(page, provider); assert.equal(state.posts.length, 1, 'opening another credential performs no write');
      })]),
    ['switching provider discards unsaved secrets and resets the suggested name', browser => synthetic(browser, {provider: 'anthropic'}, async (page, state) => {
      await choose(page, 'openai'); await page.locator('#connect-credential-name').fill('Abandoned OpenAI name');
      await page.locator('#connect-credential-secret').fill(OTHER_SECRET); await page.locator('#connect-method-change').click();
      await page.locator('#credentials').waitFor({state: 'visible'}); await privateAbsent(page);
      assert.equal(state.posts.length, 0); await choose(page, 'anthropic');
      await page.locator('#connect-credential-secret').fill(SECRET); await page.locator('#connect-credential-next').click();
      await saved(page, state);
    })],
    ['custom credential name remains editable and mobile picker stays usable', browser => synthetic(browser,
      {provider: 'npm', name: 'Build publishing token'}, async (page, state) => {
        await page.setViewportSize({width: 390, height: 844});
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
        await page.screenshot({path: join(artifacts, 'credential-picker-mobile.png'), fullPage: true});
        await choose(page, 'npm'); await page.locator('#connect-credential-name').fill('Build publishing token');
        await page.locator('#connect-credential-secret').fill(SECRET); await page.locator('#connect-credential-next').click();
        await saved(page, state);
      })],
    ['lost committed reply clears secret and blocks resend across Enter, refresh and reload', browser => synthetic(browser,
      {provider: 'openai', lostReply: true}, async (page, state) => {
        await choose(page, 'openai'); await page.locator('#connect-credential-secret').fill(SECRET);
        await page.locator('#connect-credential-secret').press('Enter');
        await page.locator('#mutation-review').waitFor({state: 'visible'}); await privateAbsent(page);
        assert.equal(state.posts.length, 1); assert.equal(state.credentials.length, 1);
        assert(await page.locator('#connect-credential-next').isDisabled());
        await page.locator('#connect-credential-form').dispatchEvent('submit');
        await page.clock.runFor(10000); assert.equal(state.posts.length, 1);
        await view(page, 'credentials');
        for (const provider of ['openai', 'github', 'npm']) assert(await page.locator('#credentials ' + SELECTORS[provider]).isDisabled());
        await page.locator('#credentials-refresh').click();
        await page.reload({waitUntil: 'networkidle'}); await page.locator('#mutation-review').waitFor({state: 'visible'});
        await privateAbsent(page); assert.equal(state.posts.length, 1);
        await acknowledgeMutationReview(page); await ready(page);
        assert.equal(state.posts.length, 1); assert.equal(state.credentials.length, 1);
      })]
  ];
}

async function run(browser) {
  const artifacts = await mkdtemp('/tmp/serverware-credential-quick-add-');
  const completed = [];
  for (const [name, test] of cases(artifacts)) { await test(browser); completed.push(name); }
  return {ok: true, groups: completed.length, completed, artifacts,
    scope: 'intercepted synthetic rendered credential-only flow', liveRequests: 0, providerCalls: 0,
    clientWrites: 0, permissionWrites: 0, otherBrowserSuitesExecuted: false, productionAcceptance: false};
}
async function main() {
  assert.equal(process.argv.length, 2);
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  let timer;
  try {
    console.log(JSON.stringify(await Promise.race([run(browser), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('quick credential browser fixture deadline')), 60000);
    })])));
  } finally { clearTimeout(timer); await browser.close(); }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });
module.exports = {run};

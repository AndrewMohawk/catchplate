#!/usr/bin/env node
'use strict';
// One focused rendered suite. All browser requests use the existing intercepted
// catalog fixture; documentation links are inspected, never opened.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {fixture, ready, view, credential, IDS} = require('./test_operator_catalog_browser.cjs');

const ROOT = resolve(__dirname, '..');
const COMMON = ['openai', 'anthropic', 'gemini', 'openrouter', 'slack', 'discord', 'notion', 'stripe', 'resend', 'gitlab', 'cloudflare', 'sentry'];
const CANARY = 'synthetic_nonstandard_prefix_NEVER_DISPLAY_credential_guide';
const PEM = '-----BEGIN PRIVATE KEY-----\nsynthetic_PEM_GUIDE_NEVER_DISPLAY\n-----END PRIVATE KEY-----';
const CAPABILITIES = JSON.parse(execFileSync('python3', ['-B', '-c',
  'import json; from catchplate import operator_common_apps as c, operator_catalog_github as g, operator_github_app as ga, operator_catalog_npm as n, operator_catalog_aws as aws, operator_catalog_x as x, operator_catalog_alchemy as a, alchemy_rpc_read as ar, operator_demo as d; origins=sorted({op["origin"] for p in c.presets() for op in p["operations"]}|{g.ORIGIN,n.ORIGIN,x.ORIGIN}|{ar.origin(chain) for chain in ar.CHAINS}); d.settings=lambda:{"allowed_upstreams":origins}; print(json.dumps({"origins":origins,"capabilities":{"common_apps":c.capability(),"github":g.capability(),"github_app":ga.capability(),"npm":n.capability(),"aws_credentials":aws.capability(),"x":x._capability(),"alchemy":a._capability()}}))'],
{cwd: ROOT, encoding: 'utf8', timeout: 5000, maxBuffer: 1024 * 1024}));
const REPLACEMENT = {schema: 'catchplate.operatorStaticKeyReplacement/v1',
  path: '/api/operator-demo/credentials/replace-key', credential_types: ['bearer', 'header']};

async function synthetic(browser, options, exercise) {
  return fixture(browser, {
    credentials: options.credentials || [], allowedUpstreams: CAPABILITIES.origins,
    responseModes: ['unfiltered_json_or_empty_v2'], credentialInputModes: ['insert', 'replace_exact'],
    catalogTransform(value) {
      value.capabilities = {...value.capabilities, ...CAPABILITIES.capabilities, static_key_replacement: REPLACEMENT};
      return value;
    }
  }, async (page, state, controls) => {
    await ready(page); await view(page, 'credentials'); await page.clock.resume();
    await page.locator('#credential-provider-picker').waitFor({state: 'visible'});
    const initial = JSON.stringify([state.credentials, state.applications, state.rules]);
    await exercise(page, state, controls);
    assert.equal(JSON.stringify([state.credentials, state.applications, state.rules]), initial);
    assert.deepEqual(state.posts, [], 'viewing guides, typing and switching never submit a mutation');
    assert.equal(state.sequence, 1, 'guide navigation cannot publish policy');
    assert(state.requests.every(item => item.method === 'GET'), 'no client, permission or provider writes');
  });
}

async function guide(page, containerId, provider, {links = true} = {}) {
  const container = page.locator('#' + containerId);
  await container.waitFor({state: 'visible'});
  assert.equal(await container.getAttribute('data-provider'), provider, 'guide identifies the selected provider');
  assert((await container.locator('h2,h3,h4,[role="heading"]').innerText()).trim().length > 0, 'guide has a readable title');
  const disclosure = container.locator(':scope > details');
  if (await disclosure.count()) {
    assert.equal(await disclosure.evaluate(node => node.open), false, 'long acquisition help starts compact');
    await disclosure.locator('summary').focus(); await page.keyboard.press('Enter');
    assert.equal(await disclosure.evaluate(node => node.open), true, 'acquisition instructions remain keyboard accessible');
  }
  const steps = await container.locator('ol > li').allInnerTexts();
  assert(steps.length >= 2 && steps.length <= 4 && steps.every(step => step.trim().length > 10), 'ordered actionable instructions');
  const anchors = await container.locator('a').evaluateAll(items => items.map(item => ({
    href: item.href, label: item.textContent, target: item.target, rel: item.rel,
    referrer: item.getAttribute('referrerpolicy')})));
  if (links) assert(anchors.length > 0, 'provider documentation is linked');
  for (const anchor of anchors) {
    const url = new URL(anchor.href);
    assert.equal(url.protocol, 'https:'); assert.equal(url.username, ''); assert.equal(url.password, '');
    assert(anchor.label.trim().length > 0); assert.equal(anchor.target, '_blank');
    assert(anchor.rel.split(/\s+/).includes('noopener')); assert(anchor.rel.split(/\s+/).includes('noreferrer'));
    assert.equal(anchor.referrer, 'no-referrer');
  }
  return container;
}

async function hint(page, fieldId) {
  const result = await page.locator('#' + fieldId).evaluate(field => {
    const ids = (field.getAttribute('aria-describedby') || '').trim().split(/\s+/).filter(Boolean);
    return {placeholder: field.getAttribute('placeholder'), ids,
      descriptions: ids.map(id => {
        const node = document.getElementById(id);
        return node ? {text: node.textContent, visible: node.getClientRects().length > 0,
          unique: document.querySelectorAll('[id="' + id + '"]').length === 1} : null;
      })};
  });
  assert(result.placeholder?.trim(), fieldId + ' has an example placeholder');
  assert(result.ids.length > 0 && new Set(result.ids).size === result.ids.length, 'field has nonduplicated helper references');
  assert(result.descriptions.every(item => item && item.unique), 'aria-describedby resolves to real unique helpers');
  assert(result.descriptions.some(item => item.visible && item.text.trim().length > 15), 'help is visible, not placeholder-only');
  return {placeholder: result.placeholder, text: result.descriptions.map(item => item.text).join(' ')};
}

async function choose(page, provider) {
  const attribute = COMMON.includes(provider) ? 'data-credential-app' : 'data-credential-provider';
  const button = page.locator('#credentials [' + attribute + '="' + provider + '"]');
  assert(await button.isEnabled(), provider + ' tile is available');
  await button.click(); await page.locator('#connect-credential-form').waitFor({state: 'visible'});
  await guide(page, 'connect-credential-guide', provider, {links: provider !== 'manual'});
}

async function leave(page) {
  await page.locator('#connect-method-change').click();
  await page.locator('#credentials').waitFor({state: 'visible'});
}

async function refresh(page) {
  await Promise.all([page.waitForResponse(response => response.url().endsWith('/api/operator-demo/catalog')),
    page.locator('#mutation-review-refresh').dispatchEvent('click')]);
  await page.waitForFunction(() => !document.getElementById('mutation-review-refresh').disabled);
}

async function privacy(page, permitted = null) {
  const surfaces = await page.evaluate(() => ({text: document.body.innerText, html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].map(item => ({id: item.id, value: item.value})),
    storage: [Object.entries(localStorage), Object.entries(sessionStorage)]}));
  for (const value of [CANARY, 'synthetic_PEM_GUIDE_NEVER_DISPLAY']) {
    assert(!JSON.stringify([surfaces.text, surfaces.html, surfaces.storage]).includes(value), 'draft material is not rendered or stored');
    assert(surfaces.fields.every(item => item.id === permitted || !item.value.includes(value)), 'draft material stays only in its input value');
  }
}

async function fits(page) {
  assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'guide does not create horizontal page overflow');
}

function cases(artifacts) {
  return [
    ['all common and built-in providers have ordered guides, safe links and visible field hints', browser => synthetic(browser, {}, async page => {
      assert.deepEqual([...CAPABILITIES.capabilities.common_apps.presets.map(item => item.id)].sort(), [...COMMON].sort());
      for (const provider of [...COMMON, 'github_token', 'npm', 'x', 'alchemy', 'manual']) {
        await choose(page, provider);
        const field = ['x', 'alchemy'].includes(provider) ? 'connect-' + provider + '-secret' : 'connect-credential-secret';
        await hint(page, field);
        assert.equal(await page.locator('#' + field).inputValue(), '');
        await leave(page);
      }
    })],
    ['Slack examples are advisory; switching clears secrets and stale hints without a write', browser => synthetic(browser, {}, async (page, state) => {
      await choose(page, 'slack');
      const slack = await hint(page, 'connect-credential-secret');
      assert.match(slack.text, /xoxb-/);
      assert.match(await page.locator('#connect-credential-guide').innerText(), /bot/i);
      const secret = page.locator('#connect-credential-secret');
      assert.equal(await secret.getAttribute('pattern'), null, 'example prefix is not a new validation constraint');
      await secret.fill(CANARY);
      assert(await secret.evaluate(node => node.checkValidity()), 'non-example prefix remains valid HTML input');
      await privacy(page, 'connect-credential-secret');
      await leave(page); await privacy(page); await choose(page, 'openai');
      const openai = await hint(page, 'connect-credential-secret');
      assert.notEqual(openai.placeholder, slack.placeholder); assert.notEqual(openai.text, slack.text);
      assert(!openai.placeholder.includes('xoxb-')); assert(!openai.text.includes('xoxb-'));
      assert.equal(await secret.inputValue(), ''); assert.equal(state.posts.length, 0);
      await leave(page); await choose(page, 'manual'); await hint(page, 'connect-credential-secret');
      assert.equal(await secret.getAttribute('pattern'), null); await privacy(page);
    })],
    ['AWS kind changes and GitHub App PEM show field-specific help without altering input values', browser => synthetic(browser, {}, async (page, state) => {
      await page.locator('#credentials [data-credential-provider="aws"]').click();
      await guide(page, 'aws-credential-guide', 'aws_long_term');
      const longTerm = await hint(page, 'aws-credential-access-key-id');
      await hint(page, 'aws-credential-secret-access-key');
      const access = page.locator('#aws-credential-access-key-id');
      await access.fill('AKIA' + 'A'.repeat(16));
      const pattern = await access.getAttribute('pattern');
      await refresh(page);
      assert.equal(await access.inputValue(), 'AKIA' + 'A'.repeat(16), 'same-kind guide render never rewrites the supplied access ID');
      assert.equal(await access.getAttribute('pattern'), pattern);
      await page.locator('#aws-credential-kind').selectOption('session');
      await guide(page, 'aws-credential-guide', 'aws_session');
      const session = await hint(page, 'aws-credential-access-key-id');
      assert.notEqual(session.placeholder, longTerm.placeholder); assert.notEqual(session.text, longTerm.text);
      await hint(page, 'aws-credential-session-token'); await hint(page, 'aws-credential-expires-at');
      assert.equal(await access.inputValue(), '', 'existing kind-change safety clears the old credential tuple');
      assert.equal(await access.getAttribute('pattern'), pattern);
      await page.locator('#aws-credential-kind').selectOption('long_term');
      await guide(page, 'aws-credential-guide', 'aws_long_term');
      assert.equal(await page.locator('#aws-credential-session-fields').isVisible(), false);
      await page.locator('#aws-credential-cancel').click();
      await choose(page, 'github_app');
      await hint(page, 'connect-github-app-id');
      const privateKey = await hint(page, 'connect-github-private-key');
      assert.match(privateKey.placeholder, /PEM|BEGIN (?:RSA )?PRIVATE KEY/i);
      assert.match(privateKey.text, /BEGIN and END/);
      await page.locator('#connect-github-private-key').fill(PEM); await privacy(page, 'connect-github-private-key');
      await refresh(page);
      assert.equal(await page.locator('#connect-github-private-key').inputValue(), PEM, 'harmless guide render preserves the draft PEM');
      await privacy(page, 'connect-github-private-key'); await leave(page); await privacy(page);
      assert.equal(state.posts.length, 0);
    })],
    ['replacement reuses provider help and desktop/mobile guides stay within the viewport', browser => synthetic(browser, {
      credentials: [credential({app_preset: 'slack', credential_generation: 1, version: 1})]
    }, async page => {
      await page.locator('#credentials-list [data-resource-id="' + IDS.credential + '"] [data-action="replace-key"]').click();
      await guide(page, 'credential-replace-guide', 'slack');
      assert.match((await hint(page, 'credential-replace-secret')).text, /xoxb-/);
      await page.locator('#credential-replace-secret').fill(CANARY); await privacy(page, 'credential-replace-secret');
      assert.equal(await page.locator('#credential-replace-secret').getAttribute('pattern'), null);
      await page.locator('#credential-replace-cancel').click(); await privacy(page);
      await choose(page, 'slack'); await fits(page);
      await page.screenshot({path: join(artifacts, 'slack-guide-desktop.png'), fullPage: true});
      await page.setViewportSize({width: 390, height: 844}); await fits(page);
      await page.screenshot({path: join(artifacts, 'slack-guide-mobile.png'), fullPage: true});
      await leave(page); await choose(page, 'github_app'); await fits(page);
      await page.screenshot({path: join(artifacts, 'github-app-guide-mobile.png'), fullPage: true});
    })]
  ];
}

async function run(browser) {
  const artifacts = await mkdtemp('/tmp/catchplate-credential-guides-');
  const completed = [];
  for (const [name, test] of cases(artifacts)) { await test(browser); completed.push(name); }
  return {ok: true, groups: completed.length, completed, artifacts, scope: 'intercepted rendered credential guidance only',
    mutations: 0, liveRequests: 0, providerCalls: 0, externalLinksOpened: 0, otherSuitesExecuted: false};
}

async function main() {
  assert.equal(process.argv.length, 2, 'no live target or credentials accepted');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  let timer;
  try {
    console.log(JSON.stringify(await Promise.race([run(browser), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('credential guide fixture deadline')), 45000);
    })])));
  } finally { clearTimeout(timer); await browser.close(); }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });
module.exports = {run};

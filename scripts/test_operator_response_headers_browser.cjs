#!/usr/bin/env node
// V2 catalog/UI fixtures only. No provider response is fetched or its header
// handling simulated here; actual admission/discard/disclosure is runtime work.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFileSync} = require('node:fs');
const {readFile, mkdtemp, stat} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const vm = require('node:vm');
const {ready, view, openRestrictions, credential, application, rule, IDS} = require('./test_operator_catalog_browser.cjs');
const {fixture, publicCatalog, supplied, google, digest, direct, draft, pair, method, review, grant,
  refresh, command, disabledClient, downloadedConfig, step, privateAbsent, PRIVATE, DUMMY} = require('./test_operator_ordinary_modes_browser.cjs');
const {clientCredentialInput, credentialHeaderTarget} = require('../serverware/operator_demo_web/app.js');
const ROOT = resolve(__dirname, '..');
const V2 = 'unfiltered_json_or_empty_v2';
const OLD = ['projected_json', 'unfiltered_json', 'unfiltered_json_or_empty_v1'];
const MODES = [...OLD, V2];
const suppliedV2 = changes => supplied({responseModes: MODES, ...changes});
const saved = changes => rule({credential_input: 'insert', response_mode: V2, response_fields: [], ...changes});
const GOOGLE_ORIGIN = 'https://gmail.googleapis.com';
const GOOGLE_PATH = '/gmail/v1/users/me/messages';
const SOURCE_FILES = ['scripts/test_operator_response_headers_browser.cjs', 'scripts/test_operator_ordinary_modes_browser.cjs',
  'scripts/test_operator_catalog_browser.cjs', 'serverware/operator_demo_portal.py',
  ...['index.html', 'style.css', 'app.js', 'workspace_core.js', 'workspace_github.js', 'workspace_applications.js', 'workspace_resources.js',
    'workspace_proxy_audit.js', 'workspace_connect.js'].map(name => 'serverware/operator_demo_web/' + name)];
let artifacts;
async function hashes() { return Object.fromEntries(await Promise.all(SOURCE_FILES.map(async name =>
  [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')]))); }
async function shot(page, name) { await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true}); }
async function metadataCopy(page, selector) {
  const text = await page.locator(selector).innerText();
  assert.match(text, /Standard API metadata is checked and discarded; no extra response headers are forwarded/);
  assert(!text.includes('Date, Server and Cache-Control'), 'technical examples stay in expandable details'); assert.match(text, /204/);
}
async function oldCopy(page, selector) {
  const text = await page.locator(selector).innerText(); assert.match(text, /strict response profile rejects unlisted upstream headers/);
  assert(!text.includes('Date, Server and Cache-Control'), 'legacy technical examples stay in expandable details');
}
async function compatibilityDetails(page, id, current) {
  const details = page.locator('#' + id); assert(!await details.evaluate(node => node.open));
  await details.locator(':scope > summary').click(); const content = details.locator('div'); assert(await content.isVisible());
  const text = await content.innerText(); assert.match(text, /Date, Server and Cache-Control/);
  assert.match(text, /at most 1 MiB/); assert.match(text, /at most 64 KiB/);
  if (current) { assert.match(text, /credential disclosure and discarded/); assert.match(text, /does not select response headers to forward/); }
  else assert.match(text, /does not merely discard them/);
  await details.locator(':scope > summary').click(); assert(!await content.isVisible());
}
async function responseFieldsHidden(page, prefix) {
  assert(!await page.locator('#' + prefix + '-response-fields-group').isVisible());
  assert(await page.locator('#' + prefix + '-response-fields').isDisabled());
}
async function maybeClick(page, selector) { if (!await page.locator(selector).isDisabled()) await page.locator(selector).click(); }

function projectionChecks() {
  const source = ['workspace_core.js', 'workspace_github.js']
    .map(name => readFileSync(join(ROOT, 'serverware/operator_demo_web', name), 'utf8')).join('\n');
  const state = {credentials: [credential({secret: PRIVATE[0]})], applications: [application()],
    rules: [saved({secret: PRIVATE[1]})], requestBodyModes: ['preserve_json_v1'], responseModes: MODES,
    credentialInputModes: ['insert', 'replace_exact'], revision: 1, sequence: 1, active: digest(1), loaded: digest(1)};
  const evaluate = (input, expression = 'projectCatalog(input)') => vm.runInNewContext(source + '\n' + expression,
    {input, clientCredentialInput, credentialHeaderTarget}, {timeout: 1000});
  for (const mode of MODES) {
    const input = publicCatalog(state); input.access_rules[0].response_mode = mode;
    input.access_rules[0].response_fields = mode === 'projected_json' ? ['id'] : [];
    assert.equal(evaluate(input).access_rules[0].response_mode, mode, 'saved modes stay exact');
    assert(!JSON.stringify(evaluate(input)).includes(PRIVATE[0])); assert(!JSON.stringify(evaluate(input)).includes(PRIVATE[1]));
  }
  for (const changes of [{response_mode: null}, {response_mode: 'future_response'}, {response_fields: ['id']}]) {
    const input = publicCatalog(state); Object.assign(input.access_rules[0], changes); assert.throws(() => evaluate(input));
  }
  const input = publicCatalog(state); input.credentials = [google()];
  input.access_rules[0].upstream_url = GOOGLE_ORIGIN + GOOGLE_PATH;
  assert.equal(evaluate(input).access_rules[0].response_mode, V2);
  for (const changes of [{methods: ['POST']}, {request_fields: ['message']}, {request_body_mode: 'preserve_json_v1'}]) {
    const changed = JSON.parse(JSON.stringify(input)); Object.assign(changed.access_rules[0], changes);
    assert.throws(() => evaluate(changed), 'V2 cannot broaden Google request constraints');
  }
  assert.equal(evaluate(publicCatalog(state), 'availableResponseModes(input)[0]'), V2);
  const unadvertised = publicCatalog(state); unadvertised.capabilities.response_modes = OLD;
  assert.equal(evaluate(unadvertised, 'operatorRuleSupported(projectCatalog(input).access_rules[0], projectCatalog(input))'), false);
  return {ok: true, groups: 1, scope: 'actual public projection/mode helpers only; no runtime header proof'};
}

const tests = [
  ['new direct rule defaults V2 without new fields and saves an explicit bounded DTO', browser => fixture(browser, suppliedV2(), async (page, state) => {
    await direct(page); assert.equal(await page.locator('#rule-response-mode').inputValue(), V2); await responseFieldsHidden(page, 'rule');
    assert.equal(await page.locator('#rule-response-mode option:checked').innerText(), 'Do not filter response content');
    await metadataCopy(page, '#rule-response-mode-help'); await compatibilityDetails(page, 'rule-compatibility-limits', true); await method(page, 'rule', 'POST');
    await page.locator('#rule-credential-input').selectOption('replace_exact'); await page.locator('#rule-placeholder').fill(DUMMY);
    await shot(page, 'v2-direct-default-desktop'); await page.locator('#rule-save').click(); await ready(page);
    assert.equal(state.posts.length, 1); const body = state.posts[0].body;
    assert.equal(body.response_mode, V2); assert.deepEqual(body.response_fields, []); assert.equal(body.request_body_mode, 'preserve_json_v1');
    assert.deepEqual(body.request_fields, []); assert.equal(body.placeholder, DUMMY);
    assert(!Object.hasOwn(body, 'unlistedHeaderPolicy') && !Object.hasOwn(body, 'response_headers'));
    await metadataCopy(page, '#access-rules-list'); await view(page, 'proxy'); await command(page); await metadataCopy(page, '#client-guidance');
  })],
  ['guided create/review/setup and private export round-trip V2 without exposing provider material', browser => fixture(browser,
    suppliedV2({applications: [], credentials: [credential({secret: PRIVATE[0], refresh_token: PRIVATE[1]})]}), async (page, state) => {
      await ready(page); await view(page, 'connect'); await page.locator('#connect-use-saved').click();
      await page.locator('#connect-credential-choice').selectOption(IDS.credential);
      await page.locator('#connect-credential-next').click(); await step(page, 'application');
      await page.locator('#connect-application-name').fill('V2 metadata client'); await page.locator('#connect-token-ttl').selectOption('3600');
      await page.locator('#connect-application-next').click(); await step(page, 'access');
      const token = await page.locator('#client-token').inputValue(); assert(token.startsWith('synthetic_application_'));
      await openRestrictions(page, 'connect');
      await page.locator('#connect-rule-name').fill('V2 JSON operation'); await page.locator('#connect-path').fill('/v1/status');
      assert.equal(await page.locator('#connect-response-mode').inputValue(), V2); await responseFieldsHidden(page, 'connect');
      await review(page); await metadataCopy(page, '#connect-review-details'); await shot(page, 'v2-guided-review-desktop');
      assert.deepEqual(state.posts.map(item => item.name), ['applications']); await grant(page);
      await page.locator('#connect-setup-slot').waitFor({state: 'visible'}); await command(page); await privateAbsent(page);
      assert.deepEqual(state.posts.map(item => item.name), ['applications', 'access-rules']);
      assert.equal(state.posts[1].body.response_mode, V2); assert.deepEqual(state.posts[1].body.response_fields, []);
      const config = await downloadedConfig(page); assert.equal(config.response_mode, V2); assert.equal(config.proxy_authorization, 'Bearer ' + token);
      assert(!Object.hasOwn(config, 'response_headers') && !Object.hasOwn(config, 'unlistedHeaderPolicy'));
      await metadataCopy(page, '#client-guidance'); await shot(page, 'v2-guided-setup-desktop');
      await page.setViewportSize({width: 390, height: 844}); assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await shot(page, 'v2-guided-setup-mobile');
    })],
  ...OLD.map(mode => [mode + ' saved rule remains exact beside a new V2 rule', browser => fixture(browser,
    suppliedV2({rules: [saved({response_mode: mode, response_fields: mode === 'projected_json' ? ['id'] : []})]}), async (page, state) => {
      const before = JSON.stringify(state.rules[0]); await direct(page); await page.locator('#rule-save').click(); await ready(page);
      assert.equal(state.posts.length, 1); assert.equal(state.rules[1].response_mode, V2); assert.equal(JSON.stringify(state.rules[0]), before);
      await oldCopy(page, `#access-rules-list [data-resource-id="${IDS.rule}"]`);
      await view(page, 'proxy'); await command(page); await oldCopy(page, '#client-guidance');
      await compatibilityDetails(page, 'client-compatibility-limits', false);
      await page.locator('#proxy-rule').selectOption(state.rules[1].id); await command(page); await metadataCopy(page, '#client-guidance');
      assert.equal(JSON.stringify(state.rules[0]), before);
    })]),
  ...OLD.map(mode => [mode + ' remains new-rule default when it is the only advertised mode', browser => fixture(browser,
    suppliedV2({responseModes: [mode]}), async (page, state) => {
      await direct(page); assert.equal(await page.locator('#rule-response-mode').inputValue(), mode);
      assert.equal(await page.locator('#rule-response-mode option[value="' + V2 + '"]').count(), 0);
      await draft(page); assert.equal(await page.locator('#connect-response-mode').inputValue(), mode); assert.equal(state.posts.length, 0);
    })]),
  ['an existing older draft mode survives added V2 support rather than switching silently', browser => fixture(browser,
    suppliedV2({responseModes: OLD}), async (page, state) => {
    await direct(page); state.responseModes = MODES; await refresh(page, 'rules-refresh');
    assert.equal(await page.locator('#rule-response-mode').inputValue(), 'unfiltered_json_or_empty_v1');
    await draft(page); await refresh(page);
    assert.equal(await page.locator('#connect-response-mode').inputValue(), 'unfiltered_json_or_empty_v1'); assert.equal(state.posts.length, 0);
  })],
  ['V2 capability withdrawal preserves the blocked direct choice and invalidates guided review', browser => fixture(browser, suppliedV2(), async (page, state) => {
    await direct(page); await draft(page); await review(page); state.responseModes = OLD; await refresh(page);
    assert(await page.locator('#connect-grant').isDisabled()); await page.locator('#connect-back').click(); await step(page, 'access');
    assert.equal(await page.locator('#connect-response-mode').inputValue(), V2);
    assert(await page.locator('#connect-response-mode option:checked').evaluate(node => node.disabled));
    await maybeClick(page, '#connect-review'); await step(page, 'access'); await view(page, 'access-rules');
    assert.equal(await page.locator('#rule-response-mode').inputValue(), V2);
    assert(await page.locator('#rule-response-mode option:checked').evaluate(node => node.disabled));
    await maybeClick(page, '#rule-save'); assert.equal(state.posts.length, 0);
  })],
  ...[{name: 'missing', value: undefined}, {name: 'empty', value: []}, {name: 'unknown-only', value: ['future_response']},
    {name: 'legacy-only', value: OLD}].map(cap => [cap.name + ' capabilities never authorize a saved V2 client', browser => fixture(browser,
      suppliedV2({responseModes: cap.value, rules: [saved()]}), async (page, state) => {
        await ready(page); await disabledClient(page); await view(page, 'access-rules');
        assert.equal(await page.locator('#rule-response-mode option[value="' + V2 + '"]:not(:disabled)').count(), 0);
        if (cap.name !== 'legacy-only') assert(await page.locator('#rule-save').isDisabled());
        assert.equal(state.posts.length, 0);
      })]),
  ...[{name: 'null', changes: {response_mode: null}}, {name: 'unknown', changes: {response_mode: 'future_response'}},
    {name: 'mixed fields', changes: {response_fields: ['id']}}].map(test => [test.name + ' saved mode fails closed', browser => fixture(browser,
      suppliedV2({rules: [saved(test.changes)]}), async (page, state) => {
        await page.locator('#load-error').waitFor({state: 'visible'}); assert(await page.locator('#rule-save').isDisabled());
        assert(await page.locator('#connect-credential-next').isDisabled()); await disabledClient(page); assert.equal(state.posts.length, 0);
      })]),
  ...['direct', 'guided'].map(flow => [flow + ' Google V2 selection keeps GET/no-body and unavailable consent controls', browser => fixture(browser,
    suppliedV2({credentials: [google()], allowedUpstreams: [GOOGLE_ORIGIN]}), async (page, state) => {
      if (flow === 'direct') { await direct(page); await page.locator('#rule-path').fill(GOOGLE_PATH); }
      else { await pair(page); await openRestrictions(page, 'connect'); await page.locator('#connect-rule-name').fill('Google read'); await page.locator('#connect-path').fill(GOOGLE_PATH); }
      const prefix = flow === 'direct' ? 'rule' : 'connect';
      assert.equal(await page.locator('#' + prefix + '-response-mode').inputValue(), V2);
      assert.equal(await page.locator('#' + prefix + '-request-body-mode').inputValue(), 'legacy_fields');
      assert.equal(await page.locator('#' + prefix + '-request-body-mode option[value="preserve_json_v1"]:not(:disabled)').count(), 0);
      await method(page, prefix, 'POST'); await maybeClick(page, flow === 'direct' ? '#rule-save' : '#connect-review'); assert.equal(state.posts.length, 0);
      await method(page, prefix, 'GET');
      if (flow === 'direct') { await page.locator('#rule-save').click(); await ready(page); }
      else { await review(page); await grant(page); }
      assert.equal(state.posts.length, 1); const body = state.posts[0].body;
      assert.equal(body.upstream_url, GOOGLE_ORIGIN + GOOGLE_PATH); assert.equal(body.response_mode, V2);
      assert.deepEqual(body.methods, ['GET']); assert.deepEqual(body.request_fields, []); assert(!Object.hasOwn(body, 'request_body_mode'));
      await view(page, 'credentials'); assert(await page.locator('#credential-google-connect').isDisabled());
      await view(page, 'connect'); assert(await page.locator('#connect-google').isDisabled());
      assert(!state.requests.some(item => /oauth|google/.test(item.path)), 'provider/consent URLs are never requested');
    })]),
  ['V2 capability plus pending policy is not ready client setup', browser => fixture(browser,
    suppliedV2({activationOverride: 'pending'}), async (page, state) => {
      await draft(page); await review(page); await grant(page); assert.equal(state.active, state.loaded);
      assert(!await page.locator('#connect-setup-slot').isVisible()); assert(await page.locator('#copy-command').isDisabled());
      assert(await page.locator('#download-config').isDisabled()); state.activationOverride = 'active'; await refresh(page);
      await page.locator('#connect-setup-slot').waitFor({state: 'visible'}); await command(page); assert.equal(state.posts.length, 1);
    })],
];

async function main() {
  assert.equal(process.argv.length, 2, 'synthetic test accepts no target, credentials or network options');
  const before = await hashes(); console.log(JSON.stringify({phase: 'source-before', hashes: before}));
  console.log(JSON.stringify(projectionChecks()));
  const root = '/srv/catchplate-fast/projects/serverware-operator-artifacts'; assert((await stat(root)).isDirectory());
  artifacts = await mkdtemp(join(root, 'response-headers-browser-synthetic-')); console.log(JSON.stringify({artifactDirectory: artifacts}));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']}); let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of tests) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: tests.length, pureGroups: 1, scope: 'intercepted response-header V2 UI only',
        liveRequests: 0, providerRequests: 0, nativeCaDownloadExecuted: false, generatedCommandsExecuted: false,
        otherBrowserSuitesExecuted: false, runtimeHeaderAcceptance: false, productionAcceptance: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('V2 fixture deadline')), 150000); })]);
  } finally {
    clearTimeout(deadline); try { await browser.close(); }
    finally { const after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after})); assert.deepEqual(after, before); }
  }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

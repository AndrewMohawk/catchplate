#!/usr/bin/env node
// Focused presentation checks only. Requests are intercepted synthetic fixtures;
// the command generator is compared, not changed or executed. No live targets.
const assert = require('node:assert/strict');
const {mkdtemp, stat} = require('node:fs/promises');
const {join} = require('node:path');
const {fixture, ready, view, openRestrictions, credential, application, rule, IDS, UPSTREAM} = require('./test_operator_catalog_browser.cjs');
const {buildCurlCommand} = require('../serverware/operator_demo_web/app.js');
let artifacts;
const supplied = (changes = {}) => ({credentials: [credential()], applications: [application()],
  responseModes: ['projected_json', 'unfiltered_json'], ...changes});
const rows = (page, selector) => page.locator(selector).evaluate(node => Object.fromEntries(
  [...node.querySelectorAll('dt')].map(label => [label.textContent, label.nextElementSibling.textContent])));
const draftRows = page => rows(page, '#rule-effective-restrictions');
const savedRows = page => rows(page, `#access-rules-list [data-resource-id="${IDS.rule}"]`);
function compactResponse(summary) {
  assert(summary.Response.includes('JSON only; no empty/204 responses'));
  assert(!Object.hasOwn(summary, 'Response limits') && !Object.hasOwn(summary, 'Response status codes'));
  assert(!Object.values(summary).some(value => value.includes('1 MiB') || value.includes('200, 201, 202')));
}
async function compatibility(page, area) {
  const details = page.locator('#' + area + '-compatibility-limits');
  const content = page.locator('#' + area + '-compatibility-content');
  assert.equal(await details.evaluate(node => node.open), false); assert(!(await content.isVisible()));
  await details.locator('summary').click(); assert(await content.isVisible());
  const text = await content.innerText();
  for (const item of ['JSON only; no empty/204 responses.', '1 MiB', '64 KiB',
    'Form, multipart, text, binary, compressed bodies, streaming and HEAD are unsupported.',
    'rejects unlisted upstream headers', 'No response headers are selected for forwarding',
    '200, 201, 202', 'error, code and message', 'does not remove size, status or transport limits']) assert(text.includes(item));
  await details.locator('summary').click(); assert(!(await content.isVisible()));
}

const tests = [
  ['live draft exposes bodyless POST and all default restrictions before save', browser => fixture(browser, supplied(), async (page, state) => {
    await ready(page); await view(page, 'access-rules');
    assert(!await page.locator('#rule-request-fields').isVisible());
    assert(await page.locator('#rule-request-fields').evaluate(node => node.closest('details')?.id === 'rule-restrictions'));
    assert.match(await page.locator('#rule-basic-compatibility').innerText(), /No request body/);
    await openRestrictions(page, 'rule');
    assert(await page.locator('#rule-body-default').isVisible());
    assert((await page.locator('#rule-body-default').innerText()).includes('POST, PUT and PATCH'));
    await page.locator('#rule-path').fill('/v1/status');
    await page.locator('input[name="rule-method"][value="GET"]').uncheck();
    await page.locator('input[name="rule-method"][value="POST"]').check();
    const summary = await draftRows(page);
    assert.equal(Object.keys(summary).length, 5);
    assert.equal(summary['Destination / methods'], UPSTREAM + '/v1/status · POST only');
    assert(summary['Request body'].startsWith('No body') && summary['Request body'].includes('POST'));
    assert(summary['Query parameters'].startsWith('None allowed'));
    assert(summary['Client headers'].includes('accept, user-agent'));
    assert(summary.Response.includes('Do not filter response content'));
    assert(summary.Response.includes('including errors')); compactResponse(summary);
    await compatibility(page, 'rule');
    assert((await page.locator('#rule-effective-context').innerText()).includes('not yet saved or validated'));
    assert(await page.evaluate(() => Boolean(document.querySelector('#rule-effective-summary').compareDocumentPosition(
      document.querySelector('#rule-save')) & Node.DOCUMENT_POSITION_FOLLOWING)));
    assert.equal(state.posts.length, 0); assert(await page.locator('#credential-google-connect').isDisabled());
    await page.setViewportSize({width: 390, height: 844});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.screenshot({path: join(artifacts, 'mobile-bodyless-post-draft-synthetic.png'), fullPage: true});
  })],
  ['edited draft and saved card show the same exact restrictions without broadening the submitted rule', browser => fixture(browser, supplied(), async (page, state) => {
    await ready(page); await view(page, 'access-rules');
    await openRestrictions(page, 'rule');
    await page.locator('#rule-name').fill('Scoped JSON operation'); await page.locator('#rule-path').fill('/v1/status');
    await page.locator('input[name="rule-method"][value="GET"]').uncheck(); await page.locator('input[name="rule-method"][value="POST"]').check();
    await page.locator('#rule-request-fields').fill('model\nmessages');
    await page.locator('#rule-request-extras summary').click();
    await page.locator('#rule-query-keys').fill('limit\ncursor'); await page.locator('#rule-allowed-headers').fill('accept\nx-client-id');
    await page.locator('#rule-response-mode').selectOption('projected_json'); await page.locator('#rule-response-fields').fill('result.id\nresult.status');
    const draft = await draftRows(page);
    assert(draft['Request body'].includes('JSON fields only: model, messages'));
    assert(draft['Query parameters'].includes('limit, cursor')); assert(draft['Client headers'].includes('accept, x-client-id'));
    assert(draft.Response.includes('result.id, result.status')); compactResponse(draft);
    await page.locator('#rule-save').click(); await ready(page);
    assert.equal(state.posts.length, 1);
    assert.deepEqual(state.posts[0].body.methods, ['POST']); assert.deepEqual(state.posts[0].body.request_fields, ['model', 'messages']);
    assert.deepEqual(state.posts[0].body.query_keys, ['limit', 'cursor']); assert.deepEqual(state.posts[0].body.allowed_headers, ['accept', 'x-client-id']);
    assert.equal(state.posts[0].body.response_mode, 'projected_json'); assert.deepEqual(state.posts[0].body.response_fields, ['result.id', 'result.status']);
    const saved = await savedRows(page);
    for (const [label, text] of Object.entries(draft)) assert.equal(saved[label], text, label);
  })],
  ['whole-JSON saved cards retain visible empty-response and request restrictions', browser => fixture(browser, supplied({rules: [rule({methods: ['POST'],
    response_mode: 'unfiltered_json', response_fields: [], allowed_headers: []})]}), async (page, state) => {
    await ready(page); await view(page, 'access-rules'); const summary = await savedRows(page);
    assert.equal(summary['Destination / methods'], UPSTREAM + '/v1/status · POST only'); assert(summary['Request body'].startsWith('No body'));
    assert(summary['Query parameters'].startsWith('None allowed')); assert(summary['Client headers'].startsWith('No extra client headers'));
    assert(summary.Response.includes('All JSON content')); compactResponse(summary);
    await openRestrictions(page, 'rule');
    assert.equal(await page.locator('#rule-response-limits').innerText(), 'JSON only; no empty/204 responses.');
    await compatibility(page, 'rule');
    assert.equal(state.posts.length, 0);
  })],
  ['existing-client guidance labels the unchanged generated curl as an incomplete connection template', browser => fixture(browser, supplied({rules: [rule({methods: ['POST'],
    request_fields: ['model'], query_keys: ['limit']})]}), async (page, state) => {
    await ready(page); await view(page, 'proxy');
    assert(await page.locator('#client-existing-settings').isVisible());
    assert((await page.locator('#client-existing-settings h2').innerText()).includes("existing client's proxy settings"));
    assert.equal(await page.locator('#client-template-title').innerText(), 'cURL connection template');
    assert((await page.locator('#client-template-warning').innerText()).includes('no request body or query parameter values'));
    const expected = buildCurlCommand({proxyUrl: 'https://proxy.example.test', upstreamUrl: UPSTREAM + '/v1/status', method: 'POST',
      caPath: './serverware-ca.pem', allowedHeaders: ['accept', 'user-agent'], credentialInput: 'insert', credential: credential()});
    assert.equal(await page.locator('#client-command').innerText(), expected);
    const guidance = await page.locator('#client-guidance').innerText();
    for (const text of ['connection template', 'no request body or query parameter values', 'fields: model', 'names allowed: limit', 'no empty/204 responses']) assert(guidance.includes(text));
    assert(!guidance.includes('1 MiB') && !guidance.includes('200, 201, 202'));
    await compatibility(page, 'client');
    assert.equal(await page.locator('#copy-command').innerText(), 'Copy connection template');
    await page.locator('#copy-command').click();
    await page.waitForFunction(() => document.querySelector('#client-copy-status').textContent.startsWith('Copied.'));
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), expected); assert.equal(state.posts.length, 0);
    await page.screenshot({path: join(artifacts, 'desktop-client-connection-template-synthetic.png'), fullPage: true});
  })],
];

async function main() {
  const args = process.argv.slice(2);
  assert(args.length === 0 || args.length === 2 && args[0] === '--from-group' && args[1] === '3',
    'usage: test_operator_rule_clarity_browser.cjs [--from-group 3]');
  const firstGroup = args.length === 0 ? 1 : 3;
  const selected = tests.slice(firstGroup - 1);
  const artifactRoot = '/srv/catchplate-fast/projects/serverware-operator-artifacts';
  assert((await stat(artifactRoot)).isDirectory());
  artifacts = await mkdtemp(join(artifactRoot, 'rule-clarity-synthetic-'));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of selected) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: selected.length, totalGroups: tests.length, firstGroup, scope: 'intercepted synthetic rule-clarity browser fixtures only',
        liveRequests: 0, otherBrowserSuitesExecuted: false, generatedCommandsExecuted: false, productionAcceptance: false, screenshots: artifacts}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('rule-clarity fixture deadline')), 55000); })]);
  } finally { clearTimeout(deadline); await browser.close(); }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

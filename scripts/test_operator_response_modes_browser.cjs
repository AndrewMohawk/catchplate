#!/usr/bin/env node
// Focused response-mode UI checks. Reuses only intercepted synthetic fixtures;
// does not run the existing catalog suite or contact any application/provider.
const assert = require('node:assert/strict');
const {fixture, ready, view, credential, application, rule, IDS} = require('./test_operator_catalog_browser.cjs');

const BOTH = ['projected_json', 'unfiltered_json'];
const supplied = (changes = {}) => ({credentials: [credential()], applications: [application()], responseModes: BOTH, ...changes});
const fields = page => page.locator('#rule-response-fields');
const mode = page => page.locator('#rule-response-mode');
const ruleCard = (page, id) => page.locator(`#access-rules-list [data-resource-id="${id}"]`);

async function form(page, name = 'Scoped status access') {
  await ready(page); await view(page, 'access-rules');
  await page.locator('#rule-name').fill(name); await page.locator('#rule-path').fill('/v1/status');
}
async function save(page) { await page.locator('#rule-save').click(); await ready(page); }
async function projectionState(page, projected) {
  assert.equal(await fields(page).evaluate(node => node.required), projected);
  assert.equal(await fields(page).isDisabled(), !projected);
  assert.equal(await page.locator('#rule-response-fields-group').isVisible(), projected);
}
async function usableCommand(page) {
  await view(page, 'proxy');
  await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  const command = await page.locator('#client-command').innerText();
  assert(command.includes('$SERVERWARE_PROXY_TOKEN') && command.includes('--cacert') && command.includes('/v1/status'));
  assert(!command.includes('--insecure') && !command.includes('--proxy-insecure'));
}

const tests = [
  ['advertised simple mode is the new-rule default and needs no response fields', browser => fixture(browser, supplied(), async (page, state) => {
    await form(page); assert.equal(await mode(page).inputValue(), 'unfiltered_json'); await projectionState(page, false);
    assert.deepEqual(await mode(page).locator('option').evaluateAll(items => items.map(item => item.value).sort()), [...BOTH].sort());
    await save(page); assert.equal(state.posts.length, 1);
    assert.equal(state.posts[0].body.response_mode, 'unfiltered_json'); assert.deepEqual(state.posts[0].body.response_fields, []);
    assert.equal(state.rules[0].response_mode, 'unfiltered_json');
    const summary = await ruleCard(page, IDS.rule).innerText();
    assert(summary.includes('Do not filter response content') && summary.includes('All JSON content (no field filtering)'));
    await usableCommand(page); assert.equal(state.posts.length, 1);
  })],
  ['explicit projection still requires selected fields and publishes that choice', browser => fixture(browser, supplied(), async (page, state) => {
    await form(page); await mode(page).selectOption('projected_json'); await projectionState(page, true);
    await page.locator('#rule-save').click(); assert.equal(state.posts.length, 0, 'empty projection must not submit');
    assert.equal(await fields(page).evaluate(node => node.validity.valueMissing), true);
    await fields(page).fill('id\nstatus'); await save(page);
    assert.equal(state.posts[0].body.response_mode, 'projected_json'); assert.deepEqual(state.posts[0].body.response_fields, ['id', 'status']);
    const summary = await ruleCard(page, IDS.rule).innerText();
    assert(summary.includes('Only return selected JSON fields') && summary.includes('id, status'));
    await usableCommand(page);
  })],
  ['explicit mode choice survives refresh and hidden projection values are not submitted', browser => fixture(browser, supplied(), async (page, state) => {
    await form(page); await mode(page).selectOption('projected_json'); await fields(page).fill('id\nstatus');
    await page.locator('#rules-refresh').click(); await ready(page);
    assert.equal(await mode(page).inputValue(), 'projected_json'); await projectionState(page, true);
    await mode(page).selectOption('unfiltered_json'); await projectionState(page, false); await save(page);
    assert.equal(state.posts[0].body.response_mode, 'unfiltered_json'); assert.deepEqual(state.posts[0].body.response_fields, []);
  })],
  ['capability withdrawal returns a pending new form to explicit projection without a write', browser => fixture(browser, supplied(), async (page, state) => {
    await form(page); assert.equal(await mode(page).inputValue(), 'unfiltered_json');
    state.responseModes = ['projected_json']; await page.locator('#rules-refresh').click();
    await page.waitForFunction(() => document.querySelector('#rule-response-mode').value === 'projected_json');
    await projectionState(page, true);
    assert.equal(await mode(page).locator('option[value="unfiltered_json"]').count(), 0);
    await page.locator('#rule-save').click(); assert.equal(state.posts.length, 0);
    assert.equal(state.rules.length, 0);
  })],
  ['legacy projected-only catalog keeps projection as the default and existing command usable', browser => fixture(browser,
    {credentials: [credential()], applications: [application()], rules: [rule()]}, async (page, state) => {
      const before = JSON.stringify(state.rules);
      await form(page); assert.equal(await mode(page).inputValue(), 'projected_json'); await projectionState(page, true);
      assert.equal(await mode(page).locator('option[value="unfiltered_json"]').count(), 0);
      await usableCommand(page); assert.equal(JSON.stringify(state.rules), before); assert.equal(state.posts.length, 0);
    })],
  ...[{name: 'missing', value: undefined}, {name: 'empty', value: []}, {name: 'unknown-only', value: ['future_json']}].map(capability =>
    [capability.name + ' response capability cannot enable a new simple-mode rule', browser => fixture(browser, supplied({responseModes: capability.value}), async (page, state) => {
      await ready(page); await view(page, 'access-rules');
      assert(await page.locator('#access-rule-fields').evaluate(node => node.disabled));
      assert(await page.locator('#rule-save').isDisabled()); assert.equal(state.posts.length, 0);
      assert.equal(await mode(page).locator('option[value="unfiltered_json"]').count(), 0);
    })]),
  ['new simple rule does not rewrite an existing projected rule or its summary', browser => fixture(browser, supplied({rules: [rule()]}), async (page, state) => {
    const before = JSON.stringify(state.rules[0]); await form(page, 'Additional simple rule'); await save(page);
    assert.equal(state.rules.length, 2); assert.equal(JSON.stringify(state.rules[0]), before);
    assert.equal(state.rules[1].response_mode, 'unfiltered_json'); assert.deepEqual(state.rules[1].response_fields, []);
    assert((await ruleCard(page, IDS.rule).innerText()).includes('id, status'));
    assert((await ruleCard(page, state.rules[1].id).innerText()).includes('All JSON content (no field filtering)'));
    await usableCommand(page);
    await page.locator('#proxy-rule').selectOption(state.rules[1].id);
    assert(!(await page.locator('#copy-command').isDisabled())); assert.equal(state.posts.length, 1);
  })],
  ...[
    {name: 'unadvertised simple mode', modes: ['projected_json'], saved: rule({response_mode: 'unfiltered_json', response_fields: []})},
    {name: 'unknown saved mode', modes: BOTH, saved: rule({response_mode: 'future_json', response_fields: []})},
    {name: 'simple mode with conflicting fields', modes: BOTH, saved: rule({response_mode: 'unfiltered_json', response_fields: ['id']})},
    {name: 'projection without explicit fields', modes: BOTH, saved: rule({response_mode: 'projected_json', response_fields: []})},
  ].map(test => [test.name + ' cannot produce an enabled client command', browser => fixture(browser,
    supplied({responseModes: test.modes, rules: [test.saved]}), async (page, state) => {
      await ready(page); await view(page, 'proxy');
      assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
      assert.equal(state.posts.length, 0);
    })]),
];

async function main() {
  assert.equal(process.argv.length, 2, 'response-mode suite does not accept live targets or credentials');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of tests) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: tests.length, scope: 'intercepted synthetic response-mode UI fixtures only',
        existingCatalogSuiteExecuted: false, liveRequests: 0, productionAcceptance: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('response-mode fixture deadline')), 75000); })]);
  } finally { clearTimeout(deadline); await browser.close(); }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

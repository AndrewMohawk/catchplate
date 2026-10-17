#!/usr/bin/env node
// Focused public placeholder configuration only. All rendered requests use the
// existing bounded synthetic fixture; generated commands are parsed, never run.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {fixture, ready, view, openRestrictions, credential, application, rule, IDS, UPSTREAM} = require('./test_operator_catalog_browser.cjs');

const MODES = ['insert', 'replace_exact'];
const DUMMY = "Bearer DUMMY-$literal-'quoted'-`value`";
const supplied = (changes = {}) => ({credentials: [credential()], applications: [application()], credentialInputModes: MODES, ...changes});
const selector = page => page.locator('#rule-credential-input');
const placeholder = page => page.locator('#rule-placeholder');
const commandArgs = command => JSON.parse(execFileSync('python3', ['-B', '-c',
  'import json, shlex, sys; print(json.dumps(shlex.split(sys.stdin.read())))'],
{input: command.replace(/\\\r?\n/g, ''), encoding: 'utf8', timeout: 5000, maxBuffer: 65536}));
const flagValues = (args, flag) => args.flatMap((value, index) => value === flag ? [args[index + 1]] : []);
function separateProxy(args) {
  assert.deepEqual(flagValues(args, '--proxy-header'), ['Proxy-Authorization: Bearer $CATCHPLATE_PROXY_TOKEN']);
  assert(!flagValues(args, '--header').some(value => /^proxy-authorization:/i.test(value)));
  assert(!args.includes('--insecure') && !args.includes('--proxy-insecure'));
}
async function form(page, name = 'Scoped credential use') {
  await ready(page); await view(page, 'access-rules');
  await openRestrictions(page, 'rule');
  await page.locator('#rule-name').fill(name); await page.locator('#rule-path').fill('/v1/status');
  await page.locator('#rule-response-fields').fill('id\nstatus');
}
async function save(page) { await page.locator('#rule-save').click(); await ready(page); }
async function placeholderState(page, replacing) {
  assert.equal(await page.locator('#rule-placeholder-group').isVisible(), replacing);
  assert.equal(await placeholder(page).isDisabled(), !replacing);
  assert.equal(await placeholder(page).evaluate(node => node.required), replacing);
}
async function clientArgs(page) {
  await view(page, 'proxy'); await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  const args = commandArgs(await page.locator('#client-command').innerText()); separateProxy(args); return args;
}

function generatorChecks() {
  const {buildCurlCommand} = require('../catchplate/operator_demo_web/app.js');
  const base = {proxyUrl: 'https://proxy.example.test', upstreamUrl: UPSTREAM + '/v1/status', method: 'GET', caPath: './catchplate-ca.pem'};
  const generate = overrides => buildCurlCommand({...base, ...overrides});
  for (const args of [commandArgs(generate({})), commandArgs(generate({credentialInput: 'insert', credential: credential()}))]) {
    separateProxy(args); assert(!flagValues(args, '--header').some(value => /^authorization:/i.test(value)));
  }
  for (const item of [credential(), ...['X-API-Key', "X-Dummy'Key", 'Accept', 'User-Agent'].map(header_name => credential({auth_type: 'header', header_name}))]) {
    const command = generate({credentialInput: 'replace_exact', placeholder: DUMMY, credential: item,
      credentialHeader: 'Proxy-Authorization', providerSecret: 'synthetic-secret-excluded', clientToken: 'synthetic-token-excluded'});
    const args = commandArgs(command); separateProxy(args);
    assert.deepEqual(flagValues(args, '--header').filter(value => value.split(':', 1)[0].toLowerCase() === item.header_name.toLowerCase()),
      [item.header_name + ': ' + DUMMY], 'one exactly preserved upstream header argument');
    assert(!command.includes('synthetic-secret-excluded') && !command.includes('synthetic-token-excluded'));
  }
  for (const value of [undefined, null, '', ' leading', 'trailing ', 'bad\rvalue', 'bad\nvalue', 'bad\tvalue', '\u007f', '\u0080', 'x'.repeat(1025)])
    assert.throws(() => generate({credentialInput: 'replace_exact', placeholder: value, credential: credential()}));
  for (const value of [null, '', 'DUMMY']) assert.throws(() => generate({credentialInput: 'insert', placeholder: value, credential: credential()}));
  for (const value of [null, '', 'replace', 'unknown']) assert.throws(() => generate({credentialInput: value, credential: credential()}));
  for (const item of [null, {auth_type: 'cookie', header_name: 'Cookie'}, ...['Authorization', 'Proxy-Authorization', 'Proxy_Authorization',
    'Host', 'Content-Type', 'Content-Length', 'Cookie', 'X_Catchplate_Admin', 'X-Key\nInjected'].map(header_name => ({auth_type: 'header', header_name}))])
    assert.throws(() => generate({credentialInput: 'replace_exact', placeholder: 'DUMMY', credential: item}));
  return {ok: true, groups: 6, scope: 'pure client generator; parsed command arguments only, no shell execution'};
}

const tests = [
  ['new rules default to insertion and omit every placeholder field', browser => fixture(browser, supplied(), async (page, state) => {
    await form(page); assert.equal(await selector(page).inputValue(), 'insert'); await placeholderState(page, false);
    await save(page); assert.equal(state.posts[0].body.credential_input, 'insert'); assert(!Object.hasOwn(state.posts[0].body, 'placeholder'));
    const args = await clientArgs(page); assert(!flagValues(args, '--header').some(value => /^authorization:/i.test(value)));
  })],
  ...[credential(), credential({auth_type: 'header', header_name: 'X-API-Key'})].map(item =>
    [item.auth_type + ' exact replacement submits and quotes the complete dummy header value', browser => fixture(browser, supplied({credentials: [item]}), async (page, state) => {
      await form(page); await selector(page).selectOption('replace_exact'); await placeholderState(page, true);
      assert.equal(await placeholder(page).getAttribute('maxlength'), '1024');
      assert.equal(await page.locator('#rule-credential-header').evaluate(node => node.tagName), 'CODE');
      assert.equal(await page.locator('#rule-credential-header').innerText(), item.header_name);
      await placeholder(page).fill(DUMMY); await save(page);
      assert.equal(state.posts[0].body.credential_input, 'replace_exact'); assert.equal(state.posts[0].body.placeholder, DUMMY);
      assert(!state.posts[0].body.allowed_headers.some(value => value.toLowerCase() === item.header_name.toLowerCase()));
      assert(flagValues(await clientArgs(page), '--header').includes(item.header_name + ': ' + DUMMY));
    })]),
  ['invalid exact values cannot submit or get silently trimmed', browser => fixture(browser, supplied(), async (page, state) => {
    await form(page); await selector(page).selectOption('replace_exact');
    for (const value of ['', ' leading', 'trailing ', 'bad\tvalue', '\u0080']) {
      await placeholder(page).fill(value); await page.locator('#rule-save').click();
      assert.equal(state.posts.length, 0); assert.equal(await placeholder(page).inputValue(), value);
    }
  })],
  ['switching to insertion omits an earlier dummy value', browser => fixture(browser, supplied(), async (page, state) => {
    await form(page); await selector(page).selectOption('replace_exact'); await placeholder(page).fill(DUMMY);
    await selector(page).selectOption('insert'); await placeholderState(page, false); await save(page);
    assert.equal(state.posts[0].body.credential_input, 'insert'); assert(!Object.hasOwn(state.posts[0].body, 'placeholder'));
  })],
  ['one credential supports distinct insert and replace rules without rewriting either choice', browser => fixture(browser, supplied(), async (page, state) => {
    await form(page, 'Insert rule'); await save(page); const first = JSON.stringify(state.rules[0]);
    await form(page, 'Replacement rule'); await selector(page).selectOption('replace_exact'); await placeholder(page).fill(DUMMY); await save(page);
    assert.equal(state.credentials.length, 1); assert.equal(state.rules.length, 2); assert.equal(JSON.stringify(state.rules[0]), first);
    assert.deepEqual(state.rules.map(item => item.credential_id), [IDS.credential, IDS.credential]);
    assert.deepEqual(state.rules.map(item => item.credential_input), ['insert', 'replace_exact']);
    assert(!Object.hasOwn(state.rules[0], 'placeholder')); assert.equal(state.rules[1].placeholder, DUMMY);
    let args = await clientArgs(page); assert(!flagValues(args, '--header').some(value => /^authorization:/i.test(value)));
    await page.locator('#proxy-rule').selectOption(state.rules[1].id); args = await clientArgs(page);
    assert(flagValues(args, '--header').includes('Authorization: ' + DUMMY)); assert.equal(state.posts.length, 2);
  })],
  ['saved legacy rule without input mode remains insertion when advertised', browser => fixture(browser,
    {credentials: [credential()], applications: [application()], rules: [rule()]}, async (page, state) => {
      const before = JSON.stringify(state.rules); assert(!Object.hasOwn(state.rules[0], 'credential_input'));
      const args = await clientArgs(page); assert(!flagValues(args, '--header').some(value => /^authorization:/i.test(value)));
      assert.equal(JSON.stringify(state.rules), before); assert.equal(state.posts.length, 0);
    })],
  ...[{name: 'missing', modes: undefined}, {name: 'empty', modes: []}, {name: 'unknown-only', modes: ['future_mode']}].map(capability =>
    [capability.name + ' capability disables new rules and unconfirmed client usage', browser => fixture(browser,
      supplied({credentialInputModes: capability.modes, rules: [rule()]}), async (page, state) => {
        await ready(page); await view(page, 'access-rules'); assert(await page.locator('#access-rule-fields').evaluate(node => node.disabled));
        assert(await page.locator('#rule-save').isDisabled()); await view(page, 'proxy');
        assert(await page.locator('#copy-command').isDisabled()); assert.equal(state.posts.length, 0);
      })]),
  ['withdrawing replacement capability returns the unsaved form to insertion', browser => fixture(browser, supplied(), async (page, state) => {
    await form(page); await selector(page).selectOption('replace_exact'); await placeholder(page).fill(DUMMY);
    state.credentialInputModes = ['insert']; await page.locator('#rules-refresh').click();
    await page.waitForFunction(() => document.querySelector('#rule-credential-input').value === 'insert');
    await placeholderState(page, false); assert.equal(await selector(page).locator('option[value="replace_exact"]').count(), 0);
    assert.equal(state.posts.length, 0);
  })],
  ...[
    {name: 'unknown mode', malformed: true, saved: rule({credential_input: 'future_mode'})},
    {name: 'missing dummy', malformed: true, saved: rule({credential_input: 'replace_exact'})},
    {name: 'empty dummy', malformed: true, saved: rule({credential_input: 'replace_exact', placeholder: ''})},
    {name: 'outer whitespace', malformed: true, saved: rule({credential_input: 'replace_exact', placeholder: ' DUMMY'})},
    {name: 'insert with placeholder', malformed: true, saved: rule({credential_input: 'insert', placeholder: 'DUMMY'})},
    {name: 'replacement not advertised', saved: rule({credential_input: 'replace_exact', placeholder: 'DUMMY'}), modes: ['insert']},
  ].map(test => [test.name + ' disables generated client actions', browser => fixture(browser,
    supplied({rules: [test.saved], credentialInputModes: test.modes || MODES}), async (page, state) => {
      if (test.malformed) {
        await page.locator('#load-error').waitFor({state: 'visible'});
        assert(await page.locator('#credential-fields').evaluate(node => node.disabled));
        assert(await page.locator('#access-rule-fields').evaluate(node => node.disabled));
      } else await ready(page);
      await view(page, 'proxy'); assert(await page.locator('#copy-command').isDisabled());
      assert(await page.locator('#download-config').isDisabled()); assert.equal(state.posts.length, 0);
    })]),
];

async function main() {
  assert.equal(process.argv.length, 2, 'credential-input tests do not accept live targets or credentials');
  console.log(JSON.stringify(generatorChecks()));
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  let deadline;
  try {
    await Promise.race([(async () => {
      for (const [name, run] of tests) { await run(browser); console.log('PASS ' + name); }
      console.log(JSON.stringify({ok: true, groups: tests.length, scope: 'intercepted synthetic per-rule credential input UI fixtures only',
        otherBrowserSuitesExecuted: false, liveRequests: 0, generatedCommandsExecuted: false, productionAcceptance: false}));
    })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('credential-input fixture deadline')), 90000); })]);
  } finally { clearTimeout(deadline); await browser.close(); }
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

#!/usr/bin/env node
// Intercepted Alchemy UI story only. Neither an actual backend nor any SDK,
// generated command, provider, proxy, CA server or native authority is executed.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {ready, view, credential, application, IDS, UPSTREAM} = require('./test_operator_catalog_browser.cjs');
const {fixture: ordinaryFixture, supplied, pair, step, review, grant, draft} = require('./test_operator_ordinary_modes_browser.cjs');
const {fixture: xFixture, xRule} = require('./operator_x_browser_fixture.cjs');
const {fixture, capability, alchemyCredential, alchemyRule, clone, privateAbsent, ORIGIN,
  BUNDLE, CHAINS, RPC, api, DUMMY, PRIVATE, APP_TOKEN} = require('./operator_alchemy_browser_fixture.cjs');
const ROOT = resolve(__dirname, '..');

async function refresh(page) {
  const response = page.waitForResponse(item => item.url() === ORIGIN + '/api/operator-demo/catalog' && item.request().method() === 'GET');
  await page.locator('#connect-status-refresh').click(); await (await response).finished();
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
}
async function keyForm(page) {
  await ready(page); await view(page, 'connect'); await page.locator('#connect-use-alchemy').click();
  assert(await page.locator('#connect-alchemy-secret').isVisible());
  assert.equal(await page.locator('#connect-alchemy-secret').getAttribute('type'), 'password');
  assert(await page.locator('#connect-credential-secret').isHidden()); assert(await page.locator('#connect-x-secret').isHidden());
  await page.locator('#connect-alchemy-name').fill('My Alchemy key'); await page.locator('#connect-alchemy-secret').fill(PRIVATE);
}
async function chainForm(page, chain = CHAINS[0]) {
  assert.equal(await page.locator('#connect-operation').inputValue(), BUNDLE);
  assert.equal(await page.locator('#connect-operation option').count(), 1);
  assert(await page.locator('#connect-operation-group').isHidden());
  assert(await page.locator('#connect-alchemy-chain-group').isVisible());
  assert.equal(await page.locator('#connect-alchemy-chain').inputValue(), '', 'the operator must explicitly choose a chain');
  assert.deepEqual(await page.locator('#connect-alchemy-chain option').evaluateAll(items => items.map(item => item.value)), ['', ...CHAINS]);
  assert(await page.locator('#connect-review').isDisabled());
  for (const id of ['connect-path', 'connect-response-mode', 'connect-response-fields',
    'connect-request-fields', 'connect-request-body-mode', 'connect-query-keys', 'connect-credential-input']) {
    assert(await page.locator('#' + id).isHidden(), id + ' hidden');
    assert(await page.locator('#' + id).isDisabled(), id + ' disabled');
  }
  assert(await page.locator('#connect-x-username-group').isHidden());
  await page.locator('#connect-alchemy-chain').selectOption(chain);
}
async function form(page, chain) { await pair(page); await chainForm(page, chain); }
async function recipe(page, chain = CHAINS[0], method = RPC[0]) {
  await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
  assert(await page.locator('#connect-setup-slot').isVisible()); assert(await page.locator('#alchemy-client-controls').isVisible());
  assert.deepEqual(await page.locator('#alchemy-client-method option').evaluateAll(items => items.map(item => item.value)), RPC);
  assert.equal(await page.locator('#alchemy-client-method').inputValue(), method);
  const text = await page.locator('#client-command').innerText();
  assert(text.includes(DUMMY)); assert(text.includes('SERVERWARE_PROXY_TOKEN'));
  assert(text.includes("--request 'POST'")); assert(text.includes(api(chain) + '/v2'));
  assert(!text.includes(api(CHAINS.find(item => item !== chain))));
  assert(text.includes(JSON.stringify({jsonrpc: '2.0', id: 1, method, params: []})));
  assert(text.includes("--header 'Content-Type: application/json'"));
  assert(text.includes('--cacert '), 'intercepted target TLS must use the trusted CA');
  assert(!/--insecure|--proxy-insecure|NODE_TLS_REJECT_UNAUTHORIZED|rejectUnauthorized:\s*false|verify\s*=\s*False/.test(text));
  assert(!text.includes(PRIVATE)); assert(!text.includes(APP_TOKEN));
  assert.match(await page.locator('#connect-activation').innerText(), /no upstream request has been tested here/);
  assert.match(await page.locator('#client-guidance').innerText(), /No Alchemy request was tested here/);
  assert.match(await page.locator('#client-guidance').innerText(), /HTTP 200 can contain an RPC error/);
  const source = 'https://github.com/AndrewMohawk/serverware/';
  const branch = 'serverware/operator-workspace/';
  const links = page.locator('#client-example-links a');
  assert.deepEqual(await links.evaluateAll(items => items.map(item => [item.textContent, item.getAttribute('href')])), [
    ['Node.js', source + 'tree/' + branch + 'examples/alchemy-chain-status-node'],
    ['Python', source + 'tree/' + branch + 'examples/alchemy-chain-status-python'],
    ['Go', source + 'tree/' + branch + 'examples/alchemy-chain-status-go'],
    ['GitHub Actions recipe (inactive)', source + 'blob/' + branch + 'examples/alchemy-chain-status-node/workflow.example.yml'],
    ['Alchemy preset scope and compatibility', source + 'blob/' + branch + 'docs/operator-provider-presets.md'],
  ]);
  for (const link of await links.all()) {
    assert.equal(await link.getAttribute('target'), '_blank');
    assert.equal(await link.getAttribute('rel'), 'noopener noreferrer');
    assert.equal(await link.getAttribute('referrerpolicy'), 'no-referrer');
    const url = new URL(await link.getAttribute('href'));
    assert.equal(url.origin, 'https://github.com'); assert.equal(url.username + url.password + url.search + url.hash, '');
    for (const privateValue of [PRIVATE, APP_TOKEN, IDS.application, IDS.credential, IDS.rule]) assert(!url.href.includes(privateValue));
  }
  const acceptance = 'Pinned Node.js, Python and Go examples passed isolated SDK-through-proxy checks. ' +
    'This page has not tested your Alchemy credentials or provider entitlement. ' +
    'The GitHub Actions recipe is inactive and has not been run.';
  assert.equal(await page.locator('#client-example-note').innerText(),
    'Public source only, separate from your private client config. ' + acceptance);
  assert((await page.locator('#client-guidance').innerText()).endsWith(acceptance));
  await privateAbsent(page); return text;
}
async function noAutomaticWrite(page, observed) {
  await page.locator('#mutation-review').waitFor({state: 'visible'});
  await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
  assert.equal(observed.grants.length, 1); assert(await page.locator('#connect-grant').isDisabled());
  assert(await page.locator('#connect-setup-step').isHidden());
  await refresh(page); assert.equal(observed.grants.length, 1);
  await page.reload({waitUntil: 'networkidle'}); await ready(page);
  assert.equal(observed.grants.length, 1, 'reload may inspect saved state but cannot replay a mutation');
}
async function screenshot(page, directory, name) {
  await page.screenshot({path: join(directory, name + '.png'), fullPage: true,
    mask: [page.locator('#client-token'), page.locator('#connect-alchemy-secret')]});
}

const tests = [
  ['key -> new app -> explicit chain -> review -> pending-null -> active, desktop/mobile', (browser, directory) => fixture(browser,
    {credentials: [], applications: [], autoLoad: false, holdCredential: true}, async (page, state, observed, controls) => {
      await keyForm(page); await page.locator('#connect-credential-next').click(); await controls.credentialArrived;
      assert.equal(await page.locator('#connect-alchemy-secret').inputValue(), ''); await privateAbsent(page);
      assert.equal(state.credentials.length, 0); assert.equal(observed.credentials.length, 1);
      controls.releaseCredential(); await step(page, 'application');
      assert.equal(state.rules.length, 0); assert.equal(state.applications.length, 0);
      await page.locator('#connect-application-choice').selectOption('new');
      await page.locator('#connect-application-name').fill('Chain status client'); await page.locator('#connect-token-ttl').selectOption('3600');
      await page.locator('#connect-application-next').click(); await step(page, 'access');
      assert.equal(observed.applications.length, 1); assert.equal(state.rules.length, 0);
      assert.equal(await page.locator('#client-token').inputValue(), APP_TOKEN);
      await chainForm(page); await review(page);
      const summary = await page.locator('#connect-review-details').innerText();
      assert(summary.includes(CHAINS[0])); assert(summary.includes(api(CHAINS[0]) + '/v2'));
      assert(summary.includes('eth_chainId') && summary.includes('eth_blockNumber')); assert.equal(observed.grants.length, 0);
      await screenshot(page, directory, 'alchemy-review-desktop'); await grant(page);
      assert.equal(observed.grants.length, 1); const savedRule = JSON.stringify(state.rules[0]); const savedRevision = state.revision;
      assert.equal(observed.catalogs.at(-1).alchemy, null, 'a prior loaded hash cannot advertise the new paired capability');
      assert.deepEqual(observed.catalogs.at(-1).ruleIds, [IDS.rule]); assert.notEqual(state.loaded, state.active);
      assert(await page.locator('#mutation-review').isHidden(), 'a saved but not loaded grant is not an uncertain mutation');
      assert(await page.locator('#connect-setup-slot').isHidden()); assert.match(await page.locator('#connect-activation').innerText(), /Waiting/);
      assert(await page.locator('#copy-command').isDisabled()); const pendingCount = observed.requests.length;
      await refresh(page); assert.equal(observed.catalogs.at(-1).alchemy, null);
      assert(await page.locator('#connect-setup-step').isVisible()); assert(await page.locator('#mutation-review').isHidden());
      state.loaded = state.active; await refresh(page); assert.deepEqual(observed.catalogs.at(-1).alchemy, capability());
      assert.equal(JSON.stringify(state.rules[0]), savedRule); assert.equal(state.revision, savedRevision);
      assert(observed.requests.slice(pendingCount).every(item => item.method === 'GET')); assert.equal(observed.grants.length, 1);
      const command = await recipe(page); await page.locator('#copy-command').click();
      assert.equal(await page.evaluate(() => navigator.clipboard.readText()), command);
      await screenshot(page, directory, 'alchemy-setup-desktop');
      await page.locator('#alchemy-client-method').selectOption(RPC[1]); await recipe(page, CHAINS[0], RPC[1]);
      await page.locator('#alchemy-proxy-ca-path').fill('/local/trusted-proxy-ca.pem');
      assert((await page.locator('#client-command').innerText()).includes("--proxy-cacert '/local/trusted-proxy-ca.pem'"));
      await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await screenshot(page, directory, 'alchemy-setup-mobile');
      assert.deepEqual(observed.credentials.map(item => item.expected_revision), [1]);
      assert.equal(observed.applications[0].expected_revision, 2); assert.equal(observed.grants[0].expected_revision, 3);
    })],
  ['no approved destination is explicit and selecting a provider never approves one', browser => fixture(browser,
    {credentials: [], applications: [], allowedUpstreams: [], capability: capability([])}, async (page, state, observed) => {
      await ready(page); await view(page, 'connect'); assert(await page.locator('#connect-use-alchemy').isDisabled());
      assert.match(await page.locator('#connect-alchemy-status').innerText(), /Proxy setup/);
      assert.equal(observed.credentials.length + observed.applications.length + observed.grants.length, 0);
      assert.deepEqual(state.allowedUpstreams, []); assert.equal(state.credentials.length + state.applications.length + state.rules.length, 0);
    })],
  ['only the explicitly approved Sepolia chain can be selected, including on mobile', (browser, directory) => fixture(browser,
    {allowedUpstreams: [api(CHAINS[1])], capability: capability([CHAINS[1]]), chain: CHAINS[1]}, async (page, state, observed) => {
      await page.setViewportSize({width: 390, height: 844}); await pair(page);
      const blocked = page.locator('#connect-alchemy-chain option[value="eth-mainnet"]');
      assert(await blocked.isDisabled()); assert.match(await blocked.innerText(), /destination not approved/);
      assert(!(await page.locator('#connect-alchemy-chain option[value="eth-sepolia"]').isDisabled()));
      await chainForm(page, CHAINS[1]); await review(page); await screenshot(page, directory, 'alchemy-sepolia-review-mobile');
      await grant(page); await recipe(page, CHAINS[1]); assert.equal(observed.grants[0].chain, CHAINS[1]);
      assert.deepEqual(state.allowedUpstreams, [api(CHAINS[1])]);
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    })],
  ['provider secret clears on method changes and navigation without submission', browser => fixture(browser,
    {credentials: [], applications: []}, async (page, state, observed) => {
      await keyForm(page); await page.locator('#connect-method-change').click();
      assert.equal(await page.locator('#connect-alchemy-secret').inputValue(), '');
      await page.locator('#connect-use-key').click(); assert(await page.locator('#connect-credential-secret').isVisible());
      assert(await page.locator('#connect-alchemy-secret').isHidden()); await page.locator('#connect-method-change').click();
      await page.locator('#connect-use-alchemy').click(); await page.locator('#connect-alchemy-secret').fill(PRIVATE);
      await view(page, 'overview'); assert.equal(await page.locator('#connect-alchemy-secret').inputValue(), '');
      assert.equal(observed.credentials.length + observed.applications.length + observed.grants.length, 0);
    })],
  ['failed key storage clears secret and does not expose private errors or retry', browser => fixture(browser,
    {credentials: [], applications: [], credentialFault: true}, async (page, state, observed) => {
      await keyForm(page); await page.locator('#connect-credential-next').click();
      await page.locator('#mutation-review').waitFor({state: 'visible'});
      await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
      assert.equal(await page.locator('#connect-alchemy-secret').inputValue(), ''); await privateAbsent(page);
      assert(await page.locator('#connect-credential-next').isDisabled()); await refresh(page);
      assert.equal(observed.credentials.length, 1); assert.equal(state.credentials.length, 0);
      await page.reload({waitUntil: 'networkidle'}); await ready(page); assert.equal(observed.credentials.length, 1);
    })],
  ['changed saved-key name or provider marker cannot advance the Alchemy checkpoint', async browser => {
    for (const change of [{name: 'Different saved name'}, {connection_type: 'x_app_bearer_v1', provider_id: 'x'}])
      await fixture(browser, {credentials: [], applications: [], credentialChange: change}, async (page, state, observed) => {
        await keyForm(page); await page.locator('#connect-credential-next').click();
        await page.locator('#mutation-review').waitFor({state: 'visible'});
        await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
        assert(await page.locator('#connect-application-step').isHidden());
        assert.equal(await page.locator('#connect-alchemy-secret').inputValue(), '');
        await refresh(page); assert.equal(observed.credentials.length, 1); assert.equal(observed.applications.length, 0);
      });
  }],
  ['missing or malformed closed capabilities never enable Alchemy', async browser => {
    const origin = clone(capability()); origin.chains[0].api_origin = 'https://arbitrary.example.test';
    const reordered = clone(capability()); reordered.chains.reverse();
    for (const value of [null, {...capability(), extra: true}, {...capability(), source_pair_required: false},
      {...capability(), rpc_methods: [...RPC, 'eth_sendRawTransaction']}, {...capability(), placeholder: 'Bearer wrong'}, origin, reordered])
      await fixture(browser, {capability: value}, async (page, state, observed) => {
        assert.equal(state.loaded, state.active); assert.deepEqual(observed.catalogs.at(-1).alchemy, value);
        await view(page, 'connect'); assert(await page.locator('#connect-use-alchemy').isDisabled());
        assert.equal(observed.credentials.length + observed.applications.length + observed.grants.length, 0);
      });
  }],
  ['an arbitrary chain injected into the DOM cannot become a grant', browser => fixture(browser, {}, async (page, state, observed) => {
    await form(page);
    await page.locator('#connect-alchemy-chain').evaluate(node => {
      const option = document.createElement('option'); option.value = 'https://arbitrary.example.test'; option.textContent = 'Unsupported test input';
      node.append(option); node.value = option.value; node.dispatchEvent(new Event('change', {bubbles: true}));
    });
    assert(await page.locator('#connect-review').isDisabled()); assert(await page.locator('#connect-review-step').isHidden());
    assert.equal(observed.grants.length, 0); await page.locator('#connect-alchemy-chain').selectOption(CHAINS[0]);
    await review(page); assert.equal(observed.grants.length, 0);
  })],
  ['destination, capability, revision, key and token changes invalidate review', async browser => {
    for (const change of [state => { state.allowedUpstreams = []; }, state => { state.alchemyCapability = capability([CHAINS[1]]); },
      state => { state.alchemyCapability = null; }, state => { state.credentials[0].status = 'revoked'; },
      state => { state.credentials[0].credential_generation++; return false; }, state => { state.applications[0].token_status = 'expired';
        state.applications[0].token_expires_at_epoch_ms = 1; }]) await fixture(browser, {}, async (page, state, observed) => {
        await form(page); await review(page);
        // A mismatched public generation must fail even if a malformed source
        // neglected to advance the catalog revision.
        if (change(state) !== false) state.revision++;
        await refresh(page); assert(await page.locator('#connect-grant').isDisabled()); assert.equal(observed.grants.length, 0);
      });
  }],
  ['unavailable selected chain is retained visibly and not silently replaced', browser => fixture(browser, {}, async (page, state, observed) => {
    await form(page); state.alchemyCapability = capability([CHAINS[1]]); state.allowedUpstreams = [api(CHAINS[1])]; state.revision++;
    await refresh(page); assert.equal(await page.locator('#connect-alchemy-chain').inputValue(), CHAINS[0]);
    assert(await page.locator('#connect-alchemy-chain option[value="eth-mainnet"]').isDisabled());
    assert(await page.locator('#connect-review').isDisabled()); assert.equal(observed.grants.length, 0);
  })],
  ['cross-provider public markers never inherit Alchemy access', async browser => {
    await fixture(browser, {credentials: [credential()]}, async (page, state, observed) => {
      await pair(page); assert.notEqual(await page.locator('#connect-operation').inputValue(), BUNDLE);
      assert(await page.locator('#connect-alchemy-chain-group').isHidden()); assert.equal(observed.grants.length, 0);
    });
    for (const changes of [{provider_id: 'x'}, {connection_type: 'x_app_bearer_v1'}, {auth_type: 'header', header_name: 'X-API-Key'}])
      await fixture(browser, {credentials: [alchemyCredential(changes)]}, async (page, state, observed) => {
        await page.locator('#load-error').waitFor({state: 'visible'}); await view(page, 'connect');
        assert(await page.locator('#connect-use-alchemy').isDisabled()); assert.equal(observed.grants.length, 0);
      });
  }],
  ['receipt for a different chain cannot be accepted as the reviewed grant', browser => fixture(browser,
    {ruleChange: {chain: CHAINS[1], upstream_url: api(CHAINS[1]) + '/v2'}}, async (page, state, observed) => {
      await form(page); await review(page); await page.locator('#connect-grant').click();
      await page.waitForFunction(() => !document.querySelector('#connect-status-refresh').disabled);
      assert.equal(observed.grants.length, 1); assert(await page.locator('#connect-setup-step').isHidden());
      assert(await page.locator('#connect-grant').isDisabled()); await refresh(page); assert.equal(observed.grants.length, 1);
    })],
  ['revoked saved permission hides setup and never creates a replacement', browser => fixture(browser,
    {rules: [alchemyRule()]}, async (page, state, observed) => {
      await pair(page); await page.locator('#connect-rule-choice').selectOption(IDS.rule); await review(page); await grant(page);
      await recipe(page); state.rules[0].status = 'revoked'; state.revision++; await refresh(page);
      assert(await page.locator('#connect-setup-slot').isHidden()); assert(await page.locator('#copy-command').isDisabled());
      assert.equal(observed.grants.length, 0);
    })],
  ['CAS refusal, storage uncertainty and a lost committed reply never replay POST', async browser => {
    for (const fault of ['409', '503', 'lost-after-commit']) await fixture(browser, {grantFault: fault}, async (page, state, observed) => {
      await form(page); await review(page); await page.locator('#connect-grant').click(); await noAutomaticWrite(page, observed);
      assert.equal(state.rules.length, fault === 'lost-after-commit' ? 1 : 0); await privateAbsent(page);
    });
  }],
  ['ordinary manual API-key flow remains independent', browser => ordinaryFixture(browser,
    supplied({credentials: [credential()], applications: [application()], responseModes: ['projected_json', 'unfiltered_json_or_empty_v2']}),
    async (page, state) => {
      await draft(page); assert(await page.locator('#connect-alchemy-chain-group').isHidden());
      assert.equal(await page.locator('#connect-operation').inputValue(), 'exact'); await review(page); await grant(page);
      assert.equal(state.posts.length, 1); assert.equal(state.posts[0].name, 'access-rules');
      assert.equal(state.posts[0].body.upstream_url, UPSTREAM + '/v1/status');
      assert(!Object.hasOwn(state.posts[0].body, 'operation_bundle')); assert.deepEqual(state.posts[0].body.response_fields, []);
    })],
  ['existing X saved flow and its accepted project links remain independent', browser => xFixture(browser,
    {rules: [xRule()]}, async (page, state, observed) => {
      await pair(page); await page.locator('#connect-rule-choice').selectOption(IDS.rule); await review(page); await grant(page);
      await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
      assert(await page.locator('#alchemy-client-controls').isHidden());
      assert((await page.locator('#client-command').innerText()).includes('serverware-x-placeholder-v1'));
      assert((await page.locator('#client-command').innerText()).includes('https://api.x.com/2/users/by/username/example_user'));
      assert.equal(await page.locator('#client-example-links a').count(), 5);
      assert.match(await page.locator('#client-example-note').innerText(), /passed isolated SDK-through-proxy checks/);
      assert.equal(observed.grants.length, 0);
    })],
];

async function hashes() {
  const names = ['scripts/test_operator_alchemy_browser.cjs', 'scripts/operator_alchemy_browser_fixture.cjs',
    'scripts/operator_x_browser_fixture.cjs', 'scripts/test_operator_catalog_browser.cjs', 'scripts/test_operator_ordinary_modes_browser.cjs',
    'serverware/operator_demo_portal.py', ...(await readdir(join(ROOT, 'serverware/operator_demo_web')))
      .filter(name => /\.(?:html|css|js)$/.test(name)).sort().map(name => 'serverware/operator_demo_web/' + name)];
  return Object.fromEntries(await Promise.all(names.map(async name =>
    [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
async function runSuite(browser) {
  assert(browser && typeof browser.newContext === 'function');
  const before = await hashes(); const directory = await mkdtemp('/tmp/serverware-alchemy-browser-');
  console.log(JSON.stringify({phase: 'source-before', hashes: before, artifactDirectory: directory}));
  const contexts = new Set(); let timer; let finished = false; let passed = 0;
  const bounded = {async newContext(...args) {
    assert(!finished); const context = await browser.newContext(...args);
    if (finished) { await context.close(); throw new Error('suite finished'); }
    contexts.add(context); context.on('close', () => contexts.delete(context)); return context;
  }};
  try {
    await Promise.race([(async () => { for (const [name, test] of tests) {
      await test(bounded, directory); passed++; console.log('PASS ' + name);
    } })(), new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('Alchemy rendered suite exceeded 180 seconds')), 180000); })]);
    const result = {ok: true, groups: passed, artifactDirectory: directory, backendAcceptance: false,
      sdkExecuted: false, providerRequests: 0, proxyRequests: 0, nativeDownloads: 0, generatedRecipeExecuted: false};
    console.log(JSON.stringify(result)); return result;
  } finally {
    finished = true; clearTimeout(timer); await Promise.all([...contexts].map(context => context.close()));
    assert.deepEqual(await hashes(), before, 'source changed during intercepted Alchemy suite');
    console.log(JSON.stringify({phase: 'source-after', sameSource: true, passed}));
  }
}
async function run(page) { return runSuite(page.context().browser()); }
async function main() {
  assert.equal(process.argv.length, 2, 'No live target or execution arguments accepted');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
  try { await runSuite(browser); } finally { await browser.close(); }
}
module.exports = {run, runSuite};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

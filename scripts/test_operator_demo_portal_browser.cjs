#!/usr/bin/env node
// Intercepted browser fixtures only: not a deployed proxy or real-provider test.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const origin = 'https://operator-ui.example.test';
const hash = 'sha256:' + 'a'.repeat(64);
const oldHash = 'sha256:' + 'b'.repeat(64);
const fakeProviderSecret = 'fixture-provider-secret-never-a-real-key';
const fakeClientToken = 'fixture-client-token-never-a-real-token';
const fixtureNow = Date.parse('2026-10-08T12:00:00Z');
const tokenLifetime = 24 * 60 * 60 * 1000;
const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const html = () => execFileSync(process.env.PYTHON || 'python3', ['-B', '-c',
  'from serverware.operator_demo_portal import render; print(render())'], {cwd: root, encoding: 'utf8'});
const response = (body, status = 200) => ({status, contentType: 'application/json', body: JSON.stringify(body)});
const connection = (overrides = {}) => ({id: 'fixture-connection', name: 'My API', upstream_url: 'https://api.example.test/v1/example',
  methods: ['GET'], auth_type: 'bearer', header_name: 'Authorization', credential_id: 'fixture-credential',
  principal_id: 'fixture-client', created_at: '2026-10-08T12:00:00Z', token_expires_at_epoch_ms: fixtureNow + tokenLifetime,
  request_fields: [], response_fields: ['id', 'status'], query_keys: [], allowed_headers: ['accept', 'user-agent'],
  policy_hash: hash, activation: 'active', client_status: 'ready', ...overrides});

async function fixture(browser, options, run) {
  const context = await browser.newContext({viewport: {width: 1280, height: 900}, serviceWorkers: 'block',
    permissions: ['clipboard-read', 'clipboard-write']});
  const page = await context.newPage(); page.setDefaultTimeout(5000);
  // Synthetic browser time makes exact token deadlines independent of wall time.
  const now = new Date(options.now ?? fixtureNow);
  await page.clock.install({time: now}); await page.clock.pauseAt(now);
  const state = {connections: options.connections || [], loaded: options.loaded ?? hash, posts: [], requests: [], errors: [], unexpected: [], statusCalls: 0};
  page.on('pageerror', error => state.errors.push(error.message));
  const document = html();
  await context.route('**/*', async route => {
    const request = route.request(); const url = new URL(request.url());
    state.requests.push({path: url.pathname, search: url.search, method: request.method()});
    if (url.origin !== origin) { state.unexpected.push('external network request'); return route.abort(); }
    if (url.pathname === '/') return route.fulfill({status: 200, contentType: 'text/html', body: document});
    if (url.pathname === '/favicon.ico') return route.fulfill({status: 204, body: ''});
    const override = await options.override?.(url, request, state);
    if (override) return route.fulfill(override);
    if (url.pathname === '/api/operator-demo/status') {
      state.statusCalls++;
      return route.fulfill(response({mode: 'operator-development', syntheticOnly: false, productionReady: false,
        hardwareVerified: false, proxy_url: 'https://serverware-proxy.example.test',
        allowed_upstreams: ['https://api.example.test'], connections: state.connections.map(item => ({...item,
          activation: state.loaded === hash ? 'active' : 'pending',
          client_status: state.loaded === hash ? item.client_status : 'pending'})), active_policy_hash: hash, loaded_policy_hash: state.loaded}));
    }
    if (url.pathname === '/api/operator-demo/connections' && request.method() === 'POST') {
      const body = request.postDataJSON(); state.posts.push(body);
      const saved = {...connection({token_expires_at_epoch_ms: options.createdExpiry ?? fixtureNow + tokenLifetime}),
        ...Object.fromEntries(Object.entries(body).filter(([key]) => key !== 'secret'))};
      state.connections.push(saved);
      return route.fulfill(response({connection: saved, client_token: fakeClientToken, policy_hash: hash,
        activation: 'active', client_status: saved.client_status}, 201));
    }
    if (url.pathname === '/api/audit/search') return route.fulfill(response({ok: true, complete: true, has_more: false,
      next_cursor: null, items: [{id: 'fixture-event', created_at: '2026-10-08T12:00:00Z',
        event_type: url.searchParams.get('eventType') || 'data_plane.response.released', event: {route_id: 'fixture-route', status: 200}}]}));
    if (url.pathname === '/api/audit/verify') return route.fulfill(response({ok: true, complete: true}));
    if (url.pathname === '/ca.pem') return route.fulfill({status: 503, contentType: 'text/plain', body: 'No real CA in UI-only fixture'});
    state.unexpected.push(url.pathname); return route.fulfill(response({detail: 'No fixture'}, 404));
  });
  try {
    await page.goto(origin + '/' + (options.hash || ''), {waitUntil: 'domcontentloaded'});
    await run(page, state);
    assert.deepEqual(state.errors, []); assert.deepEqual(state.unexpected, []);
    assert(state.requests.every(item => item.method === 'GET' || item.path === '/api/operator-demo/connections' && item.method === 'POST'));
  } finally { await context.unrouteAll({behavior: 'wait'}); await context.close(); }
}
async function ready(page) { await page.waitForFunction(() => !document.querySelector('#connection-fields').disabled); }
async function fill(page, custom = false) {
  await ready(page); await page.locator('nav a[href="#credentials"]').click();
  await page.locator('#connection-name').fill('My API');
  await page.locator('#upstream-path').fill('/v1/example');
  if (custom) { await page.locator('#auth-type').selectOption('header'); await page.locator('#header-name').fill('X-API-Key'); }
  await page.locator('#provider-secret').fill(fakeProviderSecret);
  await page.locator('#response-fields').fill('id\nstatus');
}
async function statusText(page, selector, value) { await page.waitForFunction(({selector, value}) => document.querySelector(selector).textContent.includes(value), {selector, value}); }
async function noClientActions(page) {
  for (const id of ['copy-command', 'download-config']) assert(await page.locator('#' + id).isDisabled(), id);
}
async function noTokenActions(page) {
  assert.equal(await page.locator('#client-token').inputValue(), '');
  for (const id of ['reveal-token', 'copy-token', 'dismiss-token']) assert(await page.locator('#' + id).isDisabled(), id);
  assert(await page.locator('#one-time-access').isHidden());
}

const tests = [
  ...methods.map(method => ['pure cURL generator supports ' + method, async () => {
    const {buildCurlCommand} = require(path.join(root, 'serverware/operator_demo_web/app.js'));
    const command = buildCurlCommand({proxyUrl: 'https://proxy.example.test', upstreamUrl: 'https://api.example.test/item',
      method, caPath: "./CA's certificate.pem"});
    assert(command.includes(`--request '${method}'`));
    assert(command.includes("--cacert './CA'\\''s certificate.pem'"));
    assert(command.includes('--proxy-header "Proxy-Authorization: Bearer $SERVERWARE_PROXY_TOKEN"'));
    assert(!command.includes('--insecure')); assert(!command.includes('--proxy-insecure'));
  }]),
  ['pure cURL generator refuses HEAD and unknown methods', async () => {
    const {buildCurlCommand} = require(path.join(root, 'serverware/operator_demo_web/app.js'));
    for (const method of ['HEAD', 'TRACE', '', 'get']) assert.throws(() => buildCurlCommand({
      proxyUrl: 'https://proxy.example.test', upstreamUrl: 'https://api.example.test/item', method}));
  }],
  ['bearer form, one-time token, active client example and private download', browser => fixture(browser, {}, async (page, state) => {
    await fill(page); await page.locator('#add-connection').click();
    await page.locator('#one-time-access').waitFor({state: 'visible'});
    assert.equal(await page.locator('#provider-secret').inputValue(), '');
    assert.equal(await page.locator('#client-token').getAttribute('type'), 'password');
    assert.equal(await page.locator('#client-token').inputValue(), fakeClientToken);
    assert.equal(state.posts.length, 1);
    assert.deepEqual(state.posts[0], {name: 'My API', upstream_url: 'https://api.example.test/v1/example', methods: ['GET'],
      auth_type: 'bearer', header_name: 'Authorization', secret: fakeProviderSecret, response_fields: ['id', 'status'],
      request_fields: [], query_keys: [], allowed_headers: ['accept', 'user-agent']});
    assert.equal(await page.evaluate(() => localStorage.length + sessionStorage.length), 0);
    assert(!(await page.locator('body').innerText()).includes(fakeProviderSecret));
    await page.locator('#copy-token').click();
    await statusText(page, '#token-status', 'Copied');
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), fakeClientToken);
    await page.locator('nav a[href="#proxy"]').click();
    await page.waitForFunction(() => !document.querySelector('#download-config').disabled);
    const command = await page.locator('#client-command').innerText();
    assert(command.includes('--proxy \'https://serverware-proxy.example.test\''));
    assert(command.includes('$SERVERWARE_PROXY_TOKEN')); assert(command.includes('--cacert'));
    assert(!command.includes(fakeClientToken)); assert(!command.includes(fakeProviderSecret));
    assert(!command.includes('--insecure')); assert(!command.includes('decision-gate-rs'));
    const downloadEvent = page.waitForEvent('download'); await page.locator('#download-config').click();
    const download = await downloadEvent; assert.equal(download.suggestedFilename(), 'serverware-client.private.json');
    const stream = await download.createReadStream(); const chunks = []; for await (const chunk of stream) chunks.push(chunk);
    const config = JSON.parse(Buffer.concat(chunks).toString());
    assert.equal(config.proxy_authorization, 'Bearer ' + fakeClientToken); assert(!JSON.stringify(config).includes(fakeProviderSecret));
    await download.delete();
    await page.reload(); await ready(page);
    assert(await page.locator('#one-time-access').isHidden()); assert.equal(await page.locator('#client-token').inputValue(), '');
    assert(await page.locator('#download-config').isDisabled());
  })],
  ['pending POST cannot claim active until loaded hash matches', browser => fixture(browser, {loaded: oldHash}, async (page, state) => {
    await fill(page); await page.locator('#add-connection').click();
    await page.locator('#one-time-access').waitFor({state: 'visible'});
    await statusText(page, '#connections-list', 'Pending activation');
    await page.locator('nav a[href="#proxy"]').click();
    assert(await page.locator('#copy-command').isDisabled()); assert(await page.locator('#download-config').isDisabled());
    state.loaded = hash; await page.locator('#proxy-refresh').click();
    await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
    await statusText(page, '#activation-status', 'Active:');
  })],
  ['custom header and advanced constraints submit exactly', browser => fixture(browser, {}, async (page, state) => {
    await fill(page, true); await page.locator('input[name="method"][value="POST"]').check();
    await page.locator('#connection-form summary').click();
    await page.locator('#request-fields').fill('message\nmessage'); await page.locator('#query-keys').fill('version');
    await page.locator('#allowed-headers').fill('accept\nuser-agent');
    await page.locator('#add-connection').click(); await page.locator('#one-time-access').waitFor({state: 'visible'});
    assert.equal(state.posts[0].auth_type, 'header'); assert.equal(state.posts[0].header_name, 'X-API-Key');
    assert.deepEqual(state.posts[0].methods, ['GET', 'POST']); assert.deepEqual(state.posts[0].request_fields, ['message']);
    assert.deepEqual(state.posts[0].query_keys, ['version']); assert.deepEqual(state.posts[0].allowed_headers, ['accept', 'user-agent']);
    await page.locator('nav a[href="#proxy"]').click();
    await statusText(page, '#client-guidance', 'do not add Content-Type');
  })],
  ['validation failure clears provider secret and does not echo server details', browser => fixture(browser, {
    override: (url, request) => url.pathname === '/api/operator-demo/connections' ? response({detail: fakeProviderSecret}, 422) : null,
  }, async page => {
    await fill(page); await page.locator('#add-connection').click(); await statusText(page, '#form-status', 'server rejected');
    assert.equal(await page.locator('#provider-secret').inputValue(), ''); assert(!(await page.locator('body').innerText()).includes(fakeProviderSecret));
    assert(await page.locator('#one-time-access').isHidden());
  })],
  ['session failure disables mutations', browser => fixture(browser, {
    override: url => url.pathname === '/api/operator-demo/status' ? response({detail: 'Denied'}, 401) : null,
  }, async page => {
    await page.locator('#load-error').waitFor({state: 'visible'}); await statusText(page, '#load-error-text', 'sign in again');
    assert(await page.locator('#add-connection').isDisabled());
  })],
  ['invalid paths and empty method set do not submit', browser => fixture(browser, {}, async (page, state) => {
    await fill(page); await page.locator('#upstream-path').fill('//elsewhere.example/path'); await page.locator('#add-connection').click();
    await statusText(page, '#form-status', 'exact path'); assert.equal(state.posts.length, 0);
    await page.locator('#upstream-path').fill('/v1/example'); await page.locator('input[name="method"][value="GET"]').uncheck();
    await page.locator('#add-connection').click(); assert.equal(state.posts.length, 0);
  })],
  ['form offers the JSON method matrix and refuses injected HEAD selection', browser => fixture(browser, {}, async (page, state) => {
    await fill(page);
    assert.deepEqual(await page.locator('input[name="method"]').evaluateAll(items => items.map(item => item.value)), methods);
    await page.locator('input[name="method"][value="GET"]').uncheck();
    await page.locator('input[name="method"][value="OPTIONS"]').check();
    await page.locator('#add-connection').click(); await page.locator('#one-time-access').waitFor({state: 'visible'});
    assert.deepEqual(state.posts[0].methods, ['OPTIONS']);
    await fill(page);
    await page.locator('input[name="method"][value="OPTIONS"]').uncheck();
    await page.locator('.method-options').evaluate(element => {
      const input = document.createElement('input'); input.type = 'checkbox'; input.name = 'method'; input.value = 'HEAD'; input.checked = true; element.append(input);
    });
    await page.locator('#add-connection').click(); assert.equal(state.posts.length, 1);
  })],
  ['unsupported saved method is isolated from valid clients and the workspace', browser => fixture(browser, {
    connections: [connection({id: 'unsupported-client', methods: ['HEAD']}), connection({id: 'supported-client', name: 'Supported client'})],
  }, async page => {
    await ready(page); assert(await page.locator('#load-error').isHidden());
    await page.locator('nav a[href="#proxy"]').click();
    await statusText(page, '#client-command', 'Unsupported saved method'); await noClientActions(page);
    await page.locator('#client-connection').selectOption('supported-client');
    assert(await page.locator('#copy-command').isEnabled());
    assert((await page.locator('#client-command').innerText()).includes("--request 'GET'"));
    await page.locator('nav a[href="#audit"]').click(); await statusText(page, '#audit-status', 'End of matching history');
    assert(await page.locator('#load-error').isHidden());
  })],
  ['ready client becomes expired at the exact deadline without network refresh', browser => fixture(browser, {
    connections: [connection({token_expires_at_epoch_ms: fixtureNow + 1})], hash: '#proxy',
  }, async (page, state) => {
    await ready(page); assert(await page.locator('#copy-command').isEnabled());
    const requests = state.requests.length;
    await page.clock.runFor(1);
    await noClientActions(page); await statusText(page, '#connections-list', 'Token expired');
    await statusText(page, '#activation-status', 'Active:');
    assert.equal(state.requests.length, requests, 'expiry should not depend on another status request');
  })],
  ['already-expired client cannot become ready from an active policy or stale ready field', browser => fixture(browser, {
    connections: [connection({token_expires_at_epoch_ms: fixtureNow})], hash: '#proxy',
  }, async page => {
    await ready(page); await noClientActions(page); await statusText(page, '#connections-list', 'Token expired');
    await statusText(page, '#activation-status', 'Active:'); assert(await page.locator('#load-error').isHidden());
  })],
  ...['expired', 'pending'].map(clientStatus => ['backend client_status ' + clientStatus + ' is not usable despite active policy', browser => fixture(browser, {
    connections: [connection({client_status: clientStatus})], hash: '#proxy',
  }, async page => {
    await ready(page); await noClientActions(page); await statusText(page, '#activation-status', 'Active:');
    assert(await page.locator('#load-error').isHidden());
  })]),
  ['open-page expiry clears the held one-time token and cannot restore it from metadata', browser => fixture(browser, {
    createdExpiry: fixtureNow + 1000,
  }, async (page, state) => {
    await fill(page); await page.locator('#add-connection').click(); await page.locator('#one-time-access').waitFor({state: 'visible'});
    await page.locator('nav a[href="#proxy"]').click();
    await page.waitForFunction(() => !document.querySelector('#download-config').disabled);
    await page.clock.runFor(999);
    assert(await page.locator('#download-config').isEnabled());
    assert.equal(await page.locator('#client-token').inputValue(), fakeClientToken);
    const requests = state.requests.length;
    await page.clock.runFor(1);
    await noClientActions(page); await noTokenActions(page);
    assert.equal(state.requests.length, requests);
    // Metadata alone can never restore the token after the local expiry clears it.
    state.connections[0].token_expires_at_epoch_ms = fixtureNow + tokenLifetime;
    await page.locator('#proxy-refresh').click();
    await page.waitForFunction(() => !document.querySelector('#copy-command').disabled);
    assert(await page.locator('#download-config').isDisabled()); await noTokenActions(page);
  })],
  ['held-token expiry still clears private controls after a failed status refresh', browser => fixture(browser, {
    createdExpiry: fixtureNow + 1000,
    override: (url, request, state) => url.pathname === '/api/operator-demo/status' && state.statusCalls > 1
      ? response({detail: 'Unavailable'}, 503) : null,
  }, async page => {
    await fill(page); await page.locator('#add-connection').click(); await page.locator('#one-time-access').waitFor({state: 'visible'});
    await page.locator('nav a[href="#proxy"]').click();
    await page.waitForFunction(() => !document.querySelector('#download-config').disabled);
    await page.locator('#proxy-refresh').click(); await page.locator('#load-error').waitFor({state: 'visible'});
    await page.clock.runFor(1000);
    await noClientActions(page); await noTokenActions(page);
  })],
  ...['reveal-token', 'copy-token', 'copy-command', 'download-config'].map(action => [
    action + ' rechecks expiry when the scheduled timer has not run', browser => fixture(browser, {
      createdExpiry: fixtureNow + 1000,
    }, async page => {
      await fill(page); await page.locator('#add-connection').click(); await page.locator('#one-time-access').waitFor({state: 'visible'});
      if (action === 'copy-command' || action === 'download-config') {
        await page.locator('nav a[href="#proxy"]').click();
        await page.waitForFunction(() => !document.querySelector('#download-config').disabled);
      }
      assert(await page.locator('#' + action).isEnabled());
      await page.evaluate(() => navigator.clipboard.writeText('unchanged-expiry-fixture'));
      let downloads = 0; page.on('download', () => downloads++);
      // Move wall time only: simulate an overdue/background-throttled timer.
      await page.clock.setSystemTime(new Date(fixtureNow + 1000));
      await page.locator('#' + action).click();
      await noClientActions(page); await noTokenActions(page);
      assert.equal(await page.evaluate(() => navigator.clipboard.readText()), 'unchanged-expiry-fixture');
      assert.equal(downloads, 0);
    }),
  ]),
  ['audit filter/search and complete verification', browser => fixture(browser, {}, async (page, state) => {
    await ready(page); await page.locator('nav a[href="#audit"]').click(); await statusText(page, '#audit-status', 'End of matching history');
    await page.locator('#audit-filter').selectOption('data_plane.response.blocked');
    await page.locator('#audit-query').fill('fixture-route'); await page.locator('#audit-search-form button').click();
    await statusText(page, '#audit-status', 'End of matching history');
    assert(state.requests.some(item => item.path === '/api/audit/search' && item.search.includes('eventType=data_plane.response.blocked') && item.search.includes('q=fixture-route')));
    await page.locator('#audit-verify').click(); await statusText(page, '#audit-verification', 'complete local audit chain');
  })],
  ['partial audit verification is not presented as complete', browser => fixture(browser, {
    override: url => url.pathname === '/api/audit/verify' ? response({ok: true, complete: false}) : null,
  }, async page => {
    await ready(page); await page.locator('nav a[href="#audit"]').click();
    await page.locator('#audit-verify').click(); await statusText(page, '#audit-verification', 'Incomplete verification');
  })],
  ['status failure removes stale active claims and disables client actions', browser => fixture(browser, {
    connections: [connection()], override: (url, request, state) =>
      url.pathname === '/api/operator-demo/status' && state.statusCalls > 0 ? response({detail: 'Unavailable'}, 503) : null,
  }, async page => {
    await ready(page); await page.locator('nav a[href="#proxy"]').click();
    assert(await page.locator('#copy-command').isEnabled()); await page.locator('#proxy-refresh').click();
    await page.locator('#load-error').waitFor({state: 'visible'});
    assert(await page.locator('#copy-command').isDisabled());
    await statusText(page, '#activation-status', 'Activation unknown');
    assert.equal(await page.locator('#connections-list .badge.active').count(), 0);
  })],
  ['untrusted metadata is text, all mobile views fit and invalid hashes fall back', browser => fixture(browser, {
    hash: '#constructor', connections: [{...connection(), name: '<img src=x onerror=alert(1)>'}],
  }, async page => {
    await ready(page); assert(await page.locator('#overview').isVisible());
    await page.setViewportSize({width: 390, height: 844});
    for (const view of ['credentials', 'proxy', 'audit', 'overview']) {
      await page.locator(`nav a[href="#${view}"]`).click(); await page.locator('#' + view).waitFor({state: 'visible'});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'mobile horizontal overflow: ' + view);
    }
    assert.equal(await page.locator('#connections-list img').count(), 0);
    await page.evaluate(() => { location.hash = '#toString'; }); await page.locator('#overview').waitFor({state: 'visible'});
    assert.equal(new URL(page.url()).hash, '#overview');
    assert.equal(await page.locator('#ca-download').getAttribute('href'), '/ca.pem');
  })],
];

async function runSuite(browser) {
  const results = [];
  for (const [name, run] of tests) {
    try { await run(browser); } catch (error) { throw new Error(name + ': ' + error.message, {cause: error}); }
    results.push({name, passed: true});
  }
  return {scope: 'Intercepted UI fixtures only; no deployed proxy acceptance', tests: results.length, results};
}
module.exports = {runSuite};
if (require.main === module) (async () => {
  const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox']});
  try { console.log(JSON.stringify(await runSuite(browser), null, 2)); } finally { await browser.close(); }
})().catch(error => { console.error(error.stack); process.exitCode = 1; });

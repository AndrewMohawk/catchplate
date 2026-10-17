#!/usr/bin/env node
// Deterministic UI controls only. Every network request is intercepted below;
// this suite has no service tokens, live Docker calls or production acceptance claims.
const assert = require('node:assert/strict');
const {execFileSync} = require('node:child_process');
const {readFileSync} = require('node:fs');
const path = require('node:path');
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const root = path.resolve(__dirname, '..');
const origin = 'https://sandbox-ui.example.test';
const html = execFileSync(process.env.PYTHON || 'python3', ['-B', '-c',
  'from catchplate.sandbox_portal import render; print(render())'], {cwd: root, encoding: 'utf8'});
const policy = JSON.parse(readFileSync(path.join(root, 'policies/demo.policy.json'), 'utf8'));
const checkNames = [
  'synthetic_profile_and_exact_rust_build',
  'connect_identity_and_destination_denials',
  'caller_credential_collision_denied_without_dispatch',
  'connect_tls_credential_injection_and_header_redaction',
  'route_denials_without_upstream_dispatch',
  'credential_reflection_blocked',
  'unsupported_streaming_transform_denied_without_dispatch',
  'stored_correlated_audit_without_credential_material',
];
const released = {id: 'fixture-allowed', created_at: '2026-01-01T00:00:01Z',
  event_type: 'data_plane.response.released', event: {principal_id: 'agent:demo', route_id: 'demo.echo', status: 200}};
const blocked = {id: 'fixture-blocked', created_at: '2026-01-01T00:00:02Z',
  event_type: 'data_plane.response.blocked', event: {principal_id: 'agent:demo', route_id: 'demo.echo',
    response_validation: {error: 'response_credential_reflection'}, status: 502}};

function json(body, status = 200) {
  return {status, contentType: 'application/json', body: JSON.stringify(body)};
}

function defaultResponse(url, state) {
  switch (url.pathname) {
    case '/api/auth/status': return json({authenticated: true, userId: 'sandbox-test-operator',
      authMethod: 'sandbox-header', developmentSandbox: true, roles: ['admin']});
    case '/api/sandbox/status': return json({schema: 'catchplate.developmentSandbox/v1',
      mode: 'synthetic-development', syntheticOnly: true, productionReady: false, hardwareVerified: false,
      persistent: true, allowedUpstreams: ['demo-upstream'], commissioningRequired: false});
    case '/api/bootstrap': return json({credentials: [{id: 'cred-demo-bearer', name: 'Demo bearer token',
      kind: 'bearer', version: 1, metadata: {provider: 'demo'}}], routes: [], ca_ready: true});
    case '/api/policy': return json({ready: true, policy_hash: 'sha256:' + 'a'.repeat(64), bundle: policy});
    case '/api/sandbox/check': return json({ok: true, syntheticOnly: true, checks: checkNames,
      unsupportedFeatures: ['transforming request streams (including nested JSON)']});
    case '/api/audit/search': {
      const eventType = url.searchParams.get('eventType');
      const items = eventType === blocked.event_type ? [blocked] : eventType === released.event_type ? [released] : [blocked, released];
      return json({ok: true, items, count: items.length, scanned: items.length,
        total_candidates: items.length, complete: true, has_more: false, next_cursor: null});
    }
    case '/api/audit/verify': return json({ok: true, complete: true, count: 2, total: 2});
    case '/ca.pem': return {status: 503, contentType: 'text/plain', body: 'Certificate fixture unavailable'};
    default: state.unexpected.push(url.pathname); return json({detail: 'No test fixture for route'}, 404);
  }
}

async function fixture(browser, options, run) {
  const context = await browser.newContext({viewport: {width: 1280, height: 900}, serviceWorkers: 'block'});
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  const state = {requests: [], unexpected: [], errors: [], checkCount: 0};
  page.on('pageerror', error => state.errors.push(error.message));
  await context.route('**/*', async route => {
    const request = route.request();
    const url = new URL(request.url());
    state.requests.push({path: url.pathname, query: url.search, method: request.method()});
    if (url.origin !== origin) {
      state.unexpected.push('external origin');
      return route.abort();
    }
    if (url.pathname === '/') return route.fulfill({status: 200, contentType: 'text/html', body: html});
    if (url.pathname === '/favicon.ico') return route.fulfill({status: 204, body: ''});
    if (url.pathname === '/api/sandbox/check') state.checkCount++;
    const response = await options.override?.(url, state);
    return route.fulfill(response || defaultResponse(url, state));
  });
  try {
    await page.goto(origin + '/' + (options.hash || ''), {waitUntil: 'domcontentloaded'});
    await run(page, state);
    assert.deepEqual(state.errors, [], 'unexpected browser JavaScript errors');
    assert.deepEqual(state.unexpected, [], 'browser requested an unmocked resource');
    assert(state.requests.every(request => request.method === 'GET' ||
      request.path === '/api/sandbox/check' && request.method === 'POST'), 'unexpected mutation request');
  } finally {
    options.cleanup?.();
    await context.unrouteAll({behavior: 'wait'});
    await context.close();
  }
}

async function ready(page) {
  await page.waitForFunction(() => !document.getElementById('sandbox-run-check').disabled);
}

async function textMatches(page, selector, expression) {
  await page.waitForFunction(({selector, source, flags}) => new RegExp(source, flags).test(
    document.querySelector(selector)?.textContent || ''), {selector, source: expression.source, flags: expression.flags});
}

const tests = [];

tests.push(['task navigation and invalid-hash fallback', browser => fixture(browser, {hash: '#not-a-page'}, async page => {
  await ready(page);
  assert(await page.locator('#overview').isVisible());
  assert.equal(await page.locator('nav [aria-current="page"]').getAttribute('href'), '#overview');
  await page.locator('nav a[href="#credentials"]').click();
  await page.locator('#credentials').waitFor({state: 'visible'});
  assert(await page.locator('#overview').isHidden());
  await textMatches(page, '#credentials-list', /Demo bearer token/);
  await page.locator('nav a[href="#access"]').click();
  await page.locator('#access').waitFor({state: 'visible'});
  await textMatches(page, '#demo-rule', /demo-upstream/);
  await page.evaluate(() => {location.hash = '#another-missing-page';});
  await page.locator('#overview').waitFor({state: 'visible'});
  assert.equal(await page.locator('nav [aria-current="page"]').getAttribute('href'), '#overview');
})]);

for (const hash of ['#constructor', '#toString']) {
  tests.push([`inherited property hash ${hash} safely falls back to Overview`, browser =>
    fixture(browser, {hash}, async page => {
      await ready(page);
      assert.equal(new URL(page.url()).hash, '#overview');
      assert.equal(await page.title(), 'Overview - Catchplate');
      assert(await page.locator('#overview').isVisible());
      assert.equal(await page.locator('.page:visible').count(), 1);
      assert.equal(await page.locator('nav [aria-current="page"]').getAttribute('href'), '#overview');
      // Initial navigation and hashchange use the same guard; exercise both.
      await page.locator('nav a[href="#credentials"]').click();
      await page.locator('#credentials').waitFor({state: 'visible'});
      await page.evaluate(value => {location.hash = value;}, hash);
      await page.locator('#overview').waitFor({state: 'visible'});
      assert.equal(new URL(page.url()).hash, '#overview');
      assert.equal(await page.locator('.page:visible').count(), 1);
      assert.equal(await page.locator('nav [aria-current="page"]').getAttribute('href'), '#overview');
      assert(await page.locator('#load-error').isHidden());
    })]);
}

tests.push(['workspace API failure is visible and retry recovers', async browser => {
  let fail = true;
  await fixture(browser, {override: url => url.pathname === '/api/bootstrap' && fail ?
    json({detail: 'Synthetic workspace unavailable'}, 503) : null}, async page => {
    await page.locator('#load-error').waitFor({state: 'visible'});
    assert(await page.locator('#sandbox-run-check').isDisabled());
    assert((await page.locator('#load-error-text').textContent()).trim().length > 0);
    fail = false;
    await page.locator('#retry-load').click();
    await ready(page);
    assert(await page.locator('#load-error').isHidden());
  });
}]);

tests.push(['expired JSON session cannot run a check', browser => fixture(browser, {
  override: url => url.pathname === '/api/auth/status' ? json({detail: 'Authentication required'}, 401) : null,
}, async (page, state) => {
  await page.locator('#load-error').waitFor({state: 'visible'});
  await textMatches(page, '#load-error', /sign.in|session|auth/i);
  assert(await page.locator('#sandbox-run-check').isDisabled());
  assert.equal(state.checkCount, 0);
})]);

tests.push(['HTML sign-in response cannot masquerade as JSON success', browser => fixture(browser, {
  override: url => url.pathname === '/api/auth/status' ?
    {status: 200, contentType: 'text/html', body: '<!doctype html><title>Sign in</title><p>Session expired</p>'} : null,
}, async (page, state) => {
  await page.locator('#load-error').waitFor({state: 'visible'});
  await textMatches(page, '#load-error', /sign.in|session|reload/i);
  assert(await page.locator('#sandbox-run-check').isDisabled());
  assert.equal(state.checkCount, 0);
})]);

tests.push(['failed check with partial results is not an overall pass', browser => fixture(browser, {
  override: url => url.pathname === '/api/sandbox/check' ?
    json({ok: false, error: 'Synthetic upstream unavailable', checks: checkNames.slice(0, 4)}, 503) : null,
}, async page => {
  await ready(page);
  await page.locator('#sandbox-run-check').click();
  await textMatches(page, '#sandbox-check-result', /failed|unable|error/i);
  assert.doesNotMatch(await page.locator('#sandbox-check-result').textContent(), /^\s*(Passed|Demo passed|All .*passed)/i);
  assert.doesNotMatch(await page.locator('#demo-results').textContent(), /4 passed|4 checks passed/i);
  assert(await page.locator('#sandbox-run-check').isEnabled());
})]);

tests.push(['busy check suppresses duplicate dispatch and recovers', async browser => {
  let release;
  const held = new Promise(resolve => {release = resolve;});
  try {
    await fixture(browser, {cleanup: release, override: async url => {
      if (url.pathname === '/api/sandbox/check') await held;
      return null;
    }}, async (page, state) => {
      await ready(page);
      const started = page.waitForRequest(request => new URL(request.url()).pathname === '/api/sandbox/check');
      await page.locator('#sandbox-run-check').click();
      await started;
      assert(await page.locator('#sandbox-run-check').isDisabled());
      // Deliberate duplicate DOM dispatch exercises the handler's in-flight
      // guard, not only the browser's disabled-button interaction behavior.
      await page.evaluate(() => {
        const button = document.getElementById('sandbox-run-check');
        button.dispatchEvent(new Event('click'));
        button.dispatchEvent(new Event('click'));
      });
      release();
      await textMatches(page, '#sandbox-check-result', /passed|complete/i);
      assert.equal(state.checkCount, 1);
      assert(await page.locator('#sandbox-run-check').isEnabled());
    });
  } finally { release(); }
}]);

tests.push(['CA failure is visible and never displays a fingerprint', browser => fixture(browser, {}, async page => {
  await ready(page);
  await page.locator('nav a[href="#proxy"]').click();
  await textMatches(page, '#ca-error', /unavailable|failed|error|503/i);
  assert.doesNotMatch(await page.locator('#ca-fingerprint').textContent(), /(?:[A-Fa-f0-9]{2}:){31}[A-Fa-f0-9]{2}|[A-Fa-f0-9]{64}/);
  assert.equal(await page.locator('#ca-download').getAttribute('href'), '/ca.pem');
})]);

tests.push(['blocked audit filter and incomplete verification remain honest', browser => fixture(browser, {
  override: url => url.pathname === '/api/audit/verify' ? json({ok: true, complete: false, count: 1, total: 2}) : null,
}, async (page, state) => {
  await ready(page);
  await page.locator('nav a[href="#audit"]').click();
  await textMatches(page, '#audit-list', /blocked/i);
  const filtered = page.waitForResponse(response => {
    const url = new URL(response.url());
    return url.pathname === '/api/audit/search' && url.searchParams.get('eventType') === blocked.event_type;
  });
  await page.locator('#audit-filter').selectOption('blocked');
  await filtered;
  await page.locator('[data-event-id="fixture-allowed"]').waitFor({state: 'detached'});
  await textMatches(page, '#audit-list', /blocked/i);
  assert.doesNotMatch(await page.locator('#audit-list').textContent(), /fixture-allowed|Allowed response/i);
  assert(state.requests.some(request => request.path === '/api/audit/search' &&
    new URLSearchParams(request.query).get('eventType') === blocked.event_type));
  await page.locator('#audit-verify').click();
  await textMatches(page, '#audit-verification', /incomplete|partial|not.*complete|not.*verified/i);
  assert.doesNotMatch(await page.locator('#audit-verification').textContent(), /^\s*(Verified|Audit log verified)/i);
})]);

tests.push(['client examples preserve a quoted CA path without executing it', browser => fixture(browser, {}, async page => {
  await ready(page);
  await page.locator('nav a[href="#proxy"]').click();
  const caPath = './certs/client\'s "lab" $cache.pem';
  await page.locator('#ca-path').fill(caPath);
  const curl = await page.locator('#proxy-command').textContent();
  await page.locator('#client-type').selectOption('python');
  const python = await page.locator('#proxy-command').textContent();
  // Parse the displayed snippets as data. Never execute generated client code
  // or shell text, and never contact the synthetic hostname from this suite.
  const parsed = JSON.parse(execFileSync(process.env.PYTHON || 'python3', ['-B', '-c',
    'import ast,json,shlex,sys\n' +
    'document=json.load(sys.stdin)\n' +
    'args=shlex.split(document["curl"].replace(chr(92)+chr(10), ""), comments=True)\n' +
    'tree=ast.parse(document["python"])\n' +
    'context=next(n for n in tree.body if isinstance(n,ast.Assign) and n.targets[0].id=="context")\n' +
    'ca=next(k.value.value for k in context.value.keywords if k.arg=="cafile")\n' +
    'print(json.dumps({"curlCa":args[args.index("--cacert")+1], "pythonCa":ca}))'],
  {input: JSON.stringify({curl, python}), encoding: 'utf8'}));
  assert.equal(parsed.curlCa, caPath);
  assert.equal(parsed.pythonCa, caPath);
  assert(await page.locator('#copy-proxy-command').isEnabled());
  await page.locator('#ca-path').fill('');
  assert(await page.locator('#copy-proxy-command').isDisabled());
})]);

tests.push(['Python example omits implicit Accept-Encoding without weakening TLS', browser => fixture(browser, {}, async page => {
  await ready(page);
  await page.locator('nav a[href="#proxy"]').click();
  await page.locator('#client-type').selectOption('python');
  const python = await page.locator('#proxy-command').textContent();
  // Exercise Python's actual HTTP serializer, but replace all socket I/O and
  // the CA-file read. This fixture never creates a connection or trusts a CA.
  const result = JSON.parse(execFileSync(process.env.PYTHON || 'python3', ['-B', '-c',
    'import contextlib,http.client,io,json,socket,ssl,sys\n' +
    'from unittest.mock import patch,MagicMock\n' +
    'source=sys.stdin.read(); wire=[]; context=ssl.create_default_context()\n' +
    'response=MagicMock(); response.status=200; response.read.return_value=b"{}"\n' +
    'def record(self,data): wire.append(bytes(data))\n' +
    'with patch("socket.create_connection", side_effect=AssertionError("network prohibited")), patch("ssl.create_default_context", return_value=context) as trust, patch.object(http.client.HTTPSConnection,"send",record), patch.object(http.client.HTTPSConnection,"getresponse",return_value=response), contextlib.redirect_stdout(io.StringIO()):\n' +
    ' exec(compile(source,"<rendered-client>","exec"), {})\n' +
    'print(json.dumps({"wire":b"".join(wire).decode("ascii"), "ca":trust.call_args.kwargs.get("cafile"), "tlsVerification":context.verify_mode==ssl.CERT_REQUIRED, "hostnameVerification":context.check_hostname}))'],
  {input: python, encoding: 'utf8'}));
  assert.equal(result.ca, './catchplate-ca.pem');
  assert.equal(result.tlsVerification, true);
  assert.equal(result.hostnameVerification, true);
  assert.equal(result.wire, 'GET /echo HTTP/1.1\r\nHost: demo-upstream:8443\r\n' +
    'X-Catchplate-Agent: demo-agent\r\nConnection: close\r\n\r\n');
})]);

tests.push(['empty filtered audit page still allows searching older events', browser => fixture(browser, {
  override: url => {
    if (url.pathname !== '/api/audit/search') return null;
    const older = url.searchParams.get('cursor') === 'fixture-next-page';
    const item = older ? {...blocked, event: {...blocked.event, marker: 'older-match'}} : released;
    return json({ok: true, items: [item], count: 1, scanned: 1, total_candidates: 2,
      complete: older, has_more: !older, next_cursor: older ? null : 'fixture-next-page'});
  },
}, async (page, state) => {
  await ready(page);
  await page.locator('nav a[href="#audit"]').click();
  await textMatches(page, '#audit-status', /1 events shown/);
  await page.locator('#audit-query').fill('older-match');
  await page.locator('#audit-search-form button').click();
  await textMatches(page, '#audit-status', /No matching events in the loaded page/);
  assert(await page.locator('#audit-more').isVisible());
  await page.locator('#audit-more').click();
  await textMatches(page, '#audit-status', /1 events shown.*End of matching history/);
  assert(await page.locator('#audit-more').isHidden());
  assert.equal(await page.locator('#audit-list [data-event-id]').count(), 1);
  assert(state.requests.some(request => request.path === '/api/audit/search' &&
    new URLSearchParams(request.query).get('cursor') === 'fixture-next-page'));
})]);

tests.push(['editing audit search before loading older events starts a fresh cursor', browser => fixture(browser, {
  override: url => {
    if (url.pathname !== '/api/audit/search') return null;
    const changed = url.searchParams.get('q') === 'new-query';
    if (changed && url.searchParams.has('cursor')) return json({detail: 'Fixture cursor/filter mismatch'}, 400);
    const item = changed ? {...released, id: 'fixture-new-query', event: {...released.event, marker: 'new-query'}} : released;
    return json({ok: true, items: [item], count: 1, scanned: 1, total_candidates: changed ? 1 : 2,
      complete: changed, has_more: !changed, next_cursor: changed ? null : 'fixture-original-query-cursor'});
  },
}, async (page, state) => {
  await ready(page);
  await page.locator('nav a[href="#audit"]').click();
  await textMatches(page, '#audit-status', /1 events shown/);
  await page.locator('#audit-filter').selectOption('released');
  await textMatches(page, '#audit-status', /1 events shown/);
  await page.locator('#audit-query').fill('new-query');
  // Intentionally do not submit Search: this is the formerly stale-cursor path.
  await page.locator('#audit-more').click();
  await page.locator('[data-event-id="fixture-new-query"]').waitFor({state: 'visible'});
  await textMatches(page, '#audit-status', /1 events shown.*End of matching history/);
  assert.equal(await page.locator('#audit-list [data-event-id]').count(), 1);
  const request = state.requests.find(request => request.path === '/api/audit/search' &&
    new URLSearchParams(request.query).get('q') === 'new-query');
  assert(request, 'edited query was not applied');
  assert(!new URLSearchParams(request.query).has('cursor'), 'old cursor escaped into the new search');
})]);

tests.push(['request outcomes exclude incidental text matches and search without case sensitivity', browser => fixture(browser, {
  override: url => url.pathname === '/api/audit/search' ? json({ok: true, count: 3, scanned: 3,
    total_candidates: 3, complete: true, has_more: false, next_cursor: null, items: [released, blocked,
      {id: 'fixture-incidental', event_type: 'control_plane.note', created_at: released.created_at,
        event: {text: 'Documentation mentions data_plane.response.released and agent:demo'}}]}) : null,
}, async page => {
  await ready(page);
  await page.locator('nav a[href="#audit"]').click();
  await textMatches(page, '#audit-status', /2 events shown/);
  assert.equal(await page.locator('[data-event-id="fixture-incidental"]').count(), 0);
  await page.locator('#audit-query').fill('AGENT:DEMO');
  await page.locator('#audit-search-form button').click();
  await textMatches(page, '#audit-status', /2 events shown/);
  assert.equal(await page.locator('#audit-list [data-event-id]').count(), 2);
  assert.equal(await page.locator('[data-event-id="fixture-incidental"]').count(), 0);
})]);

async function main() {
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox']});
  const passed = [];
  try {
    for (const [name, run] of tests) {
      await run(browser);
      passed.push(name);
    }
    assert(tests.length >= 8, 'the intended regression controls must all be installed');
    console.log(JSON.stringify({ok: true, boundary: 'offline browser fixtures only; no live service calls', passed}));
  } finally {
    await browser.close();
  }
}

main().catch(error => {console.error(error.stack); process.exitCode = 1;});

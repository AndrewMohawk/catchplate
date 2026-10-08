#!/usr/bin/env node
// Real deployed responses through a secret-safe local transport adapter. This
// verifies the rendered UI/API flow, NOT human Authelia or hardware acceptance.
// Optional SANDBOX_BROWSER_CHECK_PROXY=1 sends the fixed synthetic demo requests.
const { execFileSync } = require('node:child_process');
const { X509Certificate } = require('node:crypto');
const { createServer } = require('node:http');
const { chromium, request } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const ORIGIN = 'https://serverware-sandbox.example.com';
const PAGES = ['overview', 'proxy', 'credentials', 'access', 'audit'];
const DOCUMENTS = new Set(['/api/bootstrap', '/api/policy', '/api/sandbox/check']);
const READ_PATHS = new Set(['/', '/ca.pem', '/api/auth/status', '/api/sandbox/status',
  '/api/bootstrap', '/api/policy', '/api/audit/search', '/api/audit/verify']);
const CHECKS = [
  'synthetic_profile_and_exact_rust_build',
  'connect_identity_and_destination_denials',
  'caller_credential_collision_denied_without_dispatch',
  'connect_tls_credential_injection_and_header_redaction',
  'route_denials_without_upstream_dispatch',
  'credential_reflection_blocked',
  'unsupported_streaming_transform_denied_without_dispatch',
  'stored_correlated_audit_without_credential_material',
];

// Error messages, console arguments, request headers and backend bodies are
// never logged: Playwright exceptions can otherwise include the service token.
function requireCondition(value) {
  if (!value) throw new Error('browser verification invariant failed');
}

function fingerprint(value) {
  return value.replace(/^SHA-?256\s*:?\s*/i, '').replace(/[^a-f0-9]/gi, '').toLowerCase();
}

function credentialIdentity(credentials) {
  return JSON.stringify(credentials.map(credential => ({
    id: credential.id, version: credential.credential_version ?? credential.version,
  })));
}

async function navigate(page, name) {
  await page.locator(`nav[aria-label="Main navigation"] a[href="#${name}"]`).click();
  await page.locator(`#${name}`).waitFor({ state: 'visible' });
  requireCondition(new URL(page.url()).hash === `#${name}`);
  requireCondition(await page.locator('.page:visible').count() === 1);
  requireCondition(await page.locator(`nav a[href="#${name}"]`).getAttribute('aria-current') === 'page');
}

async function loaded(page) {
  await page.waitForFunction(() => !document.getElementById('sandbox-run-check')?.disabled,
    null, { timeout: 20000 });
  requireCondition(await page.locator('#load-error').isHidden());
  requireCondition((await page.locator('#operator-auth-status').innerText()).includes('sandbox-operator'));
}

async function auditAction(page, action) {
  const pending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/audit/search');
  await action();
  const response = await pending;
  requireCondition(response.status() === 200);
  const result = await response.json();
  requireCondition(result.ok === true && Array.isArray(result.items));
  await page.waitForFunction(() => !document.getElementById('audit-refresh').disabled);
  return result;
}

async function startRelay({ backend, address, token, documents, failures }) {
  // Chromium attachment downloads bypass Playwright route interception. An
  // actual loopback socket lets the real download anchor receive real bytes.
  // This relay is short-lived, fixed-target and never binds a public interface.
  let origin;
  const server = createServer(async (incoming, outgoing) => {
    let path = 'invalid_request';
    try {
      const url = new URL(incoming.url, origin);
      path = url.pathname;
      const allowed = incoming.method === 'GET' ? READ_PATHS.has(path) :
        incoming.method === 'POST' && path === '/api/sandbox/check' && !url.search;
      if (!allowed || url.origin !== origin || incoming.headers.host !== new URL(origin).host ||
          incoming.headers['x-serverware-admin-token'] ||
          (incoming.headers.origin && incoming.headers.origin !== origin)) {
        outgoing.writeHead(403); outgoing.end(); return;
      }
      let bodyBytes = 0;
      for await (const chunk of incoming) {
        bodyBytes += chunk.length;
        if (bodyBytes > 1024) { outgoing.writeHead(413); outgoing.end(); incoming.destroy(); return; }
      }
      if (bodyBytes !== 0) { outgoing.writeHead(400); outgoing.end(); return; }
      const response = await backend.fetch(`http://${address}:3000${url.pathname}${url.search}`, {
        method: incoming.method, timeout: 60000, maxRedirects: 0, headers: { Origin: ORIGIN },
      });
      requireCondition(response.status() < 300 || response.status() >= 400);
      const payload = await response.body();
      requireCondition(!payload.includes(Buffer.from(token)));
      if (response.status() >= 400) failures.push({ path, status: response.status() });
      if (DOCUMENTS.has(path)) documents.set(path, JSON.parse(payload.toString('utf8')));
      const headers = { 'Cache-Control': 'no-store', 'Content-Length': String(payload.length) };
      for (const name of ['content-type', 'content-disposition', 'content-security-policy', 'x-content-type-options']) {
        const value = response.headers()[name];
        if (value) { requireCondition(!value.includes(token)); headers[name] = value; }
      }
      outgoing.writeHead(response.status(), headers); outgoing.end(payload);
    } catch (_) {
      failures.push({ path, kind: 'transport_or_response_rejected' });
      if (!outgoing.headersSent) outgoing.writeHead(502);
      outgoing.end();
    }
  });
  server.requestTimeout = 65000;
  server.headersTimeout = 10000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  origin = `http://127.0.0.1:${server.address().port}`;
  return { server, origin };
}

async function main() {
  let stage = 'transport initialization';
  let backend, browser, context, page, relay;
  const errors = [], failures = [], documents = new Map(), checks = [];
  const screenshots = [];
  let firstLoadMs, reloadMs, proxyCheckPassed = false;
  try {
    const container = 'serverware-sandbox-serverware-1';
    const topology = JSON.parse(execFileSync('docker', ['inspect', container], { encoding: 'utf8' }))[0];
    const address = topology.NetworkSettings.Networks['serverware-sandbox_sandbox'].IPAddress;
    requireCondition(/^172\.16\.249\.[0-9]+$/.test(address));
    const token = execFileSync('docker', ['exec', container, 'python', '-c',
      "from pathlib import Path; print(Path('/run/secrets/serverware/admin.token').read_text(),end='')"],
    { encoding: 'utf8' }).trim();
    requireCondition(token.length >= 16 && !/[\r\n]/.test(token));
    backend = await request.newContext({ extraHTTPHeaders: {
      'X-Serverware-Admin-Token': token,
      Host: 'serverware-sandbox.example.com',
      'X-Forwarded-Proto': 'https',
    } });
    relay = await startRelay({ backend, address, token, documents, failures });
    browser = await chromium.launch({ headless: true, args: ['--no-sandbox'] });
    context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true });
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: relay.origin });
    await context.route('**/*', async route => {
      const url = new URL(route.request().url());
      if (url.origin !== relay.origin) {
        failures.push({ kind: 'unexpected_external_request' });
        return route.abort();
      }
      return route.continue();
    });
    page = await context.newPage();
    page.on('pageerror', () => errors.push({ kind: 'pageerror' }));
    page.on('console', message => { if (message.type() === 'error') errors.push({ kind: 'console_error' }); });

    stage = 'overview and initial data';
    const start = performance.now();
    await page.goto(relay.origin, { waitUntil: 'domcontentloaded', timeout: 30000 });
    await loaded(page);
    firstLoadMs = Math.round(performance.now() - start);
    requireCondition(await page.title() === 'Overview - Serverware');
    requireCondition(await page.locator('#overview').isVisible());
    requireCondition(await page.locator('nav[aria-label="Main navigation"] a').count() === 5);
    requireCondition(await page.locator('#admin-token').count() === 0);
    requireCondition((await page.locator('#development-sandbox-banner').innerText()).includes('Test credentials only'));
    requireCondition((await page.locator('#limitations').textContent()).includes('Streaming request transformations are unsupported and refused.'));
    requireCondition(await page.locator('#demo-results').isHidden());
    const credentials = documents.get('/api/bootstrap')?.credentials;
    const policy = documents.get('/api/policy');
    requireCondition(Array.isArray(credentials) && credentials.length > 0);
    requireCondition(policy?.ready === true && policy.bundle?.routes?.length > 0);
    const savedCredentials = credentialIdentity(credentials);
    checks.push('overview_and_honest_sandbox_boundary');

    stage = 'proxy settings and actual CA browser download';
    await navigate(page, 'proxy');
    requireCondition((await page.locator('#proxy').innerText()).includes('http://decision-gate-rs:9090'));
    requireCondition((await page.locator('#proxy').innerText()).includes('Private network only.'));
    await page.waitForFunction(() => /^[a-f0-9: -]{64,}$/i.test(
      document.getElementById('ca-fingerprint').textContent.replace(/^SHA-?256\s*:?\s*/i, '').trim()));
    stage = 'CA browser attachment download';
    const downloadPending = page.waitForEvent('download');
    await page.locator('#ca-download').click();
    const download = await downloadPending;
    requireCondition((await download.failure()) === null);
    stage = 'CA download suggested filename';
    requireCondition(download.suggestedFilename() === 'serverware-ca.pem');
    stage = 'CA download stream';
    const stream = await download.createReadStream();
    requireCondition(stream !== null);
    const chunks = [];
    let bytes = 0;
    for await (const chunk of stream) {
      bytes += chunk.length;
      requireCondition(bytes <= 65536);
      chunks.push(chunk);
    }
    stage = 'CA download public X509 certificate';
    const pem = Buffer.concat(chunks).toString('utf8');
    requireCondition(!pem.includes('PRIVATE KEY') && !pem.includes(token));
    requireCondition((pem.match(/-----BEGIN CERTIFICATE-----/g) || []).length === 1);
    const ca = new X509Certificate(pem);
    requireCondition(ca.ca && ca.checkIssued(ca) && ca.verify(ca.publicKey));
    requireCondition(Date.parse(ca.validFrom) <= Date.now() && Date.parse(ca.validTo) > Date.now());
    const caFingerprint = fingerprint(ca.fingerprint256);
    stage = 'CA downloaded and displayed fingerprints match';
    requireCondition(fingerprint(await page.locator('#ca-fingerprint').innerText()) === caFingerprint);
    checks.push('public_ca_download_certificate_and_fingerprint');

    stage = 'editable client configuration and real clipboard';
    await page.locator('#ca-path').fill('./test client/serverware-ca.pem');
    await page.locator('#client-type').selectOption('curl');
    const curl = await page.locator('#proxy-command').innerText();
    requireCondition(curl.includes('test client/serverware-ca.pem') && curl.includes('--cacert'));
    requireCondition(curl.includes('http://decision-gate-rs:9090') && curl.includes('https://demo-upstream:8443/echo'));
    requireCondition(!curl.includes('--insecure') && !curl.includes(token));
    await page.locator('#copy-proxy-command').click();
    await page.waitForFunction(() => document.getElementById('copy-status').textContent === 'Copied.');
    requireCondition(await page.evaluate(() => navigator.clipboard.readText()) === curl);
    await page.locator('#client-type').selectOption('python');
    const python = await page.locator('#proxy-command').innerText();
    requireCondition(python !== curl && python.includes('test client/serverware-ca.pem'));
    requireCondition(python.includes('ssl.create_default_context') && !python.includes('CERT_NONE'));
    await page.locator('#copy-proxy-command').click();
    await page.waitForFunction(() => document.getElementById('copy-status').textContent === 'Copied.');
    requireCondition(await page.evaluate(() => navigator.clipboard.readText()) === python);
    checks.push('curl_python_configuration_and_clipboard');
    await page.screenshot({ path: '/tmp/serverware-sandbox-proxy.png', fullPage: false });
    screenshots.push('/tmp/serverware-sandbox-proxy.png');

    stage = 'stored credentials and signed effective policy';
    await navigate(page, 'credentials');
    const credentialText = await page.locator('#credentials-list').innerText();
    for (const credential of credentials) requireCondition(credentialText.includes(credential.name));
    requireCondition(!credentialText.includes('demo-token-from-vault') && !credentialText.includes(token));
    await navigate(page, 'access');
    const renderedPolicy = JSON.parse(await page.locator('#policy-json').textContent());
    requireCondition(JSON.stringify(renderedPolicy).includes(policy.policy_hash));
    requireCondition(JSON.stringify(renderedPolicy).includes('demo.echo'));
    const demoRule = policy.bundle.routes.find(rule => rule.id === 'demo.echo');
    requireCondition(demoRule);
    const demoText = await page.locator('#demo-rule').innerText();
    for (const value of [demoRule.match.host, ...demoRule.match.methods, ...demoRule.match.paths]) {
      requireCondition(demoText.includes(value));
    }
    await page.locator('#other-rules-label').click();
    await page.locator('#rule-search').fill('no-such-rule-browser-check');
    requireCondition(await page.locator('#other-rules .rule').count() === 0);
    await page.locator('#rule-search').fill('');
    requireCondition(await page.locator('#other-rules .rule').count() === policy.bundle.routes.length - 1);
    checks.push('stored_credentials_and_signed_policy_rules');

    if (process.env.SANDBOX_BROWSER_CHECK_PROXY === '1') {
      stage = 'real proxy demo and four evidence-backed outcomes';
      await navigate(page, 'overview');
      await page.locator('#sandbox-run-check').click();
      await page.waitForFunction(() => ['passed', 'failed'].includes(
        document.getElementById('sandbox-check-result').dataset.state), null, { timeout: 60000 });
      const result = documents.get('/api/sandbox/check');
      requireCondition(result?.ok === true && JSON.stringify(result.checks) === JSON.stringify(CHECKS));
      requireCondition(await page.locator('#sandbox-check-result').getAttribute('data-state') === 'passed');
      requireCondition(await page.locator('#demo-results .result').count() === 4);
      requireCondition(await page.locator('#demo-results .result[data-state="passed"]').count() === 4);
      requireCondition(await page.locator('#demo-followup').isVisible());
      proxyCheckPassed = true;
      checks.push('real_eight_checks_and_four_user_outcomes');
    }

    stage = 'persisted audit navigation and filters';
    await auditAction(page, () => navigate(page, 'audit'));
    const released = await auditAction(page, () => page.locator('#audit-filter').selectOption('released'));
    requireCondition(released.items.every(event => event.event_type === 'data_plane.response.released'));
    if (proxyCheckPassed) requireCondition(released.items.length > 0);
    const blocked = await auditAction(page, () => page.locator('#audit-filter').selectOption('blocked'));
    requireCondition(blocked.items.every(event => event.event_type === 'data_plane.response.blocked'));
    if (proxyCheckPassed) requireCondition(blocked.items.length > 0);
    await auditAction(page, () => page.locator('#audit-filter').selectOption('all'));
    await page.locator('#audit-query').fill('no-such-audit-event-browser-check');
    const empty = await auditAction(page, () => page.locator('#audit-search-form').getByRole('button', { name: 'Search' }).click());
    requireCondition(empty.items.length === 0 && await page.locator('#audit-list .audit-card').count() === 0);
    await page.locator('#audit-query').fill('');
    const audit = await auditAction(page, () => page.locator('#audit-search-form').getByRole('button', { name: 'Search' }).click());
    requireCondition(audit.items.length > 0);
    const savedEventId = audit.items[0].id;
    requireCondition(await page.locator('#audit-list .audit-card').count() === audit.items.length);
    requireCondition(JSON.stringify(await page.locator('#audit-list .audit-card').evaluateAll(cards => cards.map(card => card.dataset.eventId))) ===
      JSON.stringify(audit.items.map(event => event.id)));
    checks.push('audit_filters_search_and_empty_state');

    stage = 'complete local audit verification';
    const verificationPending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/audit/verify');
    await page.locator('#audit-verify').click();
    const verification = await (await verificationPending).json();
    requireCondition(verification.ok === true && verification.complete === true);
    await page.waitForFunction(() => /verified/i.test(document.getElementById('audit-verification').textContent));
    checks.push('complete_local_audit_chain');

    stage = 'reload preserves stored data and chosen client configuration';
    documents.delete('/api/bootstrap');
    documents.delete('/api/policy');
    const reloadedAuditPending = page.waitForResponse(response => new URL(response.url()).pathname === '/api/audit/search');
    const reloadStart = performance.now();
    await page.reload({ waitUntil: 'domcontentloaded' });
    await loaded(page);
    await reloadedAuditPending;
    await page.waitForFunction(() => !document.getElementById('audit-refresh').disabled);
    reloadMs = Math.round(performance.now() - reloadStart);
    requireCondition(credentialIdentity(documents.get('/api/bootstrap').credentials) === savedCredentials);
    requireCondition(documents.get('/api/policy').policy_hash === policy.policy_hash);
    const persisted = await auditAction(page, () => page.locator('#audit-filter').selectOption('all'));
    requireCondition(persisted.items.some(event => event.id === savedEventId));
    requireCondition(await page.locator('#audit-list .audit-card').evaluateAll(
      (cards, id) => cards.some(card => card.dataset.eventId === id), savedEventId));
    await navigate(page, 'proxy');
    requireCondition(await page.locator('#ca-path').inputValue() === './test client/serverware-ca.pem');
    requireCondition(await page.locator('#client-type').inputValue() === 'python');
    requireCondition(await page.locator('#proxy-command').innerText() === python);
    checks.push('reload_data_policy_audit_and_client_preferences');

    stage = 'desktop and mobile five-section navigation';
    for (const width of [1440, 390]) {
      await page.setViewportSize({ width, height: width === 390 ? 844 : 1000 });
      for (const name of PAGES) {
        await navigate(page, name);
        requireCondition(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1));
      }
      await navigate(page, 'overview');
      await page.evaluate(() => window.scrollTo(0, 0));
      const path = width === 390 ? '/tmp/serverware-sandbox-mobile.png' : '/tmp/serverware-sandbox-browser.png';
      await page.screenshot({ path, fullPage: false });
      screenshots.push(path);
    }
    checks.push('all_five_sections_desktop_and_mobile_no_overflow');
    requireCondition(!(await page.content()).includes(token));
    requireCondition(errors.length === 0 && failures.length === 0);
    console.log(JSON.stringify({ ok: true, boundary: 'real backend through ephemeral localhost HTTP relay; not human SSO',
      title: await page.title(), url: page.url(), firstLoadMs, reloadMs, proxyCheckPassed,
      auditChainVerified: true, checks, screenshots, errors, failures }));
  } catch (error) {
    if (page) await page.screenshot({ path: '/tmp/serverware-sandbox-browser-failed.png', fullPage: false }).catch(() => {});
    // Extract only this script's numeric line, never the exception text/trace.
    const sourceLine = error.stack?.match(/check_development_sandbox_browser\.cjs:(\d+):\d+/g)?.slice(-1)[0]?.match(/:(\d+):\d+$/)?.[1];
    console.log(JSON.stringify({ ok: false, stage, sourceLine, checks, errors, failures }));
    process.exitCode = 1;
  } finally {
    if (context) await context.unrouteAll({ behavior: 'wait' }).catch(() => {});
    if (browser) await browser.close().catch(() => {});
    if (relay) await new Promise(resolve => { relay.server.close(resolve); relay.server.closeAllConnections(); });
    if (backend) await backend.dispose().catch(() => {});
  }
}

main().catch(() => { console.error('Sandbox browser verification failed during cleanup'); process.exitCode = 1; });

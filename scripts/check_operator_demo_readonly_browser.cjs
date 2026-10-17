#!/usr/bin/env node
// Read-only live UI evidence, not proxy execution, public ingress, SSO or pilot acceptance.
// Run --self-test without credentials. --live reads only the existing admin transport
// token from stdin; it remains in this process and never enters the browser or argv.
const assert = require('node:assert/strict');
const {createServer, request: httpRequest} = require('node:http');
const {readFileSync} = require('node:fs');
const {mkdir, writeFile, realpath} = require('node:fs/promises');
const {execFileSync} = require('node:child_process');
const {join, resolve} = require('node:path');
const {createHash, X509Certificate, randomUUID, randomBytes, timingSafeEqual} = require('node:crypto');

const ROOT = resolve(__dirname, '..');
const APP = 'http://172.16.249.19:3000';
const PUBLIC = 'https://catchplate-demo.example.com';
const CONTAINER = 'catchplate-operator-demo-catchplate-1';
const ARTIFACT_ROOT = '/srv/catchplate-fast/projects/catchplate-operator-artifacts';
const METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
const PATHS = new Set(['/', '/ca.pem', '/api/operator-demo/status', '/api/audit/search']);
const ASSETS = ['catchplate/operator_demo_portal.py', 'catchplate/operator_demo_web/index.html',
  'catchplate/operator_demo_web/style.css', 'catchplate/operator_demo_web/app.js'];
const sha256 = value => createHash('sha256').update(value).digest('hex');
class CheckFailure extends Error {}
function requireCondition(value, label) { if (!value) throw new CheckFailure(label); }
function command(binary, args, cwd = ROOT) {
  return execFileSync(binary, args, {cwd, encoding: 'utf8', timeout: 15000, maxBuffer: 2 * 1024 * 1024,
    stdio: ['ignore', 'pipe', 'pipe']});
}

// Deliberately narrower than the app: only the exact browser read flow is allowed.
// Canonical relative request-targets prevent absolute-form and normalized-path aliases.
function equalCapability(supplied, expected) {
  return typeof expected === 'string' && expected.length >= 32 && typeof supplied === 'string' &&
    Buffer.byteLength(supplied) === Buffer.byteLength(expected) && timingSafeEqual(Buffer.from(supplied), Buffer.from(expected));
}
function caCookie(value) {
  return {name: 'catchplate_readonly_ca', value, domain: '127.0.0.1', path: '/ca.pem', httpOnly: true, sameSite: 'Strict', secure: false};
}
function admittedRequest({method, target, headers}, origin, capability, downloadCapability) {
  const supplied = headers['x-catchplate-readonly-check'];
  const primary = equalCapability(supplied, capability);
  // Chromium's native anchor[download] omits extraHTTPHeaders and bypasses HTTP
  // routing. A separate HttpOnly, Strict, CA-path-only capability preserves the
  // real download interaction without granting it status/audit/page access.
  const certificateCookie = target === '/ca.pem' && typeof downloadCapability === 'string' && downloadCapability.length >= 32 &&
    equalCapability(headers.cookie, 'catchplate_readonly_ca=' + downloadCapability);
  if (supplied !== undefined && !primary) return null;
  if (!primary && !(method === 'GET' && certificateCookie && headers.referer === origin + '/' &&
      headers['sec-fetch-site'] === 'same-origin')) return null;
  if (method !== 'GET' || typeof target !== 'string' || target.length > 4096 ||
      !target.startsWith('/') || target.startsWith('//') || /[\\\x00-\x20#]/.test(target)) return null;
  let url;
  try { url = new URL(target, origin); } catch { return null; }
  if (url.origin !== origin || url.pathname + url.search !== target || headers.host !== new URL(origin).host ||
      headers.authorization || headers['proxy-authorization'] || headers['x-catchplate-admin-token'] ||
      headers.cookie && !certificateCookie || headers['transfer-encoding'] ||
      headers['content-length'] !== undefined && headers['content-length'] !== '0' ||
      headers.origin && headers.origin !== origin || headers['sec-fetch-site'] === 'cross-site') return null;
  if (url.pathname === '/favicon.ico' && !url.search) return {path: '/favicon.ico', local: true};
  if (!PATHS.has(url.pathname)) return null;
  if (url.pathname !== '/api/audit/search') return url.search ? null : {path: url.pathname};
  const query = url.searchParams;
  if (query.get('limit') !== '20' || query.get('scanLimit') !== '5000') return null;
  for (const [key, value] of query) {
    if (query.getAll(key).length !== 1 || !['limit', 'scanLimit', 'eventType', 'q', 'cursor'].includes(key)) return null;
    if (key === 'eventType' && !['data_plane.response.released', 'data_plane.response.blocked'].includes(value)) return null;
    if (key === 'q' && (!value || value.length > 128 || /[^\x20-\x7e]/.test(value))) return null;
    if (key === 'cursor' && (!value || value.length > 2048 || /[^A-Za-z0-9_=-]/.test(value))) return null;
  }
  return {path: url.pathname, search: url.search};
}

async function startRelay({adminToken, expectedHtml}) {
  requireCondition(typeof adminToken === 'string' && /^[\x21-\x7e]{32,8192}$/.test(adminToken), 'invalid_stdin_token');
  let capability = randomBytes(32).toString('base64url');
  let downloadCapability = randomBytes(32).toString('base64url');
  const browserHeaders = {'X-Catchplate-Readonly-Check': capability};
  const browserCaCookie = caCookie(downloadCapability);
  const stats = {forwarded: [], refused: 0, failures: 0, response_bytes: 0};
  let origin; let requestCount = 0;
  const server = createServer(async (incoming, outgoing) => {
    try {
      const route = admittedRequest({method: incoming.method, target: incoming.url, headers: incoming.headers}, origin, capability, downloadCapability);
      if (!route || ++requestCount > 60) {
        stats.refused++; outgoing.writeHead(403, {'Cache-Control': 'no-store'}); outgoing.end(); incoming.resume(); return;
      }
      for await (const chunk of incoming) requireCondition(chunk.length === 0, 'request_body_refused');
      if (route.local) { outgoing.writeHead(204); outgoing.end(); return; }
      const result = await new Promise((resolveResult, reject) => {
        const request = httpRequest(APP + route.path + (route.search || ''), {method: 'GET', timeout: 12000,
          headers: {'X-Catchplate-Admin-Token': adminToken, Origin: PUBLIC, Connection: 'close'}}, response => {
          let size = 0; const chunks = [];
          response.on('data', chunk => {
            size += chunk.length;
            if (size > 2 * 1024 * 1024) { response.destroy(); reject(new CheckFailure('response_size_refused')); }
            else chunks.push(chunk);
          });
          response.on('error', reject);
          response.on('end', () => resolveResult({status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks)}));
        });
        request.on('error', reject);
        request.on('timeout', () => request.destroy(new CheckFailure('backend_timeout')));
        request.end();
      });
      stats.forwarded.push({path: route.path, method: 'GET', status: result.status});
      requireCondition(result.status === 200, 'backend_non_200_or_redirect_refused');
      requireCondition(!result.body.includes(Buffer.from(adminToken)), 'transport_secret_in_response');
      if (route.path === '/') requireCondition(result.body.equals(expectedHtml), 'live_html_differs_from_committed_renderer');
      stats.response_bytes += result.body.length;
      requireCondition(stats.response_bytes <= 8 * 1024 * 1024, 'total_response_limit');
      const headers = {'Cache-Control': 'no-store', 'Content-Length': String(result.body.length), 'X-Content-Type-Options': 'nosniff'};
      for (const name of ['content-type', 'content-disposition', 'content-security-policy']) {
        const value = result.headers[name];
        if (typeof value === 'string') {
          requireCondition(!value.includes(adminToken), 'transport_secret_in_header'); headers[name] = value;
        }
      }
      outgoing.writeHead(200, headers); outgoing.end(result.body);
    } catch (_) {
      stats.failures++;
      if (!outgoing.headersSent) outgoing.writeHead(502, {'Cache-Control': 'no-store'});
      outgoing.end();
    }
  });
  server.requestTimeout = 15000; server.headersTimeout = 5000; server.maxConnections = 8;
  server.on('checkContinue', (_request, response) => { stats.refused++; response.writeHead(403); response.end(); });
  await new Promise((resolveListen, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolveListen); });
  origin = 'http://127.0.0.1:' + server.address().port;
  return {origin, stats, browserHeaders, browserCaCookie, close: async () => {
    adminToken = ''; capability = ''; downloadCapability = '';
    browserHeaders['X-Catchplate-Readonly-Check'] = ''; browserCaCookie.value = '';
    server.closeAllConnections(); await new Promise(resolveClose => server.close(resolveClose));
  }};
}

function inspectRuntimeAndSource() {
  const [container] = JSON.parse(command('docker', ['inspect', CONTAINER]));
  const labels = container.Config.Labels;
  requireCondition(container.State.Running && container.State.Health.Status === 'healthy' &&
    labels['com.docker.compose.project'] === 'catchplate-operator-demo' && labels['com.docker.compose.service'] === 'catchplate', 'unexpected_app_container');
  requireCondition(container.NetworkSettings.Networks['catchplate-operator-demo_sandbox'].IPAddress === new URL(APP).hostname,
    'app_ip_changed_reinspect_before_running');
  const env = Object.fromEntries(container.Config.Env.map(item => { const index = item.indexOf('='); return [item.slice(0, index), item.slice(index + 1)]; }));
  requireCondition(env.CATCHPLATE_ADMIN_TOKEN_FILE === '/run/secrets/catchplate/admin.token' &&
    env.CATCHPLATE_PUBLIC_URL === PUBLIC && env.CATCHPLATE_OPERATOR_DEMO === '1', 'unexpected_app_profile_or_token_file');
  const source = container.Mounts.find(mount => mount.Destination === '/app');
  requireCondition(source && source.RW === false && source.Source === '/srv/catchplate-fast/projects/catchplate-operator-polish', 'unexpected_source_mount');
  const sourceCommit = command('git', ['rev-parse', 'HEAD'], source.Source).trim();
  const assets = {};
  for (const file of ASSETS) {
    const local = readFileSync(join(ROOT, file)); const live = readFileSync(join(source.Source, file));
    const committed = Buffer.from(command('git', ['show', sourceCommit + ':' + file], source.Source));
    requireCondition(local.equals(live) && live.equals(committed), 'source_assets_not_equal_to_live_commit');
    assets[file] = sha256(local);
  }
  const expectedHtml = Buffer.from(command('python3', ['-B', '-c',
    'import sys; from catchplate.operator_demo_portal import render; sys.stdout.write(render())']));
  return {expectedHtml, evidence: {container_id: container.Id, app_origin: APP, source_commit: sourceCommit,
    renderer_sha256: sha256(expectedHtml), assets, harness_sha256: sha256(readFileSync(__filename))}};
}

function readiness(connection, status, now) {
  const expiry = connection.token_expires_at_epoch_ms;
  const valid = Number.isSafeInteger(expiry) && expiry > 0 && expiry <= 8640000000000000;
  if (connection.client_status === 'expired' || valid && now >= expiry) return 'Token expired';
  if (!valid) return 'Expiry / status unavailable';
  if (!Array.isArray(connection.methods) || !connection.methods.length || connection.methods.some(method => !METHODS.includes(method))) return 'Unsupported method';
  if (connection.client_status !== undefined && !['ready', 'pending'].includes(connection.client_status)) return 'Expiry / status unavailable';
  return status.active_policy_hash && status.active_policy_hash === status.loaded_policy_hash &&
    connection.policy_hash === status.active_policy_hash && connection.activation === 'active' && connection.client_status !== 'pending' ? 'Ready' : 'Pending activation';
}
async function navigate(page, view) {
  await page.locator(`nav a[href="#${view}"]`).click();
  await page.locator('#' + view).waitFor({state: 'visible'});
  requireCondition(await page.locator('.page:visible').count() === 1, 'navigation_not_one_section');
  requireCondition(await page.locator(`nav a[href="#${view}"]`).getAttribute('aria-current') === 'page', 'navigation_not_current');
  requireCondition(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'horizontal_overflow');
}
async function downloadBytes(download) {
  requireCondition(await download.failure() === null, 'ca_download_failed');
  const stream = await download.createReadStream(); requireCondition(stream, 'ca_download_empty');
  const chunks = []; let size = 0;
  for await (const chunk of stream) { size += chunk.length; requireCondition(size <= 65536, 'ca_download_oversize'); chunks.push(chunk); }
  return Buffer.concat(chunks);
}
async function runBrowser(browser, relay, directory) {
  const context = await browser.newContext({viewport: {width: 1280, height: 960}, serviceWorkers: 'block',
    permissions: ['clipboard-read', 'clipboard-write'], acceptDownloads: true, extraHTTPHeaders: relay.browserHeaders});
  await context.addCookies([relay.browserCaCookie]);
  const checks = []; const screenshots = []; let pageErrors = 0; let consoleErrors = 0; let blockedRequests = 0;
  let stage = 'initial_page'; let caDownload;
  await context.route('**/*', async route => {
    const request = route.request(); const url = new URL(request.url());
    const admitted = url.origin === relay.origin && admittedRequest({method: request.method(),
      target: url.pathname + url.search, headers: {...await request.allHeaders(), host: url.host}}, relay.origin,
      relay.browserHeaders['X-Catchplate-Readonly-Check'], relay.browserCaCookie.value);
    if (!admitted || request.postDataBuffer()?.length) { blockedRequests++; await route.abort(); return; }
    await route.continue();
  });
  await context.routeWebSocket('**/*', websocket => { blockedRequests++; websocket.close(); });
  const page = await context.newPage(); page.setDefaultTimeout(10000);
  page.on('pageerror', () => pageErrors++);
  page.on('console', message => { if (message.type() === 'error') consoleErrors++; });
  try {
    const loaded = page.waitForResponse(response => new URL(response.url()).pathname === '/api/operator-demo/status');
    const document = await page.goto(relay.origin, {waitUntil: 'domcontentloaded'});
    requireCondition(document.status() === 200, 'page_not_200');
    const statusResponse = await loaded; requireCondition(statusResponse.status() === 200, 'status_not_200');
    const status = await statusResponse.json();
    requireCondition(status.mode === 'operator-development' && status.productionReady === false && status.hardwareVerified === false &&
      status.syntheticOnly === false && Array.isArray(status.connections), 'incorrect_runtime_profile');
    await page.waitForFunction(() => !document.querySelector('#connection-fields').disabled);
    requireCondition(await page.locator('#load-error').isHidden(), 'status_error_visible');
    requireCondition((await page.title()).includes('Catchplate operator demo'), 'wrong_document_title');
    checks.push('live_html_matches_committed_renderer_and_real_status');

    stage = 'methods_and_lifecycle'; await navigate(page, 'credentials');
    requireCondition(JSON.stringify(await page.locator('input[name="method"]').evaluateAll(inputs => inputs.map(input => input.value))) ===
      JSON.stringify(METHODS), 'method_matrix_or_head_mismatch');
    requireCondition(await page.locator('#provider-secret').inputValue() === '' && await page.locator('#client-token').inputValue() === '' &&
      await page.locator('#one-time-access').isHidden(), 'unexpected_secret_ui_state');
    const cards = await page.locator('#connections-list article').evaluateAll(elements => elements.map(element => ({
      id: element.dataset.connectionId, badge: element.querySelector('.badge').textContent,
      active: element.querySelector('.badge').classList.contains('active'), text: element.textContent})));
    requireCondition(cards.length === status.connections.length, 'connection_count_mismatch');
    const now = await page.evaluate(() => Date.now()); const counts = {};
    for (const connection of status.connections) {
      const card = cards.find(item => item.id === connection.id); const expected = readiness(connection, status, now);
      requireCondition(card && card.badge === expected && card.active === (expected === 'Ready') &&
        card.text.includes('Client token expiry'), 'real_metadata_badge_or_expiry_mismatch');
      counts[expected] = (counts[expected] || 0) + 1;
    }
    checks.push('six_methods_no_head_and_real_readiness_expiry_badges');

    stage = 'placeholder_command'; await navigate(page, 'proxy');
    const ready = status.connections.find(connection => readiness(connection, status, Date.now()) === 'Ready');
    requireCondition(ready, 'no_unexpired_connection_for_placeholder_copy');
    await page.locator('#client-connection').selectOption(ready.id);
    const proxy = new URL(status.proxy_url).href.replace(/\/$/, '');
    const expectedCommand = require('../catchplate/operator_demo_web/app.js').buildCurlCommand({proxyUrl: proxy,
      upstreamUrl: ready.upstream_url, method: ready.methods[0], caPath: './catchplate-ca.pem', allowedHeaders: ready.allowed_headers});
    requireCondition(await page.locator('#client-command').innerText() === expectedCommand &&
      expectedCommand.includes('$CATCHPLATE_PROXY_TOKEN') && !expectedCommand.includes('--insecure') &&
      await page.locator('#download-config').isDisabled(), 'client_example_not_placeholder_only');
    await page.locator('#copy-command').click();
    await page.waitForFunction(() => document.querySelector('#client-copy-status').textContent.includes('Copied.'));
    requireCondition(await page.evaluate(() => navigator.clipboard.readText()) === expectedCommand, 'clipboard_command_mismatch');
    await page.evaluate(() => navigator.clipboard.writeText(''));
    checks.push('actual_placeholder_only_clipboard_no_client_execution');

    stage = 'public_ca'; const downloading = page.waitForEvent('download');
    await page.locator('#ca-download').click(); caDownload = await downloading;
    const ca = await downloadBytes(caDownload); const pem = ca.toString('ascii');
    requireCondition(caDownload.suggestedFilename() === 'catchplate-ca.pem' &&
      /^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\s*$/.test(pem) &&
      !pem.includes('PRIVATE KEY'), 'ca_not_one_public_certificate');
    const certificate = new X509Certificate(ca);
    requireCondition(certificate.ca && certificate.checkIssued(certificate) && certificate.verify(certificate.publicKey) && Date.parse(certificate.validFrom) <= Date.now() &&
      Date.parse(certificate.validTo) > Date.now(), 'ca_invalid_not_self_signed_or_expired');
    await caDownload.delete(); caDownload = null;
    checks.push('actual_public_ca_download_x509_validation');

    stage = 'read_only_audit'; const auditLoaded = page.waitForResponse(response => new URL(response.url()).pathname === '/api/audit/search');
    await navigate(page, 'audit'); const audit = await (await auditLoaded).json();
    requireCondition(audit.ok === true && Array.isArray(audit.items) && audit.items.length <= 20, 'audit_read_not_bounded_or_valid');
    await page.waitForFunction(count => document.querySelectorAll('#audit-list .event-card').length === count, audit.items.length);
    requireCondition(await page.locator('#audit-verification').innerText() === 'Not checked in this session.', 'unexpected_audit_verify_call');
    const filteredRead = page.waitForResponse(response => new URL(response.url()).pathname === '/api/audit/search');
    await page.locator('#audit-filter').selectOption('data_plane.response.released');
    const filtered = await (await filteredRead).json();
    requireCondition(filtered.ok === true && Array.isArray(filtered.items) && filtered.items.length <= 20 &&
      filtered.items.every(item => item.event_type === 'data_plane.response.released'), 'audit_filter_mismatch');
    await page.waitForFunction(count => {
      const cards = [...document.querySelectorAll('#audit-list .event-card')];
      return cards.length === count && cards.every(card => card.querySelector('h3').textContent === 'data_plane.response.released') &&
        document.querySelector('#audit-status').textContent.startsWith(count + ' events shown.');
    }, filtered.items.length);
    checks.push('real_bounded_read_only_audit_and_filter');

    stage = 'desktop_mobile_navigation';
    for (const [name, viewport] of [['desktop', {width: 1280, height: 960}], ['mobile', {width: 390, height: 844}]]) {
      await page.setViewportSize(viewport);
      for (const view of ['overview', 'credentials', 'proxy', 'audit']) {
        await navigate(page, view);
        const filename = name + '-' + view + '.png';
        await page.screenshot({path: join(directory, filename), fullPage: true}); screenshots.push(filename);
      }
    }
    requireCondition(await page.evaluate(() => localStorage.length + sessionStorage.length) === 0 &&
      await page.evaluate(() => document.cookie) === '', 'browser_script_visible_storage_not_empty');
    checks.push('all_four_sections_desktop_mobile_no_horizontal_overflow');
    requireCondition(pageErrors === 0 && consoleErrors === 0 && blockedRequests === 0 && relay.stats.failures === 0 && relay.stats.refused === 0,
      'browser_or_relay_error');
    return {ok: true, checks, screenshots, connection_count: status.connections.length, readiness_counts: counts,
      policy_hash: status.active_policy_hash, loaded_policy_hash: status.loaded_policy_hash, ca_sha256: sha256(ca),
      ca_fingerprint256: certificate.fingerprint256, placeholder_command_sha256: sha256(expectedCommand), audit_rows_read: audit.items.length,
      filtered_rows_read: filtered.items.length, page_errors: pageErrors, console_errors: consoleErrors, blocked_requests: blockedRequests};
  } catch (error) {
    return {ok: false, stage, reason: error instanceof CheckFailure ? error.message : 'browser_action_failed_diagnostics_suppressed',
      checks, screenshots, page_errors: pageErrors, console_errors: consoleErrors, blocked_requests: blockedRequests};
  } finally {
    if (caDownload) try { await caDownload.delete(); } catch (_) {}
    try { await page.evaluate(() => navigator.clipboard.writeText('')); } catch (_) {}
    // Keep the HTTP/WebSocket denylist installed until the context is gone.
    await context.close();
  }
}

function selfTest() {
  const origin = 'http://127.0.0.1:9999'; const capability = 'self-test-capability-is-not-a-live-token';
  const downloadCapability = 'independent-ca-capability-is-not-a-live-token';
  const headers = {host: '127.0.0.1:9999', 'x-catchplate-readonly-check': capability};
  const admitted = (target, changes = {}) => admittedRequest({method: 'GET', target, headers, ...changes}, origin, capability, downloadCapability);
  let accepted = 0; let rejected = 0;
  const accept = (target, changes) => { assert(admitted(target, changes)); accepted++; };
  const reject = (target, changes) => { assert.equal(admitted(target, changes), null); rejected++; };
  for (const target of ['/', '/ca.pem', '/api/operator-demo/status', '/api/audit/search?limit=20&scanLimit=5000',
    '/api/audit/search?limit=20&scanLimit=5000&eventType=data_plane.response.released&q=example']) accept(target);
  for (const target of ['/api/operator-demo/connections', '/api/audit/verify', '/ca.pem?x=1', '//elsewhere/',
    'http://127.0.0.1:9999/', '/a/../ca.pem', '/%63a.pem', '/ca.pem#x', '/api/audit/search',
    '/api/audit/search?limit=1000&scanLimit=5000', '/api/audit/search?limit=20&scanLimit=50000',
    '/api/audit/search?limit=20&scanLimit=5000&limit=20', '/api/audit/search?limit=20&scanLimit=5000&unexpected=x',
    '/api/audit/search?limit=20&scanLimit=5000&eventType=other', '/api/audit/search?limit=20&scanLimit=5000&q=' + 'x'.repeat(129)]) reject(target);
  for (const method of ['HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'CONNECT', 'TRACE']) reject('/', {method});
  for (const pair of [['host', 'elsewhere'], ['authorization', 'value'], ['proxy-authorization', 'value'],
    ['x-catchplate-admin-token', 'value'], ['cookie', 'value'], ['transfer-encoding', 'chunked'],
    ['content-length', '1'], ['origin', 'http://elsewhere'], ['sec-fetch-site', 'cross-site']])
    reject('/', {headers: {...headers, [pair[0]]: pair[1]}});
  reject('/', {headers: {host: headers.host}});
  reject('/', {headers: {...headers, 'x-catchplate-readonly-check': 'x'.repeat(capability.length)}});
  const downloadHeaders = {host: headers.host, cookie: 'catchplate_readonly_ca=' + downloadCapability,
    referer: origin + '/', 'sec-fetch-site': 'same-origin'};
  accept('/ca.pem', {headers: downloadHeaders});
  for (const target of ['/', '/api/operator-demo/status', '/api/audit/search?limit=20&scanLimit=5000', '/ca.pem?extra=1'])
    reject(target, {headers: downloadHeaders});
  for (const pair of [['cookie', undefined], ['cookie', 'catchplate_readonly_ca=' + capability],
    ['cookie', downloadHeaders.cookie + '; extra=value'], ['referer', undefined], ['referer', 'http://elsewhere/'],
    ['sec-fetch-site', 'cross-site'], ['x-catchplate-readonly-check', downloadCapability]])
    reject('/ca.pem', {headers: {...downloadHeaders, [pair[0]]: pair[1]}});
  console.log(JSON.stringify({ok: true, scope: 'pure read-only relay admission tests', accepted_cases: accepted, rejected_cases: rejected}));
}

async function downloadSelfTest() {
  const capability = randomBytes(32).toString('base64url'); const downloadCapability = randomBytes(32).toString('base64url');
  const publicBytes = Buffer.from('Public synthetic download; not a real CA.');
  const seen = []; let origin; let browser;
  const server = createServer((request, response) => {
    const admitted = admittedRequest({method: request.method, target: request.url, headers: request.headers}, origin, capability, downloadCapability);
    seen.push({path: request.url === '/' ? '/' : request.url === '/ca.pem' ? '/ca.pem' : 'unexpected', admitted: Boolean(admitted),
      primary_capability: equalCapability(request.headers['x-catchplate-readonly-check'], capability), cookie_present: Boolean(request.headers.cookie)});
    if (!admitted) { response.writeHead(403); response.end(); return; }
    if (request.url === '/') {
      response.writeHead(200, {'Content-Type': 'text/html'});
      response.end('<a id="ca" href="/ca.pem" download="catchplate-ca.pem">Download CA</a>'); return;
    }
    if (request.url === '/ca.pem') {
      response.writeHead(200, {'Content-Type': 'application/x-pem-file', 'Content-Disposition': 'attachment; filename="catchplate-ca.pem"'});
      response.end(publicBytes); return;
    }
    response.writeHead(404); response.end();
  });
  await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
  origin = 'http://127.0.0.1:' + server.address().port;
  try {
    const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
    browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
    const context = await browser.newContext({serviceWorkers: 'block', acceptDownloads: true,
      extraHTTPHeaders: {'X-Catchplate-Readonly-Check': capability}});
    await context.addCookies([caCookie(downloadCapability)]);
    await context.route('**/*', async route => {
      const request = route.request(); const url = new URL(request.url());
      if (url.origin !== origin || request.method() !== 'GET' || !['/', '/ca.pem'].includes(url.pathname)) { await route.abort(); return; }
      await route.continue();
    });
    await context.routeWebSocket('**/*', websocket => websocket.close());
    const page = await context.newPage(); page.setDefaultTimeout(5000);
    await page.goto(origin, {waitUntil: 'domcontentloaded'});
    requireCondition(await page.evaluate(() => document.cookie) === '', 'synthetic_cookie_script_visible');
    const pending = page.waitForEvent('download'); await page.locator('#ca').click(); const download = await pending;
    try { requireCondition((await downloadBytes(download)).equals(publicBytes), 'synthetic_download_mismatch'); }
    finally { try { await download.delete(); } catch (_) {} }
    requireCondition(seen.length === 2 && seen[0].path === '/' && seen[0].primary_capability && !seen[0].cookie_present &&
      seen[1].path === '/ca.pem' && !seen[1].primary_capability && seen[1].cookie_present && seen.every(item => item.admitted),
    'synthetic_capabilities_not_separated');
    await context.close();
    console.log(JSON.stringify({ok: true, scope: 'local synthetic native download only; no app or admin token',
      checks: ['real_native_download_preserved', 'independent_ca_only_cookie', 'http_only_cookie_not_script_visible'], seen}));
  } finally {
    try { if (browser) await browser.close(); } finally { server.closeAllConnections(); await new Promise(resolveClose => server.close(resolveClose)); }
  }
}

async function main() {
  if (process.argv.length === 3 && process.argv[2] === '--self-test') { selfTest(); return; }
  if (process.argv.length === 3 && process.argv[2] === '--download-self-test') { await downloadSelfTest(); return; }
  requireCondition(process.argv.length === 3 && process.argv[2] === '--live', 'use_explicit_self_test_or_live');
  const {expectedHtml, evidence} = inspectRuntimeAndSource();
  requireCondition(await realpath(ARTIFACT_ROOT) === ARTIFACT_ROOT, 'artifact_root_is_symlink');
  const directory = join(ARTIFACT_ROOT, 'readonly-browser-' + new Date().toISOString().replace(/[:.]/g, '-') + '-' + randomUUID());
  await mkdir(directory, {mode: 0o700});
  let token = ''; for await (const chunk of process.stdin) { token += chunk.toString(); requireCondition(token.length <= 8193, 'stdin_too_large'); }
  token = token.replace(/\n$/, '');
  const relay = await startRelay({adminToken: token, expectedHtml}); token = '';
  let browser; let deadline;
  try {
    // A dedicated browser provides an auditable network boundary and has no SSO
    // cookies or previously authenticated sessions from the shared browser MCP.
    const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
    browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking']});
    const result = await Promise.race([runBrowser(browser, relay, directory), new Promise((_, reject) => {
      deadline = setTimeout(() => reject(new CheckFailure('overall_120s_deadline')), 120000);
    })]);
    Object.assign(result, {scope: 'GET-only private live UI; no connection creation, token retrieval, proxy execution, public ingress, SSO or pilot acceptance',
      runtime: evidence, relay: relay.stats, completed_at: new Date().toISOString(), generated_client_executed: false,
      public_ingress_verified: false, human_sso_verified: false, live_mutations: 0});
    await writeFile(join(directory, 'result.json'), JSON.stringify(result, null, 2) + '\n', {flag: 'wx', mode: 0o600});
    const receipts = ['result.json', ...result.screenshots].map(file => sha256(readFileSync(join(directory, file))) + '  ' + file).join('\n') + '\n';
    await writeFile(join(directory, 'SHA256SUMS'), receipts, {flag: 'wx', mode: 0o600});
    console.log(JSON.stringify({ok: result.ok, checks: result.checks, reason: result.reason, stage: result.stage, artifact_directory: directory}));
    if (!result.ok) process.exitCode = 1;
  } finally {
    clearTimeout(deadline);
    try { if (browser) await browser.close(); } finally { await relay.close(); }
  }
}
module.exports = {admittedRequest, readiness};
if (require.main === module) main().catch(() => {
  console.error('Read-only browser check setup failed; private diagnostics suppressed.'); process.exitCode = 1;
});

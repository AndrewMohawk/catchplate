#!/usr/bin/env node
// Real private operator-demo HTTP/UI acceptance. No route mocking, public
// deployment, human SSO, real provider, sandbox or pilot acceptance is implied.
// The admin token arrives on stdin only and stays in the fixed-target relay.
const {createServer, request: httpRequest} = require('node:http');
const {isIP} = require('node:net');
const {readFileSync} = require('node:fs');
const {mkdtemp, writeFile, rm} = require('node:fs/promises');
const {lookup} = require('node:dns/promises');
const {execFile} = require('node:child_process');
const {promisify} = require('node:util');
const {join, resolve} = require('node:path');
const {randomBytes, randomUUID, X509Certificate, createHash} = require('node:crypto');
const {buildCurlCommand} = require('../catchplate/operator_demo_web/app.js');

const READ_PATHS = new Set(['/', '/ca.pem', '/api/operator-demo/status', '/api/audit/search', '/api/audit/verify']);
const WRITE_PATH = '/api/operator-demo/connections';
const MAX_RESPONSE = 2 * 1024 * 1024;
class VerificationFailure extends Error {}
function requireCondition(value, label) { if (!value) throw new VerificationFailure(label); }
function privateOrigin(value) {
  const parsed = new URL(value);
  requireCondition(parsed.protocol === 'http:' && !parsed.username && !parsed.password &&
    !parsed.search && !parsed.hash && parsed.pathname === '/', 'private app must be an HTTP origin');
  const octets = parsed.hostname.split('.').map(Number);
  requireCondition(isIP(parsed.hostname) === 4 && (octets[0] === 127 || octets[0] === 10 ||
    octets[0] === 192 && octets[1] === 168 || octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31),
  'private app must use an explicit loopback or RFC1918 IPv4 address');
  return parsed.origin;
}
function configuredOrigin(value) {
  const parsed = new URL(value);
  requireCondition(['http:', 'https:'].includes(parsed.protocol) && !parsed.username && !parsed.password &&
    !parsed.search && !parsed.hash && parsed.pathname === '/', 'configured public Origin must be exact');
  return parsed.origin;
}
async function startRelay({appUrl, adminToken, publicOrigin, failures}) {
  const backend = privateOrigin(appUrl); const admittedOrigin = configuredOrigin(publicOrigin);
  requireCondition(typeof adminToken === 'string' && adminToken.length >= 32 && adminToken.length <= 8192 &&
    !/[\r\n\0]/.test(adminToken), 'admin token input invalid');
  let origin;
  const server = createServer(async (incoming, outgoing) => {
    let routeName = 'unparsed';
    try {
      const url = new URL(incoming.url, origin); routeName = url.pathname;
      if (url.pathname === '/favicon.ico' && incoming.method === 'GET' && url.origin === origin &&
          incoming.headers.host === new URL(origin).host) { outgoing.writeHead(204); outgoing.end(); return; }
      const isWrite = incoming.method === 'POST' && routeName === WRITE_PATH && !url.search;
      requireCondition(url.origin === origin && incoming.headers.host === new URL(origin).host &&
        !incoming.headers['x-catchplate-admin-token'] &&
        (incoming.method === 'GET' && READ_PATHS.has(routeName) || isWrite) &&
        (!incoming.headers.origin || incoming.headers.origin === origin) &&
        (!isWrite || incoming.headers.origin === origin), 'relay request boundary refused');
      const body = []; let size = 0;
      for await (const chunk of incoming) { size += chunk.length; requireCondition(size <= 32768, 'relay request too large'); body.push(chunk); }
      requireCondition(isWrite || size === 0, 'relay GET body refused');
      const payload = Buffer.concat(body);
      const result = await new Promise((resolve, reject) => {
        const headers = {'X-Catchplate-Admin-Token': adminToken, Origin: admittedOrigin, Connection: 'close'};
        if (isWrite) { headers['Content-Type'] = 'application/json'; headers['Content-Length'] = payload.length; }
        const request = httpRequest(backend + url.pathname + url.search, {method: incoming.method, headers, timeout: 55000}, response => {
          let count = 0; const chunks = [];
          response.on('data', chunk => { count += chunk.length; if (count > MAX_RESPONSE) { response.destroy(); reject(new Error('relay response too large')); } else chunks.push(chunk); });
          response.on('error', reject);
          response.on('end', () => resolve({status: response.statusCode, headers: response.headers, body: Buffer.concat(chunks)}));
        });
        request.on('error', reject); request.on('timeout', () => request.destroy(new Error('relay timeout')));
        request.end(payload);
      });
      requireCondition(result.status < 300 || result.status >= 400, 'backend redirect refused');
      requireCondition(!result.body.includes(Buffer.from(adminToken)), 'admin token appeared in backend response');
      if (result.status >= 400) failures.push({path: routeName, status: result.status});
      const headers = {'Cache-Control': 'no-store', 'Content-Length': String(result.body.length)};
      for (const name of ['content-type', 'content-disposition', 'x-content-type-options', 'content-security-policy']) {
        const value = result.headers[name];
        if (typeof value === 'string') { requireCondition(!value.includes(adminToken), 'admin token appeared in response header'); headers[name] = value; }
      }
      outgoing.writeHead(result.status, headers); outgoing.end(result.body);
    } catch (_) {
      failures.push({path: routeName, kind: 'relay_boundary_or_transport_failure'});
      if (!outgoing.headersSent) outgoing.writeHead(502, {'Cache-Control': 'no-store'});
      outgoing.end();
    }
  });
  server.requestTimeout = 60000; server.headersTimeout = 10000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
  origin = 'http://127.0.0.1:' + server.address().port;
  return {server, origin};
}
async function navigate(page, view) {
  await page.locator(`nav a[href="#${view}"]`).click(); await page.locator('#' + view).waitFor({state: 'visible'});
  requireCondition(await page.locator('.page:visible').count() === 1, 'navigation must expose one workspace');
}
async function downloadedBytes(download, maximum) {
  requireCondition(await download.failure() === null, 'real browser download failed');
  const stream = await download.createReadStream(); requireCondition(stream !== null, 'download has no readable body');
  const chunks = []; let size = 0;
  for await (const chunk of stream) { size += chunk.length; requireCondition(size <= maximum, 'download exceeds bound'); chunks.push(chunk); }
  return Buffer.concat(chunks);
}
async function validateClientProxy(proxyUrl, expectedProxyUrl) {
  requireCondition(typeof expectedProxyUrl === 'string' && proxyUrl === expectedProxyUrl,
    'client execution requires the exact requested proxy URL');
  const proxy = new URL(proxyUrl);
  requireCondition(proxy.protocol === 'https:' && !proxy.username && !proxy.password &&
    !proxy.search && !proxy.hash && proxy.pathname === '/' && !isIP(proxy.hostname) && proxy.hostname.includes('.'),
  'client proxy must be an exact HTTPS hostname origin');
  const addresses = await lookup(proxy.hostname, {all: true});
  requireCondition(addresses.length > 0 && addresses.every(({address, family}) => {
    const parts = address.split('.').map(Number);
    return family === 4 && (parts[0] === 10 || parts[0] === 192 && parts[1] === 168 ||
      parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31);
  }), 'client proxy DNS must resolve only to private LAN IPv4 addresses');
}
async function executeCopiedClient({command, proxyUrl, expectedProxyUrl, fixtureOrigin, caBytes, clientToken, providerSecret}) {
  await validateClientProxy(proxyUrl, expectedProxyUrl);
  requireCondition(fixtureOrigin === 'https://demo-upstream:8443' && command === buildCurlCommand({
    proxyUrl, upstreamUrl: fixtureOrigin + '/echo', method: 'GET', caPath: './catchplate-ca.pem',
    allowedHeaders: ['accept', 'user-agent'],
  }), 'copied command does not match the exact approved fixture request');
  const scratch = resolve(process.env.TMPDIR || '/srv/catchplate-fast/tmp');
  requireCondition(scratch !== '/tmp' && !scratch.startsWith('/tmp/'), 'client scratch must use the approved non-root filesystem');
  const directory = await mkdtemp(join(scratch, 'operator-demo-client-'));
  try {
    await writeFile(join(directory, 'catchplate-ca.pem'), caBytes, {mode: 0o600, flag: 'wx'});
    // The copied command is unchanged. Private curl configuration only bounds
    // execution/output and appends the HTTP status; trust and routing stay intact.
    await writeFile(join(directory, '.curlrc'), 'connect-timeout = 5\nmax-time = 20\nmax-filesize = 65536\nsilent\nwrite-out = "\\n%{http_code}"\n',
      {mode: 0o600, flag: 'wx'});
    let result;
    try {
      result = await promisify(execFile)('/bin/sh', ['-c', command], {cwd: directory,
        env: {PATH: '/usr/bin:/bin', LC_ALL: 'C', CURL_HOME: directory, CATCHPLATE_PROXY_TOKEN: clientToken},
        timeout: 25000, killSignal: 'SIGKILL', maxBuffer: 65536, encoding: 'utf8'});
    } catch (_) { throw new VerificationFailure('generated client request failed; private diagnostics suppressed'); }
    requireCondition(![clientToken, providerSecret].some(secret => result.stdout.includes(secret) || result.stderr.includes(secret)),
      'generated client output contained secret material');
    const boundary = result.stdout.lastIndexOf('\n');
    requireCondition(boundary >= 0 && result.stdout.slice(boundary + 1) === '200', 'generated client did not receive HTTP 200');
    let body;
    try { body = JSON.parse(result.stdout.slice(0, boundary)); }
    catch (_) { throw new VerificationFailure('generated client did not receive projected JSON'); }
    const expected = {method: 'GET', path: '/echo', authorization_present: true, authorization_scheme: 'Bearer', credential_marker: 'other'};
    requireCondition(body && JSON.stringify(Object.keys(body).sort()) === JSON.stringify(Object.keys(expected).sort()) &&
      Object.entries(expected).every(([key, value]) => body[key] === value), 'generated client response projection or upstream authentication differed');
  } finally { await rm(directory, {recursive: true, force: true}); }
}
async function runLiveBrowser(browser, {baseUrl, fixtureOrigin = 'https://demo-upstream:8443'}) {
  const origin = privateOrigin(baseUrl);
  requireCondition(new URL(origin).hostname === '127.0.0.1', 'browser must use the script-owned loopback relay');
  requireCondition(fixtureOrigin === 'https://demo-upstream:8443', 'live browser check is restricted to the synthetic fixture');
  const context = await browser.newContext({viewport: {width: 1280, height: 960}, serviceWorkers: 'block',
    permissions: ['clipboard-read', 'clipboard-write']});
  const page = await context.newPage(); page.setDefaultTimeout(15000);
  const checks = []; let stage = 'initial load'; let errorCount = 0; let consoleErrorCount = 0; let unexpectedRequests = 0;
  let providerSecret = randomBytes(32).toString('base64url'); let clientToken = '';
  let connectionId; let policyHash; let caFingerprint; let commandDigest;
  const executeClient = process.env.OPERATOR_DEMO_EXECUTE_CLIENT === '1';
  const expectedProxyUrl = process.env.OPERATOR_DEMO_EXPECTED_PROXY_URL;
  let generatedClientExecuted = false;
  const downloads = [];
  page.on('pageerror', () => errorCount++);
  page.on('console', message => { if (message.type() === 'error') consoleErrorCount++; });
  page.on('request', request => { if (new URL(request.url()).origin !== origin) unexpectedRequests++; });
  try {
    const first = page.waitForResponse(response => new URL(response.url()).pathname === '/api/operator-demo/status');
    await page.goto(origin, {waitUntil: 'domcontentloaded'});
    const initialResponse = await first; requireCondition(initialResponse.status() === 200, 'status API not admitted');
    const initial = await initialResponse.json();
    requireCondition(initial.mode === 'operator-development' && initial.syntheticOnly === false &&
      initial.productionReady === false && initial.hardwareVerified === false && initial.allowed_upstreams.includes(fixtureOrigin),
    'isolated operator-development profile not established');
    if (executeClient) await validateClientProxy(initial.proxy_url, expectedProxyUrl);
    await page.waitForFunction(() => !document.querySelector('#connection-fields').disabled);
    requireCondition((await page.title()).includes('Catchplate operator demo'), 'wrong browser document');
    requireCondition(await page.locator('#overview-title').isVisible(), 'overview is blank');
    checks.push('real_operator_profile_and_page');

    stage = 'actual credential form submission';
    await navigate(page, 'credentials');
    const name = 'Browser acceptance ' + randomUUID();
    await page.locator('#connection-name').fill(name); await page.locator('#upstream-origin').selectOption(fixtureOrigin);
    await page.locator('#upstream-path').fill('/echo'); await page.locator('#provider-secret').fill(providerSecret);
    await page.locator('#response-fields').fill('method\npath\nauthorization_present\nauthorization_scheme\ncredential_marker');
    const pending = page.waitForResponse(response => new URL(response.url()).pathname === WRITE_PATH && response.request().method() === 'POST');
    await page.locator('#add-connection').click(); const createdResponse = await pending;
    requireCondition(createdResponse.ok(), 'credential form was rejected');
    const createdBytes = await createdResponse.body();
    requireCondition(!createdBytes.includes(Buffer.from(providerSecret)), 'provider secret appeared in create response');
    const created = JSON.parse(createdBytes.toString()); clientToken = created.client_token;
    requireCondition(typeof clientToken === 'string' && clientToken.length >= 32, 'one-time token missing');
    connectionId = created.connection.id; policyHash = created.policy_hash;
    requireCondition(created.connection.name === name && created.connection.upstream_url === fixtureOrigin + '/echo' &&
      JSON.stringify(created.connection.methods) === '["GET"]', 'saved connection differs from form');
    await page.locator('#one-time-access').waitFor({state: 'visible'});
    requireCondition(await page.locator('#provider-secret').inputValue() === '', 'provider input not cleared');
    requireCondition(await page.locator('#client-token').inputValue() === clientToken &&
      await page.locator('#client-token').getAttribute('type') === 'password', 'one-time token not presented safely');
    requireCondition(await page.evaluate(() => localStorage.length + sessionStorage.length) === 0, 'browser persisted client state');
    requireCondition(!(await page.locator('body').innerText()).includes(providerSecret), 'provider secret appeared in page');
    await page.locator('#copy-token').click();
    await page.waitForFunction(() => document.querySelector('#token-status').textContent.includes('Copied.'));
    requireCondition(await page.evaluate(() => navigator.clipboard.readText()) === clientToken, 'token clipboard does not match one-time token');
    checks.push('actual_credential_form_and_one_time_token');

    stage = 'actual loaded policy activation';
    await navigate(page, 'proxy');
    await page.waitForFunction(() => !document.querySelector('#copy-command').disabled, null, {timeout: 55000});
    const status = await page.evaluate(async () => (await fetch('/api/operator-demo/status', {cache: 'no-store'})).json());
    requireCondition(status.active_policy_hash === policyHash && status.loaded_policy_hash === policyHash, 'loaded policy does not match saved policy');
    requireCondition(status.connections.some(item => item.id === connectionId && item.activation === 'active'), 'new connection not active');
    requireCondition(!JSON.stringify(status).includes(clientToken) && !JSON.stringify(status).includes(providerSecret), 'status leaked secret material');
    checks.push('real_gate_loaded_policy_hash');

    stage = 'actual public CA attachment';
    const pendingCa = page.waitForEvent('download'); await page.locator('#ca-download').click();
    const caDownload = await pendingCa; downloads.push(caDownload);
    requireCondition(caDownload.suggestedFilename() === 'catchplate-ca.pem', 'unexpected CA download name');
    const caBytes = await downloadedBytes(caDownload, 65536); const pem = caBytes.toString();
    requireCondition(!pem.includes('PRIVATE KEY') && !pem.includes(providerSecret) && !pem.includes(clientToken), 'CA download contains private material');
    const certificate = new X509Certificate(caBytes);
    requireCondition(certificate.ca && certificate.checkIssued(certificate) && certificate.verify(certificate.publicKey), 'download is not a self-signed CA');
    requireCondition(Date.parse(certificate.validFrom) <= Date.now() && Date.parse(certificate.validTo) > Date.now(), 'CA is outside validity interval');
    caFingerprint = certificate.fingerprint256.replaceAll(':', '').toLowerCase(); checks.push('actual_ca_attachment_and_x509');

    stage = 'private client configuration';
    const command = await page.locator('#client-command').innerText();
    requireCondition(command.includes('--proxy ') && command.includes('--cacert ') && command.includes('$CATCHPLATE_PROXY_TOKEN') &&
      command.includes(fixtureOrigin + '/echo') && !command.includes('--insecure') && !command.includes('--proxy-insecure') &&
      !command.includes(providerSecret) && !command.includes(clientToken), 'rendered client configuration unsafe');
    commandDigest = createHash('sha256').update(command).digest('hex');
    await page.locator('#copy-command').click();
    await page.waitForFunction(() => document.querySelector('#client-copy-status').textContent.includes('Copied.'));
    const copiedCommand = await page.evaluate(() => navigator.clipboard.readText());
    requireCondition(copiedCommand === command, 'real clipboard does not match example');
    const pendingConfig = page.waitForEvent('download'); await page.locator('#download-config').click();
    const configDownload = await pendingConfig; downloads.push(configDownload);
    requireCondition(configDownload.suggestedFilename() === 'catchplate-client.private.json', 'unexpected private config filename');
    const configBytes = await downloadedBytes(configDownload, 65536); const config = JSON.parse(configBytes.toString());
    requireCondition(config.proxy_authorization === 'Bearer ' + clientToken && config.upstream_url === fixtureOrigin + '/echo' &&
      !configBytes.includes(Buffer.from(providerSecret)), 'private configuration has wrong credential boundary');
    checks.push('rendered_client_clipboard_and_private_download');
    if (executeClient) {
      stage = 'actual copied client request through the configured HTTPS proxy';
      requireCondition(config.proxy_url === status.proxy_url, 'private config proxy differs from active configuration');
      await executeCopiedClient({command: copiedCommand, proxyUrl: status.proxy_url, expectedProxyUrl,
        fixtureOrigin, caBytes, clientToken, providerSecret});
      generatedClientExecuted = true; checks.push('actual_copied_client_https_proxy_and_projected_response');
    }

    stage = 'persisted connection audit';
    await navigate(page, 'audit'); await page.locator('#audit-query').fill(connectionId);
    const auditResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/audit/search' &&
      new URL(response.url()).searchParams.get('q') === connectionId);
    await page.locator('#audit-search-form button').click(); const audit = await (await auditResponse).json();
    requireCondition(audit.ok === true && audit.items.some(item => item.event_type === 'operator_demo.connection.created' &&
      item.event?.connection_id === connectionId), 'persisted creation audit event missing');
    requireCondition(!JSON.stringify(audit).includes(clientToken) && !JSON.stringify(audit).includes(providerSecret), 'audit leaked secrets');
    await page.waitForFunction(() => document.querySelector('#audit-list').textContent.includes('operator_demo.connection.created'));
    const verifyResponse = page.waitForResponse(response => new URL(response.url()).pathname === '/api/audit/verify');
    await page.locator('#audit-verify').click(); const verified = await (await verifyResponse).json();
    requireCondition(verified.ok === true && verified.complete === true, 'complete local audit verification failed');
    checks.push('persisted_creation_audit_and_complete_chain');

    stage = 'desktop and mobile navigation';
    for (const view of ['overview', 'credentials', 'proxy', 'audit']) {
      await navigate(page, view);
      requireCondition(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'desktop horizontal overflow');
    }
    await page.setViewportSize({width: 390, height: 844});
    for (const view of ['overview', 'credentials', 'proxy', 'audit']) {
      await navigate(page, view);
      requireCondition(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1), 'mobile horizontal overflow');
    }
    await page.screenshot({path: '/tmp/catchplate-operator-demo-live-mobile.png', fullPage: true});
    checks.push('all_views_desktop_mobile');

    stage = 'reload preserves metadata but clears token';
    await page.reload({waitUntil: 'domcontentloaded'});
    await page.waitForFunction(() => !document.querySelector('#connection-fields').disabled);
    requireCondition(await page.locator('#client-token').inputValue() === '' && await page.locator('#one-time-access').isHidden(), 'token survived reload');
    requireCondition(await page.evaluate(() => localStorage.length + sessionStorage.length) === 0, 'secret storage appeared after reload');
    await navigate(page, 'credentials'); requireCondition((await page.locator('#connections-list').innerText()).includes(name), 'connection disappeared after reload');
    await page.setViewportSize({width: 1280, height: 960});
    await page.screenshot({path: '/tmp/catchplate-operator-demo-live-desktop.png', fullPage: true});
    checks.push('reload_persistence_without_token_retention');
    requireCondition(errorCount === 0 && consoleErrorCount === 0 && unexpectedRequests === 0, 'browser reported errors or external requests');
    return {ok: true, scope: 'Real isolated operator-demo UI/API and gate activation; synthetic fixture only',
      checks, connection_id: connectionId, policy_hash: policyHash, ca_sha256: caFingerprint, client_command_sha256: commandDigest,
      page_errors: errorCount, console_errors: consoleErrorCount, unexpected_requests: unexpectedRequests,
      public_ingress_verified: false, human_sso_verified: false, generated_client_executed: generatedClientExecuted,
      screenshots: ['/tmp/catchplate-operator-demo-live-mobile.png', '/tmp/catchplate-operator-demo-live-desktop.png']};
  } catch (error) { return {ok: false, stage, reason: error instanceof VerificationFailure ? error.message : 'browser action failed; private diagnostics suppressed', completed_checks: checks, page_errors: errorCount,
    console_errors: consoleErrorCount, unexpected_requests: unexpectedRequests, connection_id: connectionId || null}; }
  finally {
    providerSecret = ''; clientToken = '';
    try { await page.evaluate(async () => navigator.clipboard.writeText('')); } catch (_) {}
    for (const download of downloads) { try { await download.delete(); } catch (_) {} }
    await context.close();
  }
}

module.exports = {startRelay, runLiveBrowser};
if (require.main === module) (async () => {
  const appUrl = process.env.OPERATOR_DEMO_PRIVATE_APP_URL;
  const publicOrigin = process.env.OPERATOR_DEMO_PUBLIC_ORIGIN;
  requireCondition(Boolean(appUrl && publicOrigin), 'explicit private runtime configuration is required');
  let adminToken = readFileSync(0, 'utf8').trim(); const failures = [];
  const relay = await startRelay({appUrl, publicOrigin, adminToken, failures}); adminToken = '';
  let browser;
  try {
    const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
    browser = await chromium.launch({headless: true, args: ['--no-sandbox']});
    const result = await runLiveBrowser(browser, {baseUrl: relay.origin});
    result.relay_failures = failures;
    if (failures.length) result.ok = false;
    console.log(JSON.stringify(result, null, 2));
    if (!result.ok) process.exitCode = 1;
  } finally {
    if (browser) await browser.close();
    relay.server.closeAllConnections(); await new Promise(resolve => relay.server.close(resolve));
  }
})().catch(() => { console.error('Operator live browser setup failed; secret-bearing diagnostics were suppressed.'); process.exitCode = 1; });

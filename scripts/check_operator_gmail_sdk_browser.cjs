#!/usr/bin/env node
'use strict';
// Host rendering only. Every application byte travels through the exact
// network-none checker container's authenticated stdio bridge, never a host port.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const {spawn} = require('node:child_process');
const ORIGIN = 'https://serverware-demo.example.com';
const CATALOG = '/api/operator-demo/catalog';
const GRANT = '/api/operator-demo/access-rules/gmail-read';
const INTENTS = '/api/operator-demo/oauth/google/intents';
const PLAYWRIGHT = '/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright';
const CHROME = '/home/catchplate/.cache/ms-playwright/chromium_headless_shell-1208/chrome-headless-shell-linux64/chrome-headless-shell';
const CHROME_SHA = '27e55cc30e487493b89b663085d6deeb0707be201a568657c922fac9076c317c';
const sha = value => 'sha256:' + crypto.createHash('sha256').update(value).digest('hex');
function requireValue(value) { if (!value) throw new Error('Gmail browser permission check refused'); }
const STAGES = ['inputs', 'launch_browser', 'await_checker', 'open_page', 'await_observer', 'select_account',
  'select_app', 'select_permission', 'review', 'grant', 'await_saved', 'copy_recipe', 'close_browser', 'await_sdk'];
const FAILURES = ['workflow', 'deadline', 'signal', 'request_refused', 'page_error', 'console_error',
  'websocket', 'popup', 'download', 'checker_io', 'checker_frame', 'checker_exit'];
function failureReceipt(stage, code, observations) {
  const count = name => Number.isSafeInteger(observations[name]) && observations[name] >= 0 && observations[name] <= 32 ? observations[name] : null;
  return {schema: 'serverware.privateGmailBrowserFailure/v1', stage: STAGES.includes(stage) ? stage : 'inputs',
    code: FAILURES.includes(code) ? code : 'workflow', postCount: count('postCount'), getCount: count('getCount'),
    pageErrors: count('pageErrors'), consoleErrors: count('consoleErrors'), refusedRequests: count('refusedRequests')};
}
function requestFrame(request, id) {
  const url = new URL(request.url());
  requireValue(url.origin === ORIGIN && !url.username && !url.password && !url.search && !url.hash);
  const method = request.method(), raw = request.postDataBuffer() || Buffer.alloc(0);
  requireValue(method === 'GET' && ['/', CATALOG, INTENTS].includes(url.pathname) && !raw.length ||
    method === 'POST' && url.pathname === GRANT && raw.length > 0 && raw.length <= 4096);
  const headers = Object.fromEntries(Object.entries(request.headers()).filter(([key]) =>
    ['accept', 'content-type', 'origin', 'referer'].includes(key)));
  requireValue(!Object.keys(request.headers()).some(key => /^(authorization|proxy-authorization|cookie|x-serverware-)/.test(key)));
  return {type: 'request', id, method, path: url.pathname, headers, body: raw.toString('base64')};
}
function copiedRecipeFrame(copied, displayed, id) {
  requireValue(typeof copied === 'string' && copied === displayed && !copied.includes('\0')
    && Number.isSafeInteger(id) && id >= 1 && id <= 16);
  const raw = Buffer.from(copied, 'utf8');
  requireValue(raw.length > 0 && raw.length <= 8192 && raw.toString('utf8') === copied);
  return {type: 'done', id, copiedRecipe: raw.toString('base64')};
}

async function main() {
  const [checker, evidence] = process.argv.slice(2);
  requireValue(process.argv.length === 4 && /^[0-9a-f]{64}$/.test(checker) && path.isAbsolute(evidence));
  requireValue(fs.realpathSync(evidence) === evidence && fs.statSync(evidence).isDirectory());
  requireValue(sha(fs.readFileSync(CHROME)) === 'sha256:' + CHROME_SHA);
  requireValue(require(PLAYWRIGHT + '/package.json').version === '1.58.2');
  const target = path.join(evidence, 'gmail-browser');
  fs.mkdirSync(target, {mode: 0o700});
  const {chromium} = require(PLAYWRIGHT);
  let browser, context, child, pending = null, readyResolve, readyReject, resultResolve, resultReject, observerResolve, observerReject;
  let failed = null, buffer = Buffer.alloc(0), total = 0, stderrBytes = 0, sequence = 0;
  let permission, saved, lastCatalog, observedPost = false, chain = Promise.resolve();
  let stage = 'inputs', failure = null, intentGets = 0, catalogGets = 0;
  const observations = {postCount: 0, getCount: 0, pageErrors: 0, consoleErrors: 0,
    refusedRequests: 0, browserClosed: false, steps: [], screenshots: []};
  const ready = new Promise((resolve, reject) => { readyResolve = resolve; readyReject = reject; });
  const result = new Promise((resolve, reject) => { resultResolve = resolve; resultReject = reject; });
  const observer = new Promise((resolve, reject) => { observerResolve = resolve; observerReject = reject; });
  // Mark both promises handled even if startup fails before awaiting either.
  ready.catch(() => {}); result.catch(() => {}); observer.catch(() => {});
  function fail(code = 'workflow') {
    if (failed) return;
    failure = failureReceipt(stage, code, observations);
    failed = new Error('Gmail browser permission check refused');
    readyReject(failed); resultReject(failed); observerReject(failed);
    if (pending) { pending.reject(failed); pending = null; }
  }
  function send(frame) {
    requireValue(!failed && child && !pending && ++sequence === frame.id && sequence <= 16);
    return new Promise((resolve, reject) => {
      pending = {id: frame.id, resolve, reject};
      child.stdin.write(JSON.stringify(frame) + '\n', error => { if (error) fail('checker_io'); });
    });
  }
  const timer = setTimeout(() => fail('deadline'), 180000); // systemd's independent 185s cap owns all descendants.
  const onSignal = () => { fail('signal'); if (browser) browser.close().catch(() => {}); };
  process.once('SIGTERM', onSignal); process.once('SIGINT', onSignal);
  try {
    // Cold browser startup occurs before the checker issues its 90-second token.
    stage = 'launch_browser';
    browser = await chromium.launch({executablePath: CHROME, headless: true, timeout: 10000,
      env: {PATH: '/usr/bin:/bin', LANG: 'C.UTF-8'},
      args: ['--no-sandbox', '--disable-background-networking', '--disable-component-update',
        '--disable-domain-reliability', '--disable-sync', '--no-first-run', '--host-resolver-rules=MAP * ~NOTFOUND']});
    context = await browser.newContext({viewport: {width: 1440, height: 1000}, serviceWorkers: 'block', acceptDownloads: false});
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], {origin: ORIGIN});
    await context.routeWebSocket('**/*', socket => { observations.refusedRequests++; socket.close(); fail('websocket'); });
    await context.route('**/*', route => {
      chain = chain.then(async () => {
        try {
          const frame = requestFrame(route.request(), sequence + 1);
          if (frame.method === 'POST') {
            requireValue(!observedPost); observedPost = true; observations.postCount++;
            observations.requestSha256 = sha(Buffer.from(frame.body, 'base64'));
          } else observations.getCount++;
          const response = await send(frame);
          requireValue(response.type === 'response' && response.status === (frame.method === 'POST' ? 201 : 200)
            && typeof response.body === 'string' && Array.isArray(response.headers));
          const body = Buffer.from(response.body, 'base64');
          requireValue(body.toString('base64') === response.body && body.length > 0 && body.length <= 2 * 1024 ** 2);
          if (frame.path === '/') observations.htmlSha256 = sha(body);
          else if (frame.path === CATALOG) { lastCatalog = JSON.parse(body); catalogGets++; }
          else if (frame.path === INTENTS) { requireValue(++intentGets === 1); }
          else { saved = JSON.parse(body); observations.responseSha256 = sha(body); }
          await route.fulfill({status: response.status, headers: Object.fromEntries(response.headers), body});
          if (frame.path === CATALOG && intentGets === 1 && catalogGets >= 2) observerResolve();
        } catch (_) { observations.refusedRequests++; fail('request_refused'); await route.abort().catch(() => {}); }
      });
      return chain;
    });
    const page = await context.newPage();
    page.setDefaultTimeout(10000);
    page.on('pageerror', () => { observations.pageErrors++; fail('page_error'); });
    page.on('console', message => { if (message.type() === 'error') { observations.consoleErrors++; fail('console_error'); } });
    page.on('popup', popup => { observations.refusedRequests++; popup.close().catch(() => {}); fail('popup'); });
    page.on('download', download => { observations.refusedRequests++; download.cancel().catch(() => {}); fail('download'); });
    stage = 'await_checker';
    child = spawn('/usr/bin/docker', ['start', '--attach', '--interactive', checker], {
      stdio: ['pipe', 'pipe', 'pipe'], env: {PATH: '/usr/bin:/bin', DOCKER_HOST: 'unix:///var/run/docker.sock'}});
    const exited = new Promise(resolve => { child.once('exit', (code, signal) => resolve({code, signal})); });
    child.on('error', () => fail('checker_io'));
    child.stderr.on('data', data => { stderrBytes += data.length; if (stderrBytes > 65536) fail('checker_io'); });
    child.stdout.on('data', data => {
      try {
        total += data.length; requireValue(total <= 8 * 1024 ** 2);
        buffer = Buffer.concat([buffer, data]); requireValue(buffer.length <= 3 * 1024 ** 2);
        while (buffer.includes(10)) {
          const end = buffer.indexOf(10), line = buffer.subarray(0, end); buffer = buffer.subarray(end + 1);
          const frame = JSON.parse(line);
          if (frame.type === 'ready') {
            requireValue(!observations.selectedApplicationId && frame.schema === 'serverware.privateGmailBrowserPermission/v1'
              && /^[0-9a-f-]{36}$/.test(frame.applicationId) && /^[0-9a-f-]{36}$/.test(frame.credentialId));
            observations.selectedApplicationId = frame.applicationId; observations.selectedCredentialId = frame.credentialId;
            readyResolve(frame);
          } else if (frame.type === 'result') {
            requireValue(permission && frame.result?.ok === true); resultResolve(frame.result);
          } else {
            requireValue(pending && frame.id === pending.id && ['response', 'permission'].includes(frame.type));
            const next = pending; pending = null; next.resolve(frame);
          }
        }
      } catch (_) { fail('checker_frame'); }
    });
    child.once('exit', () => { if (!permission) fail('checker_exit'); });
    const identity = await ready;
    stage = 'open_page';
    await page.goto(ORIGIN + '/#connect', {waitUntil: 'domcontentloaded'});
    stage = 'await_observer'; await observer; requireValue(!failed);
    stage = 'select_account';
    await page.locator('#connect-use-saved').click();
    await page.locator('#connect-credential-choice').selectOption(identity.credentialId);
    await page.locator('#connect-credential-next').click(); observations.steps.push('saved_account');
    stage = 'select_app';
    await page.locator('#connect-application-choice').selectOption(identity.applicationId);
    await page.locator('#connect-application-next').click(); observations.steps.push('saved_basic_app');
    stage = 'select_permission';
    await page.locator('#connect-rule-choice').selectOption('new');
    await page.locator('#connect-operation').selectOption('gmail_read_v1');
    requireValue(await page.locator('#connect-gmail-client').inputValue() === 'sdk');
    requireValue(lastCatalog.applications.find(app => app.id === identity.applicationId)?.proxy_authentication === 'basic_and_bearer_v1');
    observations.steps.push('official_sdk_default');
    stage = 'review';
    await page.locator('#connect-review').click();
    requireValue((await page.locator('#connect-review-details').innerText()).includes('Official Gmail SDK · Go example'));
    observations.steps.push('review');
    const screenshot = async name => {
      const raw = await page.screenshot({path: path.join(target, name), fullPage: false});
      observations.screenshots.push({file: name, sha256: sha(raw)});
    };
    await screenshot('review.png');
    stage = 'grant'; requireValue(!failed);
    await page.locator('#connect-grant').click(); observations.steps.push('grant');
    stage = 'await_saved';
    await page.locator('#connect-setup-step').waitFor({state: 'visible'});
    requireValue(saved?.access_rule?.application_id === identity.applicationId
      && saved.access_rule.credential_id === identity.credentialId && saved.access_rule.credential_input === 'replace_exact'
      && saved.access_rule.placeholder === 'Bearer serverware-gmail-placeholder-v1');
    const retained = lastCatalog.access_rules.find(rule => rule.id === saved.access_rule.id);
    requireValue(retained && ['id', 'version', 'application_id', 'credential_id', 'operation_bundle', 'credential_input', 'placeholder']
      .every(key => retained[key] === saved.access_rule[key]) && lastCatalog.revision === saved.revision
      && lastCatalog.policy.policy_hash === saved.policy.policy_hash);
    observations.savedRuleId = saved.access_rule.id; observations.steps.push('saved_setup');
    requireValue(await page.locator('#client-token').inputValue() === '' && await page.locator('#one-time-access').isHidden());
    requireValue(await page.evaluate(() => localStorage.length === 0 && sessionStorage.length === 0));
    await screenshot('saved.png');
    stage = 'copy_recipe';
    await page.locator('#gmail-sdk-client-controls').waitFor({state: 'visible'});
    requireValue(await page.locator('#gmail-client-controls').isHidden()
      && await page.locator('#download-config').isDisabled());
    await page.locator('#ca-path').fill('/client-trust/inner-ca.pem');
    await page.locator('#gmail-proxy-ca-path').fill('/client-trust/outer-ca.pem');
    await page.locator('#copy-command').click();
    await page.locator('#client-copy-status').filter({hasText: /^Copied the Bash recipe for the existing Go Gmail job\./})
      .waitFor({state: 'visible'});
    const copied = await page.evaluate(() => navigator.clipboard.readText());
    const displayed = await page.locator('#client-command').textContent();
    const handoff = copiedRecipeFrame(copied, displayed, sequence + 1);
    observations.copiedRecipeSha256 = sha(Buffer.from(copied, 'utf8'));
    observations.copiedRecipeBytes = Buffer.byteLength(copied, 'utf8');
    observations.steps.push('copy_sdk_recipe');
    await chain;
    stage = 'close_browser';
    await browser.close(); browser = null; observations.browserClosed = true;
    requireValue(handoff.id === sequence + 1);
    const completion = await send(handoff);
    requireValue(completion.type === 'permission'); permission = completion.permission;
    stage = 'await_sdk';
    const sdk = await result, terminal = await exited;
    requireValue(!failed && terminal.code === 0 && terminal.signal === null && buffer.length === 0 && stderrBytes === 0);
    return {schema: 'serverware.privateGmailBrowserSdk/v1', ok: true, browserPermissionVerified: true,
      browserClientHandoffVerified: true,
      syntheticOAuthProgrammatic: true, externalSsoVerified: false, browser: observations, permission, sdk};
  } catch (error) {
    if (!failure) failure = failureReceipt(stage, 'workflow', observations);
    fs.writeFileSync(path.join(target, 'failure.json'), JSON.stringify(failure) + '\n', {flag: 'wx', mode: 0o600});
    throw error;
  } finally {
    clearTimeout(timer); process.removeListener('SIGTERM', onSignal); process.removeListener('SIGINT', onSignal);
    if (browser) await browser.close().catch(() => {});
    if (child && child.exitCode === null) { child.stdin.destroy(); child.kill('SIGTERM'); }
    // The exact systemd unit owns final descendant teardown even if Node exits.
  }
}
module.exports = {requestFrame, failureReceipt, copiedRecipeFrame};
if (require.main === module) main().then(value => process.stdout.write(JSON.stringify(value) + '\n')).catch(() => {
  process.stderr.write('Gmail browser permission check failed; no request or credential details emitted\n'); process.exitCode = 1;
});

#!/usr/bin/env node
// Browser -> byte-preserving stdin transport -> real full ASGI application.
// Root must approve execution and start the pinned network-none container first.
// No synthetic successful API replies, live destinations, CA fetches or native
// ceremonies. This is not browser TCP ingress or deployed acceptance evidence.
const assert = require('node:assert/strict');
const {withoutMutationReview} = require('./operator_mutation_recovery_test_helpers.cjs');
const {createHash} = require('node:crypto');
const {spawn, execFileSync} = require('node:child_process');
const {readFile, writeFile, mkdtemp, realpath, stat} = require('node:fs/promises');
const {join, resolve, isAbsolute} = require('node:path');
const {setTimeout: pause} = require('node:timers/promises');

const ROOT = resolve(__dirname, '..');
const ORIGIN = 'https://console.example.com';
const PREFIX = '/api/operator-demo/notifications';
const STORAGE = 'catchplate.operator.notifications.operation.v1';
const SLOTS = ['action_required.slack', 'action_required.webhook', 'audit_log.slack', 'audit_log.webhook'];
const URLS = {
  'action_required.slack': 'https://hooks.slack.com/services/SYNTHETIC/ACTION/CONNECTED_PRIVATE_ACTION_SLACK',
  'action_required.webhook': 'https://receiver.example.test/notification/CONNECTED_PRIVATE_ACTION_WEBHOOK',
  'audit_log.slack': 'https://hooks.slack.com/services/SYNTHETIC/AUDIT/CONNECTED_PRIVATE_AUDIT_SLACK',
  'audit_log.webhook': 'https://receiver.example.test/notification/CONNECTED_PRIVATE_AUDIT_WEBHOOK',
};
const EVENTS = Object.fromEntries(SLOTS.map(slot => [slot, slot.startsWith('action_required') ? 'approval.requested' :
  slot.endsWith('webhook') ? 'operator_catalog.application.created' : 'operator_catalog.application.revoked']));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HASH = /^[0-9a-f]{64}$/;
const MAX_FRAME = 1024 * 1024;
const NATIVE_OFF = {configured: false, source_available: false, observation_only: true,
  last_observation: {state: 'not_configured', observed_at_epoch_ms: null, phase: null,
    action_available: false, source_expires_at_unix_nanos: null, review_url: null}};
const PRIVATE = [...Object.values(URLS), 'CONNECTED_PRIVATE_', 'synthetic-notification-integration-administrator-token'];
const digest = raw => createHash('sha256').update(raw).digest('hex');
let artifacts;
let stage = 'preflight';
function safeDiagnostic(error, marker) {
  const frames = [];
  const stack = typeof error?.stack === 'string' ? error.stack.slice(0, 32768) : '';
  // Only our fixed source filename and numeric positions survive. In
  // particular, never retain Playwright locator/call-log/message/URL text.
  for (const match of stack.matchAll(/(?:^|\n)\s+at [^\n]*?test_operator_notifications_connected_browser\.cjs:(\d+):(\d+)\)?(?:\n|$)/g)) {
    frames.push({file: 'test_operator_notifications_connected_browser.cjs', line: Number(match[1]), column: Number(match[2])});
  }
  return {stage: /^[a-z0-9_]{1,80}$/.test(marker) ? marker : 'unknown_stage',
    error_name: typeof error?.name === 'string' && /^[A-Za-z][A-Za-z0-9]{0,79}$/.test(error.name) ? error.name : 'UnknownError',
    frames: frames.slice(0, 12)};
}
function routeClass(path) {
  if (path === '/') return 'document';
  if (path === '/api/operator-demo/catalog') return 'catalog';
  if (path === PREFIX) return 'notification_status';
  if (path === PREFIX + '/settings') return 'notification_save';
  if (path === PREFIX + '/test') return 'notification_test';
  if (path === '/api/operator-demo/applications') return 'application_create';
  if (path.startsWith(PREFIX + '/operations/') && UUID.test(path.slice((PREFIX + '/operations/').length))) return 'notification_receipt';
  return 'unclassified';
}
function responseHeaderLookup(headers) {
  return Object.fromEntries(headers.map(([name, value]) => [name.toLowerCase(), value]));
}
function diagnosticsTest() {
  const canary = 'https://private.invalid/CONNECTED_PRIVATE_DIAGNOSTIC locator-secret';
  const error = {name: 'TimeoutError', message: canary,
    stack: 'TimeoutError: ' + canary + '\n    at story (/frozen/scripts/test_operator_notifications_connected_browser.cjs:321:7)\n    at ' + canary};
  assert.deepEqual(safeDiagnostic(error, 'document_navigation'), {stage: 'document_navigation', error_name: 'TimeoutError',
    frames: [{file: 'test_operator_notifications_connected_browser.cjs', line: 321, column: 7}]});
  const unsafe = safeDiagnostic({name: canary, stack: canary}, canary);
  assert.deepEqual(unsafe, {stage: 'unknown_stage', error_name: 'UnknownError', frames: []});
  assert.equal(routeClass('/secret/CONNECTED_PRIVATE_DIAGNOSTIC'), 'unclassified');
  assert.equal(routeClass(PREFIX + '/settings'), 'notification_save');
  cleanValue([safeDiagnostic(error, 'document_navigation'), unsafe]);
  const original = [['Cache-Control', 'no-store'], ['Content-Type', 'application/json'], ['content-length', '2']];
  const encoded = JSON.stringify(original);
  assert.deepEqual(responseHeaderLookup(original), {'cache-control': 'no-store', 'content-type': 'application/json', 'content-length': '2'});
  assert.equal(JSON.stringify(original), encoded, 'lookup must preserve original response header bytes');
  process.stdout.write(JSON.stringify({pure_diagnostic_cases: 7, browser_launched: false}) + '\n');
}
async function bounded(promise, milliseconds, message) {
  let timer;
  try {
    return await Promise.race([promise, new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error(message)), milliseconds);
    })]);
  } finally { clearTimeout(timer); }
}

function options() {
  const values = {};
  for (let index = 2; index < process.argv.length; index += 2) {
    const name = process.argv[index];
    assert(['--container', '--image', '--source-sha256', '--artifact-root', '--playwright-module'].includes(name), 'unknown argument');
    assert(!Object.hasOwn(values, name) && process.argv[index + 1], 'duplicate or absent argument');
    values[name] = process.argv[index + 1];
  }
  assert(HASH.test(values['--container'] || ''), 'exact container ID required');
  assert(/^sha256:[0-9a-f]{64}$/.test(values['--image'] || ''), 'immutable backend image required');
  assert(HASH.test(values['--source-sha256'] || ''), 'frozen complete source digest required');
  assert(isAbsolute(values['--artifact-root'] || '') && values['--artifact-root'].startsWith('/srv/catchplate-fast/'), 'NVMe artifact root required');
  return {container: values['--container'], image: values['--image'], source: values['--source-sha256'],
    artifactRoot: values['--artifact-root'], module: values['--playwright-module'] ||
      '/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright'};
}

function sourceDigest() {
  const output = execFileSync('python3', ['-I', '-B', join(ROOT, 'scripts/test_operator_notifications_connected_backend.py'), '--source-digest'],
    {cwd: ROOT, encoding: 'utf8', timeout: 20000, maxBuffer: 1024}).trim();
  assert(HASH.test(output), 'source hash output');
  return output;
}

function inspectContainer(args) {
  const rows = JSON.parse(execFileSync('docker', ['inspect', '--type', 'container', args.container],
    {encoding: 'utf8', timeout: 5000, maxBuffer: 131072}));
  assert.equal(rows.length, 1);
  const value = rows[0];
  assert.equal(value.Id, args.container); assert.equal(value.Image, args.image); assert.equal(value.State.Running, true);
  assert.equal(value.HostConfig.NetworkMode, 'none'); assert.equal(value.HostConfig.ReadonlyRootfs, true);
  assert.equal(value.HostConfig.Privileged, false); assert(!value.HostConfig.CapAdd?.length);
  assert(value.HostConfig.CapDrop.includes('ALL'));
  assert(value.HostConfig.SecurityOpt.some(item => item === 'no-new-privileges' || item === 'no-new-privileges:true'));
  assert(!Object.keys(value.HostConfig.PortBindings || {}).length);
  assert(value.HostConfig.Memory > 0 && value.HostConfig.Memory <= 1073741824);
  assert.equal(value.HostConfig.MemorySwap, value.HostConfig.Memory);
  assert(value.HostConfig.NanoCpus > 0 && value.HostConfig.NanoCpus <= 1000000000);
  assert(value.HostConfig.PidsLimit > 0 && value.HostConfig.PidsLimit <= 128);
  assert(['catchplate', '10001', '10001:10001'].includes(value.Config.User));
  assert.equal(value.Config.Healthcheck?.Test?.[0], 'NONE', 'disable image healthcheck to prevent unrelated HTTP calls');
  const binds = value.Mounts.filter(item => item.Type === 'bind');
  assert.equal(binds.length, 1); assert.equal(binds[0].Destination, '/app'); assert.equal(binds[0].Source, ROOT); assert.equal(binds[0].RW, false);
  assert(value.Mounts.every(item => item.Type === 'bind' || item.Type === 'tmpfs'));
  assert(Object.hasOwn(value.HostConfig.Tmpfs || {}, '/tmp'));
  assert(value.HostConfig.Tmpfs['/tmp'].includes('size=134217728') || value.HostConfig.Tmpfs['/tmp'].includes('size=128m'));
  return {id: value.Id, image: value.Image, network: 'none', read_only_source: true,
    memory_bytes: value.HostConfig.Memory, nano_cpus: value.HostConfig.NanoCpus, pids_limit: value.HostConfig.PidsLimit};
}

class Bridge {
  constructor(args) {
    this.sequence = 0; this.buffer = Buffer.alloc(0); this.stderrBytes = 0; this.pending = null;
    this.chain = Promise.resolve(); this.failed = null; this.complete = false;
    this.ready = new Promise((resolveReady, rejectReady) => { this.resolveReady = resolveReady; this.rejectReady = rejectReady; });
    // Attach rejection observers immediately; asynchronous route failures are
    // reported by the story, never as secret-bearing uncaught trace output.
    this.ready.catch(() => {});
    this.child = spawn('docker', ['exec', '-i', args.container, 'python', '-I', '-B',
      '/app/scripts/test_operator_notifications_connected_backend.py', '--serve', '--expected-source-digest', args.source],
    {stdio: ['pipe', 'pipe', 'pipe'], env: process.env});
    this.closed = new Promise(resolveClose => this.child.once('close', (code, signal) => {
      this.exit = {code, signal};
      if (!this.complete) this.fail(new Error('backend ended before completion'));
      resolveClose(this.exit);
    }));
    this.child.on('error', () => this.fail(new Error('backend transport launch failed')));
    this.child.stdin.on('error', () => this.fail(new Error('backend input transport failed')));
    this.child.stderr.on('data', data => {
      // Deliberately do not persist arbitrary Python/library errors or URLs.
      this.stderrBytes += data.length;
      if (this.stderrBytes > 65536) this.fail(new Error('backend stderr bound'));
    });
    this.child.stdout.on('data', data => {
      try {
        this.buffer = Buffer.concat([this.buffer, data]);
        assert(this.buffer.length <= MAX_FRAME, 'backend protocol frame bound');
        let newline;
        while ((newline = this.buffer.indexOf(10)) >= 0) {
          const raw = this.buffer.subarray(0, newline); this.buffer = this.buffer.subarray(newline + 1);
          const value = JSON.parse(raw.toString('utf8'));
          if (value.type === 'failed') {
            this.backendFailure = {error_type: /^[A-Za-z]{1,80}$/.test(value.error_type) ? value.error_type : 'unknown',
              frames: Array.isArray(value.frames) ? value.frames.filter(frame => /^[A-Za-z0-9_.-]+$/.test(frame.file) &&
                Number.isInteger(frame.line) && /^[A-Za-z0-9_<>]+$/.test(frame.function)).slice(-12) : [],
              lifespan_frames: Array.isArray(value.lifespan_frames) ? value.lifespan_frames.filter(frame =>
                Array.isArray(frame) && frame.length === 3 && /^\/app\/[A-Za-z0-9_./-]+\.py$/.test(frame[0]) &&
                /^\d+$/.test(frame[1]) && /^[A-Za-z0-9_<>]+$/.test(frame[2])).slice(-12) : []};
            throw new Error('actual backend acceptance failed');
          }
          if (value.type === 'ready') { assert(!this.receivedReady); this.receivedReady = value; this.resolveReady(value); }
          else {
            assert(this.pending && value.id === this.pending.id, 'backend response identity');
            if (value.type === 'complete') this.complete = true;
            const pending = this.pending; this.pending = null; clearTimeout(pending.timer); pending.resolve(value);
          }
        }
      } catch (_) { this.fail(new Error('backend protocol failed')); }
    });
  }
  fail(error) {
    if (this.failed) return;
    this.failed = error; this.rejectReady(error);
    if (this.pending) { clearTimeout(this.pending.timer); this.pending.reject(error); this.pending = null; }
  }
  call(value) {
    const work = this.chain.then(() => {
      if (this.failed) throw this.failed;
      const id = ++this.sequence;
      assert(id <= 200, 'protocol message budget');
      return new Promise((resolveCall, rejectCall) => {
        this.pending = {id, resolve: resolveCall, reject: rejectCall,
          timer: setTimeout(() => this.fail(new Error('backend response timeout')), 30000)};
        const raw = Buffer.from(JSON.stringify({id, ...value}) + '\n');
        assert(raw.length <= MAX_FRAME, 'frontend protocol frame bound');
        this.child.stdin.write(raw);
      });
    });
    this.chain = work.catch(() => {});
    return work;
  }
  async close() {
    this.child.stdin.end();
    const exited = await bounded(this.closed, 30000, 'backend shutdown timeout').catch(() => null);
    if (!exited) {
      this.child.kill('SIGTERM');
      await bounded(this.closed, 2000, 'transport stop timeout').catch(() => {});
      throw new Error('transport cleanup incomplete; root must stop exact isolated container');
    }
    return exited;
  }
}

function cleanValue(value) {
  const raw = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of PRIVATE) assert(!raw.includes(secret), 'private fixture value exposed');
}

async function cleanPage(page) {
  const surfaces = await page.evaluate(() => ({html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].map(item => item.value),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  cleanValue(surfaces); assert.deepEqual(surfaces.local, []);
  const references = withoutMutationReview(surfaces.session);
  assert(references.every(([key]) => key === STORAGE));
  for (const [, value] of references) {
    const ref = JSON.parse(value);
    assert.deepEqual(Object.keys(ref).sort(), ['operation_id', 'kind', 'slot', 'expected_revision'].sort());
    assert(UUID.test(ref.operation_id) && ['save', 'test'].includes(ref.kind) && SLOTS.includes(ref.slot));
    assert(Number.isSafeInteger(ref.expected_revision));
  }
  for (const input of await page.locator('input[name="url"]').all()) {
    assert.equal(await input.getAttribute('type'), 'password'); assert.equal(await input.inputValue(), '');
  }
}

const form = (page, slot) => page.locator('form[data-notification-slot="' + slot + '"]');
async function settled(page) {
  await page.waitForLoadState('networkidle', {timeout: 15000});
  await page.waitForFunction(() => !document.getElementById('notifications-refresh').disabled, null, {timeout: 15000});
}
async function checkReceipt(page) {
  await page.locator('#notification-check-operation').click(); await settled(page); await cleanPage(page);
}
async function screenshot(page, name) {
  await cleanPage(page); await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true});
}

async function story(args, bridge, browser, evidence) {
  stage = 'browser_context';
  const diagnostics = evidence.browser_diagnostics = {route_errors: [], page_errors: [], console_errors: 0,
    completed_http_requests: 0, post_count: 0};
  const context = await browser.newContext({viewport: {width: 1440, height: 1100}, serviceWorkers: 'block', acceptDownloads: false});
  const state = {requests: [], posts: [], receipts: new Map(), notifications: null, errors: [], stopped: false, documents: []};
  const page = await context.newPage();
  page.setDefaultTimeout(15000);
  page.on('pageerror', error => { state.errors.push('pageerror'); if (diagnostics.page_errors.length < 8) diagnostics.page_errors.push(safeDiagnostic(error, 'page_javascript')); });
  page.on('console', message => { if (message.type() === 'error') { state.errors.push('console_error'); diagnostics.console_errors++; } });
  page.on('download', () => state.errors.push('unexpected_download'));
  page.on('popup', popup => { state.errors.push('unexpected_popup'); popup.close().catch(() => {}); });
  page.on('dialog', dialog => {
    if (dialog.type() === 'confirm' && dialog.message() === 'Clear the one-time token from this page? It cannot be retrieved again.') dialog.accept();
    else { state.errors.push('unexpected_dialog'); dialog.dismiss(); }
  });
  await context.route('**/*', async route => {
    let routeStage = 'request_admission'; let classification = 'unclassified'; let observedMethod = 'other'; let observedStatus = null;
    try {
      assert(!state.stopped, 'route after story stop');
      const request = route.request(); const url = new URL(request.url());
      assert.equal(url.origin, ORIGIN); assert.equal(url.search, ''); assert(!url.username && !url.password);
      const path = url.pathname; const method = request.method(); const body = request.postDataBuffer() || Buffer.alloc(0);
      classification = routeClass(path); observedMethod = ['GET', 'POST'].includes(method) ? method : 'other';
      const receipt = path.startsWith(PREFIX + '/operations/') && UUID.test(path.slice((PREFIX + '/operations/').length));
      assert(method === 'GET' && (['/', '/api/operator-demo/catalog', PREFIX].includes(path) || receipt) ||
        method === 'POST' && [PREFIX + '/settings', PREFIX + '/test', '/api/operator-demo/applications'].includes(path), 'browser route refused');
      assert(body.length <= (method === 'POST' ? 16384 : 0));
      routeStage = 'browser_headers';
      const browserHeaders = await request.allHeaders();
      assert(!browserHeaders.authorization && !browserHeaders['x-catchplate-admin-token'] && !browserHeaders.cookie,
        'administrator transport credential must not enter browser');
      const headers = Object.entries(browserHeaders).filter(([key]) => ['origin', 'content-type', 'content-length', 'accept', 'referer'].includes(key));
      if (method === 'POST') {
        routeStage = 'mutation_recovery_reference';
        assert.equal(browserHeaders.origin, ORIGIN); assert.equal(browserHeaders['content-type'], 'application/json');
        const input = JSON.parse(body.toString());
        if (path.startsWith(PREFIX)) {
          const ref = await request.frame().evaluate(key => JSON.parse(sessionStorage.getItem(key)), STORAGE);
          assert.deepEqual(ref, {operation_id: input.operation_id, kind: path.endsWith('/test') ? 'test' : 'save',
            slot: input.slot, expected_revision: input.expected_revision}, 'public recovery reference must precede POST');
          assert(!state.posts.some(item => item.operation_id === input.operation_id), 'operation must not replay');
          state.posts.push({path, ...ref});
        } else state.posts.push({path});
        diagnostics.post_count = state.posts.length;
      }
      assert(state.requests.length < 100, 'browser request budget');
      routeStage = 'forward_actual_http';
      const response = await bridge.call({op: 'http', method, path, headers, body_b64: body.toString('base64')});
      observedStatus = Number.isInteger(response.status) && response.status >= 100 && response.status <= 599 ? response.status : null;
      routeStage = 'response_shape';
      assert.equal(response.type, 'http');
      const raw = Buffer.from(response.body_b64, 'base64'); assert.equal(raw.toString('base64'), response.body_b64);
      const responseHeaders = Object.fromEntries(response.headers);
      const lookup = responseHeaderLookup(response.headers);
      routeStage = 'response_status';
      assert.equal(response.status, method === 'POST' && path.endsWith('/applications') ? 201 : method === 'POST' && path.endsWith('/test') ? 202 : 200,
        'actual application refused a story request');
      routeStage = 'response_framing';
      assert.equal(lookup['content-length'], String(raw.length), 'actual response framing');
      routeStage = 'response_public_scan';
      cleanValue(raw.toString());
      state.requests.push({method, path, status: response.status, response_sha256: digest(raw)});
      diagnostics.completed_http_requests = state.requests.length;
      routeStage = 'response_content_type';
      if (path === '/') {
        assert(lookup['content-type'].includes('text/html')); state.documents.push(digest(raw));
      } else {
        assert(lookup['content-type'].includes('application/json')); assert.equal(lookup['cache-control'], 'no-store');
        const data = JSON.parse(raw.toString());
        if (path === PREFIX) {
          routeStage = 'notification_status_contract';
          assert.equal(data.schema, 'catchplate.operatorNotifications/v1'); assert.equal(data.available, true);
          assert.deepEqual(data.capabilities.native_hardware, NATIVE_OFF);
          assert.equal(data.capabilities.action_required.source_available, false);
          assert.equal(data.capabilities.audit_log.source_available, true);
          assert.equal(data.worker.state, 'running');
          state.notifications = data;
        } else if (path.startsWith(PREFIX + '/')) {
          routeStage = 'notification_receipt_contract';
          assert.equal(data.schema, 'catchplate.operatorNotificationOperation/v1');
          state.receipts.set(data.operation_id, data);
        } else if (path === '/api/operator-demo/applications') {
          routeStage = 'application_receipt_contract';
          assert.equal(typeof data.client_token, 'string'); assert(data.client_token.length >= 32);
          PRIVATE.push(data.client_token); state.applicationId = data.application.id;
        }
      }
      // No JSON rewriting, synthetic response selection or application-handler
      // bypass: these are the exact actual ASGI body bytes and response headers.
      routeStage = 'fulfill_exact_response';
      await route.fulfill({status: response.status, headers: responseHeaders, body: raw});
    } catch (error) {
      state.errors.push('route_or_actual_application_failed');
      if (diagnostics.route_errors.length < 8) diagnostics.route_errors.push({...safeDiagnostic(error, routeStage),
        path_class: classification, method: observedMethod, status: observedStatus});
      await route.abort('failed').catch(() => {});
    }
  });
  try {
    stage = 'document_navigation';
    await page.goto(ORIGIN + '/#notifications', {waitUntil: 'networkidle'});
    stage = 'catalog_readiness';
    await page.waitForFunction(() => !document.querySelector('#credential-fields').disabled);
    stage = 'initial_notification_view';
    await settled(page);
    assert.equal(await page.locator('form[data-notification-slot]').count(), 4);
    assert.equal(state.posts.length, 0); assert(state.notifications.slots.every(slot => slot.revision === 0));
    assert.match(await page.locator('#notifications-worker').innerText(), /running/i);
    assert.match(await page.locator('[data-native-source]').innerText(), /not configured/i);
    assert.equal(await page.locator('[data-native-review]').getAttribute('href'), null);
    assert.equal(await page.locator('[data-notification-native] button').count(), 0);
    for (const slot of SLOTS) {
      stage = 'save_' + slot.replace('.', '_');
      const target = form(page, slot);
      await target.locator('[name="label"]').fill('Connected ' + slot);
      await target.locator('[name="enabled"]').check();
      await target.locator('[name="url_action"]').selectOption('replace');
      await target.locator('[name="url"]').fill(URLS[slot]);
      const details = target.locator('details');
      if (!await details.evaluate(node => node.open)) await details.locator('summary').click();
      await target.locator('[name="event_types"][value="' + EVENTS[slot] + '"]').check();
      await target.locator('[name="max_attempts"]').selectOption('1');
      await target.locator('[data-notification-save]').click(); await settled(page); await cleanPage(page);
      assert.match(await form(page, slot).locator('[data-slot-revision]').innerText(), /Saved revision: 1$/);
      assert.equal(state.posts.length, SLOTS.indexOf(slot) + 1);
      assert.equal(state.receipts.get(state.posts.at(-1).operation_id).status, 'saved');
      for (const other of state.notifications.slots) assert.equal(other.revision, SLOTS.indexOf(other.slot) <= SLOTS.indexOf(slot) ? 1 : 0);
    }
    stage = 'inspect_saved_destinations';
    evidence.saved = await bridge.call({op: 'inspect', phase: 'saved'});
    stage = 'saved_destinations_screenshot';
    await screenshot(page, 'four-real-saved-destinations');

    stage = 'reload_saved_destinations';
    await page.reload({waitUntil: 'networkidle'}); await settled(page); await cleanPage(page);
    assert.equal(state.posts.length, 4);
    for (const button of await page.locator('[data-notification-save],[data-notification-test]').all()) assert(await button.isDisabled());
    assert.match(await page.locator('#notification-operation-status').innerText(), /unconfirmed/i);
    stage = 'check_saved_receipt_after_reload';
    await checkReceipt(page);
    for (const slot of SLOTS) {
      assert.equal(await form(page, slot).locator('[name="label"]').inputValue(), 'Connected ' + slot);
      assert.match(await form(page, slot).locator('[data-slot-revision]').innerText(), /Saved revision: 1$/);
      assert.equal(await form(page, slot).locator('[name="url"]').inputValue(), '');
    }
    stage = 'explicit_saved_revision_test';
    await form(page, SLOTS[0]).locator('[data-notification-test]').click(); await settled(page);
    assert.equal(state.posts.length, 5);
    const test = state.posts[4]; assert.equal(test.kind, 'test'); assert.equal(test.slot, SLOTS[0]); assert.equal(test.expected_revision, 1);
    const acknowledgementDeadline = Date.now() + 15000;
    stage = 'wait_actual_test_acknowledgement';
    do {
      await checkReceipt(page);
      if (state.receipts.get(test.operation_id).status === 'acknowledged') break;
      assert(Date.now() < acknowledgementDeadline, 'real worker test acknowledgement deadline');
      await pause(300);
    } while (true);
    assert.match(await page.locator('#notification-operation-status').innerText(), /Destination acknowledged delivery/);
    assert.match(await page.locator('#notification-operation-status').innerText(), /not human approval/);
    stage = 'inspect_test_delivery';
    evidence.tested = await bridge.call({op: 'inspect', phase: 'tested'});
    assert.equal(evidence.tested.deliveries[0].delivery_id, state.receipts.get(test.operation_id).delivery_id);
    assert.equal(evidence.tested.deliveries[0].source_event_id, 'test:' + test.operation_id);
    stage = 'test_acknowledgement_screenshot';
    await screenshot(page, 'real-saved-revision-test-acknowledged');

    stage = 'create_audit_source_application';
    await page.locator('nav a[href="#applications"]').click();
    await page.locator('#application-name').fill('Connected notification audit source');
    await page.locator('#application-token-ttl').selectOption('3600');
    await page.locator('#application-create').click();
    await page.locator('#one-time-access').waitFor({state: 'visible'});
    stage = 'dismiss_one_time_application_token';
    await page.locator('#dismiss-token').click();
    await page.waitForFunction(() => document.querySelector('#client-token').value === '' && document.querySelector('#one-time-access').hidden);
    assert.equal(state.posts.length, 6); assert(UUID.test(state.applicationId));
    await page.locator('nav a[href="#notifications"]').click();
    const auditDeadline = Date.now() + 15000;
    stage = 'wait_actual_audit_acknowledgement';
    do {
      await page.locator('#notifications-refresh').click(); await settled(page);
      if (state.notifications.slots.find(slot => slot.slot === 'audit_log.webhook').last_delivery?.status === 'acknowledged') break;
      assert(Date.now() < auditDeadline, 'real worker audit acknowledgement deadline');
      await pause(300);
    } while (true);
    assert.match(await form(page, 'audit_log.webhook').innerText(), /Destination acknowledged delivery/);
    assert.equal(state.notifications.slots.find(slot => slot.slot === 'action_required.webhook').last_delivery, null);
    assert.equal(state.notifications.slots.find(slot => slot.slot === 'audit_log.slack').last_delivery, null);
    assert.equal(state.notifications.queue.acknowledged, 2);
    assert.equal(Object.values(state.notifications.queue).reduce((sum, count) => sum + count, 0), 2);
    stage = 'inspect_final_deliveries';
    evidence.completed = await bridge.call({op: 'inspect', phase: 'complete'});
    stage = 'final_delivery_screenshots';
    await screenshot(page, 'real-audit-channel-only-delivery');
    await page.setViewportSize({width: 390, height: 844});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth + 1), 'mobile horizontal overflow');
    await screenshot(page, 'mobile-real-notification-results');
    stage = 'final_browser_assertions';
    assert.deepEqual(state.errors, []);
    assert.equal(state.documents.length, 2); assert.equal(state.documents[0], state.documents[1], 'reload must preserve exact rendered production HTML');
    evidence.browser = {requests: state.requests, mutations: state.posts, application_id: state.applicationId,
      actual_html_sha256: state.documents[0], errors: [], reload_without_url_exposure: true,
      public_recovery_reference_before_posts: true, no_automatic_post_replay: true, native_source_configured: false};
  } finally {
    state.stopped = true;
    await context.close();
  }
}

async function main() {
  const args = options();
  assert.equal(await realpath(ROOT), ROOT); assert((await stat(args.artifactRoot)).isDirectory());
  assert.equal(sourceDigest(), args.source);
  const container = inspectContainer(args);
  artifacts = await mkdtemp(join(args.artifactRoot, 'notifications-connected-'));
  const evidence = {schema: 'catchplate.notificationConnectedBrowserAcceptance/v1', container, source_sha256: args.source,
    boundary: 'Host Chromium via byte-preserving stdin ASGI transport, actual full-app lifespan, isolated SQLite and verified synthetic TLS; not TCP ingress, deployed delivery or native action acceptance.'};
  let bridge, browser, timeout;
  try {
    stage = 'backend_startup';
    bridge = new Bridge(args);
    const ready = await bounded(bridge.ready, 60000, 'full-app startup timeout');
    assert.equal(ready.source_digest, args.source); assert.equal(ready.full_asgi_app, true); assert.equal(ready.lifespan_started, true);
    assert.deepEqual(ready.real_admin_origin_refusals, [401, 403]); evidence.backend_startup = ready;
    stage = 'browser_module_load';
    const {chromium} = require(args.module);
    stage = 'browser_launch';
    browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking',
      '--disable-component-update', '--disable-default-apps', '--disable-sync', '--metrics-recording-only',
      '--no-first-run', '--host-resolver-rules=MAP * ~NOTFOUND']});
    await Promise.race([story(args, bridge, browser, evidence), new Promise((_, reject) => {
      timeout = setTimeout(() => reject(new Error('connected story exceeded 180 seconds')), 180000);
    })]);
    clearTimeout(timeout);
    stage = 'browser_shutdown';
    await browser.close(); browser = null;
    stage = 'backend_shutdown';
    evidence.shutdown = await bridge.call({op: 'shutdown'});
    assert.equal(evidence.shutdown.type, 'complete'); assert.equal(evidence.shutdown.notification_worker_stopped, true);
    assert.equal(evidence.shutdown.lifespan_stopped, true); assert.equal(evidence.shutdown.receiver_stopped, true);
    const exited = await bridge.close(); assert.deepEqual(exited, {code: 0, signal: null});
    stage = 'final_source_and_container_identity';
    assert.equal(sourceDigest(), args.source); inspectContainer(args);
    evidence.ok = true; evidence.transport_exit = exited;
    cleanValue(evidence);
    await writeFile(join(artifacts, 'acceptance.json'), JSON.stringify(evidence, null, 2) + '\n', {mode: 0o600});
    process.stdout.write(JSON.stringify({ok: true, artifacts, browser_mutations: 6, verified_tls_deliveries: 2, source_sha256: args.source}) + '\n');
  } catch (error) {
    evidence.ok = false;
    evidence.failure = {kind: 'connected_acceptance_failed', backend: bridge?.backendFailure || null,
      browser: safeDiagnostic(error, stage), root_cleanup_required: true};
    cleanValue(evidence);
    await writeFile(join(artifacts, 'failure.json'), JSON.stringify(evidence, null, 2) + '\n', {mode: 0o600});
    process.stderr.write(JSON.stringify({ok: false, artifacts, failure: evidence.failure}) + '\n');
    process.exitCode = 1;
  } finally {
    clearTimeout(timeout);
    if (browser) await browser.close().catch(() => {});
    if (bridge && !bridge.exit) await bridge.close().catch(() => { process.exitCode = 1; });
  }
}

if (process.argv.length === 3 && process.argv[2] === '--diagnostics-test') diagnosticsTest();
else main().catch(error => {
  process.stderr.write(JSON.stringify({ok: false, preflight: safeDiagnostic(error, stage)}) + '\n'); process.exitCode = 1;
});

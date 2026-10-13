#!/usr/bin/env node
// One actual browser form -> byte-preserving stdin -> real full ASGI story.
// No provider, restart, synthetic successful API response or deployed-TCP claim.
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const {spawn, execFileSync} = require('node:child_process');
const {mkdtemp, writeFile, realpath, stat} = require('node:fs/promises');
const {join, resolve, isAbsolute} = require('node:path');

const ROOT = resolve(__dirname, '..');
const BACKEND = 'test_operator_google_configuration_connected_backend.py';
const ORIGIN = 'https://console.example.com';
const PREFIX = '/api/operator-demo/oauth/google/configuration/v2';
const CATALOG = '/api/operator-demo/catalog';
const STORAGE = 'serverware.operator.google.configuration.operation.v2';
const CLIENT = '123-connected-configuration.apps.googleusercontent.com';
const SECRET = 'synthetic-connected-Google-application-secret-NEVER-RETAIN';
const ADMIN = 'synthetic-connected-Google-configuration-administrator';
const PLAYWRIGHT = '/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright';
const HASH = /^[0-9a-f]{64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_FRAME = 1024 * 1024;
const sha = raw => createHash('sha256').update(raw).digest('hex');
const node = (page, name) => page.locator('#google-configuration-' + name);

function clean(value) {
  const raw = typeof value === 'string' ? value : JSON.stringify(value);
  for (const secret of [SECRET, ADMIN]) assert(!raw.includes(secret), 'private fixture material exposed');
}
function diagnostic(error, stage) {
  const frames = [];
  for (const match of String(error?.stack || '').slice(0, 32768).matchAll(/test_operator_google_configuration_connected_browser\.cjs:(\d+):(\d+)/g))
    frames.push({line: Number(match[1]), column: Number(match[2])});
  return {stage: /^[a-z_]{1,80}$/.test(stage) ? stage : 'unknown',
    name: /^[A-Za-z]{1,80}$/.test(error?.name || '') ? error.name : 'Error', frames: frames.slice(0, 12)};
}
async function bounded(promise, milliseconds) {
  let timer;
  try { return await Promise.race([promise, new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('bounded fixture deadline exceeded')), milliseconds);
  })]); } finally { clearTimeout(timer); }
}
function validateOptions(options) {
  assert(options && Object.keys(options).every(key => ['container', 'image', 'source', 'artifactRoot', 'module'].includes(key)));
  assert(HASH.test(options.container || ''));
  assert(/^sha256:[0-9a-f]{64}$/.test(options.image || ''));
  assert(HASH.test(options.source || ''));
  assert(isAbsolute(options.artifactRoot || '') && options.artifactRoot.startsWith('/srv/catchplate-fast/'));
  return {...options, module: options.module || PLAYWRIGHT};
}
function sourceDigest() {
  const output = execFileSync('python3', ['-I', '-B', join(ROOT, 'scripts', BACKEND), '--source-digest'],
    {cwd: ROOT, encoding: 'utf8', timeout: 20000, maxBuffer: 1024}).trim();
  assert(HASH.test(output)); return output;
}
function inspectContainer(options) {
  const rows = JSON.parse(execFileSync('docker', ['inspect', '--type', 'container', options.container],
    {encoding: 'utf8', timeout: 5000, maxBuffer: 131072}));
  assert.equal(rows.length, 1); const value = rows[0], host = value.HostConfig;
  assert.equal(value.Id, options.container); assert.equal(value.Image, options.image); assert(value.State.Running);
  assert.equal(host.NetworkMode, 'none'); assert.equal(host.ReadonlyRootfs, true); assert.equal(host.Privileged, false);
  assert(!host.CapAdd?.length && host.CapDrop.includes('ALL'));
  assert(host.SecurityOpt.some(item => ['no-new-privileges', 'no-new-privileges:true'].includes(item)));
  assert(!Object.keys(host.PortBindings || {}).length);
  assert(host.Memory > 0 && host.Memory <= 1073741824 && host.MemorySwap === host.Memory);
  assert(host.NanoCpus > 0 && host.NanoCpus <= 1000000000 && host.PidsLimit > 0 && host.PidsLimit <= 128);
  assert(['serverware', '10001', '10001:10001'].includes(value.Config.User));
  assert.equal(value.Config.Healthcheck?.Test?.[0], 'NONE');
  const binds = value.Mounts.filter(item => item.Type === 'bind');
  assert.equal(binds.length, 1); assert.equal(binds[0].Destination, '/app');
  assert.equal(binds[0].Source, ROOT); assert.equal(binds[0].RW, false);
  assert(value.Mounts.every(item => item.Type === 'bind' || item.Type === 'tmpfs'));
  assert(/size=(?:134217728|128m)(?:,|$)/.test(host.Tmpfs?.['/tmp'] || ''));
  return {id: value.Id, image: value.Image, network: 'none', read_only_source: true,
    memory_bytes: host.Memory, nano_cpus: host.NanoCpus, pids_limit: host.PidsLimit};
}

class Bridge {
  constructor(options) {
    this.sequence = 0; this.buffer = Buffer.alloc(0); this.stderrBytes = 0; this.chain = Promise.resolve();
    this.ready = new Promise((resolveReady, rejectReady) => { this.resolveReady = resolveReady; this.rejectReady = rejectReady; });
    this.ready.catch(() => {});
    this.child = spawn('docker', ['exec', '-i', options.container, 'python', '-I', '-B', '/app/scripts/' + BACKEND,
      '--serve', '--expected-source-digest', options.source], {stdio: ['pipe', 'pipe', 'pipe'], env: process.env});
    this.closed = new Promise(resolveClose => this.child.once('close', (code, signal) => {
      this.exit = {code, signal};
      if (!this.complete) this.fail(new Error('backend ended before completion'));
      resolveClose(this.exit);
    }));
    this.child.on('error', () => this.fail(new Error('backend launch failed')));
    this.child.stdin.on('error', () => this.fail(new Error('backend input failed')));
    this.child.stderr.on('data', data => { this.stderrBytes += data.length;
      if (this.stderrBytes > 65536) this.fail(new Error('backend diagnostic bound')); });
    this.child.stdout.on('data', data => {
      try {
        this.buffer = Buffer.concat([this.buffer, data]); assert(this.buffer.length <= MAX_FRAME);
        let end;
        while ((end = this.buffer.indexOf(10)) >= 0) {
          const raw = this.buffer.subarray(0, end); this.buffer = this.buffer.subarray(end + 1);
          const value = JSON.parse(raw.toString('utf8')); clean(value);
          if (value.type === 'failed') {
            this.backendFailure = {error_type: /^[A-Za-z]{1,80}$/.test(value.error_type) ? value.error_type : 'Error',
              frames: Array.isArray(value.frames) ? value.frames.filter(frame => /^[A-Za-z0-9_.-]+$/.test(frame.file)
                && Number.isInteger(frame.line) && /^[A-Za-z0-9_<>]+$/.test(frame.function)).slice(-12) : []};
            throw new Error('actual backend failed');
          }
          if (value.type === 'ready') { assert(!this.receivedReady); this.receivedReady = value; this.resolveReady(value); }
          else {
            assert(this.pending && this.pending.id === value.id);
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
    const result = this.chain.then(() => {
      if (this.failed) throw this.failed;
      const id = ++this.sequence; assert(id <= 80);
      return new Promise((resolveCall, rejectCall) => {
        this.pending = {id, resolve: resolveCall, reject: rejectCall,
          timer: setTimeout(() => this.fail(new Error('backend response deadline')), 30000)};
        const raw = Buffer.from(JSON.stringify({id, ...value}) + '\n'); assert(raw.length <= MAX_FRAME);
        this.child.stdin.write(raw);
      });
    });
    this.chain = result.catch(() => {}); return result;
  }
  async close() {
    this.child.stdin.end();
    try { return await bounded(this.closed, 30000); }
    catch (_) { this.child.kill('SIGTERM'); await bounded(this.closed, 2000).catch(() => {});
      throw new Error('root must stop exact isolated container'); }
  }
}

async function noMaterial(page, draft = false) {
  const value = await page.evaluate(() => ({html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].map(item => ({id: item.id, value: item.value})),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  clean(value.html); assert.deepEqual(value.local, []);
  for (const item of value.fields) if (!(draft && item.id === 'google-configuration-client-secret')) clean(item.value);
  assert(value.session.length <= 1);
  for (const [key, raw] of value.session) {
    assert.equal(key, STORAGE); clean(raw); assert(!raw.includes(CLIENT));
    const ref = JSON.parse(raw); assert.deepEqual(Object.keys(ref).sort(), ['kind', 'operation_id']);
    assert(UUID.test(ref.operation_id) && ['prepare', 'cancel'].includes(ref.kind));
  }
  return value.session.length ? JSON.parse(value.session[0][1]) : null;
}

async function story(context, bridge, directory, evidence, progress) {
  const page = await context.newPage(); page.setDefaultTimeout(15000);
  const observed = {requests: [], posts: [], documents: [], errors: [], operation: null, discovery: null};
  const diagnose = error => { if (observed.errors.length < 8) observed.errors.push(diagnostic(error, progress.stage)); };
  page.on('pageerror', diagnose);
  page.on('console', message => { if (message.type() === 'error') diagnose(new Error('console error')); });
  page.on('download', () => diagnose(new Error('unexpected download')));
  page.on('popup', popup => { diagnose(new Error('unexpected popup')); popup.close().catch(() => {}); });
  page.on('dialog', dialog => { diagnose(new Error('unexpected dialog')); dialog.dismiss(); });
  await context.route('**/*', async route => {
    try {
      const request = route.request(), url = new URL(request.url()), method = request.method(), path = url.pathname;
      assert.equal(url.origin, ORIGIN); assert.equal(url.search, ''); assert(!url.username && !url.password);
      const receipt = path.startsWith(PREFIX + '/') && UUID.test(path.slice(PREFIX.length + 1));
      assert(method === 'GET' && (['/', CATALOG, PREFIX].includes(path) || receipt)
        || method === 'POST' && [PREFIX, PREFIX + '/cancel'].includes(path));
      const body = request.postDataBuffer() || Buffer.alloc(0); assert(body.length <= (method === 'POST' ? 8192 : 0));
      const allHeaders = await request.allHeaders();
      assert(!allHeaders.cookie && !allHeaders.authorization && !allHeaders['x-serverware-admin-token']);
      const headers = Object.entries(allHeaders).filter(([key]) => ['origin', 'content-type', 'content-length', 'accept', 'referer'].includes(key));
      if (method === 'POST') {
        assert.equal(allHeaders.origin, ORIGIN); assert.equal(allHeaders['content-type'], 'application/json');
        const input = JSON.parse(body.toString('utf8')), kind = path === PREFIX ? 'prepare' : 'cancel';
        const ref = await noMaterial(page);
        assert.deepEqual(ref, {operation_id: input.operation_id, kind});
        assert.equal(await node(page, 'client-secret').inputValue(), '', 'write-only secret clears before dispatch');
        assert.equal(input.expected_revision, observed.discovery.revision);
        assert.equal(input.expected_policy_hash, observed.discovery.policy_hash);
        assert.equal(observed.posts.length, kind === 'prepare' ? 0 : 1, 'no automatic replay');
        if (kind === 'prepare') {
          assert.deepEqual(Object.keys(input).sort(), ['client_id', 'client_secret', 'expected_policy_hash', 'expected_revision', 'expected_settings_digest', 'operation_id']);
          assert.equal(input.client_id, CLIENT); assert.equal(input.client_secret, SECRET);
          assert.equal(input.expected_settings_digest, observed.discovery.effective_settings_digest);
        } else {
          assert.deepEqual(Object.keys(input).sort(), ['expected_policy_hash', 'expected_revision', 'operation_id']);
          assert.equal(input.operation_id, observed.operation.operation_id);
        }
        observed.posts.push({...ref, expected_revision: input.expected_revision, expected_policy_hash: input.expected_policy_hash});
      }
      assert(observed.requests.length < 60);
      const response = await bridge.call({op: 'http', method, path, headers, body_b64: body.toString('base64')});
      assert.equal(response.type, 'http'); const raw = Buffer.from(response.body_b64, 'base64');
      assert.equal(raw.toString('base64'), response.body_b64); clean(raw.toString('utf8'));
      assert.equal(response.status, method === 'POST' && path === PREFIX ? 201 : 200);
      const lookup = Object.fromEntries(response.headers.map(([key, value]) => [key.toLowerCase(), value]));
      assert.equal(lookup['content-length'], String(raw.length));
      observed.requests.push({method, path, status: response.status, response_sha256: sha(raw)});
      if (path === '/') { assert(lookup['content-type'].includes('text/html')); observed.documents.push(sha(raw)); }
      else {
        assert(lookup['content-type'].includes('application/json')); assert.equal(lookup['cache-control'], 'no-store');
        const value = JSON.parse(raw.toString('utf8'));
        if (path === PREFIX && method === 'GET') {
          assert.equal(value.schema, 'serverware.operatorGoogleConfiguration/v2'); assert.equal(value.readiness.consent_ready, false);
          observed.discovery = value;
        } else if (path.startsWith(PREFIX)) observed.operation = value;
      }
      // Only actual ASGI bytes/status/headers: never fabricate an HTTP success.
      await route.fulfill({status: response.status, headers: Object.fromEntries(response.headers), body: raw});
    } catch (error) { diagnose(error); await route.abort('failed').catch(() => {}); }
  });
  const act = async (control, method, path) => {
    const before = observed.requests.length;
    // Install the exact response observation before dispatch. An already-idle
    // navigation cannot satisfy this boundary, even when the click is fast.
    const completed = page.waitForResponse(response => response.url() === ORIGIN + path
      && response.request().method() === method, {timeout: 30000});
    await Promise.all([completed, node(page, control).click()]);
    await page.waitForFunction(() => document.readyState === 'complete'
      && document.querySelector('#google-configuration-review')?.disabled === false);
    assert(observed.requests.slice(before).some(item => item.method === method && item.path === path),
      'controller action must complete its exact real ASGI request');
  };
  const pendingDOM = () => page.waitForFunction(() => {
    const status = document.querySelector('#google-configuration-operation-status')?.textContent || '';
    return /prepared|pending/i.test(status) && /restart/i.test(status)
      && document.querySelector('#google-configuration-prepare')?.disabled === true
      && document.querySelector('#google-configuration-client-secret')?.value === '';
  });
  const screenshot = async name => { await noMaterial(page); await page.screenshot({path: join(directory, name + '.png'), fullPage: true,
    mask: [node(page, 'client-secret'), page.locator('#client-token'), page.locator('#connect-credential-secret')]}); };
  progress.stage = 'initial_document';
  await page.goto(ORIGIN + '/#proxy', {waitUntil: 'networkidle'});
  await page.waitForFunction(() => !document.querySelector('#credential-fields').disabled);
  assert.equal(new URL(page.url()).origin, ORIGIN); assert.match(await page.title(), /Serverware operator workspace/);
  assert.equal(observed.posts.length, 0); assert.equal(await noMaterial(page), null);
  progress.stage = 'explicit_review';
  await act('review', 'GET', PREFIX); await node(page, 'form').waitFor({state: 'visible'});
  await page.waitForFunction(callback => document.querySelector('#google-configuration-callback')?.textContent.trim() === callback,
    ORIGIN + '/api/oauth/callback/google');
  assert.equal(observed.discovery.state, 'unconfigured'); assert.equal(observed.discovery.review.eligible, true);
  assert.equal((await node(page, 'callback').innerText()).trim(), ORIGIN + '/api/oauth/callback/google');
  await node(page, 'scopes').locator('..').locator(':scope > summary').click();
  assert(await node(page, 'scopes').isVisible());
  assert.equal((await node(page, 'scopes').innerText()).trim(), observed.discovery.scopes.join('\n'));
  assert.match(await node(page, 'added-upstream').innerText(), /https:\/\/gmail\.googleapis\.com/);
  assert.equal(await node(page, 'client-secret').getAttribute('type'), 'password');
  await node(page, 'client-id').fill(CLIENT); await node(page, 'client-secret').fill(SECRET); await noMaterial(page, true);
  progress.stage = 'explicit_prepare';
  await act('prepare', 'POST', PREFIX); await pendingDOM(); await noMaterial(page);
  assert.equal(observed.posts.length, 1); assert.equal(observed.operation.status, 'pending');
  assert.match(await node(page, 'operation-status').innerText(), /prepared|pending/i);
  assert.match(await node(page, 'operation-status').innerText(), /restart/i);
  assert(await node(page, 'prepare').isDisabled());
  const reference = await noMaterial(page);
  assert.deepEqual(reference, {operation_id: observed.operation.operation_id, kind: 'prepare'});
  evidence.pending = await bridge.call({op: 'inspect', phase: 'pending'});
  await screenshot('actual-encrypted-pending');
  progress.stage = 'reload_read_only_recovery';
  const beforeReload = observed.requests.length;
  await page.reload({waitUntil: 'networkidle'});
  await page.waitForFunction(() => document.querySelector('#google-configuration-check')
    && !document.querySelector('#google-configuration-check').disabled
    && document.querySelector('#credential-fields')?.disabled === true);
  assert(observed.requests.slice(beforeReload).some(item => item.path === CATALOG));
  assert(await page.locator('#credential-add').isDisabled(), 'unresolved retained operation holds ordinary writes');
  assert.equal(observed.posts.length, 1); assert.deepEqual(await noMaterial(page), reference);
  assert(await node(page, 'prepare').isDisabled());
  await act('check', 'GET', PREFIX + '/' + reference.operation_id); await pendingDOM(); await noMaterial(page);
  assert.equal(observed.operation.status, 'pending'); assert.equal(observed.posts.length, 1);
  assert(observed.requests.slice(beforeReload).every(item => item.method === 'GET'));
  assert(observed.requests.slice(beforeReload).some(item => item.path === PREFIX + '/' + reference.operation_id));
  progress.stage = 'explicit_current_cancel';
  const beforeCancel = observed.requests.length;
  await act('cancel', 'POST', PREFIX + '/cancel');
  await page.waitForFunction(() => /cancelled/i.test(document.querySelector('#google-configuration-operation-status')?.textContent || '')
    && document.querySelector('#google-configuration-cancel')?.disabled === true);
  await noMaterial(page);
  assert.equal(observed.posts.length, 2); assert.equal(observed.operation.status, 'cancelled');
  assert(observed.posts[1].expected_revision > observed.posts[0].expected_revision);
  const cancellation = observed.requests.slice(beforeCancel);
  const freshReview = cancellation.findIndex(item => item.method === 'GET' && item.path === PREFIX);
  const cancelWrite = cancellation.findIndex(item => item.method === 'POST' && item.path === PREFIX + '/cancel');
  assert(freshReview >= 0 && cancelWrite > freshReview, 'fresh discovery precedes the one cancellation POST');
  assert.match(await node(page, 'operation-status').innerText(), /cancelled/i); assert(await node(page, 'cancel').isDisabled());
  evidence.cancelled = await bridge.call({op: 'inspect', phase: 'cancelled'});
  await screenshot('actual-cancelled-retained-custody');
  assert.deepEqual(observed.errors, []); assert.equal(observed.documents.length, 2);
  assert.equal(observed.documents[0], observed.documents[1]);
  evidence.browser = {requests: observed.requests, mutations: observed.posts, actual_html_sha256: observed.documents[0],
    errors: [], public_reference_before_dispatch: true, secret_cleared_before_dispatch: true,
    reload_recovery_without_post_replay: true, current_cancel_cas: true};
}

async function runWithPage(page, suppliedOptions) {
  const options = validateOptions(suppliedOptions), progress = {stage: 'preflight'};
  assert.equal(await realpath(ROOT), ROOT); assert((await stat(options.artifactRoot)).isDirectory());
  assert.equal(sourceDigest(), options.source); const container = inspectContainer(options);
  const directory = await mkdtemp(join(options.artifactRoot, 'google-configuration-connected-'));
  const evidence = {schema: 'serverware.googleConfigurationConnectedBrowserAcceptance/v1', container, source_sha256: options.source,
    boundary: 'Host Chromium via byte-preserving stdin to real full ASGI and isolated encrypted SQLite. No TCP ingress, deployed configuration, restart, Google contact or consent proof.'};
  let bridge, context;
  try {
    progress.stage = 'backend_startup'; bridge = new Bridge(options);
    const ready = await bounded(bridge.ready, 60000);
    assert.equal(ready.source_digest, options.source); assert.equal(ready.full_asgi_app, true);
    assert.equal(ready.lifespan_started, true); assert.equal(ready.managed_startup, true);
    assert.deepEqual(ready.real_admin_origin_refusals, [401, 403]); evidence.startup = ready;
    const browser = page.context().browser(); assert(browser, 'connected browser required');
    context = await browser.newContext({viewport: {width: 1440, height: 1100}, serviceWorkers: 'block', acceptDownloads: false});
    await bounded(story(context, bridge, directory, evidence, progress), 180000);
    await context.close(); context = null;
    progress.stage = 'backend_shutdown'; evidence.shutdown = await bridge.call({op: 'shutdown'});
    assert.equal(evidence.shutdown.type, 'complete'); assert.equal(evidence.shutdown.lifespan_stopped, true);
    assert.equal(evidence.shutdown.source_digest, options.source);
    const exit = await bridge.close(); assert.deepEqual(exit, {code: 0, signal: null});
    assert.equal(sourceDigest(), options.source); inspectContainer(options);
    evidence.ok = true; evidence.transport_exit = exit; clean(evidence);
    await writeFile(join(directory, 'acceptance.json'), JSON.stringify(evidence, null, 2) + '\n', {mode: 0o600});
    return {ok: true, artifacts: directory, browser_mutations: 2, provider_calls: 0, source_sha256: options.source};
  } catch (error) {
    evidence.ok = false; evidence.failure = {browser: diagnostic(error, progress.stage), backend: bridge?.backendFailure || null,
      root_cleanup_required: true}; clean(evidence);
    await writeFile(join(directory, 'failure.json'), JSON.stringify(evidence, null, 2) + '\n', {mode: 0o600});
    const safe = new Error('connected configuration acceptance failed; inspect retained safe evidence');
    safe.result = {ok: false, artifacts: directory, failure: evidence.failure}; throw safe;
  } finally {
    if (context) await context.close().catch(() => {});
    if (bridge && !bridge.exit) await bridge.close().catch(() => {});
  }
}

function optionsFromCLI() {
  const map = {'--container': 'container', '--image': 'image', '--source-sha256': 'source',
    '--artifact-root': 'artifactRoot', '--playwright-module': 'module'}, values = {};
  for (let i = 2; i < process.argv.length; i += 2) {
    const key = map[process.argv[i]]; assert(key && process.argv[i + 1] && !Object.hasOwn(values, key));
    values[key] = process.argv[i + 1];
  }
  return validateOptions(values);
}
async function main() {
  if (process.argv.length === 3 && process.argv[2] === '--help') {
    process.stdout.write('Usage: node scripts/test_operator_google_configuration_connected_browser.cjs --container FULL_ID --image sha256:IMAGE_ID --source-sha256 DIGEST --artifact-root /srv/catchplate-fast/EVIDENCE [--playwright-module PATH]\n'); return;
  }
  const options = optionsFromCLI(), {chromium} = require(options.module);
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--disable-background-networking',
    '--disable-component-update', '--disable-default-apps', '--disable-sync', '--metrics-recording-only',
    '--no-first-run', '--host-resolver-rules=MAP * ~NOTFOUND']});
  try {
    const page = await browser.newPage();
    process.stdout.write(JSON.stringify(await runWithPage(page, options)) + '\n');
  } finally { await browser.close(); }
}
module.exports = {runWithPage};
if (require.main === module) main().catch(error => {
  process.stderr.write(JSON.stringify(error.result || {ok: false, failure: diagnostic(error, 'preflight')}) + '\n');
  process.exitCode = 1;
});

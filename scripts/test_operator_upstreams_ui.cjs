#!/usr/bin/env node
// Pure closed DTO and inert-DOM state-machine checks. No browser, network,
// backend, database, process restart, environment edit or generated command.
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const ROOT = resolve(__dirname, '..');
const SOURCE = ['workspace_core.js', 'workspace_upstreams.js'].map(name =>
  readFileSync(resolve(ROOT, 'catchplate/operator_demo_web', name), 'utf8')).join('\n');
const HTML = readFileSync(resolve(ROOT, 'catchplate/operator_demo_web/index.html'), 'utf8');
const PATH = '/api/operator-demo/proxy/upstreams';
const STORAGE = 'catchplate.operator.upstreams.operation.v1';
const ID = '11111111-1111-4111-8111-111111111111';
const OTHER = '22222222-2222-4222-8222-222222222222';
const FIXTURE = 'https://demo-upstream:8443';
const NPM = 'https://registry.npmjs.org';
const GITHUB = 'https://api.github.com';
const digest = value => 'sha256:' + value.repeat(64);
const clone = value => JSON.parse(JSON.stringify(value));
const OLD = {allowed_upstreams: [FIXTURE], fixture_cidrs: ['127.0.0.1/32']};
const TARGET = {...OLD, allowed_upstreams: [FIXTURE, NPM]};
const review = (changes = {}) => ({schema: 'catchplate.operatorUpstreamSetupReview/v1',
  expected_revision: 7, expected_policy_hash: digest('a'), expected_settings_digest: digest('b'), old_settings: clone(OLD),
  protected_origins: [{origin: FIXTURE, reasons: ['fixture', 'retained_policy']}], fixed_first_origin: FIXTURE,
  eligible: true, pending_operation_id: null, blocked_reason: null, cold_restart_required: true, ...changes});
const receipt = (changes = {}) => ({schema: 'catchplate.operatorUpstreamSetup/v1', operation_id: ID, status: 'pending',
  old_settings: clone(OLD), target_settings: clone(TARGET), expected_settings_digest: digest('b'), target_settings_digest: digest('c'),
  reviewed_revision: 7, staged_revision: 8, policy_hash: digest('a'), created_at: '2026-10-10T12:00:00+00:00',
  revision: 8, completed_at: null, activation_receipt: null, ...changes});
function completed(status, changes = {}) {
  const value = receipt({status, revision: 9, completed_at: '2026-10-10T12:01:00+00:00', ...changes});
  if (status === 'activated') value.activation_receipt = {schema: 'catchplate.operatorUpstreamSetupActivation/v1',
    operation_id: value.operation_id, activated_revision: value.revision, policy_hash: value.policy_hash,
    settings_digest: value.target_settings_digest, activated_at: value.completed_at};
  return value;
}
function context(extras = {}) {
  const value = vm.createContext({URL, Date, ...extras}); vm.runInContext(SOURCE, value, {timeout: 1000});
  return {value, run: (expression, input) => { value.input = input; return vm.runInContext(expression, value, {timeout: 1000}); }};
}
const pure = context();
const project = value => clone(pure.run('projectUpstreamReview(input)', value));
const projectReceipt = (value, kind = 'prepare') => clone(pure.run('projectUpstreamReceipt(input.value,input.reference)',
  {value, reference: {operation_id: ID, kind}}));
const delta = (value, text) => clone(pure.run('upstreamDelta(input.review,input.text)', {review: value, text}));
class Node {
  constructor(id) { this.id = id; this.value = ''; this.textContent = ''; this.hidden = false; this.disabled = false; this.events = {}; this.children = []; }
  addEventListener(name, callback) { this.events[name] = callback; }
  insertBefore(node, before) { this.inserted = {node: node.id, before: before.id}; }
  append(node) { node.parentNode = this; this.children.push(node); }
}
function fixture(options = {}) {
  const nodes = new Map([...HTML.matchAll(/\bid="([^"]+)"/g)].map(match => [match[1], new Node(match[1])]));
  nodes.set('proxy-setup-content', new Node('proxy-setup-content'));
  const storage = new Map(Object.entries(options.storage || {})); const calls = []; const copied = []; const downloads = []; const holds = new Set();
  const state = {revision: 7, settings: clone(OLD), settingsDigest: digest('b'), operation: options.operation ? clone(options.operation) : null};
  const workspace = {state: {catalog: {revision: state.revision, policy: {policy_hash: digest('a')}, allowed_upstreams: [...state.settings.allowed_upstreams]}, uncertain: false,
    get busy() { return holds.size > 0; }}, listeners: [], subscribe(callback) { this.listeners.push(callback); }, emit() { this.listeners.forEach(callback => callback()); },
    async refresh() { this.state.catalog = {revision: state.revision, policy: {policy_hash: digest('a')}, allowed_upstreams: [...state.settings.allowed_upstreams]}; this.emit(); },
    setConsentHold(enabled, owner) { if (enabled) holds.add(owner); else holds.delete(owner); this.emit(); }};
  if (state.operation) state.revision = state.operation.revision;
  const response = (body, status = 200) => ({ok: status >= 200 && status < 300, status,
    headers: {get: () => 'application/json'}, async text() { return JSON.stringify(body); }});
  const fetch = async (path, init) => {
    const body = init.body ? JSON.parse(init.body) : null; const method = init.method || 'GET'; calls.push({path, method, body});
    assert.equal(init.credentials, 'same-origin'); assert.equal(init.redirect, 'error'); assert.equal(init.cache, 'no-store');
    if (path === PATH && method === 'GET') {
      if (options.unsupported) return response({detail: 'not found'}, 404);
      const pending = state.operation?.status === 'pending';
      return response(review({expected_revision: state.revision, expected_settings_digest: state.settingsDigest, old_settings: clone(state.settings),
        eligible: !pending, pending_operation_id: pending ? state.operation.operation_id : null, blocked_reason: pending ? 'pending_operation' : null}));
    }
    if (method === 'GET' && path === PATH + '/' + ID) return state.operation ? response(state.operation) : response({detail: 'not found'}, 404);
    assert.equal(method, 'POST'); assert.equal(JSON.parse(storage.get(STORAGE)).operation_id, body.operation_id, 'persist before POST');
    assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, digest('a'));
    if (path === PATH) {
      assert.equal(JSON.parse(storage.get(STORAGE)).kind, 'prepare');
      assert.deepEqual(Object.keys(body).sort(), ['allowed_upstreams', 'expected_policy_hash', 'expected_revision', 'expected_settings_digest', 'operation_id']);
      assert.equal(body.expected_settings_digest, state.settingsDigest); assert.deepEqual(body.allowed_upstreams, TARGET.allowed_upstreams);
      if (options.rejectInput) return response({detail: 'invalid upstream setup input'}, 422);
      if (options.conflict) return response({detail: 'upstream setup review changed; inspect saved status before preparing again'}, 409);
      if (options.unknown) throw new Error('Synthetic lost response before any confirmed outcome');
      state.operation = receipt(); state.revision = 8;
      if (options.lostPrepare) throw new Error('Synthetic lost response after commit');
      return response(state.operation, 201);
    }
    assert.equal(path, PATH + '/cancel'); assert.equal(JSON.parse(storage.get(STORAGE)).kind, 'cancel');
    assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'operation_id']);
    if (options.unknownCancel) throw new Error('Synthetic cancellation outcome unknown');
    state.operation = completed('cancelled'); state.revision = 9;
    if (options.lostCancel) throw new Error('Synthetic cancellation committed but response lost');
    return response(state.operation);
  };
  const current = context({document: {getElementById(id) { assert(nodes.has(id), id); return nodes.get(id); }},
    sessionStorage: {getItem: key => storage.get(key) ?? null,
      setItem(key, value) { if (options.storageFailure) throw new Error('unavailable'); storage.set(key, value); }, removeItem: key => storage.delete(key)},
    fetch, AbortSignal: {timeout: () => ({})}, crypto: {randomUUID: () => ID}, navigator: {clipboard: {async writeText(value) { copied.push(value); }}},
    workspaceFixture: workspace, handoffDownloads: downloads});
  current.run('downloadActivationHandoff = value => handoffDownloads.push(JSON.stringify(value))');
  const view = current.run('createUpstreamsView(workspaceFixture)'); view.show(true);
  const node = id => nodes.get(id); const event = async (id, type = 'click') => {
    assert.equal(typeof node(id).events[type], 'function', id); return node(id).events[type]({preventDefault() {}});
  };
  const prepare = async () => { await event('upstreams-review'); node('upstreams-proposed').value = TARGET.allowed_upstreams.join('\n'); await event('upstreams-proposed', 'input'); await event('upstreams-form', 'submit'); };
  return {node, event, prepare, view, workspace, state, calls, storage, copied, downloads};
}
const tests = [
  ['strict review DTO preserves canonical origins, order and immutable fixture settings', () => {
    assert.deepEqual(project(review()), review());
    for (const changes of [{extra: true}, {cold_restart_required: false}, {expected_settings_digest: 'bad'}, {eligible: false},
      {pending_operation_id: ID}, {fixed_first_origin: NPM}, {protected_origins: [{origin: NPM, reasons: ['active_rule']}]},
      {protected_origins: [{origin: FIXTURE, reasons: ['retained_policy', 'fixture']}]}, {old_settings: {...OLD, secret: 'never'}}])
      assert.throws(() => project(review(changes)));
  }],
  ['origin parser refuses URLs, aliases, private destinations and duplicates', () => {
    for (const origin of ['http://registry.npmjs.org', NPM + '/', NPM + ':443', NPM + '/pkg', 'https://user:token@npmjs.org',
      'https://REGISTRY.npmjs.org', 'https://127.0.0.1', 'https://host.local', 'https://host.test', 'https://host.internal', 'https://a..com', 'https://*.npmjs.org'])
      assert.throws(() => delta(review(), FIXTURE + '\n' + origin));
    assert.throws(() => delta(review(), FIXTURE + '\n' + NPM + '\n' + NPM));
    assert.throws(() => delta(review({old_settings: {allowed_upstreams: [GITHUB], fixture_cidrs: []}, protected_origins: [], fixed_first_origin: null}), GITHUB + '\n' + FIXTURE));
  }],
  ['32 destinations preserve the retained roster; 33 and duplicate destinations refuse', () => {
    const origins = [FIXTURE, ...Array.from({length: 31}, (_, index) => `https://service-${index}.example.com`)];
    const retained = origins.slice(0, 16);
    const protectedOrigins = origins.map(origin => ({origin, reasons: ['retained_policy']}))
      .sort((left, right) => left.origin.localeCompare(right.origin));
    const full = review({old_settings: {...OLD, allowed_upstreams: origins}, protected_origins: protectedOrigins});
    assert.deepEqual(project(full), full);
    const change = delta(review({old_settings: {...OLD, allowed_upstreams: retained}}), origins.join('\n'));
    assert.deepEqual(change.allowed_upstreams, origins);
    assert.deepEqual(change.removed, []);
    assert.deepEqual(change.added, origins.slice(16));
    assert.deepEqual(projectReceipt(receipt({target_settings: {...OLD, allowed_upstreams: origins}})).target_settings.allowed_upstreams, origins);
    const overflow = [...origins, 'https://overflow.example.com'];
    assert.throws(() => delta(review(), overflow.join('\n')), error => /1–32/.test(error.uiMessage));
    assert.throws(() => project(review({old_settings: {...OLD, allowed_upstreams: overflow}})));
    assert.throws(() => project({...full, protected_origins: [...protectedOrigins, protectedOrigins[0]]}));
    assert.throws(() => delta(review(), [...origins.slice(0, -1), origins[1]].join('\n')));
    assert.match(HTML, /Use 1–32 unique canonical HTTPS origins/);
  }],
  ['Google destination addition obeys the same 32-origin bound', () => {
    vm.runInContext(readFileSync(resolve(ROOT, 'catchplate/operator_demo_web/workspace_google_configuration.js'), 'utf8'), pure.value, {timeout: 1000});
    const origins = Array.from({length: 31}, (_, index) => `https://service-${index}.example.com`);
    const gmail = 'https://gmail.googleapis.com';
    const target = {allowed_upstreams: [...origins, gmail], fixture_cidrs: []};
    const accepts = (old, next) => pure.run('googleConfigurationTarget(input.old,input.target)', {old, target: next});
    assert.equal(accepts({allowed_upstreams: origins, fixture_cidrs: []}, target), true);
    assert.equal(accepts(target, target), true);
    assert.equal(accepts({allowed_upstreams: [...origins, NPM], fixture_cidrs: []},
      {allowed_upstreams: [...origins, NPM, gmail], fixture_cidrs: []}), false);
  }],
  ['same-set reorders, protected removal and fixed-first changes never prepare', () => {
    assert.throws(() => delta(review(), FIXTURE)); assert.throws(() => delta(review(), NPM));
    assert.throws(() => delta(review(), NPM + '\n' + FIXTURE));
    assert.throws(() => delta(review({old_settings: {...OLD, allowed_upstreams: [FIXTURE, NPM]}}), NPM + '\n' + FIXTURE));
    const change = delta(review(), FIXTURE + '\n' + NPM + '\n' + GITHUB);
    assert.deepEqual(change.allowed_upstreams, [FIXTURE, NPM, GITHUB]); assert.deepEqual(change.added, [NPM, GITHUB]);
    assert.deepEqual(change.removed, []);
  }],
  ['pending, cancelled and activated receipts have distinct strict joins', () => {
    for (const value of [receipt(), completed('cancelled'), completed('activated')]) assert.deepEqual(projectReceipt(value), value);
    for (const changes of [{operation_id: OTHER}, {status: 'applied'}, {revision: 9}, {completed_at: '2026-10-10T12:01:00Z'},
      {target_settings: {...TARGET, fixture_cidrs: []}}, {expected_settings_digest: digest('c')}, {reviewed_revision: 8}, {extra: true}])
      assert.throws(() => projectReceipt(receipt(changes)));
    const bad = completed('activated'); bad.activation_receipt.settings_digest = digest('d'); assert.throws(() => projectReceipt(bad));
    const old = completed('cancelled'); old.completed_at = '2026-10-09T00:00:00Z'; assert.throws(() => projectReceipt(old));
  }],
  ['opening Proxy settings is inert; review discovers real support explicitly', async () => {
    const f = fixture(); assert.equal(f.calls.length, 0); assert(f.node('upstreams-form').hidden); assert(f.node('upstreams-operation').hidden);
    assert.equal(f.node('upstreams-effective').textContent, FIXTURE);
    assert.equal(f.node('proxy-upstreams').parentNode, f.node('proxy-operator-settings'));
    assert.equal(f.node('proxy').inserted, undefined);
    assert(HTML.indexOf('id="proxy-setup-content"') < HTML.indexOf('id="proxy-operator-settings"'));
    await f.event('upstreams-review'); assert.equal(f.calls.length, 1); assert.equal(f.calls[0].method, 'GET'); assert(!f.node('upstreams-form').hidden);
    assert(f.node('upstreams-prepare').disabled);
  }],
  ['unsupported route offers no fake mutation or Save', async () => {
    const f = fixture({unsupported: true}); await f.event('upstreams-review');
    assert(f.node('upstreams-form').hidden); assert(f.node('upstreams-prepare').disabled); assert.match(f.node('upstreams-status').textContent, /not supported/);
    await f.event('upstreams-form', 'submit'); assert.equal(f.calls.length, 1);
  }],
  ['prepare persists reference first, sends exact CAS once and leaves effective settings untouched', async () => {
    const f = fixture(); await f.prepare(); const posts = f.calls.filter(call => call.method === 'POST'); assert.equal(posts.length, 1);
    assert.deepEqual(JSON.parse(f.storage.get(STORAGE)), {operation_id: ID, kind: 'prepare'});
    assert.equal(f.node('upstreams-effective').textContent, FIXTURE); assert.deepEqual(f.state.settings, OLD);
    assert.match(f.node('upstreams-operation-status').textContent, /Prepared.*restart required/);
    assert(f.node('upstreams-prepare').disabled); assert(!f.node('upstreams-cancel').disabled);
    await f.event('upstreams-copy'); assert.deepEqual(JSON.parse(f.copied[0]), TARGET.allowed_upstreams);
    assert(!f.copied[0].includes('fixture_cidrs')); await f.event('upstreams-form', 'submit'); assert.equal(f.calls.filter(call => call.method === 'POST').length, 1);
  }],
  ['activation handoff projects only bounded public fields from the exact current pending review', () => {
    const pending = review({expected_revision: 8, eligible: false, pending_operation_id: ID, blocked_reason: 'pending_operation'});
    const projectHandoff = (value = receipt(), selected = pending, kind = 'prepare') => clone(pure.run(
      'projectUpstreamActivationHandoff(input.value,input.reference,input.review)',
      {value, reference: {operation_id: ID, kind}, review: selected}));
    const result = projectHandoff();
    assert.deepEqual(Object.keys(result).sort(), ['schema', 'change_kind', 'operation_id', 'observed_status', 'prepared_at',
      'reviewed_revision', 'prepared_revision', 'policy_hash', 'expected_settings_digest', 'target_settings_digest',
      'current_origins', 'target_origins', 'status_path', 'next_step', 'runbook_url', 'notice'].sort());
    assert.equal(result.change_kind, 'proxy_destinations'); assert.equal(result.observed_status, 'pending');
    assert.deepEqual(result.target_origins, TARGET.allowed_upstreams); assert.equal(result.status_path, PATH + '/' + ID);
    assert.match(result.next_step, /both app and proxy/); assert.match(result.notice, /not activation/);
    assert.match(result.runbook_url, /docs\/self-hosting\.md#activate-a-prepared-configuration$/);
    assert(!JSON.stringify(result).includes('fixture_cidrs'));
    for (const value of [null, receipt({secret: 'never-export'}), completed('cancelled'), completed('activated')])
      assert.throws(() => projectHandoff(value));
    for (const changes of [{expected_revision: 9}, {expected_policy_hash: digest('f')},
      {expected_settings_digest: digest('d')}, {pending_operation_id: OTHER}])
      assert.throws(() => projectHandoff(receipt(), {...pending, ...changes}));
    assert.throws(() => projectHandoff(receipt(), pending, 'cancel'));
  }],
  ['handoff download requires validated current pending state and performs no network or storage writes', async () => {
    const f = fixture(); assert(f.node('upstreams-handoff').disabled);
    await f.event('upstreams-handoff'); assert.equal(f.downloads.length, 0); assert.equal(f.calls.length, 0);
    await f.prepare(); assert(!f.node('upstreams-handoff').disabled);
    const before = JSON.stringify({calls: f.calls, storage: [...f.storage], state: f.state});
    await f.event('upstreams-handoff'); assert.equal(f.downloads.length, 1);
    assert.equal(JSON.stringify({calls: f.calls, storage: [...f.storage], state: f.state}), before);
    f.workspace.state.catalog.revision++; f.workspace.emit(); assert(f.node('upstreams-handoff').disabled);
    await f.event('upstreams-handoff'); assert.equal(f.downloads.length, 1);
    for (const option of [{lostPrepare: true}, {unknownCancel: true}]) {
      const blocked = fixture(option); await blocked.prepare();
      if (option.unknownCancel) await blocked.event('upstreams-cancel');
      assert(blocked.node('upstreams-handoff').disabled); await blocked.event('upstreams-handoff'); assert.equal(blocked.downloads.length, 0);
    }
  }],
  ['public handoff file uses a fixed filename and releases its object URL', async () => {
    const calls = []; let blob;
    const anchor = {click() { calls.push('click'); }, remove() { calls.push('remove'); }};
    const download = context({Blob, URL: {createObjectURL(value) { blob = value; return 'blob:synthetic'; },
      revokeObjectURL(value) { assert.equal(value, 'blob:synthetic'); calls.push('revoke'); }},
      document: {createElement(name) { assert.equal(name, 'a'); return anchor; }, body: {append(value) { assert.equal(value, anchor); calls.push('append'); }}},
      setTimeout(callback, milliseconds) { assert.equal(milliseconds, 1000); callback(); }});
    const value = {schema: 'catchplate.operatorActivationHandoff/v1'};
    download.run('downloadActivationHandoff(input)', value);
    assert.deepEqual(JSON.parse(await blob.text()), value); assert.equal(blob.type, 'application/json');
    assert.equal(anchor.download, 'catchplate-activation-handoff.public.json'); assert.equal(anchor.href, 'blob:synthetic');
    assert.deepEqual(calls, ['append', 'click', 'remove', 'revoke']);
  }],
  ['stale catalog or blocked browser storage prevents any POST', async () => {
    for (const storageFailure of [false, true]) {
      const f = fixture({storageFailure}); await f.event('upstreams-review'); f.node('upstreams-proposed').value = TARGET.allowed_upstreams.join('\n');
      if (!storageFailure) { f.workspace.state.catalog.revision++; f.workspace.emit(); }
      await f.event('upstreams-form', 'submit'); assert(!f.calls.some(call => call.method === 'POST')); assert(f.node('upstreams-prepare').disabled);
    }
  }],
  ['lost prepare response recovers by GET and never replays POST, including after reload', async () => {
    const f = fixture({lostPrepare: true}); await f.prepare(); assert.match(f.node('upstreams-operation-status').textContent, /unconfirmed/);
    await f.event('upstreams-check'); assert.match(f.node('upstreams-operation-status').textContent, /Prepared/);
    assert.equal(f.calls.filter(call => call.method === 'POST').length, 1);
    const reloaded = fixture({operation: f.state.operation, storage: Object.fromEntries(f.storage)});
    assert.equal(reloaded.calls.length, 0); await reloaded.event('upstreams-check'); assert(!reloaded.calls.some(call => call.method === 'POST'));
    assert.match(reloaded.node('upstreams-operation-status').textContent, /Prepared/);
  }],
  ['404 or 409 retains the uncertain UUID and offers only same-operation GET recovery', async () => {
    for (const option of ['unknown', 'conflict']) {
      const f = fixture({[option]: true}); await f.prepare(); await f.event('upstreams-check'); await f.event('upstreams-form', 'submit');
      assert.equal(f.calls.filter(call => call.method === 'POST').length, 1); assert.equal(JSON.parse(f.storage.get(STORAGE)).operation_id, ID);
      assert.match(f.node('upstreams-status').textContent, /could still complete/); assert(f.node('upstreams-cancel').disabled);
    }
  }],
  ['known precommit 422 may retire that rejected request but never silently repeats', async () => {
    const f = fixture({rejectInput: true}); await f.prepare(); assert.equal(f.storage.has(STORAGE), false);
    assert.equal(f.calls.filter(call => call.method === 'POST').length, 1); assert(f.node('upstreams-form').hidden);
    assert.match(f.node('upstreams-status').textContent, /before committing/);
  }],
  ['cancellation is a separate exact request; a lost cancellation is recovered rather than repeated', async () => {
    const f = fixture({lostCancel: true}); await f.prepare(); await f.event('upstreams-cancel');
    assert.deepEqual(JSON.parse(f.storage.get(STORAGE)), {operation_id: ID, kind: 'cancel'});
    await f.event('upstreams-check'); assert.match(f.node('upstreams-operation-status').textContent, /cancelled/);
    assert.deepEqual(f.state.settings, OLD); assert.equal(f.calls.filter(call => call.method === 'POST').length, 2);
    await f.event('upstreams-cancel'); assert.equal(f.calls.filter(call => call.method === 'POST').length, 2);
  }],
  ['pending read after uncertain cancellation does not permit cancellation replay', async () => {
    const f = fixture({unknownCancel: true}); await f.prepare(); await f.event('upstreams-cancel'); await f.event('upstreams-check');
    assert.match(f.node('upstreams-operation-status').textContent, /Cancellation is not yet confirmed/);
    assert(f.node('upstreams-cancel').disabled); assert(f.node('upstreams-prepare').disabled);
    await f.event('upstreams-cancel'); assert.equal(f.calls.filter(call => call.method === 'POST').length, 2);
  }],
  ['activation is reported separately from effective settings and proxy readiness', async () => {
    const f = fixture({operation: completed('activated'), storage: {[STORAGE]: JSON.stringify({operation_id: ID, kind: 'prepare'})}});
    await f.event('upstreams-check'); assert.match(f.node('upstreams-operation-status').textContent, /Cold-start activation is recorded/);
    assert.match(f.node('upstreams-operation-status').textContent, /check proxy activation separately/);
    assert.equal(f.node('upstreams-effective').textContent, FIXTURE); assert(!f.calls.some(call => call.method === 'POST'));
  }],
];
async function main() {
  assert.equal(process.argv.length, 2, 'No live target or execution arguments accepted');
  for (const [name, test] of tests) { await test(); console.log('PASS ' + name); }
  console.log(JSON.stringify({ok: true, groups: tests.length, browser: false, network: false, source: 'closed DTO and inert DOM only'}));
}
module.exports = {review, receipt, completed, OLD, TARGET, ID, FIXTURE, NPM, GITHUB, digest};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

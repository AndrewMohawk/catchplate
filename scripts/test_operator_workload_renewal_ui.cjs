#!/usr/bin/env node
// Actual public JS with inert DOM and intercepted fetch. No browser, network,
// backend, proxy, private-key creation, token issuance or deployment.
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const {webcrypto, createHash} = require('node:crypto');
const vm = require('node:vm');
const ROOT = resolve(__dirname, '..');
const asset = name => readFileSync(resolve(ROOT, 'serverware/operator_demo_web', name), 'utf8');
const portal = readFileSync(resolve(ROOT, 'serverware/operator_demo_portal.py'), 'utf8');
const files = [...portal.match(/SCRIPT_FILES = \(([^)]*)\)/)[1].matchAll(/"([a-z_]+\.js)"/g)].map(match => match[1]);
const source = files.filter(name => name !== 'app.js').map(asset).join('\n');
const html = asset('index.html');
const NOW = 1800000000000;
const ID = '11111111-1111-4111-8111-111111111111';
const ENROLLMENT = '22222222-2222-4222-8222-222222222222';
const REPLACEMENT = '33333333-3333-4333-8333-333333333333';
const PROXY = 'https://proxy.example.test';
const KEY = '12'.repeat(32);
const fingerprint = 'sha256:' + createHash('sha256').update(Buffer.from(KEY, 'hex')).digest('hex');
const digest = letter => 'sha256:' + letter.repeat(64);
const clone = value => JSON.parse(JSON.stringify(value));
const cap = () => ({schema: 'serverware.workloadTokenRenewal/v1', enroll_path: '/api/operator-demo/applications/renewal/enroll',
  cancel_path: '/api/operator-demo/applications/renewal/cancel', path: '/v1/workload/renew', audience: PROXY + '/v1/workload/renew',
  overlap_seconds: 300, token_lifetime_seconds: {min: 3600, max: 86400, default: 3600},
  enrollment_lifetime_seconds: {min: 86400, max: 7776000, default: 2592000}, single_writer: true});
const enrollment = (changes = {}) => ({version: 1, enrollment_id: ENROLLMENT, expires_at_epoch_ms: NOW + 30 * 86400000,
  public_key_fingerprint: fingerprint, token_lifetime_seconds: 3600, overlap_seconds: 300,
  audience: PROXY + '/v1/workload/renew', status: 'active', ...changes});
const application = (changes = {}) => ({id: ID, name: 'Reporting job', status: 'active', created_at: new Date(NOW).toISOString(),
  revoked_at: null, principal_id: 'agent:operator-demo:' + ID, token_generation: 1,
  token_expires_at_epoch_ms: NOW + 86400000, token_status: 'valid', access_status: 'unassigned', active_rule_count: 0,
  client_renewal: null, ...changes});
const catalog = (changes = {}) => ({schema: 'serverware.operatorCatalog/v1', mode: 'operator-development', productionReady: false,
  hardwareVerified: false, revision: 7, policy: {policy_hash: digest('a'), loaded_policy_hash: digest('a'), sequence: 2, activation: 'active'},
  proxy_url: PROXY, applications: [application()], credentials: [], access_rules: [], allowed_upstreams: [], limits: {},
  capabilities: {oauth: false, workload_renewal: cap()}, ...changes});
class Node {
  constructor(id = '') { this.id = id; this.value = ''; this.textContent = ''; this.hidden = false; this.disabled = false; this.checked = false; this.events = {}; this.children = []; }
  addEventListener(name, callback) { this.events[name] = callback; }
  append(...children) { this.children.push(...children); }
  replaceChildren() { this.children = []; this.value = ''; }
  querySelectorAll() { return []; }
  reportValidity() { return true; }
  scrollIntoView() { this.scrolled = true; }
  focus() { this.focused = true; }
}
class Clock extends Date { constructor(...args) { super(...(args.length ? args : [NOW])); } static now() { return NOW; } }
function context(extras = {}) {
  const ctx = vm.createContext({URL, Date: Clock, crypto: webcrypto, Uint8Array, console, ...extras});
  vm.runInContext(source, ctx, {timeout: 1000});
  return {ctx, run(expression, input) { ctx.input = input; return vm.runInContext(expression, ctx, {timeout: 1000}); }};
}
const pure = context();
const evaluate = (expression, input) => clone(pure.run(expression, input));
async function fixture(options = {}) {
  const nodes = new Map([...html.matchAll(/\bid="([^"]+)"/g)].map(match => [match[1], new Node(match[1])]));
  const node = id => { assert(nodes.has(id), 'known DOM target ' + id); return nodes.get(id); };
  node('application-renewal-days').value = '30'; node('application-renewal-hours').value = '1';
  const state = clone(options.catalog || catalog()); const calls = []; const confirmations = []; const invalidated = []; const events = {};
  const response = body => ({ok: true, status: 200, headers: {get: () => 'application/json'}, json: async () => clone(body)});
  const fetch = async (path, request) => {
    calls.push({path, method: request.method || 'GET', body: request.body ? JSON.parse(request.body) : null});
    if (!request.method) { if (options.afterRefresh && calls.some(call => call.method === 'POST')) options.afterRefresh(state); return response(state); }
    const body = JSON.parse(request.body);
    assert.equal(body.expected_revision, state.revision); assert.equal(body.expected_policy_hash, state.policy.policy_hash);
    assert.equal(body.id, ID); const item = state.applications[0];
    if (path.endsWith('/enroll')) {
      assert.deepEqual(Object.keys(body).sort(), ['enrollment_lifetime_seconds', 'expected_policy_hash', 'expected_revision', 'id', 'public_key', 'token_lifetime_seconds']);
      assert.equal(body.public_key, KEY);
      item.client_renewal = enrollment({enrollment_id: item.client_renewal ? REPLACEMENT : ENROLLMENT,
        token_lifetime_seconds: body.token_lifetime_seconds, expires_at_epoch_ms: NOW + body.enrollment_lifetime_seconds * 1000});
      delete item.client_renewal_cancelled_at_epoch_ms;
      item.token_expires_at_epoch_ms = Math.min(item.token_expires_at_epoch_ms, item.client_renewal.expires_at_epoch_ms);
    } else {
      assert.equal(path, '/api/operator-demo/applications/renewal/cancel');
      assert.deepEqual(Object.keys(body).sort(), ['expected_policy_hash', 'expected_revision', 'id']);
      item.client_renewal = null; item.client_renewal_cancelled_at_epoch_ms = NOW;
    }
    state.revision++;
    if (options.pendingPolicy) { state.policy.policy_hash = digest('b'); state.policy.sequence++; state.policy.activation = 'pending'; }
    if (options.unknown) throw new Error('synthetic lost reply');
    const result = {application: clone(item), revision: state.revision, policy: clone(state.policy)};
    if (options.result) options.result(result);
    return response(result);
  };
  const c = context({element: node, fetch, AbortSignal, setTimeout: () => 1, clearTimeout() {},
    Option: class extends Node { constructor(text, value) { super(); this.textContent = text; this.value = value; } },
    document: {getElementById: node}, location: {hash: '#applications', origin: 'https://operator.example.test'},
    window: {addEventListener(name, callback) { events[name] = callback; }, confirm(text) {
      confirmations.push(text); if (options.confirm) return options.confirm(c.ctx.workspace, state); return true;
    }}});
  c.ctx.invalidate = id => invalidated.push(id);
  c.run('workspace = createOperatorWorkspace(); view = createWorkloadRenewalView(workspace, invalidate)');
  await c.run('workspace.refresh()');
  const fire = async (id, name = 'click') => { await node(id).events[name]({preventDefault() {}}); };
  const select = async () => { node('application-renewal-client').value = ID; await fire('application-renewal-client', 'change'); };
  const fill = async () => { await select(); node('application-renewal-key').value = KEY; node('application-renewal-consent').checked = true; };
  return {c, node, state, calls, confirmations, invalidated, events, fire, fill, select,
    posts: () => calls.filter(call => call.method === 'POST'), submit: () => fire('application-renewal-form', 'submit')};
}
const tests = [
  ['closed capability and configured HTTPS audience only', () => {
    assert.deepEqual(evaluate('projectWorkloadRenewalCapability(input, "' + PROXY + '")', cap()), cap());
    const explicitPort = {...cap(), audience: PROXY + ':443/v1/workload/renew'};
    assert.deepEqual(evaluate('projectWorkloadRenewalCapability(input, "' + PROXY + ':443")', explicitPort), explicitPort);
    assert.equal(evaluate('projectWorkloadRenewalCapability(input, "' + PROXY + '")', explicitPort), null);
    for (const delta of [{extra: true}, {single_writer: false}, {overlap_seconds: 301}, {path: '/renew'},
      {token_lifetime_seconds: {min: 1, max: 86400, default: 3600}}, {audience: 'https://other.example/v1/workload/renew'},
      {audience: PROXY + '/v1/workload/renew?x=1'}, {audience: PROXY + '/v1/workload/renew#x'},
      {audience: ' ' + PROXY + '/v1/workload/renew'}, {audience: 'https://user@proxy.example.test/v1/workload/renew'},
      {audience: PROXY.replace('https:', 'http:') + '/v1/workload/renew'}])
      assert.equal(evaluate('projectWorkloadRenewalCapability(input, "' + PROXY + '")', {...cap(), ...delta}), null);
  }],
  ['metadata projection is public and closed', () => {
    assert.deepEqual(evaluate('projectClientRenewal(input)', enrollment()), enrollment());
    assert.equal(evaluate('projectClientRenewal(input)', null), null);
    for (const delta of [{public_key: KEY}, {private_key: 'not accepted'}, {previous_token: {}}, {status: 'verified'},
      {token_lifetime_seconds: 3601.5}, {expires_at_epoch_ms: Infinity}, {enrollment_id: 'bad'}, {enrollment_id: [ENROLLMENT]},
      {public_key_fingerprint: 'not-digest'}, {public_key_fingerprint: [fingerprint]}])
      assert.throws(() => pure.run('projectClientRenewal(input)', {...enrollment(), ...delta}));
  }],
  ['catalog accepts absent legacy metadata and cancellation tombstone, rejects contradictions', () => {
    const old = catalog(); delete old.applications[0].client_renewal; delete old.capabilities.workload_renewal;
    assert.equal(evaluate('projectCatalog(input)', old).capabilities.workload_renewal, null);
    const cancelled = catalog({applications: [application({client_renewal_cancelled_at_epoch_ms: NOW})]});
    assert.equal(evaluate('projectCatalog(input)', cancelled).applications[0].client_renewal_cancelled_at_epoch_ms, NOW);
    for (const delta of [{client_renewal_cancelled_at_epoch_ms: -1}, {client_renewal: enrollment(), client_renewal_cancelled_at_epoch_ms: NOW},
      {client_renewal: {...enrollment(), public_key: KEY}}])
      assert.throws(() => pure.run('projectCatalog(input)', catalog({applications: [application(delta)]})));
  }],
  ['setup is exact public helper DTO, not a token or key export', () => {
    const setup = evaluate('workloadRenewalSetup(input)', application({client_renewal: enrollment(), private_key: 'NEVER', client_token: 'NEVER'}));
    assert.equal(setup.schema, 'serverware.managedClientSetup/v1');
    assert.deepEqual(Object.keys(setup).sort(), ['schema', 'application_id', 'enrollment_id', 'audience', 'public_key_fingerprint',
      'token_generation', 'token_expires_at_epoch_ms', 'enrollment_expires_at_epoch_ms', 'token_lifetime_seconds', 'overlap_seconds'].sort());
    assert(!JSON.stringify(setup).includes('NEVER')); assert(!JSON.stringify(setup).includes(KEY));
    assert(evaluate('workloadRenewalSetup(input)', application({token_expires_at_epoch_ms: NOW - 1, client_renewal: enrollment()})));
    assert.equal(evaluate('workloadRenewalSetup(input)', application({client_renewal: enrollment({expires_at_epoch_ms: NOW})})), null);
    assert.equal(evaluate('workloadRenewalSetup(input)', application({token_expires_at_epoch_ms: NOW + 91 * 86400000, client_renewal: enrollment()})), null);
  }],
  ['public-key and finite lifetime payloads reject secrets and invalid limits', () => {
    const good = [ID, KEY, 30, 1];
    assert.deepEqual(evaluate('workloadRenewalEnrollment(...input)', good), {id: ID, public_key: KEY, enrollment_lifetime_seconds: 2592000, token_lifetime_seconds: 3600});
    for (const args of [[ID, 'BEGIN PRIVATE KEY', 30, 1], [ID, KEY.toUpperCase().replace('1', 'A'), 30, 1], [ID, KEY, 0, 1],
      [ID, KEY, 91, 1], [ID, KEY, 1.5, 1], [ID, KEY, 30, 0], [ID, KEY, 30, 25], [ID, KEY, 30, '1']])
      assert.throws(() => pure.run('workloadRenewalEnrollment(...input)', args));
  }],
  ['opening and choosing an existing client performs no mutation', async () => {
    const f = await fixture(); await f.select(); assert.equal(f.posts().length, 0);
    assert.match(f.node('application-renewal-summary').textContent, /Manual token rotation required/);
    assert.equal(f.node('application-renewal-days').value, '30'); assert.equal(f.node('application-renewal-hours').value, '1');
  }],
  ['unsupported, pending, busy and uncertain workspaces cannot enroll', async () => {
    for (const kind of ['unsupported', 'pending', 'busy', 'uncertain']) {
      const input = catalog(); if (kind === 'unsupported') delete input.capabilities.workload_renewal;
      if (kind === 'pending') input.policy.activation = 'pending';
      const f = await fixture({catalog: input}); await f.fill();
      if (['busy', 'uncertain'].includes(kind)) f.c.run('workspace.state.' + kind + ' = true; workspace.emit()');
      await f.submit(); assert.equal(f.posts().length, 0); assert(f.node('application-renewal-enroll').disabled);
    }
  }],
  ['explicit consent is mandatory even with valid input', async () => {
    const f = await fixture(); await f.fill(); f.node('application-renewal-consent').checked = false;
    await f.submit(); assert.equal(f.posts().length, 0); assert.equal(f.confirmations.length, 0);
  }],
  ['enrollment sends one exact CAS payload and returns public setup', async () => {
    const f = await fixture(); await f.fill(); await f.submit();
    assert.equal(f.posts().length, 1); assert.equal(f.posts()[0].path, '/api/operator-demo/applications/renewal/enroll');
    assert.deepEqual(f.invalidated, [ID]); assert.equal(f.node('application-renewal-key').value, '');
    assert.equal(f.node('application-renewal-consent').checked, false); assert(!f.c.run('workspace.state.uncertain'));
    assert.match(f.node('application-renewal-status').textContent, /Enrollment saved/);
    assert.equal(JSON.parse(f.node('application-renewal-setup').textContent).enrollment_id, ENROLLMENT);
    assert.match(f.confirmations[0], /replaces any previous enrollment/);
  }],
  ['replacement is explicit, finite and uses a new enrollment identifier', async () => {
    const f = await fixture({catalog: catalog({applications: [application({client_renewal: enrollment()})]})});
    await f.fill(); f.node('application-renewal-days').value = '1'; f.node('application-renewal-hours').value = '24'; await f.submit();
    assert.equal(f.posts().length, 1); assert.equal(f.state.applications[0].client_renewal.enrollment_id, REPLACEMENT);
    assert.equal(f.state.applications[0].client_renewal.token_lifetime_seconds, 86400);
    assert(!f.c.run('workspace.state.uncertain'));
  }],
  ['expired token does not prevent explicit finite enrollment', async () => {
    const expiry = NOW - 1; const f = await fixture({catalog: catalog({applications: [application({token_expires_at_epoch_ms: expiry, token_status: 'expired'})]})});
    await f.fill(); await f.submit(); assert.equal(f.posts().length, 1);
    assert.equal(f.state.applications[0].token_expires_at_epoch_ms, expiry); assert(!f.c.run('workspace.state.uncertain'));
  }],
  ['cancel sends no key or new lifetime and preserves current token', async () => {
    const f = await fixture({catalog: catalog({applications: [application({client_renewal: enrollment()})]})});
    await f.select(); await f.fire('application-renewal-cancel'); assert.equal(f.posts().length, 1);
    assert.equal(f.state.applications[0].client_renewal, null); assert.equal(f.state.applications[0].token_generation, 1);
    assert.equal(f.state.applications[0].token_expires_at_epoch_ms, NOW + 86400000);
    assert.match(f.node('application-renewal-summary').textContent, /Renewal cancelled/);
    assert(f.node('application-renewal-download').disabled); assert.deepEqual(f.invalidated, []);
  }],
  ['cancel remains available when capability is unavailable or policy is pending', async () => {
    for (const kind of ['unsupported', 'pending']) {
      const input = catalog({applications: [application({client_renewal: enrollment()})]});
      if (kind === 'unsupported') delete input.capabilities.workload_renewal;
      else input.policy.activation = 'pending';
      const f = await fixture({catalog: input}); await f.fill();
      assert(f.node('application-renewal-enroll').disabled); assert(f.node('application-renewal-download').disabled);
      assert(!f.node('application-renewal-cancel').disabled); assert(!f.node('application-renewal-client').disabled);
      await f.submit(); assert.equal(f.posts().length, 0);
      await f.fire('application-renewal-cancel'); assert.equal(f.posts().length, 1);
      assert.equal(f.posts()[0].path, '/api/operator-demo/applications/renewal/cancel');
      assert.equal(f.state.applications[0].client_renewal, null); assert(!f.c.run('workspace.state.uncertain'));
    }
  }],
  ['lost response refreshes saved state but blocks every retry until review', async () => {
    const f = await fixture({unknown: true}); await f.fill(); await f.submit(); await f.fill(); await f.submit();
    assert.equal(f.posts().length, 1); assert(f.c.run('workspace.state.uncertain'));
    assert.equal(f.node('application-renewal-key').value, KEY); // New typing is inert while uncertain.
    assert(f.node('application-renewal-download').disabled); assert.equal(f.state.applications[0].client_renewal.enrollment_id, ENROLLMENT);
  }],
  ['mismatched receipt cannot authorize setup or automatic reenrollment', async () => {
    for (const change of [r => { r.application.client_renewal.public_key_fingerprint = digest('f'); },
      r => { r.revision++; }, r => { r.client_token = 'unexpected'; }, r => { r.application.token_generation++; },
      r => { r.policy.sequence++; }, r => { r.application.active_rule_count++; },
      r => { r.application.client_renewal.expires_at_epoch_ms += 91 * 86400000; }]) {
      const f = await fixture({result: change}); await f.fill(); await f.submit();
      assert.equal(f.posts().length, 1); assert(f.c.run('workspace.state.uncertain')); assert(f.node('application-renewal-download').disabled);
    }
  }],
  ['refreshed-state conflict requires review even after a good response', async () => {
    const f = await fixture({afterRefresh: state => { state.applications[0].token_generation++; }});
    await f.fill(); await f.submit(); assert(f.c.run('workspace.state.uncertain'));
    assert.match(f.node('application-renewal-status').textContent, /refreshed saved state could not be confirmed/);
  }],
  ['saved but pending policy does not export setup or claim enforcement', async () => {
    const f = await fixture({pendingPolicy: true, catalog: catalog({applications: [application({active_rule_count: 1})]})}); await f.fill(); await f.submit();
    assert(!f.c.run('workspace.state.uncertain')); assert(f.node('application-renewal-download').disabled);
    assert.match(f.node('application-renewal-status').textContent, /Wait for the exact saved policy/);
  }],
  ['confirmation cancellation and concurrent catalog change send nothing', async () => {
    for (const confirm of [() => false, workspace => { workspace.state.catalog.revision++; return true; }]) {
      const f = await fixture({confirm}); await f.fill(); await f.submit(); assert.equal(f.posts().length, 0);
    }
  }],
  ['navigation clears typed public key and opt-in without saving', async () => {
    const f = await fixture(); await f.fill(); f.events.pagehide();
    assert.equal(f.node('application-renewal-key').value, ''); assert.equal(f.node('application-renewal-consent').checked, false);
    assert.equal(f.posts().length, 0);
  }],
  ['asset wiring and manual rotation cancellation remain explicit', () => {
    assert(files.indexOf('workspace_workload_renewal.js') < files.indexOf('workspace_applications.js'));
    assert.match(asset('workspace_applications.js'), /cancels any workload renewal enrollment/);
    assert(!asset('workspace_workload_renewal.js').includes('localStorage'));
    assert(!asset('workspace_workload_renewal.js').includes('sessionStorage'));
    assert.match(html, /Never|not a private key/); assert(!html.includes('No unlimited tokens or automatic renewal.'));
    const ids = [...html.matchAll(/\bid="([^"]+)"/g)].map(match => match[1]); assert.equal(ids.length, new Set(ids).size);
  }],
];
async function main() {
  assert.equal(process.argv.length, 2, 'No live targets accepted');
  for (const [name, test] of tests) { await test(); console.log('PASS ' + name); }
  console.log(JSON.stringify({ok: true, groups: tests.length, browser: false, network: false, source: 'closed renewal DTO and inert DOM only'}));
}
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

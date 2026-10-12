#!/usr/bin/env node
// Focused reload regression: actual core + Google controllers, inert DOM and
// synthetic GET responses only. Not browser/backend/provider acceptance.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {fileURLToPath} from 'node:url';
import vm from 'node:vm';

const ASSETS = new URL('../serverware/operator_demo_web/', import.meta.url);
const SOURCE = ['workspace_core.js', 'workspace_google.js', 'workspace_upstreams.js', 'workspace_google_configuration.js']
  .map(name => readFileSync(new URL(name, ASSETS), 'utf8')).join('\n');
const HTML = readFileSync(new URL('index.html', ASSETS), 'utf8');
const PATH = '/api/operator-demo/oauth/google/configuration/v2';
const KEY = 'serverware.operator.google.configuration.operation.v2';
const ID = '11111111-1111-4111-8111-111111111111';
const OWNER = '22222222-2222-4222-8222-222222222222';
const ORIGIN = 'https://operator.example.com';
const CLIENT = '123-synthetic.apps.googleusercontent.com';
const SECRET = 'synthetic-Google-secret-NEVER-STORE';
const PRIVATE = '<script>private-error-canary()</script>';
const SCOPES = ['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid'];
const OLD = {allowed_upstreams: ['https://demo-upstream:8443'], fixture_cidrs: ['127.0.0.1/32']};
const TARGET = {...OLD, allowed_upstreams: [...OLD.allowed_upstreams, 'https://gmail.googleapis.com']};
const hash = character => 'sha256:' + character.repeat(64);
const clone = value => JSON.parse(JSON.stringify(value));
const profile = {schema: 'serverware.operatorGoogleProfile/v1', profile: 'operator-google-v1', provider_id: 'google',
  client_id: CLIENT, redirect_uri: ORIGIN + '/api/oauth/callback/google', permission_preset: 'gmail_readonly', scopes: SCOPES,
  api_origins: ['https://gmail.googleapis.com'], authorization_url: 'https://accounts.google.com/o/oauth2/v2/auth',
  token_url: 'https://oauth2.googleapis.com/token', revocation_url: 'https://oauth2.googleapis.com/revoke',
  identity_url: 'https://openidconnect.googleapis.com/v1/userinfo'};
function operation(status = 'pending') {
  const value = {schema: 'serverware.operatorGoogleManagedSetup/v2', operation_id: ID, client_id: CLIENT,
    old_settings: clone(OLD), target_settings: clone(TARGET), expected_settings_digest: hash('b'), public_url: ORIGIN,
    redirect_uri: profile.redirect_uri, profile_binding: clone(profile), profile_binding_digest: hash('c'),
    reviewed_revision: 7, staged_revision: 8, policy_hash: hash('a'), created_at: '2026-10-10T12:00:00Z',
    setup_contract: 'serverware.operatorGoogleManagedSetupBinding/v2',
    custody_ref: {owner_id: OWNER, config_version: 1, key_source: 'operator-provider-key-v1'}, secret_present: true,
    status, revision: status === 'pending' ? 8 : 9,
    completed_at: status === 'pending' ? null : '2026-10-10T12:01:00Z', activation_receipt: null};
  if (status === 'activated') value.activation_receipt = {schema: 'serverware.operatorGoogleSetupActivation/v1',
    operation_id: ID, activated_revision: 9, policy_hash: hash('a'), profile_binding_digest: hash('c'),
    settings_digest: hash('d'), activated_at: value.completed_at};
  return value;
}
function discovery(op) {
  const state = op.status === 'cancelled' ? 'unconfigured' : op.status;
  return {schema: 'serverware.operatorGoogleConfiguration/v2', state, revision: op.revision, policy_hash: hash('a'),
    effective_settings: clone(state === 'activated' ? TARGET : OLD),
    effective_settings_digest: state === 'activated' ? hash('d') : hash('b'), public_url: ORIGIN,
    redirect_uri: profile.redirect_uri, permission_preset: 'gmail_readonly', scopes: [...SCOPES],
    blocked_reason: state === 'pending' ? 'pending_configuration' : state === 'activated' ? 'already_configured' : 'capacity',
    review: null, operation: state === 'unconfigured' ? null : clone(op),
    readiness: {pair_ready: true, consent_ready: state === 'activated', loaded_policy_hash: hash('a')}};
}
class Node {
  constructor(id) { this.id = id; this.events = {}; this.value = ''; this.children = []; this._text = ''; this.hidden = false; this.disabled = false; }
  get textContent() { return this._text + this.children.map(child => typeof child === 'string' ? child : child.textContent).join(''); }
  set textContent(value) { this._text = value; this.children = []; }
  append(...children) { this.children.push(...children); }
  addEventListener(name, callback) { (this.events[name] ||= []).push(callback); }
  querySelectorAll() { return []; }
  insertBefore(node, before) { this.inserted = {node: node.id, before: before.id}; }
  set innerHTML(_) { throw new Error('HTML injection forbidden'); }
}
function fixture(options = {}) {
  const nodes = new Map([...HTML.matchAll(/\bid="([^"]+)"/g)].map(match => [match[1], new Node(match[1])]));
  nodes.set('proxy-setup-content', new Node('proxy-setup-content'));
  const created = [];
  const node = id => { const value = nodes.get(id) || created.find(item => item.id === id); assert(value, 'Real element must exist'); return value; };
  node('mutation-review').hidden = true;
  const reference = {operation_id: ID, kind: options.kind || 'prepare'};
  const stored = Object.hasOwn(options, 'stored') ? options.stored : options.empty ? null : options.malformed ? '{' : JSON.stringify(reference);
  const storage = new Map(stored === null ? [] : [[KEY, stored]]); const writes = []; const calls = []; const forbidden = [];
  const state = {operation: clone(options.operation || operation()), status: 200, badOperation: false, discoveryTransform: null, removeFailure: false};
  const location = {origin: ORIGIN, protocol: 'https:', hash: '#overview'};
  const deny = name => () => { forbidden.push(name); throw new Error('Forbidden fixture effect'); };
  const context = vm.createContext({URL, Date, TextEncoder, location, element: node,
    window: {addEventListener() {}}, document: {getElementById: node,
      createElement() { const value = new Node(''); created.push(value); return value; }},
    sessionStorage: {getItem(key) { if (options.unreadable) throw new Error(PRIVATE); return storage.get(key) ?? null; },
      setItem(key, value) { writes.push({key, value}); storage.set(key, value); },
      removeItem(key) { if (state.removeFailure) throw new Error(PRIVATE); writes.push({key, removed: true}); storage.delete(key); }},
    localStorage: {getItem: deny('localStorage'), setItem: deny('localStorage')},
    crypto: {randomUUID: deny('new-operation')}, setTimeout: deny('timer'), clearTimeout() {},
    AbortSignal: {timeout(value) { assert.equal(value, 30000); return {}; }},
    fetch(path, init) {
      try {
        assert.equal(init.method, 'GET'); assert.equal(init.body, undefined);
        assert.equal(init.credentials, 'same-origin'); assert.equal(init.cache, 'no-store'); assert.equal(init.redirect, 'error');
        assert(path === PATH || path === PATH + '/' + ID);
      } catch (error) { forbidden.push('unexpected-request'); throw error; }
      calls.push({path, method: init.method});
      const body = state.status !== 200 ? {detail: PRIVATE} : path === PATH ?
        state.discoveryTransform ? state.discoveryTransform(discovery(state.operation)) : discovery(state.operation) :
        state.badOperation ? {...state.operation, operation_id: OWNER} : state.operation;
      return Promise.resolve({ok: state.status === 200, status: state.status,
        headers: {get: () => 'application/json'}, async text() { return JSON.stringify(body); }});
    },
  });
  vm.runInContext(SOURCE, context, {timeout: 2000});
  const workspace = vm.runInContext('createOperatorWorkspace()', context, {timeout: 1000});
  const catalog = () => ({revision: state.operation.revision, allowed_upstreams: clone(state.operation.status === 'activated' ? TARGET : OLD).allowed_upstreams,
    policy: {policy_hash: hash('a'), loaded_policy_hash: hash('a'), activation: 'active'}});
  workspace.state.catalog = catalog();
  workspace.refresh = async () => {
    workspace.state.catalog = catalog(); node('load-error').hidden = true;
    node('mutation-review-confirm').disabled = !workspace.state.uncertain;
    workspace.emit(); return true;
  };
  if (options.priorWarning) workspace.requireReview(options.priorWarning);
  if (options.xHold) workspace.setConsentHold(true, 'x-provider-configuration');
  context.workspaceFixture = workspace;
  const view = vm.runInContext('createGoogleConfigurationView(workspaceFixture)', context, {timeout: 1000});
  const event = async (id, type = 'click') => {
    const target = node(id); assert(Array.isArray(target.events[type]));
    for (const callback of target.events[type]) await callback({preventDefault() {}, currentTarget: target});
  };
  const navigate = active => { location.hash = active ? '#proxy' : '#overview'; return view.show(active); };
  const clean = ({retired = false, storedValue = stored} = {}) => {
    assert.equal(node('google-configuration-client-secret').value, ''); assert.deepEqual(writes, retired ? [{key: KEY, removed: true}] : []);
    assert.deepEqual(forbidden, []); assert.equal(storage.get(KEY) ?? null, retired ? null : storedValue);
    for (const value of [...nodes.values(), ...created].map(item => item.textContent)) assert(!value.includes(PRIVATE) && !value.includes(SECRET));
    assert(calls.every(call => call.method === 'GET'));
  };
  return {node, workspace, state, reference, storage, calls, view, event, navigate, location, clean};
}

const tests = [
  ['clean Overview load has no configuration hold, request or recovery banner', () => {
    const f = fixture({empty: true}); assert.equal(f.workspace.state.busy, false); assert.equal(f.workspace.state.uncertain, false);
    assert.equal(f.node('mutation-review').hidden, true); assert.deepEqual(f.calls, []); f.clean();
  }],
  ['retained prepare and cancel locators explain Overview hold and direct explicit read-only recovery', async () => {
    for (const kind of ['prepare', 'cancel']) {
      const f = fixture({kind}); assert.equal(f.location.hash, '#overview'); assert.deepEqual(f.calls, []);
      assert.equal(f.workspace.state.busy, true); assert.equal(f.workspace.ready('credentials'), false);
      assert.equal(f.node('mutation-review').hidden, false);
      assert.match(f.node('mutation-review-text').textContent, /Google.*recovery/);
      assert.match(f.node('google-configuration-recovery-hint').textContent, /Google.*Proxy setup.*Google provider settings.*Check operation result/);
      assert.equal(f.node('google-configuration-recovery-hint').hidden, false);
      assert.equal(f.node('google-configuration-recovery-link').href, '#proxy');
      assert.equal(f.node('google-configuration-recovery-link').textContent, 'Check Google configuration result');
      assert.match(f.node('google-configuration-operation-status').textContent, /unconfirmed|unknown/i);
      assert.equal(f.node('google-configuration-check').disabled, false, 'Check remains available during its own hold');
      assert.equal(f.node('google-configuration-operation-reference').textContent, ID);
      await f.navigate(true); assert.equal(f.location.hash, '#proxy'); assert.deepEqual(f.calls, []);
      assert.deepEqual(f.node('proxy').inserted, {node: 'google-configuration-panel', before: 'proxy-setup-content'});
      await f.event('mutation-review-confirm'); assert.equal(f.workspace.state.uncertain, true);
      f.node('google-configuration-client-secret').value = SECRET;
      await f.event('google-configuration-check');
      assert.deepEqual(f.calls, [{path: PATH + '/' + ID, method: 'GET'}, {path: PATH, method: 'GET'}]);
      assert.equal(f.workspace.state.busy, kind === 'cancel'); assert.equal(f.workspace.state.uncertain, true);
      assert.equal(f.storage.get(KEY), JSON.stringify(f.reference)); f.clean();
    }
  }],
  ['terminal GET retires only after explicit acknowledgement and second Overview load has no repeated hold', async () => {
    for (const status of ['cancelled', 'activated']) {
      const f = fixture({kind: 'cancel'}); await f.navigate(true); f.state.operation = operation(status);
      await f.event('google-configuration-check'); assert.equal(f.workspace.state.busy, false);
      assert.equal(f.node('google-configuration-recovery-hint').hidden, true);
      assert.equal(f.workspace.state.uncertain, true); assert.equal(f.workspace.ready('credentials'), false);
      assert.match(f.node('google-configuration-operation-status').textContent, status === 'cancelled' ? /Cancelled/ : /Activation is recorded/);
      assert.equal(f.storage.get(KEY), JSON.stringify(f.reference), 'A terminal GET alone never retires recovery');
      assert.equal(f.node('mutation-review-confirm').disabled, false, 'Fresh catalogue permits explicit acknowledgement');
      await f.event('mutation-review-confirm'); assert.equal(f.workspace.state.uncertain, false);
      assert.equal(f.workspace.ready('credentials'), true); assert.equal(f.calls.length, 2); f.clean({retired: true});
      const reloaded = fixture({stored: f.storage.get(KEY) ?? null, operation: f.state.operation});
      assert.equal(reloaded.workspace.state.uncertain, false); assert.equal(reloaded.workspace.state.busy, false);
      assert.equal(reloaded.workspace.ready('credentials'), true); assert.equal(reloaded.node('mutation-review').hidden, true);
      assert.deepEqual(reloaded.calls, []); reloaded.clean();
    }
  }],
  ['missing or mismatched operation never removes reference or authorizes replay', async () => {
    for (const code of [200, 404, 503]) {
      const f = fixture(); f.state.status = code; f.state.badOperation = code === 200; await f.navigate(true);
      await f.event('google-configuration-check'); assert.equal(f.workspace.state.busy, true);
      assert.equal(f.workspace.state.uncertain, true); assert.equal(f.node('google-configuration-prepare').disabled, true);
      await f.event('google-configuration-form', 'submit'); assert.equal(f.calls.length, 1); f.clean();
    }
  }],
  ['malformed or unreadable stored reference explains blocked recovery without new operation', async () => {
    for (const option of [{malformed: true}, {unreadable: true}]) {
      const f = fixture(option); assert.equal(f.workspace.state.busy, true); assert.equal(f.workspace.state.uncertain, true);
      assert.equal(f.node('mutation-review').hidden, false);
      assert.match(f.node('google-configuration-recovery-hint').textContent, /Google.*Proxy setup.*Google provider settings/);
      assert.equal(f.node('google-configuration-recovery-link').textContent, 'Review Google recovery status');
      assert.equal(f.node('google-configuration-recovery-link').href, '#proxy');
      assert.match(f.node('google-configuration-operation-status').textContent, /reference.*retained|storage|safely/i);
      assert.equal(f.node('google-configuration-check').disabled, true);
      await f.navigate(true); await f.event('google-configuration-form', 'submit'); assert.deepEqual(f.calls, []); f.clean();
    }
  }],
  ['Google terminal recovery cannot release independent X configuration hold', async () => {
    for (const prior of [false, true]) {
      const warning = 'X application save needs independent recovery.';
      const f = fixture({kind: 'cancel', priorWarning: prior ? warning : null, xHold: prior});
      if (!prior) { f.workspace.requireReview(warning); f.workspace.setConsentHold(true, 'x-provider-configuration'); }
      assert(f.node('mutation-review-text').textContent.startsWith(warning), 'Google preserves the existing owner warning');
      assert.equal(f.node('google-configuration-recovery-hint').hidden, false, 'Later owner warning preserves Google sibling link');
      assert.equal(f.node('google-configuration-recovery-link').href, '#proxy');
      await f.navigate(true); f.state.operation = operation('cancelled'); await f.event('google-configuration-check');
      assert.equal(f.node('google-configuration-recovery-hint').hidden, true);
      assert.equal(f.workspace.state.busy, true); assert.equal(f.workspace.ready('credentials'), false);
      await f.event('mutation-review-confirm'); assert.equal(f.workspace.state.uncertain, true);
      assert.equal(f.storage.get(KEY), JSON.stringify(f.reference), 'Another owner prevents retirement as well as writes');
      f.workspace.setConsentHold(false, 'x-provider-configuration'); assert.equal(f.workspace.state.busy, false);
      await f.event('mutation-review-confirm'); assert.equal(f.workspace.ready('credentials'), true); f.clean({retired: true});
    }
  }],
  ['pending status and current catalog or configuration drift never retire the retained locator', async () => {
    const pending = fixture(); await pending.navigate(true); await pending.event('google-configuration-check');
    await pending.event('mutation-review-confirm'); pending.clean();
    for (const change of ['catalog', 'settings', 'owner', 'profile', 'selection']) {
      const f = fixture(); f.state.operation = operation('activated'); await f.navigate(true);
      if (change !== 'catalog') f.state.discoveryTransform = value => {
        if (change === 'settings') value.effective_settings_digest = hash('e');
        if (change === 'owner') value.operation.custody_ref.owner_id = ID;
        if (change === 'profile') value.operation.profile_binding_digest = value.operation.activation_receipt.profile_binding_digest = hash('e');
        if (change === 'selection') value.operation = null;
        return value;
      };
      await f.event('google-configuration-check');
      if (change === 'catalog') { f.workspace.state.catalog.revision++; f.workspace.emit(); }
      await f.event('mutation-review-confirm'); assert.equal(f.calls.length, 2); f.clean();
    }
  }],
  ['changed retained locator or failed storage removal reestablishes recovery without clearing another reference', async () => {
    for (const changed of [false, true]) {
      const f = fixture(); f.state.operation = operation('cancelled'); await f.navigate(true); await f.event('google-configuration-check');
      const replacement = JSON.stringify({operation_id: OWNER, kind: 'prepare'});
      if (changed) f.storage.set(KEY, replacement); else f.state.removeFailure = true;
      await f.event('mutation-review-confirm');
      assert.equal(f.workspace.state.uncertain, true); assert.equal(f.workspace.state.busy, true);
      assert.equal(f.workspace.ready('credentials'), false); assert.equal(f.node('mutation-review').hidden, false);
      assert.equal(f.calls.length, 2); f.clean(changed ? {storedValue: replacement} : {});
    }
  }],
  ['reviewing already activated selected settings does not create a persistent interrupted-operation reference', async () => {
    const f = fixture({empty: true, operation: operation('activated')}); await f.navigate(true);
    await f.event('google-configuration-review');
    assert.deepEqual(f.calls, [{path: PATH, method: 'GET'}]);
    assert.equal(f.workspace.state.uncertain, false); assert.equal(f.workspace.state.busy, false);
    assert.match(f.node('google-configuration-operation-status').textContent, /Activation is recorded/);
    assert.equal(f.node('google-configuration-operation-reference').textContent, ID); f.clean();
  }],
];

let group = 'arguments';
try {
  assert.equal(process.argv.length, 2, 'No live target or execution arguments');
  for (const [name, test] of tests) { group = name; await test(); process.stdout.write('PASS ' + name + '\n'); }
  process.stdout.write(JSON.stringify({ok: true, groups: tests.length, browser: false, network: false,
    scope: 'actual core and Google controller; inert navigation/DOM and synthetic GETs, independent X owner via real core hold'}) + '\n');
} catch (error) {
  const path = fileURLToPath(import.meta.url);
  const frames = String(error?.stack || '').split('\n').filter(line => line.includes(path))
    .map(line => /:(\d+):(\d+)\)?$/.exec(line)).filter(Boolean).slice(0, 6)
    .map(match => ({line: Number(match[1]), column: Number(match[2])}));
  process.stderr.write(JSON.stringify({ok: false, group, frames}) + '\n'); process.exitCode = 1;
}

#!/usr/bin/env node
'use strict';
// Actual inline UI functions, independent synthetic DTOs and an inert DOM.
// No application import, browser, provider, HTTP, native authority or hardware.
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const source = readFileSync(resolve(__dirname, '../catchplate/app.py'), 'utf8');
const clone = value => JSON.parse(JSON.stringify(value));
function section(start, end) {
  const a = source.indexOf(start), b = source.indexOf(end, a + start.length);
  assert.ok(a >= 0 && b > a, `missing actual source section: ${start}`);
  assert.equal(source.indexOf(start, a + start.length), -1, `ambiguous start: ${start}`);
  assert.equal(source.indexOf(end, b + end.length), -1, `ambiguous end: ${end}`);
  return source.slice(a, b);
}
function declaration(prefix) {
  const lines = source.split('\n').filter(line => line.startsWith(`    ${prefix}`));
  assert.equal(lines.length, 1, `exact actual declaration: ${prefix}`);
  return lines[0];
}
const actual = [
  ...['const $ =', 'const esc =', 'const json =', 'const canonicalValue =',
    'let approvalReviewGeneration =', 'let approvalReviewLoadInFlight =',
    'let approvalDecisionInFlight =', 'const approvalDecisionUncertain =',
    'const approvalDecisionUnsent =', 'let resolvedApprovalDeepLink =', 'let csrfToken ='].map(declaration),
  section('    function adminToken(', '    let oidcSessionActivationBusy'),
  section('    class ApiError ', '    function setStatus('),
  section('    function setStatus(', '    function controlStateKey('),
  section('    function controlStateKey(', '    function splitPortalList('),
  section('    function credentialToJson(', '    function policyAuthorityPackage('),
  section('    async function api(', '    function persistPendingMutation('),
  section('    function queueStatusRank(', '    function redactAuditEvidence('),
  section('    function focusApprovalReview(', '    async function seedDemo('),
  `globalThis.ui = {deny, approve, loadApprovalReview, loadApprovalReviewAction, runUiAction, recoverApprovalDecision,
    renderJitApprovals, renderApprovalDecisionState, approvalReviewActionBlockReason,
    denialReason, api, bumpGeneration: () => ++approvalReviewGeneration,
    busy: () => approvalDecisionInFlight, held: id => approvalDecisionUncertain.has(id)};`
].join('\n');

// Public contracts independently checked against the decision DTOs,
// _authority_jit_decision_options and the public-summary/full-review producers.
const ID = '11111111-1111-4111-8111-111111111111';
const OTHER = '44444444-4444-4444-8444-444444444444';
const RECEIPT = '22222222-2222-4222-8222-222222222222';
const CHALLENGE = '33333333-3333-4333-8333-333333333333';
const MARKER = `catchplate.approvalDecisionUncertain.${ID}`;
const NOW = Date.parse('2030-01-01T00:00:00Z');
const digest = char => 'sha256:' + char.repeat(64);
const date = offset => new Date(NOW + offset).toISOString();
const credentialId = Buffer.from('test-credential').toString('base64url');
function metadata(id = ID) {
  return {id, status: 'pending', route_id: 'synthetic-route', principal_id: 'user:fixture',
    credential_id: 'synthetic-credential', credential_version: 1, policy_hash: digest('a'),
    request_digest: digest('b'), operation_digest: digest('c'), method: 'POST',
    url: digest('d'), requested_at: date(-10000), expires_at: date(60000),
    grant_ttl_seconds: 30, grant_max_uses: 1, approved_until: null, decision_note: null,
    approver_policy_digest: digest('f'), approver_policy: {principals: ['user:fixture'], threshold: 1}};
}
function review(id = ID) {
  const item = metadata(id);
  return {id, status: item.status, route_id: item.route_id, principal_id: item.principal_id,
    credential_ref: item.credential_id, credential_version: item.credential_version,
    policy_hash: item.policy_hash, method: item.method, requested_at: item.requested_at,
    expires_at: item.expires_at, url: 'https://synthetic.example.test/redacted',
    source_identity: {}, normalized_operation_fields: {}, redacted_payload_summary: {},
    risk_flags: ['credential_version_bound', 'policy_hash_current'], previous_similar_approvals: [],
    retry_semantics: {request_digest: item.request_digest, operation_digest: item.operation_digest,
      grant_ttl_seconds: 30, grant_max_uses: 1}, review_digest: digest('e'),
    review_receipt: {id: RECEIPT, expires_at: date(30000)}};
}
function options(kind = 'deny') {
  return {publicKey: {challenge: Buffer.alloc(32, 3).toString('base64url'),
    rpId: 'catchplate.example.test', allowCredentials: [{type: 'public-key', id: credentialId, transports: ['usb']}],
    timeout: 120000, userVerification: 'required'},
  catchplate: {authorityChallengeId: CHALLENGE, operation: kind === 'approve' ? 'jit.decide' : 'jit.deny'}};
}
function approvalResult(status = 'approved', threshold = 1) {
  return {...metadata(), status, approved_until: status === 'approved' ? date(30000) : null,
    approver_policy: {principals: threshold > 1 ? ['user:fixture', 'user:second'] : ['user:fixture'], threshold},
    data_plane_grant_publish: {enabled: status === 'approved', ok: status === 'approved', error: null}};
}
const buffer = value => Uint8Array.from(Buffer.from(value)).buffer;
function assertion() {
  return {id: credentialId, rawId: buffer('test-credential'), type: 'public-key',
    response: {clientDataJSON: buffer('synthetic-client-data'), authenticatorData: buffer('synthetic-auth-data'),
      signature: buffer('synthetic-signature'), userHandle: null}};
}
function deferred() {
  let resolve, reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return {promise, resolve, reject};
}

// Re-rendering genuinely replaces controls. Keeping the old note node would
// conceal a capture/restore regression, even though this is not a browser DOM.
function inertDocument() {
  const nodes = new Map();
  class Node {
    constructor(tag = 'div', attrs = {}) {
      this.tagName = tag.toUpperCase(); this.id = attrs.id || ''; this.attrs = attrs;
      this.value = attrs.value || ''; this.checked = false; this.readOnly = false;
      this.disabled = Object.hasOwn(attrs, 'disabled'); this.children = []; this._html = '';
      if (this.id) nodes.set(this.id, this);
    }
    set innerHTML(html) {
      for (const child of this.children) if (child.id) nodes.delete(child.id);
      this.children = []; this._html = html;
      const tags = /<(input|button|textarea|select)\b((?:[^>"']|"[^"]*"|'[^']*')*)>/g;
      for (const match of html.matchAll(tags)) {
        const attrs = {};
        for (const part of match[2].matchAll(/([\w-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
          attrs[part[1]] = part[2] ?? part[3] ?? part[4] ?? '';
        }
        this.children.push(new Node(match[1], attrs));
      }
    }
    get innerHTML() { return this._html; }
    get options() { return [{value: this.value}]; }
    setAttribute(key, value) { this.attrs[key] = value; }
    focus() {} scrollIntoView() {}
  }
  for (const id of ['admin-token', 'operator-status', 'approvals', 'approval-review',
    'approval-review-actions', 'jit-approval-search', 'jit-approval-status-filter']) {
    new Node(id.includes('filter') ? 'select' : id.includes('token') || id.includes('search') ? 'input' : 'div', {id});
  }
  nodes.get('jit-approval-status-filter').value = 'all';
  return {nodes, getElementById: id => nodes.get(id) || null,
    querySelectorAll: selector => {
      assert.equal(selector, 'input, select, textarea');
      return [...nodes.values()].filter(node => ['INPUT', 'SELECT', 'TEXTAREA'].includes(node.tagName));
    }};
}
function fixture(config = {}) {
  const document = inertDocument(), calls = [], prompts = [], events = [];
  const storage = config.storage || new Map(), control = {now: NOW, ...config};
  const state = {approvals: [metadata()], approvalReview: review(),
    authStatus: {authenticated: true, userId: 'user:fixture', authMethod: 'oidc', sessionState: 'active', roles: ['approver']}};
  let csrfCalls = 0, ui;
  const context = {
    state, document, ArrayBuffer, Uint8Array, TextEncoder,
    Date: class extends Date { static now() { return control.now; } },
    atob: value => Buffer.from(value, 'base64').toString('binary'),
    btoa: value => Buffer.from(value, 'binary').toString('base64'),
    requestAnimationFrame: callback => callback(),
    setTimeout: () => { throw Error('unexpected automatic timer'); },
    setInterval: () => { throw Error('unexpected automatic retry'); },
    window: {PublicKeyCredential: function SyntheticCredential() {}, history: {replaceState() {}},
      matchMedia: () => ({matches: false})},
    sessionStorage: {
      getItem(key) { if (control.storageGetError) throw Error('synthetic storage read failure'); return storage.get(key) ?? null; },
      setItem(key, value) { events.push(['store', key, value]); if (control.storageSetError) throw Error('synthetic storage write failure'); if (!control.storageDropWrite) storage.set(key, value); },
      removeItem(key) { events.push(['remove', key]); if (control.storageRemoveError) throw Error('synthetic storage removal failure'); storage.delete(key); }
    },
    navigator: {credentials: {get: async request => {
      prompts.push(request); events.push(['prompt']);
      return control.get ? control.get(request) : assertion();
    }}},
    ensureCsrfToken: async () => { csrfCalls++; return control.csrf ? control.csrf(csrfCalls) : 'synthetic-csrf'; },
    credentialReplacementApiGuard: () => null,
    discardCredentialReplacement() {}, renderAuthStatus() {},
    pill: value => String(value), routeName: value => value,
    render: () => ui.renderJitApprovals(),
    refresh: async () => { throw Error('unexpected broad refresh'); },
    fetch: async (path, init) => {
      assert.ok(path.startsWith('/api/approvals'), 'only inert approval API paths allowed');
      assert.equal(Object.hasOwn(init, 'checkContext'), false, 'local guard must not escape into fetch');
      const call = {path, method: init.method, body: init.body ? JSON.parse(init.body) : undefined,
        cache: init.cache, headers: clone(init.headers)};
      calls.push(call); events.push(['fetch', path]);
      let result;
      if (control.fetch) result = await control.fetch(call);
      if (result === undefined) {
        if (path.endsWith('/webauthn/options')) result = {value: options(path.includes('/deny/') ? 'deny' : 'approve')};
        else if (path.endsWith('/deny')) result = {value: {id: ID, status: 'denied'}};
        else if (path === `/api/approvals/${ID}/approve?ttl_seconds=30`) result = {value: approvalResult()};
        else if (path.endsWith('/review')) result = {value: review(path.split('/')[3])};
        else if (path === '/api/approvals') result = {value: [{...metadata(),
          status: calls.some(call => call.path.includes('/approve?')) ? 'approved' : 'denied'}]};
        else throw Error(`unexpected synthetic route: ${path}`);
      }
      return {ok: (result.status || 200) < 400, status: result.status || 200,
        text: async () => control.text ? control.text(call, result) : JSON.stringify(result.value)};
    }
  };
  vm.createContext(context);
  vm.runInContext(actual, context, {timeout: 1000, filename: 'actual-approval-ui.js'});
  ui = context.ui;
  ui.renderJitApprovals();
  const node = id => document.getElementById(id);
  const note = value => { const input = node(`approval-review-deny-note-${ID}`); assert.ok(input); input.value = value; };
  note(config.reason ?? 'Operator declined');
  return {ui, state, control, calls, prompts, events, storage, context, document, node, note};
}
const writes = f => f.calls.filter(call => call.method === 'POST');
const finals = f => f.calls.filter(call => call.path.endsWith('/deny'));
const approveFinals = f => f.calls.filter(call => call.path.includes('/approve?'));
async function refused(f) { await assert.rejects(f.ui.deny(ID)); assert.equal(finals(f).length, 0); assert.equal(f.ui.busy(), null); }
async function refusedApprove(f) { await assert.rejects(f.ui.approve(ID)); assert.equal(approveFinals(f).length, 0); assert.equal(f.ui.busy(), null); }
function noPrivateStorage(f) {
  for (const entry of f.events.filter(event => event[0] === 'store')) assert.deepEqual(entry, ['store', MARKER, ID]);
  for (const [key, value] of f.storage) assert.deepEqual([key, value], [MARKER, ID]);
}
const tests = [];
const group = (name, run) => tests.push({name, run});

group('exact options, assertion and denial payload through actual guarded API', async () => {
  const f = fixture({reason: '  Operator declined  '});
  assert.deepEqual(clone(await f.ui.deny(ID)), {uiHandled: true, denied: true});
  assert.deepEqual(f.calls.map(call => [call.method, call.path]), [
    ['POST', `/api/approvals/${ID}/deny/webauthn/options`], ['POST', `/api/approvals/${ID}/deny`], ['GET', '/api/approvals']]);
  assert.deepEqual(writes(f)[0].body, {reason: 'Operator declined', reviewReceiptId: RECEIPT});
  assert.deepEqual(finals(f)[0].body, {reason: 'Operator declined', reviewReceiptId: RECEIPT,
    authorityChallengeId: CHALLENGE, assertion: {id: credentialId, rawId: credentialId, type: 'public-key',
      response: Object.fromEntries(['clientDataJSON', 'authenticatorData', 'signature'].map(key =>
        [key, Buffer.from(assertion().response[key]).toString('base64url')]))}});
  assert.equal(f.prompts.length, 1);
  assert.equal(f.prompts[0].publicKey.timeout, 30000);
  assert.deepEqual([...f.prompts[0].publicKey.challenge], [...Buffer.alloc(32, 3)]);
  assert.deepEqual([...f.prompts[0].publicKey.allowCredentials[0].id], [...Buffer.from('test-credential')]);
  assert.equal(writes(f)[1].headers['X-Catchplate-CSRF-Token'], 'synthetic-csrf');
  assert.ok(f.events.findIndex(event => event[0] === 'store') < f.events.findIndex(event => event[1]?.endsWith('/deny')));
  assert.equal(f.calls[2].cache, 'no-store'); assert.equal(f.state.approvalReview, null);
  assert.equal(f.storage.size, 0); assert.equal(f.ui.held(ID), false); noPrivateStorage(f);
});
group('null and exact UTF-8 boundary reasons', async () => {
  for (const reason of ['', '   ', 'a'.repeat(500), 'é'.repeat(250), '😀'.repeat(125)]) {
    const f = fixture({reason}); await f.ui.deny(ID);
    assert.equal(finals(f)[0].body.reason, reason.trim() || null);
  }
});
group('oversize, control and invalid Unicode reason refused before options', async () => {
  for (const reason of ['a'.repeat(501), 'é'.repeat(251), '😀'.repeat(126), 'a\nb', 'a\x00b', 'a\x7fb', '\ud800']) {
    const f = fixture({reason}); await refused(f); assert.equal(f.calls.length, 0); assert.equal(f.prompts.length, 0);
  }
});
group('one panel reason survives actual replaced-control rendering', async () => {
  const entered = deferred(), released = deferred();
  const f = fixture({get: () => { entered.resolve(); return released.promise; }});
  const original = f.node(`approval-review-deny-note-${ID}`), pending = f.ui.deny(ID);
  await entered.promise;
  assert.notEqual(f.node(original.id), original); assert.equal(f.node(original.id).value, 'Operator declined');
  assert.equal(f.node(`jit-deny-note-${ID}`), null, 'queue must not offer a competing reason');
  for (const action of ['approve', 'deny']) assert.equal(f.node(`approval-review-${action}-${ID}`).disabled, true);
  const rowActions = f.node('approvals').children.filter(node => /=> (?:approve|deny)\(/.test(node.attrs.onclick || ''));
  assert.equal(rowActions.length, 2); assert.ok(rowActions.every(node => node.disabled));
  released.resolve(assertion()); await pending;
});
group('missing review or expired receipt loads once and stops for inspection', async () => {
  for (const mutation of [f => { f.state.approvalReview = null; }, f => { f.state.approvalReview = review(OTHER); },
    f => { delete f.state.approvalReview.review_receipt; }, f => { f.state.approvalReview.review_receipt.expires_at = date(0); }]) {
    const f = fixture(); mutation(f); const result = await f.ui.deny(ID);
    assert.equal(result.pending, true); assert.equal(result.reviewLoaded, true);
    assert.deepEqual(f.calls.map(call => call.path), [`/api/approvals/${ID}/review`]); assert.equal(f.prompts.length, 0);
  }
});
group('pending, expiry, current policy and exact public request binding required', async () => {
  const changes = [f => { f.state.approvals = []; }, f => { f.state.approvals[0].status = 'denied'; },
    f => { f.state.approvalReview.status = 'approved'; }, f => { f.control.now = NOW + 60000; f.state.approvalReview.review_receipt.expires_at = date(120000); },
    f => { f.state.approvalReview.risk_flags = []; }, f => { f.state.approvalReview.risk_flags.push('policy_hash_not_current'); },
    ...['route_id', 'principal_id', 'credential_version', 'policy_hash', 'expires_at', 'requested_at', 'method',
      'credential_id', 'request_digest', 'operation_digest'].map(key => f => { f.state.approvals[0][key] = 'changed'; })];
  for (const change of changes) { const f = fixture(); change(f); await refused(f); assert.equal(writes(f).length, 0); }
});
group('malformed receipt UUID or review digest cannot authorize a decision', async () => {
  for (const change of [r => { r.review_receipt.id = 'not-a-uuid'; }, r => { r.review_digest = digest('E'); }, r => { delete r.review_digest; }]) {
    const f = fixture(); change(f.state.approvalReview); f.ui.renderApprovalDecisionState();
    assert.equal(f.node(`approval-review-deny-${ID}`).disabled, true); await refused(f); assert.equal(writes(f).length, 0);
  }
});
group('WebAuthn unavailable or authority options refused produces no final write', async () => {
  for (const unavailable of ['window', 'navigator']) {
    const f = fixture(); if (unavailable === 'window') f.context.window.PublicKeyCredential = undefined;
    else f.context.navigator.credentials.get = undefined;
    await refused(f); assert.equal(writes(f).length, 0);
  }
  const f = fixture({fetch: async () => ({status: 503, value: {detail: 'synthetic authority unavailable'}})});
  await refused(f); assert.equal(writes(f).length, 1); assert.equal(f.prompts.length, 0);
});
group('malformed authority-bound options fail closed before prompting', async () => {
  const changes = [o => { o.catchplate.operation = 'jit.approve'; }, o => { o.catchplate.authorityChallengeId = ''; },
    o => { o.catchplate.authorityChallengeId = 'x'.repeat(513); }, o => { o.publicKey.challenge = 'bad='; },
    o => { o.publicKey.challenge = ''; }, o => { o.publicKey.challenge = 'AB'; },
    o => { o.publicKey.rpId = 'bad host'; }, o => { o.publicKey.rpId = ''; },
    o => { o.publicKey.userVerification = 'preferred'; }, ...[0, 120001, 1.5, '1000'].map(n => o => { o.publicKey.timeout = n; }),
    o => { o.publicKey.allowCredentials = []; }, o => { o.publicKey.allowCredentials[0].type = 'other'; },
    o => { o.publicKey.allowCredentials[0].id = 'AB'; }];
  for (const change of changes) {
    const value = options(); change(value); const f = fixture({fetch: async () => ({value})});
    await refused(f); assert.equal(f.prompts.length, 0); assert.equal(f.storage.size, 0);
  }
});
group('user cancellation never submits or stores a recovery marker', async () => {
  for (const name of ['NotAllowedError', 'AbortError']) {
    const f = fixture({get: async () => { const error = Error('synthetic cancellation'); error.name = name; throw error; }});
    assert.deepEqual(clone(await f.ui.deny(ID)), {uiHandled: true, cancelled: true});
    assert.equal(finals(f).length, 0); assert.equal(f.storage.size, 0); assert.equal(f.ui.busy(), null);
  }
});
group('malformed or unbound assertion refuses final submission', async () => {
  const changes = [a => null, a => ({...a, type: 'other'}), a => ({...a, id: 'other'}),
    a => ({...a, rawId: buffer('different')}), a => ({...a, response: {}}),
    ...['clientDataJSON', 'authenticatorData', 'signature'].flatMap(key => [
      a => ({...a, response: {...a.response, [key]: new ArrayBuffer(0)}}),
      a => ({...a, response: {...a.response, [key]: new ArrayBuffer(65537)}}),
      a => ({...a, response: {...a.response, [key]: new Uint8Array(3)}})])];
  for (const change of changes) { const f = fixture({get: async () => change(assertion())}); await refused(f); assert.equal(f.storage.size, 0); }
});
group('duplicate and conflicting decisions share one in-flight guard', async () => {
  for (const first of ['deny', 'approve']) {
    const entered = deferred(), released = deferred();
    const f = fixture({fetch: async call => {
      if (call.path.endsWith('/webauthn/options')) { entered.resolve(); return released.promise; }
    }});
    const pending = f.ui[first](ID); const settled = pending.catch(error => error);
    await entered.promise;
    await assert.rejects(f.ui.deny(ID), /in progress/); await assert.rejects(f.ui.approve(ID), /in progress/);
    assert.equal(writes(f).length, 1); released.reject(Error('synthetic stop before any final decision'));
    assert.ok(await settled); assert.equal(finals(f).length, 0); assert.equal(f.ui.busy(), null);
  }
});
const drift = [f => { f.state.approvalReview = clone(f.state.approvalReview); }, f => { f.ui.bumpGeneration(); },
  f => { f.state.approvalReview.review_receipt.id = OTHER; }, f => { f.state.approvalReview.review_digest = digest('f'); },
  f => { f.state.approvals[0].status = 'denied'; }, f => { f.state.approvals[0].policy_hash = digest('f'); },
  f => { f.state.authStatus.userId = 'user:changed'; }, f => { f.state.authStatus.roles = []; },
  f => { f.state.authStatus.sessionState = 'inactive'; }, f => { f.node('admin-token').value = 'synthetic-changed-token'; },
  f => { f.note('changed reason'); }, f => { f.control.now = NOW + 30000; }];
for (const phase of ['options', 'assertion']) group(`review, metadata, auth, reason and clocks remain current through ${phase}`, async () => {
  for (const change of drift) {
    const entered = deferred(), released = deferred();
    const f = fixture(phase === 'options' ? {fetch: async call => {
      if (call.path.endsWith('/webauthn/options')) { entered.resolve(); await released.promise; return {value: options()}; }
    }} : {get: async () => { entered.resolve(); await released.promise; return assertion(); }});
    const pending = f.ui.deny(ID), rejected = assert.rejects(pending);
    await entered.promise; change(f); released.resolve(); await rejected;
    assert.equal(finals(f).length, 0); assert.equal(f.ui.busy(), null);
  }
});
group('actual transport rechecks freshness after CSRF and response decoding', async () => {
  for (const stage of ['csrf', 'text']) {
    let f;
    f = fixture(stage === 'csrf' ? {csrf: async () => { f.note('changed during csrf'); return 'synthetic-csrf'; }}
      : {text: async (call, result) => { f.note('changed during decode'); return JSON.stringify(result.value); }});
    await refused(f); assert.equal(f.prompts.length, 0); assert.equal(writes(f).length, stage === 'csrf' ? 0 : 1);
  }
});
group('unknown final response recovers metadata only and never retries', async () => {
  for (const bad of ['lost', null, {id: OTHER, status: 'denied'}, {id: ID, status: 'pending'}, {status: 'denied'}]) {
    const f = fixture({fetch: async call => {
      if (call.path.endsWith('/deny')) { if (bad === 'lost') throw Error('synthetic lost reply'); return {value: bad}; }
      if (call.path === '/api/approvals') return {value: [metadata()]};
    }});
    assert.equal((await f.ui.deny(ID)).uncertain, true);
    assert.equal(finals(f).length, 1); assert.equal(f.state.approvalReview, null); assert.equal(f.storage.get(MARKER), ID);
    assert.deepEqual(f.calls.slice(2).map(call => [call.method, call.path]), [['GET', '/api/approvals']]);
    await assert.rejects(f.ui.deny(ID)); await assert.rejects(f.ui.approve(ID));
    assert.equal(f.calls.length, 3); noPrivateStorage(f);
  }
});
group('reload retains UUID-only hold and explicit Review remains metadata-only', async () => {
  const storage = new Map([[MARKER, ID]]), f = fixture({storage, fetch: async call => {
    assert.equal(call.path, '/api/approvals'); return {value: [metadata()]};
  }});
  await assert.rejects(f.ui.deny(ID)); await assert.rejects(f.ui.approve(ID));
  assert.equal(await f.ui.loadApprovalReview(ID), false);
  assert.deepEqual(f.calls.map(call => [call.method, call.path]), [['GET', '/api/approvals']]);
  assert.equal(f.state.approvalReview, null); assert.equal(storage.get(MARKER), ID); noPrivateStorage(f);
});
group('Review action preserves pending and terminal recovery messages through the real UI wrapper', async () => {
  for (const status of ['pending', 'denied']) {
    const f = fixture({storage: new Map([[MARKER, ID]]), fetch: async call => {
      assert.equal(call.path, '/api/approvals'); return {value: [{...metadata(), status}]};
    }});
    const result = await f.ui.runUiAction('Load approval review', () => f.ui.loadApprovalReviewAction(ID));
    assert.deepEqual(clone(result), {uiHandled: true, pending: true, reviewLoaded: false});
    assert.equal(f.node('operator-status').textContent,
      `Current approval status: ${status}. No decision or private review was retried.`);
    assert.equal(f.node('operator-status').className, 'operator-status pending');
    assert.deepEqual(f.calls.map(call => [call.method, call.path]), [['GET', '/api/approvals']]);
    assert.equal(f.state.approvalReview, null); assert.equal(f.prompts.length, 0);
    assert.equal(f.storage.get(MARKER) ?? null, status === 'pending' ? ID : null); noPrivateStorage(f);
  }
  assert.match(section('    function queueStatusRank(', '    function redactAuditEvidence('),
    /runUiAction\('Load approval review',\s*\(\)\s*=>\s*loadApprovalReviewAction\(/,
    'actual queue Review must use the status-preserving action wrapper');
});
group('pending, missing, duplicate or malformed recovery metadata retains hold', async () => {
  for (const value of [[metadata()], [], [metadata(), metadata()], {items: [metadata()]}, [{id: ID}], [{id: OTHER, status: 'denied'}]]) {
    const f = fixture({storage: new Map([[MARKER, ID]]), fetch: async () => ({value})});
    try { await f.ui.loadApprovalReview(ID); } catch (_) { /* Refusal is expected for malformed metadata. */ }
    assert.equal(f.storage.get(MARKER), ID); assert.equal(f.state.approvalReview, null);
    assert.equal(f.calls.length, 1); assert.equal(f.calls[0].path, '/api/approvals');
  }
});
group('only exact terminal metadata releases a submitted hold without reopening review', async () => {
  for (const status of ['approved', 'denied', 'expired', 'superseded']) {
    const f = fixture({storage: new Map([[MARKER, ID]]), fetch: async () => ({value: [{...metadata(), status}]})});
    assert.equal(await f.ui.loadApprovalReview(ID), false);
    assert.equal(f.storage.size, 0); assert.equal(f.ui.held(ID), false); assert.equal(f.state.approvalReview, null);
    assert.equal(f.calls.length, 1); assert.equal(f.calls[0].path, '/api/approvals');
  }
});
group('storage unavailability or malformed marker refuses decisions before any request', async () => {
  for (const config of [{storageGetError: true}, {storage: new Map([[MARKER, 'malformed']])}]) {
    const f = fixture(config); await refused(f); assert.equal(f.calls.length, 0); assert.equal(f.prompts.length, 0);
  }
});
group('failed hold installation never dispatches denial and permits explicit unsent recovery', async () => {
  for (const config of [{storageSetError: true}, {storageDropWrite: true}, {storageDropWrite: true, storageRemoveError: true}]) {
    const f = fixture(config); await refused(f); assert.equal(writes(f).length, 1);
    assert.equal(f.calls.some(call => call.path === '/api/approvals'), false, 'provably unsent is not unknown backend outcome');
    f.control.storageSetError = false; f.control.storageDropWrite = false; f.control.storageRemoveError = false;
    assert.equal(await f.ui.loadApprovalReview(ID), true, 'explicit action may clear only provably-unsent residue');
    assert.equal(finals(f).length, 0); assert.equal(f.storage.size, 0); assert.equal(f.ui.held(ID), false);
  }
});
group('same-page submitted hold cannot be bypassed by deleting its storage marker', async () => {
  const f = fixture({fetch: async call => {
    if (call.path.endsWith('/deny')) throw Error('synthetic unknown outcome');
    if (call.path === '/api/approvals') return {value: [metadata()]};
  }});
  await f.ui.deny(ID); f.storage.delete(MARKER);
  await assert.rejects(f.ui.deny(ID)); await assert.rejects(f.ui.approve(ID));
  assert.equal(finals(f).length, 1); assert.equal(f.ui.held(ID), true);
});
group('competing review responses cannot replace the latest explicit selection', async () => {
  const entered = deferred(), released = deferred();
  const f = fixture({fetch: async call => {
    if (call.path === `/api/approvals/${ID}/review`) { entered.resolve(); await released.promise; return {value: review()}; }
  }});
  const first = f.ui.loadApprovalReview(ID); await entered.promise;
  assert.equal(await f.ui.loadApprovalReview(OTHER), true);
  released.resolve(); assert.equal(await first, false); assert.equal(f.state.approvalReview.id, OTHER);
});
group('automatic deep-link loading cannot replace selection or issue receipts while held', async () => {
  const f = fixture(); assert.equal(await f.ui.loadApprovalReview(OTHER, {automatic: true}), false); assert.equal(f.calls.length, 0);
  const held = fixture({storage: new Map([[MARKER, ID]])}); held.state.approvalReview = null;
  assert.equal(await held.ui.loadApprovalReview(ID, {automatic: true}), false); assert.equal(held.calls.length, 0);
  const entered = deferred(), released = deferred();
  const racing = fixture({fetch: async call => { entered.resolve(); await released.promise; return {value: review(ID)}; }});
  racing.state.approvalReview = null;
  const explicit = racing.ui.loadApprovalReview(ID); await entered.promise;
  assert.equal(await racing.ui.loadApprovalReview(OTHER, {automatic: true}), false);
  released.resolve(); assert.equal(await explicit, true); assert.equal(racing.calls.length, 1);
  assert.match(source, /loadApprovalReview\(directApprovalId,\s*\{automatic:\s*true\}\)/,
    'actual refresh must delegate to the guarded automatic-load helper');
});

group('approval requires the exact authority-bound assertion and policy TTL', async () => {
  const f = fixture();
  const result = await f.ui.approve(ID);
  assert.equal(result.uiHandled, true); assert.equal(result.approved, true);
  assert.deepEqual(f.calls.map(call => [call.method, call.path]), [
    ['POST', `/api/approvals/${ID}/webauthn/options`],
    ['POST', `/api/approvals/${ID}/approve?ttl_seconds=30`], ['GET', '/api/approvals']]);
  assert.deepEqual(writes(f)[0].body, {reviewReceiptId: RECEIPT, ttlSeconds: 30});
  assert.deepEqual(approveFinals(f)[0].body, {reviewReceiptId: RECEIPT, authorityChallengeId: CHALLENGE,
    assertion: {id: credentialId, rawId: credentialId, type: 'public-key',
      response: Object.fromEntries(['clientDataJSON', 'authenticatorData', 'signature'].map(key =>
        [key, Buffer.from(assertion().response[key]).toString('base64url')]))}});
  assert.equal(f.prompts.length, 1); assert.equal(f.prompts[0].publicKey.userVerification, 'required');
  assert.equal(f.prompts[0].publicKey.timeout, 30000);
  assert.ok(f.events.findIndex(event => event[0] === 'store')
    < f.events.findIndex(event => event[0] === 'fetch' && event[1].includes('/approve?')));
  assert.equal(f.state.approvalReview, null); assert.equal(f.storage.size, 0); assert.equal(f.ui.held(ID), false);
  noPrivateStorage(f);
});
group('approval refreshes missing or expired review and waits for inspection', async () => {
  for (const change of [f => { f.state.approvalReview = null; },
    f => { f.state.approvalReview.review_receipt.expires_at = date(0); }]) {
    const f = fixture(); change(f); const result = await f.ui.approve(ID);
    assert.equal(result.pending, true); assert.equal(result.reviewLoaded, true);
    assert.deepEqual(f.calls.map(call => [call.method, call.path]), [['GET', `/api/approvals/${ID}/review`]]);
    assert.equal(f.prompts.length, 0); assert.equal(f.storage.size, 0);
  }
});
group('approval TTL is an exact bounded integer shared by metadata and review', async () => {
  for (const ttl of [0, 3601, 1.5, '30', null, undefined]) {
    const f = fixture(); f.state.approvals[0].grant_ttl_seconds = ttl;
    f.state.approvalReview.retry_semantics.grant_ttl_seconds = ttl;
    await refusedApprove(f); assert.equal(f.calls.length, 0);
  }
  const f = fixture(); f.state.approvalReview.retry_semantics.grant_ttl_seconds = 31;
  await refusedApprove(f); assert.equal(f.calls.length, 0);
  for (const threshold of [0, 17, 1.5, '2', undefined]) {
    const f = fixture(); f.state.approvals[0].approver_policy.threshold = threshold;
    await refusedApprove(f); assert.equal(f.calls.length, 0);
  }
});
group('approval cannot omit WebAuthn or continue after authority options refusal', async () => {
  for (const missing of ['window', 'navigator']) {
    const f = fixture();
    if (missing === 'window') f.context.window.PublicKeyCredential = undefined;
    else f.context.navigator.credentials.get = undefined;
    await refusedApprove(f); assert.equal(writes(f).length, 0);
  }
  const f = fixture({fetch: async () => ({status: 503, value: {detail: 'synthetic authority unavailable'}})});
  await refusedApprove(f); assert.equal(writes(f).length, 1); assert.equal(f.prompts.length, 0);
});
group('approval rejects wrong operation, unbound credentials and malformed options', async () => {
  const changes = [o => { o.catchplate.operation = 'jit.deny'; }, o => { o.catchplate.operation = 'jit.approve'; },
    o => { o.catchplate.authorityChallengeId = ''; }, o => { o.publicKey.allowCredentials = []; },
    o => { o.publicKey.allowCredentials[0].id = 'AB'; }, o => { o.publicKey.allowCredentials[0].type = 'other'; },
    o => { o.publicKey.challenge = ''; }, o => { o.publicKey.userVerification = 'preferred'; },
    o => { o.publicKey.rpId = 'bad host'; }, o => { o.publicKey.timeout = 120001; }];
  for (const change of changes) {
    const value = options('approve'); change(value); const f = fixture({fetch: async () => ({value})});
    await refusedApprove(f); assert.equal(f.prompts.length, 0); assert.equal(f.storage.size, 0);
  }
});
group('approval cancellation cannot create a final decision or recovery hold', async () => {
  for (const name of ['NotAllowedError', 'AbortError']) {
    const f = fixture({get: async () => { const error = Error('synthetic cancellation'); error.name = name; throw error; }});
    const result = await f.ui.approve(ID); assert.equal(result.uiHandled, true); assert.equal(result.cancelled, true);
    assert.equal(approveFinals(f).length, 0); assert.equal(f.storage.size, 0); assert.equal(f.ui.busy(), null);
  }
});
group('approval refuses missing or ineligible assertion bytes', async () => {
  const changes = [a => null, a => ({...a, id: 'other'}), a => ({...a, rawId: buffer('other')}),
    a => ({...a, response: {...a.response, signature: new ArrayBuffer(0)}}),
    a => ({...a, response: {...a.response, authenticatorData: new Uint8Array(3)}}),
    a => ({...a, response: {...a.response, clientDataJSON: new ArrayBuffer(65537)}})];
  for (const change of changes) {
    const f = fixture({get: async () => change(assertion())}); await refusedApprove(f); assert.equal(f.storage.size, 0);
  }
});
for (const phase of ['options', 'assertion']) group(`approval review, auth, TTL and receipt stay fresh through ${phase}`, async () => {
  const changes = [f => { f.state.approvalReview = clone(f.state.approvalReview); }, f => { f.ui.bumpGeneration(); },
    f => { f.state.approvalReview.review_receipt.id = OTHER; }, f => { f.state.approvalReview.review_digest = digest('f'); },
    f => { f.state.approvals[0].status = 'denied'; }, f => { f.state.approvals[0].policy_hash = digest('f'); },
    f => { f.state.approvals[0].grant_ttl_seconds = 31; },
    f => { f.state.approvalReview.retry_semantics.grant_ttl_seconds = 31; },
    f => { f.state.authStatus.userId = 'user:changed'; }, f => { f.state.authStatus.roles = []; },
    f => { f.state.authStatus.sessionState = 'inactive'; }, f => { f.node('admin-token').value = 'synthetic-changed-token'; },
    f => { f.control.now = NOW + 30000; }];
  for (const change of changes) {
    const entered = deferred(), released = deferred();
    const f = fixture(phase === 'options' ? {fetch: async call => {
      if (call.path.endsWith('/webauthn/options')) { entered.resolve(); await released.promise; return {value: options('approve')}; }
    }} : {get: async () => { entered.resolve(); await released.promise; return assertion(); }});
    const pending = f.ui.approve(ID), rejected = assert.rejects(pending);
    await entered.promise; change(f); released.resolve(); await rejected;
    assert.equal(approveFinals(f).length, 0); assert.equal(f.ui.busy(), null);
  }
});
group('approval transport rechecks context after CSRF and options decoding', async () => {
  for (const stage of ['csrf', 'text']) {
    let f;
    f = fixture(stage === 'csrf'
      ? {csrf: async () => { f.state.authStatus.userId = 'user:changed'; return 'synthetic-csrf'; }}
      : {text: async (call, result) => { f.state.authStatus.userId = 'user:changed'; return JSON.stringify(result.value); }});
    await refusedApprove(f); assert.equal(f.prompts.length, 0); assert.equal(writes(f).length, stage === 'csrf' ? 0 : 1);
  }
});
group('unknown approval blocks both decisions and recovers metadata without replay', async () => {
  for (const bad of ['lost', null, {id: ID, status: 'approved'}, {id: OTHER, status: 'approved'}]) {
    const f = fixture({fetch: async call => {
      if (call.path.includes('/approve?')) { if (bad === 'lost') throw Error('synthetic lost reply'); return {value: bad}; }
      if (call.path === '/api/approvals') return {value: [metadata()]};
    }});
    assert.equal((await f.ui.approve(ID)).uncertain, true);
    assert.equal(approveFinals(f).length, 1); assert.equal(f.state.approvalReview, null);
    assert.deepEqual(f.calls.slice(2).map(call => [call.method, call.path]), [['GET', '/api/approvals']]);
    assert.equal(f.storage.get(MARKER), ID); noPrivateStorage(f);
    await assert.rejects(f.ui.approve(ID)); await assert.rejects(f.ui.deny(ID)); assert.equal(f.calls.length, 3);
    const reloaded = fixture({storage: f.storage, fetch: async () => ({value: [metadata()]})});
    await assert.rejects(reloaded.ui.approve(ID)); await assert.rejects(reloaded.ui.deny(ID));
    await reloaded.ui.loadApprovalReviewAction(ID);
    assert.deepEqual(reloaded.calls.map(call => [call.method, call.path]), [['GET', '/api/approvals']]);
    assert.equal(reloaded.storage.get(MARKER), ID); assert.equal(reloaded.state.approvalReview, null);
  }
});
group('known threshold vote remains pending without claiming a usable grant', async () => {
  const value = approvalResult('pending', 2);
  const f = fixture({fetch: async call => {
    if (call.path.includes('/approve?')) return {value};
    if (call.path === '/api/approvals') return {value: [{...metadata(), approver_policy: clone(value.approver_policy)}]};
  }});
  f.state.approvals[0].approver_policy = clone(value.approver_policy);
  const result = await f.ui.runUiAction('Approve request', () => f.ui.approve(ID));
  assert.equal(result.uiHandled, true); assert.equal(result.pending, true); assert.notEqual(result.approved, true);
  assert.match(f.node('operator-status').textContent, /vote|threshold/i);
  assert.match(f.node('operator-status').textContent, /pending|no grant|waiting|await/i);
  assert.notEqual(f.node('operator-status').className, 'operator-status success');
  assert.equal(approveFinals(f).length, 1); assert.equal(f.calls.length, 3);
  assert.equal(f.state.approvalReview, null); assert.equal(f.storage.size, 0); assert.equal(f.ui.held(ID), false);
});
group('approval response must preserve reviewed identity and valid decision semantics', async () => {
  const changes = [r => { r.route_id = 'other'; }, r => { r.principal_id = 'user:other'; },
    r => { r.credential_version = 2; }, r => { r.policy_hash = digest('f'); }, r => { r.request_digest = digest('f'); },
    r => { r.operation_digest = digest('f'); }, r => { r.approved_until = date(0); },
    r => { r.status = 'pending'; r.approved_until = null; }, r => { r.approver_policy.threshold = 2; },
    r => { r.data_plane_grant_publish.enabled = 'true'; }, r => { r.data_plane_grant_publish.ok = null; },
    r => { delete r.data_plane_grant_publish; }];
  for (const change of changes) {
    const value = approvalResult(); change(value);
    const f = fixture({fetch: async call => {
      if (call.path.includes('/approve?')) return {value};
      if (call.path === '/api/approvals') return {value: [metadata()]};
    }});
    assert.equal((await f.ui.approve(ID)).uncertain, true);
    assert.equal(approveFinals(f).length, 1); assert.equal(f.storage.get(MARKER), ID);
    assert.equal(f.state.approvalReview, null); assert.equal(f.calls.length, 3);
  }
});
group('known approval with failed grant publication warns without retrying decision', async () => {
  const value = approvalResult(); value.data_plane_grant_publish = {enabled: true, ok: false, error: 'synthetic delivery unavailable'};
  const f = fixture({fetch: async call => call.path.includes('/approve?') ? {value} : undefined});
  const result = await f.ui.runUiAction('Approve request', () => f.ui.approve(ID));
  assert.equal(result.uiHandled, true); assert.equal(result.approved, true); assert.notEqual(result.uncertain, true);
  assert.match(f.node('operator-status').textContent, /publish|publication|deliver/i);
  assert.notEqual(f.node('operator-status').className, 'operator-status success');
  assert.equal(approveFinals(f).length, 1); assert.equal(f.calls.length, 3); assert.equal(f.storage.size, 0);
});
group('approval installs a durable hold before submission or fails without a final POST', async () => {
  for (const config of [{storageGetError: true}, {storageSetError: true}, {storageDropWrite: true}]) {
    const f = fixture(config); await refusedApprove(f);
    assert.equal(f.calls.some(call => call.path === '/api/approvals'), false);
    assert.equal(writes(f).length, config.storageGetError ? 0 : 1); noPrivateStorage(f);
  }
});

(async () => {
  for (const {name, run} of tests) { await run(); process.stdout.write(`PASS ${name}\n`); }
  process.stdout.write(JSON.stringify({ok: true, groups: tests.length, browser: false, network: false,
    scope: 'actual approval UI functions with inert DOM and synthetic API/WebAuthn; not browser or protected authority acceptance'}) + '\n');
})().catch(error => { console.error(error); process.exitCode = 1; });

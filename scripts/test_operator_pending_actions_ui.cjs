#!/usr/bin/env node
'use strict';
// Actual public queue module, inert DOM and synthetic GET replies only. No app,
// browser, network, authority, private review, decision or deployment acceptance.
const assert = require('node:assert/strict');
const {mutationReviewStorage} = require('./operator_mutation_recovery_test_helpers.cjs');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const {createHash} = require('node:crypto');
const vm = require('node:vm');
const SOURCE = resolve(__dirname, '../serverware/operator_demo_web/workspace_pending_actions.js');
const CORE = resolve(__dirname, '../serverware/operator_demo_web/workspace_core.js');
const CAP = '/api/approvals/capabilities', LIST = '/api/approvals?status=pending';
const HOST = '/api/operator-demo/approvals';
const NOW = Date.parse('2026-10-13T12:00:00Z');
const ID = '11111111-1111-4111-8111-111111111111', OTHER = '22222222-2222-4222-8222-222222222222';
const DETAIL = '/api/approvals/' + ID, OTHER_DETAIL = '/api/approvals/' + OTHER;
const PRIVATE = 'synthetic-private-review-must-not-appear';
const INJECTED = '<img src="https://untrusted.example.test/x" onerror="globalThis.pendingInjected=true">';
const copy = value => JSON.parse(JSON.stringify(value));
const capability = (changes = {}) => ({schema: 'serverware.approvalCapabilities/v1', can_list: true,
  can_open_native_review: false, can_decide: false, reason: 'protected_review_unavailable', ...changes});
const hostCapability = (changes = {}) => ({schema: 'serverware.approvalCapabilities/v2', mode: 'host_trusted_v1',
  can_list: true, can_review: true, can_decide: true, reason: null, ...changes});
const approval = (changes = {}) => ({id: ID, status: 'pending', route_id: 'synthetic.status.read', method: 'GET',
  url: 'sha256:' + 'a'.repeat(64), requested_at: new Date(NOW - 1000).toISOString(), expires_at: new Date(NOW + 600000).toISOString(),
  principal_id: 'agent:synthetic-client', credential_id: 'synthetic-credential', credential_version: 1,
  policy_hash: 'sha256:' + 'b'.repeat(64), ...changes});
const hostApproval = (changes = {}) => approval({assurance: 'host-trusted', reviewer_id: 'user:operator',
  consumed_at: null, approved_until: null, ...changes});
const hostReview = (changes = {}) => ({assurance: 'host-trusted', approval: hostApproval(),
  document: {...Object.fromEntries(['method', 'url', 'principal_id', 'route_id', 'credential_id', 'credential_version', 'policy_hash']
    .map(key => [key, hostApproval()[key]])), request_digest: 'sha256:' + 'c'.repeat(64), operation_digest: 'sha256:' + 'd'.repeat(64),
    headers: {accept: 'application/json'}, query: {}, body_sha256: 'sha256:' + 'e'.repeat(64), operation: {name: 'synthetic.status.read'}},
  review_receipt_id: OTHER, review_digest: 'sha256:' + 'f'.repeat(64), review_expires_at: new Date(NOW + 60000).toISOString(), ...changes});
function deferred() { let release; const promise = new Promise(resolve => { release = resolve; }); return {promise, release}; }
const flush = async () => { for (let i = 0; i < 24; i++) await Promise.resolve(); };
const response = (body, status = 200, type = 'application/json') => ({ok: status >= 200 && status < 300, status,
  headers: {get: name => name.toLowerCase() === 'content-type' ? type : null}, text: async () => JSON.stringify(body)});
class Node {
  constructor(tag = 'div') { this.tagName = tag; this.children = []; this.events = {}; this.attributes = {};
    this.dataset = {}; this.hidden = false; this.disabled = false; this.ownText = ''; }
  set textContent(value) { this.ownText = String(value); this.children = []; }
  get textContent() { return this.ownText + this.children.map(child => typeof child === 'string' ? child : child.textContent).join(' '); }
  set innerHTML(_) { throw new Error('HTML insertion is forbidden'); }
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.ownText = ''; this.children = [...children]; }
  setAttribute(name, value) { this.attributes[name] = String(value); }
  addEventListener(name, callback) { this.events[name] = callback; }
  focus() { this.focused = true; }
}
function descendants(node) { return node.children.flatMap(child => typeof child === 'string' ? [] : [child, ...descendants(child)]); }
function load(extras = {}) {
  const context = vm.createContext({module: {exports: {}}, Date: class extends Date { static now() { return NOW; } },
    ...extras});
  vm.runInContext(readFileSync(SOURCE, 'utf8'), context, {timeout: 1000, filename: SOURCE});
  return context.module.exports;
}
function fixture(options = {}) {
  const nodes = new Map(['pending-actions', 'pending-actions-status', 'pending-actions-access', 'pending-actions-refresh',
    'pending-actions-list', 'pending-actions-selected'].map(id => [id, new Node()]));
  const node = id => { assert(nodes.has(id), 'known queue DOM target'); return nodes.get(id); };
  const calls = [], faults = [], replacements = [], storageReads = [], events = {}, storage = new Map(options.storage || []);
  const allowedPaths = options.host ? [CAP, HOST, HOST + '/' + ID, HOST + '/' + OTHER,
    HOST + '/' + ID + '/review', HOST + '/' + ID + '/decision'] : [CAP, LIST, DETAIL, OTHER_DETAIL];
  let authLost = 0;
  const api = load({document: {getElementById: node, createElement: tag => new Node(tag)}, AbortController,
    AbortSignal: {any: signals => AbortSignal.any(signals), timeout: value => {
      assert(options.host ? [15000, 30000].includes(value) : value === 15000); return new AbortController().signal;
    }}, setTimeout() { throw new Error('queue must not poll'); }, setInterval() { throw new Error('queue must not poll'); },
    window: {addEventListener: (name, callback) => { events[name] = callback; }},
    history: {replaceState: (state, title, path) => { assert.equal(state, null); assert.equal(title, ''); replacements.push(path); }},
    sessionStorage: {getItem: key => { storageReads.push(key); if (options.storageFailure) throw new Error('unavailable'); return storage.get(key) ?? null; },
      setItem(key, value) { if (!options.host || options.storageFailure) throw new Error('queue must not write recovery storage'); storage.set(key, value); },
      removeItem(key) { if (!options.host || options.storageFailure) throw new Error('queue must not clear recovery storage'); storage.delete(key); }},
    fetch: async (path, init) => {
      const call = {path, init}; calls.push(call);
      try {
        assert(allowedPaths.includes(path));
        const post = options.host && ['/review', '/decision'].some(suffix => path.endsWith(suffix));
        assert.equal(init.method, post ? 'POST' : 'GET'); if (!post) assert.equal(init.body, undefined);
        assert.equal(init.credentials, 'same-origin'); assert.equal(init.cache, 'no-store'); assert.equal(init.redirect, 'error');
        assert.deepEqual(copy(init.headers), {Accept: 'application/json', ...(post ? {'Content-Type': 'application/json'} : {})}); assert(init.signal instanceof AbortSignal);
        if (options.handler) return await options.handler(call, calls.length);
        if ([DETAIL, OTHER_DETAIL, HOST + '/' + ID, HOST + '/' + OTHER].includes(path)) return response(options.selected || {}, options.selected ? 200 : 404);
        return path === CAP ? response(options.capability || (options.host ? hostCapability() : capability()), options.capStatus || 200) :
          response(options.rows || [], options.listStatus || 200);
      } catch (error) { faults.push(error.message); throw error; }
    }});
  const view = api.createPendingActionsView({onAuthenticationLost: () => { authLost++; options.onAuthenticationLost?.(); }});
  return {api, view, node, calls, faults, replacements, storage, storageReads, events,
    get authLost() { return authLost; },
    async show(selection = {}) { view.show(true, selection); await flush(); },
    buttons(id = 'pending-actions-selected') { return descendants(node(id)).filter(value => value.tagName === 'button'); },
    verify() { assert.deepEqual(faults, []); assert(calls.every(call => allowedPaths.includes(call.path))); }};
}
function workspaceFixture(handler) {
  // Reuse the existing inert catalog DOM and literal public catalog fixture;
  // run the actual core transport, projection, refresh and mutation functions.
  const {context, rawCatalog} = require('./test_operator_npm_ui.cjs');
  const f = context(), calls = [], faults = [], timers = new Map(); let nextTimer = 0;
  const raw = rawCatalog({credentials: [], rules: [], capability: null});
  const reply = (body = raw, status = 200) => ({...response(body, status), json: async () => copy(body)});
  Object.assign(f.value, {sessionStorage: mutationReviewStorage(), AbortSignal: {timeout: delay => { assert.equal(delay, 30000); return undefined; }},
    setTimeout(callback, delay) { assert.equal(delay, 2000); timers.set(++nextTimer, callback); return nextTimer; },
    clearTimeout(id) { timers.delete(id); },
    fetch: async (path, init) => {
      const call = {path, method: init.method || 'GET', body: init.body}; calls.push(call);
      try {
        assert.equal(init.credentials, 'same-origin'); assert.equal(init.cache, 'no-store'); assert.equal(init.redirect, 'error');
        return await handler(call, {raw, reply, calls});
      } catch (error) { faults.push(error.message); throw error; }
    }});
  const workspace = f.run('createOperatorWorkspace()');
  return {...f, workspace, calls, raw, reply, timers, node: id => f.dom.getElementById(id),
    verify() { assert.deepEqual(faults, []); }};
}
const tests = [
  ['closed capabilities reject malformed or contradictory authority', () => {
    const api = load(); assert.deepEqual(copy(api.projectApprovalCapabilities(capability())), capability());
    for (const change of [{extra: true}, {schema: 'other'}, {can_list: 1}, {can_open_native_review: 'false'},
      {can_decide: true}, {reason: null}, {reason: 'unknown'}, {reason: 'role_required'}])
      assert.throws(() => api.projectApprovalCapabilities({...capability(), ...change}));
    assert.throws(() => api.projectApprovalCapabilities(Object.create(capability())));
  }],
  ['public projection discards all private and unexpected fields', () => {
    const api = load(); const item = approval({canonical_request: PRIVATE, review_receipt: PRIVATE, request_body: PRIVATE,
      authn_evidence: PRIVATE, approved_by: PRIVATE, url: INJECTED}); const before = copy(item);
    assert.deepEqual(copy(api.projectPendingApprovals([item])), [approval({url: INJECTED})]);
    assert.deepEqual(item, before); assert(!JSON.stringify(api.projectPendingApprovals([item])).includes(PRIVATE));
  }],
  ['metadata requires bounded scalar fields and unique exact pending IDs', () => {
    const api = load();
    for (const delta of [{id: [ID]}, {id: ID.toUpperCase() + 'x'}, {method: ['GET']}, {policy_hash: ['sha256:' + 'b'.repeat(64)]},
      {status: 'approved'}, {route_id: ''}, {route_id: 'a\nb'}, {credential_version: 0}, {credential_version: '1'},
      {principal_id: {}}, {requested_at: 'not-a-date'}, {expires_at: null}, {url: 'x'.repeat(4097)}])
      assert.throws(() => api.projectPendingApprovals([approval(delta)]));
    for (const value of [null, {}, [approval(), approval()], Array.from({length: 101}, () => approval())])
      assert.throws(() => api.projectPendingApprovals(value));
  }],
  ['credentialed and both established credentialless pairs coexist without contradictory metadata', async () => {
    const absent = approval({id: OTHER, credential_id: '', credential_version: 0});
    const unknown = approval({id: '33333333-3333-4333-8333-333333333333', credential_id: null, credential_version: null});
    const f = fixture({rows: [approval(), absent, unknown]});
    assert.deepEqual(copy(f.api.projectPendingApprovals([approval(), absent, unknown])), [approval(), absent, unknown]);
    for (const delta of [{credential_id: '', credential_version: 1}, {credential_id: '', credential_version: null},
      {credential_id: null, credential_version: 0}, {credential_id: null, credential_version: 1},
      {credential_id: 'saved', credential_version: 0}, {credential_id: 'saved', credential_version: null}])
      assert.throws(() => f.api.projectPendingApprovals([approval(delta)]));
    await f.show({requestedId: OTHER});
    assert.equal(f.node('pending-actions-list').children.length, 3);
    const detail = descendants(f.node('pending-actions-selected')).find(node => node.tagName === 'dl');
    const values = Object.fromEntries(detail.children.filter((_, index) => index % 2 === 0)
      .map((node, index) => [node.textContent, detail.children[index * 2 + 1].textContent]));
    assert.equal(values.Credential, 'Unavailable'); assert.equal(values.Version, 'Unavailable'); f.verify();
  }],
  ['deep-link parsing preserves one exact ID and never invents a fallback', () => {
    const {pendingApprovalLocation: parse} = load();
    for (const path of ['/', '/approvals-other', '/api/approvals', null, [ID]]) assert.equal(parse(path), null);
    for (const path of ['/approvals', '/approvals/']) assert.deepEqual(copy(parse(path)), {id: null, invalid: false});
    assert.deepEqual(copy(parse('/approvals/' + ID)), {id: ID, invalid: false});
    for (const tail of ['bad', ID + '/', ID + '/review', '%31' + ID.slice(1), ID + '?other=1'])
      assert.deepEqual(copy(parse('/approvals/' + tail)), {id: null, invalid: true});
  }],
  ['hidden construction and refresh are inert; capability always precedes metadata', async () => {
    const gate = deferred(); const f = fixture({handler: call => call.path === CAP ? gate.promise : response([])});
    assert.equal(await f.view.refresh(), false); assert.equal(f.calls.length, 0);
    await f.show(); assert.deepEqual(f.calls.map(call => call.path), [CAP]);
    assert.match(f.node('pending-actions-status').textContent, /Loading/); assert(f.node('pending-actions-refresh').disabled);
    assert.equal(await f.view.refresh(), false); gate.release(response(capability())); await flush();
    assert.deepEqual(f.calls.map(call => call.path), [CAP, LIST]);
    assert.equal(f.node('pending-actions-status').textContent, 'No pending actions visible to you.'); f.verify();
  }],
  ['role and authority list refusal never request metadata', async () => {
    for (const reason of ['role_required', 'authority_unavailable']) {
      const f = fixture({capability: capability({can_list: false, reason})}); await f.show();
      assert.deepEqual(f.calls.map(call => call.path), [CAP]); assert.match(f.node('pending-actions-status').textContent, /unavailable/);
      assert.equal(f.node('pending-actions-list').children.length, 0); f.verify();
    }
  }],
  ['ordinary metadata and synthetic all-true capabilities never wire a review opener', async () => {
    for (const cap of [capability(), capability({can_open_native_review: true, can_decide: true, reason: null})]) {
      const f = fixture({rows: [approval()], capability: cap}); await f.show({requestedId: ID});
      assert.match(f.node('pending-actions-selected').textContent, new RegExp(ID)); assert.equal(f.buttons().length, 0);
      assert.match(f.node('pending-actions-access').textContent, /not available|not connected/); assert.equal(f.calls.length, 2); f.verify();
    }
  }],
  ['selection changes only the exact public deep link and uses text nodes', async () => {
    const f = fixture({rows: [approval({route_id: INJECTED, canonical_request: PRIVATE}), approval({id: OTHER})]});
    await f.show(); await f.buttons('pending-actions-list')[0].events.click();
    assert.deepEqual(f.replacements, ['/approvals/' + ID + '#pending-actions']);
    const selected = f.node('pending-actions-selected').textContent;
    assert(selected.includes(ID) && selected.includes(INJECTED) && !selected.includes(PRIVATE) && !selected.includes(OTHER));
    assert(f.node('pending-actions-selected').focused); assert.equal(f.calls.length, 2); f.verify();
  }],
  ['missing and invalid links do not select an available different request', async () => {
    for (const selection of [{requestedId: OTHER}, {requestedId: 'bad'}, {requestedId: [ID]}, {invalidLink: true}]) {
      const f = fixture({rows: [approval()]}); await f.show(selection);
      assert.match(f.node('pending-actions-selected').textContent, /not found|link is invalid/);
      assert(!f.node('pending-actions-selected').textContent.includes('synthetic.status.read'));
      assert.equal(f.replacements.length, 0); assert.equal(f.buttons().length, 0); f.verify();
    }
  }],
  ['exact status survives leaving the pending queue without replaying a decision', async () => {
    for (const state of ['approved', 'denied', 'expired', 'pending']) {
      const key = 'serverware.approvalDecisionUncertain.' + ID;
      const f = fixture({rows: [approval({id: OTHER})], selected: approval({status: state, canonical_request: PRIVATE}), storage: [[key, ID]],
        capability: capability({can_open_native_review: true, can_decide: true, reason: null})});
      f.view.setReviewOpener(() => assert.fail('status recovery must not open review'));
      await f.show({requestedId: ID});
      const shown = f.node('pending-actions-selected').textContent;
      assert.match(shown, new RegExp('Status: ' + state[0].toUpperCase() + state.slice(1)));
      assert(!shown.includes(PRIVATE)); assert(!shown.includes(OTHER));
      assert.match(shown, /No review or decision will be retried/);
      if (state === 'approved') assert.match(shown, /does not confirm that the provider request completed/);
      if (state !== 'pending') assert.equal(f.buttons().length, 0);
      else assert(f.buttons()[0].disabled);
      assert.deepEqual(f.calls.map(call => call.path), [CAP, LIST, DETAIL]);
      assert.deepEqual([...f.storage], [[key, ID]]); f.verify();
    }
  }],
  ['refresh follows an exact pending request to its recorded terminal status', async () => {
    let completed = false;
    const f = fixture({handler: call => call.path === CAP ? response(capability()) :
      call.path === LIST ? response(completed ? [] : [approval()]) : response(approval({status: 'denied'}))});
    await f.show({requestedId: ID}); assert.equal(f.calls.length, 2);
    completed = true; assert.equal(await f.view.refresh(), true);
    assert.match(f.node('pending-actions-selected').textContent, /Status: Denied/);
    assert.equal(f.node('pending-actions-list').children.length, 0);
    assert.deepEqual(f.calls.map(call => call.path), [CAP, LIST, CAP, LIST, DETAIL]); f.verify();
  }],
  ['exact status rejects wrong IDs, unknown states and authentication loss', async () => {
    for (const answer of [response(approval({id: OTHER, status: 'approved'})), response(approval({status: 'unknown'})),
      response({detail: PRIVATE}, 503), response({}, 401), response({}, 403)]) {
      const f = fixture({handler: call => call.path === CAP ? response(capability()) : call.path === LIST ? response([]) : answer});
      await f.show({requestedId: ID});
      assert.match(f.node('pending-actions-status').textContent, /could not be loaded|sign in again/);
      assert(!f.node('pending-actions-selected').textContent.includes('Status:'));
      assert.equal(f.buttons().length, 0); assert.equal(f.authLost, [401, 403].includes(answer.status) ? 1 : 0); f.verify();
    }
  }],
  ['late exact status cannot overwrite a different selected request', async () => {
    const delayed = deferred();
    const f = fixture({handler: call => call.path === CAP ? response(capability()) : call.path === LIST ? response([]) :
      call.path === DETAIL ? delayed.promise : response(approval({id: OTHER, status: 'denied'}))});
    await f.show({requestedId: ID}); await f.show({requestedId: OTHER});
    delayed.release(response(approval({status: 'approved'}))); await flush();
    assert.match(f.node('pending-actions-selected').textContent, /Status: Denied/);
    assert(!f.node('pending-actions-selected').textContent.includes(ID));
    assert(f.calls.find(call => call.path === DETAIL).init.signal.aborted); f.verify();
  }],
  ['recovery holds and expired rows disable even a future explicit opener without changing markers', async () => {
    for (const kind of ['held', 'invalid', 'storage-failure', 'expired']) {
      const key = 'serverware.approvalDecisionUncertain.' + ID;
      const storage = kind === 'held' ? [[key, ID]] : kind === 'invalid' ? [[key, 'invalid']] : [];
      const f = fixture({rows: [approval(kind === 'expired' ? {expires_at: new Date(NOW).toISOString()} : {})], storage,
        storageFailure: kind === 'storage-failure', capability: capability({can_open_native_review: true, can_decide: true, reason: null})});
      let opened = 0; f.view.setReviewOpener(() => { opened++; }); await f.show({requestedId: ID});
      assert.equal(f.buttons().length, 1); assert(f.buttons()[0].disabled); await f.buttons()[0].events.click();
      assert.equal(opened, 0); assert.deepEqual([...f.storage], storage); assert.equal(f.calls.length, 2); f.verify();
    }
  }],
  ['HTTP and malformed replies show fixed unavailable text, never private server details', async () => {
    for (const answer of [response({detail: PRIVATE}, 503), response({}, 200, 'text/html'),
      {...response(null), text: async () => PRIVATE}, response({...capability(), extra: PRIVATE})]) {
      const f = fixture({handler: () => answer}); await f.show();
      assert.match(f.node('pending-actions-status').textContent, /could not be loaded/);
      assert(!f.node('pending-actions-status').textContent.includes(PRIVATE)); assert.equal(f.authLost, 0); assert.equal(f.calls.length, 1); f.verify();
    }
    const f = fixture({listStatus: 503, rows: [{detail: PRIVATE}]}); await f.show();
    assert.match(f.node('pending-actions-status').textContent, /could not be loaded/); assert.equal(f.calls.length, 2); f.verify();
  }],
  ['only current 401 or 403 invokes authentication loss', async () => {
    for (const code of [401, 403]) {
      const f = fixture({capStatus: code}); await f.show(); assert.equal(f.authLost, 1);
      assert.match(f.node('pending-actions-status').textContent, /sign in again/); f.verify();
    }
    const delayed = deferred(); const f = fixture({handler: () => delayed.promise}); await f.show();
    f.view.show(false); assert(f.calls[0].init.signal.aborted); delayed.release(response({}, 401)); await flush();
    assert.equal(f.authLost, 0); assert.equal(f.calls.length, 1); f.verify();
  }],
  ['late metadata cannot repopulate a hidden view or replace a fresh navigation', async () => {
    const delayed = deferred(); let lists = 0;
    const f = fixture({handler: call => call.path === CAP ? response(capability()) : ++lists === 1 ? delayed.promise : response([approval({id: OTHER})])});
    await f.show({requestedId: ID}); f.view.show(false); assert(f.calls[1].init.signal.aborted);
    await f.show({requestedId: OTHER}); delayed.release(response([approval()])); await flush();
    assert.equal(f.node('pending-actions-list').children.length, 1);
    assert.equal(f.node('pending-actions-list').children[0].dataset.pendingApprovalId, OTHER);
    assert(f.node('pending-actions-selected').textContent.includes(OTHER)); assert(!f.node('pending-actions-selected').textContent.includes(ID)); f.verify();
  }],
  ['external authentication loss and pagehide clear saved metadata and abort pending work', async () => {
    const f = fixture({rows: [approval()]}); await f.show({requestedId: ID});
    f.view.authenticationLost(); assert.equal(f.node('pending-actions-list').children.length, 0);
    assert(!f.node('pending-actions-selected').textContent.includes('synthetic.status.read'));
    assert.match(f.node('pending-actions-status').textContent, /sign in again/);
    await f.view.refresh(); f.events.pagehide(); assert.equal(f.node('pending-actions-list').children.length, 0);
    assert.equal(await f.view.refresh(), false); f.verify();
  }],
  ['queue authentication loss fences an earlier catalog success until an explicit manual refresh', async () => {
    for (const status of [401, 403]) {
      const delayed = deferred();
      const f = workspaceFixture((call, {reply, calls}) => {
        assert.equal(call.path, '/api/operator-demo/catalog'); assert.equal(call.method, 'GET');
        return calls.length === 1 ? delayed.promise : reply();
      });
      const oldRefresh = f.workspace.refresh();
      const queue = fixture({capStatus: status, onAuthenticationLost: f.workspace.authenticationLost});
      f.workspace.onAuthenticationLost(queue.view.authenticationLost); await queue.show({requestedId: ID});
      assert.equal(queue.authLost, 1); assert.equal(f.workspace.state.catalog, null);
      delayed.release(f.reply()); assert.equal(await oldRefresh, false);
      assert.equal(f.workspace.state.catalog, null); assert.equal(f.workspace.ready('applications'), false);
      assert.equal(f.node('load-error').hidden, false); assert.match(f.node('load-error-text').textContent, /Reload and sign in again/);
      assert(f.node('mutation-review-confirm').disabled); assert.match(queue.node('pending-actions-status').textContent, /sign in again/);
      assert.equal(await f.workspace.refresh(), false);
      assert.equal(await f.workspace.mutate('applications', {}, 'connect-status',
        () => assert.fail('authentication-held mutation must not reach success callback')), false); assert.equal(f.calls.length, 1);
      assert.equal(await f.workspace.refresh({manual: true}), true); assert(f.workspace.state.catalog);
      assert.equal(f.node('load-error').hidden, true); assert.equal(f.calls.length, 2); f.verify(); queue.verify();
    }
  }],
  ['authentication loss cancels queued polling and an own catalog denial retains the sign-in error', async () => {
    const f = workspaceFixture((call, {raw, reply, calls}) => {
      assert.equal(call.path, '/api/operator-demo/catalog'); assert.equal(call.method, 'GET');
      return calls.length === 1 ? reply({...raw, policy: {...raw.policy, activation: 'pending', loaded_policy_hash: null}}) : reply({}, 401);
    });
    assert.equal(await f.workspace.refresh(), true); assert.equal(f.timers.size, 1);
    const alreadyQueued = [...f.timers.values()][0]; f.workspace.authenticationLost();
    assert.equal(f.timers.size, 0); assert.equal(await alreadyQueued(), false); assert.equal(f.calls.length, 1);
    assert.equal(await f.workspace.refresh({manual: true}), false);
    assert.equal(f.workspace.state.catalog, null); assert.equal(f.node('load-error').hidden, false);
    assert.match(f.node('load-error-text').textContent, /Reload and sign in again/);
    assert(f.node('mutation-review-confirm').disabled); assert.equal(f.timers.size, 0); f.verify();
  }],
  ['mutation authentication loss remains uncertain with no automatic catalog restoration or mutation retry', async () => {
    const f = workspaceFixture((call, {reply}) => {
      if (call.path === '/api/operator-demo/catalog') { assert.equal(call.method, 'GET'); return reply(); }
      assert.equal(call.path, '/api/operator-demo/applications'); assert.equal(call.method, 'POST'); return reply({}, 403);
    });
    assert.equal(await f.workspace.refresh(), true);
    assert.equal(await f.workspace.mutate('applications', {name: 'synthetic client'}, 'connect-status', () => assert.fail('unauthenticated reply must not reach success callback')), false);
    assert.equal(f.workspace.state.catalog, null); assert.equal(f.workspace.state.uncertain, true); assert.equal(f.workspace.state.busy, false);
    assert.equal(f.node('load-error').hidden, false); assert.match(f.node('load-error-text').textContent, /Reload and sign in again/);
    assert.deepEqual(f.calls.map(call => call.method), ['GET', 'POST']);
    assert.equal(await f.workspace.mutate('applications', {}, 'connect-status',
      () => assert.fail('uncertain mutation must not reach success callback')), false);
    assert.equal(await f.workspace.refresh({manual: true}), true); assert.equal(f.workspace.state.uncertain, true);
    assert.equal(f.workspace.ready('applications'), false); assert.deepEqual(f.calls.map(call => call.method), ['GET', 'POST', 'GET']); f.verify();
  }],
];
const hostTests = [
  ['host capability is distinct from native and rejects contradictory availability', () => {
    const api = load(); assert.deepEqual(copy(api.projectApprovalCapabilities(hostCapability())), hostCapability());
    for (const patch of [{mode: 'native'}, {can_open_native_review: true}, {can_review: false},
      {can_list: false}, {reason: 'protected_review_unavailable'}, {can_decide: 1}])
      assert.throws(() => api.projectApprovalCapabilities(hostCapability(patch)));
    assert.equal(api.projectApprovalCapabilities(capability()).schema, 'serverware.approvalCapabilities/v1');
  }],
  ['host queue requires explicit review then one approval and explains the manual identical retry', async () => {
    const document = {...hostReview().document, operation: {name: INJECTED}, private_unexpected: PRIVATE};
    const f = fixture({host: true, handler: ({path, init}) => {
      if (path === CAP) return response(hostCapability());
      if (path === HOST) return response([hostApproval()]);
      if (path.endsWith('/review')) { assert.deepEqual(JSON.parse(init.body), {}); return response(hostReview({document})); }
      assert(path.endsWith('/decision'));
      assert.deepEqual(JSON.parse(init.body), {decision: 'approve', review_receipt_id: OTHER,
        review_digest: 'sha256:' + 'f'.repeat(64), note: null});
      return response(hostApproval({status: 'approved', approved_until: new Date(NOW + 30000).toISOString()}));
    }});
    f.view.setReviewOpener(() => assert.fail('host must not open native review'));
    await f.show({requestedId: ID}); assert.equal(f.calls.length, 2);
    assert(f.node('pending-actions-access').textContent.includes('server administrator can bypass'));
    assert.deepEqual(f.buttons().map(button => button.textContent), ['Review request']);
    await f.buttons()[0].events.click(); await flush();
    assert(!f.node('pending-actions-selected').textContent.includes(PRIVATE));
    assert(f.node('pending-actions-selected').textContent.includes('untrusted.example.test/x'));
    assert.deepEqual(f.buttons().map(button => button.textContent), ['Approve once', 'Deny']);
    await f.buttons()[0].events.click(); await flush();
    assert.equal(f.calls.filter(call => call.init.method === 'POST').length, 2);
    assert(f.node('pending-actions-selected').textContent.includes('Explicitly retry exactly the same request once'));
    assert(!f.storage.has('serverware.hostApprovalDecisionUncertain.' + ID));
    assert.equal(f.buttons().length, 0); f.verify();
  }],
  ['host denial submits one explicit decision and never forwards a provider request', async () => {
    const f = fixture({host: true, handler: ({path, init}) => path === CAP ? response(hostCapability()) :
      path === HOST ? response([hostApproval()]) : path.endsWith('/review') ? response(hostReview()) :
      (assert.equal(JSON.parse(init.body).decision, 'deny'), response(hostApproval({status: 'denied'})))});
    await f.show({requestedId: ID}); await f.buttons()[0].events.click(); await flush();
    await f.buttons().find(button => button.textContent === 'Deny').events.click(); await flush();
    assert(f.node('pending-actions-selected').textContent.includes('No retry is authorized'));
    assert.equal(f.calls.filter(call => call.path.endsWith('/decision')).length, 1); f.verify();
  }],
  ['uncertain host decision allows status reads only, including after a tab reload', async () => {
    let reads = 0;
    const handler = ({path}) => path === CAP ? response(hostCapability()) :
      path === HOST ? response([hostApproval()]) : path.endsWith('/review') ? response(hostReview()) :
      path.endsWith('/decision') ? response({}, 503) : response(hostApproval(++reads === 1 ? {} :
        {status: 'approved', approved_until: new Date(NOW + 30000).toISOString()}));
    const f = fixture({host: true, handler}); await f.show({requestedId: ID});
    await f.buttons()[0].events.click(); await flush(); await f.buttons()[0].events.click(); await flush();
    assert.deepEqual(f.buttons().map(button => button.textContent), ['Check decision status']);
    const reloaded = fixture({host: true, handler, storage: [...f.storage]}); await reloaded.show({requestedId: ID});
    assert.deepEqual(reloaded.buttons().map(button => button.textContent), ['Check decision status']);
    await reloaded.buttons()[0].events.click(); await flush();
    assert.deepEqual(reloaded.buttons().map(button => button.textContent), ['Check decision status']);
    await reloaded.buttons()[0].events.click(); await flush();
    assert(reloaded.node('pending-actions-selected').textContent.includes('Approved once'));
    assert(reloaded.calls.every(call => call.init.method === 'GET'));
    f.verify(); reloaded.verify();
  }],
  ['host review scope and expiry are checked; leaving the view discards a late private reply', async () => {
    const api = load();
    for (const patch of [{assurance: 'native'}, {review_receipt_id: 'bad'}, {review_digest: 'bad'},
      {review_expires_at: new Date(NOW).toISOString()}, {approval: hostApproval({id: OTHER})},
      {document: {...hostReview().document, method: 'POST'}}])
      assert.throws(() => api.projectHostApprovalReview(hostReview(patch), ID));
    const pending = deferred();
    const f = fixture({host: true, handler: ({path}) => path === CAP ? response(hostCapability()) :
      path === HOST ? response([hostApproval()]) : pending.promise});
    await f.show({requestedId: ID}); const opening = f.buttons()[0].events.click(); await flush();
    f.view.show(false); pending.release(response(hostReview())); await opening; await flush();
    assert.equal(f.buttons().length, 0); assert(!f.node('pending-actions-selected').textContent.includes('Request review')); f.verify();
  }],
  ['host permission capability gates exact recipes and never combines with an X daily quota', () => {
    const f = require('./test_operator_npm_ui.cjs').context();
    const cap = {schema: 'serverware.operatorHostApprovals/v1', mode: 'host_trusted_v1', available: true,
      operation_bundles: ['x_text_post_v1', 'github_issues_write_v1'], generic_rules: true,
      setting_path: '/api/operator-demo/access-rules/approval'};
    f.value.hostCap = cap;
    assert.equal(f.run('projectHostApprovalsCapability(hostCap).mode'), 'host_trusted_v1');
    assert.equal(f.run('operatorHostApprovalAvailable({capabilities:{host_approvals:hostCap}}, {})'), true);
    assert.equal(f.run('operatorHostApprovalAvailable({capabilities:{host_approvals:hostCap}}, {operation_bundle:"x_text_post_v1"})'), true);
    assert.equal(f.run('operatorHostApprovalAvailable({capabilities:{host_approvals:hostCap}}, {operation_bundle:"x_text_post_v1",daily_post_attempt_limit:5})'), false);
    assert.equal(f.run('operatorHostApprovalAvailable({capabilities:{host_approvals:hostCap}}, {operation_bundle:"unknown"})'), false);
    assert.equal(f.run('operatorHostApprovalAvailable({capabilities:{host_approvals:{...hostCap,available:false}}}, {})'), false);
    assert.throws(() => f.run('projectHostApprovalsCapability({...hostCap,setting_path:"https://untrusted.test"})'));
  }],
  ['guided creation carries the explicit approval setting into a provider permission', async () => {
    const {context, rawCatalog, existingPair, IDS} = require('./test_operator_npm_ui.cjs');
    const f = context(), raw = rawCatalog({rules: []}), posts = [];
    raw.capabilities.host_approvals = {schema: 'serverware.operatorHostApprovals/v1', mode: 'host_trusted_v1', available: true,
      operation_bundles: ['npm_metadata_read_v1'], generic_rules: true, setting_path: '/api/operator-demo/access-rules/approval'};
    const workspace = {state: {catalog: f.run('projectCatalog(input)', raw), busy: false, uncertain: false},
      ready: () => true, loaded: () => true, subscribe(callback) { this.render = callback; callback(); },
      async mutate(path, body) { posts.push({path, body: copy(body)}); return false; }};
    Object.assign(f.value, {workspaceFixture: workspace, applicationsFixture: {mount() {}, tokenFor() { return null; }}});
    f.run('createConnectView(workspaceFixture, applicationsFixture, {mount(){},select(){}})');
    const node = id => f.dom.getElementById(id);
    const event = async (id, type = 'click') => { const target = node(id); await target.events[type]({preventDefault() {}, currentTarget: target}); };
    await existingPair({node, event});
    node('connect-operation').value = 'npm_metadata_read_v1'; await event('connect-operation', 'change');
    node('connect-npm-packages').value = '@example/fixture\nexample-package'; node('connect-approval-required').checked = true;
    await event('connect-access-form', 'submit');
    assert(node('connect-review-details').children.some(item => item.textContent.includes('Host-trusted')));
    await event('connect-grant');
    assert.equal(posts.length, 1); assert.equal(posts[0].path, 'access-rules/npm-metadata');
    assert.equal(posts[0].body.approval_mode, 'host_review_v1'); assert.equal(posts[0].body.application_id, IDS.application);
  }],
  ['existing permission toggle and confirmation bind only the reviewed rule and approval mode', async () => {
    const {context, rawCatalog, IDS} = require('./test_operator_npm_ui.cjs');
    const f = context(), raw = rawCatalog(), posts = [];
    raw.capabilities.host_approvals = {schema: 'serverware.operatorHostApprovals/v1', mode: 'host_trusted_v1', available: true,
      operation_bundles: ['npm_metadata_read_v1'], generic_rules: true, setting_path: '/api/operator-demo/access-rules/approval'};
    const catalog = copy(f.run('projectCatalog(input)', raw));
    const workspace = {state: {catalog, busy: false, uncertain: false}, ready: () => true, loaded: () => true,
      subscribe(callback) { callback(); }, mutate(path, body) { posts.push({path, body: copy(body)}); }};
    f.value.workspaceFixture = workspace; f.run('createAccessRulesView(workspaceFixture)');
    const button = descendants(f.dom.getElementById('access-rules-list')).find(item => item.dataset.action === 'change-approval');
    assert(button && !button.disabled); await button.events.click();
    assert.deepEqual(posts, [{path: 'access-rules/approval', body: {id: IDS.rule, approval_mode: 'host_review_v1'}}]);
    f.value.beforeApproval = catalog;
    const item = {...catalog.access_rules[0], approval_mode: 'host_review_v1'};
    const policy = {...catalog.policy, sequence: catalog.policy.sequence + 1, policy_hash: 'sha256:' + 'e'.repeat(64)};
    const result = {revision: catalog.revision + 1, policy, access_rule: item};
    const confirmation = f.run('operatorOrdinaryMutationConfirmation("access-rules/approval", {id:beforeApproval.access_rules[0].id,approval_mode:"host_review_v1"}, beforeApproval)');
    confirmation.receive(result); confirmation.confirm({...catalog, revision: result.revision, policy, access_rules: [item]});
    const mismatch = f.run('operatorOrdinaryMutationConfirmation("access-rules/approval", {id:beforeApproval.access_rules[0].id,approval_mode:"host_review_v1"}, beforeApproval)');
    assert.throws(() => mismatch.receive({...result, access_rule: {...item, approval_mode: undefined}}));
    assert.throws(() => mismatch.receive({...result, access_rule: {...item, name: 'unexpected change'}}));
  }],
];
async function main() {
  assert(process.argv.length === 2 || process.argv.length === 3 && process.argv[2] === '--host', 'synthetic test accepts only --host');
  const selected = process.argv[2] === '--host' ? hostTests : [...tests, ...hostTests];
  const before = createHash('sha256').update(readFileSync(SOURCE)).digest('hex');
  const coreBefore = createHash('sha256').update(readFileSync(CORE)).digest('hex');
  for (const [name, run] of selected) { await run(); console.log('PASS ' + name); }
  assert.equal(createHash('sha256').update(readFileSync(SOURCE)).digest('hex'), before, 'source unchanged during test');
  assert.equal(createHash('sha256').update(readFileSync(CORE)).digest('hex'), coreBefore, 'workspace core unchanged during test');
  console.log(JSON.stringify({ok: true, groups: selected.length, sourceSha256: before, backendAcceptance: false,
    nativeReviewAcceptance: false, scope: process.argv[2] === '--host' ? 'host-trusted UI with inert DOM and synthetic API replies' :
      'pending-actions UI with inert DOM and synthetic API replies'}));
}
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });
module.exports = {capability, approval, CAP, LIST, NOW, ID, OTHER, PRIVATE, INJECTED, tests};

#!/usr/bin/env node
'use strict';
// Actual workspace + notification + audit controllers, inert DOM, deterministic
// deferred synthetic GETs. No browser, backend, network, provider or mutation.
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');
const {context, rawCatalog, clone} = require('./test_operator_npm_ui.cjs');
const ASSETS = resolve(__dirname, '../serverware/operator_demo_web');
const CATALOG = '/api/operator-demo/catalog', NOTIFICATIONS = '/api/operator-demo/notifications';
const SEARCH = '/api/audit/search?limit=20&scanLimit=5000', VERIFY = '/api/audit/verify';
const STORAGE = 'serverware.operator.notifications.operation.v1';
const OP = '11111111-1111-4111-8111-111111111111', DELIVERY = '22222222-2222-4222-8222-222222222222';
const PRIVATE = 'https://notify.example.test/synthetic-private-draft-never-send';
const reference = {operation_id: OP, kind: 'test', slot: 'audit_log.webhook', expected_revision: 1};
const RECOVERY = NOTIFICATIONS + '/operations/' + OP;
const flush = async () => { for (let i = 0; i < 32; i++) await Promise.resolve(); };
const text = node => String(node.textContent || '') + node.children.map(text).join(' ');
const event = id => ({id, event_type: 'operator_catalog.application.created', created_at: '2026-10-08T12:00:00Z', event: {application_id: id}});
const history = (id = 'synthetic-current', more = false) => ({ok: true, complete: !more, has_more: more,
  next_cursor: more ? 'synthetic-cursor' : null, items: [event(id)]});
const operation = () => ({schema: 'serverware.operatorNotificationOperation/v1', operation_id: OP, kind: 'test',
  slot: reference.slot, revision: 1, status: 'acknowledged', delivery_id: DELIVERY, slot_state: null});
function notificationStatus() {
  const channels = {action_required: ['approval.requested'], audit_log: ['operator_catalog.application.created']};
  return {schema: 'serverware.operatorNotifications/v1', available: true,
    slots: ['action_required.slack', 'action_required.webhook', 'audit_log.slack', 'audit_log.webhook'].map(slot => {
      const [channel, adapter] = slot.split('.'); return {slot, channel, adapter, revision: 1, label: slot,
        enabled: true, secret_present: true, event_types: channels[channel], max_attempts: 1, last_delivery: null};
    }), queue: Object.fromEntries(['queued', 'sending', 'acknowledged', 'failed', 'outcome_unknown', 'suppressed', 'expired'].map(key => [key, 0])),
    cursor: null, backlog: {pending_source_events: 0, queue_capacity: 256, retained_capacity: 10000},
    capabilities: {action_required: {source_available: false, event_types: channels.action_required},
      audit_log: {source_available: true, event_types: channels.audit_log}, source_note: 'Synthetic source metadata only.',
      test_note: 'No delivery or readiness proof.', native_hardware: {configured: false, source_available: false,
        observation_only: true, last_observation: {state: 'not_configured', observed_at_epoch_ms: null, phase: null,
          action_available: false, source_expires_at_unix_nanos: null, review_url: null}}},
    worker: {state: 'running', last_cycle_at_epoch_ms: 1800000000000, last_code: 'ready'}};
}
// Only the local fixture gains dynamic form/name/data selectors and text nodes.
// Existing helper files, their DOM implementation and product source stay intact.
function notificationDom(dom) {
  const create = dom.createElement;
  function matches(node, selector) {
    const checked = selector.endsWith(':checked'); if (checked) selector = selector.slice(0, -8);
    const match = selector.match(/^\[(name|data-[a-z-]+)(?:="([^"]*)")?\]$/);
    if (!match) return node.tag === selector;
    const key = match[1].startsWith('data-') ? match[1].slice(5).replace(/-([a-z])/g, (_, c) => c.toUpperCase()) : null;
    const value = key ? node.dataset[key] : node.name;
    return value !== undefined && (match[2] === undefined || value === match[2]) && (!checked || node.checked === true);
  }
  dom.createElement = tag => {
    const node = create(tag);
    node.querySelectorAll = selector => node.descendants().filter(child => selector.split(',').some(part => matches(child, part.trim())));
    node.querySelector = selector => node.querySelectorAll(selector)[0] || null;
    if (tag === 'form') node.elements = {namedItem: name => node.descendants().find(child => child.name === name) || null};
    Object.defineProperty(node, 'innerHTML', {set() { throw new Error('inert fixture forbids HTML insertion'); }});
    return node;
  };
  dom.createTextNode = value => { const node = dom.createElement('#text'); node.textContent = value; return node; };
}
function response(body, status = 200, type = 'application/json') {
  return {ok: status >= 200 && status < 300, status, headers: {get: () => type},
    json: async () => clone(body), text: async () => JSON.stringify(body)};
}
function fixture({retained = false} = {}) {
  const current = context(); notificationDom(current.dom);
  const node = id => current.dom.getElementById(id);
  const calls = [], planned = [], faults = [], timers = new Map(), allTimers = [], storageWrites = [];
  const storage = new Map(retained ? [[STORAGE, JSON.stringify(reference)]] : []);
  let timerId = 0, authenticationLosses = 0, shown = false;
  Object.assign(current.value, {URLSearchParams, AbortSignal: {timeout: milliseconds => {
    assert.equal(milliseconds, 30000); return new AbortController().signal;
  }}, clearTimeout: id => timers.delete(id), setTimeout: (callback, delay) => {
    assert.equal(delay, 2000, 'only catalog activation polling is expected');
    const entry = {id: ++timerId, callback, delay}; timers.set(entry.id, entry); allTimers.push(entry); return entry.id;
  }, sessionStorage: {getItem: key => storage.get(key) ?? null,
    setItem(key, value) { storageWrites.push(['set', key]); storage.set(key, value); },
    removeItem(key) { storageWrites.push(['remove', key]); storage.delete(key); }},
  crypto: {randomUUID() { throw new Error('no operation may be created'); }},
  fetch(path, options) {
    calls.push({path, method: options.method || 'GET'});
    const expected = planned.shift();
    try {
      assert.equal(options.method || 'GET', 'GET'); assert.equal(options.body, undefined);
      assert.equal(options.credentials, 'same-origin'); assert.equal(options.cache, 'no-store'); assert.equal(options.redirect, 'error');
      assert(options.signal instanceof AbortSignal); assert(expected, 'unexpected synthetic request'); assert.equal(path, expected.path);
    } catch (error) { faults.push(error.message); return Promise.reject(error); }
    return expected.promise;
  }});
  for (const filename of ['workspace_notifications.js', 'workspace_proxy_audit.js'])
    vm.runInContext(readFileSync(resolve(ASSETS, filename), 'utf8'), current.value, {timeout: 1000});
  const workspace = current.run('createOperatorWorkspace()'); current.value.actualWorkspace = workspace;
  const notifications = current.run('createNotificationsView(actualWorkspace)');
  const audit = current.run('createAuditView(actualWorkspace)');
  workspace.onAuthenticationLost(() => { authenticationLosses++; });
  function expect(path, body, status = 200, {deferred = false, type = 'application/json'} = {}) {
    let accept, reject;
    const promise = new Promise((resolve, fail) => { accept = resolve; reject = fail; });
    planned.push({path, promise});
    const handle = {reply: () => accept(response(body, status, type)), fail: () => reject(new Error('synthetic transport failure'))};
    if (!deferred) handle.reply(); return handle;
  }
  const fire = (id, type = 'click') => {
    const target = node(id); assert.equal(typeof target.events[type], 'function', 'actual event handler exists');
    return target.events[type]({preventDefault() {}, currentTarget: target});
  };
  return {workspace, notifications, audit, node, calls, timers, allTimers, storage, storageWrites, expect, fire,
    get authenticationLosses() { return authenticationLosses; },
    async catalog(raw = rawCatalog()) { expect(CATALOG, raw); assert.equal(await workspace.refresh({manual: true}), true); },
    async notify(body = notificationStatus(), code = 200, type = 'application/json') {
      expect(NOTIFICATIONS, body, code, {type});
      if (!shown) { shown = true; notifications.show(true); } else await fire('notifications-refresh');
      await flush();
    },
    async auditRows(body = history()) { expect(SEARCH, body); audit.open(); await flush(); },
    forms() { return node('notifications-panels').descendants().filter(child => child.tag === 'form'); },
    verify(paths) {
      assert.deepEqual(faults, []); assert.equal(planned.length, 0, 'every planned response was consumed');
      assert.deepEqual(calls.map(call => call.path), paths); assert(calls.every(call => call.method === 'GET'));
      assert.deepEqual(storageWrites, [], 'public recovery reference is neither replaced nor cleared');
    }};
}
function auditCleared(f) {
  assert.equal(f.node('audit-list').children.length, 0); assert(f.node('audit-more').hidden);
  assert.match(f.node('audit-status').textContent, /session.*could not be verified/i);
  assert.match(f.node('audit-verification').textContent, /session.*could not be verified/i);
}
function authHeld(f) {
  assert.equal(f.workspace.state.catalog, null); assert.equal(f.workspace.ready('credentials'), false);
  assert.equal(f.node('load-error').hidden, false); assert(f.node('mutation-review-confirm').disabled);
  for (const id of ['audit-refresh', 'audit-more', 'audit-filter', 'audit-query', 'audit-verify']) assert(f.node(id).disabled, id);
  assert(f.node('audit-search-form').querySelector('button').disabled); auditCleared(f);
}
async function blockedAuditReads(f) {
  const before = f.calls.length;
  f.audit.open();
  for (const [id, type] of [['audit-refresh', 'click'], ['audit-more', 'click'], ['audit-filter', 'change'],
    ['audit-search-form', 'submit'], ['audit-verify', 'click']]) await f.fire(id, type);
  await flush(); assert.equal(f.calls.length, before, 'programmatic handlers also refuse reads while authentication is held');
}
const unverifiedHistory = 'Verify the stored audit chain again for this history view.';
const historyChanges = [
  {name: 'refresh', event: ['audit-refresh', 'click'], path: SEARCH},
  {name: 'filter', event: ['audit-filter', 'change'], path: SEARCH + '&eventType=operator_catalog.application.created',
    select: f => { f.node('audit-filter').value = 'operator_catalog.application.created'; }},
  {name: 'search', event: ['audit-search-form', 'submit'], path: SEARCH + '&q=chosen-client',
    select: f => { f.node('audit-query').value = 'chosen-client'; }},
  {name: 'paging', event: ['audit-more', 'click'], path: SEARCH + '&cursor=synthetic-cursor'},
];
const tests = [
  ...[401, 403].map(code => ['notification ' + code + ' invalidates old catalog success and queued activation polling', async () => {
    // Before the fix, notification's direct null/emit did not advance the core
    // epoch: this old 200 restored catalog readiness and its pending poll.
    const f = fixture(); await f.catalog(); await f.notify(); assert.equal(f.forms().length, 4);
    const old = f.expect(CATALOG, rawCatalog(), 200, {deferred: true}); const reading = f.workspace.refresh();
    await f.notify({detail: PRIVATE}, code, 'text/html'); authHeld(f); assert.equal(f.authenticationLosses, 1);
    old.reply(); assert.equal(await reading, false); authHeld(f);
    assert.equal(await f.workspace.refresh(), false); await blockedAuditReads(f);
    f.verify([CATALOG, NOTIFICATIONS, CATALOG, NOTIFICATIONS]);
    const poll = fixture(); const pending = rawCatalog(); pending.policy.activation = 'pending';
    pending.policy.loaded_policy_hash = 'sha256:' + '0'.repeat(64);
    await poll.catalog(pending); assert.equal(poll.timers.size, 1); const queued = poll.allTimers[0];
    await poll.notify({detail: PRIVATE}, code, 'text/html'); assert.equal(poll.timers.size, 0);
    await queued.callback(); await flush(); authHeld(poll); poll.verify([CATALOG, NOTIFICATIONS]);
  }]),
  ['notification recovery keeps its exact reference, clears draft URLs and never resubmits', async () => {
    for (const code of [401, 403]) {
      const f = fixture({retained: true}); await f.catalog(); await f.notify();
      assert(f.forms().every(form => form.querySelector('[data-notification-fields]').disabled));
      f.expect(RECOVERY, operation()); f.expect(NOTIFICATIONS, notificationStatus()); await f.fire('notification-check-operation');
      const form = f.forms().find(item => item.dataset.notificationSlot === reference.slot);
      assert(!form.querySelector('[data-notification-fields]').disabled);
      form.elements.namedItem('url_action').value = 'replace'; form.elements.namedItem('url').value = PRIVATE;
      form.events.change(); assert.equal(form.elements.namedItem('url').value, PRIVATE);
      f.expect(RECOVERY, {detail: PRIVATE}, code, {type: 'text/html'}); await f.fire('notification-check-operation');
      authHeld(f); assert.equal(form.elements.namedItem('url').value, '', 'shared auth loss clears write-only draft URL');
      assert.equal(f.storage.get(STORAGE), JSON.stringify(reference));
      await f.catalog(); assert(form.querySelector('[data-notification-fields]').disabled, 'catalog recovery cannot resolve an unknown notification operation');
      f.expect(RECOVERY, operation()); f.expect(NOTIFICATIONS, notificationStatus()); await f.fire('notification-check-operation');
      assert(f.forms().every(item => !item.querySelector('[data-notification-fields]').disabled));
      assert.equal(f.storage.get(STORAGE), JSON.stringify(reference));
      f.verify([CATALOG, NOTIFICATIONS, RECOVERY, NOTIFICATIONS, RECOVERY, CATALOG, RECOVERY, NOTIFICATIONS]);
    }
  }],
  ['cross-view authentication loss clears loaded audit history; recovery stays explicit and preserves uncertain mutations', async () => {
    const f = fixture(); await f.catalog(); await f.auditRows(history('existing-private-audit', true));
    f.expect(VERIFY, {ok: true, complete: true}); await f.fire('audit-verify');
    assert.equal(f.node('audit-list').children.length, 1); assert(!f.node('audit-more').hidden);
    f.workspace.requireReview('Synthetic mutation outcome remains unknown.');
    await f.notify({detail: PRIVATE}, 401); authHeld(f); await blockedAuditReads(f);
    assert.equal(await f.workspace.mutate('credentials', {}, 'notifications-status'), false);
    await f.catalog(); f.audit.open(); await flush(); auditCleared(f);
    assert(f.workspace.state.uncertain); assert.equal(await f.workspace.mutate('credentials', {}, 'notifications-status'), false);
    f.expect(SEARCH, history('after-explicit-refresh')); await f.fire('audit-refresh');
    assert.equal(f.node('audit-list').children.length, 1); assert(text(f.node('audit-list')).includes('after-explicit-refresh'));
    f.expect(VERIFY, {ok: true, complete: true}); await f.fire('audit-verify');
    assert.equal(f.node('audit-verification').textContent, 'The complete local audit chain is consistent.');
    assert(f.workspace.state.uncertain); assert.equal(f.node('mutation-review').hidden, false);
    f.verify([CATALOG, SEARCH, VERIFY, NOTIFICATIONS, CATALOG, SEARCH, VERIFY]);
  }],
  ['late audit search success or rejection cannot repopulate history after notification authentication loss', async () => {
    for (const rejected of [false, true]) {
      const f = fixture(); await f.catalog();
      const old = f.expect(SEARCH, history('stale-audit'), 200, {deferred: true}); f.audit.open(); await flush();
      await f.notify({detail: PRIVATE}, 403); authHeld(f);
      if (rejected) old.fail(); else old.reply(); await flush(); authHeld(f); await blockedAuditReads(f);
      f.verify([CATALOG, SEARCH, NOTIFICATIONS]);
    }
  }],
  ['old verification success or rejection cannot replace or enable a newer pending verification', async () => {
    for (const rejected of [false, true]) {
      const f = fixture(); await f.catalog();
      const old = f.expect(VERIFY, {ok: true, complete: true}, 200, {deferred: true}); const first = f.fire('audit-verify');
      await f.notify({detail: PRIVATE}, 401); authHeld(f); await f.catalog();
      f.audit.open(); await flush(); auditCleared(f);
      const fresh = f.expect(VERIFY, {ok: true, complete: false}, 200, {deferred: true}); const second = f.fire('audit-verify');
      assert(f.node('audit-verify').disabled); const checking = f.node('audit-verification').textContent;
      if (rejected) old.fail(); else old.reply(); await first; await flush();
      assert(f.node('audit-verify').disabled, 'stale finally cannot enable the newer verifier');
      assert.equal(f.node('audit-verification').textContent, checking);
      fresh.reply(); await second; assert.equal(f.node('audit-verification').textContent, 'Verification was incomplete.');
      assert(!f.node('audit-verify').disabled); f.verify([CATALOG, VERIFY, NOTIFICATIONS, CATALOG, VERIFY]);
    }
  }],
  ['old search success or rejection cannot replace a newer explicit filtered search or its paging state', async () => {
    for (const rejected of [false, true]) {
      const f = fixture(); await f.catalog();
      const old = f.expect(SEARCH, history('stale-page', true), 200, {deferred: true}); f.audit.open(); await flush();
      await f.notify({detail: PRIVATE}, 403); await f.catalog(); f.audit.open(); await flush(); auditCleared(f);
      f.node('audit-query').value = 'chosen-client'; const path = SEARCH + '&q=chosen-client';
      const fresh = f.expect(path, history('fresh-page', true), 200, {deferred: true}); f.fire('audit-search-form', 'submit'); await flush();
      const loading = f.node('audit-status').textContent; assert(f.node('audit-more').disabled);
      if (rejected) old.fail(); else old.reply(); await flush();
      assert(f.node('audit-more').disabled, 'stale finally cannot enable paging for a pending newer search');
      assert.equal(f.node('audit-status').textContent, loading); assert.equal(f.node('audit-list').children.length, 0);
      fresh.reply(); await flush(); assert.equal(f.node('audit-list').children.length, 1);
      assert(text(f.node('audit-list')).includes('fresh-page')); assert(!text(f.node('audit-list')).includes('stale-page'));
      f.expect(path + '&cursor=synthetic-cursor', history('older-current-page')); await f.fire('audit-more');
      assert.equal(f.node('audit-list').children.length, 2); assert(f.node('audit-more').hidden);
      f.verify([CATALOG, SEARCH, NOTIFICATIONS, CATALOG, path, path + '&cursor=synthetic-cursor']);
    }
  }],
  ['refresh, filter, search and paging invalidate completed verification, including a failed history read', async () => {
    for (const change of historyChanges) for (const rejected of [false, true]) {
      const f = fixture(); await f.catalog(); await f.auditRows(history('previous-page', true));
      f.expect(VERIFY, {ok: true, complete: true}); await f.fire('audit-verify');
      assert.equal(f.node('audit-verification').textContent, 'The complete local audit chain is consistent.');
      change.select?.(f);
      const next = f.expect(change.path, history('current-page'), 200, {deferred: true});
      f.fire(...change.event); await flush();
      assert.equal(f.node('audit-verification').textContent, unverifiedHistory, change.name);
      assert(f.node('audit-verify').disabled, change.name + ' blocks verification while history is loading');
      const before = f.calls.length; await f.fire('audit-verify');
      assert.equal(f.calls.length, before, 'programmatic verification cannot race a pending history read');
      if (rejected) next.fail(); else next.reply(); await flush();
      assert.equal(f.node('audit-verification').textContent, unverifiedHistory);
      assert(!f.node('audit-verify').disabled, 'history completion permits an explicit new verification');
      if (rejected) assert.match(f.node('audit-status').textContent, /response was lost or unavailable/i);
      else assert.equal(f.node('audit-list').children.length, change.name === 'paging' ? 2 : 1);
      f.expect(VERIFY, {ok: true, complete: false}); await f.fire('audit-verify');
      assert.equal(f.node('audit-verification').textContent, 'Verification was incomplete.');
      f.verify([CATALOG, SEARCH, VERIFY, change.path, VERIFY]);
    }
  }],
  ['pending verification success, error and finally stay invalidated during every history transition', async () => {
    for (const change of historyChanges) for (const rejected of [false, true]) {
      const f = fixture(); await f.catalog(); await f.auditRows(history('previous-page', true));
      const old = f.expect(VERIFY, {ok: true, complete: true}, 200, {deferred: true}); const first = f.fire('audit-verify');
      change.select?.(f);
      const next = f.expect(change.path, history('current-page'), 200, {deferred: true});
      f.fire(...change.event); await flush();
      const loading = f.node('audit-status').textContent;
      assert.equal(f.node('audit-verification').textContent, unverifiedHistory);
      if (rejected) old.fail(); else old.reply(); await first; await flush();
      assert.equal(f.node('audit-verification').textContent, unverifiedHistory, change.name);
      assert.equal(f.node('audit-status').textContent, loading);
      assert(f.node('audit-verify').disabled, 'stale verification finally cannot enable the current history view');
      const before = f.calls.length; await f.fire('audit-verify'); assert.equal(f.calls.length, before);
      next.reply(); await flush();
      assert.equal(f.node('audit-verification').textContent, unverifiedHistory); assert(!f.node('audit-verify').disabled);
      f.verify([CATALOG, SEARCH, VERIFY, change.path]);
    }
  }],
  ['verification from old history cannot replace or re-enable a new pending or completed verification', async () => {
    for (const change of historyChanges) for (const rejected of [false, true]) for (const completed of [false, true]) {
      const f = fixture(); await f.catalog(); await f.auditRows(history('previous-page', true));
      const old = f.expect(VERIFY, {ok: true, complete: true}, 200, {deferred: true}); const first = f.fire('audit-verify');
      change.select?.(f); f.expect(change.path, history('current-page')); f.fire(...change.event); await flush();
      const fresh = f.expect(VERIFY, {ok: true, complete: false}, 200, {deferred: true}); const second = f.fire('audit-verify');
      if (completed) { fresh.reply(); await second; }
      const label = f.node('audit-verification').textContent;
      assert.equal(label, completed ? 'Verification was incomplete.' : 'Checking the stored audit chain...');
      assert.equal(f.node('audit-verify').disabled, !completed);
      if (rejected) old.fail(); else old.reply(); await first; await flush();
      assert.equal(f.node('audit-verification').textContent, label, change.name);
      assert.equal(f.node('audit-verify').disabled, !completed, 'stale finally cannot alter current verification controls');
      if (!completed) { fresh.reply(); await second; }
      assert.equal(f.node('audit-verification').textContent, 'Verification was incomplete.');
      assert(!f.node('audit-verify').disabled); f.verify([CATALOG, SEARCH, VERIFY, change.path, VERIFY]);
    }
  }],
  ['non-authentication notification failure keeps audit readiness; external auth loss clears a draft URL', async () => {
    const f = fixture({retained: true}); await f.catalog(); await f.auditRows(); await f.notify();
    f.expect(RECOVERY, operation()); f.expect(NOTIFICATIONS, notificationStatus()); await f.fire('notification-check-operation');
    await f.notify({detail: PRIVATE}, 503); assert(f.workspace.state.catalog); assert.equal(f.authenticationLosses, 0);
    assert.equal(f.node('audit-list').children.length, 1); await f.notify();
    const form = f.forms().find(item => item.dataset.notificationSlot === reference.slot);
    form.elements.namedItem('url_action').value = 'replace'; form.elements.namedItem('url').value = PRIVATE; form.events.change();
    f.expect(CATALOG, {detail: PRIVATE}, 403); assert.equal(await f.workspace.refresh({manual: true}), false);
    assert.equal(form.elements.namedItem('url').value, ''); assert.equal(f.storage.get(STORAGE), JSON.stringify(reference));
    authHeld(f); f.verify([CATALOG, SEARCH, NOTIFICATIONS, RECOVERY, NOTIFICATIONS, NOTIFICATIONS, NOTIFICATIONS, CATALOG]);
  }],
];
async function main() {
  assert.equal(process.argv.length, 2, 'synthetic suite accepts no live target');
  for (const [name, run] of tests) { await run(); console.log('PASS ' + name); }
  console.log(JSON.stringify({ok: true, groups: tests.length,
    scope: 'actual workspace, notification and audit controllers; inert DOM and synthetic deferred GETs, not browser or backend acceptance'}));
}
if (require.main === module) main().catch(error => { console.error(error); process.exitCode = 1; });

#!/usr/bin/env node
'use strict';
// Rendered notification UX only. All requests are intercepted synthetic
// fixtures; no real server, webhook, Slack destination or delivery is used.
const assert = require('node:assert/strict');
const {mkdtemp} = require('node:fs/promises');
const {join} = require('node:path');
const {fixture: baseFixture, ready, view, NOW} = require('./test_operator_catalog_browser.cjs');

const PREFIX = '/api/operator-demo/notifications';
const STORAGE = 'catchplate.operator.notifications.operation.v1';
const SECRET = 'https://receiver.example.test/SYNTHETIC_PRIVATE_NOTIFICATION_URL';
const SLOTS = ['action_required.slack', 'action_required.webhook', 'audit_log.slack', 'audit_log.webhook'];
const STATES = ['queued', 'sending', 'acknowledged', 'failed', 'outcome_unknown', 'suppressed', 'expired'];
const EVENTS = {action_required: ['operator.host_approval.requested'],
  audit_log: ['data_plane.request.denied', 'operator_catalog.credential.created']};
const clone = value => JSON.parse(JSON.stringify(value));
const card = (page, slot) => page.locator('[data-notification-slot="' + slot + '"]');

function delivery(status = 'outcome_unknown') {
  return {delivery_id: '77777777-7777-4777-8777-777777777777', status, attempts: status === 'queued' ? 0 : 1,
    code: status === 'outcome_unknown' ? 'delivery_unknown' : null, http_status: null,
    created_at_epoch_ms: NOW, updated_at_epoch_ms: NOW};
}
function snapshot() {
  const slots = SLOTS.map((slot, index) => ({slot, channel: slot.split('.')[0], adapter: slot.split('.')[1],
    revision: index === 1 ? 0 : index + 1, label: ['Team approvals', '', 'Audit archive', 'Audit receiver'][index],
    enabled: index === 0 || index === 3, secret_present: index !== 1,
    event_types: index === 1 ? [] : [EVENTS[slot.split('.')[0]][0]], max_attempts: index === 2 ? 3 : 1,
    last_delivery: index === 3 ? delivery() : index === 0 ?
      {...delivery('failed'), code: 'http_rejected', http_status: 429} : null}));
  return {schema: 'catchplate.operatorNotifications/v1', available: true, slots,
    queue: Object.fromEntries(STATES.map(state => [state, state === 'outcome_unknown' ? 1 : 0])), cursor: null,
    backlog: {pending_source_events: 0, queue_capacity: 256, retained_capacity: 10000},
    capabilities: {action_required: {source_available: false, event_types: EVENTS.action_required},
      audit_log: {source_available: true, event_types: EVENTS.audit_log},
      native_hardware: {configured: false, source_available: false, observation_only: true,
        last_observation: {state: 'not_configured', observed_at_epoch_ms: null, phase: null,
          action_available: false, source_expires_at_unix_nanos: null, review_url: null}},
      source_note: 'Synthetic source status only.', test_note: 'Synthetic delivery is separate from action completion.'},
    worker: {state: 'running', last_cycle_at_epoch_ms: NOW, last_code: 'ready'}};
}

async function settled(page) {
  await page.waitForLoadState('networkidle');
  await page.waitForFunction(() => !document.getElementById('notifications-refresh').disabled);
}
async function privateAbsent(page) {
  const surfaces = await page.evaluate(() => ({html: document.documentElement.outerHTML,
    values: [...document.querySelectorAll('input,textarea')].map(input => input.value),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  assert(!JSON.stringify(surfaces).includes(SECRET), 'destination URLs do not survive closing, switching or submission');
}
async function openEditor(page, slot) {
  await card(page, slot).locator('[data-notification-edit]').click();
  assert.equal(await card(page, slot).locator('[data-notification-fields]').isVisible(), true);
  assert.equal(await page.locator('[data-notification-fields]:visible').count(), 1);
  assert.equal(await card(page, slot).locator('[data-notification-edit]').getAttribute('aria-expanded'), 'true');
}

async function fixture(browser, exercise, {lostReply = false} = {}) {
  const state = {snapshot: snapshot(), posts: [], reads: [], receipts: new Map()};
  return baseFixture(browser, {async notificationHandler({route, request, path, body, state: catalog, answer}) {
    if (request.method() === 'GET') {
      state.reads.push(path);
      if (path === PREFIX) return answer(route, clone(state.snapshot));
      assert(path.startsWith(PREFIX + '/operations/'));
      const receipt = state.receipts.get(path.slice((PREFIX + '/operations/').length));
      assert(receipt, 'only the retained exact operation reference is queried');
      return answer(route, clone(receipt));
    }
    assert.equal(request.method(), 'POST');
    assert([PREFIX + '/settings', PREFIX + '/test'].includes(path));
    const kind = path.endsWith('/settings') ? 'save' : 'test';
    const target = state.snapshot.slots.find(slot => slot.slot === body.slot); assert(target);
    assert.equal(body.expected_revision, target.revision);
    assert.equal(state.posts.some(post => post.body.operation_id === body.operation_id), false, 'no operation is replayed');
    const retained = await request.frame().evaluate(key => JSON.parse(sessionStorage.getItem(key)), STORAGE);
    assert.deepEqual(retained, {operation_id: body.operation_id, kind, slot: body.slot, expected_revision: body.expected_revision});
    state.posts.push({kind, body: clone(body)});
    if (kind === 'save') {
      assert.equal(body.url_action, 'keep'); assert.equal(Object.hasOwn(body, 'url'), false);
      Object.assign(target, {revision: target.revision + 1, label: body.label, enabled: body.enabled,
        event_types: [...body.event_types], max_attempts: body.max_attempts});
    } else {
      assert.deepEqual(Object.keys(body).sort(), ['expected_revision', 'operation_id', 'slot']);
      target.last_delivery = delivery('queued'); state.snapshot.queue.queued++;
    }
    const receipt = {schema: 'catchplate.operatorNotificationOperation/v1', operation_id: body.operation_id, kind,
      slot: body.slot, revision: target.revision, status: kind === 'save' ? 'saved' : 'queued',
      delivery_id: kind === 'save' ? null : target.last_delivery.delivery_id, slot_state: kind === 'save' ? clone(target) : null};
    state.receipts.set(body.operation_id, clone(receipt));
    if (lostReply) { catalog.expectedFailures.add(path); return route.abort('failed'); }
    return answer(route, receipt, kind === 'test' ? 202 : 200);
  }}, async (page, catalog) => {
    await ready(page); await view(page, 'notifications'); await settled(page); await page.clock.resume();
    assert.equal(new URL(page.url()).origin, 'https://operator-catalog.example.test');
    assert.match(await page.title(), /Notifications.*Catchplate/i);
    assert.equal(await page.locator('[data-notification-slot]').count(), 4);
    await exercise(page, state);
    assert.equal(catalog.posts.length, state.posts.length);
    assert(catalog.posts.every(post => ['notifications/settings', 'notifications/test'].includes(post.name)));
    await privateAbsent(page);
  });
}

async function runSuite(browser) {
  const artifacts = await mkdtemp('/tmp/catchplate-notification-summary-');
  await fixture(browser, async (page, state) => {
    assert.equal(await page.locator('[data-notification-fields]:visible').count(), 0);
    assert.equal(await page.locator('[data-notification-edit]:visible').count(), 4);
    assert.equal(await page.locator('[data-notification-draft]:visible').count(), 0);
    assert.equal(await page.locator('#notification-operation-status').isVisible(), false, 'empty recovery card does not precede setup');
    assert.match(await card(page, 'action_required.slack').innerText(), /Team approvals.*Enabled/s);
    assert.equal(await card(page, 'action_required.slack').locator('[data-notification-delivery]').isVisible(), true);
    assert.match(await card(page, 'action_required.slack').innerText(), /Delivery failed.*HTTP status: 429/s);
    assert.match(await card(page, 'action_required.webhook').innerText(), /No destination saved.*Not configured/s);
    assert.match(await card(page, 'audit_log.slack').innerText(), /Audit archive.*Disabled/s);
    assert.equal(await card(page, 'audit_log.webhook').locator('[data-notification-delivery]').isVisible(), true);
    assert.match(await card(page, 'audit_log.webhook').innerText(), /outcome unknown.*no automatic replay/is);
    assert.equal(await page.locator('[data-slot-revision]:visible').count(), 0);
    await page.locator('[data-notification-jump="audit_log"]').click();
    assert.equal(await page.evaluate(() => document.activeElement.id), 'notification-channel-audit_log');
    await page.locator('[data-notification-jump="action_required"]').click();
    assert.equal(await page.evaluate(() => document.activeElement.id), 'notification-channel-action_required');
    assert.equal(state.posts.length, 0);
    await page.screenshot({path: join(artifacts, 'summary-desktop.png'), fullPage: true});
    await page.setViewportSize({width: 390, height: 844});
    assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
    await page.screenshot({path: join(artifacts, 'summary-mobile.png'), fullPage: true});
  });
  console.log('PASS four summary cards, visible uncertainty, type jumps and mobile layout');

  await fixture(browser, async (page, state) => {
    const saved = clone(state.snapshot.slots);
    await openEditor(page, 'action_required.webhook');
    const fresh = card(page, 'action_required.webhook');
    assert.equal(await fresh.locator('[name="enabled"]').isChecked(), false);
    assert.equal(await fresh.locator('[name="event_types"]:checked').count(), 0);
    assert.equal(await fresh.locator('[name="url_action"]').isVisible(), false);
    assert.equal(await fresh.locator('[name="url"]').getAttribute('type'), 'password');
    assert.equal(await fresh.locator('[data-notification-draft]').isVisible(), false);
    await fresh.locator('[name="label"]').fill('Unsaved action destination');
    await fresh.locator('[name="url"]').fill(SECRET);
    await openEditor(page, 'audit_log.slack');
    assert.equal(await fresh.locator('[data-notification-fields]').isVisible(), false);
    await privateAbsent(page);
    const audit = card(page, 'audit_log.slack');
    assert.equal(await audit.locator('[name="enabled"]').isChecked(), false);
    assert.equal(await audit.locator('[name="max_attempts"]').inputValue(), '3');
    assert.equal(await audit.locator('[name="max_attempts"]').isVisible(), false);
    await audit.locator('[data-notification-advanced] summary').click();
    assert.equal(await audit.locator('[name="max_attempts"]').isVisible(), true);
    assert.match(await audit.locator('[data-slot-revision]').innerText(), /3/);
    await audit.locator('[data-notification-edit]').click();
    assert.equal(await page.locator('[data-notification-fields]:visible').count(), 0);
    await openEditor(page, 'action_required.webhook');
    await fresh.locator('[name="url"]').fill(SECRET);
    await view(page, 'overview'); await privateAbsent(page);
    await view(page, 'notifications');
    assert.equal(await page.locator('[data-notification-fields]:visible').count(), 0);
    assert.deepEqual(state.snapshot.slots, saved); assert.equal(state.posts.length, 0);
  });
  console.log('PASS selected editor, unchanged defaults, advanced settings and cleared abandoned URL');

  await fixture(browser, async (page, state) => {
    const untouched = clone(state.snapshot.slots.filter(slot => slot.slot !== 'audit_log.slack'));
    await openEditor(page, 'audit_log.slack');
    await card(page, 'audit_log.slack').locator('[name="label"]').fill('Renamed audit archive');
    await card(page, 'audit_log.slack').locator('[data-notification-save]').click(); await settled(page);
    assert.equal(state.posts.length, 1); assert.equal(state.posts[0].kind, 'save');
    const {operation_id, ...saved} = state.posts[0].body;
    assert.deepEqual(saved, {slot: 'audit_log.slack', expected_revision: 3, label: 'Renamed audit archive', enabled: false,
      event_types: ['data_plane.request.denied'], max_attempts: 3, url_action: 'keep'});
    assert.deepEqual(state.snapshot.slots.filter(slot => slot.slot !== 'audit_log.slack'), untouched);
    assert.match(await card(page, 'audit_log.slack').locator('[data-notification-destination]').innerText(), /Renamed audit archive/);
    assert.match(await page.locator('#notification-operation-status').innerText(), /No message was sent by Save/);
    assert.equal(await card(page, 'audit_log.slack').locator('[data-notification-test]').isDisabled(), true);
    assert.equal(await page.locator('[data-notification-fields]:visible').count(), 1);
  });
  console.log('PASS one explicit slot-local save, no enabling or test, summary reflects confirmed settings');

  await fixture(browser, async (page, state) => {
    await openEditor(page, 'action_required.slack');
    await card(page, 'action_required.slack').locator('[data-notification-test]').click(); await settled(page);
    assert.equal(state.posts.length, 1); assert.equal(state.posts[0].kind, 'test');
    assert.equal(await page.locator('#notification-operation-status').isVisible(), true);
    assert.match(await page.locator('#notification-operation-status').innerText(), /lost or unavailable|check.*result/i);
    await card(page, 'action_required.slack').locator('[data-notification-edit]').click();
    assert.equal(await page.locator('[data-notification-fields]:visible').count(), 0);
    assert.equal(await page.locator('#notification-check-operation').isVisible(), true);
    assert.equal(await page.locator('#notification-check-operation').isDisabled(), false);
    const operation = state.posts[0].body.operation_id;
    await page.locator('#notification-check-operation').click(); await settled(page);
    assert.equal(state.posts.length, 1, 'receipt review never retries the test');
    assert(state.reads.includes(PREFIX + '/operations/' + operation));
    assert.match(await page.locator('#notification-operation-status').innerText(), /queued.*not yet delivered/i);
    assert.equal(await page.locator('[data-notification-fields]:visible').count(), 0);
    await page.screenshot({path: join(artifacts, 'operation-recovery-visible.png'), fullPage: true});
  }, {lostReply: true});
  console.log('PASS explicit test with lost reply, visible recovery and read-only receipt check without replay');
  return {ok: true, groups: 4, artifactDirectory: artifacts,
    scope: 'synthetic rendered notification UX; no live writes or destination deliveries'};
}

module.exports = {runSuite};
if (require.main === module) (async () => {
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true, args: ['--no-sandbox', '--host-resolver-rules=MAP * ~NOTFOUND']});
  try { console.log(JSON.stringify(await runSuite(browser))); } finally { await browser.close(); }
})().catch(error => { console.error(error.stack); process.exitCode = 1; });

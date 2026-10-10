#!/usr/bin/env node
// Pure public DTO/presentation checks with an inert DOM and controlled clocks.
// No browser, application import, HTTP, native owner, database or hardware.
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');

const NOW = 1800000000000;
const REVIEW = 'https://serverware.example.com/pilot-prelaunch/action-status/' + 'a'.repeat(64) + '/' + 'b'.repeat(64);
const PHASES = ['prepare_available', 'security_key_available', 'confirmation_available', 'waiting', 'preparing',
  'preparing_confirmation', 'action_in_progress', 'response_captured', 'cancelled', 'expired'];
const ACTION_PHASES = PHASES.slice(0, 3);
let now = NOW; let timerId = 0; let networkCalls = 0;
const timers = new Map();
class Node {
  constructor(tag, text) { this.tag = tag; this.textContent = text === undefined ? '' : String(text); this.children = []; this.dataset = {}; this.attributes = {}; }
  append(...children) { this.children.push(...children); }
  setAttribute(name, value) { this.attributes[name] = value; }
  removeAttribute(name) { delete this.attributes[name]; delete this[name]; }
}
class Clock extends Date { static now() { return now; } }
const context = vm.createContext({Date: Clock, URL, operatorError: message => Object.assign(new Error('Safe UI error'), {uiMessage: message}),
  textNode: (tag, text) => new Node(tag, text),
  setTimeout: (callback, delay) => { const id = ++timerId; timers.set(id, {callback, delay}); return id; },
  clearTimeout: id => timers.delete(id),
  fetch: () => { networkCalls++; throw new Error('No network permitted'); }});
const source = readFileSync(resolve(__dirname, '../serverware/operator_demo_web/workspace_notifications.js'), 'utf8');
vm.runInContext(source, context, {timeout: 1000});
const api = vm.runInContext('({valid:notificationNativeValid, present:notificationNativePresentation, project:projectNotificationStatus, render:createNotificationNativeObservation})', context);

function native(state = 'not_configured', changes = {}) {
  return {configured: state !== 'not_configured', source_available: ['waiting', 'observed'].includes(state), observation_only: true,
    last_observation: {state, observed_at_epoch_ms: ['not_configured', 'not_observed'].includes(state) ? null : NOW,
      phase: state === 'observed' ? 'security_key_available' : null, action_available: state === 'observed',
      source_expires_at_unix_nanos: state === 'observed' ? String(BigInt(NOW + 30000) * 1000000n) : null,
      review_url: state === 'observed' ? REVIEW : null, ...changes}};
}
function status(value = native()) {
  const events = ['native_pilot.confirmation_available', 'native_pilot.prepare_available', 'native_pilot.security_key_available'];
  return {schema: 'serverware.operatorNotifications/v1', available: true,
    slots: ['action_required.slack', 'action_required.webhook', 'audit_log.slack', 'audit_log.webhook'].map(slot => ({slot,
      channel: slot.split('.')[0], adapter: slot.split('.')[1], revision: 0, label: '', enabled: false, secret_present: false,
      event_types: [], max_attempts: 1, last_delivery: null})),
    queue: Object.fromEntries(['queued', 'sending', 'acknowledged', 'failed', 'outcome_unknown', 'suppressed', 'expired'].map(key => [key, 0])),
    cursor: null, backlog: {pending_source_events: 0, queue_capacity: 256, retained_capacity: 10000},
    capabilities: {audit_log: {source_available: true, event_types: events},
      action_required: {source_available: value.source_available, event_types: events}, native_hardware: value,
      source_note: 'Last observer read only.', test_note: 'Synthetic test is not readiness or approval.'},
    worker: {state: 'running', last_cycle_at_epoch_ms: NOW, last_code: 'ready'}};
}
function node(panel, key) { const match = panel.children.find(item => Object.hasOwn(item.dataset, key)); assert(match, key); return match; }
function allNodes(root) { return [root, ...root.children.flatMap(allNodes)]; }
function reject(change) { const candidate = native('observed'); change(candidate); assert.equal(api.valid(candidate), false); assert.throws(() => api.project(status(candidate))); }
const tests = [
  ['configuration and last successful read never imply an action', () => {
    for (const state of ['not_configured', 'not_observed', 'waiting', 'unavailable']) {
      const value = native(state); assert(api.valid(value)); assert.equal(api.project(status(value)).capabilities.native_hardware.last_observation.state, state);
      const view = api.present(value, NOW); assert.match(view.availability, /No native action/); assert.equal(view.phase, null);
      assert.equal(view.reviewUrl, null); assert.equal(view.refreshAfterMs, null);
    }
    assert.match(api.present(native('not_observed'), NOW).source, /configured; no observation/);
    assert.match(api.present(native('waiting'), NOW).source, /last source read succeeded/);
    assert.match(api.present(native('unavailable'), NOW).source, /last source read was unavailable/);
  }],
  ['all ten phases are last observations, not commands or enrollment proof', () => {
    for (const phase of PHASES) {
      const value = native('observed', {phase, action_available: ACTION_PHASES.includes(phase)});
      assert(api.valid(value)); const view = api.present(value, NOW);
      assert.match(view.phase, /^Last observed phase:/); assert.equal(view.reviewUrl, REVIEW);
      assert.doesNotMatch(view.phase + view.availability, /press (?:your|the) key now|enrollment succeeded|ceremony complete/i);
      assert.match(view.availability, ACTION_PHASES.includes(phase) ? /snapshot reported.*does not confirm/ : /did not report an available action/);
    }
    assert.match(api.present(native('observed', {phase: 'action_in_progress', action_available: false}), NOW).phase, /already in progress/);
    assert.match(api.present(native('observed', {phase: 'response_captured', action_available: false}), NOW).phase, /enrollment not confirmed/);
  }],
  ['original nanosecond expiry demotes without truncation, renewal or removing historical review', () => {
    const before = native('observed', {source_expires_at_unix_nanos: String(BigInt(NOW) * 1000000n + 1n)});
    assert.match(api.present(before, NOW).availability, /snapshot reported/);
    assert.equal(api.present(before, NOW).refreshAfterMs, 1);
    assert.match(api.present(before, NOW + 1).availability, /original source window has expired/);
    assert.equal(api.present(before, NOW + 1).reviewUrl, REVIEW);
    const exact = native('observed', {source_expires_at_unix_nanos: String(BigInt(NOW) * 1000000n)});
    assert.match(api.present(exact, NOW).availability, /expired/);
    assert.equal(exact.last_observation.source_expires_at_unix_nanos, String(BigInt(NOW) * 1000000n));
  }],
  ['cached snapshot ages out at exactly fifteen seconds and clock uncertainty never promotes it', () => {
    const value = native('observed');
    assert.match(api.present(value, NOW + 14999).availability, /snapshot reported/);
    assert.equal(api.present(value, NOW + 14999).refreshAfterMs, 1);
    assert.match(api.present(value, NOW + 15000).availability, /stale/);
    assert.match(api.present(value, NOW - 1).availability, /clock cannot confirm/);
    assert.match(api.present(value, Number.NaN).availability, /clock cannot confirm/);
    assert.equal(api.present(value, NOW - 1).refreshAfterMs, null);
    assert.equal(value.source_available, true, 'historical successful read is not relabeled as a fresh check');
  }],
  ['server-demoted snapshots and nonactionable observations remain nonactionable', () => {
    assert.match(api.present(native('observed', {action_available: false}), NOW).availability, /did not report/);
    const value = native('observed', {phase: 'response_captured', action_available: false, source_expires_at_unix_nanos: null});
    assert(api.valid(value)); assert.equal(api.present(value, NOW).expiresAt, null);
    assert.equal(api.present(value, NOW).reviewUrl, REVIEW);
  }],
  ['malformed capabilities and cross-state contradictions fail closed', () => {
    for (const change of [item => { delete item.observation_only; }, item => { item.observation_only = false; },
      item => { item.secret = 'forbidden'; }, item => { item.configured = false; }, item => { item.source_available = false; },
      item => { item.last_observation.state = 'claimed'; }, item => { item.last_observation.phase = 'unknown'; },
      item => { item.last_observation.observed_at_epoch_ms = null; }, item => { item.last_observation.observed_at_epoch_ms = 1.5; },
      item => { item.last_observation.action_available = 'true'; }, item => { item.last_observation.source_expires_at_unix_nanos = null; },
      item => { item.last_observation.phase = 'action_in_progress'; }, item => { item.last_observation.extra = true; }]) reject(change);
    for (const state of ['not_configured', 'not_observed', 'waiting', 'unavailable']) {
      const value = native(state, {action_available: true}); assert.equal(api.valid(value), false);
    }
    const value = status(native('observed')); value.capabilities.action_required.source_available = false; assert.throws(() => api.project(value));
    const legacy = status(); legacy.capabilities.native_hardware = {source_available: false}; assert.throws(() => api.project(legacy));
  }],
  ['native review locator and expiry have exact closed grammars', () => {
    for (const url of [null, '/#notifications', REVIEW.replace('https:', 'http:'), REVIEW + '?token=forbidden', REVIEW + '#prepare',
      REVIEW.replace('serverware.example.com', 'other.example.test'), REVIEW.replace('/action-status/', '/prepare/'),
      REVIEW.replace('a'.repeat(64), 'a'.repeat(63)), REVIEW.replace('b'.repeat(64), 'B'.repeat(64))])
      reject(item => { item.last_observation.review_url = url; });
    for (const expiry of ['0', '01', '-1', '1.5', '1e18', '9223372036854775808', '99999999999999999999', 1800000000000000000])
      reject(item => { item.last_observation.source_expires_at_unix_nanos = expiry; });
    assert(api.valid(native('observed', {source_expires_at_unix_nanos: '9223372036854775807'})));
  }],
  ['inert DOM contains only fixed read-only review link and no native action controls', () => {
    now = NOW; const controller = api.render(native('observed')); controller.update();
    const elements = allNodes(controller.panel); assert(!elements.some(item => ['button', 'form', 'input'].includes(item.tag)));
    const links = elements.filter(item => item.tag === 'a'); assert.equal(links.length, 1); assert.equal(links[0].href, REVIEW);
    assert.equal(links[0].referrerPolicy, 'no-referrer'); assert.match(links[0].textContent, /read only/);
    assert(elements.every(item => !Object.keys(item.attributes).some(key => key.startsWith('on'))));
    assert.match(node(controller.panel, 'nativePhase').textContent, /^Last observed phase:/);
    assert.match(node(controller.panel, 'nativeObservedAt').textContent, /^Last source check:/);
    assert.match(node(controller.panel, 'nativeExpiry').textContent, /^Original source expiry:/);
    controller.stop(); assert.equal(timers.size, 0);
  }],
  ['presentation timer only demotes, cannot rearm after clock rollback, and stops when hidden', () => {
    now = NOW; const value = native('observed'); const unchanged = JSON.stringify(value);
    const controller = api.render(value); controller.update(); assert.equal(timers.size, 1);
    const tick = [...timers.values()][0]; assert.equal(tick.delay, 15000);
    now += 15000; tick.callback(); assert.match(node(controller.panel, 'nativeAvailability').textContent, /stale/);
    now = NOW + 30000; [...timers.values()][0].callback(); assert.match(node(controller.panel, 'nativeAvailability').textContent, /expired/);
    now = NOW + 1; controller.update(); assert.match(node(controller.panel, 'nativeAvailability').textContent, /clock cannot confirm/);
    assert.equal(timers.size, 0); assert.equal(JSON.stringify(value), unchanged);
    const hidden = api.render(native('observed')); now = NOW; hidden.update(false); assert.equal(timers.size, 0); hidden.stop();
    assert.equal(networkCalls, 0);
  }],
  ['rollback before first stale tick permanently demotes the same cached observation across refresh', () => {
    now = NOW; const value = native('observed'); const clock = {key: null, latest: null, uncertain: false};
    const controller = api.render(value, clock); controller.update();
    assert.match(node(controller.panel, 'nativeAvailability').textContent, /snapshot reported/);
    const firstTick = [...timers.values()][0]; assert.equal(firstTick.delay, 15000);
    now = NOW - 1; firstTick.callback();
    assert.match(node(controller.panel, 'nativeAvailability').textContent, /clock cannot confirm/);
    assert.equal(timers.size, 0); assert.equal(clock.uncertain, true);
    for (const time of [NOW + 1, NOW + 1000, NOW + 16000]) {
      now = time; firstTick.callback();
      assert.match(node(controller.panel, 'nativeAvailability').textContent, /clock cannot confirm/);
      assert.equal(timers.size, 0);
    }
    now = NOW + 1000;
    const refreshed = api.render(value, clock); refreshed.update();
    assert.match(node(refreshed.panel, 'nativeAvailability').textContent, /clock cannot confirm/);
    assert.equal(timers.size, 0);
    const newObservation = native('observed', {observed_at_epoch_ms: NOW + 1000});
    const fresh = api.render(newObservation, clock); fresh.update();
    assert.equal(clock.uncertain, false); assert.match(node(fresh.panel, 'nativeAvailability').textContent, /snapshot reported/);
    fresh.stop(); assert.equal(timers.size, 0); assert.equal(networkCalls, 0);
  }],
  ['missing source renders no native review locator and does not schedule a poll', () => {
    now = NOW;
    for (const state of ['not_configured', 'not_observed', 'waiting', 'unavailable']) {
      const controller = api.render(native(state)); controller.update();
      const link = node(controller.panel, 'nativeReview'); assert.equal(link.hidden, true); assert.equal(link.href, undefined);
      assert.equal(timers.size, 0); controller.stop();
    }
    assert.equal(networkCalls, 0);
  }],
];

for (const [name, test] of tests) { test(); console.log('PASS ' + name); }
assert.equal(timers.size, 0); assert.equal(networkCalls, 0);
console.log(JSON.stringify({ok: true, groups: tests.length, scope: 'pure native notification UI DTO and inert DOM checks; no browser, network, owner or hardware'}));

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
const api = vm.runInContext('({valid:notificationNativeValid, present:notificationNativePresentation, project:projectNotificationStatus, render:createNotificationNativeObservation, delivery:notificationDeliveryMessage, presets:notificationAuditPresets, selectPreset:notificationPresetSelection, filterProblem:notificationFilterProblem, filterMessage:notificationFilterMessage})', context);
const PRESETS = {
  proxy_blocks: ['data_plane.connect.denied', 'data_plane.policy.reload_failed', 'data_plane.request.denied', 'data_plane.response.blocked'],
  access_changes: ['access_rule.alchemy_chain_status_created', 'access_rule.created', 'access_rule.github_created',
    'access_rule.npm_install_created', 'access_rule.npm_metadata_created', 'access_rule.npm_publish_created',
    'access_rule.revoked', 'access_rule.x_username_created', 'application.created', 'application.proxy_authentication_changed',
    'application.revoked', 'application.token_rotated', 'credential.alchemy_key_created', 'credential.aws_sigv4_created',
    'credential.aws_sigv4_replaced', 'credential.created', 'credential.github_app_created', 'credential.github_app_key_replaced',
    'credential.github_token_created', 'credential.key_replaced', 'credential.npm_token_created', 'credential.revoked',
    'credential.x_app_bearer_created'].map(type => 'operator_catalog.' + type),
  approval_history: ['approval.approved', 'approval.decision_recorded', 'approval.denied', 'approval.requested', 'approval.review_opened',
    'control_plane.approval.approved', 'control_plane.approval.consumed', 'control_plane.approval.denied',
    'control_plane.approval.invalidated', 'control_plane.approval.requested'],
};
const AUDIT = [...Object.values(PRESETS).flat(), 'credential.oauth_refresh_failed'].sort();
const plain = value => JSON.parse(JSON.stringify(value));

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
function delivery(changes = {}) {
  const value = status();
  Object.assign(value.slots[0], {revision: 1, label: 'Action Slack', enabled: true, secret_present: true,
    last_delivery: {delivery_id: '77777777-7777-4777-8777-777777777777', status: 'failed', attempts: 1,
      code: null, http_status: null, created_at_epoch_ms: NOW, updated_at_epoch_ms: NOW, ...changes}});
  return api.project(value).slots[0].last_delivery;
}
const tests = [
  ['audit presets have a fixed supported roster and are not action-source presets', () => {
    assert.deepEqual(plain(api.presets).map(item => item.id), Object.keys(PRESETS));
    const eventSource = readFileSync(resolve(__dirname, '../serverware/operator_notification_events.py'), 'utf8');
    assert(Object.isFrozen(api.presets));
    for (const preset of api.presets) {
      assert(Object.isFrozen(preset)); assert(Object.isFrozen(preset.events));
      assert.match(preset.label, /^Add /); assert.deepEqual(plain(preset.events), PRESETS[preset.id]);
      assert.deepEqual(plain(preset.events), [...new Set(preset.events)].sort());
      for (const type of preset.events) {
        // Catalog summary literals are prefixed by the actual event producer.
        const literal = type.replace(/^operator_catalog\./, '');
        assert(eventSource.includes('"' + literal + '"') || eventSource.includes("'" + literal + "'"), type);
        assert(!type.startsWith('native_pilot.'));
      }
    }
    assert.equal(networkCalls, 0);
  }],
  ['explicit preset selection adds to a draft without mutating inputs and is idempotent', () => {
    const advertised = Object.freeze([...AUDIT]); const selected = Object.freeze(['credential.oauth_refresh_failed']);
    for (const [id, expected] of Object.entries(PRESETS)) {
      const next = api.selectPreset('audit_log', id, advertised, selected);
      assert.deepEqual(plain(next), [...selected, ...expected].sort());
      assert.deepEqual(plain(api.selectPreset('audit_log', id, advertised, next)), plain(next));
      assert.deepEqual(selected, ['credential.oauth_refresh_failed']); assert.deepEqual(advertised, AUDIT);
      assert.notEqual(next, selected);
    }
    assert.equal(networkCalls, 0);
  }],
  ['audit presets select only advertised events and cannot cross into action-required slots', () => {
    const advertised = ['approval.requested', 'fixture.future_audit', 'native_pilot.prepare_available'];
    assert.deepEqual(plain(api.selectPreset('audit_log', 'approval_history', advertised, [])), ['approval.requested']);
    assert.deepEqual(plain(api.selectPreset('audit_log', 'approval_history', advertised, ['fixture.future_audit'])),
      ['approval.requested', 'fixture.future_audit']);
    for (const channel of ['action_required', 'unknown', null])
      assert.equal(api.selectPreset(channel, 'approval_history', advertised, []), null);
    assert.equal(api.selectPreset('audit_log', 'proxy_blocks', advertised, []), null);
    assert.equal(api.selectPreset('audit_log', 'unknown', advertised, []), null);
    assert.equal(api.selectPreset('audit_log', 'approval_history', [], []), null);
    assert.equal(networkCalls, 0);
  }],
  ['preset selection rejects malformed or unadvertised current filters without repairing or expanding them', () => {
    for (const selected of [null, {}, ['unknown.event'], ['approval.requested', 'approval.requested'],
      ['approval.requested', 'approval.approved'], ['Bad.Type'], Array.from({length: 65}, (_, i) => 'fixture.' + String(i).padStart(2, '0'))])
      assert.equal(api.selectPreset('audit_log', 'approval_history', AUDIT, selected), null);
    for (const advertised of [null, {}, ['approval.requested', 'approval.requested'], ['Bad.Type'],
      Array.from({length: 69}, (_, i) => 'fixture.' + String(i).padStart(2, '0'))])
      assert.equal(api.selectPreset('audit_log', 'approval_history', advertised, []), null);
    assert.equal(networkCalls, 0);
  }],
  ['additive presets respect the 64-event union limit without dropping existing selections', () => {
    const other = Array.from({length: 64}, (_, i) => 'fixture.event_' + String(i).padStart(2, '0'));
    const advertised = Object.freeze([...PRESETS.proxy_blocks, ...other].sort());
    const full = Object.freeze([...other]);
    assert.equal(api.selectPreset('audit_log', 'proxy_blocks', advertised, full), null);
    assert.deepEqual(full, other);
    const next = api.selectPreset('audit_log', 'proxy_blocks', advertised, other.slice(0, 60));
    assert.equal(next.length, 64); assert.deepEqual(plain(next), [...PRESETS.proxy_blocks, ...other.slice(0, 60)].sort());
    assert.deepEqual(plain(api.selectPreset('audit_log', 'proxy_blocks', advertised, next)), plain(next));
    assert.equal(api.selectPreset('audit_log', 'proxy_blocks', advertised, other.slice(0, 61)), null);
  }],
  ['enabled-empty draft validation is visible and muted empty settings remain savable', () => {
    assert.match(api.filterProblem(true, []), /Select at least one event or disable.*Nothing was submitted/);
    assert.equal(api.filterProblem(false, []), null);
    assert.match(api.filterMessage(true, []), /No source events selected in this draft.*Empty saved filters deliver no source events; synthetic tests are separate/);
    assert.match(api.filterMessage(false, []), /Disabled; no source events selected.*save.*without enabling delivery/);
    for (const enabled of [true, false]) {
      assert.equal(api.filterProblem(enabled, ['approval.requested']), null);
      assert.match(api.filterMessage(enabled, ['approval.requested']), /Draft changes take effect only after Save.*does not confirm source availability/);
      assert.match(api.filterProblem(enabled, Array.from({length: 65}, (_, i) => 'fixture.' + String(i).padStart(2, '0'))), /at most 64/);
    }
    assert.match(api.filterMessage(false, new Array(65)), /65\/64.*Remove events before saving/);
    assert.equal(networkCalls, 0);
  }],
  ['saved enabled-empty and muted-empty slots remain readable without implicit filter changes', () => {
    const value = status();
    for (const [index, slot] of value.slots.entries()) Object.assign(slot, {revision: 1, label: 'Saved destination',
      enabled: index % 2 === 0, secret_present: true, event_types: []});
    const before = JSON.stringify(value);
    assert.equal(api.project(value), value); assert.equal(JSON.stringify(value), before);
    assert(value.slots.every(slot => slot.event_types.length === 0));
    assert.equal(networkCalls, 0);
  }],
  ['68 advertised audit types never widen the 64-filter destination limit or select anything', () => {
    const value = status();
    const types = [...Array.from({length: 64}, (_, index) => 'fixture.event_' + String(index).padStart(2, '0')),
      'operator_catalog.access_rule.npm_install_created', 'operator_catalog.credential.github_app_created',
      'operator_catalog.credential.github_app_key_replaced',
      'operator_catalog.x_oauth.configuration_saved'].sort();
    value.capabilities.audit_log.event_types = types;
    const before = JSON.stringify(value);
    assert.equal(api.project(value), value); assert.equal(JSON.stringify(value), before);
    assert(value.slots.every(slot => slot.event_types.length === 0));
    Object.assign(value.slots[2], {revision: 1, label: 'Audit destination', enabled: true, secret_present: true,
      event_types: types.slice(0, 64)});
    assert.equal(api.project(value).slots[2].event_types.length, 64);
    value.slots[2].event_types = types.slice(0, 65); assert.throws(() => api.project(value));
    value.slots[2].event_types = types; assert.throws(() => api.project(value));
    value.slots[2].event_types = [];
    value.capabilities.audit_log.event_types = [...types, 'zz.extra']; assert.throws(() => api.project(value));
    value.capabilities.audit_log.event_types = types;
    value.capabilities.action_required.event_types = types.slice(0, 65); assert.throws(() => api.project(value));
    assert.equal(networkCalls, 0);
  }],
  ['all retained delivery reason codes have fixed useful explanations without changing the outcome', () => {
    const cases = [
      ['dns_unavailable', /hostname could not be resolved/], ['dns_timeout', /DNS lookup timed out/],
      ['connect_unavailable', /could not be reached/], ['connect_timeout', /connection timed out/],
      ['tls_unavailable', /verified HTTPS connection/], ['tls_timeout', /HTTPS handshake timed out/],
      ['destination_invalid', /not supported by this adapter/], ['egress_denied', /deployment egress policy/],
      ['payload_invalid', /message could not be prepared/], ['transport_unavailable', /final checks were unavailable/],
      ['deadline_exceeded', /delivery time limit elapsed/], ['dispatch_cancelled', /check prevented sending/],
      ['http_rejected', /non-success HTTP status/], ['acknowledgement_invalid', /acknowledgement contract/],
      ['delivery_unknown', /Check the destination for this message/], ['configuration_changed', /not redirected/],
      ['action_no_longer_current', /source action is no longer current/], ['action_expired', /cannot renew/],
      ['action_source_unavailable', /source action could not be validated/], ['native_source_unavailable', /does not establish hardware readiness/]
    ];
    for (const [code, explanation] of cases) {
      const value = Object.freeze(delivery({code})); const before = JSON.stringify(value);
      const message = api.delivery(value);
      assert.match(message, /^Delivery failed\./); assert.match(message, /Attempts: 1\./);
      assert(message.includes('Last result: ' + code + '.')); assert.match(message, explanation);
      assert.equal(JSON.stringify(value), before); assert.doesNotMatch(message, /HTTP status:/);
    }
    const queued = api.delivery(delivery({status: 'queued', code: 'dns_timeout'}));
    assert.match(queued, /^Delivery queued; not yet acknowledged\./); assert.doesNotMatch(queued, /Synthetic test/);
    assert.equal(api.delivery(null), 'No delivery receipt for this slot.');
  }],
  ['unknown delivery codes are never reflected and malformed metadata fails projection', () => {
    for (const code of ['private_destination_token_must_not_render', 'constructor', '__proto__']) {
      const message = api.delivery(delivery({code}));
      assert.match(message, /Delivery detail unavailable\./); assert(!message.includes(code));
    }
    for (const code of ['https://secret.example.test/private', '<script>private</script>', 'RAW_RESPONSE', true])
      assert.throws(() => delivery({code}));
    for (const http_status of [true, '403', 199, 600, 200.5, Number.NaN]) assert.throws(() => delivery({http_status}));
    const missing = api.delivery(delivery()); assert.match(missing, /^Delivery failed\./);
    assert.doesNotMatch(missing, /Last result:|HTTP status:|undefined|null/);
  }],
  ['HTTP success and conflicting codes never promote failed or unknown delivery to acknowledgement', () => {
    const failed = api.delivery(delivery({code: 'acknowledgement_invalid', http_status: 200}));
    assert.match(failed, /^Delivery failed\./); assert.match(failed, /HTTP status: 200\./);
    assert.match(failed, /HTTP success alone is not acknowledgement/); assert.doesNotMatch(failed, /Destination acknowledged/);
    for (const code of ['delivery_unknown', 'acknowledged', 'connect_unavailable', 'unknown_private_reason']) {
      const message = api.delivery(delivery({status: 'outcome_unknown', code, http_status: 200}));
      assert.match(message, /^Delivery outcome unknown\./); assert.match(message, /may have received it; no automatic replay/);
      assert.match(message, /HTTP status: 200\./); assert.doesNotMatch(message, /Destination acknowledged|Last result: acknowledged|explicitly testing again/);
    }
    const acknowledged = api.delivery(delivery({status: 'acknowledged', code: 'acknowledged', http_status: 204}));
    assert.match(acknowledged, /^Destination acknowledged delivery\./);
    assert.match(acknowledged, /not human approval or action completion/); assert.match(acknowledged, /HTTP status: 204\./);
    assert.match(api.delivery(delivery({status: 'suppressed', code: 'configuration_changed'})), /^Delivery suppressed because its saved configuration or source action is no longer current\./);
    assert.match(api.delivery(delivery({status: 'expired', code: 'action_expired'})), /^Delivery expired\./);
    assert.equal(networkCalls, 0); assert.equal(timers.size, 0);
  }],
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
console.log(JSON.stringify({ok: true, groups: tests.length, scope: 'pure notification delivery and native observation UI DTO and inert DOM checks; no browser, network, owner or hardware'}));

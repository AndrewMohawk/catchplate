#!/usr/bin/env node
// Pure presentation only: no app, provider, audit writer, browser or network.
const assert = require('node:assert/strict');
const {readFileSync} = require('node:fs');
const {resolve} = require('node:path');
const vm = require('node:vm');

const TYPE = 'data_plane.response.blocked';
const UNKNOWN = 'This event does not establish whether the provider received the request.';
function marker(upstreamDispatch = 'response_received', mayHaveCommitted = true) {
  return {upstreamDispatch, providerOutcome: 'unknown', retryProviderRequest: false,
    providerOperationMayHaveCommitted: mayHaveCommitted};
}
function record(event = {}, event_type = TYPE, id = 'synthetic-audit-event') {
  return {id, event_type, created_at: '2026-10-11T12:00:00Z', actor_type: 'data_plane',
    event: {component: 'catchplate-decision-gate-rs', outcome: 'blocked', method: 'POST',
      attempt_id: '11111111-1111-4111-8111-111111111111', upstream_status: 201, ...event}};
}
function run() {
  let effects = 0;
  const forbid = () => { effects++; throw new Error('No effects permitted'); };
  const context = vm.createContext({fetch: forbid, setTimeout: forbid, document: {createElement: forbid}});
  vm.runInContext(readFileSync(resolve(__dirname, '../catchplate/operator_demo_web/workspace_proxy_audit.js'), 'utf8'), context, {timeout: 1000});
  const present = vm.runInContext('auditProviderOutcome', context);
  const unknown = value => { const result = present(value); assert.equal(result.kind, 'unknown'); assert.equal(result.warning, false); assert.equal(result.text, UNKNOWN); };
  const tests = [
    ['exact post-dispatch write markers warn without asserting provider completion', () => {
      for (const dispatch of ['response_received', 'attempted']) {
        const value = record(marker(dispatch)); const before = JSON.stringify(value);
        Object.freeze(value.event); Object.freeze(value);
        const result = present(value);
        assert.equal(result.kind, 'write_unconfirmed'); assert.equal(result.warning, true);
        assert.equal(result.text, (dispatch === 'response_received' ? 'Provider response withheld.' : 'Provider dispatch was attempted.') +
          ' This write may have completed. Check the provider before retrying; do not retry automatically.');
        assert.equal(JSON.stringify(value), before);
      }
    }],
    ['false markers never infer a write from HTTP method and true markers are not inferred from status', () => {
      for (const dispatch of ['response_received', 'attempted']) {
        const result = present(record({...marker(dispatch, false), method: 'POST', upstream_status: 200}));
        assert.equal(result.kind, 'completion_unconfirmed'); assert.equal(result.warning, false);
        assert.equal(result.text, (dispatch === 'response_received' ? 'Provider response withheld.' : 'Provider dispatch was attempted.') +
          ' Provider completion is unconfirmed; do not retry automatically.');
        assert.doesNotMatch(result.text, /write may|completed\./);
      }
      assert.equal(present(record({...marker(), method: 'GET', upstream_status: 503})).kind, 'write_unconfirmed');
    }],
    ['missing partial malformed or inherited markers retain legacy uncertainty', () => {
      unknown(record()); unknown(record({release_started: true, status: 201, status_code: 200}));
      for (const field of ['upstreamDispatch', 'providerOutcome', 'retryProviderRequest', 'providerOperationMayHaveCommitted']) {
        const value = record(marker()); delete value.event[field]; unknown(value);
      }
      for (const change of [{upstreamDispatch: 'sent'}, {upstreamDispatch: true}, {providerOutcome: 'committed'},
        {providerOutcome: null}, {retryProviderRequest: true}, {retryProviderRequest: 0},
        {providerOperationMayHaveCommitted: 'true'}, {providerOperationMayHaveCommitted: 1},
        {providerOperationMayHaveCommitted: null}, {outcome: 'released'}]) unknown(record({...marker(), ...change}));
      const inherited = record(); Object.setPrototypeOf(inherited.event, marker()); unknown(inherited);
      const noOutcome = record(marker()); delete noOutcome.event.outcome; unknown(noOutcome);
      unknown(record({response_validation: marker(), payload: marker()}));
      unknown({...record(), ...marker()});
      for (const event of [null, [], 'response_received', true]) unknown({...record(), event});
    }],
    ['other event types do not acquire a warning even with a complete marker', () => {
      for (const type of ['data_plane.response.released', 'data_plane.response.release_started', 'data_plane.request.denied',
        'operator_catalog.credential.created', 'response.blocked', '', null]) assert.equal(present(record(marker(), type)), null);
      for (const value of [null, undefined, {}, [], false]) assert.equal(present(value), null);
    }],
    ['presentation is fixed text and does not echo event errors identifiers or URLs', () => {
      const canary = '<img src="https://private.example.test/token" onerror="globalThis.executed=true">';
      const value = record({...marker(), error: canary, attempt_id: canary, url: canary});
      const result = present(value); assert(!result.text.includes(canary)); assert.doesNotMatch(result.text, /https:|<img/);
      unknown(record({...marker(), providerOutcome: canary}));
      assert.equal(value.event.error, canary, 'presentation must not rewrite retained event details');
      assert.equal(effects, 0);
    }],
  ];
  for (const [name, test] of tests) { test(); console.log('PASS ' + name); }
  assert.equal(effects, 0);
  console.log(JSON.stringify({ok: true, groups: tests.length, scope: 'pure audit marker presentation only; no producer or provider proof'}));
}
if (require.main === module) run();
module.exports = {marker, record, TYPE, UNKNOWN};

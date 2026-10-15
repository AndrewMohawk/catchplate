#!/usr/bin/env node
// Rendered notification protocol fixtures only. Every API response is synthetic
// and intercepted; no app, destination, Slack, provider, CA or proxy is contacted.
const assert = require('node:assert/strict');
const {withoutMutationReview} = require('./operator_mutation_recovery_test_helpers.cjs');
const {createHash} = require('node:crypto');
const {execFileSync} = require('node:child_process');
const {readFile, readdir, mkdtemp} = require('node:fs/promises');
const {join, resolve} = require('node:path');
const {fixture: baseFixture, ready, view, credential, application, rule, NOW} = require('./test_operator_catalog_browser.cjs');

const ROOT = resolve(__dirname, '..');
const PATH = '/api/operator-demo/notifications';
const STORAGE = 'serverware.operator.notifications.operation.v1';
const SLOTS = ['action_required.slack', 'action_required.webhook', 'audit_log.slack', 'audit_log.webhook'];
const STATES = ['queued', 'sending', 'acknowledged', 'failed', 'outcome_unknown', 'suppressed', 'expired'];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const PRIVATE = ['https://notify.example.test/synthetic-private-destination',
  'https://hooks.slack.com/services/T00000000/B00000000/SYNTHETIC_NOT_A_REAL_WEBHOOK',
  'synthetic-private-error-MUST-NOT-RENDER', 'private_delivery_detail_must_not_render'];
const clone = value => JSON.parse(JSON.stringify(value));
const AUDIT_PRESETS = {
  proxy_blocks: ['data_plane.connect.denied', 'data_plane.policy.reload_failed', 'data_plane.request.denied', 'data_plane.response.blocked'],
  access_changes: ['access_rule.alchemy_chain_status_created', 'access_rule.created', 'access_rule.github_created',
    'access_rule.npm_install_created', 'access_rule.npm_metadata_created', 'access_rule.npm_publish_created',
    'access_rule.revoked', 'access_rule.x_username_created', 'application.created', 'application.proxy_authentication_changed',
    'application.renewal_cancelled', 'application.renewal_enrolled', 'application.revoked',
    'application.token_renewed', 'application.token_rotated', 'credential.alchemy_key_created', 'credential.aws_sigv4_created',
    'credential.aws_sigv4_replaced', 'credential.created', 'credential.github_app_created', 'credential.github_app_key_replaced',
    'credential.github_token_created', 'credential.key_replaced', 'credential.npm_token_created', 'credential.revoked',
    'credential.x_app_bearer_created'].map(type => 'operator_catalog.' + type),
  approval_history: ['approval.approved', 'approval.decision_recorded', 'approval.denied', 'approval.requested', 'approval.review_opened',
    'control_plane.approval.approved', 'control_plane.approval.consumed', 'control_plane.approval.denied',
    'control_plane.approval.invalidated', 'control_plane.approval.requested',
    'operator.host_approval.approved', 'operator.host_approval.claimed', 'operator.host_approval.denied',
    'operator.host_approval.expired', 'operator.host_approval.requested', 'operator.host_approval.reviewed'],
};
const EVENTS = JSON.parse(execFileSync('python3', ['-I', '-B', '-c',
  `import ast,json,pathlib
tree=ast.parse(pathlib.Path("serverware/operator_notification_events.py").read_text())
assignments={n.targets[0].id:n.value for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Name)}
summaries=ast.literal_eval(assignments["_SUMMARIES"])
summaries.update(ast.literal_eval(assignments["_GOOGLE_SUMMARIES"]))
host_requested=ast.literal_eval(assignments["HOST_REQUESTED"])
assert host_requested=="operator.host_approval.requested"
host_summaries=assignments["_HOST_SUMMARIES"]
assert isinstance(host_summaries,ast.Dict) and len(host_summaries.keys)==6
for key,value in zip(host_summaries.keys,host_summaries.values):
    name=host_requested if isinstance(key,ast.Name) and key.id=="HOST_REQUESTED" else ast.literal_eval(key)
    summary=ast.literal_eval(value)
    assert type(name) is str and type(summary) is str
    summaries[name]=summary
x_saved=ast.literal_eval(assignments["_X_CONFIGURATION_SAVED"])
assert x_saved=="operator_catalog.x_oauth.configuration_saved"
x_entries=[n for n in tree.body if isinstance(n,ast.Assign) and len(n.targets)==1 and isinstance(n.targets[0],ast.Subscript)
    and isinstance(n.targets[0].value,ast.Name) and n.targets[0].value.id=="_SUMMARIES"
    and isinstance(n.targets[0].slice,ast.Name) and n.targets[0].slice.id=="_X_CONFIGURATION_SAVED"]
assert len(x_entries)==1 and type(ast.literal_eval(x_entries[0].value)) is str
summaries[x_saved]=ast.literal_eval(x_entries[0].value)
catalog=ast.literal_eval(assignments["_CATALOG"])
native=ast.literal_eval(assignments["NATIVE_EVENT_TYPES"])
known={"_SUMMARIES":[*summaries,*["operator_catalog."+key for key in catalog]],"NATIVE_EVENT_TYPES":list(native)}
def event_list(node):
    if isinstance(node,ast.Name) and node.id in known: return list(known[node.id])
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in {"tuple","sorted"} and len(node.args)==1 and not node.keywords:
        values=event_list(node.args[0])
        return sorted(values) if node.func.id=="sorted" else values
    if isinstance(node,(ast.Tuple,ast.List)):
        values=[]
        for item in node.elts:
            if isinstance(item,ast.Constant) and type(item.value) is str: values.append(item.value)
            elif isinstance(item,ast.Name) and item.id=="HOST_REQUESTED": values.append(host_requested)
            elif isinstance(item,ast.Starred): values.extend(event_list(item.value))
            else: raise ValueError("unsupported event enum expression")
        return values
    raise ValueError("unsupported event enum expression")
result={"action_required":event_list(assignments["ACTION_EVENT_TYPES"]),"audit_log":event_list(assignments["AUDIT_EVENT_TYPES"])}
assert all(len(values)<=(77 if channel=="audit_log" else 64) and len(values)==len(set(values)) for channel,values in result.items())
print(json.dumps(result))`],
{cwd: ROOT, timeout: 5000, maxBuffer: 65536, encoding: 'utf8'})); // AST only: no application/config/database import.
const INPUTS = ['scripts/test_operator_notifications_browser.cjs', 'scripts/test_operator_catalog_browser.cjs',
  'serverware/operator_demo_portal.py', 'serverware/operator_notification_api.py', 'serverware/operator_notifications.py',
  'serverware/operator_notification_store.py', 'serverware/operator_notification_events.py'];
let artifacts;
let suiteRunning = false;

function slot(name, changes = {}) {
  const [channel, adapter] = name.split('.');
  return {slot: name, channel, adapter, revision: 1, label: name + ' destination', enabled: true,
    secret_present: true, event_types: [EVENTS[channel][0]], max_attempts: 1, last_delivery: null, ...changes};
}
function delivery(changes = {}) {
  return {delivery_id: '77777777-7777-4777-8777-777777777777', status: 'queued', attempts: 0, code: null,
    http_status: null, created_at_epoch_ms: NOW, updated_at_epoch_ms: NOW, ...changes};
}
function status(changes = {}) {
  return {schema: 'serverware.operatorNotifications/v1', available: true, slots: SLOTS.map(name => slot(name)),
    queue: Object.fromEntries(STATES.map(state => [state, 0])), cursor: null,
    backlog: {pending_source_events: 0, queue_capacity: 256, retained_capacity: 10000},
    capabilities: {audit_log: {source_available: true, event_types: [...EVENTS.audit_log]},
      action_required: {source_available: false, event_types: [...EVENTS.action_required]},
      native_hardware: {configured: false, source_available: false, observation_only: true, last_observation: {
        state: 'not_configured', observed_at_epoch_ms: null, phase: null, action_available: false,
        source_expires_at_unix_nanos: null, review_url: null}},
      source_note: 'Native source availability describes the last observer read, not live hardware readiness.',
      test_note: 'A synthetic delivery test does not establish hardware readiness or approval.'},
    worker: {state: 'running', last_cycle_at_epoch_ms: NOW, last_code: 'ready'}, ...changes};
}
function operation(body, kind, changes = {}) {
  return {schema: 'serverware.operatorNotificationOperation/v1', operation_id: body.operation_id, kind,
    slot: body.slot, revision: body.expected_revision + (kind === 'save' ? 1 : 0), status: kind === 'save' ? 'saved' : 'queued',
    delivery_id: kind === 'test' ? delivery().delivery_id : null, slot_state: null, ...changes};
}
async function fixture(browser, options, exercise) {
  const observed = {snapshot: status(options.status), posts: [], reads: [], operations: new Map(),
    nextFault: null, readFault: null, statusFault: null, receiptTransform: null, statusTransform: null};
  const notificationHandler = async ({route, request, path, body, state, answer}) => {
    if (request.method() === 'GET') {
      observed.reads.push(path);
      if (path === PATH) {
        if (observed.statusFault) {
          state.expectedFailures.add(path);
          return answer(route, {detail: PRIVATE[2]}, observed.statusFault);
        }
        const result = clone(observed.snapshot);
        return answer(route, observed.statusTransform ? observed.statusTransform(result) : result);
      }
      assert(path.startsWith(PATH + '/operations/') && UUID.test(path.slice((PATH + '/operations/').length)));
      const receipt = observed.operations.get(path.slice((PATH + '/operations/').length));
      if (observed.readFault || !receipt) {
        state.expectedFailures.add(path);
        return answer(route, {detail: PRIVATE[2]}, observed.readFault || 404);
      }
      return answer(route, observed.receiptTransform ? observed.receiptTransform(clone(receipt)) : clone(receipt));
    }
    assert.equal(request.method(), 'POST'); assert(body && typeof body === 'object' && !Array.isArray(body));
    assert(UUID.test(body.operation_id)); assert(SLOTS.includes(body.slot));
    assert(Number.isSafeInteger(body.expected_revision) && body.expected_revision >= 0 && body.expected_revision <= 1024);
    const retained = await request.frame().evaluate(key => JSON.parse(sessionStorage.getItem(key)), STORAGE);
    assert.deepEqual(retained, {operation_id: body.operation_id,
      kind: path === PATH + '/settings' ? 'save' : 'test', slot: body.slot, expected_revision: body.expected_revision},
    'the closed public recovery reference is persisted before the single POST');
    assert(!observed.posts.some(item => item.body.operation_id === body.operation_id), 'no automatic POST replay of an operation UUID');
    const target = observed.snapshot.slots.find(item => item.slot === body.slot); assert(target);
    assert.equal(body.expected_revision, target.revision, 'exact saved slot CAS, independent of catalog revision');
    const kind = path === PATH + '/settings' ? 'save' : 'test';
    if (kind === 'save') {
      assert.deepEqual(Object.keys(body).sort(), ['operation_id', 'slot', 'expected_revision', 'label', 'enabled',
        'event_types', 'max_attempts', 'url_action', ...(body.url_action === 'replace' ? ['url'] : [])].sort());
      assert.equal(typeof body.label, 'string'); assert(body.label.length >= 1 && body.label.length <= 80 && body.label.trim() === body.label);
      assert.equal(typeof body.enabled, 'boolean'); assert(['keep', 'replace', 'clear'].includes(body.url_action));
      assert(!body.enabled || body.event_types.length > 0, 'enabled-empty drafts must stop before POST');
      assert(Number.isInteger(body.max_attempts) && body.max_attempts >= 1 && body.max_attempts <= 3);
      assert.deepEqual(body.event_types, [...new Set(body.event_types)].sort());
      assert(body.event_types.every(value => EVENTS[target.channel].includes(value)));
      if (body.url_action === 'replace') assert(PRIVATE.slice(0, 2).includes(body.url), 'only synthetic fixture destinations accepted');
      if (body.url_action === 'clear') assert.equal(body.enabled, false);
      if (body.url_action === 'keep') assert.equal(target.secret_present, true);
    } else {
      assert.equal(path, PATH + '/test'); assert(body.expected_revision > 0);
      assert.deepEqual(Object.keys(body).sort(), ['operation_id', 'slot', 'expected_revision'].sort());
      assert.equal(target.enabled, true); assert.equal(target.secret_present, true);
    }
    observed.posts.push({path, kind, body: clone(body)});
    const fault = observed.nextFault; observed.nextFault = null;
    if (fault && fault !== 'lost-after-commit' && fault !== 'malformed-after-commit') {
      state.expectedFailures.add(path);
      if (fault.raw !== undefined) return route.fulfill({status: fault.status, contentType: fault.contentType || 'application/json', body: fault.raw});
      const detail = fault.detail || (fault.status === 422 ? 'invalid notification input' : PRIVATE[2]);
      return answer(route, fault.payload || {detail, ...(fault.code ? {code: fault.code} : {})}, fault.status || 503);
    }
    if (kind === 'save') Object.assign(target, {revision: target.revision + 1, label: body.label, enabled: body.enabled,
      secret_present: body.url_action === 'replace' || body.url_action === 'keep' && target.secret_present,
      event_types: [...body.event_types], max_attempts: body.max_attempts, last_delivery: null});
    else { target.last_delivery = delivery(); observed.snapshot.queue.queued++; }
    const receipt = operation(body, kind, {slot_state: kind === 'save' ? clone(target) : null});
    observed.operations.set(body.operation_id, clone(receipt));
    if (fault === 'lost-after-commit') { state.expectedFailures.add(path); return route.abort('failed'); }
    if (fault === 'malformed-after-commit') return answer(route, {...receipt, slot: 'invalid.slot'}, kind === 'test' ? 202 : 200);
    return answer(route, observed.receiptTransform ? observed.receiptTransform(clone(receipt)) : receipt, kind === 'test' ? 202 : 200);
  };
  return baseFixture(browser, {credentials: [credential()], applications: [application()], rules: [rule()], notificationHandler},
    async (page, state, controls) => {
      const resources = JSON.stringify([state.credentials, state.applications, state.rules, state.revision, state.sequence, state.active]);
      await exercise(page, observed, state, controls);
      assert.equal(JSON.stringify([state.credentials, state.applications, state.rules, state.revision, state.sequence, state.active]), resources,
        'notification UI never mutates credentials, application tokens, permissions or proxy policy');
      assert.equal(state.posts.length, observed.posts.length);
      assert(state.posts.every(item => ['notifications/settings', 'notifications/test'].includes(item.name)));
      assert(state.requests.every(item => !/oauth|ca\.pem|\/echo/.test(item.path)));
    });
}
async function hashes() {
  const frontend = (await readdir(join(ROOT, 'serverware/operator_demo_web'), {recursive: true}))
    .filter(name => /\.(?:html|js|css)$/.test(name)).map(name => 'serverware/operator_demo_web/' + name);
  const inputs = [...INPUTS, ...frontend].sort();
  return Object.fromEntries(await Promise.all(inputs.map(async name =>
    [name, createHash('sha256').update(await readFile(join(ROOT, name))).digest('hex')])));
}
async function clean(page) {
  const surfaces = await page.evaluate(() => ({html: document.documentElement.outerHTML,
    fields: [...document.querySelectorAll('input,textarea')].map(item => item.value),
    local: Object.entries(localStorage), session: Object.entries(sessionStorage)}));
  for (const secret of PRIVATE) assert(!JSON.stringify(surfaces).includes(secret), 'destination URL/raw error never retained in visible DOM, fields or storage');
  assert.deepEqual(surfaces.local, []);
  const references = withoutMutationReview(surfaces.session);
  assert(references.every(([key]) => key === STORAGE), 'only exact public operation recovery metadata or shared review marker may persist');
  for (const [, value] of references) {
    const ref = JSON.parse(value);
    assert.deepEqual(Object.keys(ref).sort(), ['operation_id', 'kind', 'slot', 'expected_revision'].sort());
    assert(UUID.test(ref.operation_id) && ['save', 'test'].includes(ref.kind) && SLOTS.includes(ref.slot));
    assert(Number.isSafeInteger(ref.expected_revision) && ref.expected_revision >= 0 && ref.expected_revision <= 1024);
  }
}
async function screenshot(page, name) {
  await clean(page); await page.screenshot({path: join(artifacts, name + '.png'), fullPage: true});
}
const form = (page, name = 'audit_log.webhook') => page.locator('form[data-notification-slot="' + name + '"]');
async function settled(page) {
  await page.waitForLoadState('networkidle');
  await page.waitForFunction(() => !document.getElementById('notifications-refresh').disabled);
}
async function open(page) {
  await ready(page); await view(page, 'notifications'); await settled(page);
  assert.equal(await page.locator('form[data-notification-slot]').count(), 4);
}
async function submit(page, target = form(page), kind = 'save') {
  await target.locator('[data-notification-' + kind + ']').click(); await settled(page); await clean(page);
}
async function checkOperation(page) {
  await page.locator('#notification-check-operation').click(); await settled(page); await clean(page);
}
async function recovery(page) {
  const value = await page.evaluate(key => sessionStorage.getItem(key), STORAGE);
  if (value === null) return null;
  const result = JSON.parse(value);
  assert.deepEqual(Object.keys(result).sort(), ['operation_id', 'kind', 'slot', 'expected_revision'].sort());
  assert(UUID.test(result.operation_id)); assert(['save', 'test'].includes(result.kind)); assert(SLOTS.includes(result.slot));
  assert(Number.isSafeInteger(result.expected_revision)); return result;
}
async function writesDisabled(page) {
  const buttons = page.locator('[data-notification-save],[data-notification-test]');
  assert.equal(await buttons.count(), 8);
  for (const button of await buttons.all()) assert(await button.isDisabled());
}
async function savedRevision(page, name, revision) {
  assert.match(await form(page, name).locator('[data-slot-revision]').innerText(), new RegExp('(?:^|\\D)' + revision + '(?:$|\\D)'));
}

const tests = [
  ['Notifications is lazy and feature-off accepts four default slots but exposes no forms or actions', browser => fixture(browser,
    {status: status({available: false, disabled_reason: 'deployment_disabled',
      slots: SLOTS.map(name => slot(name, {revision: 0, label: '', enabled: false, secret_present: false, event_types: []})),
      capabilities: {...status().capabilities, audit_log: {source_available: false, event_types: [...EVENTS.audit_log]}},
      worker: {state: 'disabled', last_cycle_at_epoch_ms: null, last_code: null}})}, async (page, observed, state) => {
      await ready(page); assert.deepEqual(observed.reads, []); await view(page, 'notifications'); await settled(page);
      assert.equal(observed.reads.length, 1);
      assert.equal(await page.locator('form[data-notification-slot],[data-notification-save],[data-notification-test]').count(), 0);
      assert.match(await page.locator('#notifications-status').innerText(), /disabled|unavailable|not enabled/i);
      assert.match(await page.locator('#notifications-worker').innerText(), /disabled/i);
      assert.equal(observed.snapshot.slots.length, 4); assert(observed.snapshot.slots.every(item => item.revision === 0));
      assert.equal(observed.posts.length, 0); assert.equal(state.posts.length, 0);
      await screenshot(page, 'notifications-deployment-disabled');
    })],
  ['four independent destinations separate action and audit source availability honestly', browser => fixture(browser, {},
    async (page, observed) => {
      await open(page);
      assert.equal(await page.locator('[data-notification-channel="action_required"]').count(), 1);
      assert.equal(await page.locator('[data-notification-channel="audit_log"]').count(), 1);
      assert.match(await page.locator('#notifications').innerText(), /not connected|not available|unavailable/i);
      assert.match(await page.locator('#notifications').innerText(), /synthetic.*(?:not|does not).*(?:hardware|approval)/is);
      for (const name of SLOTS) {
        const target = form(page, name); const stored = observed.snapshot.slots.find(item => item.slot === name);
        assert.equal(await target.locator('[name="label"]').inputValue(), stored.label);
        assert.equal(await target.locator('[name="url"]').getAttribute('type'), 'password');
        assert.equal(await target.locator('[name="url"]').inputValue(), '');
        assert.equal(await target.locator('[name="enabled"]').isChecked(), true);
        assert.equal(await target.locator('[name="event_types"]').count(), EVENTS[stored.channel].length);
        await savedRevision(page, name, 1);
      }
      await form(page).locator('[name="label"]').fill('An unsaved label in one slot');
      await form(page).locator('[name="max_attempts"]').selectOption('3');
      for (const name of SLOTS.filter(name => name !== 'audit_log.webhook')) {
        assert.equal(await form(page, name).locator('[name="label"]').inputValue(), name + ' destination');
        assert.equal(await form(page, name).locator('[name="max_attempts"]').inputValue(), '1');
      }
      assert.equal(observed.posts.length, 0); await screenshot(page, 'four-independent-notification-slots');
    })],
  ['new destinations stay muted and empty until an explicit slot-local draft choice', browser => fixture(browser,
    {status: {slots: SLOTS.map(name => slot(name, {revision: 0, label: '', enabled: false, secret_present: false, event_types: []}))}},
    async (page, observed) => {
      await open(page); const before = clone(observed.snapshot.slots);
      for (const name of SLOTS) {
        const target = form(page, name);
        assert.equal(await target.locator('[name="event_types"]:checked').count(), 0);
        assert.equal(await target.locator('[name="enabled"]').isChecked(), false);
        assert.equal(await target.locator('details').getAttribute('open'), null);
        assert(await target.locator('[data-notification-events-status]').isVisible());
        assert.match(await target.locator('[data-notification-events-status]').innerText(), /Disabled; no source events selected/);
        assert(await target.locator('[data-notification-test]').isDisabled());
        assert.equal(await target.locator('[data-notification-preset]').count(), name.startsWith('audit_log.') ? 3 : 0);
      }
      const target = form(page);
      await target.locator('[data-notification-preset="proxy_blocks"]').click();
      assert.deepEqual(await target.locator('[name="event_types"]:checked').evaluateAll(nodes => nodes.map(node => node.value)), AUDIT_PRESETS.proxy_blocks);
      assert.equal(await target.locator('[name="enabled"]').isChecked(), false);
      assert.deepEqual(observed.snapshot.slots, before); assert.equal(observed.posts.length, 0); assert.equal(await recovery(page), null);
      await page.locator('#notifications-refresh').click(); await settled(page);
      assert.equal(await form(page).locator('[name="event_types"]:checked').count(), 0, 'refresh reads saved filters, not the unsubmitted preset');
      assert.equal(observed.posts.length, 0);
    })],
  ['saved enabled-empty destinations warn outside collapsed details and cannot save, but synthetic test stays separate', browser => fixture(browser,
    {status: {slots: SLOTS.map(name => slot(name, {event_types: []}))}}, async (page, observed) => {
      await open(page); const before = clone(observed.snapshot.slots);
      for (const name of SLOTS) {
        const target = form(page, name);
        assert.equal(await target.locator('details').getAttribute('open'), null);
        assert(await target.locator('[data-notification-events-status]').isVisible());
        assert.match(await target.locator('[data-slot-status]').innerText(), /Enabled, but no source events are selected/);
        assert.match(await target.locator('[data-notification-events-status]').innerText(), /No source events selected in this draft.*Empty saved filters deliver no source events/s);
        assert(await target.locator('[data-notification-save]').isDisabled());
        assert(await target.locator('[data-notification-test]').isEnabled());
        await target.evaluate(node => node.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true})));
      }
      assert.equal(observed.posts.length, 0); assert.equal(await recovery(page), null); assert.deepEqual(observed.snapshot.slots, before);
      assert.match(await page.locator('#notifications-status').innerText(), /Select at least one event or disable.*Nothing was submitted/s);
      await submit(page, form(page), 'test');
      assert.equal(observed.posts.length, 1); assert.equal(observed.posts[0].kind, 'test');
      assert(observed.snapshot.slots.every(item => item.event_types.length === 0));
      await screenshot(page, 'enabled-empty-notification-warning');
    })],
  ['muted empty settings can be saved but enabling requires an explicit nonempty filter', browser => fixture(browser,
    {status: {slots: SLOTS.map(name => slot(name, {enabled: false, event_types: []}))}}, async (page, observed) => {
      await open(page); const others = clone(observed.snapshot.slots.slice(0, 3)); let target = form(page);
      assert(await target.locator('[data-notification-save]').isEnabled());
      assert(await target.locator('[data-notification-test]').isDisabled());
      await target.locator('[name="label"]').fill('Muted audit destination'); await submit(page, target);
      assert.equal(observed.posts.length, 1); assert.equal(observed.posts[0].kind, 'save');
      assert.equal(observed.posts[0].body.enabled, false); assert.deepEqual(observed.posts[0].body.event_types, []);
      target = form(page); await target.locator('[name="enabled"]').check();
      assert(await target.locator('[data-notification-save]').isDisabled());
      await target.evaluate(node => node.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true})));
      assert.equal(observed.posts.length, 1);
      await target.locator('details summary').click();
      await target.locator('[name="event_types"][value="data_plane.request.denied"]').check();
      assert(await target.locator('[data-notification-save]').isEnabled());
      assert(await target.locator('[data-notification-test]').isDisabled());
      await submit(page, target);
      assert.equal(observed.posts.length, 2); assert(observed.posts.every(item => item.kind === 'save'));
      assert.equal(observed.posts[1].body.enabled, true); assert.deepEqual(observed.posts[1].body.event_types, ['data_plane.request.denied']);
      assert.deepEqual(observed.snapshot.slots.slice(0, 3), others); assert.equal(observed.snapshot.queue.queued, 0);
    })],
  ['explicit audit presets add exact supported filters only to the selected draft until Save', browser => fixture(browser,
    {status: {slots: SLOTS.map(name => slot(name, name.startsWith('audit_log.') ?
      {enabled: false, event_types: ['credential.oauth_refresh_failed']} : {}))}}, async (page, observed) => {
      await open(page); const before = clone(observed.snapshot.slots); const target = form(page); let selected = ['credential.oauth_refresh_failed'];
      const reads = observed.reads.length;
      for (const [id, types] of Object.entries(AUDIT_PRESETS)) {
        assert(types.every(type => EVENTS.audit_log.includes(type)), 'independent preset oracle agrees with actual advertised event contract');
        await target.locator('[data-notification-preset="' + id + '"]').click();
        selected = [...new Set([...selected, ...types])].sort();
        assert.deepEqual(await target.locator('[name="event_types"]:checked').evaluateAll(nodes => nodes.map(node => node.value)), selected);
        assert.equal(await target.locator('[name="enabled"]').isChecked(), false);
        assert.deepEqual(observed.snapshot.slots, before); assert.equal(observed.posts.length, 0);
        assert.equal(observed.reads.length, reads); assert.equal(await recovery(page), null);
        for (const name of SLOTS.filter(item => item !== 'audit_log.webhook')) {
          assert.deepEqual(await form(page, name).locator('[name="event_types"]:checked').evaluateAll(nodes => nodes.map(node => node.value)),
            before.find(item => item.slot === name).event_types);
        }
      }
      await target.locator('[data-notification-preset="proxy_blocks"]').click();
      assert.deepEqual(await target.locator('[name="event_types"]:checked').evaluateAll(nodes => nodes.map(node => node.value)), selected);
      await submit(page, target);
      assert.equal(observed.posts.length, 1); assert.equal(observed.posts[0].kind, 'save');
      assert.deepEqual(observed.posts[0].body.event_types, selected); assert.equal(observed.posts[0].body.enabled, false);
      assert.equal(observed.snapshot.queue.queued, 0); assert.deepEqual(observed.snapshot.slots.slice(0, 3), before.slice(0, 3));
    })],
  ['unavailable audit presets stay disabled and partial capability lists never select unadvertised events', browser => fixture(browser,
    {status: {capabilities: {...status().capabilities, audit_log: {source_available: true,
      event_types: ['approval.requested', 'data_plane.connect.denied']}},
      slots: SLOTS.map(name => slot(name, name.startsWith('audit_log.') ? {event_types: ['approval.requested']} : {}))}},
    async (page, observed) => {
      await open(page); const target = form(page); const before = clone(observed.snapshot.slots);
      assert(await target.locator('[data-notification-preset="access_changes"]').isDisabled());
      await target.locator('[data-notification-preset="access_changes"]').evaluate(node => node.dispatchEvent(new Event('click', {bubbles: true})));
      assert.equal(await target.locator('[name="event_types"]:checked').count(), 1);
      await target.locator('[data-notification-preset="proxy_blocks"]').click();
      await target.locator('[data-notification-preset="approval_history"]').click();
      assert.deepEqual(await target.locator('[name="event_types"]:checked').evaluateAll(nodes => nodes.map(node => node.value)),
        ['approval.requested', 'data_plane.connect.denied']);
      assert.equal(observed.posts.length, 0); assert.equal(await recovery(page), null); assert.deepEqual(observed.snapshot.slots, before);
      assert.equal(await form(page, 'action_required.webhook').locator('[data-notification-preset]').count(), 0);
    })],
  ['77 available audit types preserve saved filters and enforce a 64-selection limit', browser => fixture(browser, {},
    async (page, observed) => {
      await open(page); const target = form(page); const before = clone(observed.snapshot.slots);
      assert.equal(await target.locator('[name="event_types"]').count(), 77);
      assert.equal(await target.locator('[name="event_types"]:checked').count(), 1);
      await target.locator('details').locator('summary').click();
      for (const checkbox of await target.locator('[name="event_types"]').all()) await checkbox.check();
      assert.match(await target.locator('[data-notification-events-summary]').innerText(), /77\/64 selected/);
      assert(await target.locator('[data-notification-save]').isDisabled());
      // Bypassing a disabled submit button still hits the same bounded guard.
      await target.evaluate(node => node.dispatchEvent(new Event('submit', {bubbles: true, cancelable: true})));
      assert.equal(observed.posts.length, 0); assert.equal(await recovery(page), null);
      assert.deepEqual(observed.snapshot.slots, before);
      for (const checkbox of (await target.locator('[name="event_types"]').all()).slice(0, 12)) await checkbox.uncheck();
      assert.match(await target.locator('[data-notification-events-summary]').innerText(), /65\/64 selected/);
      assert(await target.locator('[data-notification-save]').isDisabled());
      for (const button of await target.locator('[data-notification-preset]').all()) assert(await button.isDisabled());
      const overLimit = await target.locator('[name="event_types"]:checked').evaluateAll(nodes => nodes.map(node => node.value));
      await target.locator('[data-notification-preset="proxy_blocks"]').evaluate(node => node.dispatchEvent(new Event('click', {bubbles: true})));
      assert.deepEqual(await target.locator('[name="event_types"]:checked').evaluateAll(nodes => nodes.map(node => node.value)), overLimit);
      assert.equal(observed.posts.length, 0);
      await target.locator('[name="event_types"]').nth(12).uncheck();
      assert(await target.locator('[data-notification-save]').isEnabled());
      await submit(page, target); assert.equal(observed.posts.length, 1);
      assert.equal(observed.posts[0].body.event_types.length, 64);
      assert(observed.posts[0].body.event_types.includes('operator_catalog.access_rule.npm_install_created'));
      assert(observed.posts[0].body.event_types.includes('operator_catalog.credential.github_app_created'));
      assert(observed.posts[0].body.event_types.includes('operator_catalog.credential.github_app_key_replaced'));
      assert(observed.posts[0].body.event_types.includes('operator_catalog.x_oauth.configuration_saved'));
    })],
  ['explicit saves use each slot revision and leave all other destinations and application resources unchanged', browser => fixture(browser, {},
    async (page, observed) => {
      await open(page);
      for (const name of SLOTS) {
        const others = clone(observed.snapshot.slots.filter(item => item.slot !== name)); const target = form(page, name);
        await target.locator('[name="label"]').fill('Saved ' + name);
        await target.locator('[name="url_action"]').selectOption('keep');
        await target.locator('[name="max_attempts"]').selectOption('2');
        await submit(page, target);
        const post = observed.posts.at(-1); assert.equal(post.kind, 'save'); assert.equal(post.body.slot, name);
        assert.equal(post.body.expected_revision, 1); assert.equal(post.body.max_attempts, 2); assert(!Object.hasOwn(post.body, 'url'));
        assert.deepEqual(observed.snapshot.slots.filter(item => item.slot !== name), others);
        await savedRevision(page, name, 2);
      }
      assert.equal(observed.posts.length, 4); assert(observed.posts.every(item => item.kind === 'save'));
      assert.equal(observed.snapshot.queue.queued, 0, 'save never queues a test');
      await clean(page);
    })],
  ['replace, keep and clear are explicit and never retrieve or retain the destination URL', browser => fixture(browser, {},
    async (page, observed) => {
      await open(page); const target = form(page);
      await target.locator('[name="url_action"]').selectOption('replace'); await target.locator('[name="url"]').fill(PRIVATE[0]);
      await submit(page, target); assert.equal(observed.posts[0].body.url, PRIVATE[0]);
      await savedRevision(page, 'audit_log.webhook', 2); assert.equal(await target.locator('[name="url"]').inputValue(), '');
      await target.locator('[name="url_action"]').selectOption('keep'); await submit(page, target);
      assert(!Object.hasOwn(observed.posts[1].body, 'url')); assert.equal(observed.posts[1].body.expected_revision, 2);
      await target.locator('[name="url_action"]').selectOption('clear'); await target.locator('[name="enabled"]').uncheck();
      await submit(page, target); assert.equal(observed.posts[2].body.url_action, 'clear');
      assert(!Object.hasOwn(observed.posts[2].body, 'url')); assert.equal(observed.posts[2].body.enabled, false);
      assert.equal(observed.snapshot.slots.find(item => item.slot === 'audit_log.webhook').secret_present, false);
      await savedRevision(page, 'audit_log.webhook', 4); assert(await target.locator('[data-notification-test]').isDisabled());
      assert.equal(observed.posts.length, 3); await screenshot(page, 'cleared-notification-destination');
    })],
  ['test is explicit, uses only saved slot revision and does not imply delivery or hardware approval', browser => fixture(browser, {},
    async (page, observed) => {
      await open(page);
      await form(page).locator('[name="label"]').fill('An unsaved destination label');
      assert(await form(page).locator('[data-notification-test]').isDisabled());
      await form(page).locator('[name="url_action"]').selectOption('replace'); await form(page).locator('[name="url"]').fill(PRIVATE[0]);
      assert(await form(page).locator('[data-notification-test]').isDisabled());
      await page.locator('#notifications-refresh').click(); await settled(page); await clean(page);
      assert.equal(observed.posts.length, 0); await submit(page, form(page), 'test');
      assert.equal(observed.posts.length, 1); const post = observed.posts[0];
      assert.equal(post.kind, 'test'); assert.equal(post.body.expected_revision, 1);
      assert.deepEqual(Object.keys(post.body).sort(), ['operation_id', 'slot', 'expected_revision'].sort());
      assert(observed.snapshot.slots.every(item => item.revision === 1));
      assert.match(await page.locator('#notification-operation-status').innerText(), /queued|pending/i);
      const ref = await recovery(page); assert.equal(ref.operation_id, post.body.operation_id); assert.equal(ref.kind, 'test');
      observed.operations.get(ref.operation_id).status = 'acknowledged';
      observed.snapshot.slots.find(item => item.slot === ref.slot).last_delivery = delivery({status: 'acknowledged', attempts: 1,
        code: 'acknowledged', http_status: 200});
      observed.snapshot.queue.queued = 0; observed.snapshot.queue.acknowledged = 1;
      await checkOperation(page);
      assert.match(await page.locator('#notification-operation-status').innerText(), /acknowledged/i);
      assert.match(await page.locator('#notifications').innerText(), /not.*(?:approval|hardware)|does not.*(?:approval|hardware)/is);
      assert.equal(observed.posts.length, 1); await screenshot(page, 'synthetic-test-receipt-not-approval');
    })],
  ['unsaved and disabled destinations cannot send a saved-destination test', browser => fixture(browser,
    {status: {slots: SLOTS.map((name, index) => slot(name, index < 2 ?
      {revision: 0, label: '', enabled: false, secret_present: false, event_types: []} : {enabled: false}))}},
    async (page, observed) => {
      await open(page);
      for (const name of SLOTS) assert(await form(page, name).locator('[data-notification-test]').isDisabled());
      assert.equal(observed.posts.length, 0); await clean(page);
    })],
  ['lost save, receipt 404 and reload retain exact public recovery identity without replay or secret persistence', browser => fixture(browser, {},
    async (page, observed) => {
      await open(page); const target = form(page);
      observed.nextFault = 'lost-after-commit'; observed.readFault = 404;
      await target.locator('[name="url_action"]').selectOption('replace'); await target.locator('[name="url"]').fill(PRIVATE[0]);
      await submit(page, target); await writesDisabled(page);
      const reference = await recovery(page); assert(reference); assert.equal(reference.expected_revision, 1);
      assert.equal(observed.posts.length, 1); assert.equal(observed.snapshot.slots.find(item => item.slot === reference.slot).revision, 2);
      await checkOperation(page); assert.deepEqual(await recovery(page), reference); await writesDisabled(page);
      await screenshot(page, 'lost-save-404-held-no-replay');
      await page.reload({waitUntil: 'networkidle'}); await open(page); await writesDisabled(page);
      assert.deepEqual(await recovery(page), reference); assert.equal(observed.posts.length, 1); await clean(page);
      await checkOperation(page); assert.deepEqual(await recovery(page), reference); await writesDisabled(page);
      observed.readFault = null; await checkOperation(page);
      assert(await form(page).locator('[data-notification-save]').isEnabled());
      await savedRevision(page, reference.slot, 2); assert.equal(observed.posts.length, 1);
      assert(observed.reads.filter(path => path.includes('/operations/')).every(path => path === PATH + '/operations/' + reference.operation_id));
      assert.deepEqual(await recovery(page), reference, 'known receipt remains available for explicit inspection');
    })],
  ['lost explicit test is inspected by GET and unknown delivery is never automatically re-sent', browser => fixture(browser, {},
    async (page, observed) => {
      await open(page); observed.nextFault = 'lost-after-commit'; await submit(page, form(page), 'test');
      await writesDisabled(page); const reference = await recovery(page); assert.equal(reference.kind, 'test');
      observed.operations.get(reference.operation_id).status = 'outcome_unknown';
      observed.snapshot.slots.find(item => item.slot === reference.slot).last_delivery = delivery({status: 'outcome_unknown', attempts: 1,
        code: 'delivery_unknown'});
      observed.snapshot.queue.queued = 0; observed.snapshot.queue.outcome_unknown = 1;
      await checkOperation(page);
      assert.match(await page.locator('#notification-operation-status').innerText(), /unknown|uncertain/i);
      await page.locator('#notifications-refresh').click(); await settled(page);
      assert.equal(observed.posts.length, 1); assert.equal(observed.snapshot.queue.outcome_unknown, 1); await clean(page);
    })],
  ['422 and exact revision/capacity conflicts are definite refusals without implicit retry', async browser => {
    for (const fault of [{status: 422}, {status: 422, detail: 'invalid operator catalog input'}, {status: 409, code: 'notification_revision_conflict'},
      {status: 409, code: 'notification_capacity_conflict'}]) await fixture(browser, {}, async (page, observed) => {
      await open(page); observed.nextFault = fault; await submit(page);
      assert.equal(await recovery(page), null); assert.equal(observed.posts.length, 1);
      assert(observed.snapshot.slots.every(item => item.revision === 1));
      await page.locator('#notifications-refresh').click(); await settled(page);
      assert.equal(observed.posts.length, 1); assert(await form(page).locator('[data-notification-save]').isEnabled()); await clean(page);
    });
  }],
  ['ambiguous conflicts, 503 and malformed 422 retain uncertainty after fresh status and receipt 404', async browser => {
    for (const fault of [{status: 409, code: 'notification_operation_conflict'}, {status: 409, code: 'notification_conflict'},
      {status: 409, code: 'unknown_conflict'}, {status: 503}, {status: 422, detail: PRIVATE[2]},
      {status: 422, payload: {}}, {status: 422, raw: '{not-json'},
      {status: 422, raw: PRIVATE[2], contentType: 'text/plain'}]) await fixture(browser, {}, async (page, observed) => {
      await open(page); observed.nextFault = fault; await submit(page); await writesDisabled(page);
      const reference = await recovery(page); assert(reference);
      await page.locator('#notifications-refresh').click(); await settled(page); await writesDisabled(page);
      await checkOperation(page); await writesDisabled(page);
      assert.deepEqual(await recovery(page), reference); assert.equal(observed.posts.length, 1); await clean(page);
    });
  }],
  ['malformed positive receipts hold the exact operation until a matching public GET receipt is reviewed', async browser => {
    for (const transform of [value => ({...value, slot: 'invalid.slot'}),
      value => ({...value, operation_id: '99999999-9999-4999-8999-999999999999'}),
      value => ({...value, revision: value.revision + 1}), value => ({...value, url: PRIVATE[0]})])
      await fixture(browser, {}, async (page, observed) => {
        await open(page); observed.receiptTransform = transform; await submit(page); await writesDisabled(page);
        const reference = await recovery(page); assert(reference); assert.equal(observed.posts.length, 1);
        observed.receiptTransform = null; await checkOperation(page);
        assert(await form(page).locator('[data-notification-save]').isEnabled()); assert.equal(observed.posts.length, 1); await clean(page);
      });
  }],
  ['malformed or unavailable status never enables writes or exposes raw response fields', async browser => {
    for (const transform of [value => ({...value, slots: value.slots.slice(1)}),
      value => ({...value, slots: [value.slots[0], value.slots[0], ...value.slots.slice(2)]}),
      value => ({...value, slots: value.slots.map((item, index) => index === 0 ? {...item, secret_present: 'yes'} : item)}),
      value => ({...value, url: PRIVATE[0]})]) await fixture(browser, {}, async (page, observed) => {
      observed.statusTransform = transform; await ready(page); await view(page, 'notifications'); await settled(page);
      for (const button of await page.locator('[data-notification-save],[data-notification-test]').all()) assert(await button.isDisabled());
      assert.match(await page.locator('#notifications-status').innerText(), /unavailable|invalid|could not|cannot|failed/i);
      assert.equal(observed.posts.length, 0); await clean(page);
    });
    await fixture(browser, {}, async (page, observed) => {
      observed.statusFault = 503; await ready(page); await view(page, 'notifications'); await settled(page);
      for (const button of await page.locator('[data-notification-save],[data-notification-test]').all()) assert(await button.isDisabled());
      assert.equal(observed.posts.length, 0); await clean(page);
    });
  }],
  ['leaving Notifications clears an unsaved destination without saving or testing it', browser => fixture(browser, {},
    async (page, observed) => {
      await open(page); const target = form(page);
      await target.locator('[name="url_action"]').selectOption('replace'); await target.locator('[name="url"]').fill(PRIVATE[0]);
      await view(page, 'overview'); await clean(page); await open(page);
      assert.equal(await target.locator('[name="url"]').inputValue(), ''); assert.equal(observed.posts.length, 0);
      await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await screenshot(page, 'notifications-mobile-secret-free');
    })],
  ['blocked recovery storage prevents the POST and clears the typed destination', browser => fixture(browser, {},
    async (page, observed) => {
      await open(page);
      await page.evaluate(() => { Storage.prototype.setItem = () => { throw new DOMException('Synthetic storage refusal', 'SecurityError'); }; });
      await form(page).locator('[name="url_action"]').selectOption('replace'); await form(page).locator('[name="url"]').fill(PRIVATE[0]);
      await submit(page); await writesDisabled(page);
      assert.equal(observed.posts.length, 0); assert.equal(await recovery(page), null);
      assert.match(await page.locator('#notification-operation-status').innerText(), /reference.*(?:read|stored)|duplicate/is); await clean(page);
    })],
  ['each action and audit destination renders its own safe failure reason and HTTP status without changing settings', browser => fixture(browser,
    {status: {slots: SLOTS.map((name, index) => slot(name, {last_delivery: delivery([
      {status: 'failed', attempts: 1, code: 'http_rejected', http_status: 403},
      {status: 'failed', attempts: 2, code: 'tls_unavailable'},
      {status: 'failed', attempts: 1, code: 'acknowledgement_invalid', http_status: 200},
      {status: 'outcome_unknown', attempts: 1, code: 'delivery_unknown', http_status: 502}
    ][index])}))}}, async (page, observed) => {
      const before = JSON.stringify(observed.snapshot); await open(page);
      const expected = [
        [/^Delivery failed\./, /Last result: http_rejected\./, /HTTP status: 403\./, /receiver access requirements/],
        [/^Delivery failed\./, /Last result: tls_unavailable\./, /receiver certificate and service trust/],
        [/^Delivery failed\./, /Last result: acknowledgement_invalid\./, /HTTP status: 200\./, /HTTP success alone is not acknowledgement/],
        [/^Delivery outcome unknown\./, /Last result: delivery_unknown\./, /HTTP status: 502\./, /may have received it; no automatic replay/]
      ];
      const codes = ['http_rejected', 'tls_unavailable', 'acknowledgement_invalid', 'delivery_unknown'];
      for (const [index, name] of SLOTS.entries()) {
        const target = form(page, name); const text = await target.locator('[data-notification-delivery]').innerText();
        for (const pattern of expected[index]) assert.match(text, pattern);
        assert.doesNotMatch(text, /Destination acknowledged/);
        for (const [other, code] of codes.entries()) if (index !== other) assert(!text.includes(code), 'details never cross slots');
        assert.equal(await target.locator('[name="label"]').inputValue(), observed.snapshot.slots[index].label);
        assert(await target.locator('[name="enabled"]').isChecked());
        assert.deepEqual(await target.locator('[name="event_types"]:checked').evaluateAll(items => items.map(item => item.value)),
          observed.snapshot.slots[index].event_types);
        assert.equal(await target.locator('[name="url"]').inputValue(), '');
      }
      assert.doesNotMatch(await form(page, SLOTS[1]).locator('[data-notification-delivery]').innerText(), /HTTP status:/);
      assert.equal(EVENTS.audit_log.length, 77); assert.equal(EVENTS.action_required.length, 6);
      assert(EVENTS.audit_log.includes('operator_catalog.access_rule.npm_install_created'));
      assert(EVENTS.audit_log.includes('operator_catalog.credential.github_app_created'));
      assert(EVENTS.audit_log.includes('operator_catalog.x_oauth.configuration_saved'));
      assert.equal(JSON.stringify(observed.snapshot), before); assert.equal(observed.posts.length, 0);
      await screenshot(page, 'notification-slot-failure-details');
    })],
  ['unknown delivery details stay private and GET refresh never replays an uncertain message', browser => fixture(browser,
    {status: {slots: SLOTS.map((name, index) => slot(name, {last_delivery: delivery([
      {status: 'failed', attempts: 1, code: PRIVATE[3], http_status: 503},
      {status: 'outcome_unknown', attempts: 1, code: 'acknowledged', http_status: 200},
      {status: 'failed', attempts: 1},
      {status: 'queued', attempts: 1, code: 'dns_timeout'}
    ][index])}))}}, async (page, observed) => {
      await open(page);
      const first = await form(page, SLOTS[0]).locator('[data-notification-delivery]').innerText();
      assert.match(first, /Delivery detail unavailable\./); assert.match(first, /HTTP status: 503\./); assert(!first.includes(PRIVATE[3]));
      const uncertain = await form(page, SLOTS[1]).locator('[data-notification-delivery]').innerText();
      assert.match(uncertain, /^Delivery outcome unknown\./); assert.match(uncertain, /may have received it; no automatic replay/);
      assert.match(uncertain, /HTTP status: 200\./); assert.doesNotMatch(uncertain, /Destination acknowledged|Last result: acknowledged|explicitly testing again/);
      assert.doesNotMatch(await form(page, SLOTS[2]).locator('[data-notification-delivery]').innerText(), /Last result:|HTTP status:|undefined|null/);
      const queued = await form(page, SLOTS[3]).locator('[data-notification-delivery]').innerText();
      assert.match(queued, /^Delivery queued; not yet acknowledged\./); assert.match(queued, /Last result: dns_timeout\./);
      const settings = observed.snapshot.slots.map(({last_delivery, ...saved}) => clone(saved));
      Object.assign(observed.snapshot.slots[0].last_delivery, {code: 'http_rejected', http_status: 429});
      Object.assign(observed.snapshot.slots[1].last_delivery, {code: 'delivery_unknown', http_status: null});
      const response = page.waitForResponse(item => item.url().endsWith(PATH) && item.request().method() === 'GET');
      await page.locator('#notifications-refresh').click(); await response; await settled(page);
      await page.waitForFunction(() => document.querySelector('[data-notification-slot="action_required.slack"] [data-notification-delivery]')?.textContent.includes('HTTP status: 429.'));
      assert.match(await form(page, SLOTS[0]).locator('[data-notification-delivery]').innerText(), /Last result: http_rejected\./);
      const refreshed = await form(page, SLOTS[1]).locator('[data-notification-delivery]').innerText();
      assert.match(refreshed, /Last result: delivery_unknown\./); assert.match(refreshed, /no automatic replay/);
      assert.doesNotMatch(refreshed, /HTTP status:|Destination acknowledged/);
      assert.deepEqual(observed.snapshot.slots.map(({last_delivery, ...saved}) => saved), settings);
      assert.equal(observed.posts.length, 0); assert.equal(await recovery(page), null); await clean(page);
      await page.setViewportSize({width: 390, height: 844});
      assert(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1));
      await screenshot(page, 'notification-failure-details-mobile');
    })],
  ['backlog and terminal delivery statuses remain distinct from successful action or hardware completion', browser => fixture(browser,
    {status: {backlog: {pending_source_events: 47, queue_capacity: 256, retained_capacity: 10000},
      worker: {state: 'running', last_cycle_at_epoch_ms: NOW, last_code: 'notification_source_backlog'},
      slots: SLOTS.map((name, index) => slot(name, {last_delivery: delivery([
        {status: 'failed', attempts: 1, code: 'connect_unavailable'},
        {status: 'outcome_unknown', attempts: 1, code: 'delivery_unknown'},
        {status: 'suppressed', code: 'configuration_changed'},
        {status: 'expired', code: 'action_expired'}][index])})),
      queue: {...status().queue, queued: 256, failed: 1, outcome_unknown: 1, suppressed: 1, expired: 1}}}, async (page, observed) => {
      await open(page);
      assert.match(await page.locator('#notifications-worker').innerText(), /backlog.*retained|queued.*drained/i);
      assert.match(await page.locator('#notifications-queue').innerText(), /Pending source events: 47/);
      assert.match(await page.locator('#notifications-queue').innerText(), /Queue limit: 256/);
      for (const [index, text] of [/Delivery failed/, /outcome unknown/, /Delivery suppressed/, /Delivery expired/].entries())
        assert.match(await form(page, SLOTS[index]).innerText(), text);
      assert.match(await form(page, SLOTS[3]).innerText(), /deadline.*not.*extended/i);
      assert.equal(observed.posts.length, 0); await screenshot(page, 'notification-backlog-and-distinct-outcomes');
    })],
];

async function runSuite(browser, {fromGroup = 1} = {}) {
  assert(!suiteRunning, 'notification suite is already running');
  assert(browser && typeof browser.newContext === 'function', 'an existing Playwright browser is required');
  assert(tests.length > 0, 'fixture cases must be finalized before execution');
  assert(Number.isInteger(fromGroup) && fromGroup >= 1 && fromGroup <= tests.length, 'valid first group required');
  suiteRunning = true;
  const owned = new Set(); const creating = new Set();
  let stopping = false; let created = 0; let closed = 0; let deadline; let cleanupDeadline;
  let before; let after;
  const scopedBrowser = {async newContext(options) {
    assert(!stopping, 'notification suite has stopped');
    const pending = browser.newContext(options); creating.add(pending);
    let context;
    try { context = await pending; }
    finally { creating.delete(pending); }
    owned.add(context); created++;
    context.once('close', () => { owned.delete(context); closed++; });
    if (stopping) { await context.close(); throw new Error('notification suite stopped during context creation'); }
    return context;
  }};
  try {
    before = await hashes(); console.log(JSON.stringify({phase: 'source-before', hashes: before}));
    artifacts = await mkdtemp('/tmp/serverware-notifications-browser-');
    console.log(JSON.stringify({artifactDirectory: artifacts, scope: 'synthetic notification fixtures; no actual destinations'}));
    try {
      await Promise.race([(async () => {
        for (const [name, run] of tests.slice(fromGroup - 1)) {
          assert(!stopping, 'notification suite has stopped');
          await run(scopedBrowser); console.log('PASS ' + name);
        }
      })(), new Promise((_, reject) => { deadline = setTimeout(() => reject(new Error('notification fixture absolute deadline')), 150000); })]);
    } finally {
      stopping = true; clearTimeout(deadline);
      try {
        await Promise.race([(async () => {
          await Promise.allSettled([...creating]);
          await Promise.allSettled([...owned].map(context => context.close()));
          assert.equal(owned.size, 0, 'all suite-owned contexts must be closed');
          assert.equal(creating.size, 0, 'no suite context creation may remain pending');
          assert.equal(closed, created, 'every suite-created context reported closure');
        })(), new Promise((_, reject) => { cleanupDeadline = setTimeout(() => reject(new Error('notification context cleanup deadline')), 10000); })]);
      } finally {
        clearTimeout(cleanupDeadline);
        console.log(JSON.stringify({phase: 'context-cleanup', created, closed, remaining: owned.size,
          pendingCreations: creating.size, sharedBrowserClosed: false}));
        after = await hashes(); console.log(JSON.stringify({phase: 'source-after', hashes: after}));
        assert.deepEqual(after, before, 'source bytes and complete frontend roster stayed frozen throughout fixture run');
      }
    }
    const summary = {ok: true, groups: tests.length - fromGroup + 1, totalGroups: tests.length, firstGroup: fromGroup,
      scope: 'intercepted synthetic Notifications browser fixtures only',
      liveRequests: 0, destinationDeliveries: 0, sourceWorkerExecuted: false, productionAcceptance: false};
    console.log(JSON.stringify(summary));
    return {...summary, artifactDirectory: artifacts, sourcePinsBefore: before, sourcePinsAfter: after,
      ownedContextCleanup: {created, closed, remaining: owned.size, pendingCreations: creating.size, sharedBrowserClosed: false}};
  } finally {
    suiteRunning = false;
  }
}
async function main() {
  assert.equal(process.argv.length, 2, 'notification fixtures accept no live target or credentials');
  const {chromium} = require('/home/catchplate/.nvm/versions/node/v25.5.0/lib/node_modules/playwright');
  const browser = await chromium.launch({headless: true,
    args: ['--no-sandbox', '--disable-background-networking', '--disable-component-update', '--disable-sync', '--host-resolver-rules=MAP * ~NOTFOUND']});
  try { return await runSuite(browser); }
  finally { await browser.close(); }
}
module.exports = {runSuite};
if (require.main === module) main().catch(error => { console.error(error.stack); process.exitCode = 1; });

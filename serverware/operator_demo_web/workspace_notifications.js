// Notifications have their own saved revisions and operation receipts. They do
// not share catalog mutation/retry state, and never retain a webhook URL.
const notificationSlots = Object.freeze(['action_required.slack', 'action_required.webhook', 'audit_log.slack', 'audit_log.webhook']);
const notificationStates = Object.freeze(['queued', 'sending', 'acknowledged', 'failed', 'outcome_unknown', 'suppressed', 'expired']);
const notificationOperationKey = 'serverware.operator.notifications.operation.v1';
const notificationUUID = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
const notificationInteger = (value, minimum = 0, maximum = Number.MAX_SAFE_INTEGER) => Number.isSafeInteger(value) && value >= minimum && value <= maximum;
function notificationObject(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
}
function notificationTypes(value, maximum = 64) {
  return Array.isArray(value) && value.length <= maximum && value.every((item, i) =>
    typeof item === 'string' && /^[a-z][a-z0-9_.]{0,127}$/.test(item) && (!i || value[i - 1] < item));
}
const notificationAuditPresets = Object.freeze([
  {id: 'proxy_blocks', label: 'Add proxy blocks and errors', events: [
    'data_plane.connect.denied', 'data_plane.policy.reload_failed', 'data_plane.request.denied', 'data_plane.response.blocked']},
  {id: 'access_changes', label: 'Add credential and permission changes', events: [
    'access_rule.alchemy_chain_status_created', 'access_rule.created', 'access_rule.github_created',
    'access_rule.npm_install_created', 'access_rule.npm_metadata_created', 'access_rule.npm_publish_created',
    'access_rule.revoked', 'access_rule.x_username_created', 'application.created',
    'application.proxy_authentication_changed', 'application.revoked', 'application.token_rotated',
    'credential.alchemy_key_created', 'credential.aws_sigv4_created', 'credential.aws_sigv4_replaced',
    'credential.created', 'credential.github_app_created', 'credential.github_app_key_replaced',
    'credential.github_token_created', 'credential.key_replaced', 'credential.npm_token_created',
    'credential.revoked', 'credential.x_app_bearer_created'].map(type => 'operator_catalog.' + type)},
  {id: 'approval_history', label: 'Add approval history', events: [
    'approval.approved', 'approval.decision_recorded', 'approval.denied', 'approval.requested', 'approval.review_opened',
    'control_plane.approval.approved', 'control_plane.approval.consumed', 'control_plane.approval.denied',
    'control_plane.approval.invalidated', 'control_plane.approval.requested']},
].map(preset => Object.freeze({...preset, events: Object.freeze(preset.events)})));
function notificationPresetSelection(channel, presetId, advertised, selected) {
  const preset = notificationAuditPresets.find(item => item.id === presetId);
  if (channel !== 'audit_log' || !preset || !notificationTypes(advertised, 68) || !notificationTypes(selected) ||
      selected.some(type => !advertised.includes(type))) return null;
  const available = preset.events.filter(type => advertised.includes(type));
  if (!available.length) return null;
  const next = [...new Set([...selected, ...available])].sort();
  return notificationTypes(next) ? next : null;
}
function notificationFilterProblem(enabled, selected) {
  if (!notificationTypes(selected)) return 'Choose at most 64 event types for this destination. Nothing was submitted.';
  return enabled && !selected.length ? 'No source events selected. Select at least one event or disable this destination before saving. Nothing was submitted.' : null;
}
function notificationFilterMessage(enabled, selected) {
  if (selected.length > 64) return 'Too many event types selected (' + selected.length + '/64). Remove events before saving.';
  if (!selected.length) return enabled ?
    'No source events selected in this draft. Select events or disable it before saving. Empty saved filters deliver no source events; synthetic tests are separate.' :
    'Disabled; no source events selected. You can save this destination without enabling delivery.';
  return selected.length + ' source event types selected' + (enabled ? '.' : '; delivery is disabled.') +
    ' Draft changes take effect only after Save. Selection does not confirm source availability or delivery.';
}
const notificationNativePhases = Object.freeze({prepare_available: 'Preparation available', security_key_available: 'Security-key phase available',
  confirmation_available: 'Confirmation available', waiting: 'Waiting', preparing: 'Preparation in progress',
  preparing_confirmation: 'Confirmation preparation in progress', action_in_progress: 'Action already in progress',
  response_captured: 'Response captured — enrollment not confirmed', cancelled: 'Cancelled', expired: 'Expired'});
const notificationNativeActionPhases = Object.freeze(['prepare_available', 'security_key_available', 'confirmation_available']);
function notificationNativeExpiry(value) {
  return typeof value === 'string' && /^[1-9][0-9]{0,18}$/.test(value) && BigInt(value) <= 9223372036854775807n;
}
function notificationNativeValid(value) {
  if (!notificationObject(value, ['configured', 'source_available', 'observation_only', 'last_observation']) ||
      typeof value.configured !== 'boolean' || typeof value.source_available !== 'boolean' || value.observation_only !== true) return false;
  const last = value.last_observation;
  if (!notificationObject(last, ['state', 'observed_at_epoch_ms', 'phase', 'action_available', 'source_expires_at_unix_nanos', 'review_url']) ||
      !['not_configured', 'not_observed', 'waiting', 'observed', 'unavailable'].includes(last.state) ||
      typeof last.action_available !== 'boolean' || value.configured !== (last.state !== 'not_configured') ||
      value.source_available !== ['waiting', 'observed'].includes(last.state) ||
      (['not_configured', 'not_observed'].includes(last.state) ? last.observed_at_epoch_ms !== null : !notificationInteger(last.observed_at_epoch_ms))) return false;
  if (last.state !== 'observed') return last.phase === null && !last.action_available && last.source_expires_at_unix_nanos === null && last.review_url === null;
  return Object.hasOwn(notificationNativePhases, last.phase) &&
    (last.source_expires_at_unix_nanos === null || notificationNativeExpiry(last.source_expires_at_unix_nanos)) &&
    typeof last.review_url === 'string' && /^https:\/\/serverware\.example\.com\/pilot-prelaunch\/action-status\/[0-9a-f]{64}\/[0-9a-f]{64}$/.test(last.review_url) &&
    (!last.action_available || notificationNativeActionPhases.includes(last.phase) && last.source_expires_at_unix_nanos !== null);
}
function notificationNativePresentation(value, now = Date.now()) {
  if (!notificationNativeValid(value)) throw operatorError('Native source observation is unsupported. No action availability can be inferred.');
  const last = value.last_observation;
  const result = {source: {not_configured: 'Native source not configured.', not_observed: 'Native source configured; no observation has completed.',
    waiting: 'The last source read succeeded, but no native phase was available.',
    unavailable: 'The last source read was unavailable. No actionable phase is confirmed.',
    observed: 'The last source read succeeded. This cached observation is not a live readiness check.'}[last.state],
    phase: last.phase === null ? null : 'Last observed phase: ' + notificationNativePhases[last.phase] + '.',
    observedAt: last.observed_at_epoch_ms, expiresAt: last.source_expires_at_unix_nanos === null ? null : Number(BigInt(last.source_expires_at_unix_nanos) / 1000000n),
    reviewUrl: last.review_url, availability: 'No native action is offered on this page.', refreshAfterMs: null};
  if (last.state !== 'observed') return result;
  const clockValid = notificationInteger(now) && now >= last.observed_at_epoch_ms;
  const expired = clockValid && last.source_expires_at_unix_nanos !== null && BigInt(now) * 1000000n >= BigInt(last.source_expires_at_unix_nanos);
  const stale = clockValid && now - last.observed_at_epoch_ms >= 15000;
  result.availability = !clockValid ? 'This browser clock cannot confirm the observation age. No current action availability is inferred.' :
    expired ? 'The original source window has expired. No action is offered and its deadline has not been extended.' :
    stale ? 'This observation is stale (15 seconds or older). No current action availability is inferred.' :
    last.action_available ? 'That snapshot reported an available action; it does not confirm the action is still available. Inspect authenticated native status and return to the existing registration tab.' :
    'The last snapshot did not report an available action. No action is offered here.';
  if (clockValid && !expired) {
    const remaining = [];
    if (!stale) remaining.push(last.observed_at_epoch_ms + 15000 - now);
    if (last.source_expires_at_unix_nanos !== null) remaining.push(Number((BigInt(last.source_expires_at_unix_nanos) + 999999n) / 1000000n) - now);
    if (remaining.length) result.refreshAfterMs = Math.max(1, Math.min(...remaining));
  }
  return result;
}
function createNotificationNativeObservation(value, clock = {key: null, latest: null, uncertain: false}) {
  const last = value.last_observation;
  const key = JSON.stringify([last.state, last.observed_at_epoch_ms, last.phase, last.source_expires_at_unix_nanos, last.review_url]);
  // A settings refresh may return the same cached observation. Only a new
  // observation identity can clear clock uncertainty, not rebuilding its DOM.
  if (clock.key !== key) { clock.key = key; clock.latest = null; clock.uncertain = false; }
  const panel = textNode('article'); panel.dataset.notificationNative = '';
  panel.append(textNode('h3', 'Native source observations'));
  const source = textNode('p'); source.dataset.nativeSource = '';
  const phase = textNode('p'); phase.dataset.nativePhase = '';
  const availability = textNode('p'); availability.dataset.nativeAvailability = ''; availability.setAttribute('role', 'status');
  const observed = textNode('p', undefined, 'small muted'); observed.dataset.nativeObservedAt = '';
  const expiry = textNode('p', undefined, 'small muted'); expiry.dataset.nativeExpiry = '';
  const review = textNode('a', 'Inspect authenticated native status (read only)'); review.dataset.nativeReview = ''; review.referrerPolicy = 'no-referrer';
  panel.append(source, phase, availability, observed, expiry, review);
  panel.append(textNode('p', 'Observation only: this page cannot start or prepare a ceremony, request a security-key gesture, approve an action, or confirm enrollment.', 'small muted'));
  let timer;
  const stop = () => clearTimeout(timer);
  const dateLabel = value => { const date = new Date(value); return Number.isFinite(date.getTime()) ? date.toISOString() : 'Timestamp unavailable'; };
  function update(active = true) {
    stop(); const now = Date.now();
    if (!notificationInteger(now) || clock.latest !== null && now < clock.latest) clock.uncertain = true;
    if (notificationInteger(now)) clock.latest = clock.latest === null ? now : Math.max(clock.latest, now);
    const current = notificationNativePresentation(value, clock.uncertain ? Number.NaN : now);
    source.textContent = current.source; phase.textContent = current.phase || ''; phase.hidden = current.phase === null;
    availability.textContent = current.availability;
    observed.textContent = current.observedAt === null ? 'No completed source observation.' : 'Last source check: ' + dateLabel(current.observedAt) + '.';
    expiry.textContent = current.expiresAt === null ? 'No original action expiry is present in this observation.' : 'Original source expiry: ' + dateLabel(current.expiresAt) + '.';
    review.hidden = current.reviewUrl === null;
    if (current.reviewUrl === null) review.removeAttribute('href'); else review.href = current.reviewUrl;
    // This timer only demotes cached presentation. It never polls an owner,
    // renews a deadline, changes delivery settings, or initiates an action.
    if (active && current.refreshAfterMs !== null) timer = setTimeout(() => update(), Math.min(current.refreshAfterMs, 2147483647));
  }
  return {panel, update, stop};
}
function notificationSlotValid(value) {
  if (!notificationObject(value, ['slot', 'channel', 'adapter', 'revision', 'label', 'enabled', 'secret_present', 'event_types', 'max_attempts', 'last_delivery']) ||
      !notificationSlots.includes(value.slot) || value.slot !== value.channel + '.' + value.adapter ||
      !notificationInteger(value.revision, 0, 1024) || typeof value.label !== 'string' ||
      !/^[\x20-\x7e]{0,80}$/.test(value.label) || value.label !== value.label.trim() ||
      (value.revision > 0 && !value.label) || typeof value.enabled !== 'boolean' || typeof value.secret_present !== 'boolean' ||
      value.enabled && !value.secret_present || !notificationTypes(value.event_types) || !notificationInteger(value.max_attempts, 1, 3)) return false;
  if (value.revision === 0 && (value.enabled || value.secret_present || value.label || value.event_types.length || value.last_delivery !== null)) return false;
  const delivery = value.last_delivery;
  return delivery === null || notificationObject(delivery, ['delivery_id', 'status', 'attempts', 'code', 'http_status', 'created_at_epoch_ms', 'updated_at_epoch_ms']) &&
    notificationUUID(delivery.delivery_id) && notificationStates.includes(delivery.status) && notificationInteger(delivery.attempts, 0, 3) &&
    (delivery.code === null || typeof delivery.code === 'string' && /^[a-z_]{1,80}$/.test(delivery.code)) &&
    (delivery.http_status === null || notificationInteger(delivery.http_status, 200, 599)) &&
    notificationInteger(delivery.created_at_epoch_ms, 1) && notificationInteger(delivery.updated_at_epoch_ms, delivery.created_at_epoch_ms);
}
function projectNotificationStatus(value) {
  const bad = () => { throw operatorError('Notification status is unsupported or unavailable. No settings or tests can be submitted.'); };
  if (!value || !notificationObject(value, ['schema', 'available', 'slots', 'queue', 'cursor', 'backlog', 'capabilities', 'worker',
      ...(value.available === false ? ['disabled_reason'] : [])]) || value.schema !== 'serverware.operatorNotifications/v1' ||
      typeof value.available !== 'boolean' || value.available === false && value.disabled_reason !== 'deployment_disabled' ||
      !Array.isArray(value.slots) || value.slots.length !== 4 || new Set(value.slots.map(slot => slot?.slot)).size !== 4 ||
      !value.slots.every(notificationSlotValid) || !notificationObject(value.queue, notificationStates) ||
      !notificationStates.every(state => notificationInteger(value.queue[state], 0, 10000)) ||
      !notificationObject(value.backlog, ['pending_source_events', 'queue_capacity', 'retained_capacity']) ||
      !notificationInteger(value.backlog.pending_source_events) || value.backlog.queue_capacity !== 256 || value.backlog.retained_capacity !== 10000) bad();
  const caps = value.capabilities;
  if (!notificationObject(caps, ['action_required', 'audit_log', 'native_hardware', 'source_note', 'test_note']) ||
      !notificationNativeValid(caps.native_hardware) ||
      !['source_note', 'test_note'].every(key => typeof caps[key] === 'string' && caps[key].length <= 512) ||
      !['action_required', 'audit_log'].every(channel => notificationObject(caps[channel], ['source_available', 'event_types']) &&
        typeof caps[channel].source_available === 'boolean' && notificationTypes(caps[channel].event_types, channel === 'audit_log' ? 68 : 64)) ||
      !value.available && (caps.action_required.source_available || caps.native_hardware.source_available) ||
      caps.native_hardware.source_available && !caps.action_required.source_available || caps.audit_log.source_available !== value.available ||
      !value.slots.every(slot => slot.event_types.every(type => caps[slot.channel].event_types.includes(type)))) bad();
  const worker = value.worker;
  if (!notificationObject(worker, ['state', 'last_cycle_at_epoch_ms', 'last_code']) ||
      !['disabled', 'running', 'not_started', 'unavailable'].includes(worker.state) ||
      value.available === (worker.state === 'disabled') ||
      !(worker.last_cycle_at_epoch_ms === null || notificationInteger(worker.last_cycle_at_epoch_ms, 1)) ||
      ![null, 'ready', 'notification_worker_unavailable', 'notification_source_backlog'].includes(worker.last_code)) bad();
  const cursor = value.cursor;
  if (cursor !== null && (!notificationObject(cursor, ['rowid', 'event_id', 'event_hash']) || !notificationInteger(cursor.rowid) ||
      (cursor.rowid === 0 ? cursor.event_id !== null || cursor.event_hash !== null :
        typeof cursor.event_id !== 'string' || !/^[\x20-\x7e]{1,256}$/.test(cursor.event_id) ||
        typeof cursor.event_hash !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(cursor.event_hash)))) bad();
  if (!value.available && (value.slots.some(slot => slot.revision !== 0) || notificationStates.some(state => value.queue[state] !== 0) ||
      value.backlog.pending_source_events !== 0 || cursor !== null)) bad();
  return value;
}
function notificationReferenceValid(value) {
  return notificationObject(value, ['operation_id', 'kind', 'slot', 'expected_revision']) && notificationUUID(value.operation_id) &&
    ['save', 'test'].includes(value.kind) && notificationSlots.includes(value.slot) &&
    notificationInteger(value.expected_revision, value.kind === 'test' ? 1 : 0, 1024);
}
function projectNotificationReceipt(value, reference) {
  if (!notificationReferenceValid(reference) || !notificationObject(value, ['schema', 'operation_id', 'kind', 'slot', 'revision', 'status', 'delivery_id', 'slot_state']) ||
      value.schema !== 'serverware.operatorNotificationOperation/v1' || value.operation_id !== reference.operation_id ||
      value.kind !== reference.kind || value.slot !== reference.slot ||
      value.revision !== reference.expected_revision + (reference.kind === 'save' ? 1 : 0) ||
      (value.kind === 'save' ? value.status !== 'saved' || value.delivery_id !== null || !notificationSlotValid(value.slot_state) ||
        value.slot_state.slot !== value.slot || value.slot_state.revision !== value.revision :
        !notificationStates.includes(value.status) || !notificationUUID(value.delivery_id) || value.slot_state !== null))
    throw operatorError('The operation receipt could not be verified. Keep this operation reference and check its result; do not resubmit.');
  return value;
}
function notificationOutcome(status) {
  return {saved: 'Settings saved. No message was sent by Save.', queued: 'Synthetic test queued; not yet delivered.',
    sending: 'Delivery attempt in progress; acknowledgement is not yet known.', acknowledged: 'Destination acknowledged delivery. This is not human approval or action completion.',
    failed: 'Delivery failed. Inspect the saved destination before explicitly testing again.',
    outcome_unknown: 'Delivery outcome unknown. The destination may have received it; no automatic replay is offered.',
    expired: 'Delivery expired. Its original action deadline was not extended.',
    suppressed: 'Delivery suppressed because its saved configuration or source action is no longer current.'}[status];
}
const notificationDeliveryReasons = Object.freeze({
  dns_unavailable: 'The destination hostname could not be resolved. Check the saved destination and service DNS access.',
  dns_timeout: 'The destination DNS lookup timed out. Check service DNS access.',
  connect_unavailable: 'The destination could not be reached. Check receiver availability and outbound connectivity.',
  connect_timeout: 'The connection timed out. Check receiver availability and outbound connectivity.',
  tls_unavailable: 'A verified HTTPS connection could not be established. Check the receiver certificate and service trust settings.',
  tls_timeout: 'The HTTPS handshake timed out. Check receiver availability.',
  destination_invalid: 'The saved destination is not supported by this adapter. Review its URL in the receiver settings.',
  egress_denied: 'The destination is blocked by the deployment egress policy. Ask the deployment operator to review permitted destinations.',
  payload_invalid: 'The notification message could not be prepared. Check service health.',
  transport_unavailable: 'Delivery preparation or its final checks were unavailable. Refresh status and check service health.',
  deadline_exceeded: 'The delivery time limit elapsed. Check service health and receiver availability.',
  dispatch_cancelled: 'A final configuration or source check prevented sending. Refresh status before taking another action.',
  http_rejected: 'The receiver returned a non-success HTTP status. Check the destination settings and receiver access requirements.',
  acknowledgement_invalid: 'The receiver response did not meet this adapter\'s acknowledgement contract. HTTP success alone is not acknowledgement.',
  delivery_unknown: 'Check the destination for this message before deciding whether to send another explicit test.',
  configuration_changed: 'The saved slot changed; the queued message was not redirected to its replacement.',
  action_no_longer_current: 'The source action is no longer current. Review its current state.',
  action_expired: 'The original action window ended. This notification cannot renew it.',
  action_source_unavailable: 'The source action could not be validated. Refresh status and check the source service.',
  native_source_unavailable: 'The native action source could not be validated. A delivery test does not establish hardware readiness.'
});
function notificationDeliveryMessage(delivery) {
  if (delivery === null) return 'No delivery receipt for this slot.';
  // Only called with a projected slot. Never reflect an unrecognized code or
  // promote the recorded outcome from a code or an HTTP status alone.
  let message = (delivery.status === 'queued' ? 'Delivery queued; not yet acknowledged.' : notificationOutcome(delivery.status)) +
    ' Attempts: ' + delivery.attempts + '.';
  if (delivery.code !== null) {
    if (Object.hasOwn(notificationDeliveryReasons, delivery.code))
      message += ' Last result: ' + delivery.code + '. ' + notificationDeliveryReasons[delivery.code];
    else if (delivery.code === 'acknowledged' && delivery.status === 'acknowledged') message += ' Last result: acknowledged.';
    else message += ' Delivery detail unavailable.';
  }
  if (delivery.http_status !== null) message += ' HTTP status: ' + delivery.http_status + '.';
  return message;
}
function createNotificationsView(workspace) {
  const prefix = '/api/operator-demo/notifications';
  let status = null; let busy = false; let visible = false; let opened = false;
  let nativeObservation = null;
  const nativeObservationClock = {key: null, latest: null, uncertain: false};
  let reference = null; let receipt = null; let storageBlocked = false;
  try {
    const retained = sessionStorage.getItem(notificationOperationKey);
    if (retained !== null) {
      const candidate = JSON.parse(retained);
      if (!notificationReferenceValid(candidate)) throw new Error('Invalid reference');
      reference = candidate;
    }
  } catch (_) { storageBlocked = true; }
  const forms = new Map();
  const pending = () => storageBlocked || reference !== null && receipt === null;
  const canWrite = () => visible && status?.available && !busy && !pending() && workspace.state.catalog && !workspace.state.busy && !workspace.state.uncertain;
  const say = message => { element('notifications-status').textContent = message; };
  function clearSecrets() { for (const form of forms.values()) form.elements.namedItem('url').value = ''; }
  function operationMessage(message) {
    element('notification-operation-status').textContent = message || (storageBlocked ?
      'The retained operation reference could not be read or stored. Notification changes are blocked to avoid an untraceable duplicate.' : reference ?
      (receipt ? notificationOutcome(receipt.status) : 'A previous request has an unconfirmed outcome. Check its result; refreshing settings does not prove whether it committed.') : 'No notification operation in this session.');
    element('notification-operation-reference').textContent = reference ? reference.operation_id : '';
    element('notification-operation-details').hidden = !reference;
  }
  function draftChanged(form, slot) {
    return form.elements.namedItem('label').value.trim() !== slot.label || form.elements.namedItem('enabled').checked !== slot.enabled ||
      form.elements.namedItem('url_action').value !== 'keep' || form.elements.namedItem('url').value !== '' ||
      Number(form.elements.namedItem('max_attempts').value) !== slot.max_attempts ||
      JSON.stringify([...form.querySelectorAll('[name="event_types"]:checked')].map(input => input.value).sort()) !== JSON.stringify(slot.event_types);
  }
  function controls() {
    element('notifications-refresh').disabled = busy;
    element('notification-check-operation').disabled = busy || !reference || storageBlocked;
    for (const [slotName, form] of forms) {
      const slot = status?.slots.find(item => item.slot === slotName);
      form.querySelector('[data-notification-fields]').disabled = !canWrite();
      const action = form.elements.namedItem('url_action').value;
      const input = form.elements.namedItem('url'); input.disabled = !canWrite() || action !== 'replace'; input.required = action === 'replace';
      form.querySelector('[data-notification-url-group]').hidden = action !== 'replace';
      const selectedEvents = [...form.querySelectorAll('[name="event_types"]:checked')].map(input => input.value).sort();
      const enabled = form.elements.namedItem('enabled').checked;
      form.querySelector('[data-notification-events-summary]').textContent = 'Event filters (' + selectedEvents.length + '/64 selected)';
      form.querySelector('[data-notification-events-status]').textContent = notificationFilterMessage(enabled, selectedEvents);
      form.querySelector('[data-notification-save]').disabled = !canWrite() || Boolean(notificationFilterProblem(enabled, selectedEvents));
      for (const button of form.querySelectorAll('[data-notification-preset]')) button.disabled = !canWrite() ||
        !notificationPresetSelection(slot.channel, button.dataset.notificationPreset, status.capabilities[slot.channel].event_types, selectedEvents);
      form.querySelector('[data-notification-test]').disabled = !canWrite() || !slot || !slot.enabled || !slot.secret_present || !slot.revision || draftChanged(form, slot) ||
        ['queued', 'sending'].includes(slot.last_delivery?.status);
    }
  }
  async function request(path, options = {}) {
    let response;
    try { response = await fetch(path, {credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(30000), ...options}); }
    catch (_) { throw operatorError('The response was lost or unavailable. Do not assume the change failed; check the retained operation result.'); }
    if ([401, 403].includes(response.status)) { workspace.state.catalog = null; workspace.emit(); }
    let body = null;
    try {
      if (!response.headers.get('content-type')?.includes('application/json')) throw new Error('Not JSON');
      const raw = await response.text(); if (raw.length > 131072) throw new Error('Oversized response'); body = JSON.parse(raw);
    } catch (_) { /* Never render response bodies or exception text. */ }
    if (!response.ok) {
      const rejectedInput = response.status === 422 && notificationObject(body, ['detail']) &&
        ['invalid notification input', 'invalid operator catalog input'].includes(body.detail);
      const error = operatorError([401, 403].includes(response.status) ? 'Your session could not be verified. Reload and sign in; retain any unconfirmed operation reference.' :
        response.status === 404 ? 'No receipt is recorded yet. The original request could still complete; keep the reference and check again.' :
        rejectedInput ? 'The service rejected these form fields. Correct them before making a new explicit request.' :
        'The service could not confirm the result. Check the retained operation; do not resubmit an uncertain request.');
      error.notificationStatus = response.status;
      error.notificationRejectedInput = rejectedInput;
      error.notificationCode = notificationObject(body, ['detail', 'code']) &&
        ['notification_revision_conflict', 'notification_operation_conflict', 'notification_capacity_conflict', 'notification_conflict'].includes(body.code) ? body.code : null;
      throw error;
    }
    return body;
  }
  function field(form, fields, name, title, tag = 'input') {
    const id = 'notification-' + form.dataset.notificationSlot.replace('.', '-') + '-' + name;
    const label = textNode('label', title); label.htmlFor = id;
    const input = textNode(tag); input.id = id; input.name = name; fields.append(label, input); return input;
  }
  function renderSlot(slot) {
    const form = textNode('form', undefined, 'card'); form.dataset.notificationSlot = slot.slot; form.autocomplete = 'off';
    form.append(textNode('h3', slot.adapter === 'slack' ? 'Slack' : 'Generic webhook'));
    const state = textNode('p', slot.revision === 0 ? 'Not configured.' :
      (slot.enabled ? slot.event_types.length ? 'Enabled for selected events.' : 'Enabled, but no source events are selected.' : 'Disabled.') +
      ' Destination URL ' + (slot.secret_present ? 'stored; never returned.' : 'not stored.'));
    state.dataset.slotStatus = ''; form.append(state);
    const revision = textNode('p', 'Saved revision: ' + slot.revision, 'small muted'); revision.dataset.slotRevision = ''; form.append(revision);
    const delivery = textNode('p', notificationDeliveryMessage(slot.last_delivery), 'small');
    delivery.dataset.notificationDelivery = ''; form.append(delivery);
    const fields = textNode('fieldset'); fields.dataset.notificationFields = ''; form.append(fields);
    const label = field(form, fields, 'label', 'Destination label'); label.maxLength = 80; label.required = true; label.value = slot.label;
    const enabledLabel = textNode('label'); const enabled = textNode('input'); enabled.type = 'checkbox'; enabled.name = 'enabled'; enabled.checked = slot.enabled;
    enabledLabel.append(enabled, document.createTextNode(' Enabled for selected events')); fields.append(enabledLabel);
    const action = field(form, fields, 'url_action', 'URL action', 'select');
    for (const [value, title] of [['keep', 'Keep the saved URL'], ['replace', 'Set or replace the URL'], ['clear', 'Remove the URL (requires disabled)']]) {
      const option = textNode('option', title); option.value = value;
      option.disabled = value === 'keep' && !slot.secret_present || value === 'clear' && slot.revision === 0; action.append(option);
    }
    action.value = slot.secret_present ? 'keep' : 'replace';
    const group = textNode('div'); group.dataset.notificationUrlGroup = ''; fields.append(group);
    const url = field(form, group, 'url', 'Webhook URL'); url.type = 'password'; url.maxLength = 4096; url.autocomplete = 'new-password'; url.spellcheck = false;
    group.append(textNode('p', 'Write-only HTTPS destination. Never paste it into an application permission. Cleared on submission and when leaving this page.', 'small muted'));
    const eventStatus = textNode('p'); eventStatus.dataset.notificationEventsStatus = ''; eventStatus.setAttribute('aria-live', 'polite'); fields.append(eventStatus);
    if (slot.channel === 'audit_log') {
      fields.append(textNode('p', 'Optional audit presets add supported event types to this destination’s draft. Existing selections stay selected. Review filters, then Save; presets never enable delivery or send a test.', 'small muted'));
      const presets = textNode('div', undefined, 'actions');
      for (const preset of notificationAuditPresets) {
        const button = textNode('button', preset.label, 'secondary'); button.type = 'button'; button.dataset.notificationPreset = preset.id;
        button.addEventListener('click', () => {
          if (!canWrite()) return;
          const selected = [...form.querySelectorAll('[name="event_types"]:checked')].map(input => input.value).sort();
          const next = notificationPresetSelection(slot.channel, preset.id, status.capabilities[slot.channel].event_types, selected);
          if (!next) { say('This audit preset is unavailable or would exceed 64 selected events. No filters were changed.'); return; }
          for (const checkbox of form.querySelectorAll('[name="event_types"]')) checkbox.checked = next.includes(checkbox.value);
          controls(); say('Audit preset added to this destination’s draft only. Review the filters and Save explicitly. No message was sent.');
        });
        presets.append(button);
      }
      fields.append(presets, textNode('p', 'Presets are unavailable if none of their events are supported or adding them would exceed 64 selections. Approval history is an audit summary, not an action-required alert.', 'small muted'));
    }
    const events = textNode('details'); const eventSummary = textNode('summary'); eventSummary.dataset.notificationEventsSummary = ''; events.append(eventSummary);
    events.append(textNode('p', 'Choose at most 64 event types for this destination. Only selected event types are delivered. An empty selection delivers no source events; synthetic tests remain separate.', 'small muted'));
    for (const type of status.capabilities[slot.channel].event_types) {
      const item = textNode('label'); const checkbox = textNode('input'); checkbox.type = 'checkbox'; checkbox.name = 'event_types'; checkbox.value = type;
      checkbox.checked = slot.event_types.includes(type); item.append(checkbox, document.createTextNode(' ' + type)); events.append(item);
    }
    fields.append(events);
    const attempts = field(form, fields, 'max_attempts', 'Maximum delivery attempts', 'select');
    for (const count of [1, 2, 3]) { const option = textNode('option', String(count)); option.value = String(count); attempts.append(option); } attempts.value = String(slot.max_attempts);
    fields.append(textNode('p', 'Retries are bounded by this slot and the original action deadline. Unknown delivery outcomes are not automatically replayed.', 'small muted'));
    const buttons = textNode('div', undefined, 'actions'); const save = textNode('button', 'Save settings — no message sent'); save.type = 'submit'; save.dataset.notificationSave = '';
    const test = textNode('button', 'Send synthetic test', 'secondary'); test.type = 'button'; test.dataset.notificationTest = ''; buttons.append(save, test); fields.append(buttons);
    fields.append(textNode('p', 'Test uses only this slot’s saved URL and revision. Save or refresh draft changes first. Acknowledgement does not prove approval, hardware readiness, or audit-chain integrity.', 'small muted'));
    form.addEventListener('submit', event => { event.preventDefault(); submit('save', slot.slot, form); });
    test.addEventListener('click', () => submit('test', slot.slot, form));
    form.addEventListener('input', controls); form.addEventListener('change', () => { if (action.value !== 'replace') url.value = ''; controls(); });
    forms.set(slot.slot, form); return form;
  }
  function render() {
    nativeObservation?.stop(); nativeObservation = null;
    clearSecrets(); forms.clear(); element('notifications-panels').replaceChildren();
    element('notifications-worker').textContent = !status ? 'Worker status unavailable.' :
      {disabled: 'Delivery worker disabled.', running: 'Delivery worker running; this is not delivery confirmation.',
        not_started: 'Delivery worker has not started. Saved settings alone cannot deliver messages.', unavailable: 'Delivery worker unavailable. Inspect deployment health before testing.'}[status.worker.state] +
      (status.worker.last_code === 'notification_source_backlog' ? ' Source backlog retained; queued deliveries are still being drained.' : '');
    element('notifications-queue').textContent = status?.available ?
      'Delivery history: ' + notificationStates.map(state => state.replace('_', ' ') + ' ' + status.queue[state]).join(' · ') +
      '. Pending source events: ' + status.backlog.pending_source_events + '. Queue limit: ' + status.backlog.queue_capacity +
      '; retained delivery limit: ' + status.backlog.retained_capacity + '.' : '';
    if (status?.available) {
      for (const [channel, title] of [['action_required', 'Action-required alerts'], ['audit_log', 'Audit-log delivery']]) {
        const section = textNode('section', undefined, 'card'); section.dataset.notificationChannel = channel;
        section.append(textNode('h2', title), textNode('p', channel === 'action_required' ? status.capabilities.action_required.source_available ?
          'Action-required delivery has source support. Native availability below describes only the last source read, not current gesture readiness.' :
          'Action-required source is not available according to the last recorded status. You may configure destinations and send a synthetic test, but a test does not establish native readiness.' :
          'Delivers safe summaries of newly committed selected audit events. This is not a verified audit archive or an application webhook.'));
        if (channel === 'action_required') {
          nativeObservation = createNotificationNativeObservation(status.capabilities.native_hardware, nativeObservationClock);
          nativeObservation.update(visible); section.append(nativeObservation.panel);
        }
        const cards = textNode('div', undefined, 'two-column');
        for (const slot of status.slots.filter(item => item.channel === channel)) cards.append(renderSlot(slot));
        section.append(cards); element('notifications-panels').append(section);
      }
    }
    operationMessage(); controls();
  }
  async function loadStatus() {
    try {
      status = projectNotificationStatus(await request(prefix));
      say(status.available ? 'Four independent destinations. Save changes only configuration; sending a synthetic test is a separate action.' :
        'Notifications are unavailable: disabled by deployment configuration. No destinations can be configured or tested here.');
    } catch (error) { status = null; say(operatorMessage(error)); }
    render();
  }
  async function refresh() { if (busy) return; busy = true; controls(); await loadStatus(); busy = false; controls(); }
  async function submit(kind, slotName, form) {
    if (!canWrite()) return;
    const slot = status.slots.find(item => item.slot === slotName);
    if (kind === 'test' && (!slot.enabled || !slot.secret_present || !slot.revision || draftChanged(form, slot) || ['queued', 'sending'].includes(slot.last_delivery?.status))) return;
    let body = {operation_id: crypto.randomUUID(), slot: slotName, expected_revision: slot.revision};
    if (kind === 'save') {
      const urlAction = form.elements.namedItem('url_action').value;
      body = {...body, label: form.elements.namedItem('label').value.trim(), enabled: form.elements.namedItem('enabled').checked,
        event_types: [...form.querySelectorAll('[name="event_types"]:checked')].map(input => input.value).sort(),
        max_attempts: Number(form.elements.namedItem('max_attempts').value), url_action: urlAction,
        ...(urlAction === 'replace' ? {url: form.elements.namedItem('url').value} : {})};
      const filterProblem = notificationFilterProblem(body.enabled, body.event_types);
      if (filterProblem) { say(filterProblem); return; }
      if (!/^[\x20-\x7e]{1,80}$/.test(body.label) || urlAction === 'clear' && body.enabled ||
          urlAction === 'replace' && !body.url || urlAction === 'keep' && !slot.secret_present || slot.revision === 0 && urlAction !== 'replace') {
        say('Enter a printable destination label and a replacement URL for a new slot. Disable the slot before removing its URL. Nothing was submitted.'); return;
      }
      if (urlAction === 'replace') {
        let valid = false;
        try { const url = new URL(body.url); valid = /^[\x21-\x7e]{1,4096}$/.test(body.url) && !/[\\#]/.test(body.url) &&
          url.protocol === 'https:' && Boolean(url.hostname) && !url.username && !url.password; } catch (_) { /* Fixed safe copy below. */ }
        if (!valid) { body.url = ''; say('Use an HTTPS webhook URL with no spaces, embedded username/password or fragment. Nothing was submitted.'); return; }
      }
    }
    const nextReference = {operation_id: body.operation_id, kind, slot: slotName, expected_revision: slot.revision};
    try { sessionStorage.setItem(notificationOperationKey, JSON.stringify(nextReference)); }
    catch (_) { body.url = ''; clearSecrets(); storageBlocked = true; operationMessage(); controls(); return; }
    reference = nextReference; receipt = null; busy = true; operationMessage('Submitting once. Keep this operation reference until its result is confirmed.'); controls();
    try {
      const response = request(prefix + (kind === 'save' ? '/settings' : '/test'), {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
      if (Object.hasOwn(body, 'url')) body.url = ''; clearSecrets();
      receipt = projectNotificationReceipt(await response, reference);
      await loadStatus(); operationMessage();
    } catch (error) {
      const definite = error.notificationRejectedInput === true || error.notificationStatus === 409 &&
        ['notification_revision_conflict', 'notification_capacity_conflict'].includes(error.notificationCode);
      if (definite) {
        try { sessionStorage.removeItem(notificationOperationKey); reference = null; receipt = null; }
        catch (_) { storageBlocked = true; }
        status = null; render();
        say(error.notificationCode === 'notification_revision_conflict' ? 'This change was rejected because the saved revision changed. Refresh settings and review them before making a new explicit request.' :
          error.notificationCode === 'notification_capacity_conflict' ? 'This change was rejected because notification capacity was reached. No retry was sent. Refresh after capacity changes.' : operatorMessage(error));
      } else { operationMessage(operatorMessage(error)); }
    } finally { if (Object.hasOwn(body, 'url')) body.url = ''; clearSecrets(); busy = false; controls(); }
  }
  async function checkOperation() {
    if (busy || !reference || storageBlocked) return;
    busy = true; controls();
    try {
      const checked = projectNotificationReceipt(await request(prefix + '/operations/' + reference.operation_id), reference);
      receipt = checked; await loadStatus(); operationMessage();
    } catch (error) { receipt = null; operationMessage(operatorMessage(error)); }
    finally { busy = false; controls(); }
  }
  element('notifications-refresh').addEventListener('click', refresh);
  element('notification-check-operation').addEventListener('click', checkOperation);
  window.addEventListener('pagehide', () => { clearSecrets(); nativeObservation?.stop(); }); workspace.subscribe(controls); operationMessage(); controls();
  return {show(active) { visible = active; if (!active) clearSecrets(); nativeObservation?.update(active); controls(); if (active && !opened) { opened = true; refresh(); } }};
}

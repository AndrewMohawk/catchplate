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
function notificationTypes(value) {
  return Array.isArray(value) && value.length <= 64 && value.every((item, i) =>
    typeof item === 'string' && /^[a-z][a-z0-9_.]{0,127}$/.test(item) && (!i || value[i - 1] < item));
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
      !notificationObject(caps.native_hardware, ['source_available']) || caps.native_hardware.source_available !== false ||
      !['source_note', 'test_note'].every(key => typeof caps[key] === 'string' && caps[key].length <= 512) ||
      !['action_required', 'audit_log'].every(channel => notificationObject(caps[channel], ['source_available', 'event_types']) &&
        typeof caps[channel].source_available === 'boolean' && notificationTypes(caps[channel].event_types)) ||
      caps.action_required.source_available !== false || caps.audit_log.source_available !== value.available ||
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
function createNotificationsView(workspace) {
  const prefix = '/api/operator-demo/notifications';
  let status = null; let busy = false; let visible = false; let opened = false;
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
      form.querySelector('[data-notification-events-summary]').textContent = 'Event filters (' + form.querySelectorAll('[name="event_types"]:checked').length + ' selected)';
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
      (slot.enabled ? 'Enabled for selected events.' : 'Disabled.') + ' Destination URL ' + (slot.secret_present ? 'stored; never returned.' : 'not stored.'));
    state.dataset.slotStatus = ''; form.append(state);
    const revision = textNode('p', 'Saved revision: ' + slot.revision, 'small muted'); revision.dataset.slotRevision = ''; form.append(revision);
    form.append(textNode('p', slot.last_delivery ? notificationOutcome(slot.last_delivery.status) + ' Attempts: ' + slot.last_delivery.attempts + '.' : 'No delivery receipt for this slot.', 'small'));
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
    const events = textNode('details'); const eventSummary = textNode('summary'); eventSummary.dataset.notificationEventsSummary = ''; events.append(eventSummary);
    events.append(textNode('p', 'Only selected event types are delivered. An empty selection delivers no source events; synthetic tests remain separate.', 'small muted'));
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
        section.append(textNode('h2', title), textNode('p', channel === 'action_required' ?
          'Action-required source is not connected in this deployment. You may configure destinations and send a synthetic test, but native security-key prompts will not be delivered.' :
          'Delivers safe summaries of newly committed selected audit events. This is not a verified audit archive or an application webhook.'));
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
  window.addEventListener('pagehide', clearSecrets); workspace.subscribe(controls); operationMessage(); controls();
  return {show(active) { visible = active; if (!active) clearSecrets(); controls(); if (active && !opened) { opened = true; refresh(); } }};
}

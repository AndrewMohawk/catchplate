// Retained deployment configuration, separate from credentials and access rules.
// Preparing or cancelling never changes process settings or restarts anything.
const upstreamSetupPath = '/api/operator-demo/proxy/upstreams';
const upstreamOperationKey = 'serverware.operator.upstreams.operation.v1';
const upstreamReasons = Object.freeze({fixture: 'Retained diagnostic fixture', active_rule: 'Active permission',
  retained_policy: 'Retained signed policy', google_profile: 'Configured Google profile'});
const upstreamObject = (value, keys) => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));
const upstreamUUID = value => typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value);
const upstreamDigest = value => typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value);
const upstreamRevision = value => Number.isSafeInteger(value) && value >= 1;
const upstreamTime = value => typeof value === 'string' && value.length <= 64 &&
  /^\d{4}-\d{2}-\d{2}T[0-9:.]+(?:Z|[+-]\d{2}:\d{2})$/.test(value) && Number.isFinite(Date.parse(value));
function upstreamOrigin(value, fixtureAllowed = false) {
  if (fixtureAllowed && value === 'https://demo-upstream:8443') return true;
  if (typeof value !== 'string' || value.length > 261 || !value.startsWith('https://')) return false;
  const host = value.slice(8);
  return host.includes('.') && /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/.test(host) &&
    !host.endsWith('.localhost') && !host.endsWith('.local') && !host.endsWith('.internal') &&
    !host.endsWith('.invalid') && !host.endsWith('.test') && !/^\d+(?:\.\d+){3}$/.test(host) &&
    host.split('.').every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}
function upstreamOrigins(value, fixtureAllowed = false) {
  return Array.isArray(value) && value.length >= 1 && value.length <= 16 && new Set(value).size === value.length &&
    value.every(origin => upstreamOrigin(origin, fixtureAllowed));
}
function upstreamSettings(value) {
  return upstreamObject(value, ['allowed_upstreams', 'fixture_cidrs']) && upstreamOrigins(value.allowed_upstreams, true) &&
    Array.isArray(value.fixture_cidrs) && value.fixture_cidrs.length <= 1 && value.fixture_cidrs.every(cidr =>
      typeof cidr === 'string' && cidr.length <= 64 && /^(?:[0-9.]+\/32|[0-9a-f:]+\/128)$/.test(cidr));
}
function projectUpstreamReview(value) {
  const bad = () => { throw operatorError('Destination review is unsupported or incomplete. No change can be prepared.'); };
  if (!upstreamObject(value, ['schema', 'expected_revision', 'expected_policy_hash', 'expected_settings_digest', 'old_settings',
    'protected_origins', 'fixed_first_origin', 'eligible', 'pending_operation_id', 'blocked_reason', 'cold_restart_required']) ||
    value.schema !== 'serverware.operatorUpstreamSetupReview/v1' || !upstreamRevision(value.expected_revision) ||
    !upstreamDigest(value.expected_policy_hash) || !upstreamDigest(value.expected_settings_digest) || !upstreamSettings(value.old_settings) ||
    value.cold_restart_required !== true || typeof value.eligible !== 'boolean' ||
    !(value.pending_operation_id === null || upstreamUUID(value.pending_operation_id)) ||
    ![null, 'pending_operation', 'pending_google_setup', 'capacity'].includes(value.blocked_reason) ||
    value.eligible !== (value.blocked_reason === null) || value.pending_operation_id !== null && value.blocked_reason !== 'pending_operation' ||
    !(value.fixed_first_origin === null || value.fixed_first_origin === value.old_settings.allowed_upstreams[0]) ||
    !Array.isArray(value.protected_origins) || value.protected_origins.length > 16) bad();
  let previous = '';
  for (const item of value.protected_origins) {
    if (!upstreamObject(item, ['origin', 'reasons']) || !value.old_settings.allowed_upstreams.includes(item.origin) || item.origin <= previous ||
      !Array.isArray(item.reasons) || !item.reasons.length || item.reasons.length > 4 ||
      item.reasons.some((reason, index) => !Object.hasOwn(upstreamReasons, reason) || index > 0 && item.reasons[index - 1] >= reason)) bad();
    previous = item.origin;
  }
  return value;
}
function upstreamDelta(review, text) {
  const origins = text.split(/\r?\n/).map(value => value.trim()).filter(Boolean);
  const before = review.old_settings.allowed_upstreams;
  if (!upstreamOrigins(origins, before.includes('https://demo-upstream:8443')))
    throw operatorError('Enter 1–16 unique canonical HTTPS origins, one per line: lowercase host, no path, slash, port, IP address or credentials. Keep the existing diagnostic fixture exactly as shown.');
  const added = origins.filter(origin => !before.includes(origin));
  const removed = before.filter(origin => !origins.includes(origin));
  if (!added.length && !removed.length) throw operatorError('Change at least one destination. Reordering the same list is not a configuration change.');
  if (review.fixed_first_origin !== null && origins[0] !== review.fixed_first_origin)
    throw operatorError('Keep the retained first destination first. Its signed empty-policy binding cannot be moved here.');
  if (review.protected_origins.some(item => !origins.includes(item.origin)))
    throw operatorError('A protected destination cannot be removed. Its existing fixture, permission, policy or Google configuration still requires it.');
  return {allowed_upstreams: origins, added, removed};
}
function upstreamReference(value) {
  return upstreamObject(value, ['operation_id', 'kind']) && upstreamUUID(value.operation_id) && ['prepare', 'cancel'].includes(value.kind);
}
function projectUpstreamReceipt(value, reference) {
  const bad = () => { throw operatorError('The destination operation receipt could not be verified. Keep its reference and check the result; do not resubmit.'); };
  if (!upstreamReference(reference) || !upstreamObject(value, ['schema', 'operation_id', 'status', 'old_settings', 'target_settings',
    'expected_settings_digest', 'target_settings_digest', 'reviewed_revision', 'staged_revision', 'policy_hash', 'created_at',
    'revision', 'completed_at', 'activation_receipt']) || value.schema !== 'serverware.operatorUpstreamSetup/v1' ||
    value.operation_id !== reference.operation_id || !['pending', 'cancelled', 'activated'].includes(value.status) ||
    !upstreamSettings(value.old_settings) || !upstreamSettings(value.target_settings) ||
    !operatorExact(value.old_settings.fixture_cidrs, value.target_settings.fixture_cidrs) ||
    !upstreamDigest(value.expected_settings_digest) || !upstreamDigest(value.target_settings_digest) ||
    value.expected_settings_digest === value.target_settings_digest || !upstreamDigest(value.policy_hash) ||
    !upstreamRevision(value.reviewed_revision) || value.staged_revision !== value.reviewed_revision + 1 ||
    !upstreamRevision(value.revision) || value.revision < value.staged_revision || !upstreamTime(value.created_at)) bad();
  const old = value.old_settings.allowed_upstreams; const target = value.target_settings.allowed_upstreams;
  if (old.length === target.length && old.every(origin => target.includes(origin)) ||
    target.includes('https://demo-upstream:8443') !== old.includes('https://demo-upstream:8443')) bad();
  if (value.status === 'pending') {
    if (value.revision !== value.staged_revision || value.completed_at !== null || value.activation_receipt !== null) bad();
  } else if (!upstreamTime(value.completed_at) || Date.parse(value.completed_at) < Date.parse(value.created_at) || value.revision <= value.staged_revision) bad();
  if (value.status === 'cancelled' && value.activation_receipt !== null) bad();
  if (value.status === 'activated') {
    const activated = value.activation_receipt;
    if (value.revision !== value.staged_revision + 1 || !upstreamObject(activated, ['schema', 'operation_id', 'activated_revision', 'policy_hash', 'settings_digest', 'activated_at']) ||
      activated.schema !== 'serverware.operatorUpstreamSetupActivation/v1' || activated.operation_id !== value.operation_id ||
      activated.activated_revision !== value.revision || activated.policy_hash !== value.policy_hash ||
      activated.settings_digest !== value.target_settings_digest || activated.activated_at !== value.completed_at) bad();
  }
  return value;
}
function createUpstreamsView(workspace) {
  // Deployment configuration must not follow the per-application setup panel
  // when Connect temporarily moves that panel into its final wizard step.
  const panel = element('proxy-upstreams'); const home = element('proxy');
  home.insertBefore(panel, element('proxy-setup-content'));
  let review = null; let receipt = null; let reference = null;
  let visible = false; let busy = false; let storageBlocked = false; let draftStarted = false;
  try {
    const raw = sessionStorage.getItem(upstreamOperationKey);
    if (raw !== null) { const parsed = JSON.parse(raw); if (!upstreamReference(parsed)) throw new Error(); reference = parsed; }
  } catch (_) { storageBlocked = true; }
  const say = value => { element('upstreams-status').textContent = value; };
  const current = () => review && workspace.state.catalog && review.expected_revision === workspace.state.catalog.revision &&
    review.expected_policy_hash === workspace.state.catalog.policy.policy_hash &&
    operatorExact(review.old_settings.allowed_upstreams, workspace.state.catalog.allowed_upstreams);
  const unresolved = () => reference !== null && (receipt === null || reference.kind === 'cancel' && receipt.status === 'pending');
  const ready = () => visible && !busy && !storageBlocked && !workspace.state.busy && !workspace.state.uncertain && current();
  function draft() { try { return review ? upstreamDelta(review, element('upstreams-proposed').value) : null; } catch (_) { return null; } }
  function retain(next) {
    try { sessionStorage.setItem(upstreamOperationKey, JSON.stringify(next)); reference = next; receipt = null; return true; }
    catch (_) { storageBlocked = true; return false; }
  }
  function operationText() {
    if (storageBlocked) return 'The operation reference could not be read or retained in this tab. Changes are blocked to avoid an untraceable duplicate.';
    if (!reference) return 'No destination change has been prepared in this tab.';
    if (!receipt) return 'The last request has an unconfirmed outcome. Check its result using the retained reference. A missing receipt does not prove failure.';
    if (receipt.status === 'pending') return reference.kind === 'cancel' ?
      'Cancellation is not yet confirmed. The last read still showed a prepared change. Check again; the cancellation is not resent.' :
      'Prepared — restart required. Effective destinations are unchanged. Arrange a separate controlled restart with the deployment operator.';
    return receipt.status === 'cancelled' ? 'The prepared change was cancelled. No destination settings were applied by this operation.' :
      'Cold-start activation is recorded. Refresh effective destinations and check proxy activation separately. This is not a successful client request.';
  }
  function render() {
    const catalog = workspace.state.catalog;
    element('upstreams-effective').textContent = catalog ? catalog.allowed_upstreams.join('\n') : 'Effective destinations unavailable. Refresh workspace status.';
    element('upstreams-review').disabled = busy || !catalog || workspace.state.busy;
    element('upstreams-form').hidden = !review;
    element('upstreams-fields').disabled = !ready() || !review?.eligible || unresolved() || receipt?.status === 'pending';
    const delta = draft();
    let inputMessage = '';
    if (review && !delta) { try { upstreamDelta(review, element('upstreams-proposed').value); } catch (error) { inputMessage = operatorMessage(error); } }
    element('upstreams-input-status').textContent = inputMessage;
    element('upstreams-added').textContent = delta ? delta.added.join('\n') || 'None' : 'Review a valid changed destination list.';
    element('upstreams-removed').textContent = delta ? delta.removed.join('\n') || 'None' : 'Review a valid changed destination list.';
    element('upstreams-prepare').disabled = !ready() || !review?.eligible || unresolved() || receipt?.status === 'pending' || !delta;
    element('upstreams-check').disabled = busy || !reference || storageBlocked;
    element('upstreams-cancel').disabled = !ready() || receipt?.status !== 'pending' || unresolved() || reference?.kind !== 'prepare' ||
      review?.pending_operation_id !== reference?.operation_id;
    element('upstreams-copy').disabled = busy || receipt?.status !== 'pending' || unresolved();
    element('upstreams-operation-status').textContent = operationText();
    element('upstreams-pending-note').hidden = receipt?.status !== 'pending';
    element('upstreams-operation').hidden = !reference && !storageBlocked;
    element('upstreams-operation-reference').textContent = reference?.operation_id || '';
    element('upstreams-operation-details').hidden = !reference;
    element('upstreams-prepared').hidden = !receipt;
    element('upstreams-prepared-list').textContent = receipt ? receipt.target_settings.allowed_upstreams.join('\n') : '';
    const restrictions = review ? review.protected_origins.map(item => item.origin + ' — ' + item.reasons.map(reason => upstreamReasons[reason]).join(', ')) : [];
    if (review?.fixed_first_origin) restrictions.push('Keep first: ' + review.fixed_first_origin);
    element('upstreams-protected').textContent = restrictions.join('\n') || 'No protected destinations in the current review.';
    element('upstreams-review-state').textContent = !review ? '' : !current() ? 'Workspace state changed. Review destination settings again before preparing or cancelling.' :
      review.blocked_reason === 'pending_operation' ? 'A prepared destination change is pending. Inspect the operation before making another change.' :
      review.blocked_reason === 'pending_google_setup' ? 'A Google setup change is pending. Resolve that separate operation first.' :
      review.blocked_reason === 'capacity' ? 'Retained configuration capacity is reached. No new change can be prepared.' :
      'Review is current. Preparation records this exact proposed list; it does not apply it.';
  }
  async function request(path, options = {}) {
    let response;
    try { response = await fetch(path, {credentials: 'same-origin', cache: 'no-store', redirect: 'error', signal: AbortSignal.timeout(30000), ...options}); }
    catch (_) { throw operatorError('The response was lost or unavailable. Retain the operation reference and check its result; no request is resent automatically.'); }
    if ([401, 403].includes(response.status)) { workspace.state.catalog = null; workspace.emit(); }
    let body = null;
    try { const raw = await response.text(); if (!response.headers.get('content-type')?.includes('application/json') || raw.length > 32768) throw new Error(); body = JSON.parse(raw); }
    catch (_) { /* Never render server bodies or raw exceptions. */ }
    if (!response.ok) {
      const invalid = response.status === 422 && upstreamObject(body, ['detail']) &&
        ['invalid operator catalog input', 'invalid upstream setup input'].includes(body.detail);
      const error = operatorError([401, 403].includes(response.status) ? 'Your session could not be verified. Reload and sign in; keep any retained operation reference.' :
        response.status === 404 && path === upstreamSetupPath ? 'Destination configuration is not supported by this deployment. Effective destinations remain unchanged; there is no Save or Apply action here.' :
        response.status === 404 ? 'No actor-owned receipt is recorded yet. The original request could still complete. Keep its reference and check again.' :
        invalid ? 'The service rejected these fields before committing a change. Refresh and review them before a new explicit request.' :
        'The service could not confirm this operation. Check its retained result; do not resubmit an uncertain request.');
      error.upstreamRejectedInput = invalid; throw error;
    }
    return body;
  }
  async function loadReview() {
    review = projectUpstreamReview(await request(upstreamSetupPath));
    if (review.pending_operation_id && !unresolved() && receipt?.status !== 'pending' && reference?.operation_id !== review.pending_operation_id)
      retain({operation_id: review.pending_operation_id, kind: 'prepare'});
    if (!draftStarted) { element('upstreams-proposed').value = review.old_settings.allowed_upstreams.join('\n'); draftStarted = true; }
    await workspace.refresh();
  }
  async function refresh() {
    if (busy || workspace.state.busy) return; busy = true; render();
    try { await loadReview(); say('Effective deployment destinations were reviewed. No configuration was changed.'); }
    catch (error) { review = null; say(operatorMessage(error)); }
    finally { busy = false; render(); }
  }
  function retireRejected(referenceBefore) {
    try { sessionStorage.removeItem(upstreamOperationKey); reference = referenceBefore; receipt = null;
      if (referenceBefore) sessionStorage.setItem(upstreamOperationKey, JSON.stringify(referenceBefore)); }
    catch (_) { storageBlocked = true; }
  }
  async function submit(kind) {
    if (!ready()) return;
    if (kind === 'prepare' && (!review.eligible || unresolved() || receipt?.status === 'pending')) return;
    if (kind === 'cancel' && (receipt?.status !== 'pending' || unresolved() || reference?.kind !== 'prepare' || review.pending_operation_id !== reference.operation_id)) return;
    let body; const previousReference = reference; const reviewedSettings = review.old_settings;
    if (kind === 'prepare') {
      let changed; try { changed = upstreamDelta(review, element('upstreams-proposed').value); } catch (error) { say(operatorMessage(error)); return; }
      body = {operation_id: crypto.randomUUID(), allowed_upstreams: changed.allowed_upstreams,
        expected_settings_digest: review.expected_settings_digest, expected_revision: review.expected_revision, expected_policy_hash: review.expected_policy_hash};
    } else body = {operation_id: reference.operation_id, expected_revision: review.expected_revision, expected_policy_hash: review.expected_policy_hash};
    if (!retain({operation_id: body.operation_id, kind})) { render(); return; }
    busy = true; workspace.setConsentHold(true, 'proxy-upstream-change'); render(); say('Submitting this operation once. No process settings are changed by this request.');
    try {
      receipt = projectUpstreamReceipt(await request(upstreamSetupPath + (kind === 'cancel' ? '/cancel' : ''),
        {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)}), reference);
      if (kind === 'prepare' && (!operatorExact(receipt.target_settings.allowed_upstreams, body.allowed_upstreams) ||
        !operatorExact(receipt.old_settings, reviewedSettings) ||
        receipt.expected_settings_digest !== body.expected_settings_digest || receipt.reviewed_revision !== body.expected_revision || receipt.policy_hash !== body.expected_policy_hash)) {
        receipt = null; throw operatorError('The prepared receipt does not match the reviewed destination list. Keep the reference and inspect its result; do not repeat.');
      }
      await loadReview(); say(operationText());
    } catch (error) {
      if (error.upstreamRejectedInput) { retireRejected(kind === 'cancel' ? previousReference : null); review = null; }
      say(operatorMessage(error));
    } finally { busy = false; workspace.setConsentHold(false, 'proxy-upstream-change'); render(); }
  }
  async function check() {
    if (busy || !reference || storageBlocked) return; busy = true; render();
    try { receipt = projectUpstreamReceipt(await request(upstreamSetupPath + '/' + reference.operation_id), reference);
      await loadReview(); say(operationText()); }
    catch (error) { receipt = null; say(operatorMessage(error)); }
    finally { busy = false; render(); }
  }
  element('upstreams-review').addEventListener('click', refresh);
  element('upstreams-form').addEventListener('submit', event => { event.preventDefault(); return submit('prepare'); });
  element('upstreams-proposed').addEventListener('input', () => { draftStarted = true; render(); });
  element('upstreams-check').addEventListener('click', check);
  element('upstreams-cancel').addEventListener('click', () => submit('cancel'));
  element('upstreams-copy').addEventListener('click', async () => {
    if (busy || receipt?.status !== 'pending' || unresolved()) return;
    try { await navigator.clipboard.writeText(JSON.stringify(receipt.target_settings.allowed_upstreams));
      say('Copied only the public destination array. No deployment file, token, key, command or running setting was changed. Restart is still a separate operator action.'); }
    catch (_) { say('Clipboard access was denied. The public destination list remains visible for manual copying.'); }
  });
  workspace.subscribe(render); render();
  return {show(active) { visible = active; render(); }};
}

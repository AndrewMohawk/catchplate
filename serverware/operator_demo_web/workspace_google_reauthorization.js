// Same-account maintenance, never initial consent or a new app permission.
// Only the public operation UUID may survive navigation in sessionStorage.
const googleReauthorizationStatuses = Object.freeze(['prepared', 'awaiting_consent', 'exchanging',
  'candidate_held', 'review_required', 'adopted', 'denied', 'expired', 'failed']);
const googleReauthorizationTerminal = Object.freeze(['adopted', 'denied', 'expired', 'failed']);
const googleReauthorizationReasons = Object.freeze(['start_failed', 'state_changed', 'consent_denied',
  'exchange_failed', 'adoption_uncertain', 'identity_mismatch', 'candidate_unavailable']);
function reauthorizationInvalid() {
  const error = new Error('Invalid Google reauthorization metadata');
  error.uiMessage = 'Reauthorization could not be verified. Check the exact saved operation; do not repeat the request.';
  return error;
}
function reauthorizationUuid(value) { return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value); }
function reauthorizationInteger(value) { return Number.isSafeInteger(value) && value > 0; }
function reauthorizationHash(value) { return typeof value === 'string' && /^sha256:[0-9a-f]{64}$/.test(value); }
function reauthorizationText(value, max = 256) { return typeof value === 'string' && value.length > 0 && value.length <= max && !/[\u0000-\u001f\u007f]/.test(value); }
function reauthorizationTime(value) { return reauthorizationText(value, 64) && Number.isFinite(Date.parse(value)); }
function reauthorizationIds(value) {
  return Array.isArray(value) && value.length <= 64 && value.every(reauthorizationUuid) &&
    JSON.stringify(value) === JSON.stringify([...new Set(value)].sort());
}
function reauthorizationScopes(value) {
  return JSON.stringify(value) === JSON.stringify(['email', 'https://www.googleapis.com/auth/gmail.readonly', 'openid']);
}
function projectGoogleReauthorizationReview(value) {
  if (!value || value.schema !== 'serverware.operatorGoogleReauthorizationReview/v1' ||
      !reauthorizationUuid(value.credential_id) || !reauthorizationUuid(value.original_oauth_intent_id) ||
      !reauthorizationText(value.name, 128) || value.provider_id !== 'google' ||
      !reauthorizationText(value.provider_subject) || !reauthorizationText(value.provider_account) ||
      !reauthorizationText(value.oauth_client_id) || !reauthorizationScopes(value.scopes) || typeof value.eligible !== 'boolean' ||
      !reauthorizationInteger(value.expected_revision) || !reauthorizationHash(value.expected_policy_hash) ||
      !reauthorizationInteger(value.expected_credential_generation) ||
      !reauthorizationIds(value.affected_rule_ids) || !reauthorizationIds(value.application_ids)) throw reauthorizationInvalid();
  return {schema: value.schema, credential_id: value.credential_id, name: value.name, provider_id: 'google',
    provider_subject: value.provider_subject, provider_account: value.provider_account, oauth_client_id: value.oauth_client_id,
    scopes: [...value.scopes], original_oauth_intent_id: value.original_oauth_intent_id,
    expected_revision: value.expected_revision, expected_policy_hash: value.expected_policy_hash,
    expected_credential_generation: value.expected_credential_generation, affected_rule_ids: [...value.affected_rule_ids],
    application_ids: [...value.application_ids], eligible: value.eligible};
}
function projectGoogleReauthorizationOperation(value) {
  if (!value || value.schema !== 'serverware.operatorGoogleReauthorization/v1' ||
      !reauthorizationUuid(value.operation_id) || !reauthorizationUuid(value.credential_id) ||
      !reauthorizationText(value.name, 128) || value.provider_id !== 'google' ||
      !reauthorizationText(value.provider_account) || !reauthorizationScopes(value.scopes) ||
      !googleReauthorizationStatuses.includes(value.status) ||
      !(value.reason === null || googleReauthorizationReasons.includes(value.reason)) ||
      !reauthorizationTime(value.created_at) || !reauthorizationInteger(value.expires_at_epoch) ||
      !reauthorizationInteger(value.expected_revision) || !reauthorizationHash(value.expected_policy_hash) ||
      !reauthorizationInteger(value.expected_credential_generation) ||
      !reauthorizationIds(value.affected_rule_ids) || !reauthorizationIds(value.application_ids)) throw reauthorizationInvalid();
  let receipt = null;
  if (value.status === 'adopted') {
    const raw = value.receipt;
    if (!raw || raw.schema !== 'serverware.operatorGoogleReauthorizationReceipt/v1' ||
        raw.operation_id !== value.operation_id || raw.credential_id !== value.credential_id ||
        raw.previous_credential_generation !== value.expected_credential_generation ||
        !reauthorizationInteger(raw.credential_generation) || raw.credential_generation !== raw.previous_credential_generation + 1 ||
        !reauthorizationUuid(raw.original_oauth_intent_id) || raw.revision !== value.expected_revision ||
        raw.policy_hash !== value.expected_policy_hash || !reauthorizationTime(raw.adopted_at) ||
        JSON.stringify(raw.affected_rule_ids) !== JSON.stringify(value.affected_rule_ids) ||
        JSON.stringify(raw.application_ids) !== JSON.stringify(value.application_ids)) throw reauthorizationInvalid();
    receipt = {schema: raw.schema, operation_id: raw.operation_id, credential_id: raw.credential_id,
      previous_credential_generation: raw.previous_credential_generation, credential_generation: raw.credential_generation,
      original_oauth_intent_id: raw.original_oauth_intent_id, revision: raw.revision, policy_hash: raw.policy_hash,
      affected_rule_ids: [...raw.affected_rule_ids], application_ids: [...raw.application_ids], adopted_at: raw.adopted_at};
  } else if (value.receipt !== null) throw reauthorizationInvalid();
  return {schema: value.schema, operation_id: value.operation_id, credential_id: value.credential_id, name: value.name,
    provider_id: 'google', provider_account: value.provider_account, scopes: [...value.scopes], status: value.status,
    // Raw reason text is never rendered. Public status alone determines copy.
    reason: value.reason, created_at: value.created_at, expires_at_epoch: value.expires_at_epoch,
    expected_revision: value.expected_revision, expected_policy_hash: value.expected_policy_hash,
    expected_credential_generation: value.expected_credential_generation, affected_rule_ids: [...value.affected_rule_ids],
    application_ids: [...value.application_ids], receipt};
}
function googleReauthorizationAccountMatches(review, catalog) {
  const account = catalog?.credentials.find(item => item.id === review?.credential_id);
  if (!account || account.status !== 'active' || account.auth_type !== 'google_oauth' ||
      account.provider_subject !== review.provider_subject || account.provider_account !== review.provider_account ||
      account.oauth_client_id !== review.oauth_client_id || account.permission_preset !== 'gmail_readonly' ||
      JSON.stringify(account.scopes) !== JSON.stringify(review.scopes)) return false;
  const rules = catalog.access_rules.filter(rule => rule.credential_id === account.id && rule.status === 'active');
  return JSON.stringify(rules.map(rule => rule.id).sort()) === JSON.stringify(review.affected_rule_ids) &&
    JSON.stringify([...new Set(rules.map(rule => rule.application_id))].sort()) === JSON.stringify(review.application_ids) &&
    review.application_ids.every(id => catalog.applications.some(app => app.id === id && app.status === 'active'));
}
function reauthorizationReviewedOperation(operation, review) {
  return operation.credential_id === review.credential_id && operation.name === review.name &&
    operation.provider_account === review.provider_account && JSON.stringify(operation.scopes) === JSON.stringify(review.scopes) &&
    ['expected_revision', 'expected_policy_hash', 'expected_credential_generation'].every(key => operation[key] === review[key]) &&
    JSON.stringify(operation.affected_rule_ids) === JSON.stringify(review.affected_rule_ids) &&
    JSON.stringify(operation.application_ids) === JSON.stringify(review.application_ids);
}
function validateGoogleReauthorizationStart(value, capability, review, operationId, now = Date.now()) {
  const operation = projectGoogleReauthorizationOperation(value?.operatorGoogleReauthorization);
  if (operation.operation_id !== operationId || operation.status !== 'awaiting_consent' ||
      !reauthorizationReviewedOperation(operation, review)) throw reauthorizationInvalid();
  const validate = typeof module !== 'undefined' && module.exports ? require('./workspace_google.js').validateGoogleStart : validateGoogleStart;
  const checked = validate({...value, operatorGoogleIntent: {id: operation.operation_id, name: operation.name,
    provider_id: 'google', permission_preset: 'gmail_readonly', scopes: [...operation.scopes], created_at: operation.created_at,
    expires_at_epoch: operation.expires_at_epoch, status: 'awaiting_consent'}}, capability, review.name, now);
  if (new URL(checked.authorizationUrl).searchParams.get('client_id') !== review.oauth_client_id) throw reauthorizationInvalid();
  return {operation, authorizationUrl: checked.authorizationUrl};
}
function googleReauthorizationReturnHint(href) {
  const url = new URL(href); const values = url.searchParams.getAll('operator_google_reauthorization');
  const exact = [...url.searchParams.keys()].length === 1;
  if (values.length) url.search = '';
  return {present: values.length > 0, id: exact && values.length === 1 && reauthorizationUuid(values[0]) ? values[0] : null,
    clean: url.pathname + url.search + url.hash};
}
function createGoogleReauthorizationView(workspace, applications) {
  const storageKey = 'serverware.googleReauthorization.operation';
  const hint = googleReauthorizationReturnHint(location.href);
  if (hint.present) history.replaceState(null, '', hint.clean);
  let operationId = hint.id;
  if (!hint.present) {
    try { const saved = sessionStorage.getItem(storageKey); if (reauthorizationUuid(saved)) operationId = saved; }
    catch (_) { /* Storage availability is checked before any start request. */ }
  }
  let opened = hint.present || Boolean(operationId); let attempted = opened; let checking = false;
  let target = null; let review = null; let operation = null; let confirmed = false; let serial = 0; let capabilityKey = '';
  let notice = hint.present && !hint.id ? 'Invalid return reference. No reauthorization was verified or retried.' : '';
  const capability = () => workspace.state.catalog?.capabilities.google_reauthorization;
  const hold = value => workspace.setConsentHold(value, 'google-reauthorization');
  const heldToken = () => applications.hasHeldToken();
  const coherent = () => Boolean(review && googleReauthorizationAccountMatches(review, workspace.state.catalog) &&
    review.expected_revision === workspace.state.catalog.revision && review.expected_policy_hash === workspace.state.catalog.policy.policy_hash);
  function remember(id) {
    try { sessionStorage.setItem(storageKey, id); return sessionStorage.getItem(storageKey) === id; }
    catch (_) { return false; }
  }
  function render() {
    element('google-reauthorization-panel').hidden = !opened;
    element('google-reauthorization-token-warning').hidden = !opened || !heldToken();
    element('google-reauthorization-start').hidden = attempted;
    element('google-reauthorization-start').disabled = !opened || !capability() || !coherent() || review?.eligible !== true || attempted || checking ||
      workspace.state.busy || workspace.state.uncertain || heldToken();
    element('google-reauthorization-refresh').disabled = !opened || !capability() || checking || workspace.writeInFlight();
    element('google-reauthorization-leave').disabled = checking || workspace.writeInFlight();
    const labels = {prepared: 'Reauthorization prepared; no saved authorization link is replayed.',
      awaiting_consent: 'Waiting for Google consent. No repeat request was sent.', exchanging: 'Confirming the Google exchange. Do not repeat consent.',
      candidate_held: 'A replacement is retained but not active. Check saved status; do not repeat consent.',
      review_required: 'Reauthorization needs server-side review. Existing permissions are not recreated; no retry was sent.',
      adopted: confirmed ? 'Reauthorization saved for the same account. Existing app permissions and application tokens were preserved. A Gmail request has not been tested here.' :
        'A replacement receipt exists, but the current account and assignments have not been confirmed. Check saved status.',
      denied: 'Google consent was declined. No replacement was confirmed; no automatic retry was sent.',
      expired: 'This consent attempt expired. No replacement was confirmed; no automatic retry was sent.',
      failed: 'Reauthorization did not complete. Inspect saved status; do not assume provider-side rollback.'};
    element('google-reauthorization-status').textContent = checking ? 'Checking the exact account and saved operation...' : notice ||
      (!capability() ? 'Reauthorization is unavailable in this deployment. No request will be retried.' : operation ? labels[operation.status] :
        attempted ? 'The operation outcome is unconfirmed. Check saved status; do not repeat the request.' :
        coherent() ? review.eligible ? 'Review the same account, current credential version and affected apps before continuing.' :
          'This account is not currently eligible for a new reauthorization. Check saved status; no request was sent.' :
          'The saved account or permissions changed. Check saved status to obtain a fresh review.');
    const list = element('google-reauthorization-review'); list.replaceChildren();
    const display = review || operation;
    if (display) {
      const catalog = workspace.state.catalog;
      const apps = display.application_ids.map(id => catalog?.applications.find(item => item.id === id)).filter(Boolean);
      const rules = display.affected_rule_ids.map(id => catalog?.access_rules.find(item => item.id === id)).filter(Boolean);
      const names = items => operatorConnectResourceChoices(items).map(item => item.name).join(', ') || 'None';
      const rows = [['Google account', display.provider_account], ['Permission', 'Read Gmail'],
        [coherent() ? 'Current reviewed credential version' : 'Originally reviewed credential version', String(display.expected_credential_generation)],
        ['Assigned apps (' + display.application_ids.length + ')', names(apps)],
        ['Existing access rules (' + display.affected_rule_ids.length + ')', names(rules)],
        ['Changes', 'Same credential and permissions. No application token is created, rotated or renewed.']];
      for (const [name, value] of rows) list.append(textNode('dt', name), textNode('dd', value));
    }
    if (operationId) list.append(textNode('dt', 'Public recovery reference'), textNode('dd', operationId));
  }
  async function observe() {
    if (!opened || checking || workspace.writeInFlight() || !capability()) return false;
    checking = true; confirmed = false; const version = ++serial; const cap = {...capability()}; render();
    try {
      let next = null;
      if (operationId) {
        next = projectGoogleReauthorizationOperation(await workspace.api(cap.status_path_prefix + operationId));
        if (next.operation_id !== operationId || target && next.credential_id !== target) throw reauthorizationInvalid();
        operation = next;
      }
      const id = next?.credential_id || target;
      if (!reauthorizationUuid(id)) throw reauthorizationInvalid();
      // Pending status is observational, not a request for new eligibility.
      // On callback success obtain a new review for exact current identity and
      // version lineage; the old active account alone cannot prove adoption.
      const nextReview = !next || next.status === 'adopted' ?
        projectGoogleReauthorizationReview(await workspace.api(cap.status_path_prefix + id + cap.review_path_suffix)) : review;
      const refreshed = await workspace.refresh({manual: true});
      if (version !== serial || !refreshed || JSON.stringify(capability()) !== JSON.stringify(cap))
        throw reauthorizationInvalid();
      if ((!next || next.status === 'adopted') && (!nextReview || nextReview.credential_id !== id ||
          !googleReauthorizationAccountMatches(nextReview, workspace.state.catalog) ||
          nextReview.expected_revision !== workspace.state.catalog.revision || nextReview.expected_policy_hash !== workspace.state.catalog.policy.policy_hash))
        throw reauthorizationInvalid();
      if (next && nextReview && (next.provider_account !== nextReview.provider_account || JSON.stringify(next.scopes) !== JSON.stringify(nextReview.scopes) ||
          JSON.stringify(next.affected_rule_ids) !== JSON.stringify(nextReview.affected_rule_ids) ||
          JSON.stringify(next.application_ids) !== JSON.stringify(nextReview.application_ids))) throw reauthorizationInvalid();
      if (next?.status === 'adopted' && (next.receipt.original_oauth_intent_id !== nextReview.original_oauth_intent_id ||
          nextReview.expected_credential_generation < next.receipt.credential_generation)) throw reauthorizationInvalid();
      target = id; review = nextReview; operation = next; confirmed = next?.status === 'adopted'; notice = '';
      hold(attempted && (!next || !googleReauthorizationTerminal.includes(next.status)));
      return true;
    } catch (_) {
      notice = 'Saved reauthorization status or the current account could not be verified. No navigation or retry occurred.';
      if (attempted) hold(true);
      return false;
    } finally { checking = false; render(); }
  }
  async function open(id) {
    if (!capability() || workspace.state.busy || workspace.state.uncertain || checking) return;
    const account = workspace.state.catalog.credentials.find(item => item.id === id && item.status === 'active' && item.auth_type === 'google_oauth');
    if (!account) return;
    // A retained uncertain operation is recovered, never replaced by a new POST.
    if (!operationId) { target = id; review = null; operation = null; attempted = false; }
    opened = true; notice = ''; location.hash = 'credentials'; render(); await observe();
    element('google-reauthorization-panel').scrollIntoView({block: 'nearest'});
  }
  element('google-reauthorization-start').addEventListener('click', async () => {
    if (!capability() || !coherent() || review.eligible !== true || attempted || checking || workspace.state.busy || workspace.state.uncertain || heldToken()) return;
    if (!window.confirm('Reauthorize ' + review.provider_account + ' at stored credential version ' + review.expected_credential_generation +
        '? Existing app permissions and application tokens remain unchanged. Continue to Google in this tab; unsaved drafts will be lost. This is not Disconnect.')) return;
    // No await between the exact review check and mutate: its CAS snapshot must
    // equal the reviewed values, never silently rebase consent onto a new catalog.
    if (!coherent() || review.eligible !== true || workspace.state.busy || workspace.state.uncertain || heldToken()) return;
    const reviewed = review; const cap = {...capability()}; const google = workspace.state.catalog.capabilities.google_oauth;
    operationId = crypto.randomUUID();
    if (!remember(operationId)) { operationId = null; notice = 'This browser cannot retain the public recovery reference. No start request was sent.'; render(); return; }
    attempted = true; notice = ''; let receipt = null;
    const saved = await workspace.mutate('oauth/google/reauthorize', {operation_id: operationId, credential_id: reviewed.credential_id,
      expected_revision: reviewed.expected_revision, expected_policy_hash: reviewed.expected_policy_hash,
      expected_credential_generation: reviewed.expected_credential_generation, affected_rule_ids: [...reviewed.affected_rule_ids]},
    'google-reauthorization-status', result => {
      receipt = validateGoogleReauthorizationStart(result, google, reviewed, operationId); operation = receipt.operation; hold(true);
    });
    hold(true);
    const observed = await observe();
    if (!saved || !observed || !receipt || JSON.stringify(capability()) !== JSON.stringify(cap) || heldToken() || workspace.state.uncertain ||
        operation?.status !== 'awaiting_consent' || JSON.stringify(operation) !== JSON.stringify(receipt.operation) ||
        !coherent() || !reauthorizationReviewedOperation(operation, reviewed) || operation.expires_at_epoch * 1000 <= Date.now()) {
      receipt = null; notice = 'The start response or current operation was not confirmed. Check saved status; no navigation or repeat request occurred.';
      if (saved) workspace.requireReview('Reauthorization may have started, but the exact saved state was not confirmed.');
      render(); return;
    }
    const destination = receipt.authorizationUrl; receipt = null; location.assign(destination);
  });
  element('google-reauthorization-refresh').addEventListener('click', observe);
  element('google-reauthorization-leave').addEventListener('click', () => {
    if (checking || workspace.writeInFlight() || !window.confirm('Leave reauthorization? This does not cancel Google consent, disconnect the account or retry a request. Any uncertain write still needs saved-state review.')) return;
    ++serial; opened = false; hold(false);
    if (!attempted || operation && googleReauthorizationTerminal.includes(operation.status) && (!operation.receipt || confirmed)) {
      try { sessionStorage.removeItem(storageKey); } catch (_) { /* No provider material is stored here. */ }
      operationId = null; target = null; review = null; operation = null; attempted = false;
    }
    render();
  });
  workspace.subscribe(() => {
    const key = JSON.stringify(capability());
    if (key !== capabilityKey) {
      capabilityKey = key;
      if (opened && operationId && capability()) queueMicrotask(observe);
      else if (attempted && opened) hold(true);
    }
    if (confirmed && (!review || !googleReauthorizationAccountMatches(review, workspace.state.catalog))) confirmed = false;
    render();
  });
  window.addEventListener('pageshow', event => {
    if (event.persisted && opened) { confirmed = false; if (attempted) hold(true); observe(); }
  });
  if (opened) { hold(true); location.hash = 'credentials'; }
  render();
  return {open};
}
if (typeof module !== 'undefined' && module.exports) module.exports = {projectGoogleReauthorizationReview,
  projectGoogleReauthorizationOperation, googleReauthorizationAccountMatches, validateGoogleReauthorizationStart,
  googleReauthorizationReturnHint};

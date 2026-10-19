// Provider application configuration is separate from account consent. Only a
// public operation locator is retained; neither secrets nor POST bodies are.
const googleConfigurationPath = '/api/operator-demo/oauth/google/configuration/v2';
const googleConfigurationKey = 'catchplate.operator.google.configuration.operation.v2';
const googleConfigurationClient = value => typeof value === 'string' &&
  /^[A-Za-z0-9][A-Za-z0-9_-]{0,199}\.apps\.googleusercontent\.com$/.test(value);
function googleConfigurationOrigin(value) {
  try { return googleText(value, 2048) && value !== 'https://demo-upstream:8443' &&
    new URL(value).protocol === 'https:' && new URL(value).origin === value; } catch (_) { return false; }
}
function googleConfigurationReference(value) {
  return upstreamObject(value, ['operation_id', 'kind']) && upstreamUUID(value.operation_id) && ['prepare', 'cancel'].includes(value.kind);
}
function googleConfigurationProfile(client, redirect) {
  return {schema: 'catchplate.operatorGoogleProfile/v1', profile: 'operator-google-v1', provider_id: 'google',
    client_id: client, redirect_uri: redirect, permission_preset: 'gmail_readonly', scopes: [...operatorGoogleScopes],
    api_origins: ['https://gmail.googleapis.com'], authorization_url: 'https://accounts.google.com/o/oauth2/v2/auth',
    token_url: 'https://oauth2.googleapis.com/token', revocation_url: 'https://oauth2.googleapis.com/revoke',
    identity_url: 'https://openidconnect.googleapis.com/v1/userinfo'};
}
function googleConfigurationTarget(old, target) {
  if (!upstreamSettings(old) || !upstreamSettings(target)) return false;
  const origins = [...old.allowed_upstreams];
  if (!origins.includes('https://gmail.googleapis.com')) origins.push('https://gmail.googleapis.com');
  return origins.length <= 32 && operatorExact(target, {allowed_upstreams: origins, fixture_cidrs: old.fixture_cidrs});
}
function projectGoogleConfigurationOperation(value, reference = null) {
  const bad = () => { throw operatorError('The Google configuration receipt could not be verified. Keep its reference and check the result; do not resubmit.'); };
  if (!upstreamObject(value, ['schema', 'operation_id', 'client_id', 'old_settings', 'target_settings', 'expected_settings_digest',
    'public_url', 'redirect_uri', 'profile_binding', 'profile_binding_digest', 'reviewed_revision', 'staged_revision', 'policy_hash',
    'created_at', 'setup_contract', 'custody_ref', 'secret_present', 'status', 'revision', 'completed_at', 'activation_receipt']) ||
    value.schema !== 'catchplate.operatorGoogleManagedSetup/v2' || value.setup_contract !== 'catchplate.operatorGoogleManagedSetupBinding/v2' ||
    !upstreamUUID(value.operation_id) || reference !== null && (!googleConfigurationReference(reference) || value.operation_id !== reference.operation_id) ||
    !googleConfigurationClient(value.client_id) || !googleConfigurationOrigin(value.public_url) ||
    value.redirect_uri !== value.public_url + '/api/oauth/callback/google' ||
    !operatorExact(value.profile_binding, googleConfigurationProfile(value.client_id, value.redirect_uri)) ||
    !googleConfigurationTarget(value.old_settings, value.target_settings) || !upstreamDigest(value.expected_settings_digest) ||
    !upstreamDigest(value.profile_binding_digest) || !upstreamDigest(value.policy_hash) ||
    !upstreamRevision(value.reviewed_revision) || !upstreamRevision(value.staged_revision) || value.staged_revision !== value.reviewed_revision + 1 ||
    !upstreamRevision(value.revision) || value.revision < value.staged_revision || !upstreamTime(value.created_at) ||
    value.secret_present !== true || !['pending', 'cancelled', 'activated'].includes(value.status) ||
    !upstreamObject(value.custody_ref, ['owner_id', 'config_version', 'key_source']) || !upstreamUUID(value.custody_ref.owner_id) ||
    !Number.isSafeInteger(value.custody_ref.config_version) || value.custody_ref.config_version < 1 || value.custody_ref.config_version > 16 ||
    value.custody_ref.key_source !== 'operator-provider-key-v1') bad();
  if (value.status === 'pending') {
    if (value.revision !== value.staged_revision || value.completed_at !== null || value.activation_receipt !== null) bad();
  } else if (!upstreamTime(value.completed_at) || Date.parse(value.completed_at) < Date.parse(value.created_at) || value.revision <= value.staged_revision) bad();
  if (value.status === 'cancelled' && value.activation_receipt !== null) bad();
  if (value.status === 'activated') {
    const receipt = value.activation_receipt;
    if (value.revision !== value.staged_revision + 1 || !upstreamObject(receipt, ['schema', 'operation_id', 'activated_revision',
      'policy_hash', 'profile_binding_digest', 'settings_digest', 'activated_at']) ||
      receipt.schema !== 'catchplate.operatorGoogleSetupActivation/v1' || receipt.operation_id !== value.operation_id ||
      receipt.activated_revision !== value.revision || receipt.policy_hash !== value.policy_hash ||
      receipt.profile_binding_digest !== value.profile_binding_digest || !upstreamDigest(receipt.settings_digest) ||
      receipt.activated_at !== value.completed_at) bad();
  }
  return value;
}
function projectGoogleConfiguration(value) {
  const bad = () => { throw operatorError('Google provider settings are unsupported or incomplete. No configuration can be prepared.'); };
  if (!upstreamObject(value, ['schema', 'state', 'revision', 'policy_hash', 'effective_settings', 'effective_settings_digest',
    'public_url', 'redirect_uri', 'permission_preset', 'scopes', 'blocked_reason', 'review', 'operation', 'readiness']) ||
    value.schema !== 'catchplate.operatorGoogleConfiguration/v2' || !['unconfigured', 'pending', 'activated'].includes(value.state) ||
    !upstreamRevision(value.revision) || !upstreamDigest(value.policy_hash) || !upstreamSettings(value.effective_settings) ||
    !upstreamDigest(value.effective_settings_digest) || !googleConfigurationOrigin(value.public_url) ||
    value.redirect_uri !== value.public_url + '/api/oauth/callback/google' || value.permission_preset !== 'gmail_readonly' || !googleScopes(value.scopes) ||
    !upstreamObject(value.readiness, ['pair_ready', 'consent_ready', 'loaded_policy_hash']) ||
    typeof value.readiness.pair_ready !== 'boolean' || typeof value.readiness.consent_ready !== 'boolean' ||
    !(value.readiness.loaded_policy_hash === null || upstreamDigest(value.readiness.loaded_policy_hash)) ||
    value.readiness.pair_ready && value.readiness.loaded_policy_hash !== value.policy_hash ||
    value.readiness.consent_ready && (!value.readiness.pair_ready || value.state !== 'activated') ||
    ![null, 'pending_configuration', 'already_configured', 'pending_destinations', 'capacity'].includes(value.blocked_reason)) bad();
  if (value.state === 'pending' && value.blocked_reason !== 'pending_configuration' ||
    value.state === 'activated' && value.blocked_reason !== 'already_configured' ||
    value.state === 'unconfigured' && ![null, 'pending_destinations', 'capacity'].includes(value.blocked_reason)) bad();
  if (value.review !== null) {
    const review = value.review;
    if (value.state !== 'unconfigured' || value.blocked_reason !== null || !upstreamObject(review, ['schema', 'expected_revision',
      'expected_policy_hash', 'expected_settings_digest', 'old_settings', 'target_settings', 'public_url', 'redirect_uri',
      'provider_id', 'permission_preset', 'scopes', 'eligible']) || review.schema !== 'catchplate.operatorGoogleManagedSetupReview/v2' ||
      review.eligible !== true || review.expected_revision !== value.revision || review.expected_policy_hash !== value.policy_hash ||
      review.expected_settings_digest !== value.effective_settings_digest || !operatorExact(review.old_settings, value.effective_settings) ||
      !googleConfigurationTarget(review.old_settings, review.target_settings) || review.public_url !== value.public_url ||
      review.redirect_uri !== value.redirect_uri || review.provider_id !== 'google' || review.permission_preset !== 'gmail_readonly' || !googleScopes(review.scopes)) bad();
  } else if (value.state === 'unconfigured' && value.blocked_reason === null) bad();
  if (value.operation !== null) {
    const operation = projectGoogleConfigurationOperation(value.operation);
    if (value.state !== operation.status || value.state === 'unconfigured' || operation.revision > value.revision ||
      operation.public_url !== value.public_url || operation.redirect_uri !== value.redirect_uri) bad();
  }
  return value;
}

function projectGoogleActivationHandoff(value, reference, discovery) {
  const receipt = projectGoogleConfigurationOperation(value, reference);
  const current = projectGoogleConfiguration(discovery);
  if (!googleConfigurationReference(reference) || reference.kind !== 'prepare' || receipt.status !== 'pending' ||
      current.state !== 'pending' || !operatorExact(current.operation, receipt) || current.revision !== receipt.staged_revision ||
      current.policy_hash !== receipt.policy_hash || current.effective_settings_digest !== receipt.expected_settings_digest ||
      !operatorExact(current.effective_settings, receipt.old_settings))
    throw operatorError('Review the exact pending Google operation again before downloading its handoff.');
  // Do not export the OAuth client ID, profile/custody objects or any secret fields.
  return {schema: 'catchplate.operatorActivationHandoff/v1', change_kind: 'managed_google',
    operation_id: receipt.operation_id, observed_status: 'pending', prepared_at: receipt.created_at,
    reviewed_revision: receipt.reviewed_revision, prepared_revision: receipt.staged_revision,
    policy_hash: receipt.policy_hash, expected_settings_digest: receipt.expected_settings_digest,
    profile_binding_digest: receipt.profile_binding_digest,
    current_origins: [...receipt.old_settings.allowed_upstreams], target_origins: [...receipt.target_settings.allowed_upstreams],
    status_path: googleConfigurationPath + '/' + receipt.operation_id,
    next_step: 'Perform the separately reviewed app/proxy restart with managed provider custody preserved. Do not export the secret or add the legacy Google environment layer.',
    runbook_url: activationHandoffRunbook, notice: activationHandoffNotice};
}

function createGoogleConfigurationView(workspace) {
  const panel = element('google-configuration-panel');
  element('proxy-operator-settings').append(panel);
  let discovery = null; let reference = null; let receipt = null; let retainedRaw = null;
  let visible = false; let busy = false; let storageBlocked = false; let recoveryHint = null;
  const holdOwner = 'google-provider-configuration';
  try {
    const raw = sessionStorage.getItem(googleConfigurationKey);
    if (raw !== null) { if (raw.length > 128) throw new Error(); const parsed = JSON.parse(raw);
      if (!googleConfigurationReference(parsed)) throw new Error(); reference = parsed; retainedRaw = raw; }
  } catch (_) { storageBlocked = true; }
  const clearSecret = () => { element('google-configuration-client-secret').value = ''; };
  const say = value => { element('google-configuration-status').textContent = value; };
  const unresolved = () => reference !== null && (receipt === null || reference.kind === 'cancel' && receipt.status === 'pending');
  const current = () => discovery && workspace.state.catalog && discovery.revision === workspace.state.catalog.revision &&
    discovery.policy_hash === workspace.state.catalog.policy.policy_hash &&
    operatorExact(discovery.effective_settings.allowed_upstreams, workspace.state.catalog.allowed_upstreams);
  const canWrite = () => visible && !busy && !storageBlocked && !workspace.state.busy && !workspace.state.uncertain && current();
  const canCancel = () => visible && !busy && !storageBlocked && !workspace.state.busy && !workspace.state.uncertain &&
    !unresolved() && receipt?.status === 'pending' && reference?.kind === 'prepare';
  function handoff() {
    if (!visible || busy || storageBlocked || workspace.state.busy || !current() || unresolved()) return null;
    try { return projectGoogleActivationHandoff(receipt, reference, discovery); } catch (_) { return null; }
  }
  function validInput() {
    const secret = element('google-configuration-client-secret').value;
    return googleConfigurationClient(element('google-configuration-client-id').value) && secret.length > 0 &&
      secret === secret.trim() && !/[\u0000\r\n]/.test(secret) && new TextEncoder().encode(secret).length <= 4096;
  }
  function retain(next) {
    try { const raw = JSON.stringify(next); sessionStorage.setItem(googleConfigurationKey, raw);
      reference = next; retainedRaw = raw; receipt = null; return true; }
    catch (_) { storageBlocked = true; return false; }
  }
  function terminalCurrent() {
    if (!reference || !receipt || !current() || receipt.operation_id !== reference.operation_id ||
      receipt.revision > discovery.revision || receipt.policy_hash !== discovery.policy_hash ||
      receipt.public_url !== discovery.public_url || receipt.redirect_uri !== discovery.redirect_uri) return false;
    if (receipt.status === 'cancelled') return discovery.state === 'unconfigured' && discovery.operation === null &&
      discovery.effective_settings_digest === receipt.expected_settings_digest && operatorExact(discovery.effective_settings, receipt.old_settings);
    return receipt.status === 'activated' && discovery.state === 'activated' && operatorExact(discovery.operation, receipt) &&
      discovery.effective_settings_digest === receipt.activation_receipt.settings_digest && operatorExact(discovery.effective_settings, receipt.target_settings);
  }
  function acknowledgeTerminal() {
    // The core's earlier click listener must have accepted this explicit review
    // acknowledgement. Never release another owner's hold or infer a terminal
    // result from discovery alone. Keep the verified history visible in memory.
    if (busy || storageBlocked || workspace.state.busy || workspace.state.uncertain || retainedRaw === null || !terminalCurrent()) return;
    try {
      if (sessionStorage.getItem(googleConfigurationKey) !== retainedRaw || !operatorExact(JSON.parse(retainedRaw), reference)) throw new Error();
      sessionStorage.removeItem(googleConfigurationKey);
      if (sessionStorage.getItem(googleConfigurationKey) !== null) throw new Error();
      retainedRaw = null;
    } catch (_) {
      storageBlocked = true;
      workspace.requireReview('Google provider recovery could not retire its exact completed reference safely. Review Google recovery status; do not repeat the request.');
    }
    update();
  }
  function update() {
    if (recoveryHint) recoveryHint.hidden = !storageBlocked && !unresolved();
    workspace.setConsentHold(busy || storageBlocked || unresolved(), holdOwner); render();
  }
  function operationText() {
    if (storageBlocked) return 'The public operation reference could not be retained safely in this tab. Changes are blocked; do not repeat an uncertain request.';
    if (!reference) return 'No Google provider configuration has been prepared in this tab.';
    if (!receipt) return 'Outcome unconfirmed. Check the retained operation using read-only recovery. A missing receipt does not prove failure; do not prepare another operation.';
    if (receipt.status === 'pending') return reference.kind === 'cancel' ?
      'Cancellation is unconfirmed. The last read still showed a pending configuration. Check again; cancellation is never resent automatically.' :
      'Prepared — a separate controlled restart is required. Google configuration has not been activated by this request.';
    return receipt.status === 'cancelled' ? 'Cancelled. This retained operation did not activate Google configuration. Review current settings before preparing another.' :
      'Activation is recorded for this operation. Exact app/proxy readiness is a separate current check below; this is not Google consent or a successful provider request.';
  }
  function render() {
    const eligible = current() && discovery.review !== null;
    element('google-configuration-review').disabled = busy || workspace.writeInFlight();
    element('google-configuration-form').hidden = !discovery?.review;
    element('google-configuration-fields').disabled = !canWrite() || !eligible || unresolved() || receipt?.status === 'pending';
    element('google-configuration-prepare').disabled = !canWrite() || !eligible || unresolved() || receipt?.status === 'pending' || !validInput();
    element('google-configuration-check').disabled = busy || storageBlocked || !reference || workspace.writeInFlight();
    element('google-configuration-cancel').disabled = !canCancel();
    element('google-configuration-handoff').disabled = handoff() === null;
    element('google-configuration-callback').textContent = discovery?.redirect_uri || 'Review provider settings to get this deployment’s exact callback URL.';
    element('google-configuration-scopes').textContent = discovery ? discovery.scopes.join('\n') : 'Read Gmail (gmail_readonly); exact scopes are shown after review.';
    element('google-configuration-added-upstream').textContent = !discovery?.review ? 'No configuration change is currently eligible.' :
      discovery.effective_settings.allowed_upstreams.includes('https://gmail.googleapis.com') ? 'None — https://gmail.googleapis.com is already an allowed destination.' : 'https://gmail.googleapis.com';
    element('google-configuration-discovery-state').textContent = !discovery ? 'Google provider configuration has not been reviewed.' : !current() ?
      'Workspace state changed. Review Google provider settings again; previous readiness is not current.' : discovery.state === 'unconfigured' ?
      discovery.blocked_reason === 'pending_destinations' ? 'Resolve the pending proxy destination change first.' :
      discovery.blocked_reason === 'capacity' ? 'Configuration capacity is reached. No new preparation is available.' :
      'Not configured. Preparation stores the application secret and records an exact configuration for a separate controlled restart.' :
      discovery.state === 'pending' ? 'A Google provider configuration is pending. A controlled restart is required; no account consent was started.' :
      discovery.readiness.consent_ready ? 'Activated. The exact app/proxy pair was ready at the last check. Account consent is separate and is checked again when started.' :
      'Activated, but the exact app/proxy pair is not confirmed ready. Refresh this review before connecting an account.';
    element('google-configuration-review-state').textContent = !discovery?.review ? '' : current() ?
      'Reviewed: Read Gmail only, the callback and scopes above, and the listed destination addition. Prepare does not restart services or contact Google.' : 'Review changed. Review again before submitting.';
    element('google-configuration-operation').hidden = !reference && !storageBlocked;
    element('google-configuration-operation-status').textContent = operationText();
    element('google-configuration-operation-reference').textContent = reference?.operation_id || '';
    element('google-configuration-prepared').hidden = !receipt;
    element('google-configuration-prepared-client').textContent = receipt?.client_id || '';
    element('google-configuration-prepared-upstreams').textContent = receipt ? receipt.target_settings.allowed_upstreams.join('\n') : '';
    element('google-configuration-connect-link').hidden = !current() || discovery?.readiness.consent_ready !== true;
  }
  async function request(path, method = 'GET', payload = null) {
    let pending;
    try {
      pending = fetch(path, {method, credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        signal: AbortSignal.timeout(30000), ...(payload ? {headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)} : {})});
    } catch (_) { throw operatorError('The response was lost or unavailable. Keep the operation reference and check its result; do not repeat the request.'); }
    finally { if (payload && Object.hasOwn(payload, 'client_secret')) payload.client_secret = ''; payload = null; clearSecret(); }
    let response;
    try { response = await pending; }
    catch (_) { throw operatorError('The response was lost or unavailable. Keep the operation reference and check its result; do not repeat the request.'); }
    if ([401, 403].includes(response.status)) { workspace.state.catalog = null; workspace.emit(); }
    let body = null;
    try { const raw = await response.text(); if (!response.headers.get('content-type')?.includes('application/json') || raw.length > 32768) throw new Error(); body = JSON.parse(raw); }
    catch (_) { /* Never display response bodies or raw exceptions. */ }
    if (!response.ok) {
      const rejected = method === 'POST' && response.status === 422 && upstreamObject(body, ['detail']) && body.detail === 'invalid operator catalog input';
      const error = operatorError([401, 403].includes(response.status) ? 'Your session could not be verified. Sign in again and retain any operation reference.' :
        response.status === 404 && path === googleConfigurationPath && method === 'GET' ?
          'Self-service Google provider configuration is unavailable in this deployment. Existing externally configured account connections are unchanged.' :
        response.status === 404 ? 'No actor-owned receipt was found. This does not prove failure or permit a retry. Retain the reference and check again.' :
        rejected ? 'The fields were rejected before configuration preparation. Review again and re-enter the secret for a new explicit request.' :
        'The Google configuration outcome is unconfirmed. Check the retained reference; do not resubmit or prepare another operation.');
      error.googleConfigurationRejectedInput = rejected; throw error;
    }
    if (response.status !== (method === 'POST' && path === googleConfigurationPath ? 201 : 200))
      throw operatorError('The response could not be verified. Keep the operation reference and use read-only recovery.');
    return body;
  }
  async function loadDiscovery() {
    discovery = null; // Failed post-write reads must never retain a pre-write review.
    discovery = projectGoogleConfiguration(await request(googleConfigurationPath));
    // Adopt only the explicitly selected actor-owned operation, never a latest
    // historical row, and never replace an unresolved tab reference.
    if (!reference && discovery.operation) {
      const selected = {operation_id: discovery.operation.operation_id, kind: 'prepare'};
      if (discovery.operation.status === 'pending') {
        if (retain(selected)) receipt = discovery.operation;
      } else {
        // Reviewing already-activated settings is not an interrupted mutation.
        // Do not recreate a persistent recovery hold on the next page load.
        reference = selected; receipt = discovery.operation;
      }
    }
    await workspace.refresh();
  }
  async function refresh() {
    if (busy || workspace.writeInFlight()) return;
    clearSecret(); busy = true; update();
    try { await loadDiscovery(); say('Google provider settings reviewed. No configuration, restart or account consent was performed.'); }
    catch (error) { clearSecret(); discovery = null; say(operatorMessage(error)); }
    finally { busy = false; update(); }
  }
  function retireRejected(priorReference, priorReceipt, priorRaw) {
    try {
      if (priorRaw !== null) sessionStorage.setItem(googleConfigurationKey, priorRaw);
      else sessionStorage.removeItem(googleConfigurationKey);
      reference = priorReference; receipt = priorReceipt; retainedRaw = priorRaw;
    } catch (_) { storageBlocked = true; }
  }
  async function submit(kind) {
    if (!canWrite()) { clearSecret(); return; }
    if (kind === 'prepare' && (!discovery.review || unresolved() || receipt?.status === 'pending' || !validInput()) || kind === 'cancel' &&
      (receipt?.status !== 'pending' || reference?.kind !== 'prepare' || unresolved() || discovery.operation?.operation_id !== reference.operation_id)) {
      clearSecret(); render(); return;
    }
    const priorReference = reference; const priorReceipt = receipt; const priorRaw = retainedRaw; const reviewed = discovery;
    let payload = null;
    try {
      payload = kind === 'prepare' ? {operation_id: crypto.randomUUID(), client_id: element('google-configuration-client-id').value,
        client_secret: element('google-configuration-client-secret').value, expected_revision: reviewed.revision,
        expected_policy_hash: reviewed.policy_hash, expected_settings_digest: reviewed.effective_settings_digest} :
        {operation_id: reference.operation_id, expected_revision: reviewed.revision, expected_policy_hash: reviewed.policy_hash};
    } catch (_) {
      say('The configuration request could not be prepared. No request was sent. Review again before entering the secret.');
      discovery = null; return;
    } finally { clearSecret(); render(); }
    const requestedClient = payload.client_id;
    if (!retain({operation_id: payload.operation_id, kind})) { if (Object.hasOwn(payload, 'client_secret')) payload.client_secret = ''; payload = null;
      say('The operation reference could not be retained. No request was sent; changes remain blocked in this tab.'); update(); return; }
    busy = true; update(); say('Submitting once. Preparation does not restart services or contact Google.');
    try {
      const pending = request(googleConfigurationPath + (kind === 'cancel' ? '/cancel' : ''), 'POST', payload);
      payload = null; // request synchronously serialized and cleared client_secret before its first await.
      const result = projectGoogleConfigurationOperation(await pending, reference);
      if (result.status !== (kind === 'prepare' ? 'pending' : 'cancelled') || kind === 'prepare' &&
        (result.client_id !== requestedClient || result.reviewed_revision !== reviewed.revision || result.policy_hash !== reviewed.policy_hash ||
          result.expected_settings_digest !== reviewed.effective_settings_digest || !operatorExact(result.old_settings, reviewed.effective_settings) ||
          result.public_url !== reviewed.public_url || result.redirect_uri !== reviewed.redirect_uri))
        throw operatorError('The receipt does not match the reviewed operation. Retain its reference and check the result; do not repeat.');
      receipt = result;
      await loadDiscovery(); say(operationText());
    } catch (error) {
      discovery = null;
      if (error.googleConfigurationRejectedInput) retireRejected(priorReference, priorReceipt, priorRaw);
      say(operatorMessage(error));
    } finally { if (payload && Object.hasOwn(payload, 'client_secret')) payload.client_secret = ''; payload = null; clearSecret(); busy = false; update(); }
  }
  async function check() {
    if (busy || !reference || storageBlocked || workspace.writeInFlight()) return;
    clearSecret(); busy = true; update();
    try { receipt = projectGoogleConfigurationOperation(await request(googleConfigurationPath + '/' + reference.operation_id), reference);
      await loadDiscovery(); say(operationText()); }
    catch (error) { clearSecret(); receipt = null; discovery = null; say(operatorMessage(error)); }
    finally { busy = false; update(); }
  }
  async function cancel() {
    if (!canCancel()) { clearSecret(); return; }
    const operationId = reference.operation_id;
    clearSecret(); busy = true; update();
    let reviewed = false;
    try {
      await loadDiscovery();
      if (!current() || discovery.state !== 'pending' || discovery.operation?.operation_id !== operationId ||
        reference?.operation_id !== operationId || unresolved())
        throw operatorError('The selected pending configuration changed. No cancellation was sent. Check its operation result and review current settings.');
      reviewed = true;
    } catch (error) { clearSecret(); discovery = null; say(operatorMessage(error)); }
    finally { busy = false; update(); }
    if (reviewed) return submit('cancel');
  }
  element('google-configuration-review').addEventListener('click', refresh);
  element('google-configuration-form').addEventListener('submit', event => { event.preventDefault(); return submit('prepare'); });
  element('google-configuration-form').addEventListener('invalid', clearSecret, true);
  for (const id of ['google-configuration-client-id', 'google-configuration-client-secret']) element(id).addEventListener('input', render);
  element('google-configuration-check').addEventListener('click', check);
  element('google-configuration-cancel').addEventListener('click', cancel);
  element('google-configuration-handoff').addEventListener('click', () => {
    clearSecret(); const value = handoff(); render(); if (value === null) return;
    try { downloadActivationHandoff(value); say('Downloaded public Google activation handoff. No secret was exported, services restarted or consent started; the deployment owner must recheck the operation.'); }
    catch (_) { say('The public handoff could not be downloaded. Keep the operation reference and use the activation guide; no settings were changed.'); }
  });
  element('mutation-review-confirm').addEventListener('click', acknowledgeTerminal);
  window.addEventListener('pagehide', clearSecret);
  if (reference || storageBlocked) {
    const message = storageBlocked ?
      'Google provider configuration recovery is blocked because this tab could not safely read its public operation reference. Open Proxy setup → Google provider settings to inspect recovery status; do not repeat a possibly saved request.' :
      'Google provider configuration needs a status check. Open Proxy setup → Google provider settings → Check operation result before allowing another change. The public operation reference is retained; no request has been repeated.';
    recoveryHint = textNode('p'); recoveryHint.id = 'google-configuration-recovery-hint';
    recoveryHint.append(textNode('span', message), ' ');
    const link = textNode('a', storageBlocked ? 'Review Google recovery status' : 'Check Google configuration result');
    link.id = 'google-configuration-recovery-link'; link.href = '#google-configuration-panel'; recoveryHint.append(link);
    // Keep another owner's warning and hold intact. requireReview replaces only
    // its text paragraph, so this owner-scoped navigation survives later alerts.
    element('mutation-review').append(recoveryHint);
    if (!workspace.state.uncertain) workspace.requireReview('Google provider configuration recovery is required. Use the Google status link below before allowing another change.');
    else element('mutation-review').hidden = false;
  }
  workspace.subscribe(render); update();
  return {show(active) { visible = active; if (!active) clearSecret(); render(); }};
}

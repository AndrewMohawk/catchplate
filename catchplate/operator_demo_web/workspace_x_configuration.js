// First-save provider settings only. No account consent or provider request is
// performed here; storage retains only an unresolved public operation UUID.
const xConfigurationPath = '/api/operator-demo/oauth/x/configuration/v1';
const xConfigurationKey = 'catchplate.operator.x.configuration.operation.v1';
const xConfigurationScopes = Object.freeze(['offline.access', 'tweet.read', 'tweet.write', 'users.read']);
const xConfigurationClient = value => typeof value === 'string' && /^[\x21-\x7e]{1,256}$/.test(value);
function xConfigurationProfile(client) {
  return {schema: 'catchplate.operatorXOAuthProfile/v1', profile: 'operator-x-oauth-v1', provider_id: 'x',
    client_id: client, redirect_uri: location.origin + '/api/oauth/callback/x', client_auth_method: 'client_secret_basic',
    permission_preset: 'x_text_post_v1', scopes: [...xConfigurationScopes], api_origins: ['https://api.x.com'],
    authorization_url: 'https://x.com/i/oauth2/authorize', token_url: 'https://api.x.com/2/oauth2/token',
    revocation_url: 'https://api.x.com/2/oauth2/revoke', identity_url: 'https://api.x.com/2/users/me'};
}
function xConfigurationBinding(value) {
  return value && xConfigurationClient(value.client_id) && location.protocol === 'https:' &&
    operatorExact(value, xConfigurationProfile(value.client_id));
}
function projectXConfigurationOperation(value, operationId = null) {
  if (!upstreamObject(value, ['schema', 'operation_id', 'status', 'config_version', 'committed_revision', 'policy_hash',
    'profile_binding_digest', 'public_profile', 'client_secret_configured', 'consent_ready']) ||
    value.schema !== 'catchplate.operatorXConfigurationOperation/v1' || !upstreamUUID(value.operation_id) ||
    operationId !== null && value.operation_id !== operationId || value.status !== 'committed' || value.config_version !== 1 ||
    !upstreamRevision(value.committed_revision) || value.committed_revision < 2 || !upstreamDigest(value.policy_hash) ||
    !upstreamDigest(value.profile_binding_digest) || !xConfigurationBinding(value.public_profile) ||
    value.client_secret_configured !== true || value.consent_ready !== false)
    throw operatorError('The X application receipt could not be verified. Keep its reference and check the result; do not resubmit.');
  return value;
}
function projectXConfiguration(value) {
  const bad = () => { throw operatorError('X application settings are unsupported or incomplete. No change can be saved.'); };
  if (!upstreamObject(value, ['schema', 'state', 'revision', 'policy_hash', 'redirect_uri', 'permission_preset', 'scopes',
    'configuration', 'operation', 'review', 'blocked_reason', 'consent_ready']) ||
    value.schema !== 'catchplate.operatorXConfiguration/v1' || !['unconfigured', 'configured'].includes(value.state) ||
    !upstreamRevision(value.revision) || !upstreamDigest(value.policy_hash) || location.protocol !== 'https:' ||
    value.redirect_uri !== location.origin + '/api/oauth/callback/x' || value.permission_preset !== 'x_text_post_v1' ||
    !operatorExact(value.scopes, xConfigurationScopes) || value.consent_ready !== false ||
    ![null, 'already_configured', 'pending_google_configuration', 'pending_upstream_configuration'].includes(value.blocked_reason)) bad();
  if (value.state === 'configured') {
    const config = value.configuration;
    if (value.blocked_reason !== 'already_configured' || value.review !== null ||
      !upstreamObject(config, ['config_version', 'profile_binding_digest', 'public_profile', 'client_secret_configured']) ||
      config.config_version !== 1 || !upstreamDigest(config.profile_binding_digest) ||
      !xConfigurationBinding(config.public_profile) || config.client_secret_configured !== true) bad();
    if (value.operation !== null) {
      const operation = projectXConfigurationOperation(value.operation);
      if (operation.committed_revision > value.revision ||
        operation.committed_revision === value.revision && operation.policy_hash !== value.policy_hash || operation.config_version !== config.config_version ||
        operation.profile_binding_digest !== config.profile_binding_digest || !operatorExact(operation.public_profile, config.public_profile)) bad();
    }
  } else {
    if (value.configuration !== null || value.operation !== null || value.blocked_reason === 'already_configured') bad();
    if (value.blocked_reason === null) {
      if (!upstreamObject(value.review, ['expected_revision', 'expected_policy_hash']) ||
        value.review.expected_revision !== value.revision || value.review.expected_policy_hash !== value.policy_hash) bad();
    } else if (value.review !== null) bad();
  }
  return value;
}

function createXConfigurationView(workspace) {
  const panel = element('x-configuration-panel');
  element('proxy-operator-settings').append(panel);
  let discovery = null; let receipt = null; let operationId = null;
  let visible = false; let busy = false; let storageBlocked = false;
  let available = null; let reviewedOnce = false;
  const holdOwner = 'x-provider-configuration';
  try {
    const saved = sessionStorage.getItem(xConfigurationKey);
    if (saved !== null) { if (!upstreamUUID(saved)) throw new Error(); operationId = saved; }
  } catch (_) { storageBlocked = true; }
  const clearSecret = () => { element('x-configuration-client-secret').value = ''; };
  const say = text => { element('x-configuration-status').textContent = text; };
  const unresolved = () => operationId !== null && receipt === null;
  const current = () => discovery && workspace.state.catalog && discovery.revision === workspace.state.catalog.revision &&
    discovery.policy_hash === workspace.state.catalog.policy.policy_hash;
  const profile = () => discovery?.configuration?.public_profile || receipt?.public_profile || null;
  function validInput() {
    const secret = element('x-configuration-client-secret').value;
    return xConfigurationClient(element('x-configuration-client-id').value) && secret.length > 0 && secret === secret.trim() &&
      !/[\u0000\r\n]/.test(secret) && new TextEncoder().encode(secret).length <= 4096;
  }
  const canSave = () => visible && !busy && !storageBlocked && !workspace.state.busy && !workspace.state.uncertain &&
    current() && discovery.review !== null && !operationId && !receipt && validInput();
  function render() {
    const saved = profile();
    const displayedOperation = operationId || receipt?.operation_id || null;
    panel.hidden = available !== true && !operationId;
    element('x-configuration-settings').hidden = available !== true;
    element('x-configuration-review').hidden = available === false;
    element('x-configuration-review').disabled = busy || workspace.writeInFlight();
    element('x-configuration-form').hidden = !discovery?.review || Boolean(saved);
    element('x-configuration-fields').disabled = !visible || busy || storageBlocked || workspace.state.busy ||
      workspace.state.uncertain || !current() || operationId !== null;
    element('x-configuration-save').disabled = !canSave();
    element('x-configuration-callback').textContent = discovery?.redirect_uri || saved?.redirect_uri ||
      'Review settings to get this deployment’s exact callback URL.';
    element('x-configuration-copy').disabled = !discovery && !saved;
    element('x-configuration-scopes').textContent = discovery || saved ? xConfigurationScopes.join('\n') : 'Exact scopes are shown after review.';
    element('x-configuration-saved').hidden = !saved;
    element('x-configuration-saved-client').textContent = saved?.client_id || '';
    element('x-configuration-operation').hidden = !displayedOperation;
    element('x-configuration-operation-reference').textContent = displayedOperation || '';
    element('x-configuration-check').disabled = busy || storageBlocked || !operationId || workspace.writeInFlight();
    element('x-configuration-consent').textContent = saved ?
      (workspace.state.catalog?.capabilities?.x_oauth ?
        'Application settings are saved. Connect an X account in Credentials, then grant a separate posting permission. No post or provider-access test was run here.' :
        'Application settings are saved. Account consent is unavailable until the current paired gate is ready. Saving settings does not connect an account or grant posting.') :
      'Save application settings first. Account consent and posting permissions are separate steps.';
    element('x-configuration-account-link').hidden = !saved || !workspace.state.catalog?.capabilities?.x_oauth;
    if (discovery && !current() && !busy && !unresolved())
      say('Workspace state changed. Review X application settings again before saving.');
  }
  function update() { workspace.setConsentHold(busy || available !== false && storageBlocked || unresolved(), holdOwner); render(); }
  function summary() {
    if (storageBlocked) return 'The public save reference could not be retained safely. Changes are blocked in this tab; do not repeat an uncertain save.';
    if (unresolved()) return 'Save outcome unconfirmed. Use Check result; do not submit another save. A missing receipt does not prove failure.';
    if (profile()) return 'X application saved. No restart is required. Account consent and posting are separate; no provider request was made by this save.';
    if (!discovery) return 'X application settings have not been reviewed.';
    if (!current()) return 'Workspace state changed. Review X application settings again before saving.';
    if (discovery.blocked_reason === 'pending_google_configuration') return 'Resolve the pending Google configuration before saving an X application.';
    if (discovery.blocked_reason === 'pending_upstream_configuration') return 'Resolve the pending destination change before saving an X application.';
    return 'Not configured. Enter the OAuth Client ID and Client secret to save this application.';
  }
  async function request(path, payload = null) {
    const writing = payload !== null;
    let pending;
    try {
      pending = fetch(path, {method: writing ? 'POST' : 'GET', credentials: 'same-origin', cache: 'no-store', redirect: 'error',
        signal: AbortSignal.timeout(30000), ...(writing ? {headers: {'Content-Type': 'application/json'}, body: JSON.stringify(payload)} : {})});
    } catch (_) { throw operatorError('The response was unavailable. Keep the save reference and check its result; do not resubmit.'); }
    finally { if (payload) payload.client_secret = ''; payload = null; clearSecret(); }
    let response;
    try { response = await pending; }
    catch (_) { throw operatorError('The response was lost. Keep the save reference and check its result; do not resubmit.'); }
    if ([401, 403].includes(response.status)) { workspace.state.catalog = null; workspace.emit(); }
    let value = null;
    try { const raw = await response.text(); if (!response.headers.get('content-type')?.includes('application/json') || raw.length > 32768) throw new Error(); value = JSON.parse(raw); }
    catch (_) { /* Never render a response body or raw exception. */ }
    if (!response.ok) {
      const rejected = writing && response.status === 422 && upstreamObject(value, ['detail']) && value.detail === 'invalid operator catalog input';
      const error = operatorError([401, 403].includes(response.status) ? 'Your session could not be verified. Sign in again and keep any save reference.' :
        response.status === 404 && path === xConfigurationPath && !writing ? 'X application configuration is unavailable in this deployment. No settings were changed.' :
        response.status === 404 ? 'No actor-owned save receipt was found. This does not prove failure or permit a retry. Keep the reference and check again.' :
        rejected ? 'The fields were rejected before saving. Review the settings and re-enter the secret for a new explicit save.' :
        'The X application result is unconfirmed. Keep the save reference and check it; do not resubmit.');
      error.xConfigurationRejectedInput = rejected;
      error.xConfigurationUnavailable = response.status === 404 && path === xConfigurationPath && !writing;
      throw error;
    }
    if (response.status !== (writing ? 201 : 200))
      throw operatorError('The response could not be verified. Keep any save reference and use Check result.');
    return value;
  }
  function retain(id) {
    try { sessionStorage.setItem(xConfigurationKey, id); operationId = id; return true; }
    catch (_) { storageBlocked = true; return false; }
  }
  function retire(id) {
    try {
      if (operationId !== id || sessionStorage.getItem(xConfigurationKey) !== id) throw new Error();
      sessionStorage.removeItem(xConfigurationKey);
      if (sessionStorage.getItem(xConfigurationKey) !== null) throw new Error();
      operationId = null;
    } catch (_) {
      storageBlocked = true;
      throw operatorError('The confirmed save reference could not be cleared safely. Keep its reference and inspect recovery before another change.');
    }
  }
  async function load() {
    discovery = null;
    const next = projectXConfiguration(await request(xConfigurationPath));
    if (receipt && (next.state !== 'configured' || receipt.profile_binding_digest !== next.configuration.profile_binding_digest ||
      !operatorExact(receipt.public_profile, next.configuration.public_profile) || receipt.committed_revision > next.revision ||
      receipt.committed_revision === next.revision && receipt.policy_hash !== next.policy_hash))
      throw operatorError('Saved X settings and the operation receipt disagree. Keep the reference and check again; do not save another application.');
    // A historical committed receipt is read-only information, not a new
    // unresolved save. Merely viewing settings must not create a reload hold.
    if (!operationId) receipt = next.operation;
    // A discovery read may resolve only this exact retained operation, never a
    // different actor's setting or an unrelated/latest historical operation.
    if (operationId && next.operation?.operation_id === operationId) receipt = next.operation;
    discovery = next; available = true;
    const refreshed = await workspace.refresh();
    if (operationId && receipt) {
      if (!refreshed || !current())
        throw operatorError('Saved X settings could not be joined to current workspace state. Keep the reference and check again; no new save was sent.');
      retire(operationId);
    }
  }
  async function review() {
    if (busy || workspace.writeInFlight()) return;
    reviewedOnce = true; clearSecret(); busy = true; update();
    try { await load(); say(summary()); }
    catch (error) {
      discovery = null; receipt = null; available = !error.xConfigurationUnavailable; say(operatorMessage(error));
      if (!available && operationId) {
        say('X configuration is unavailable, but this earlier save remains unresolved. Keep its operation ID and use Check result when recovery is available; do not save again.');
        workspace.requireReview('An earlier X application save is unresolved. Open Proxy setup → X (Twitter) application → Check result. Keep its public operation ID; do not repeat the save.');
      }
    }
    finally { busy = false; update(); }
  }
  async function save() {
    if (!canSave()) { clearSecret(); render(); return; }
    const reviewed = discovery;
    const requestedClient = element('x-configuration-client-id').value;
    let payload = null;
    try {
      payload = {operation_id: crypto.randomUUID(), client_id: requestedClient,
        client_secret: element('x-configuration-client-secret').value,
        expected_revision: reviewed.revision, expected_policy_hash: reviewed.policy_hash};
      if (!retain(payload.operation_id)) { say('The save reference could not be retained. No request was sent.'); return; }
      busy = true; update(); say('Saving the X application once. No consent or provider request is started.');
      const pending = request(xConfigurationPath, payload);
      payload = null; // request serialized synchronously and discarded its secret.
      const result = projectXConfigurationOperation(await pending, operationId);
      if (result.committed_revision !== reviewed.revision + 1 || result.policy_hash !== reviewed.policy_hash ||
        result.public_profile.client_id !== requestedClient)
        throw operatorError('The receipt does not match this save. Keep its reference and check the result; do not resubmit.');
      receipt = result;
      await load(); say(summary());
    } catch (error) {
      discovery = null;
      if (error.xConfigurationRejectedInput) {
        try { retire(operationId); } catch (_) { /* Preserve the storage hold. */ }
      } else if (operationId) workspace.requireReview('X application save could not be fully confirmed. Use Check result with its retained operation ID before allowing another change.');
      say(receipt ? 'A save receipt was returned, but current settings could not be rechecked. Use Check result; no new save was sent.' : operatorMessage(error));
      receipt = null;
    } finally {
      if (payload) payload.client_secret = ''; payload = null; clearSecret(); busy = false; update();
    }
  }
  async function check() {
    if (busy || storageBlocked || !operationId || workspace.writeInFlight()) return;
    clearSecret(); busy = true; update();
    try {
      receipt = projectXConfigurationOperation(await request(xConfigurationPath + '/' + operationId), operationId);
      await load(); say(summary());
    } catch (error) { discovery = null; receipt = null; say(operatorMessage(error)); }
    finally { busy = false; update(); }
  }
  element('x-configuration-review').addEventListener('click', review);
  element('x-configuration-form').addEventListener('submit', event => { event.preventDefault(); return save(); });
  element('x-configuration-form').addEventListener('invalid', clearSecret, true);
  for (const id of ['x-configuration-client-id', 'x-configuration-client-secret']) element(id).addEventListener('input', render);
  element('x-configuration-check').addEventListener('click', check);
  element('x-configuration-copy').addEventListener('click', async () => {
    const callback = discovery?.redirect_uri || profile()?.redirect_uri;
    if (!callback) return;
    try { await navigator.clipboard.writeText(callback); say('Callback URL copied. No secret or consent link was copied.'); }
    catch (_) { say('Copy was unavailable. Select and copy the displayed callback URL.'); }
  });
  window.addEventListener('pagehide', clearSecret);
  window.addEventListener('hashchange', clearSecret);
  workspace.subscribe(() => {
    render();
    if (visible && !reviewedOnce && !busy && !workspace.writeInFlight()) void review();
  });
  say(summary());
  if (operationId || storageBlocked) workspace.requireReview(storageBlocked ?
    'X application save recovery is blocked because this tab cannot safely read its public operation reference. Open Proxy setup → X (Twitter) application to inspect the recovery status; do not repeat a possibly saved request.' :
    'An earlier X application save is unresolved. Open Proxy setup → X (Twitter) application → Check result before allowing another change. The public operation ID is retained in this tab.');
  update();
  return {show(active) {
    visible = active; if (!active) clearSecret();
    if (active && !reviewedOnce) return review();
    render();
  }};
}

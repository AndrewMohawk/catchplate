// Only a public operation UUID is retained. OAuth state, codes, authorization
// URLs and provider credentials never enter browser storage or rendered output.
const xAccountStorageKey = 'serverware.operator.x.account.operation.v1';
const xAccountScopes = Object.freeze(['offline.access', 'tweet.read', 'tweet.write', 'users.read']);
function xAccountCapabilityDescriptor() {
  return {schema: 'serverware.operatorXOAuth/v1', connection_type: 'x_user_oauth_v1', auth_type: 'x_oauth',
    permission_preset: 'x_text_post_v1', start_path: '/api/operator-demo/oauth/x/start',
    operation_path_prefix: '/api/operator-demo/oauth/x/operations/',
    disconnect_review_path_template: '/api/operator-demo/oauth/x/accounts/{credential_id}/disconnect-review',
    disconnect_path: '/api/operator-demo/oauth/x/disconnect', source_pair_required: true,
    automatic_refresh: true, daily_quota_available: false};
}
function projectXAccountCapability(value) { return operatorExact(value, xAccountCapabilityDescriptor()) ? xAccountCapabilityDescriptor() : null; }
function xAccountIdentity(value) {
  return Object.fromEntries(['id', 'status', 'connection_type', 'auth_type', 'header_name', 'provider_id', 'provider_account',
    'provider_subject', 'oauth_client_id', 'permission_preset', 'scopes', 'credential_generation'].map(key => [key, value?.[key]]));
}
function projectXAccount(value) {
  const bad = () => { throw operatorError('Saved X account metadata is incomplete. Changes are disabled.'); };
  if (!xPostCredentialValid(value) || !['active', 'quarantined', 'revoked'].includes(value.status) ||
      !Number.isSafeInteger(value.active_rule_count) || value.active_rule_count < 0 ||
      !(value.status === 'revoked' ? value.credential_generation === null :
        Number.isSafeInteger(value.credential_generation) && value.credential_generation > 0)) bad();
  const result = xAccountIdentity(value);
  if (value.status === 'quarantined') {
    if (typeof value.quarantined_at !== 'string' || value.quarantined_at.length > 64 || !Number.isFinite(Date.parse(value.quarantined_at)) ||
        value.quarantine_reason !== 'operator_x_cleanup_fence' || value.provider_revocation_status !== 'not_proven' || value.active_rule_count !== 0) bad();
    Object.assign(result, {quarantined_at: value.quarantined_at, quarantine_reason: value.quarantine_reason, provider_revocation_status: 'not_proven'});
  }
  return result;
}
function projectXAccountOperation(value, id) {
  const statuses = ['consent_pending', 'exchanging', 'connected', 'denied', 'failed', 'uncertain', 'disconnect_pending', 'disconnected'];
  const reasons = [null, 'consent_denied', 'expired', 'exchange_failed', 'refresh_failed', 'persistence_failed', 'identity_conflict', 'cleanup_unconfirmed'];
  if (!upstreamObject(value, ['schema', 'operation_id', 'kind', 'status', 'credential_id', 'reason', 'created_at', 'expires_at_epoch_ms']) ||
      value.schema !== 'serverware.operatorXAccountOperation/v1' || !upstreamUUID(value.operation_id) || value.operation_id !== id ||
      !['consent', 'disconnect'].includes(value.kind) || !statuses.includes(value.status) || !reasons.includes(value.reason) ||
      !(value.credential_id === null || upstreamUUID(value.credential_id)) ||
      typeof value.created_at !== 'string' || value.created_at.length > 64 || !Number.isFinite(Date.parse(value.created_at)) ||
      (value.kind === 'consent' ? !Number.isSafeInteger(value.expires_at_epoch_ms) || value.expires_at_epoch_ms <= 0 ||
        ['disconnect_pending', 'disconnected'].includes(value.status) : value.expires_at_epoch_ms !== null ||
        ['consent_pending', 'exchanging', 'connected', 'denied'].includes(value.status)) ||
      ['connected', 'disconnected'].includes(value.status) && (!value.credential_id || value.reason !== null))
    throw operatorError('The X operation result could not be verified. Keep its reference and use Check result; do not resubmit.');
  return {...value};
}
function projectXDisconnectReview(value, credential, catalog) {
  const ids = values => Array.isArray(values) && values.length <= 64 && values.every(upstreamUUID) &&
    new Set(values).size === values.length && operatorExact(values, [...values].sort());
  if (!upstreamObject(value, ['schema', 'credential_id', 'expected_credential_generation', 'expected_revision', 'expected_policy_hash',
    'review_digest', 'affected_credential_ids', 'affected_rule_ids']) || value.schema !== 'serverware.operatorXDisconnectReview/v1' ||
    !isXOAuthCredential(credential) || value.credential_id !== credential.id ||
    value.expected_credential_generation !== credential.credential_generation || !Number.isSafeInteger(value.expected_credential_generation) ||
    value.expected_credential_generation < 1 || value.expected_revision !== catalog.revision || value.expected_policy_hash !== catalog.policy.policy_hash ||
    !upstreamDigest(value.review_digest) || !ids(value.affected_credential_ids) || !value.affected_credential_ids.includes(credential.id) ||
    !ids(value.affected_rule_ids)) throw operatorError('The X disconnect scope changed or could not be verified. Review it again.');
  for (const id of value.affected_credential_ids) {
    const other = catalog.credentials.find(item => item.id === id);
    if (!isXOAuthCredential(other) || other.oauth_client_id !== credential.oauth_client_id || other.provider_subject !== credential.provider_subject)
      throw operatorError('The X disconnect account scope could not be verified.');
  }
  for (const id of value.affected_rule_ids) if (!catalog.access_rules.some(rule => rule.id === id && value.affected_credential_ids.includes(rule.credential_id)))
    throw operatorError('The X disconnect permission scope could not be verified.');
  return {...value, affected_credential_ids: [...value.affected_credential_ids], affected_rule_ids: [...value.affected_rule_ids]};
}
function projectXConsentStart(value, id, configuration) {
  if (!upstreamObject(value, ['schema', 'operation_id', 'status', 'authorization_url', 'state', 'expires_at_epoch_ms', 'profile_binding_digest']) ||
      value.schema !== 'serverware.operatorXConsent/v1' || value.operation_id !== id || value.status !== 'consent_pending' ||
      typeof value.state !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.state) ||
      value.profile_binding_digest !== configuration?.profile_binding_digest ||
      !Number.isSafeInteger(value.expires_at_epoch_ms) || value.expires_at_epoch_ms <= Date.now() || value.expires_at_epoch_ms > Date.now() + 600000 ||
      typeof value.authorization_url !== 'string' || value.authorization_url.length > 8192)
    throw operatorError('The X consent response could not be verified. Check its saved result; do not start again.');
  const url = new URL(value.authorization_url); const pairs = [...url.searchParams];
  const expected = {response_type: 'code', client_id: configuration.public_profile.client_id,
    redirect_uri: location.origin + '/api/oauth/callback/x', scope: xAccountScopes.join(' '), state: value.state,
    code_challenge: url.searchParams.get('code_challenge'), code_challenge_method: 'S256'};
  if (url.origin !== 'https://x.com' || url.pathname !== '/i/oauth2/authorize' || url.username || url.password || url.hash ||
      pairs.length !== 7 || !/^[A-Za-z0-9_-]{43}$/.test(expected.code_challenge || '') ||
      !operatorExact(Object.fromEntries(pairs), expected)) throw operatorError('The X consent destination could not be verified. Check the saved result.');
  return value.authorization_url;
}
function createXAccountsView(workspace, applications, connect) {
  const paths = xAccountCapabilityDescriptor(); const owner = 'x-account-operation';
  const panel = element('x-account-panel');
  let operationId = null; let operation = null; let settled = null; let disconnectReview = null;
  let busy = false; let storageBlocked = false;
  const say = text => { element('x-account-status').textContent = text; };
  const catalog = () => workspace.state.catalog;
  const capability = () => projectXAccountCapability(catalog()?.capabilities.x_oauth);
  const context = () => catalog() ? JSON.stringify({revision: catalog().revision, policy: catalog().policy.policy_hash,
    credentials: catalog().credentials.filter(isXOAuthCredential).map(xAccountIdentity),
    rules: catalog().access_rules.filter(isXPostRule)}) : null;
  const managedAccount = item => isXOAuthCredential(item) && ['active', 'quarantined'].includes(item.status);
  const canManage = () => catalog() && !busy && !storageBlocked && !operationId && !workspace.state.busy && !workspace.state.uncertain;
  const canWrite = () => capability() && canManage();
  // Failure is not proof that exchanged material was safely disposed of.
  const terminal = value => value && (['connected', 'disconnected'].includes(value.status) ||
    value.status === 'denied' && value.reason === 'consent_denied');
  try {
    const saved = sessionStorage.getItem(xAccountStorageKey);
    if (saved !== null) { if (!upstreamUUID(saved)) throw new Error(); operationId = saved; }
  } catch (_) { storageBlocked = true; }
  const returned = new URL(location.href);
  const callbackIds = returned.searchParams.getAll('serverware_x_operation');
  if (callbackIds.length) {
    returned.searchParams.delete('serverware_x_operation');
    history.replaceState(null, '', returned.pathname + returned.search + '#credentials');
    if (callbackIds.length !== 1 || !upstreamUUID(callbackIds[0]) || operationId && operationId !== callbackIds[0]) storageBlocked = true;
    else {
      operationId = callbackIds[0];
      try { sessionStorage.setItem(xAccountStorageKey, operationId); if (sessionStorage.getItem(xAccountStorageKey) !== operationId) throw new Error(); }
      catch (_) { storageBlocked = true; }
    }
  }
  const hint = textNode('p', undefined, 'notice'); hint.id = 'x-account-recovery-hint';
  const link = textNode('a', 'Open X account recovery'); link.href = '#credentials';
  hint.append(textNode('span', 'An X account operation needs review. '), link);
  element('mutation-review').append(hint);
  function render() {
    if (settled && settled !== context()) settled = null;
    const unresolved = Boolean(operationId && !settled);
    workspace.setConsentHold(busy || storageBlocked || unresolved, owner);
    panel.hidden = !capability() && !catalog()?.credentials.some(managedAccount) && !operationId && !storageBlocked;
    element('x-account-title').textContent = capability() ? 'Connect an X account' : 'Manage X account recovery';
    hint.hidden = !operationId && !storageBlocked;
    if (!hint.hidden) element('mutation-review').hidden = false;
    element('connect-x-account').hidden = !capability(); element('connect-x-account').disabled = !canWrite();
    element('x-account-name').disabled = !canWrite();
    element('x-account-start').disabled = !canWrite() || !element('x-account-name').value.trim();
    element('x-account-check').disabled = busy || storageBlocked || !operationId || workspace.writeInFlight();
    element('x-account-acknowledge').hidden = !terminal(operation);
    element('x-account-acknowledge').disabled = !settled || busy || workspace.state.busy || storageBlocked;
    element('x-account-operation').textContent = operationId ? 'Operation reference: ' + operationId : '';
    const connected = operation?.status === 'connected' && catalog()?.credentials.find(item => item.id === operation.credential_id && item.status === 'active' && isXOAuthCredential(item));
    element('x-account-use').hidden = !connected;
    element('x-account-use').disabled = !connected || !capability() || Boolean(operationId) || workspace.state.busy || workspace.state.uncertain;
    element('x-disconnect-review').hidden = !disconnectReview;
    element('x-disconnect-submit').disabled = !canManage() || !disconnectCurrent();
  }
  function disconnectCurrent() {
    return disconnectReview && catalog() && disconnectReview.expected_revision === catalog().revision &&
      disconnectReview.expected_policy_hash === catalog().policy.policy_hash &&
      catalog().credentials.some(item => item.id === disconnectReview.credential_id && managedAccount(item) &&
        item.credential_generation === disconnectReview.expected_credential_generation);
  }
  function warn(text) { say(text); if (!workspace.state.uncertain) workspace.requireReview(text); render(); }
  function retain(id) {
    if (!upstreamUUID(id) || operationId) throw operatorError('Resolve the existing X operation first.');
    try { sessionStorage.setItem(xAccountStorageKey, id); if (sessionStorage.getItem(xAccountStorageKey) !== id) throw new Error(); }
    catch (_) { storageBlocked = true; throw operatorError('The public X operation reference could not be saved safely. No request was sent.'); }
    operationId = id; operation = null; settled = null;
  }
  function validateTerminal() {
    if (!terminal(operation) || !catalog()) return false;
    if (operation.status === 'connected' && !catalog().credentials.some(item => item.id === operation.credential_id && item.status === 'active' && isXOAuthCredential(item))) return false;
    if (operation.status === 'disconnected' && !catalog().credentials.some(item => item.id === operation.credential_id && item.status === 'revoked' && isXOAuthCredential(item))) return false;
    settled = context(); return true;
  }
  async function check() {
    if (busy || storageBlocked || !operationId || workspace.writeInFlight()) return;
    busy = true; render();
    try {
      const observed = projectXAccountOperation(await workspace.api(paths.operation_path_prefix + operationId), operationId);
      if (operation && (observed.kind !== operation.kind || observed.created_at !== operation.created_at || observed.expires_at_epoch_ms !== operation.expires_at_epoch_ms))
        throw operatorError('The X operation identity changed. Keep the original reference; do not repeat it.');
      operation = observed;
      if (!await workspace.refresh()) throw operatorError('Refresh saved accounts before resolving this X operation.');
      const confirmed = validateTerminal();
      say('X operation: ' + operation.status.replaceAll('_', ' ') + (operation.reason ? ' (' + operation.reason.replaceAll('_', ' ') + ')' : '') +
        (confirmed ? '. Review the saved account and acknowledge this result. No posting permission was granted.' : '. Use Check result again; no request is replayed.'));
      if (confirmed && !workspace.state.uncertain) workspace.requireReview('The X account operation has a final result. Acknowledge it in Accounts & keys, then review saved resources.');
    } catch (_) { warn('The X account result is unavailable or unverified. Keep its reference and use Check result. Absence is not permission to repeat.'); }
    finally { busy = false; render(); workspace.emit(); }
  }
  element('x-account-start').addEventListener('click', async () => {
    if (!canWrite()) return;
    const name = element('x-account-name').value.trim();
    if (!name || name.length > 128 || /[\u0000-\u001f\u007f]/.test(name)) return;
    if (!window.confirm('Continue to X to authorize this account? Save any one-time application token first. This leaves the page, grants no app permission, and sends no post.')) return;
    const reviewed = {expected_revision: catalog().revision, expected_policy_hash: catalog().policy.policy_hash};
    busy = true; workspace.state.busy = true; render(); let authorization = null;
    try {
      const config = projectXConfiguration(await workspace.api(xConfigurationPath));
      if (config.state !== 'configured' || config.revision !== reviewed.expected_revision || config.policy_hash !== reviewed.expected_policy_hash ||
          !capability() || catalog().revision !== reviewed.expected_revision || catalog().policy.policy_hash !== reviewed.expected_policy_hash)
        throw operatorError('Review current X configuration before consent.');
      retain(crypto.randomUUID());
      const result = await workspace.api(paths.start_path, {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({operation_id: operationId, name, ...reviewed})});
      authorization = projectXConsentStart(result, operationId, config.configuration);
      // The server owns the HttpOnly state cookie. No authorization URL is kept
      // for resuming/replaying consent, even when navigation fails.
      location.assign(authorization);
    } catch (_) { warn(operationId ? 'X consent could not be confirmed. Use Check result; do not start another consent request.' : 'X consent was not started. Review current application settings and saved state.'); }
    finally { authorization = null; busy = false; workspace.state.busy = false; render(); workspace.emit(); }
  });
  element('x-account-check').addEventListener('click', check);
  element('x-account-name').addEventListener('input', render);
  element('connect-x-account').addEventListener('click', () => {
    if (!capability()) return; location.hash = 'credentials'; panel.scrollIntoView({block: 'nearest'}); element('x-account-name').focus();
  });
  element('x-account-acknowledge').addEventListener('click', () => {
    if (!operationId || !terminal(operation) || !settled || settled !== context() || busy || workspace.state.busy || storageBlocked) return;
    try {
      if (sessionStorage.getItem(xAccountStorageKey) !== operationId) throw new Error();
      sessionStorage.removeItem(xAccountStorageKey);
      if (sessionStorage.getItem(xAccountStorageKey) !== null) throw new Error();
      operationId = null; settled = null;
      say('X result acknowledged. Confirm the shared saved-state review before making another change. No request was sent.');
    } catch (_) { storageBlocked = true; warn('The exact X operation reference could not be retired safely. No request was sent.'); }
    render(); workspace.emit();
  });
  element('x-account-use').addEventListener('click', () => {
    render(); if (element('x-account-use').disabled) return; connect.selectXAccountCredential(operation.credential_id);
  });
  async function disconnect(id) {
    // Protective cleanup does not depend on readiness to create new access.
    // The actor-owned review endpoint still admits the account and exact scope.
    if (!canManage()) return;
    const selected = catalog().credentials.find(item => item.id === id && managedAccount(item));
    if (!selected) return;
    busy = true; render(); location.hash = 'credentials';
    try {
      disconnectReview = projectXDisconnectReview(await workspace.api(paths.disconnect_review_path_template.replace('{credential_id}', id)), selected, catalog());
      const describe = (ids, resources) => ids.map(value => resources.find(item => item.id === value)?.name + ' (' + value + ')').join('; ') || 'None';
      element('x-disconnect-details').replaceChildren(...[
        ['Account', selected.provider_account], ['Connections to disconnect', describe(disconnectReview.affected_credential_ids, catalog().credentials)],
        ['Permissions to revoke', describe(disconnectReview.affected_rule_ids, catalog().access_rules)]
      ].flatMap(([label, value]) => [textNode('dt', label), textNode('dd', value)]));
      say('Review every affected connection and permission. Applications and their proxy tokens are not deleted.');
    } catch (_) { disconnectReview = null; say('The disconnect scope could not be reviewed. No disconnect was sent.'); }
    finally { busy = false; render(); panel.scrollIntoView({block: 'nearest'}); }
  }
  element('x-disconnect-dismiss').addEventListener('click', () => { if (!busy) { disconnectReview = null; render(); } });
  element('x-disconnect-submit').addEventListener('click', async () => {
    if (!canManage() || !disconnectCurrent() || !window.confirm('Disconnect exactly the listed X connections and revoke their listed permissions? Provider cleanup will be checked; an uncertain result must not be replayed.')) return;
    busy = true; workspace.state.busy = true; render();
    try {
      retain(crypto.randomUUID());
      const body = {operation_id: operationId, ...Object.fromEntries(['credential_id', 'expected_credential_generation',
        'expected_revision', 'expected_policy_hash', 'review_digest'].map(key => [key, disconnectReview[key]]))};
      operation = projectXAccountOperation(await workspace.api(paths.disconnect_path, {method: 'POST',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)}), operationId);
      if (operation.kind !== 'disconnect' || operation.credential_id !== body.credential_id) throw new Error();
      disconnectReview = null;
      await workspace.refresh(); validateTerminal();
      warn('X disconnect result: ' + operation.status.replaceAll('_', ' ') + '. Review saved accounts and Check result before acknowledging.');
    } catch (_) { warn('The X disconnect outcome could not be confirmed. Use Check result; do not repeat disconnect.'); }
    finally { busy = false; workspace.state.busy = false; render(); workspace.emit(); }
  });
  if (operationId || storageBlocked) warn(storageBlocked ?
    'The X account recovery reference could not be read safely. Open Accounts & keys to inspect recovery; do not repeat an uncertain request.' :
    'An X account operation needs review. Open Accounts & keys and use Check result.');
  workspace.subscribe(render); render();
  return {disconnect, check};
}

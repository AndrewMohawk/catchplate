// The exported pure generator is also the browser's only client-example path.
// It accepts public metadata and never accepts a provider secret or client token.
const CLIENT_METHODS = Object.freeze(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
function buildCurlCommand({proxyUrl, upstreamUrl, method, caPath, allowedHeaders = ['accept', 'user-agent']}) {
  const quote = value => "'" + String(value).replace(/'/g, "'\\''") + "'";
  for (const value of [proxyUrl, upstreamUrl]) {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash)
      throw new Error('Client configuration requires credential-free HTTPS URLs');
  }
  if (!CLIENT_METHODS.includes(method)) throw new Error('Invalid client method');
  const accept = allowedHeaders.some(name => name.toLowerCase() === 'accept') ? 'Accept: application/json' : 'Accept:';
  return ['curl --fail-with-body --show-error --http1.1', "  --noproxy ''", `  --proxy ${quote(proxyUrl)}`,
    '  --proxy-header "Proxy-Authorization: Bearer $SERVERWARE_PROXY_TOKEN"',
    `  --cacert ${quote(caPath || './serverware-ca.pem')}`, `  --request ${quote(method)}`,
    `  --header ${quote(accept)}`, "  --header 'User-Agent:'", `  ${quote(upstreamUrl)}`].join(' \\\n');
}

if (typeof module !== 'undefined' && module.exports) module.exports = {buildCurlCommand};
else (() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const views = {overview: 'Overview', credentials: 'Credentials & access', proxy: 'Proxy setup', audit: 'Audit log'};
  const state = {status: null, selected: '', token: '', tokenConnection: '', submitting: false,
    statusEpoch: 0, poll: null, polls: 0, command: '', auditEpoch: 0, auditCursor: null,
    auditSelection: '', auditCount: 0, auditLoaded: false, expiryTimer: null,
    tokenExpiresAt: null, tokenClientStatus: null, revoking: '', revocationCheck: null, revocationReceipts: []};
  const text = value => typeof value === 'string' ? value : '';
  const fields = id => [...new Set($(id).value.split(/\r?\n/).map(value => value.trim()).filter(Boolean))];
  function node(tag, content, className) {
    const result = document.createElement(tag);
    if (content !== undefined) result.textContent = String(content);
    if (className) result.className = className;
    return result;
  }
  function problem(message) { const error = new Error('Operator UI request failed'); error.uiMessage = message; return error; }
  function message(error) { return error.uiMessage || 'Could not reach the service. Check your connection, then refresh status. Do not resubmit a credential until you have checked saved connections.'; }
  function clearToken() {
    state.token = ''; state.tokenConnection = ''; state.tokenExpiresAt = null; state.tokenClientStatus = null;
    $('client-token').value = ''; $('client-token').type = 'password';
    $('one-time-access').hidden = true; $('reveal-token').textContent = 'Reveal';
    $('reveal-token').setAttribute('aria-pressed', 'false');
    for (const id of ['client-token', 'reveal-token', 'copy-token', 'dismiss-token']) $(id).disabled = true;
    $('download-config').disabled = true;
  }
  async function api(path, options = {}, failureDescriptions = {}) {
    const response = await fetch(path, {credentials: 'same-origin', cache: 'no-store',
      redirect: 'error', signal: AbortSignal.timeout(30000), ...options});
    if (response.status === 401 || response.status === 403) {
      clearToken(); state.status = null; $('connection-fields').disabled = true;
      throw problem('Your session or request origin could not be verified. Reload this page and sign in again.');
    }
    if (!response.headers.get('content-type')?.includes('application/json'))
      throw problem('The service did not return a valid response. Reload this page to sign in again.');
    // Never display a raw server error: it could contain submitted secret material.
    if (!response.ok) {
      if (response.status === 409 && path === '/api/operator-demo/connections') {
        const rejected = await response.json().catch(() => ({}));
        const limits = {operator_demo_active_limit: 'The active connection limit is reached. Revoke an unneeded connection explicitly, then refresh before adding another.',
          operator_demo_retained_limit: 'The lifetime connection limit is reached. This workspace cannot admit another connection; contact the deployment operator. Revocation is still available. No history has been pruned or reset.'};
        if (Object.hasOwn(limits, rejected?.code)) throw problem(limits[rejected.code]);
      }
      const descriptions = {409: 'The configuration changed or this connection already exists. Refresh saved connections before submitting again.',
        422: 'Check the upstream, exact path, methods and field lists. The server rejected this configuration.',
        503: 'The service could not confirm policy publication or activation. Refresh saved connections before submitting again.', ...failureDescriptions};
      throw problem(descriptions[response.status] || `Request failed (HTTP ${response.status}). Refresh status before trying again.`);
    }
    return response.json();
  }
  function httpsUrl(value, originOnly = false) {
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.username || url.password || url.hash || url.search ||
          (originOnly && url.pathname !== '/')) return null;
      return url;
    } catch { return null; }
  }
  function active() {
    const status = state.status;
    return Boolean(status && typeof status.active_policy_hash === 'string' && status.active_policy_hash &&
      status.loaded_policy_hash === status.active_policy_hash);
  }
  function policyLoaded(connection) {
    return active() && connection.policy_hash === state.status.active_policy_hash && connection.activation === 'active';
  }
  function validExpiry(value) { return Number.isSafeInteger(value) && value > 0 && value <= 8640000000000000; }
  function supportedMethods(connection) { return connection.methods.length > 0 && connection.methods.every(method => CLIENT_METHODS.includes(method)); }
  function clientStatus(connection) {
    if (state.revoking === connection.id || state.revocationCheck?.id === connection.id ||
        state.revocationReceipts.some(receipt => receipt.connection_id === connection.id)) return 'revoking';
    if (connection.client_status === 'expired' || validExpiry(connection.token_expires_at_epoch_ms) && Date.now() >= connection.token_expires_at_epoch_ms) return 'expired';
    if (!validExpiry(connection.token_expires_at_epoch_ms)) return 'unavailable';
    if (!supportedMethods(connection)) return 'unsupported';
    if (connection.client_status !== undefined && !['ready', 'pending'].includes(connection.client_status)) return 'unavailable';
    return policyLoaded(connection) && connection.client_status !== 'pending' ? 'ready' : 'pending';
  }
  function connectionReady(connection) { return clientStatus(connection) === 'ready'; }
  function syncTokenControls() {
    if (state.token && (!validExpiry(state.tokenExpiresAt) || Date.now() >= state.tokenExpiresAt || state.tokenClientStatus === 'expired')) {
      const expired = state.tokenClientStatus === 'expired' || validExpiry(state.tokenExpiresAt) && Date.now() >= state.tokenExpiresAt;
      clearToken();
      $('token-expiry-status').textContent = expired ? 'Client token expired and was cleared from this page. It has not been renewed.' :
        'Client token cleared because its expiry could not be verified. Check saved connection status.';
    }
    for (const id of ['client-token', 'reveal-token', 'copy-token', 'dismiss-token'])
      $(id).disabled = !state.token || state.revoking === state.tokenConnection;
  }
  function scheduleExpiry() {
    clearTimeout(state.expiryTimer); state.expiryTimer = null;
    const now = Date.now();
    const deadlines = [...(state.status?.connections || []).map(connection => connection.token_expires_at_epoch_ms),
      ...(state.token ? [state.tokenExpiresAt] : [])].filter(value => validExpiry(value) && value > now);
    if (deadlines.length) {
      // One local deadline, not a network poll. The cap avoids browser timer
      // overflow for older metadata; no timer remains once all tokens expire.
      state.expiryTimer = setTimeout(refreshClientLifecycle, Math.min(Math.min(...deadlines) - now, 2147483647));
    }
  }
  function refreshClientLifecycle() {
    syncTokenControls();
    if (state.status) renderConnections();
    else { state.command = ''; $('copy-command').disabled = true; $('download-config').disabled = true; }
    scheduleExpiry();
  }
  function metadata(connection) {
    // Explicit public metadata projection. Never retain unknown response fields.
    const allowed = ['id', 'name', 'upstream_url', 'auth_type', 'header_name', 'credential_id', 'principal_id',
      'created_at', 'token_expires_at_epoch_ms', 'policy_hash', 'activation', 'client_status'];
    const result = Object.fromEntries(allowed.map(key => [key, connection[key]]));
    for (const key of ['methods', 'request_fields', 'response_fields', 'query_keys', 'allowed_headers'])
      result[key] = Array.isArray(connection[key]) ? connection[key].filter(value => typeof value === 'string') : [];
    return result;
  }
  function revocationMetadata(receipt) {
    const fields = ['connection_id', 'name', 'credential_id', 'principal_id', 'revoked_at', 'expected_policy_hash',
      'revocation_policy_hash', 'sequence', 'policy_hash', 'enforcement'];
    if (!receipt || fields.filter(key => key !== 'sequence').some(key => typeof receipt[key] !== 'string') ||
        !receipt.connection_id || !Number.isSafeInteger(receipt.sequence) || receipt.sequence < 1 ||
        !['pending', 'enforced'].includes(receipt.enforcement) ||
        !['expected_policy_hash', 'revocation_policy_hash', 'policy_hash'].every(key => /^sha256:[a-f0-9]{64}$/.test(receipt[key])))
      throw problem('Revocation receipts could not be verified. Refresh status before changing any connection.');
    return Object.fromEntries(fields.map(key => [key, receipt[key]]));
  }
  function mutationsBusy() { return state.submitting || Boolean(state.revoking || state.revocationCheck); }
  function connectionLimit() {
    const limits = state.status?.connection_limits;
    if (limits && limits.retained_count >= limits.retained_max)
      return 'Lifetime connection capacity reached. Adding a connection is disabled; contact the deployment operator. Existing connections can still be revoked. No history is pruned or reset.';
    if (limits && limits.active_count >= limits.active_max)
      return 'Active connection capacity reached. Revoke an unneeded connection explicitly, then refresh to add another.';
    return '';
  }
  function syncMutationControls() {
    const limit = connectionLimit();
    $('connection-fields').disabled = mutationsBusy() || !state.status?.allowed_upstreams.length || Boolean(limit);
    $('connection-capacity').textContent = limit;
    for (const button of document.querySelectorAll('.revoke-connection'))
      button.disabled = mutationsBusy() || !Array.isArray(state.status?.revocations);
  }
  function clearRevokedToken(connectionId, uncertain = false) {
    if (state.tokenConnection !== connectionId) return;
    clearToken();
    $('token-expiry-status').textContent = uncertain ?
      'Client token cleared because the revocation outcome is uncertain. Check the saved revocation receipt; no replacement token has been issued.' :
      'Client token cleared because this connection was revoked or is no longer saved. No replacement token has been issued.';
  }
  function revocationEnforced(receipt) {
    return receipt.enforcement === 'enforced' && active() && receipt.policy_hash === state.status.active_policy_hash &&
      state.status.revocations?.some(value => value.connection_id === receipt.connection_id) &&
      !state.status.connections.some(connection => connection.id === receipt.connection_id);
  }
  function renderRevocations() {
    const cards = state.revocationReceipts.map(receipt => {
      const card = node('article', undefined, 'card'); card.dataset.revokedConnectionId = receipt.connection_id;
      const head = node('div', undefined, 'connection-head');
      const label = !state.status ? 'Enforcement unknown' : revocationEnforced(receipt) ? 'Enforced' : 'Pending enforcement';
      head.append(node('h3', receipt.name), node('span', label, 'badge' + (label === 'Enforced' ? ' active' : ''))); card.append(head);
      appendMetadata(card, [['Connection ID', receipt.connection_id], ['Revocation saved', receipt.revoked_at],
        ['Revocation policy', receipt.revocation_policy_hash], ['Current policy', state.status?.active_policy_hash || 'Status unavailable']]);
      card.append(node('p', label === 'Enforced' ? 'The proxy has loaded the current saved policy without this connection.' :
        'Revocation is saved, but current proxy enforcement is not confirmed. Refresh status before relying on it.', 'small muted'));
      return card;
    });
    $('revocations-list').replaceChildren(...(cards.length ? cards : [node('p',
      state.status && !Array.isArray(state.status.revocations) ? 'This service does not report revocation receipts. Revocation is disabled; contact the deployment operator.' : 'No saved revocations reported.', 'muted')]));
  }
  function reconcileRevocation() {
    const check = state.revocationCheck;
    if (!check) return;
    const receipt = state.status.revocations?.find(value => value.connection_id === check.id);
    if (receipt) {
      clearRevokedToken(check.id); state.revocationCheck = null;
      $('revocation-status').textContent = `Revocation saved for ${check.name}. See the receipt below for current enforcement. Already-dispatched requests cannot be recalled.`;
    } else if (Array.isArray(state.status.revocations) && !check.committed && state.status.connections.some(value => value.id === check.id)) {
      state.revocationCheck = null;
      $('revocation-status').textContent = `${check.error} Status refreshed: this connection is still saved and no revocation receipt was found. Review it before explicitly trying again.`;
    } else {
      $('revocation-status').textContent = 'The revocation outcome cannot be reconciled with saved status. Changes remain disabled. Refresh status or contact the deployment operator; do not assume revocation failed.';
    }
  }
  function navigate() {
    let view = location.hash.slice(1) || 'overview';
    if (view === 'main-content') { $('main-content').focus(); return; }
    if (!Object.hasOwn(views, view)) { view = 'overview'; history.replaceState(null, '', '#overview'); }
    for (const name of Object.keys(views)) {
      $(name).hidden = name !== view;
      const link = document.querySelector(`nav a[href="#${name}"]`);
      if (name === view) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    }
    $('page-label').textContent = views[view]; document.title = views[view] + ' - Serverware operator demo';
    if (view === 'audit' && state.status && !state.auditLoaded) loadAudit();
  }
  function appendMetadata(card, values) {
    const list = node('dl', undefined, 'metadata');
    for (const [label, value] of values) list.append(node('dt', label), node('dd', value || 'None'));
    card.append(list);
  }
  function renderStatus() {
    const status = state.status;
    const activation = active() ? 'Active: the proxy has loaded the saved policy.' :
      'Pending: the proxy has not confirmed the saved policy. Do not send requests yet.';
    $('overview-policy').textContent = activation; $('activation-status').textContent = activation;
    $('connection-summary').textContent = `${status.connections.length} saved connection${status.connections.length === 1 ? '' : 's'}`;
    $('proxy-url').textContent = status.proxy_url || 'Public HTTPS endpoint not configured.';
    const currentOrigin = $('upstream-origin').value;
    $('upstream-origin').replaceChildren(node('option', 'Choose an approved upstream'));
    $('upstream-origin').firstChild.value = '';
    for (const origin of status.allowed_upstreams) { const option = node('option', origin); option.value = origin; $('upstream-origin').append(option); }
    if (status.allowed_upstreams.includes(currentOrigin)) $('upstream-origin').value = currentOrigin;
    else if (status.allowed_upstreams.length === 1) $('upstream-origin').value = status.allowed_upstreams[0];
    syncMutationControls();
    if (!status.allowed_upstreams.length) $('form-status').textContent = 'No upstream is configured. Ask the deployment operator to approve a destination.';
    refreshClientLifecycle();
  }
  function renderConnections() {
    const status = state.status;
    const cards = status.connections.map(connection => {
      const card = node('article', undefined, 'card'); card.dataset.connectionId = text(connection.id);
      const head = node('div', undefined, 'connection-head'); const readiness = clientStatus(connection);
      const label = {ready: 'Ready', expired: 'Token expired', pending: 'Pending activation', revoking: 'Revocation in progress', unsupported: 'Unsupported method', unavailable: 'Expiry / status unavailable'}[readiness];
      head.append(node('h3', connection.name), node('span', label, 'badge' + (readiness === 'ready' ? ' active' : '')));
      card.append(head);
      const expires = validExpiry(connection.token_expires_at_epoch_ms) ? new Date(connection.token_expires_at_epoch_ms).toLocaleString() : 'Not reported';
      appendMetadata(card, [['Proxy policy', policyLoaded(connection) ? 'Policy loaded' : 'Pending activation'],
        ['Exact URL', connection.upstream_url], ['Methods', connection.methods.join(', ')],
        ['Provider auth', connection.auth_type === 'bearer' ? 'Bearer token' : connection.header_name],
        ['Response fields', connection.response_fields.join(', ')], ['Request fields', connection.request_fields.join(', ')],
        ['Query keys', connection.query_keys.join(', ')], ['Client token expiry', expires]]);
      if (!supportedMethods(connection)) card.append(node('p', 'Unsupported saved method. This connection cannot generate a client configuration; other connections are unaffected.', 'small muted'));
      const button = node('button', 'Configure this client', 'secondary'); button.type = 'button';
      button.addEventListener('click', () => { state.selected = connection.id; $('client-connection').value = connection.id; renderClient(); location.hash = 'proxy'; });
      const revoke = node('button', 'Revoke connection', 'secondary revoke-connection'); revoke.type = 'button';
      revoke.setAttribute('aria-label', 'Revoke connection ' + text(connection.name));
      revoke.addEventListener('click', () => revokeConnection(connection.id));
      const actions = node('div', undefined, 'actions'); actions.append(button, revoke);
      card.append(node('p', 'Provider credential stored. Its value is never returned by this page.', 'small muted'), actions);
      return card;
    });
    $('connections-list').replaceChildren(...(cards.length ? cards : [node('p', 'No connections yet. Add your first credential above.', 'muted')]));
    $('client-connection').replaceChildren();
    if (!status.connections.length) { const option = node('option', 'Add a credential first'); option.value = ''; $('client-connection').append(option); }
    for (const connection of status.connections) { const option = node('option', connection.name); option.value = connection.id; $('client-connection').append(option); }
    if (!status.connections.some(connection => connection.id === state.selected)) state.selected = status.connections[0]?.id || '';
    $('client-connection').value = state.selected;
    renderClient(); renderRevocations(); syncMutationControls();
  }
  async function loadStatus({poll = false, revokeReconcile = false} = {}) {
    if (state.revoking && !revokeReconcile) return;
    const epoch = ++state.statusEpoch;
    clearTimeout(state.poll);
    if (!poll) state.polls = 0;
    try {
      const result = await api('/api/operator-demo/status');
      if (epoch !== state.statusEpoch) return;
      if (result.mode !== 'operator-development' || result.syntheticOnly !== false ||
          result.productionReady !== false || result.hardwareVerified !== false ||
          !Array.isArray(result.allowed_upstreams) || !Array.isArray(result.connections))
        throw problem('This page is not connected to the expected operator-development profile. Configuration is disabled.');
      const proxy = httpsUrl(result.proxy_url, true);
      // A public client example must never silently use a Docker-only listener.
      const proxyValid = proxy && proxy.hostname.includes('.') && proxy.hostname !== '127.0.0.1' &&
        !proxy.hostname.endsWith('.localhost') && !proxy.hostname.endsWith('.local');
      const revocations = Array.isArray(result.revocations) ? result.revocations.map(revocationMetadata) : null;
      const limits = result.connection_limits;
      const publicLimits = limits && ['active_max', 'retained_max', 'active_count', 'retained_count'].every(key =>
        Number.isSafeInteger(limits[key]) && limits[key] >= (key.endsWith('_max') ? 1 : 0)) ?
        Object.fromEntries(['active_max', 'retained_max', 'active_count', 'retained_count'].map(key => [key, limits[key]])) : null;
      state.status = {mode: result.mode, proxy_url: proxyValid ? proxy.href.replace(/\/$/, '') : '',
        allowed_upstreams: result.allowed_upstreams.filter(value => typeof value === 'string' && httpsUrl(value, true)),
        connections: result.connections.map(metadata), revocations, connection_limits: publicLimits,
        active_policy_hash: result.active_policy_hash, loaded_policy_hash: result.loaded_policy_hash};
      if (revocations) state.revocationReceipts = [
        ...state.revocationReceipts.filter(receipt => !revocations.some(value => value.connection_id === receipt.connection_id)), ...revocations];
      const held = state.status.connections.find(connection => connection.id === state.tokenConnection);
      if (state.token && held) {
        state.tokenExpiresAt = validExpiry(held.token_expires_at_epoch_ms) && validExpiry(state.tokenExpiresAt) ?
          Math.min(state.tokenExpiresAt, held.token_expires_at_epoch_ms) : null;
        state.tokenClientStatus = held.client_status;
      } else if (state.token) clearRevokedToken(state.tokenConnection);
      reconcileRevocation();
      $('load-error').hidden = true; renderStatus();
      if ($('form-status').textContent === 'Loading workspace...') $('form-status').textContent = 'Ready. Use a disposable, least-privilege provider credential.';
      if (!active() && (state.status.connections.length || state.revocationReceipts.length) && state.polls++ < 30)
        state.poll = setTimeout(() => loadStatus({poll: true}), 4000);
      if (location.hash === '#audit' && !state.auditLoaded) loadAudit();
    } catch (error) {
      if (epoch !== state.statusEpoch) return;
      state.status = null; $('connection-fields').disabled = true;
      syncTokenControls(); scheduleExpiry();
      $('load-error-text').textContent = message(error); $('load-error').hidden = false;
      $('overview-policy').textContent = 'Activation unknown. Status could not be loaded.';
      $('activation-status').textContent = 'Activation unknown. Refresh status before use.';
      $('copy-command').disabled = true; $('download-config').disabled = true;
      for (const badge of document.querySelectorAll('#connections-list .badge')) { badge.textContent = 'Status unavailable'; badge.className = 'badge'; }
      if (state.revocationCheck) $('revocation-status').textContent = 'Revocation outcome is unconfirmed because saved status could not be loaded. Refresh status before trying again; do not assume the request failed.';
      renderRevocations(); syncMutationControls();
    }
  }
  async function revokeConnection(connectionId) {
    if (mutationsBusy() || !Array.isArray(state.status?.revocations)) return;
    const connection = state.status.connections.find(value => value.id === connectionId);
    const expected = state.status.active_policy_hash;
    if (!connection || !/^sha256:[a-f0-9]{64}$/.test(expected || '')) {
      $('revocation-status').textContent = 'The saved connection or policy could not be verified. Refresh status before revoking.'; return;
    }
    if (!window.confirm(`Revoke local proxy access for "${connection.name}" (${connection.id})?\n\nThis removes its stored credential from this workspace and denies new requests after the proxy loads the policy. It does not revoke the credential at the provider. Already-dispatched requests cannot be recalled. No replacement token will be issued.`)) return;
    state.revoking = connection.id;
    state.revocationCheck = {id: connection.id, name: text(connection.name), committed: false, error: ''};
    ++state.statusEpoch; clearTimeout(state.poll);
    $('revocation-status').textContent = `Saving revocation for ${connection.name}...`;
    refreshClientLifecycle(); syncMutationControls();
    try {
      const result = await api('/api/operator-demo/connections/revoke', {method: 'POST',
        headers: {'Content-Type': 'application/json'}, body: JSON.stringify({connection_id: connection.id, expected_policy_hash: expected})}, {
        404: 'This connection was not found. Check saved revocations before trying again.',
        409: 'The saved policy changed or this request conflicts with a previous revocation. Review refreshed status before trying again.',
        413: 'The revocation request was rejected as too large. Refresh this page before trying again.',
        422: 'The connection or expected policy was rejected. Refresh status before trying again.',
        503: 'The service could not confirm the revocation result. Do not assume it failed.'});
      const receipt = revocationMetadata(result.revocation);
      if (receipt.connection_id !== connection.id || receipt.expected_policy_hash !== expected || receipt.policy_hash !== result.policy_hash)
        throw problem('The returned revocation receipt did not match this request. Check saved status before trying again.');
      state.revocationCheck.committed = true;
      state.revocationReceipts = [...state.revocationReceipts.filter(value => value.connection_id !== receipt.connection_id), receipt];
      clearRevokedToken(connection.id); state.auditLoaded = false;
      $('revocation-status').textContent = `Revocation saved for ${connection.name}. Checking current proxy enforcement...`;
    } catch (error) {
      clearRevokedToken(connection.id, true);
      state.revocationCheck.error = error.uiMessage || 'The revocation response was lost or unavailable.';
      $('revocation-status').textContent = state.revocationCheck.error + ' Checking saved status before allowing another attempt...';
    }
    // A failed or lost POST response never authorizes automatic resubmission.
    // Only a fresh GET can reconcile the tombstone or re-enable explicit retry.
    await loadStatus({revokeReconcile: true});
    state.revoking = '';
    refreshClientLifecycle(); syncMutationControls();
  }
  async function submit(event) {
    event.preventDefault();
    if (mutationsBusy() || connectionLimit() || !state.status || !$('connection-form').reportValidity()) return;
    const methods = [...document.querySelectorAll('input[name="method"]:checked')].map(input => input.value);
    const path = $('upstream-path').value.trim(); const origin = $('upstream-origin').value;
    if (!methods.length || methods.some(method => !CLIENT_METHODS.includes(method)) || !path.startsWith('/') || path.startsWith('//') || /[?#\\\s*]/.test(path) ||
        !state.status.allowed_upstreams.includes(origin) || !fields('response-fields').length) {
      $('form-status').textContent = 'Select at least one method, an approved upstream, an exact path and at least one response field.'; return;
    }
    if (state.token && !window.confirm('Creating another connection clears the previous one-time token from this page. Have you saved it?')) return;
    clearToken(); state.submitting = true; syncMutationControls();
    const body = {name: $('connection-name').value.trim(), upstream_url: origin.replace(/\/$/, '') + path,
      methods, auth_type: $('auth-type').value, header_name: $('auth-type').value === 'bearer' ? 'Authorization' : $('header-name').value.trim(),
      secret: $('provider-secret').value, response_fields: fields('response-fields'), request_fields: fields('request-fields'),
      query_keys: fields('query-keys'), allowed_headers: fields('allowed-headers')};
    $('provider-secret').value = ''; $('form-status').textContent = 'Saving credential and publishing its scoped policy...';
    try {
      const request = api('/api/operator-demo/connections', {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body)});
      body.secret = '';
      const result = await request;
      if (!result.connection || typeof result.connection.id !== 'string' || !text(result.client_token))
        throw problem('The response did not include a complete one-time token. Check saved connections; do not assume the save failed.');
      state.token = result.client_token; state.tokenConnection = result.connection.id; state.selected = result.connection.id;
      state.tokenExpiresAt = result.connection.token_expires_at_epoch_ms; state.tokenClientStatus = result.connection.client_status;
      result.client_token = ''; $('client-token').value = state.token; $('one-time-access').hidden = false;
      $('token-expiry-status').textContent = ''; syncTokenControls(); scheduleExpiry();
      $('token-status').textContent = 'Save the token now. Clipboard and downloaded files are outside Serverware; keep them private.';
      $('form-status').textContent = 'Credential saved. Save the one-time client token below; checking proxy activation...';
      $('connection-form').reset(); $('header-field').hidden = true; $('header-name').required = false;
      state.auditLoaded = false;
      await loadStatus();
      $('one-time-access').scrollIntoView({block: 'nearest'});
    } catch (error) { $('form-status').textContent = message(error); }
    finally { body.secret = ''; $('provider-secret').value = ''; state.submitting = false;
      syncMutationControls(); }
  }
  function selectedConnection() { return state.status?.connections.find(connection => connection.id === state.selected); }
  function renderClient() {
    const connection = selectedConnection(); const proxy = state.status?.proxy_url;
    state.command = ''; $('copy-command').disabled = true; $('download-config').disabled = true;
    if (!connection || !proxy || !httpsUrl(connection.upstream_url)) {
      $('client-command').textContent = connection ? 'A valid public HTTPS proxy endpoint is not configured.' : 'Add a credential to generate a scoped example.';
      $('client-guidance').textContent = ''; return;
    }
    if (!supportedMethods(connection)) {
      $('client-command').textContent = 'Unsupported saved method: ' + (connection.methods.join(', ') || 'not reported') + '.';
      $('client-guidance').textContent = 'Select another connection. This demo cannot generate a supported configuration for these saved methods.'; return;
    }
    const readiness = clientStatus(connection);
    if (readiness === 'revoking') {
      $('client-command').textContent = 'Revocation is in progress or saved for this connection.';
      $('client-guidance').textContent = 'Do not use this client. Check the revocation receipt and current proxy enforcement in Credentials & access.'; return;
    }
    if (readiness === 'expired' || readiness === 'unavailable') {
      $('client-command').textContent = readiness === 'expired' ? 'Client token expired. This connection cannot authenticate requests.' : 'Client token expiry or status is unavailable.';
      $('client-guidance').textContent = readiness === 'expired' ? 'The policy may remain loaded, but this token is no longer usable. Select another unexpired connection; no token has been renewed.' :
        'Refresh connection status before using this client. Copy and download are disabled.'; return;
    }
    const method = connection.methods[0];
    try {
      state.command = buildCurlCommand({proxyUrl: proxy, upstreamUrl: connection.upstream_url,
        method, caPath: $('ca-path').value, allowedHeaders: connection.allowed_headers});
    } catch {
      $('client-command').textContent = 'This saved connection cannot generate a supported client configuration.';
      $('client-guidance').textContent = 'Select another connection or refresh its status.'; return;
    }
    $('client-command').textContent = state.command;
    $('copy-command').disabled = !connectionReady(connection);
    $('download-config').disabled = !connectionReady(connection) || !state.token || state.tokenConnection !== connection.id;
    $('client-guidance').textContent = (connectionReady(connection) ? 'Policy loaded and client token not expired. This command is a configuration example, not a successful request test.' :
      'Waiting for the saved policy to be loaded. Copy/download will be available after activation.') +
      (connection.request_fields.length ? ' If your endpoint requires a body, send application/json using only the approved request fields. Media type is controlled by the JSON policy; do not add Content-Type to the allowed-header list.' : ' Request bodies are forbidden for this connection.');
  }
  async function copy(value, target) {
    try { await navigator.clipboard.writeText(value); $(target).textContent = 'Copied. Keep the clipboard private.'; }
    catch { $(target).textContent = 'Clipboard access was denied. Select and copy the displayed value manually.'; }
  }
  function downloadConfig() {
    refreshClientLifecycle();
    if ($('download-config').disabled) return;
    const connection = selectedConnection();
    if (!connection || !state.token || state.tokenConnection !== connection.id || !connectionReady(connection)) return;
    const config = {proxy_url: state.status.proxy_url, upstream_url: connection.upstream_url, methods: connection.methods,
      ca_file: $('ca-path').value || './serverware-ca.pem', proxy_authorization: 'Bearer ' + state.token,
      token_expires_at_epoch_ms: connection.token_expires_at_epoch_ms,
      note: 'Private client configuration. Development only. Never commit this file. The provider credential is not included.'};
    const url = URL.createObjectURL(new Blob([JSON.stringify(config, null, 2) + '\n'], {type: 'application/json'}));
    const anchor = node('a'); anchor.href = url; anchor.download = 'serverware-client.private.json';
    document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    $('client-copy-status').textContent = 'Downloaded private client configuration. Keep it out of source control.';
  }
  function auditCard(event) {
    const card = node('article', undefined, 'card event-card');
    card.append(node('h3', event.event_type || 'Recorded event'), node('time', event.created_at || 'Time not reported'));
    const detail = node('details'); detail.append(node('summary', 'Event details'), node('pre', JSON.stringify(event, null, 2))); card.append(detail);
    return card;
  }
  async function loadAudit(append = false) {
    const epoch = ++state.auditEpoch;
    const selection = JSON.stringify([$('audit-filter').value, $('audit-query').value.trim()]);
    if (selection !== state.auditSelection) append = false;
    state.auditSelection = selection;
    if (!append) { state.auditCursor = null; state.auditCount = 0; $('audit-list').replaceChildren(); }
    const query = new URLSearchParams({limit: '20', scanLimit: '5000'});
    if ($('audit-filter').value) query.set('eventType', $('audit-filter').value);
    if ($('audit-query').value.trim()) query.set('q', $('audit-query').value.trim());
    if (append && state.auditCursor) query.set('cursor', state.auditCursor);
    $('audit-status').textContent = 'Loading stored events...'; $('audit-more').disabled = true;
    try {
      const result = await api('/api/audit/search?' + query);
      if (epoch !== state.auditEpoch) return;
      if (result.ok !== true || !Array.isArray(result.items)) throw problem('The audit service returned an incomplete event list.');
      for (const event of result.items) $('audit-list').append(auditCard(event));
      state.auditCount += result.items.length; state.auditCursor = result.has_more ? text(result.next_cursor) : null; state.auditLoaded = true;
      $('audit-more').hidden = !state.auditCursor;
      $('audit-status').textContent = `${state.auditCount} events shown. ` +
        (result.has_more || result.complete === false ? 'Partial history; load older events to continue.' : 'End of matching history.');
    } catch (error) { if (epoch === state.auditEpoch) { $('audit-status').textContent = message(error); state.auditLoaded = false; $('audit-more').hidden = true; } }
    finally { if (epoch === state.auditEpoch) $('audit-more').disabled = false; }
  }
  async function verifyAudit() {
    if ($('audit-verify').disabled) return;
    $('audit-verify').disabled = true; $('audit-verification').textContent = 'Checking the stored audit chain...';
    try {
      const result = await api('/api/audit/verify');
      $('audit-verification').textContent = result.ok === true && result.complete === true ? 'The complete local audit chain is consistent.' :
        result.ok === true ? 'Incomplete verification. The full chain has not been verified.' : 'Verification failed. The stored chain did not pass its integrity check.';
    } catch (error) { $('audit-verification').textContent = message(error); }
    finally { $('audit-verify').disabled = false; }
  }
  window.addEventListener('hashchange', navigate);
  window.addEventListener('pagehide', () => { clearTimeout(state.poll); clearTimeout(state.expiryTimer); clearToken(); $('provider-secret').value = ''; });
  window.addEventListener('focus', refreshClientLifecycle);
  window.addEventListener('pageshow', refreshClientLifecycle);
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refreshClientLifecycle(); });
  $('connection-form').addEventListener('submit', submit);
  $('auth-type').addEventListener('change', () => { const custom = $('auth-type').value === 'header'; $('header-field').hidden = !custom; $('header-name').required = custom; });
  for (const id of ['retry-load', 'refresh-status', 'proxy-refresh']) $(id).addEventListener('click', () => loadStatus());
  $('reveal-token').addEventListener('click', () => { refreshClientLifecycle(); if (!state.token) return; const reveal = $('client-token').type === 'password'; $('client-token').type = reveal ? 'text' : 'password'; $('reveal-token').textContent = reveal ? 'Hide' : 'Reveal'; $('reveal-token').setAttribute('aria-pressed', String(reveal)); });
  $('copy-token').addEventListener('click', () => { refreshClientLifecycle(); if (state.token) copy(state.token, 'token-status'); });
  $('dismiss-token').addEventListener('click', () => { if (state.token && window.confirm('Clear this one-time token? You must have saved it to use this connection.')) { clearToken(); refreshClientLifecycle(); } });
  $('client-connection').addEventListener('change', () => { state.selected = $('client-connection').value; renderClient(); });
  $('ca-path').addEventListener('input', renderClient);
  $('copy-command').addEventListener('click', () => { refreshClientLifecycle(); if (!$('copy-command').disabled && state.command) copy(state.command, 'client-copy-status'); });
  $('download-config').addEventListener('click', downloadConfig);
  $('audit-refresh').addEventListener('click', () => loadAudit());
  $('audit-more').addEventListener('click', () => loadAudit(true));
  $('audit-filter').addEventListener('change', () => loadAudit());
  $('audit-search-form').addEventListener('submit', event => { event.preventDefault(); loadAudit(); });
  $('audit-verify').addEventListener('click', verifyAudit);
  navigate(); loadStatus();
})();

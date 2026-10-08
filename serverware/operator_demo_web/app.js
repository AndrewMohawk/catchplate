// The exported pure generator is also the browser's only client-example path.
// It accepts public metadata and never accepts a provider secret or client token.
function buildCurlCommand({proxyUrl, upstreamUrl, method, caPath, allowedHeaders = ['accept', 'user-agent']}) {
  const quote = value => "'" + String(value).replace(/'/g, "'\\''") + "'";
  for (const value of [proxyUrl, upstreamUrl]) {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash)
      throw new Error('Client configuration requires credential-free HTTPS URLs');
  }
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'].includes(method)) throw new Error('Invalid client method');
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
    auditSelection: '', auditCount: 0, auditLoaded: false};
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
    state.token = ''; state.tokenConnection = '';
    $('client-token').value = ''; $('client-token').type = 'password';
    $('one-time-access').hidden = true; $('reveal-token').textContent = 'Reveal';
    $('reveal-token').setAttribute('aria-pressed', 'false');
    $('download-config').disabled = true;
  }
  async function api(path, options = {}) {
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
      const descriptions = {409: 'The configuration changed or this connection already exists. Refresh saved connections before submitting again.',
        422: 'Check the upstream, exact path, methods and field lists. The server rejected this configuration.',
        503: 'The service could not confirm policy publication or activation. Refresh saved connections before submitting again.'};
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
  function connectionActive(connection) {
    return active() && connection.policy_hash === state.status.active_policy_hash && connection.activation === 'active';
  }
  function metadata(connection) {
    // Explicit public metadata projection. Never retain unknown response fields.
    const allowed = ['id', 'name', 'upstream_url', 'auth_type', 'header_name', 'credential_id', 'principal_id',
      'created_at', 'token_expires_at_epoch_ms', 'policy_hash', 'activation'];
    const result = Object.fromEntries(allowed.map(key => [key, connection[key]]));
    for (const key of ['methods', 'request_fields', 'response_fields', 'query_keys', 'allowed_headers'])
      result[key] = Array.isArray(connection[key]) ? connection[key].filter(value => typeof value === 'string') : [];
    return result;
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
    $('connection-fields').disabled = state.submitting || !status.allowed_upstreams.length;
    if (!status.allowed_upstreams.length) $('form-status').textContent = 'No upstream is configured. Ask the deployment operator to approve a destination.';
    const cards = status.connections.map(connection => {
      const card = node('article', undefined, 'card'); card.dataset.connectionId = text(connection.id);
      const head = node('div', undefined, 'connection-head'); const ready = connectionActive(connection);
      head.append(node('h3', connection.name), node('span', ready ? 'Active' : 'Pending activation', 'badge' + (ready ? ' active' : '')));
      card.append(head);
      const expires = new Date(connection.token_expires_at_epoch_ms);
      appendMetadata(card, [['Exact URL', connection.upstream_url], ['Methods', connection.methods.join(', ')],
        ['Provider auth', connection.auth_type === 'bearer' ? 'Bearer token' : connection.header_name],
        ['Response fields', connection.response_fields.join(', ')], ['Request fields', connection.request_fields.join(', ')],
        ['Query keys', connection.query_keys.join(', ')], ['Client token expiry', Number.isNaN(expires.getTime()) ? 'Not reported' : expires.toLocaleString()]]);
      const button = node('button', 'Configure this client', 'secondary'); button.type = 'button';
      button.addEventListener('click', () => { state.selected = connection.id; $('client-connection').value = connection.id; renderClient(); location.hash = 'proxy'; });
      card.append(node('p', 'Provider credential stored. Its value is never returned by this page.', 'small muted'), button);
      return card;
    });
    $('connections-list').replaceChildren(...(cards.length ? cards : [node('p', 'No connections yet. Add your first credential above.', 'muted')]));
    $('client-connection').replaceChildren();
    if (!status.connections.length) { const option = node('option', 'Add a credential first'); option.value = ''; $('client-connection').append(option); }
    for (const connection of status.connections) { const option = node('option', connection.name); option.value = connection.id; $('client-connection').append(option); }
    if (!status.connections.some(connection => connection.id === state.selected)) state.selected = status.connections[0]?.id || '';
    $('client-connection').value = state.selected;
    renderClient();
  }
  async function loadStatus({poll = false} = {}) {
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
      state.status = {mode: result.mode, proxy_url: proxyValid ? proxy.href.replace(/\/$/, '') : '',
        allowed_upstreams: result.allowed_upstreams.filter(value => typeof value === 'string' && httpsUrl(value, true)),
        connections: result.connections.map(metadata), active_policy_hash: result.active_policy_hash, loaded_policy_hash: result.loaded_policy_hash};
      $('load-error').hidden = true; renderStatus();
      if ($('form-status').textContent === 'Loading workspace...') $('form-status').textContent = 'Ready. Use a disposable, least-privilege provider credential.';
      if (!active() && state.status.connections.length && state.polls++ < 30)
        state.poll = setTimeout(() => loadStatus({poll: true}), 4000);
      if (location.hash === '#audit' && !state.auditLoaded) loadAudit();
    } catch (error) {
      if (epoch !== state.statusEpoch) return;
      state.status = null; $('connection-fields').disabled = true;
      $('load-error-text').textContent = message(error); $('load-error').hidden = false;
      $('overview-policy').textContent = 'Activation unknown. Status could not be loaded.';
      $('activation-status').textContent = 'Activation unknown. Refresh status before use.';
      $('copy-command').disabled = true; $('download-config').disabled = true;
      for (const badge of document.querySelectorAll('#connections-list .badge')) { badge.textContent = 'Status unavailable'; badge.className = 'badge'; }
    }
  }
  async function submit(event) {
    event.preventDefault();
    if (state.submitting || !state.status || !$('connection-form').reportValidity()) return;
    const methods = [...document.querySelectorAll('input[name="method"]:checked')].map(input => input.value);
    const path = $('upstream-path').value.trim(); const origin = $('upstream-origin').value;
    if (!methods.length || !path.startsWith('/') || path.startsWith('//') || /[?#\\\s*]/.test(path) ||
        !state.status.allowed_upstreams.includes(origin) || !fields('response-fields').length) {
      $('form-status').textContent = 'Select at least one method, an approved upstream, an exact path and at least one response field.'; return;
    }
    if (state.token && !window.confirm('Creating another connection clears the previous one-time token from this page. Have you saved it?')) return;
    clearToken(); state.submitting = true; $('connection-fields').disabled = true;
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
      result.client_token = ''; $('client-token').value = state.token; $('one-time-access').hidden = false;
      $('token-status').textContent = 'Save the token now. Clipboard and downloaded files are outside Serverware; keep them private.';
      $('form-status').textContent = 'Credential saved. Save the one-time client token below; checking proxy activation...';
      $('connection-form').reset(); $('header-field').hidden = true; $('header-name').required = false;
      state.auditLoaded = false;
      await loadStatus();
      $('one-time-access').scrollIntoView({block: 'nearest'});
    } catch (error) { $('form-status').textContent = message(error); }
    finally { body.secret = ''; $('provider-secret').value = ''; state.submitting = false;
      $('connection-fields').disabled = !state.status?.allowed_upstreams.length; }
  }
  function selectedConnection() { return state.status?.connections.find(connection => connection.id === state.selected); }
  function renderClient() {
    const connection = selectedConnection(); const proxy = state.status?.proxy_url;
    state.command = ''; $('copy-command').disabled = true; $('download-config').disabled = true;
    if (!connection || !proxy || !httpsUrl(connection.upstream_url) || !connection.methods.length) {
      $('client-command').textContent = connection ? 'A valid public HTTPS proxy endpoint is not configured.' : 'Add a credential to generate a scoped example.';
      $('client-guidance').textContent = ''; return;
    }
    const method = connection.methods[0];
    state.command = buildCurlCommand({proxyUrl: proxy, upstreamUrl: connection.upstream_url,
      method, caPath: $('ca-path').value, allowedHeaders: connection.allowed_headers});
    $('client-command').textContent = state.command;
    $('copy-command').disabled = !connectionActive(connection);
    $('download-config').disabled = !connectionActive(connection) || !state.token || state.tokenConnection !== connection.id;
    $('client-guidance').textContent = (connectionActive(connection) ? 'Active policy confirmed. This command is a configuration example, not a successful request test.' :
      'Waiting for the saved policy to be loaded. Copy/download will be available after activation.') +
      (connection.request_fields.length ? ' If your endpoint requires a body, add your own JSON using only the approved request fields and an allowed Content-Type header.' : ' Request bodies are forbidden for this connection.');
  }
  async function copy(value, target) {
    try { await navigator.clipboard.writeText(value); $(target).textContent = 'Copied. Keep the clipboard private.'; }
    catch { $(target).textContent = 'Clipboard access was denied. Select and copy the displayed value manually.'; }
  }
  function downloadConfig() {
    if ($('download-config').disabled) return;
    const connection = selectedConnection();
    if (!connection || !state.token || state.tokenConnection !== connection.id || !connectionActive(connection)) return;
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
  window.addEventListener('pagehide', () => { clearTimeout(state.poll); clearToken(); $('provider-secret').value = ''; });
  $('connection-form').addEventListener('submit', submit);
  $('auth-type').addEventListener('change', () => { const custom = $('auth-type').value === 'header'; $('header-field').hidden = !custom; $('header-name').required = custom; });
  for (const id of ['retry-load', 'refresh-status', 'proxy-refresh']) $(id).addEventListener('click', () => loadStatus());
  $('reveal-token').addEventListener('click', () => { const reveal = $('client-token').type === 'password'; $('client-token').type = reveal ? 'text' : 'password'; $('reveal-token').textContent = reveal ? 'Hide' : 'Reveal'; $('reveal-token').setAttribute('aria-pressed', String(reveal)); });
  $('copy-token').addEventListener('click', () => { if (state.token) copy(state.token, 'token-status'); });
  $('dismiss-token').addEventListener('click', () => { if (window.confirm('Clear this one-time token? You must have saved it to use this connection.')) clearToken(); });
  $('client-connection').addEventListener('change', () => { state.selected = $('client-connection').value; renderClient(); });
  $('ca-path').addEventListener('input', renderClient);
  $('copy-command').addEventListener('click', () => { if (!$('copy-command').disabled && state.command) copy(state.command, 'client-copy-status'); });
  $('download-config').addEventListener('click', downloadConfig);
  $('audit-refresh').addEventListener('click', () => loadAudit());
  $('audit-more').addEventListener('click', () => loadAudit(true));
  $('audit-filter').addEventListener('change', () => loadAudit());
  $('audit-search-form').addEventListener('submit', event => { event.preventDefault(); loadAudit(); });
  $('audit-verify').addEventListener('click', verifyAudit);
  navigate(); loadStatus();
})();

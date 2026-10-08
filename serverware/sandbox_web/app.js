/* The fixed sandbox console uses existing authenticated APIs only. No secrets,
 * provider setup, policy writes or server reconfiguration happen in this UI. */
(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const views = {overview: 'Overview', proxy: 'Proxy setup', credentials: 'Credentials', access: 'Access rules', audit: 'Audit log'};
  const state = {loaded: false, loading: false, running: false, caLoaded: false, caLoading: false,
    policy: null, auditLoaded: false, auditCursor: null, auditEpoch: 0, auditCount: 0, auditQuery: null};
  const outcomes = [
    {title: 'Allowed request', checks: ['connect_tls_credential_injection_and_header_redaction'],
      description: 'The API received the test credential. The client received only the permitted response fields.'},
    {title: 'Unauthorized requests blocked', checks: ['connect_identity_and_destination_denials',
      'caller_credential_collision_denied_without_dispatch', 'route_denials_without_upstream_dispatch'],
      description: 'Requests outside the tested identity, destination and access rules were refused.'},
    {title: 'Unsafe response blocked', checks: ['credential_reflection_blocked'],
      description: 'The API tried to return its credential. Serverware blocked that response before it reached the client.'},
    {title: 'Activity recorded', checks: ['stored_correlated_audit_without_credential_material'],
      description: 'Matching request and response events were found in the stored audit log, without the tested secrets.'},
  ];
  const requiredChecks = ['synthetic_profile_and_exact_rust_build',
    'unsupported_streaming_transform_denied_without_dispatch', ...outcomes.flatMap(outcome => outcome.checks)];

  function node(tag, text, className) {
    const element = document.createElement(tag);
    if (text !== undefined) element.textContent = String(text);
    if (className) element.className = className;
    return element;
  }
  function details(label, value) {
    const element = node('details');
    element.append(node('summary', label), node('pre', JSON.stringify(value, null, 2)));
    return element;
  }
  function settings(entries) {
    const list = node('dl', undefined, 'settings');
    for (const [key, value] of entries) list.append(node('dt', key), node('dd', value ?? 'Not specified'));
    return list;
  }
  function message(error) { return error.uiMessage || 'The request could not be completed. Check your connection, or reload to sign in again.'; }
  function problem(text) { const error = new Error('UI request failed'); error.uiMessage = text; return error; }
  async function api(path, options = {}) {
    const response = await fetch(path, {credentials: 'same-origin', cache: 'no-store',
      signal: AbortSignal.timeout(55000), ...options});
    if (response.status === 401 || response.status === 403 || response.redirected ||
        !response.headers.get('content-type')?.includes('application/json')) {
      throw problem('Your session could not be verified. Reload this page and sign in again.');
    }
    const result = await response.json();
    if (!response.ok && path !== '/api/sandbox/check') throw problem(`Service unavailable (HTTP ${response.status}). Try again shortly.`);
    return {result, ok: response.ok};
  }

  function navigate(focus = false) {
    let name = location.hash.slice(1) || 'overview';
    if (name === 'limitations') { $('limitations').open = true; $('limitations').scrollIntoView(); return; }
    if (!Object.hasOwn(views, name)) { name = 'overview'; history.replaceState(null, '', '#overview'); }
    for (const [id, label] of Object.entries(views)) {
      $(id).hidden = id !== name;
      const link = document.querySelector(`nav a[href="#${id}"]`);
      if (id === name) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
      if (id === name) { $('page-label').textContent = label; document.title = `${label} - Serverware`; }
    }
    if (state.loaded && name === 'proxy') loadCA();
    if (state.loaded && name === 'audit' && !state.auditLoaded) loadAudit();
    if (focus) {
      const heading = $(name).querySelector('h1'); heading.tabIndex = -1; heading.focus({preventScroll: true});
      window.scrollTo({top: 0, behavior: 'instant'});
    }
  }

  function renderCredentials(credentials) {
    $('credentials-list').replaceChildren();
    $('credential-count').textContent = `${credentials.length} stored ${credentials.length === 1 ? 'credential' : 'credentials'}`;
    if (!credentials.length) { $('credentials-list').append(node('p', 'No stored credentials were returned for this workspace.', 'notice')); return; }
    for (const credential of credentials) {
      const card = node('article', undefined, 'card');
      const header = node('div', undefined, 'credential-header');
      header.append(node('h2', credential.name), node('span', 'Test credential', 'badge neutral'));
      const routes = (state.policy.bundle?.routes || []).filter(route => route.credentialRef === credential.id);
      card.append(header, node('p', '•••• •••• •••• ••••', 'masked-key'),
        node('p', 'The secret is used by the proxy, not displayed or delivered to your application.', 'small muted'),
        settings([['Type', credential.kind], ['Version', credential.credential_version ?? credential.version],
          ['Account', credential.metadata?.provider_subject], ['State', credential.lifecycle_status],
          ['Referenced by', `${routes.length} configured access rules`]]),
        details('Credential reference', {id: credential.id, kind: credential.kind,
          version: credential.credential_version ?? credential.version,
          provider: credential.metadata?.provider_id, account: credential.metadata?.provider_subject}));
      const link = node('a', 'See access rules →', 'text-link'); link.href = '#access'; card.append(link);
      $('credentials-list').append(card);
    }
  }
  function ruleSummary(route) {
    const match = route.match || {};
    const block = node('div', undefined, 'rule');
    const title = node('h3', `${match.host || 'Unknown destination'}${match.port ? ':' + match.port : ''}`);
    block.append(title);
    const methods = node('p');
    for (const method of match.methods || []) methods.append(node('span', method, 'badge'));
    methods.append(node('code', (match.paths || []).join(', '))); block.append(methods);
    block.append(node('p', `Application identities: ${(route.principals || []).join(', ') || 'None'}`));
    block.append(details('Rule details', route));
    return block;
  }
  function renderPolicy(policy) {
    const routes = policy.bundle?.routes || [];
    $('policy-summary').textContent = policy.ready ? `${routes.length} configured rules` : 'Policy unavailable';
    $('policy-json').textContent = JSON.stringify({policy_hash: policy.policy_hash, ready: policy.ready, bundle: policy.bundle}, null, 2);
    $('demo-rule').replaceChildren();
    const echo = routes.find(route => route.id === 'demo.echo');
    if (echo) {
      $('demo-rule').append(ruleSummary(echo), node('p', 'This rule lets the demo application call the test API with the stored credential. Serverware checks both the request and the returned response.', 'small muted'));
      $('demo-rule').append(settings([['Stored credential', echo.credentialRef],
        ['Allowed request fields', (echo.adapter?.config?.request?.allowedFields || []).join(', ') || 'None'],
        ['Returned response fields', (echo.adapter?.config?.response?.allowedFields || []).join(', ') || 'None'],
        ['Unknown or unsafe response', 'Blocked by response validation']]));
    } else $('demo-rule').append(node('p', 'The demo rule is missing from the signed policy.', 'error-text'));
    $('other-rules-label').textContent = `Other configured rules (${routes.filter(route => route.id !== 'demo.echo').length})`;
    renderOtherRules();
  }
  function renderOtherRules() {
    const search = $('rule-search').value.trim().toLowerCase();
    const rules = (state.policy?.bundle?.routes || []).filter(route => route.id !== 'demo.echo' &&
      JSON.stringify({id: route.id, match: route.match, principals: route.principals}).toLowerCase().includes(search));
    $('other-rules').replaceChildren(...rules.map(ruleSummary));
    if (!rules.length) $('other-rules').append(node('p', 'No configured rules match this search.', 'muted'));
  }

  async function loadWorkspace() {
    if (state.loading) return;
    state.loading = true; state.loaded = false; $('sandbox-run-check').disabled = true;
    $('load-error').hidden = true; $('retry-load').disabled = true;
    try {
      const [{result: profile}, {result: auth}] = await Promise.all([api('/api/sandbox/status'), api('/api/auth/status')]);
      if (profile.mode !== 'synthetic-development' || profile.syntheticOnly !== true || profile.productionReady !== false ||
          profile.hardwareVerified !== false || !auth.authenticated) throw problem('This page requires an authenticated synthetic sandbox workspace.');
      const [{result: bootstrap}, {result: policy}] = await Promise.all([api('/api/bootstrap'), api('/api/policy')]);
      if (!Array.isArray(bootstrap.credentials) || !Array.isArray(policy.bundle?.routes)) throw problem('Workspace configuration is incomplete. Try again or check the service.');
      state.policy = policy;
      $('operator-auth-status').textContent = bootstrap.currentUserId || auth.userId || auth.user || 'Signed in';
      renderPolicy(policy); renderCredentials(bootstrap.credentials); state.loaded = true;
      $('sandbox-run-check').disabled = !policy.ready;
      $('sandbox-check-result').textContent = policy.ready ? 'Ready when you are. Nothing is sent until you run the demo.' : 'The signed policy is not ready. Reload after checking the service.';
      navigate();
    } catch (error) {
      $('load-error-text').textContent = message(error); $('load-error').hidden = false;
      $('operator-auth-status').textContent = 'Workspace unavailable';
      $('sandbox-check-result').textContent = 'Load the workspace before running the demo.';
    } finally { state.loading = false; $('retry-load').disabled = false; }
  }

  function renderOutcomes(checks) {
    const completed = new Set(checks);
    $('demo-results').replaceChildren(...outcomes.map(outcome => {
      const passed = outcome.checks.every(check => completed.has(check));
      const card = node('article', undefined, 'result'); card.dataset.state = passed ? 'passed' : 'unverified';
      card.append(node('span', passed ? 'Passed' : 'Not verified', `badge ${passed ? '' : 'neutral'}`),
        node('h3', outcome.title), node('p', passed ? outcome.description : 'This outcome has not been verified by this run.'));
      return card;
    }));
    $('demo-results').hidden = false;
  }
  async function runDemo() {
    if (state.running || !state.loaded || $('sandbox-run-check').disabled) return;
    state.running = true; $('sandbox-run-check').disabled = true;
    $('sandbox-check-result').dataset.state = 'running';
    $('sandbox-check-result').textContent = 'Running real proxy requests and waiting for their audit records...';
    $('demo-results').hidden = true; $('demo-followup').hidden = true;
    try {
      const {result, ok} = await api('/api/sandbox/check', {method: 'POST'});
      const checks = Array.isArray(result.checks) ? result.checks : [];
      renderOutcomes(checks);
      $('check-json').textContent = JSON.stringify(result, null, 2); $('demo-followup').hidden = false;
      if (!ok || result.ok !== true || !requiredChecks.every(check => checks.includes(check))) {
        throw problem(result.error || 'The proxy returned an incomplete check result. Review the completed outcomes below.');
      }
      $('sandbox-check-result').dataset.state = 'passed';
      $('sandbox-check-result').textContent = 'Demo passed. Allowed requests worked, unsafe requests and responses were blocked, and activity was recorded.';
    } catch (error) {
      $('sandbox-check-result').dataset.state = 'failed';
      $('sandbox-check-result').textContent = `Demo failed: ${message(error)} No automatic retry was made.`;
    } finally {
      state.running = false; $('sandbox-run-check').disabled = false;
      state.auditLoaded = false;
      if (location.hash === '#audit') loadAudit();
    }
  }

  async function loadCA() {
    if (state.caLoaded || state.caLoading) return;
    state.caLoading = true; $('ca-error').textContent = ''; $('ca-fingerprint').textContent = 'Loading certificate...';
    try {
      const response = await fetch('/ca.pem', {credentials: 'same-origin', cache: 'no-store', signal: AbortSignal.timeout(15000)});
      if (!response.ok || response.redirected) throw problem('CA download unavailable. Reload to check your session, then try the download again.');
      const pem = await response.text();
      const match = /^-----BEGIN CERTIFICATE-----\s+([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----\s*$/.exec(pem);
      if (!match || pem.length > 65536) throw problem('A valid public CA certificate was not returned. Do not install this response.');
      const der = Uint8Array.from(atob(match[1].replace(/\s/g, '')), char => char.charCodeAt(0));
      const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', der));
      $('ca-fingerprint').textContent = [...digest].map(byte => byte.toString(16).padStart(2, '0').toUpperCase()).join(':');
      state.caLoaded = true;
    } catch (error) { $('ca-fingerprint').textContent = 'Unavailable'; $('ca-error').textContent = message(error); }
    finally { state.caLoading = false; }
  }
  function shellQuote(value) { return "'" + value.replaceAll("'", "'\\''") + "'"; }
  function saveClientPreferences() {
    try { localStorage.setItem('serverware.sandbox.client.v1', JSON.stringify({client: $('client-type').value, ca: $('ca-path').value})); } catch (_) { /* Private browsing may disallow storage; generation still works. */ }
  }
  function renderCommand() {
    const ca = $('ca-path').value.trim();
    const valid = ca.length > 0 && ca.length <= 512 && !/[\x00-\x1f\x7f]/.test(ca);
    $('ca-path').setCustomValidity(valid ? '' : 'Enter a CA file path without control characters.');
    $('copy-proxy-command').disabled = !valid;
    $('copy-status').textContent = '';
    if (!valid) { $('proxy-command').textContent = 'Enter the downloaded CA file path to generate your configuration.'; return; }
    const proxy = 'http://decision-gate-rs:9090';
    if ($('client-type').value === 'python') {
      $('proxy-command').textContent = '# Run inside the sandbox network; trust only this downloaded CA.\n' +
        'import http.client\nimport ssl\n\n' +
        `context = ssl.create_default_context(cafile=${JSON.stringify(ca)})\n` +
        'connection = http.client.HTTPSConnection("decision-gate-rs", 9090, context=context, timeout=10)\n' +
        'connection.set_tunnel("demo-upstream", 8443, headers={"X-Serverware-Agent": "demo-agent"})\n' +
        'try:\n    # Send only the headers allowed by this demo policy.\n' +
        '    connection.putrequest("GET", "/echo", skip_host=True, skip_accept_encoding=True)\n' +
        '    connection.putheader("Host", "demo-upstream:8443")\n' +
        '    connection.putheader("X-Serverware-Agent", "demo-agent")\n' +
        '    connection.putheader("Connection", "close")\n    connection.endheaders()\n' +
        '    response = connection.getresponse()\n    print(response.status, response.read().decode())\n' +
        'finally:\n    connection.close()';
    } else {
      $('proxy-command').textContent = '# Run inside the sandbox network, with the downloaded CA file.\n' +
        "curl --fail-with-body --max-time 10 --noproxy '' \\\n" +
        `  --proxy ${shellQuote(proxy)} \\\n  --cacert ${shellQuote(ca)} \\\n` +
        "  --proxy-header 'X-Serverware-Agent: demo-agent' \\\n" +
        "  --header 'X-Serverware-Agent: demo-agent' \\\n" +
        "  'https://demo-upstream:8443/echo'";
    }
    saveClientPreferences();
  }
  async function copyCommand() {
    try { await navigator.clipboard.writeText($('proxy-command').textContent); $('copy-status').textContent = 'Copied.'; }
    catch (_) { $('copy-status').textContent = 'Clipboard unavailable. Select and copy the configuration above.'; }
  }

  const eventLabels = {
    'data_plane.response.released': ['Allowed response', 'passed', 'The response passed validation and was returned to the application.'],
    'data_plane.response.blocked': ['Blocked response', 'blocked', 'The API response failed validation and was not returned to the application.'],
    'data_plane.credential.release_started': ['Credential use started', 'neutral', 'The proxy began using a credential for an authorized request. This is not a completed response.'],
    'data_plane.credential_lease.issued': ['Proxy credential lease issued', 'neutral', 'Internal credential delivery to the proxy; not to the calling application.'],
    'ca.direct_download': ['Development CA downloaded', 'neutral', 'The public development certificate was requested. No private key was downloaded.'],
    'control_plane.bootstrap': ['Workspace opened', 'neutral', 'The operator console read its configuration.'],
  };
  function auditCard(event) {
    const payload = event.event || {};
    const [title, tone, description] = eventLabels[event.event_type] || [event.event_type, 'neutral', 'A stored audit event. Expand the details for the exact record.'];
    const card = node('article', undefined, 'card audit-card'); card.dataset.eventId = event.id;
    const head = node('div', undefined, 'audit-event-head');
    const heading = node('h3', title); heading.append(node('span', tone === 'passed' ? 'Allowed' : tone === 'blocked' ? 'Blocked' : 'Recorded', `badge ${tone}`));
    const date = new Date(event.created_at);
    const time = node('time', Number.isNaN(date.getTime()) ? 'Time unavailable' : date.toLocaleString()); time.dateTime = event.created_at || '';
    head.append(heading, time);
    const context = [payload.method, payload.route_id, payload.principal_id].filter(Boolean).join(' · ');
    card.append(head, node('p', context || event.actor_id || 'System event', 'event-subtitle'), node('p', description, 'small muted'), details('Event details', event));
    return card;
  }
  async function loadAudit(append = false) {
    const epoch = ++state.auditEpoch;
    const filter = $('audit-filter').value;
    const search = $('audit-query').value.trim();
    const selection = JSON.stringify([filter, search]);
    // A cursor is valid only for the filters that issued it. Editing a search
    // before clicking "older" starts that search rather than reusing its cursor.
    if (state.auditQuery !== selection) append = false;
    state.auditQuery = selection;
    if (!append) { state.auditCursor = null; state.auditCount = 0; $('audit-list').replaceChildren(); }
    $('audit-status').textContent = 'Loading stored events...'; $('audit-more').disabled = true; $('audit-refresh').disabled = true;
    const query = new URLSearchParams({limit: '20', scanLimit: '5000'});
    if (filter === 'released' || filter === 'blocked') query.set('eventType', `data_plane.response.${filter}`);
    // Outcome selection is performed server-side. The existing API supports one
    // literal text query, so an additional user query filters this bounded page.
    if (!filter) query.set('q', 'data_plane.response.');
    else if (search) query.set('q', search);
    if (append && state.auditCursor) query.set('cursor', state.auditCursor);
    try {
      const {result} = await api('/api/audit/search?' + query);
      if (epoch !== state.auditEpoch) return;
      if (result.ok !== true || !Array.isArray(result.items)) throw problem('The audit service returned an incomplete event list.');
      const items = !filter ? result.items.filter(event =>
        ['data_plane.response.released', 'data_plane.response.blocked'].includes(event.event_type) &&
        (!search || JSON.stringify(event).toLowerCase().includes(search.toLowerCase()))) : result.items;
      for (const event of items) $('audit-list').append(auditCard(event));
      state.auditCount += items.length; state.auditCursor = result.has_more ? result.next_cursor : null; state.auditLoaded = true;
      $('audit-more').hidden = !state.auditCursor;
      const partial = result.has_more || result.complete === false;
      $('audit-status').textContent = `${state.auditCount} events shown. ${partial ? 'Older events are available; this is not the full history.' : 'End of matching history.'}` +
        (!filter && search ? ' Search applies to loaded request outcomes; load older events to continue searching.' : '');
      if (!state.auditCount) $('audit-status').textContent = partial ? 'No matching events in the loaded page. Older pages may match; use Load older events to keep looking.' : 'No matching events. Run the demo or change the filters.';
    } catch (error) {
      if (epoch !== state.auditEpoch) return;
      $('audit-status').textContent = message(error); state.auditLoaded = false; $('audit-more').hidden = true;
    } finally {
      if (epoch === state.auditEpoch) { $('audit-more').disabled = false; $('audit-refresh').disabled = false; }
    }
  }
  async function verifyAudit() {
    if ($('audit-verify').disabled) return;
    $('audit-verify').disabled = true; $('audit-verification').textContent = 'Checking the stored event chain...';
    try {
      const {result} = await api('/api/audit/verify');
      $('audit-verification').textContent = result.ok === true && result.complete === true ?
        'Verified. The complete local audit chain is consistent.' : result.ok === true ?
        'Incomplete verification. The full local audit chain has not been verified.' :
        'Verification failed. The stored audit chain did not pass its integrity check.';
    } catch (error) { $('audit-verification').textContent = message(error); }
    finally { $('audit-verify').disabled = false; }
  }

  try {
    const saved = JSON.parse(localStorage.getItem('serverware.sandbox.client.v1') || 'null');
    if (saved && ['curl', 'python'].includes(saved.client) && typeof saved.ca === 'string' && saved.ca.length <= 512) {
      $('client-type').value = saved.client; $('ca-path').value = saved.ca;
    }
  } catch (_) { /* Only optional, non-secret client preferences are stored. */ }
  $('sandbox-run-check').addEventListener('click', runDemo);
  $('retry-load').addEventListener('click', loadWorkspace);
  $('client-type').addEventListener('change', renderCommand);
  $('ca-path').addEventListener('input', renderCommand);
  $('copy-proxy-command').addEventListener('click', copyCommand);
  $('rule-search').addEventListener('input', renderOtherRules);
  $('audit-refresh').addEventListener('click', () => loadAudit());
  $('audit-more').addEventListener('click', () => loadAudit(true));
  $('audit-filter').addEventListener('change', () => loadAudit());
  $('audit-search-form').addEventListener('submit', event => { event.preventDefault(); loadAudit(); });
  $('audit-verify').addEventListener('click', verifyAudit);
  window.addEventListener('hashchange', () => navigate(true));
  renderCommand(); navigate(); loadWorkspace();
})();

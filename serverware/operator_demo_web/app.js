// The exported pure generator is also the browser's only client-example path.
// It accepts public metadata and never accepts a provider secret or client token.
const CLIENT_METHODS = Object.freeze(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
function credentialHeaderTarget(credential) {
  const bearer = ['bearer', 'google_oauth', 'x_oauth'].includes(credential?.auth_type);
  const name = bearer && credential.header_name === 'Authorization' ? 'Authorization' :
    credential?.auth_type === 'header' ? credential.header_name : null;
  if (typeof name !== 'string' || !/^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,128}$/.test(name))
    throw new Error('A saved bearer, Google account or custom-header credential is required');
  const canonical = name.toLowerCase().replace(/_/g, '-');
  const reserved = ['cookie', 'host', 'content-type', 'content-length', 'content-encoding', 'connection', 'keep-alive',
    'proxy-authenticate', 'proxy-authorization', 'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'upgrade'];
  if (reserved.includes(canonical) || canonical.startsWith('x-serverware-') ||
      canonical === 'authorization' && !bearer) throw new Error('The credential header cannot be replaced');
  return name;
}
function clientCredentialInput({credentialInput = 'insert', placeholder, credential} = {}) {
  if (credentialInput === 'insert') {
    if (placeholder !== undefined) throw new Error('Automatic insertion does not accept a placeholder');
    return null;
  }
  if (credentialInput !== 'replace_exact' || typeof placeholder !== 'string' || placeholder.length < 1 || placeholder.length > 1024 ||
      /[^\x20-\x7e]/.test(placeholder) || placeholder.startsWith(' ') || placeholder.endsWith(' '))
    throw new Error('Replacement requires an exact printable ASCII dummy value without outer whitespace');
  return {name: credentialHeaderTarget(credential), value: placeholder};
}
function buildCurlCommand({proxyUrl, upstreamUrl, method, caPath, allowedHeaders = ['accept', 'user-agent'],
    credentialInput = 'insert', placeholder, credential, proxyAuthentication = 'bearer', applicationId}) {
  const quote = value => "'" + String(value).replace(/'/g, "'\\''") + "'";
  for (const value of [proxyUrl, upstreamUrl]) {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash)
      throw new Error('Client configuration requires credential-free HTTPS URLs');
  }
  if (!CLIENT_METHODS.includes(method)) throw new Error('Invalid client method');
  let proxyLogin;
  if (proxyAuthentication === 'bearer') proxyLogin = ['  --proxy-header "Proxy-Authorization: Bearer $SERVERWARE_PROXY_TOKEN"'];
  else if (proxyAuthentication === 'basic_and_bearer_v1' && typeof applicationId === 'string' &&
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(applicationId))
    proxyLogin = ['  --proxy-basic', `  --proxy-user ${quote(applicationId + ':')}"$SERVERWARE_PROXY_TOKEN"`];
  else throw new Error('Unsupported proxy authentication or application username');
  const dummyHeader = clientCredentialInput({credentialInput, placeholder, credential});
  const target = dummyHeader?.name.toLowerCase();
  const insertsAccept = credentialInput === 'insert' && credential?.auth_type === 'header' && credential.header_name?.toLowerCase() === 'accept';
  const accept = !insertsAccept && allowedHeaders.some(name => name.toLowerCase() === 'accept') ? 'Accept: application/json' : 'Accept:';
  const headers = [];
  if (target !== 'accept') headers.push(`  --header ${quote(accept)}`);
  if (target !== 'user-agent') headers.push("  --header 'User-Agent:'");
  if (dummyHeader) headers.push(`  --header ${quote(dummyHeader.name + ': ' + dummyHeader.value)}`);
  return ['curl --fail-with-body --show-error --http1.1', "  --noproxy ''", `  --proxy ${quote(proxyUrl)}`,
    ...proxyLogin,
    `  --cacert ${quote(caPath || './serverware-ca.pem')}`, `  --request ${quote(method)}`,
    ...headers, `  ${quote(upstreamUrl)}`].join(' \\\n');
}

if (typeof module !== 'undefined' && module.exports) module.exports = {buildCurlCommand, clientCredentialInput, credentialHeaderTarget};
else {
  const workspace = createOperatorWorkspace();
  let reauthorization; let xAccounts; let connect;
  createCredentialsView(workspace, {reauthorize: id => reauthorization.open(id), disconnectX: id => xAccounts.disconnect(id),
    add: template => connect.addCredential(template), canAdd: () => connect.canAddCredential(), use: id => connect.selectCredential(id)}); createAccessRulesView(workspace);
  const applications = createApplicationsView(workspace);
  reauthorization = createGoogleReauthorizationView(workspace, applications);
  const proxy = createProxyView(workspace, applications); const audit = createAuditView(workspace);
  const upstreams = createUpstreamsView(workspace);
  const googleConfiguration = createGoogleConfigurationView(workspace);
  const xConfiguration = createXConfigurationView(workspace);
  connect = createConnectView(workspace, applications, proxy);
  const notifications = createNotificationsView(workspace);
  const pendingActions = createPendingActionsView({onAuthenticationLost: workspace.authenticationLost});
  const ecrPublications = createEcrPublicationsView(workspace);
  workspace.subscribe(() => pendingActions.setCatalog(workspace.state.catalog));
  pendingActions.setReviewOpener(id => {
    if (typeof id !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id))
      throw new Error('Invalid protected review identifier');
    // Keep the workspace's opener isolation. Only the dedicated, authenticated
    // coordinator may open a native popup after its explicit Open gesture.
    window.location.assign('/approvals/review/native#approval=' + id);
  });
  workspace.onAuthenticationLost(pendingActions.authenticationLost);
  xAccounts = createXAccountsView(workspace, applications, connect);
  createGoogleView(workspace, applications, connect);
  function navigate() {
    const approvalLocation = pendingApprovalLocation(location.pathname);
    let view = location.hash.slice(1) || (approvalLocation ? 'pending-actions' : 'overview');
    if (view === 'main-content') { element('main-content').focus(); return; }
    if (!Object.hasOwn(operatorViews, view)) { view = 'overview'; history.replaceState(null, '', '#overview'); }
    for (const name of Object.keys(operatorViews)) {
      element(name).hidden = name !== view;
      const link = document.querySelector('nav a[href="#' + name + '"]');
      if (link) { if (name === view) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current'); }
    }
    element('page-label').textContent = operatorViews[view]; document.title = operatorViews[view] + ' - Serverware operator workspace';
    connect.show(view === 'connect');
    notifications.show(view === 'notifications');
    pendingActions.show(view === 'pending-actions', {requestedId: approvalLocation?.id,
      invalidLink: approvalLocation?.invalid === true});
    ecrPublications.show(view === 'pending-actions');
    upstreams.show(view === 'proxy');
    googleConfiguration.show(view === 'proxy');
    xConfiguration.show(view === 'proxy');
    if (view === 'audit') audit.open();
  }
  // The retained #connect route is an action, not a second resource inventory.
  // Explicit links open access setup; the credential editor selects save-only
  // mode through its own controller entrypoint without changing API identities.
  document.addEventListener('click', event => {
    const link = event.target.closest('a[href="#connect"]');
    if (link && !connect.startSetup()) event.preventDefault();
  });
  element('overview-try-demo').addEventListener('click', () => {
    const panel = element('overview-demo-panel'); panel.hidden = !panel.hidden;
    element('overview-try-demo').setAttribute('aria-expanded', String(!panel.hidden));
  });
  function renderSyntheticDemo(catalog) {
    const rules = operatorSyntheticPermissions(catalog);
    const approved = catalog?.allowed_upstreams.includes('https://demo-upstream:8443');
    element('overview-demo-status').textContent = !catalog ? 'Refresh saved state to inspect synthetic API permissions.' :
      !rules.length ? approved ? 'No saved diagnostic permission exists. For this optional check, use a made-up Bearer value, never a real provider secret, then choose an application and explicitly allow https://demo-upstream:8443/echo. This page does not create a starter connection or send a request.' :
        'The synthetic API destination is not approved in this instance. Diagnostics are optional; your other connections remain available.' :
        rules.length + ' saved synthetic connection-check permission' + (rules.length === 1 ? '' : 's') + '. Choose one explicitly; none has been selected or tested by opening this list.';
    if (catalog && approved && !rules.length) {
      const link = textNode('a', 'Configure an optional connection check'); link.id = 'overview-demo-connect'; link.href = '#connect';
      element('overview-demo-status').append(' ', link);
    }
    renderCards('overview-demo-list', rules.map(rule => {
      const app = catalog.applications.find(item => item.id === rule.application_id);
      const credential = catalog.credentials.find(item => item.id === rule.credential_id);
      const tokenValid = app?.status === 'active' && app.token_status === 'valid' &&
        Number.isSafeInteger(app.token_expires_at_epoch_ms) && app.token_expires_at_epoch_ms > Date.now();
      const configurable = approved && rule.status === 'active' && tokenValid && operatorRuleSupported(rule, catalog);
      const state = rule.status !== 'active' ? 'Revoked permission' : !tokenValid ? 'Application access unavailable' :
        !configurable ? 'Setup unavailable' : workspace.loaded() && rule.enforcement === 'active' ? 'Policy loaded · request untested' : 'Activation pending';
      const card = resourceCard(rule, state, [['Application', app?.name || 'Unavailable client'],
        ['Account or key', credential?.name || 'Unavailable account or key'], ['Allowed request', rule.methods.join(', ') + ' ' + rule.upstream_url]]);
      card.dataset.demoRuleId = rule.id;
      const details = textNode('details'); details.append(textNode('summary', 'Details'));
      const metadata = textNode('dl', undefined, 'metadata');
      for (const [label, value] of [['Permission ID', rule.id], ['Client ID', rule.application_id], ['Credential ID', rule.credential_id]])
        metadata.append(textNode('dt', label), textNode('dd', value));
      details.append(metadata); card.append(details);
      const button = textNode('button', 'Open client setup', 'secondary'); button.dataset.demoOpen = '';
      button.disabled = !configurable || workspace.state.busy || workspace.state.uncertain;
      button.addEventListener('click', () => {
        const current = workspace.state.catalog;
        const selected = operatorSyntheticPermissions(current).find(item => item.id === rule.id);
        const selectedApp = current?.applications.find(item => item.id === selected?.application_id);
        if (!selected || workspace.state.busy || workspace.state.uncertain ||
          !current.allowed_upstreams.includes('https://demo-upstream:8443') || !operatorRuleSupported(selected, current) ||
          selectedApp?.token_status !== 'valid' || !Number.isSafeInteger(selectedApp.token_expires_at_epoch_ms) ||
          selectedApp.token_expires_at_epoch_ms <= Date.now() || !proxy.select(selected.application_id, selected.id)) {
          element('overview-demo-status').textContent = 'This saved permission is no longer available for setup. Refresh and review its application token and permissions; no request was sent.'; return;
        }
        location.hash = 'proxy';
      });
      card.append(button);
      if (!tokenValid) {
        const review = textNode('a', 'Review application access'); review.href = '#applications'; card.append(review);
      }
      return card;
    }), 'No matching saved permissions. Other accounts, applications, and permissions remain available in their management pages.');
  }
  workspace.subscribe(() => {
    const catalog = workspace.state.catalog;
    renderSyntheticDemo(catalog);
    const label = !catalog ? 'Status unavailable. Refresh before use.' : workspace.loaded() ?
      'Active: the proxy has loaded the current saved policy.' : 'Pending: the proxy has not confirmed the saved policy.';
    element('overview-policy').textContent = label; element('activation-status').textContent = label;
    element('proxy-url').textContent = catalog?.proxy_url || 'HTTPS proxy endpoint unavailable.';
    const diagnostics = operatorDiagnosticResources(catalog);
    for (const [name, collection] of [['credentials', 'credentials'], ['applications', 'applications'], ['rules', 'access_rules']])
      element('overview-' + name + '-count').textContent = catalog ? String(catalog[collection].filter(item =>
        item.status === 'active' && !diagnostics[collection].has(item.id)).length) : 'Unavailable';
    if (catalog) {
      const ordinaryApps = catalog.applications.filter(item => item.status === 'active' && !diagnostics.applications.has(item.id));
      const validApps = ordinaryApps.filter(item => item.token_status === 'valid' && item.token_expires_at_epoch_ms > Date.now());
      const step = !catalog.credentials.some(item => item.status === 'active' && !diagnostics.credentials.has(item.id)) ? ['Add your first credential', '#credentials'] :
        !validApps.length ? ordinaryApps.length ? ['Review expired client access', '#applications'] : ['Set up access with a saved credential', '#connect'] :
        !catalog.access_rules.some(item => item.status === 'active' && !diagnostics.access_rules.has(item.id) && validApps.some(app => app.id === item.application_id)) ? ['Choose permissions for your client', '#connect'] :
        !workspace.loaded() ? ['Check pending proxy activation', '#proxy'] : ['Configure your client and send a scoped test request', '#proxy'];
      element('overview-next-action').textContent = step[0]; element('overview-next-action').href = step[1];
    }
    if (location.hash === '#audit') audit.open();
  });
  for (const id of ['retry-load', 'credentials-refresh', 'applications-refresh', 'rules-refresh', 'proxy-refresh'])
    element(id).addEventListener('click', () => workspace.refresh({manual: true}));
  window.addEventListener('hashchange', navigate);
  navigate(); workspace.refresh();
}

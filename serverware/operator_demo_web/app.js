// The exported pure generator is also the browser's only client-example path.
// It accepts public metadata and never accepts a provider secret or client token.
const CLIENT_METHODS = Object.freeze(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']);
function credentialHeaderTarget(credential) {
  const bearer = ['bearer', 'google_oauth'].includes(credential?.auth_type);
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
    credentialInput = 'insert', placeholder, credential}) {
  const quote = value => "'" + String(value).replace(/'/g, "'\\''") + "'";
  for (const value of [proxyUrl, upstreamUrl]) {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash)
      throw new Error('Client configuration requires credential-free HTTPS URLs');
  }
  if (!CLIENT_METHODS.includes(method)) throw new Error('Invalid client method');
  const dummyHeader = clientCredentialInput({credentialInput, placeholder, credential});
  const target = dummyHeader?.name.toLowerCase();
  const insertsAccept = credentialInput === 'insert' && credential?.auth_type === 'header' && credential.header_name?.toLowerCase() === 'accept';
  const accept = !insertsAccept && allowedHeaders.some(name => name.toLowerCase() === 'accept') ? 'Accept: application/json' : 'Accept:';
  const headers = [];
  if (target !== 'accept') headers.push(`  --header ${quote(accept)}`);
  if (target !== 'user-agent') headers.push("  --header 'User-Agent:'");
  if (dummyHeader) headers.push(`  --header ${quote(dummyHeader.name + ': ' + dummyHeader.value)}`);
  return ['curl --fail-with-body --show-error --http1.1', "  --noproxy ''", `  --proxy ${quote(proxyUrl)}`,
    '  --proxy-header "Proxy-Authorization: Bearer $SERVERWARE_PROXY_TOKEN"',
    `  --cacert ${quote(caPath || './serverware-ca.pem')}`, `  --request ${quote(method)}`,
    ...headers, `  ${quote(upstreamUrl)}`].join(' \\\n');
}

if (typeof module !== 'undefined' && module.exports) module.exports = {buildCurlCommand, clientCredentialInput, credentialHeaderTarget};
else {
  const workspace = createOperatorWorkspace();
  createCredentialsView(workspace); createAccessRulesView(workspace);
  const applications = createApplicationsView(workspace);
  const proxy = createProxyView(workspace, applications); const audit = createAuditView(workspace);
  const connect = createConnectView(workspace, applications, proxy);
  function navigate() {
    let view = location.hash.slice(1) || 'connect';
    if (view === 'main-content') { element('main-content').focus(); return; }
    if (!Object.hasOwn(operatorViews, view)) { view = 'connect'; history.replaceState(null, '', '#connect'); }
    for (const name of Object.keys(operatorViews)) {
      element(name).hidden = name !== view;
      const link = document.querySelector('nav a[href="#' + name + '"]');
      if (name === view) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    }
    element('page-label').textContent = operatorViews[view]; document.title = operatorViews[view] + ' - Serverware operator workspace';
    connect.show(view === 'connect');
    if (view === 'audit') audit.open();
  }
  workspace.subscribe(() => {
    const catalog = workspace.state.catalog;
    const label = !catalog ? 'Status unavailable. Refresh before use.' : workspace.loaded() ?
      'Active: the proxy has loaded the current saved policy.' : 'Pending: the proxy has not confirmed the saved policy.';
    element('overview-policy').textContent = label; element('activation-status').textContent = label;
    element('proxy-url').textContent = catalog?.proxy_url || 'HTTPS proxy endpoint unavailable.';
    for (const [name, collection] of [['credentials', 'credentials'], ['applications', 'applications'], ['rules', 'access_rules']])
      element('overview-' + name + '-count').textContent = catalog ? String(catalog[collection].filter(item => item.status === 'active').length) : 'Unavailable';
    if (catalog) {
      const validApps = catalog.applications.filter(item => item.status === 'active' && item.token_status === 'valid' && item.token_expires_at_epoch_ms > Date.now());
      const step = !catalog.credentials.some(item => item.status === 'active') ? ['Connect your first app', '#connect'] :
        !validApps.length ? ['Connect an app with a saved credential', '#connect'] :
        !catalog.access_rules.some(item => item.status === 'active' && validApps.some(app => app.id === item.application_id)) ? ['Choose permitted access for your app', '#connect'] :
        !workspace.loaded() ? ['Check pending proxy activation', '#proxy'] : ['Configure your app and send a scoped test request', '#proxy'];
      element('overview-next-action').textContent = step[0]; element('overview-next-action').href = step[1];
    }
    if (location.hash === '#audit') audit.open();
  });
  for (const id of ['retry-load', 'credentials-refresh', 'applications-refresh', 'rules-refresh', 'proxy-refresh'])
    element(id).addEventListener('click', () => workspace.refresh({manual: true}));
  window.addEventListener('hashchange', navigate);
  navigate(); workspace.refresh();
}

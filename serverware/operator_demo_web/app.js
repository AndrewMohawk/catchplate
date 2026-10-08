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
else {
  const workspace = createOperatorWorkspace();
  createCredentialsView(workspace); createAccessRulesView(workspace);
  const applications = createApplicationsView(workspace);
  createProxyView(workspace, applications); const audit = createAuditView(workspace);
  function navigate() {
    let view = location.hash.slice(1) || 'overview';
    if (view === 'main-content') { element('main-content').focus(); return; }
    if (!Object.hasOwn(operatorViews, view)) { view = 'overview'; history.replaceState(null, '', '#overview'); }
    for (const name of Object.keys(operatorViews)) {
      element(name).hidden = name !== view;
      const link = document.querySelector('nav a[href="#' + name + '"]');
      if (name === view) link.setAttribute('aria-current', 'page'); else link.removeAttribute('aria-current');
    }
    element('page-label').textContent = operatorViews[view]; document.title = operatorViews[view] + ' - Serverware operator workspace';
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
      const step = !catalog.credentials.some(item => item.status === 'active') ? ['Save your first provider credential', '#credentials'] :
        !validApps.length ? ['Create an application or rotate an expired token', '#applications'] :
        !catalog.access_rules.some(item => item.status === 'active' && validApps.some(app => app.id === item.application_id)) ? ['Grant an application access with a rule', '#access-rules'] :
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

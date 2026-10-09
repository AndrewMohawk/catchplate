function createProxyView(workspace, applications) {
  const home = element('proxy'); const content = textNode('div'); content.id = 'proxy-setup-content';
  content.append(...[...home.children].slice(2)); home.append(content);
  let command = '';
  renderOperatorCompatibility('client-compatibility-content');
  function render() {
    command = ''; element('copy-command').disabled = true; element('download-config').disabled = true;
    const catalog = workspace.state.catalog;
    if (!catalog) { element('client-command').textContent = 'Refresh workspace status before using this client.'; return; }
    chooseOptions('proxy-application', catalog.applications.filter(item => item.status === 'active'), 'Create an application first');
    const application = catalog.applications.find(item => item.id === element('proxy-application').value);
    chooseOptions('proxy-rule', catalog.access_rules.filter(item => item.status === 'active' && item.application_id === application?.id), 'Add an access rule for this application');
    const rule = catalog.access_rules.find(item => item.id === element('proxy-rule').value);
    chooseOptions('proxy-method', (rule?.methods || []).filter(method => operatorMethods.includes(method)).map(method => ({id: method, name: method})), 'No supported method');
    const credential = catalog.credentials.find(item => item.id === rule?.credential_id);
    if (!application || !rule) {
      element('client-command').textContent = 'Choose an application with a saved access rule.';
      element('client-guidance').textContent = 'Credentials and applications alone grant no access. Add a rule, then return here.'; return;
    }
    const valid = application.token_status === 'valid' && Number.isSafeInteger(application.token_expires_at_epoch_ms) && application.token_expires_at_epoch_ms > Date.now();
    const supported = operatorRuleSupported(rule, catalog);
    renderOperatorCompatibility('client-compatibility-content', rule);
    if (!valid || !supported || credential?.status !== 'active') {
      element('client-command').textContent = !valid ? 'The application token is expired, revoked or cannot be verified.' : 'The saved rule or credential is unavailable or unsupported.';
      element('client-guidance').textContent = !valid ? 'Use Applications to explicitly rotate its token. No token has been renewed automatically.' : 'Review the saved access rule before use.'; return;
    }
    let dummyHeader;
    try {
      const proxy = new URL(catalog.proxy_url);
      if (proxy.protocol !== 'https:' || proxy.username || proxy.password || proxy.pathname !== '/' || proxy.search || proxy.hash ||
          !proxy.hostname.includes('.') || proxy.hostname === '127.0.0.1' || proxy.hostname.endsWith('.local') || proxy.hostname.endsWith('.localhost')) throw new Error();
      command = buildCurlCommand({proxyUrl: catalog.proxy_url, upstreamUrl: rule.upstream_url, method: element('proxy-method').value,
        caPath: element('ca-path').value, allowedHeaders: rule.allowed_headers,
        credentialInput: rule.credential_input, placeholder: rule.placeholder, credential});
      dummyHeader = clientCredentialInput({credentialInput: rule.credential_input, placeholder: rule.placeholder, credential});
    } catch (_) { element('client-command').textContent = 'A valid public HTTPS proxy and supported rule are required.'; return; }
    element('client-command').textContent = command;
    const ready = workspace.loaded() && rule.enforcement === 'active' && application.access_status === 'active' && !workspace.state.busy && !workspace.state.uncertain;
    element('copy-command').disabled = !ready;
    element('download-config').disabled = !ready || !applications.tokenFor(application.id);
    element('client-guidance').textContent = (ready ? 'Policy loaded and token not expired. This is a connection template, not a successful request test.' :
      'Saved configuration is not currently confirmed for use. Wait for activation and resolve any uncertain change.') +
      ' The template supplies no request body or query parameter values. Use your existing client to provide the endpoint-specific data within this rule.' +
      (dummyHeader ? ' Send the displayed exact dummy ' + dummyHeader.name + ' header once. It is not a provider secret or your Serverware application token.' :
        ' Do not send a provider credential header; Serverware adds it automatically.') +
      (['unfiltered_json', 'unfiltered_json_or_empty_v1'].includes(rule.response_mode) ? ' Response content: all JSON fields, including error responses; no field filtering.' :
        ' Successful JSON responses contain only the selected fields. Error responses retain only error, code and message fields.') +
      ' ' + operatorResponseLimits(rule.response_mode) + ' See Compatibility limits for sizes, supported statuses and transport restrictions.' +
      (rule.request_body_mode === 'preserve_json_v1' ? ' Request content: keep your client’s JSON bytes unchanged, up to 64 KiB, or send no body. Nonempty bodies require application/json. No request-field list is needed; forms, binary and streaming are unsupported.' :
        rule.request_fields.length ? ' If the endpoint requires a body, send application/json using only these fields: ' + rule.request_fields.join(', ') +
        '. Do not add Content-Type to the allowed-header list.' : ' Request bodies are forbidden by this rule, including for POST, PUT and PATCH.') +
      (rule.query_keys.length ? ' Query parameter names allowed: ' + rule.query_keys.join(', ') + '; supply their values yourself.' : ' No query parameters are allowed.');
  }
  for (const id of ['proxy-application', 'proxy-rule', 'proxy-method']) element(id).addEventListener('change', render);
  element('ca-path').addEventListener('input', render);
  element('copy-command').addEventListener('click', async () => {
    render(); if (element('copy-command').disabled || !command) return;
    try { await navigator.clipboard.writeText(command); element('client-copy-status').textContent = 'Copied. This connection template has no request body or query values. Set the application token in your client environment.'; }
    catch (_) { element('client-copy-status').textContent = 'Clipboard access was denied. Select and copy the displayed example manually.'; }
  });
  element('download-config').addEventListener('click', () => {
    render(); if (element('download-config').disabled) return;
    const catalog = workspace.state.catalog; const application = catalog.applications.find(item => item.id === element('proxy-application').value);
    const rule = catalog.access_rules.find(item => item.id === element('proxy-rule').value); const token = applications.tokenFor(application.id);
    if (!token) return;
    const credential = catalog.credentials.find(item => item.id === rule.credential_id);
    const dummyHeader = clientCredentialInput({credentialInput: rule.credential_input, placeholder: rule.placeholder, credential});
    const config = {application_id: application.id, access_rule_id: rule.id, proxy_url: catalog.proxy_url, upstream_url: rule.upstream_url,
      methods: rule.methods, response_mode: rule.response_mode, credential_input: rule.credential_input,
      request_headers: dummyHeader ? {[dummyHeader.name]: dummyHeader.value} : {},
      ca_file: element('ca-path').value || './serverware-ca.pem', proxy_authorization: 'Bearer ' + token,
      token_expires_at_epoch_ms: application.token_expires_at_epoch_ms, note: 'Private development client configuration. Never commit or share. Provider credential not included.'};
    if (Object.hasOwn(rule, 'request_body_mode')) config.request_body_mode = rule.request_body_mode;
    const url = URL.createObjectURL(new Blob([JSON.stringify(config, null, 2) + '\n'], {type: 'application/json'}));
    const anchor = textNode('a'); anchor.href = url; anchor.download = 'serverware-client.private.json'; document.body.append(anchor); anchor.click(); anchor.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000); element('client-copy-status').textContent = 'Downloaded private client configuration. Keep it out of source control.';
  });
  function select(applicationId, ruleId) {
    const catalog = workspace.state.catalog;
    if (!catalog?.access_rules.some(rule => rule.id === ruleId && rule.application_id === applicationId && rule.status === 'active')) return false;
    element('proxy-application').value = applicationId; render();
    element('proxy-rule').value = ruleId; render();
    return element('proxy-application').value === applicationId && element('proxy-rule').value === ruleId;
  }
  function mount(container) {
    (container || home).append(content);
    for (const id of ['proxy-application', 'proxy-rule']) element(id).disabled = Boolean(container);
  }
  workspace.subscribe(render); return {render, select, mount};
}
function createAuditView(workspace) {
  let loaded = false; let cursor = null; let count = 0; let epoch = 0; let selection = '';
  async function load(append = false) {
    const version = ++epoch; const filter = JSON.stringify([element('audit-filter').value, element('audit-query').value.trim()]);
    if (filter !== selection) append = false;
    selection = filter;
    if (!append) { cursor = null; count = 0; element('audit-list').replaceChildren(); }
    const query = new URLSearchParams({limit: '20', scanLimit: '5000'});
    if (element('audit-filter').value) query.set('eventType', element('audit-filter').value);
    if (element('audit-query').value.trim()) query.set('q', element('audit-query').value.trim());
    if (append && cursor) query.set('cursor', cursor);
    element('audit-status').textContent = 'Loading stored events...'; element('audit-more').disabled = true;
    try {
      const result = await workspace.api('/api/audit/search?' + query);
      if (version !== epoch) return;
      if (result.ok !== true || !Array.isArray(result.items)) throw operatorError('The audit response was incomplete.');
      for (const event of result.items) {
        const card = textNode('article', undefined, 'card event-card'); card.append(textNode('h3', event.event_type || 'Recorded event'), textNode('time', event.created_at || 'Time not reported'));
        const details = textNode('details'); details.append(textNode('summary', 'Event details'), textNode('pre', JSON.stringify(event, null, 2))); card.append(details); element('audit-list').append(card);
      }
      count += result.items.length; cursor = result.has_more && typeof result.next_cursor === 'string' ? result.next_cursor : null; loaded = true;
      element('audit-more').hidden = !cursor;
      element('audit-status').textContent = `${count} events shown. ` + (result.has_more || result.complete === false ? 'Partial history; load older events to continue.' : 'End of matching history.');
    } catch (error) { if (version === epoch) { loaded = false; element('audit-status').textContent = operatorMessage(error); element('audit-more').hidden = true; } }
    finally { if (version === epoch) element('audit-more').disabled = false; }
  }
  element('audit-refresh').addEventListener('click', () => load()); element('audit-more').addEventListener('click', () => load(true));
  element('audit-filter').addEventListener('change', () => load());
  element('audit-search-form').addEventListener('submit', event => { event.preventDefault(); load(); });
  element('audit-verify').addEventListener('click', async () => {
    element('audit-verify').disabled = true; element('audit-verification').textContent = 'Checking the stored audit chain...';
    try { const result = await workspace.api('/api/audit/verify'); element('audit-verification').textContent = result.ok === true && result.complete === true ?
      'The complete local audit chain is consistent.' : result.ok === true ? 'Verification was incomplete.' : 'Audit verification failed.'; }
    catch (error) { element('audit-verification').textContent = operatorMessage(error); }
    finally { element('audit-verify').disabled = false; }
  });
  return {open: () => { if (!loaded && workspace.state.catalog) load(); }};
}

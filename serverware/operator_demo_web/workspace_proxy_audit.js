// Repository links contain public source paths only. Never personalize them
// with an application ID, provider URL, credential, or private configuration.
function operatorExampleProjects(rule, catalog) {
  if (!rule || rule.status !== 'active' || !operatorRuleSupported(rule, catalog)) return [];
  const source = 'https://github.com/AndrewMohawk/serverware/';
  const branch = 'serverware/operator-workspace/';
  const project = (label, directory) => ({label, kind: 'project', href: source + 'tree/' + branch + 'examples/' + directory});
  const guide = (label, filename) => ({label, kind: 'guide', href: source + 'blob/' + branch + 'docs/' + filename});
  switch (rule.operation_bundle) {
    case 'github_issues_read_v1':
    case 'github_issues_write_v1':
      return [project('Node.js + GitHub Actions', 'github-issues-node'),
        project('Python', 'github-issues-python'), project('Go', 'github-issues-go')];
    case 'npm_metadata_read_v1': return [project('npm registry project', 'npm-registry'),
      guide('npm metadata guide', 'operator-npm-metadata.md')];
    case 'npm_publish_v1': return [project('npm registry project', 'npm-registry'),
      guide('npm publishing guide', 'operator-npm-publish.md')];
    case 'x_username_read_v1': return [project('Node.js', 'x-username-node'),
      project('Python', 'x-username-python'), project('Go', 'x-username-go'),
      {label: 'GitHub Actions recipe (inactive)', kind: 'guide',
        href: source + 'blob/' + branch + 'examples/x-username-node/workflow.example.yml'},
      guide('X preset scope and compatibility', 'operator-provider-presets.md')];
    case 'gmail_read_v1': return [
      ...(rule.credential_input === 'replace_exact' && rule.placeholder === 'Bearer serverware-gmail-placeholder-v1' ?
        [project('Go + Gmail SDK', 'google-gmail-go')] : []),
      guide('Google / Gmail guide', 'operator-gmail-job-verification.md')];
    default: return [];
  }
}
function renderOperatorExampleProjects(rule, catalog) {
  const panel = element('client-examples'); const links = element('client-example-links');
  const projects = operatorExampleProjects(rule, catalog);
  links.replaceChildren(); panel.hidden = projects.length === 0;
  element('client-example-note').textContent = !projects.length ? '' : isXRule(rule) ?
    'Public source only, separate from your private client config. Pinned Node.js, Python and Go examples passed isolated SDK-through-proxy checks. This page has not tested your X credentials or provider entitlement. The GitHub Actions recipe is inactive and has not been run.' : projects[0].kind === 'project' ?
    'Public source only, separate from your private client config. Check each README for setup and verification status; opening an example does not run it or verify access.' :
    'This saved permission links to its setup and verification guide only. The Go SDK project requires the documented exact Gmail dummy-header replacement. The public guide contains no private client config and does not verify your access.';
  for (const project of projects) {
    const link = textNode('a', project.label, 'button secondary');
    link.href = project.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; link.referrerPolicy = 'no-referrer';
    links.append(link);
  }
}
function createProxyView(workspace, applications) {
  const home = element('proxy'); const content = textNode('div'); content.id = 'proxy-setup-content';
  content.append(...[...home.children].slice(2)); home.append(content);
  let command = '';
  let gmailContext = '';
  let githubContext = '';
  renderOperatorCompatibility('client-compatibility-content');
  function render() {
    command = ''; element('copy-command').disabled = true; element('download-config').disabled = true;
    renderOperatorExampleProjects(null, null);
    element('gmail-client-controls').hidden = true;
    element('github-client-controls').hidden = true;
    element('npm-client-controls').hidden = true;
    element('npm-publish-client-controls').hidden = true;
    element('client-proxy-login').hidden = true;
    for (const id of ['client-proxy-auth-mode', 'client-proxy-host', 'client-proxy-port', 'client-proxy-username',
      'client-proxy-password-note', 'client-proxy-login-status']) element(id).textContent = '';
    const catalog = workspace.state.catalog;
    if (!catalog) { element('client-command').textContent = 'Refresh workspace status before using this client.'; return; }
    chooseOptions('proxy-application', catalog.applications.filter(item => item.status === 'active'), 'Create an application first');
    const application = catalog.applications.find(item => item.id === element('proxy-application').value);
    chooseOptions('proxy-rule', catalog.access_rules.filter(item => item.status === 'active' && item.application_id === application?.id), 'Add an access rule for this application');
    const rule = catalog.access_rules.find(item => item.id === element('proxy-rule').value);
    const gmail = isGmailRule(rule);
    const github = isGithubRule(rule);
    const npm = isNpmRule(rule);
    const npmPublish = isNpmPublishRule(rule);
    const x = isXRule(rule);
    element('npm-publish-client-controls').hidden = !npmPublish;
    element('npm-publish-client-summary').textContent = npmPublish ? npmPublishReview(rule) : '';
    element('npm-client-controls').hidden = !npm;
    if (npm) chooseOptions('npm-client-package', rule.packages.map(name => ({id: name, name})), 'Choose an allowed package');
    const githubSelection = github ? application?.id + ':' + rule.id : '';
    if (githubSelection !== githubContext) { element('github-client-operation').value = 'read'; githubContext = githubSelection; }
    element('github-client-controls').hidden = !github;
    element('github-client-operation').querySelector('option[value="create"]').disabled = rule?.operation_bundle !== operatorGithub.write;
    element('proxy-method').hidden = github || npm || npmPublish || x; element('proxy-method').disabled = github || npm || npmPublish || x;
    document.querySelector('label[for="proxy-method"]').hidden = github || npm || npmPublish || x;
    const context = gmail ? application?.id + ':' + rule.id : '';
    if (context !== gmailContext) { element('gmail-client-operation').value = 'list'; element('gmail-message-id').value = ''; gmailContext = context; }
    element('gmail-client-controls').hidden = !gmail;
    const messageRead = gmail && element('gmail-client-operation').value === 'message';
    element('gmail-message-group').hidden = !messageRead;
    element('client-template-title').textContent = x ? 'X · Username lookup connection template' : npmPublish ? 'npm · Publish package' : npm ? 'npm · Read package metadata' : github ? 'GitHub · Octokit client recipe' : gmail ? 'Gmail client connection templates' : 'cURL connection template';
    element('client-template-warning').textContent = x ?
      'Only the exact saved username is permitted. This cURL template uses a public dummy, never the real X token. The page does not execute a lookup or prove provider entitlement.' : npmPublish ?
      'This public-publishing example can publish a new version when you explicitly run it locally. Review your tarball contents first. This page neither executes publishing nor verifies npm access. Do not automatically retry an uncertain publish.' : npm ?
      'Save the dedicated npmrc settings, then run the separate npm view command in an empty test directory with a clean npm environment and fresh private cache. Only the public dummy token appears here. No package lookup is executed or verified by this page.' : github ?
      'Use the real GitHub URL through the HTTPS proxy. This recipe supplies only a public dummy upstream token and reads the Serverware app token locally. It is not a successful request test; selecting a creation example does not execute it.' : gmail ?
      'List messages first, then use an actual returned message ID to read it. Your client handles pagination and each request. These templates are not an automated mail job or proof of a successful Gmail request.' :
      'This template includes no request body or query parameter values. It is not a complete API operation or a successful request test. Supply endpoint-specific data in your existing client, using only what the selected rule permits.';
    chooseOptions('proxy-method', (rule?.methods || []).filter(method => operatorMethods.includes(method)).map(method => ({id: method, name: method})), 'No supported method');
    const credential = catalog.credentials.find(item => item.id === rule?.credential_id);
    if (!application || !rule) {
      element('client-command').textContent = 'Choose an application with a saved access rule.';
      element('client-guidance').textContent = 'Credentials and applications alone grant no access. Add a rule, then return here.'; return;
    }
    const valid = application.token_status === 'valid' && Number.isSafeInteger(application.token_expires_at_epoch_ms) && application.token_expires_at_epoch_ms > Date.now();
    const supported = operatorRuleSupported(rule, catalog);
    renderOperatorCompatibility('client-compatibility-content', rule);
    // Browsing public code does not require a current token. The existing gates
    // below still control personalized recipes, copy, and private downloads.
    renderOperatorExampleProjects(rule, catalog);
    if (!valid || !supported || credential?.status !== 'active') {
      element('client-command').textContent = !valid ? 'The application token is expired, revoked or cannot be verified.' : 'The saved rule or credential is unavailable or unsupported.';
      element('client-guidance').textContent = !valid ? 'Use Applications to explicitly rotate its token. No token has been renewed automatically.' : 'Review the saved access rule before use.'; return;
    }
    let dummyHeader; let proxy;
    const proxyAuthentication = applicationProxyAuthentication(application);
    if ((npm || npmPublish) && proxyAuthentication !== 'basic_and_bearer_v1') {
      element('client-command').textContent = 'The stock npm client needs standard username/password proxy login.';
      element('client-guidance').textContent = 'Use Applications to explicitly enable standard proxy login if advertised, then refresh. The app ID is the username and its existing Serverware token is the password. No login mode or token is changed automatically.';
      return;
    }
    const messageId = element('gmail-message-id').value;
    if (messageRead && !/^[A-Za-z0-9_-]{1,512}$/.test(messageId)) {
      element('client-command').textContent = 'Enter a valid message ID returned by this account’s message list.';
      element('client-guidance').textContent = 'No command is available until the message ID is valid. Provider tokens and the application token do not belong in this field.'; return;
    }
    try {
      proxy = new URL(catalog.proxy_url);
      if (proxy.protocol !== 'https:' || proxy.username || proxy.password || proxy.pathname !== '/' || proxy.search || proxy.hash ||
          !proxy.hostname.includes('.') || proxy.hostname === '127.0.0.1' || proxy.hostname.endsWith('.local') || proxy.hostname.endsWith('.localhost')) throw new Error();
      command = npmPublish ? buildNpmPublishClientRecipe({proxyUrl: catalog.proxy_url, applicationId: application.id, proxyAuthentication,
        packageName: rule.package, tag: rule.tag, publishingWindow: rule.publishing_window, caPath: element('ca-path').value}) :
        npm ? buildNpmClientRecipe({proxyUrl: catalog.proxy_url, applicationId: application.id, proxyAuthentication,
        packages: rule.packages, packageName: element('npm-client-package').value, caPath: element('ca-path').value}) : github ? buildGithubClientRecipe({proxyUrl: catalog.proxy_url, applicationId: application.id, proxyAuthentication,
        repository: rule.repository, bundle: rule.operation_bundle, operation: element('github-client-operation').value,
        caPath: element('ca-path').value, proxyCaPath: element('github-proxy-ca-path').value}) :
        buildCurlCommand({proxyUrl: catalog.proxy_url, upstreamUrl: rule.upstream_url + (messageRead ? '/' + messageId : ''), method: element('proxy-method').value,
        caPath: element('ca-path').value, allowedHeaders: rule.allowed_headers,
        credentialInput: rule.credential_input, placeholder: rule.placeholder, credential,
        proxyAuthentication, applicationId: application.id});
      dummyHeader = clientCredentialInput({credentialInput: rule.credential_input, placeholder: rule.placeholder, credential});
    } catch (_) { element('client-command').textContent = 'A valid public HTTPS proxy and supported rule are required.'; return; }
    element('client-command').textContent = command;
    const ready = workspace.loaded() && rule.enforcement === 'active' && application.access_status === 'active' && !workspace.state.busy && !workspace.state.uncertain;
    element('copy-command').disabled = !ready;
    element('download-config').disabled = !ready || !applications.tokenFor(application.id);
    const basic = proxyAuthentication === 'basic_and_bearer_v1';
    element('client-proxy-login').hidden = false;
    element('client-proxy-auth-mode').textContent = basic ? 'Standard username/password login; Bearer also accepted.' : 'Bearer proxy authentication only.';
    element('client-proxy-host').textContent = proxy.hostname; element('client-proxy-port').textContent = proxy.port || '443';
    element('client-proxy-username').textContent = basic ? application.id : 'Not used for Bearer';
    element('client-proxy-password-note').textContent = basic ?
      'Use this application’s existing Serverware client token as the password, never the provider key. This page does not retrieve it.' :
      'Send this application’s existing token in the Proxy-Authorization: Bearer header. Username/password login is not enabled; never use the provider key.';
    element('client-proxy-login-status').textContent = (ready ? 'The exact saved policy is loaded. No client connection was tested here. ' :
      'Wait for the exact saved policy to load and resolve uncertain changes before using this login. ') +
      'Application token expires ' + new Date(application.token_expires_at_epoch_ms).toLocaleString() + '; no token was renewed.';
    if (x) {
      element('client-guidance').textContent = (ready ? 'The saved policy is loaded and the app token is not expired. No X lookup was tested here. ' :
        'Wait for the exact saved policy and resolve uncertain changes before using this template. ') +
        'Look up ' + rule.username + ' at api.x.com, GET only with no query or body. No posting, search, pagination, user OAuth, DMs, media or streams. ' +
        'Send the exact public dummy Bearer serverware-x-placeholder-v1 once. Your Serverware app token authenticates only to the proxy; never give the client the real provider token. ' +
        'No response-field setup; supported full JSON can contain provider errors even with HTTP 200. Keep both TLS legs verified. ' +
        'Pinned Node.js, Python and Go examples passed isolated SDK-through-proxy checks. This page has not tested your X credentials or provider entitlement. The GitHub Actions recipe is inactive and has not been run.';
      return;
    }
    if (npmPublish) {
      element('client-guidance').textContent = (ready ? 'The saved policy is loaded and the app token is not expired. No npm publication was tested here. ' :
        'Wait for the exact saved policy and resolve uncertain changes before using the recipe. ') + npmPublishReview(rule) +
        ' Publishing hours do not renew the app token or provider token. The public npm dummy is not a real credential; set only the Serverware app token in your local environment. ' +
        'Keep strict-ssl enabled and load the downloaded CA with NODE_EXTRA_CA_CERTS before npm starts; retain default roots. See Compatibility limits.';
      return;
    }
    if (npm) {
      element('client-guidance').textContent = (ready ? 'The saved policy is loaded and the app token is not expired. No npm lookup was tested here. ' :
        'Wait for the exact saved policy and resolve uncertain changes before using the recipe. ') +
        'Read package metadata for the explicit package list only. npm view and pacote.manifest; no install, publish, tarballs or npm audit. ' +
        'The npmrc dummy token is public, not your npm account token. Configure the Serverware app token only in the local environment. ' +
        'NODE_EXTRA_CA_CERTS adds the downloaded CA to Node default roots before startup; for a private outer proxy CA, use a deliberate additional-CA file containing both required roots. Keep strict-ssl enabled and do not override cafile. See Compatibility limits.';
      return;
    }
    if (github) {
      element('client-guidance').textContent = (ready ? 'The saved policy is loaded and the app token is not expired. No GitHub request was tested here. ' :
        'Wait for the exact saved policy and resolve uncertain changes before using the recipe. ') +
        githubPermissionName(rule.operation_bundle) + ' for ' + rule.repository.owner + '/' + rule.repository.name +
        '. No response-field setup: supported JSON content/errors and selected pagination/retry metadata are preserved. ' +
        'The app token authenticates only to the proxy; the fixed dummy authenticates no real GitHub account. ' +
        'Keep outer proxy trust separate from destination trust; no global TLS bypass. No automatic retry of an uncertain issue/comment creation. See Compatibility limits.';
      return;
    }
    if (gmail) {
      element('client-guidance').textContent = (ready ? 'Policy loaded and app token not expired. No Gmail request or refresh was tested here. ' :
        'Waiting for the exact policy to load; resolve uncertain changes before use. ') +
        'Use GET lists and individual message reads; no request body. Your client may follow nextPageToken and request full or metadata message JSON. No age restriction, attachments, history, Calendar or writes. ' +
        (rule.query_mode === 'orderedFormV1' ? 'Supported query parameters may remain in client order; operation and value limits still apply. ' :
          'This retained permission still requires legacy canonical query encoding/order. ') +
        (dummyHeader ? 'Send the displayed exact dummy Authorization header once; it is not the app token or a provider secret. ' :
          'Do not send a Google token: Serverware adds provider authentication. ') +
        'Required JSON only, up to 1 MiB success / 64 KiB error; no empty 204 or streaming. Standard metadata is checked and discarded. See Compatibility limits.';
      return;
    }
    element('client-guidance').textContent = (ready ? 'Policy loaded and token not expired. This is a connection template, not a successful request test.' :
      'Saved configuration is not currently confirmed for use. Wait for activation and resolve any uncertain change.') +
      ' The template supplies no request body or query parameter values. Use your existing client to provide the endpoint-specific data within this rule.' +
      (dummyHeader ? ' Send the displayed exact dummy ' + dummyHeader.name + ' header once. It is not a provider secret or your Serverware application token.' :
        ' Do not send a provider credential header; Serverware adds it automatically.') +
      (operatorResponseKeepsJson(rule.response_mode) ? ' Response content: all JSON fields, including error responses; no field filtering.' :
        ' Successful JSON responses contain only the selected fields. Error responses retain only error, code and message fields.') +
      ' ' + operatorResponseLimits(rule.response_mode) + ' ' + operatorResponseHeaderSummary(rule.response_mode) + ' See Compatibility limits for sizes, supported statuses and transport restrictions.' +
      (rule.request_body_mode === 'preserve_json_v1' ? ' Request content: keep your client’s JSON bytes unchanged, up to 64 KiB, or send no body. Nonempty bodies require application/json. No request-field list is needed; forms, binary and streaming are unsupported.' :
        rule.request_fields.length ? ' If the endpoint requires a body, send application/json using only these fields: ' + rule.request_fields.join(', ') +
        '. Do not add Content-Type to the allowed-header list.' : ' Request bodies are forbidden by this rule, including for POST, PUT and PATCH.') +
      (rule.query_keys.length ? ' Query parameter names allowed: ' + rule.query_keys.join(', ') + '; supply their values yourself.' : ' No query parameters are allowed.');
  }
  for (const id of ['proxy-application', 'proxy-rule', 'proxy-method', 'gmail-client-operation', 'github-client-operation', 'npm-client-package']) element(id).addEventListener('change', render);
  element('gmail-message-id').addEventListener('input', render);
  element('ca-path').addEventListener('input', render);
  element('github-proxy-ca-path').addEventListener('input', render);
  element('copy-command').addEventListener('click', async () => {
    render(); if (element('copy-command').disabled || !command) return;
    try {
      await navigator.clipboard.writeText(command);
      element('client-copy-status').textContent = !element('npm-publish-client-controls').hidden ?
        'Copied npmrc settings and the separate publishing command. Review the local package before running it; this page sent no publish request.' : !element('npm-client-controls').hidden ?
        'Copied npmrc settings and the separate metadata command. Set the app token and a fresh private cache locally; no lookup was executed by this page.' : !element('github-client-controls').hidden ?
        'Copied the GitHub client recipe. Set the application token and any creation content locally. No request was executed by this page.' :
        'Copied. This connection template has no request body or query values. Set the application token in your client environment.';
    }
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
      ca_file: element('ca-path').value || './serverware-ca.pem',
      token_expires_at_epoch_ms: application.token_expires_at_epoch_ms, note: 'Private development client configuration. Never commit or share. Provider credential not included.'};
    if (applicationProxyAuthentication(application) === 'basic_and_bearer_v1') Object.assign(config,
      {proxy_authentication: 'basic_and_bearer_v1', proxy_username: application.id, proxy_password: token});
    else config.proxy_authorization = 'Bearer ' + token;
    if (Object.hasOwn(rule, 'request_body_mode')) config.request_body_mode = rule.request_body_mode;
    if (isXRule(rule)) {
      config.operation_bundle = rule.operation_bundle; config.username = rule.username;
      config.note += ' X app-only username lookup only: GET with no query or body. Fixed public dummy; no posting or user OAuth. Provider entitlement and ordinary SDK compatibility have not been verified by this page.';
    }
    if (isGmailRule(rule)) {
      config.operation_bundle = rule.operation_bundle; config.age_policy = {mode: rule.age_policy.mode};
      if (Object.hasOwn(rule, 'query_mode')) config.query_mode = rule.query_mode;
      config.operations = [{name: 'List messages', method: 'GET', url: rule.upstream_url},
        {name: 'Read message', method: 'GET', url_template: rule.upstream_url + '/{message_id}', message_id_source: 'id returned by this account message list'}];
      config.note += ' Your client performs pagination and separate message reads; this is not an automated mail job. No age restriction.';
    }
    if (isGithubRule(rule)) {
      config.operation_bundle = rule.operation_bundle; config.repository = {...rule.repository}; config.query_mode = rule.query_mode;
      config.client_recipe = {packages: {'@octokit/rest': '22.0.1', undici: '8.11.2'}, minimum_node: '22.19',
        sdk_auth_token: operatorGithub.token, proxy_ca_file: element('github-proxy-ca-path').value || null,
        destination_ca_file: config.ca_file};
      config.note += ' The public SDK dummy is not the provider token. Outer proxy TLS and destination TLS use separate trust. No automatic retry after uncertain creation.';
    }
    if (isNpmRule(rule)) {
      config.operation_bundle = rule.operation_bundle; config.packages = [...rule.packages];
      config.client_recipe = {npm_version: '11.8.0', pacote_version: '21.0.4', node_version: '25.5.0',
        package: element('npm-client-package').value, sdk_auth_token: operatorNpm.token, strict_ssl: true,
        extra_ca_file: config.ca_file, fresh_cache_required: true, automatic_retries: 0, metadata_only: true};
      config.note += ' npm view/pacote.manifest metadata only; no install, publish, tarballs or npm audit. Use NODE_EXTRA_CA_CERTS before Node startup; retain default roots and TLS verification. The public npm dummy is not the provider token.';
    }
    if (isNpmPublishRule(rule)) {
      config.operation_bundle = rule.operation_bundle; config.package = rule.package; config.tag = rule.tag;
      config.publishing_window = rule.publishing_window === null ? null : {...rule.publishing_window};
      config.publishing_window_timezone = 'UTC'; config.read_metadata_included = true;
      config.client_recipe = {npm_version: '11.8.0', node_version: '25.5.0', sdk_auth_token: operatorNpm.token,
        strict_ssl: true, extra_ca_file: config.ca_file, fresh_cache_required: true, automatic_retries: 0};
      config.note += ' Publishing changes the registry; this page has not run it. Metadata reads remain allowed outside publishing hours. No automatic retry after an uncertain publish. Keep TLS verification and Node default roots enabled.';
    }
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
